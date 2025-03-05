use anyhow::Result;
use clap::Parser;
use memmap2::Mmap;
use object::{BinaryFormat, Object, ObjectSection, SectionKind};
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::Path;

const ASSET_HEADER_SIZE: usize = size_of::<AssetHeader>();

#[repr(C)]
#[derive(Debug)]
struct AssetHeader {
    name_ptr: u64,
    name_len: u64,
    data_ptr: u64,
    data_size: u64,
}

#[derive(Debug)]
struct Asset {
    name: String,
    data: Vec<u8>,
}

#[derive(Debug)]
struct SectionInfo {
    virtual_address: u64,
    file_offset: u64,
    size: u64,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    input: String,

    #[arg(short, long)]
    output: String,
}

struct Dumper {
    mmap: Mmap,
    data_section: SectionInfo,
    binary_format: BinaryFormat,
}

impl Dumper {
    fn new(file: File) -> Result<Self> {
        let mmap = unsafe { Mmap::map(&file)? };
        let obj = object::File::parse(&*mmap)?;
        let binary_format = obj.format();
        // TODO: support Mach-O format
        if binary_format == BinaryFormat::MachO {
            return Err(anyhow::anyhow!("Mach-O format is not supported"));
        }

        let matched_sections = obj
            .sections()
            .filter(|section| {
                let section_name = section.name().expect("section name not found").to_string();
                let matched_section = match binary_format {
                    BinaryFormat::Pe => {
                        section_name == ".rdata" && section.kind() == SectionKind::ReadOnlyData
                    }
                    _ => false,
                };
                matched_section
            })
            .collect::<Vec<_>>();
        if matched_sections.len() != 1 {
            return Err(anyhow::anyhow!("RDATA section not found or not unique"));
        }

        let ref data_section = matched_sections[0];
        let data_section = SectionInfo {
            virtual_address: data_section.address(),
            file_offset: data_section.file_range().expect("file range not found").0,
            size: data_section.size(),
        };

        Ok(Self {
            mmap,
            data_section,
            binary_format,
        })
    }

    fn convert_rva_to_file_offset(&self, rva: u64) -> Result<u64> {
        let section = &self.data_section;

        if rva >= section.virtual_address && rva < section.virtual_address + section.size {
            let section_offset = rva - section.virtual_address;
            return Ok(section.file_offset + section_offset);
        }

        Err(anyhow::anyhow!("RVA is not in rdata section"))
    }

    fn heuristic_search_assets(&self) -> Result<Vec<Asset>> {
        // get start offset and scan length
        let (start_offset, scan_length) = match self.binary_format {
            BinaryFormat::Pe => {
                let section = &self.data_section;
                (section.file_offset as usize, section.size as usize)
            }
            _ => unreachable!(),
        };

        let end_offset = start_offset.saturating_add(scan_length);
        assert!(end_offset <= self.mmap.len(), "end_offset is out of range");

        // println!("Scanning from offset 0x{:x} to 0x{:x}", start_offset, end_offset);

        let mut assets = Vec::new();
        let mut offset = start_offset;
        let mut scan_step = 8; // TODO: detect PE/Mach-O file format to determine pointer size
        while offset + ASSET_HEADER_SIZE <= end_offset {
            if let Ok(asset) = self.parse_asset(offset) {
                // println!("Found asset at offset 0x{:x}: {}", offset, String::from_utf8_lossy(&asset.name));
                assets.push(asset);
                scan_step = ASSET_HEADER_SIZE;
            }

            offset += scan_step;
        }

        // println!("Scan completed");
        Ok(assets)
    }

    fn parse_asset(&self, offset: usize) -> Result<Asset> {
        if offset + ASSET_HEADER_SIZE > self.mmap.len() {
            return Err(anyhow::anyhow!("offset is out of range"));
        }

        let chunk = &self.mmap[offset..offset + ASSET_HEADER_SIZE];

        let header = unsafe { &*(chunk.as_ptr() as *const AssetHeader) };

        let name_off = self.convert_rva_to_file_offset(header.name_ptr)?;
        let data_off = self.convert_rva_to_file_offset(header.data_ptr)?;

        if !self.validate_asset_pointers(name_off, header.name_len, data_off, header.data_size) {
            return Err(anyhow::anyhow!("invalid asset pointers"));
        }

        let name = self.retrieve_asset_name(name_off as usize, header.name_len as usize)?;
        let data = self.retrieve_asset_data(data_off as usize, header.data_size as usize)?;

        Ok(Asset { name, data })
    }

    fn validate_asset_pointers(
        &self,
        name_ptr: u64,
        name_len: u64,
        data_ptr: u64,
        data_size: u64,
    ) -> bool {
        let name_offset = name_ptr as usize;
        let data_offset = data_ptr as usize;

        // check if pointers are in the file range
        if name_offset >= self.mmap.len()
            || name_offset.saturating_add(name_len as usize) > self.mmap.len()
            || data_offset >= self.mmap.len()
            || data_offset.saturating_add(data_size as usize) > self.mmap.len()
        {
            return false;
        }

        // check name format
        if self.mmap[name_offset] != b'/' {
            return false;
        }

        // check brotli decompression
        let mut decompressor = brotli::Decompressor::new(
            &self.mmap[data_offset..data_offset + data_size as usize],
            data_size as usize,
        );
        let mut decompressed = Vec::new();
        decompressor.read_to_end(&mut decompressed).is_ok()
    }

    fn retrieve_asset_name(&self, offset: usize, len: usize) -> Result<String> {
        let name = self.mmap[offset..offset + len].to_vec();
        if !name.iter().all(|&b| b.is_ascii()) {
            return Err(anyhow::anyhow!("invalid name"));
        }
        let name = String::from_utf8(name)?;

        Ok(name)
    }

    fn retrieve_asset_data(&self, offset: usize, len: usize) -> Result<Vec<u8>> {
        Ok(self.mmap[offset..offset + len].to_vec())
    }

    fn decompress_asset(&self, asset: &Asset) -> Result<Vec<u8>> {
        let reader = Cursor::new(&asset.data);
        let mut decompressor = brotli::Decompressor::new(reader, asset.data.len());
        let mut decompressed = Vec::new();
        decompressor.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let file = File::open(&args.input)?;

    let dumper = Dumper::new(file)?;

    println!("Scanning for assets...");
    let assets = dumper.heuristic_search_assets()?;
    println!("Scanning completed. Found {} assets", assets.len());

    if assets.is_empty() {
        return Err(anyhow::anyhow!("No assets found"));
    }

    // dump assets
    for asset in assets {
        let decompressed = dumper.decompress_asset(&asset)?;

        // remove starts with /
        let path = Path::new(&args.output).join(&asset.name[1..]);
        // create parent directory if not exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        println!("Dump asset: {}", asset.name);
        fs::write(path, decompressed)?;
    }

    println!("Done :)");

    Ok(())
}
