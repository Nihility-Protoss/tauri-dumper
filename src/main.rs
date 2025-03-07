use anyhow::{Result, anyhow};
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
    // !for Windows PE,
    // - .rdata section
    // !for Mach-O
    // - __DATA segment, __const section
    // - __DATA_CONST segment, __const section
    sections: Vec<SectionInfo>,
    binary_format: BinaryFormat,
}

impl Dumper {
    fn new(file: File) -> Result<Self> {
        let mmap = unsafe { Mmap::map(&file)? };
        let obj = object::File::parse(&*mmap)?;
        let binary_format = obj.format();

        // find .rdata or similar section
        let sections = match binary_format {
            BinaryFormat::Pe => obj
                .sections()
                .filter(|s| s.name() == Ok(".rdata") && s.kind() == SectionKind::ReadOnlyData)
                .map(|s| SectionInfo {
                    virtual_address: s.address(),
                    file_offset: s.file_range().unwrap().0,
                    size: s.size(),
                })
                .collect::<Vec<_>>(),
            BinaryFormat::MachO => {
                // fliter all sections with segment name,
                // seg name is __TEXT or __DATA_CONST
                // and section name is __const
                obj.sections()
                    .filter(|s| {
                        s.segment_name() == Ok(Some("__TEXT"))
                            || s.segment_name() == Ok(Some("__DATA_CONST"))
                    })
                    .filter(|s| s.name() == Ok("__const"))
                    .map(|s| SectionInfo {
                        virtual_address: s.address(),
                        file_offset: s.file_range().unwrap().0,
                        size: s.size(),
                    })
                    .collect::<Vec<_>>()
            }
            _ => unreachable!(),
        };

        Ok(Self {
            mmap,
            sections,
            binary_format,
        })
    }

    fn convert_rva_to_file_offset(&self, rva: u64) -> Result<u64> {
        // in mach-o, __TEXT,__const section inlcude assets content,
        match self.binary_format {
            BinaryFormat::MachO => {
                // *Q: only need low 48 bits of the pointer
                // *A: high 16 bits has another meaning in mach-o
                return Ok(rva & 0xFFFFFFFFFFFF);
            }
            BinaryFormat::Pe => {
                let Some(ref section) = self.sections.first() else {
                    return Err(anyhow::anyhow!("RDATA section not found"));
                };

                // check if rva is in the target section
                if rva >= section.virtual_address && rva < section.virtual_address + section.size {
                    return Ok(rva - section.virtual_address + section.file_offset);
                }
            }
            _ => unreachable!(),
        }

        Err(anyhow::anyhow!("RVA is not in rdata section"))
    }

    fn heuristic_search_assets(&self) -> Result<Vec<Asset>> {
        // get start offset and scan length
        let (scan_start, scan_length) = match self.binary_format {
            BinaryFormat::Pe => {
                let section = self.sections.first().expect("RDATA section not found");
                (section.file_offset as usize, section.size as usize)
            }
            BinaryFormat::MachO => {
                // search range always in __DATA_CONST,__const section
                let section = self
                    .sections
                    .last()
                    .expect("__DATA_CONST section not found");
                (section.file_offset as usize, section.size as usize)
            }
            _ => panic!("Unsupported binary format"),
        };

        let end_offset = scan_start.saturating_add(scan_length);
        assert!(end_offset <= self.mmap.len(), "end_offset is out of range");
        
        let mut assets = Vec::new();
        let mut offset = scan_start;
        let mut scan_step = 8; // TODO: detect PE/Mach-O file format to determine pointer size
        while offset + ASSET_HEADER_SIZE <= end_offset {
            if let Ok(asset) = self.parse_asset(offset) {
                // println!("Found asset at offset 0x{:x}: {}", offset, String::from_utf8_lossy(&asset.name));
                assets.push(asset);
                scan_step = ASSET_HEADER_SIZE;
            }

            offset += scan_step;
        }

        Ok(assets)
    }

    fn parse_asset(&self, offset: usize) -> Result<Asset> {
        if offset + ASSET_HEADER_SIZE > self.mmap.len() {
            return Err(anyhow!("offset is out of range"));
        }

        let chunk = &self.mmap[offset..offset + ASSET_HEADER_SIZE];

        let header = unsafe { &*(chunk.as_ptr() as *const AssetHeader) };

        let name_off = self.convert_rva_to_file_offset(header.name_ptr)?;
        let data_off = self.convert_rva_to_file_offset(header.data_ptr)?;

        if !self.validate_asset_pointers(name_off, header.name_len, data_off, header.data_size) {
            return Err(anyhow!("invalid asset pointers"));
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
            return Err(anyhow!("invalid name"));
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
        return Err(anyhow!("No assets found"));
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

        println!("Dump asset: {}, size: {:#X}", asset.name, asset.data.len());
        fs::write(path, decompressed)?;
    }

    println!("Done :)");

    Ok(())
}
