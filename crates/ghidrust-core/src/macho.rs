//! Minimal Mach-O 64-bit little-endian loader (hand-rolled).
//!
//! Reference: OS X ABI Mach-O File Format / `loader.h` (`mach_header_64`,
//! `LC_SEGMENT_64`, `LC_UNIXTHREAD` / `LC_MAIN`) — no LLVM/libobject crate.

use crate::error::{Error, Result};
use crate::program::{MemoryBlock, Program, SectionInfo};

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM_64: u32 = 0xcffa_edfe;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_MAIN: u32 = 0x8000_0028;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const X86_THREAD_STATE64: u32 = 4;

pub fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let m = u32::from_le_bytes(data[0..4].try_into().unwrap());
    m == MH_MAGIC_64 || m == MH_CIGAM_64
}

fn rdu32(data: &[u8], off: usize) -> Result<u32> {
    if off + 4 > data.len() {
        return Err(Error::Parse("macho trunc u32".into()));
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

fn rdu64(data: &[u8], off: usize) -> Result<u64> {
    if off + 8 > data.len() {
        return Err(Error::Parse("macho trunc u64".into()));
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

fn cstr16(data: &[u8]) -> String {
    let n = data.iter().position(|&b| b == 0).unwrap_or(data.len()).min(16);
    String::from_utf8_lossy(&data[..n]).into_owned()
}

pub fn load_macho(data: &[u8], name: impl Into<String>) -> Result<Program> {
    if !is_macho(data) {
        return Err(Error::UnsupportedFormat("not Mach-O".into()));
    }
    let magic = rdu32(data, 0)?;
    if magic != MH_MAGIC_64 {
        return Err(Error::Parse("only little-endian MH_MAGIC_64".into()));
    }
    let cputype = rdu32(data, 4)?;
    let ncmds = rdu32(data, 16)? as usize;
    let sizeofcmds = rdu32(data, 20)? as usize;
    let mut prog = Program::new(name.into(), "Mach-O 64");
    if cputype == CPU_TYPE_X86_64 {
        prog.image_base = 0x100000000;
    }
    prog.file_bytes = data.to_vec();

    let mut off = 32usize;
    let cmds_end = 32 + sizeofcmds;
    for _ in 0..ncmds {
        if off + 8 > data.len() || off + 8 > cmds_end {
            break;
        }
        let cmd = rdu32(data, off)?;
        let cmdsize = rdu32(data, off + 4)? as usize;
        if cmdsize < 8 || off + cmdsize > data.len() {
            break;
        }
        match cmd {
            LC_SEGMENT_64 => parse_segment_64(&mut prog, data, off, cmdsize)?,
            LC_UNIXTHREAD => {
                if let Some(rip) = parse_unixthread_rip(data, off, cmdsize)? {
                    prog.entry = Some(rip);
                }
            }
            LC_MAIN => {
                if off + 24 <= data.len() {
                    let entryoff = rdu64(data, off + 8)?;
                    if prog.entry.is_none() {
                        prog.entry = Some(prog.image_base.saturating_add(entryoff));
                    }
                }
            }
            _ => {}
        }
        off += cmdsize;
    }
    if prog.image_base == 0 {
        if let Some(s) = prog.sections.iter().find(|s| s.va != 0) {
            prog.image_base = s.va & !0xfff;
        }
    }
    Ok(prog)
}

fn parse_segment_64(prog: &mut Program, data: &[u8], off: usize, cmdsize: usize) -> Result<()> {
    // mach_header already skipped; segment_command_64 at off
    // cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8)
    // maxprot(4) initprot(4) nsects(4) flags(4)
    if cmdsize < 72 {
        return Ok(());
    }
    let segname = cstr16(&data[off + 8..off + 24]);
    let vmaddr = rdu64(data, off + 24)?;
    let vmsize = rdu64(data, off + 32)?;
    let fileoff = rdu64(data, off + 40)? as usize;
    let filesize = rdu64(data, off + 48)? as usize;
    let initprot = rdu32(data, off + 56 + 4)?; // skip maxprot
    let nsects = rdu32(data, off + 64)? as usize;
    if prog.image_base == 0 && vmaddr != 0 {
        prog.image_base = vmaddr;
    }
    let mut sect_off = off + 72;
    if nsects == 0 {
        let mut bytes = vec![0u8; vmsize as usize];
        let n = filesize.min(data.len().saturating_sub(fileoff)).min(bytes.len());
        if n > 0 {
            bytes[..n].copy_from_slice(&data[fileoff..fileoff + n]);
        }
        prog.sections.push(SectionInfo {
            name: segname.clone(),
            va: vmaddr,
            virtual_size: vmsize,
            raw_size: filesize as u64,
            file_offset: fileoff as u64,
            characteristics: initprot,
        });
        prog.blocks.push(MemoryBlock {
            name: segname,
            va: vmaddr,
            size: vmsize,
            bytes,
            readable: initprot & 1 != 0,
            writable: initprot & 2 != 0,
            executable: initprot & 4 != 0,
        });
        return Ok(());
    }
    for _ in 0..nsects {
        if sect_off + 80 > off + cmdsize || sect_off + 80 > data.len() {
            break;
        }
        let sectname = cstr16(&data[sect_off..sect_off + 16]);
        let _seg = cstr16(&data[sect_off + 16..sect_off + 32]);
        let addr = rdu64(data, sect_off + 32)?;
        let size = rdu64(data, sect_off + 40)?;
        let soff = rdu32(data, sect_off + 48)? as usize;
        let flags = rdu32(data, sect_off + 64)?;
        let mut bytes = vec![0u8; size as usize];
        let n = (size as usize).min(data.len().saturating_sub(soff));
        if soff != 0 && n > 0 {
            bytes[..n].copy_from_slice(&data[soff..soff + n]);
        }
        let name = if sectname.is_empty() {
            segname.clone()
        } else {
            format!("{segname},{sectname}")
        };
        prog.sections.push(SectionInfo {
            name: name.clone(),
            va: addr,
            virtual_size: size,
            raw_size: size,
            file_offset: soff as u64,
            characteristics: flags,
        });
        prog.blocks.push(MemoryBlock {
            name,
            va: addr,
            size,
            bytes,
            readable: true,
            writable: flags & 0x1 == 0, // S_REGULAR writable-ish; keep honest defaults
            executable: flags & 0x80000000 != 0 || segname == "__TEXT",
        });
        sect_off += 80;
    }
    Ok(())
}

fn parse_unixthread_rip(data: &[u8], off: usize, cmdsize: usize) -> Result<Option<u64>> {
    // cmd, cmdsize, flavor, count, then 21×u64 for x86_THREAD_STATE64
    // rip is the 16th qword (0-based index 16)
    if cmdsize < 16 {
        return Ok(None);
    }
    let flavor = rdu32(data, off + 8)?;
    if flavor != X86_THREAD_STATE64 {
        return Ok(None);
    }
    let state = off + 16;
    let rip_off = state + 16 * 8;
    if rip_off + 8 > off + cmdsize || rip_off + 8 > data.len() {
        return Ok(None);
    }
    Ok(Some(rdu64(data, rip_off)?))
}

/// Tiny x86-64 MH_EXECUTE with `__TEXT,__text` containing `ret` at entry.
pub fn tiny_x64_bytes() -> Vec<u8> {
    // header 32 + LC_SEGMENT_64 (72+80=152) + LC_UNIXTHREAD (16+168=184) = 368
    // text at file offset 0x180 (384), vmaddr 0x100000180
    const HDR: usize = 32;
    const SEG: usize = 152;
    const THR: usize = 184;
    const TEXT_OFF: usize = 0x180;
    const VM: u64 = 0x100000000;
    const TEXT_VA: u64 = VM + TEXT_OFF as u64;
    let mut b = vec![0u8; TEXT_OFF + 16];
    // mach_header_64
    b[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    b[4..8].copy_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
    b[8..12].copy_from_slice(&3u32.to_le_bytes()); // ALL
    b[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
    b[16..20].copy_from_slice(&2u32.to_le_bytes()); // ncmds
    b[20..24].copy_from_slice(&((SEG + THR) as u32).to_le_bytes());
    b[24..28].copy_from_slice(&1u32.to_le_bytes()); // MH_NOUNDEFS
    // LC_SEGMENT_64
    let mut o = HDR;
    b[o..o + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    b[o + 4..o + 8].copy_from_slice(&(SEG as u32).to_le_bytes());
    b[o + 8..o + 16].copy_from_slice(b"__TEXT\0\0");
    b[o + 24..o + 32].copy_from_slice(&VM.to_le_bytes());
    b[o + 32..o + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    b[o + 40..o + 48].copy_from_slice(&0u64.to_le_bytes());
    b[o + 48..o + 56].copy_from_slice(&(TEXT_OFF as u64 + 16).to_le_bytes());
    b[o + 56..o + 60].copy_from_slice(&7u32.to_le_bytes()); // maxprot rwx
    b[o + 60..o + 64].copy_from_slice(&5u32.to_le_bytes()); // initprot rx
    b[o + 64..o + 68].copy_from_slice(&1u32.to_le_bytes()); // nsects
    o += 72;
    // section_64
    b[o..o + 6].copy_from_slice(b"__text");
    b[o + 16..o + 22].copy_from_slice(b"__TEXT");
    b[o + 32..o + 40].copy_from_slice(&TEXT_VA.to_le_bytes());
    b[o + 40..o + 48].copy_from_slice(&16u64.to_le_bytes());
    b[o + 48..o + 52].copy_from_slice(&(TEXT_OFF as u32).to_le_bytes());
    b[o + 64..o + 68].copy_from_slice(&0x8000_0400u32.to_le_bytes()); // S_ATTR_PURE_INSTRUCTIONS|SOME_INSTRUCTIONS
    // LC_UNIXTHREAD
    o = HDR + SEG;
    b[o..o + 4].copy_from_slice(&LC_UNIXTHREAD.to_le_bytes());
    b[o + 4..o + 8].copy_from_slice(&(THR as u32).to_le_bytes());
    b[o + 8..o + 12].copy_from_slice(&X86_THREAD_STATE64.to_le_bytes());
    b[o + 12..o + 16].copy_from_slice(&42u32.to_le_bytes()); // count in u32
    let rip_off = o + 16 + 16 * 8;
    b[rip_off..rip_off + 8].copy_from_slice(&TEXT_VA.to_le_bytes());
    b[TEXT_OFF] = 0xC3; // ret
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiny_fixture_loads_sections_and_entry() {
        let bytes = tiny_x64_bytes();
        assert!(is_macho(&bytes));
        let dest = crate::fixture_path("tiny_x64.macho");
        if !dest.is_file() {
            let _ = std::fs::write(&dest, &bytes);
        }
        let p = load_macho(&bytes, "tiny_x64.macho").expect("load");
        assert_eq!(p.format, "Mach-O 64");
        assert!(!p.sections.is_empty(), "sections");
        let entry = p.entry.expect("entry");
        assert!(entry > 0);
        let b = p.read_va(entry, 1).expect("text byte");
        assert_eq!(b[0], 0xC3);
        let via_path = crate::load_path(&dest).expect("load_path macho");
        assert_eq!(via_path.format, "Mach-O 64");
        assert!(via_path.entry.is_some());
        assert!(!via_path.sections.is_empty());
    }
}
