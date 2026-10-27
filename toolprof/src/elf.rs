//! Program interpreter of an executable.
//!
//! When the kernel runs a dynamically linked ELF it also opens the
//! interpreter named in `PT_INTERP` (e.g. `ld-linux-x86-64.so.2`) for
//! execution, without any syscall from userspace that a tracer could see.
//! Landlock checks that open, so the interpreter needs the same rights as
//! the program. For `#!` scripts the interpreter is the first word of the
//! shebang line.

use std::io::Read;
use std::path::Path;

const PT_INTERP: u32 = 3;

/// Interpreter of the executable at `path`, if any.
pub fn interpreter(path: &Path) -> std::io::Result<Option<String>> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.by_ref().take(1 << 20).read_to_end(&mut buf)?;
    Ok(interpreter_of(&buf))
}

/// Same as [`interpreter`] on the first bytes of a file.
pub fn interpreter_of(b: &[u8]) -> Option<String> {
    if let Some(rest) = b.strip_prefix(b"#!") {
        let line = rest.split(|&c| c == b'\n').next()?;
        let s = String::from_utf8_lossy(line);
        return s.split_whitespace().next().map(str::to_owned);
    }
    // ELF64, little endian.
    if b.len() < 64 || &b[..4] != b"\x7fELF" || b[4] != 2 || b[5] != 1 {
        return None;
    }
    let u16_at = |o: usize| b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]));
    let u32_at = |o: usize| {
        b.get(o..o + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    };
    let u64_at = |o: usize| {
        b.get(o..o + 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    };
    let phoff = u64_at(0x20)? as usize;
    let phentsize = u16_at(0x36)? as usize;
    let phnum = u16_at(0x38)? as usize;
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if u32_at(ph)? != PT_INTERP {
            continue;
        }
        let off = u64_at(ph + 8)? as usize;
        let size = u64_at(ph + 32)? as usize;
        let raw = b.get(off..off.checked_add(size)?)?;
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        return Some(String::from_utf8_lossy(&raw[..end]).into_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_with_interp(interp: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes());
        // phdr 0: PT_LOAD, phdr 1: PT_INTERP at 0x100
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        let p = 64 + 56;
        b[p..p + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0x100u64.to_le_bytes());
        b[p + 32..p + 40].copy_from_slice(&(interp.len() as u64 + 1).to_le_bytes());
        b[0x100..0x100 + interp.len()].copy_from_slice(interp);
        b
    }

    #[test]
    fn finds_pt_interp() {
        let b = elf_with_interp(b"/lib64/ld-linux-x86-64.so.2");
        assert_eq!(
            interpreter_of(&b).as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
    }

    #[test]
    fn static_elf_and_garbage_have_none() {
        let mut b = elf_with_interp(b"/x");
        b[64 + 56..64 + 60].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(interpreter_of(&b), None);
        assert_eq!(interpreter_of(b"hello"), None);
        let mut short = elf_with_interp(b"/x");
        short.truncate(0x90);
        assert_eq!(interpreter_of(&short), None);
    }

    #[test]
    fn shebang() {
        assert_eq!(
            interpreter_of(b"#!/bin/sh -e\necho").as_deref(),
            Some("/bin/sh")
        );
    }

    #[test]
    fn host_binary_has_an_interpreter_or_is_static() {
        // /proc/self/exe is this test binary; dynamically linked on glibc.
        let i = interpreter(Path::new("/proc/self/exe")).unwrap();
        if let Some(p) = i {
            assert!(p.starts_with('/'), "{p}");
        }
    }
}
