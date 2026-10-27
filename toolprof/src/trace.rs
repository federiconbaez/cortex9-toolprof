//! Loader of the toolprof eBPF program (needs root or CAP_BPF +
//! CAP_PERFMON): programs the comm filter and the path-argument table,
//! attaches the `raw_syscalls` tracepoints, runs a command, and writes one
//! JSON line per recorded syscall of the matching tasks.
//!
//! Each line is the `cortex9-tracer` JSON object (formatted by the
//! published crate) plus `path`, `path_truncated`, `path_fault` and
//! `noreturn`.

use crate::argspec::PATH_ARGS;
use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use cortex9_tracer::event::Event;
use cortex9_tracer::format::Formatter;
use cortex9_tracer::syscalls::Arch;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use toolprof_common::{
    config, maps, offsets, programs, COMM_LEN, PATH_CAP, PATH_EVENT_SIZE, PATH_FLAG_FAULT,
    PATH_FLAG_NORETURN, PATH_FLAG_PRESENT, PATH_FLAG_TRUNCATED,
};

#[cfg(embedded_ebpf)]
static EMBEDDED: Option<&[u8]> = Some(aya::include_bytes_aligned!(env!("TOOLPROF_EBPF_OBJ")));
#[cfg(not(embedded_ebpf))]
static EMBEDDED: Option<&[u8]> = None;

const DEFAULT_OBJECT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../toolprof-ebpf/target/bpfel-unknown-none/release/toolprof-ebpf"
);

pub struct TraceOptions {
    pub comms: Vec<String>,
    pub object: Option<PathBuf>,
    pub command: Vec<std::ffi::OsString>,
    /// Run the command as this uid/gid (e.g. from `SUDO_UID`).
    pub run_as: Option<(u32, u32)>,
}

pub struct TraceSummary {
    pub events: u64,
    pub dropped: u64,
    pub undecodable: u64,
    pub status: ExitStatus,
}

/// Decode the path tail of a ring buffer record.
pub fn decode_path(b: &[u8]) -> (Option<String>, u32) {
    if b.len() < PATH_EVENT_SIZE {
        return (None, 0);
    }
    let flags = u32::from_le_bytes(
        b[offsets::PATH_FLAGS..offsets::PATH_FLAGS + 4]
            .try_into()
            .unwrap(),
    );
    let len = u32::from_le_bytes(
        b[offsets::PATH_LEN..offsets::PATH_LEN + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if flags & PATH_FLAG_PRESENT == 0 {
        return (None, flags);
    }
    let raw = &b[offsets::PATH..offsets::PATH + PATH_CAP];
    let end = raw
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(raw.len())
        .min(len);
    (
        Some(String::from_utf8_lossy(&raw[..end]).into_owned()),
        flags,
    )
}

/// One output line for a decoded record.
pub fn json_line(fmt: &Formatter, e: &Event, path: Option<String>, flags: u32) -> String {
    let mut v: serde_json::Value =
        serde_json::from_str(&fmt.json(e)).expect("tracer JSON is valid");
    let o = v.as_object_mut().expect("object");
    if let Some(p) = path {
        o.insert("path".into(), p.into());
    }
    if flags & PATH_FLAG_TRUNCATED != 0 {
        o.insert("path_truncated".into(), true.into());
    }
    if flags & PATH_FLAG_FAULT != 0 {
        o.insert("path_fault".into(), true.into());
    }
    if flags & PATH_FLAG_NORETURN != 0 {
        o.insert("noreturn".into(), true.into());
    }
    v.to_string()
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer; CLOCK_MONOTONIC always exists.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn load(object: &Option<PathBuf>) -> Result<Ebpf> {
    if let Some(p) = object {
        return Ebpf::load_file(p).with_context(|| format!("loading {}", p.display()));
    }
    if let Some(bytes) = EMBEDDED {
        return Ebpf::load(bytes).context("loading embedded eBPF object");
    }
    Ebpf::load_file(DEFAULT_OBJECT)
        .with_context(|| format!("loading {DEFAULT_OBJECT} (build toolprof-ebpf or pass --object)"))
}

fn program(ebpf: &mut Ebpf, arch: Arch, comms: &[String]) -> Result<()> {
    let mut flags = 0u32;
    if !comms.is_empty() {
        let mut m: HashMap<&mut MapData, [u8; COMM_LEN], u8> =
            HashMap::try_from(ebpf.map_mut(maps::COMM_FILTER).context("COMM_FILTER")?)?;
        for c in comms {
            if c.is_empty() || c.len() >= COMM_LEN {
                bail!("comm `{c}` must be 1..=15 bytes");
            }
            let mut key = [0u8; COMM_LEN];
            key[..c.len()].copy_from_slice(c.as_bytes());
            m.insert(key, 1, 0)?;
        }
        flags |= config::FLAG_COMM_FILTER;
    }
    {
        let mut m: HashMap<&mut MapData, u32, u32> =
            HashMap::try_from(ebpf.map_mut(maps::PATH_ARG).context("PATH_ARG")?)?;
        for (name, idx) in PATH_ARGS {
            if let Some(nr) = arch.number(name) {
                m.insert(nr, *idx, 0)?;
            }
        }
    }
    let nr = |n: &str| arch.number(n).unwrap_or(u32::MAX);
    let mut cfg: Array<&mut MapData, u32> =
        Array::try_from(ebpf.map_mut(maps::CONFIG).context("CONFIG")?)?;
    cfg.set(config::FLAGS, flags, 0)?;
    cfg.set(config::SELF_TGID, std::process::id(), 0)?;
    cfg.set(config::EXECVE_NR, nr("execve"), 0)?;
    cfg.set(config::EXECVEAT_NR, nr("execveat"), 0)?;
    cfg.set(config::EXIT_NR, nr("exit"), 0)?;
    cfg.set(config::EXIT_GROUP_NR, nr("exit_group"), 0)?;
    Ok(())
}

fn attach(ebpf: &mut Ebpf, prog: &str, name: &str) -> Result<()> {
    let tp: &mut TracePoint = ebpf
        .program_mut(prog)
        .with_context(|| format!("program {prog}"))?
        .try_into()?;
    tp.load()
        .with_context(|| format!("verifier rejected {prog}"))?;
    tp.attach("raw_syscalls", name)
        .with_context(|| format!("attaching raw_syscalls/{name}"))?;
    Ok(())
}

fn dropped(ebpf: &Ebpf) -> u64 {
    ebpf.map(maps::DROPPED)
        .and_then(|m| Array::<_, u64>::try_from(m).ok())
        .and_then(|a| a.get(&0, 0).ok())
        .unwrap_or(0)
}

/// Trace `opt.command` until it exits, writing JSON lines to `out`.
pub fn run<W: Write>(opt: &TraceOptions, out: &mut W) -> Result<TraceSummary> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(trace(opt, out))
}

async fn trace<W: Write>(opt: &TraceOptions, out: &mut W) -> Result<TraceSummary> {
    let Some(arch) = Arch::host() else {
        bail!("no syscall table for this architecture")
    };
    let Some((prog, args)) = opt.command.split_first() else {
        bail!("no command to trace")
    };
    let mut ebpf = load(&opt.object)?;
    program(&mut ebpf, arch, &opt.comms)?;
    let ring = RingBuf::try_from(ebpf.take_map(maps::EVENTS).context("EVENTS map")?)?;
    attach(&mut ebpf, programs::SYS_EXIT, "sys_exit")?;
    attach(&mut ebpf, programs::SYS_ENTER, "sys_enter")?;
    let fmt = Formatter {
        arch: Some(arch),
        start_ns: monotonic_ns(),
        args: 0,
    };

    let mut cmd = Command::new(prog);
    cmd.args(args);
    if let Some((uid, gid)) = opt.run_as {
        use std::os::unix::process::CommandExt;
        cmd.uid(uid).gid(gid);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning {}", prog.to_string_lossy()))?;

    // SAFETY: the RingBuf owns its fd and keeps it open while AsyncFd lives.
    let mut ring = unsafe { AsyncFd::register(ring)? };
    let mut events = 0u64;
    let mut undecodable = 0u64;
    let mut drain = |rb: &mut RingBuf<MapData>, out: &mut W| -> Result<()> {
        while let Some(item) = rb.next() {
            match Event::decode(&item) {
                Ok(e) => {
                    let (path, flags) = decode_path(&item);
                    writeln!(out, "{}", json_line(&fmt, &e, path, flags))?;
                    events += 1;
                }
                Err(_) => undecodable += 1,
            }
        }
        Ok(())
    };
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let status = loop {
        tokio::select! {
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                drain(guard.get_inner_mut(), out)?;
                guard.clear_ready();
            }
            _ = tick.tick() => {
                if let Some(st) = child.try_wait()? {
                    break st;
                }
            }
        }
    };
    // Records submitted before the child was reaped are already in the
    // ring; read them all.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drain(ring.get_mut(), out)?;
    out.flush()?;
    Ok(TraceSummary {
        events,
        dropped: dropped(&ebpf),
        undecodable,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use toolprof_common::EVENT_SIZE;

    fn record(flags: u32, path: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; PATH_EVENT_SIZE];
        b[EVENT_SIZE..EVENT_SIZE + 4].copy_from_slice(&flags.to_le_bytes());
        b[EVENT_SIZE + 4..EVENT_SIZE + 8].copy_from_slice(&(path.len() as u32).to_le_bytes());
        b[EVENT_SIZE + 8..EVENT_SIZE + 8 + path.len()].copy_from_slice(path);
        b
    }

    #[test]
    fn path_tail() {
        let (p, f) = decode_path(&record(PATH_FLAG_PRESENT, b"/etc/ld.so.cache"));
        assert_eq!(p.as_deref(), Some("/etc/ld.so.cache"));
        assert_eq!(f, PATH_FLAG_PRESENT);
        let (p, _) = decode_path(&record(0, b"ignored"));
        assert_eq!(p, None);
        assert_eq!(decode_path(&[0u8; 120]).0, None);
    }

    #[test]
    fn json_has_tracer_fields_and_extensions() {
        let mut b = record(PATH_FLAG_PRESENT | PATH_FLAG_NORETURN, b"/x");
        b[84..88].copy_from_slice(&231u32.to_le_bytes());
        b[88..92].copy_from_slice(b"tool");
        let e = Event::decode(&b).unwrap();
        let (p, f) = decode_path(&b);
        let fmt = Formatter {
            arch: Some(Arch::X86_64),
            start_ns: 0,
            args: 0,
        };
        let v: serde_json::Value = serde_json::from_str(&json_line(&fmt, &e, p, f)).unwrap();
        assert_eq!(v["syscall"], "exit_group");
        assert_eq!(v["comm"], "tool");
        assert_eq!(v["path"], "/x");
        assert_eq!(v["noreturn"], true);
        let back = crate::event::parse(v.to_string().as_bytes()).unwrap();
        assert_eq!(back[0].nr, 231);
    }
}
