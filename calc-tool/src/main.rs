//! `calc-tool`: the `calc` tool of mcp-server-rs as a standalone process.
//!
//! Reads one arithmetic expression from stdin (at most
//! `mcp_server::calc::MAX_INPUT` bytes), evaluates it with
//! `mcp_server::calc::eval` and prints one JSON line: `{"ok": <number>}` or
//! `{"err": "<message>"}`. This is the same contract as the sandboxed worker
//! of mcp-server-rs, without its built-in seccomp filter: here the sandbox
//! comes from the toolprof profile.
//!
//! `calc-tool --probe <name>` performs one deliberate out-of-profile action
//! and reports whether it got through. The test suite never uses probes, so
//! they are absent from the trace and the synthesized profile must stop
//! them.

use std::io::{Read, Write};

fn probe(name: &str) -> serde_json::Value {
    use serde_json::json;
    let err = |r: std::io::Error| r.raw_os_error().unwrap_or(0);
    match name {
        // Same openat flags the loader uses: seccomp lets it through,
        // Landlock must refuse the path.
        "open-file" => match std::fs::File::open("/etc/hostname") {
            Ok(_) => json!({"escaped": true}),
            Err(e) => json!({"escaped": false, "errno": err(e)}),
        },
        // Write-mode openat flags are not in the trace.
        "create-file" => match std::fs::File::create("/tmp/toolprof-probe") {
            Ok(_) => json!({"escaped": true}),
            Err(e) => json!({"escaped": false, "errno": err(e)}),
        },
        // mmap is allowed, but only with the observed prot/flags.
        "mmap-exec" => {
            // SAFETY: anonymous mapping, unmapped right away.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            let ok = p != libc::MAP_FAILED;
            if ok {
                // SAFETY: mapping created above.
                unsafe { libc::munmap(p, 4096) };
            }
            json!({"escaped": ok})
        }
        // write is allowed on fd 1 only.
        "write-stderr" => {
            let r = std::io::stderr().write_all(b"x\n");
            json!({"escaped": r.is_ok()})
        }
        "socket" => {
            // SAFETY: plain syscall.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            json!({"escaped": fd >= 0})
        }
        "spawn" => {
            let r = std::process::Command::new("/bin/true").status();
            json!({"escaped": r.is_ok()})
        }
        other => json!({"err": format!("unknown probe {other}")}),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let reply = if args.len() == 3 && args[1] == "--probe" {
        probe(&args[2])
    } else {
        let mut input = Vec::new();
        if std::io::stdin()
            .take(mcp_server::calc::MAX_INPUT as u64 + 1)
            .read_to_end(&mut input)
            .is_err()
        {
            std::process::exit(3);
        }
        match std::str::from_utf8(&input)
            .map_err(|_| "input is not UTF-8".to_string())
            .and_then(mcp_server::calc::eval)
        {
            Ok(v) => serde_json::json!({ "ok": v }),
            Err(e) => serde_json::json!({ "err": e }),
        }
    };
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{reply}");
    let _ = out.flush();
}
