//! Enforcement without a trace (unprivileged): hand-built profiles prove
//! that `toolprof run` really installs Landlock and a seccomp filter with
//! argument conditions before the tool starts.
#![cfg(target_os = "linux")]

mod common;
use common::*;
use cortex9_tracer::syscalls::Arch;
use std::ffi::OsStr;
use std::path::Path;
use toolprof::argspec::Width;
use toolprof::profile::*;

/// Every syscall of the host table except `deny`, with optional
/// conditions; Landlock: read+execute everywhere, nothing else.
fn broad_profile(deny: &[&str], conditioned: Vec<SyscallRule>) -> Profile {
    let arch = Arch::host().expect("syscall table");
    let mut syscalls: Vec<SyscallRule> = arch
        .entries()
        .filter(|(_, n)| !deny.contains(n) && !conditioned.iter().any(|c| c.name == *n))
        .map(|(nr, n)| SyscallRule {
            name: n.into(),
            nr,
            rules: vec![],
        })
        .collect();
    syscalls.extend(conditioned);
    Profile {
        version: FORMAT_VERSION,
        tool: vec!["calc-tool".into()],
        seccomp: Seccomp {
            arch: arch.to_string(),
            syscalls,
        },
        landlock: Landlock {
            fs: vec![FsRule {
                path: "/".into(),
                access: vec![FsAccess::ReadFile, FsAccess::ReadDir, FsAccess::Execute],
            }],
            deny_tcp: true,
            scope: true,
        },
    }
}

fn masked_zero(arg: u8, mask: u64) -> Vec<Cond> {
    vec![Cond {
        arg,
        width: Width::Dword,
        op: Op::MaskedEq { mask },
        value: 0,
    }]
}

fn write_profile(tag: &str, p: &Profile) -> std::path::PathBuf {
    let d = tmpdir(tag);
    let f = d.join("profile.json");
    std::fs::write(&f, p.to_json()).unwrap();
    f
}

fn nr(name: &str) -> u32 {
    Arch::host().unwrap().number(name).unwrap()
}

#[test]
fn broad_profile_keeps_the_suite_green() {
    let f = write_profile("broad", &broad_profile(&["socket"], vec![]));
    let tp = toolprof();
    let cmd: Vec<&OsStr> = vec![
        tp.as_os_str(),
        OsStr::new("run"),
        OsStr::new("-p"),
        f.as_os_str(),
        OsStr::new("--"),
        calc_tool_os(),
    ];
    let s = suite(&["--cases", cases().to_str().unwrap()], &cmd);
    assert_eq!(s["failed"], 0, "{s}");
    assert_eq!(s["cases"], s["passed"]);
}

fn calc_tool_os() -> &'static OsStr {
    Box::leak(calc_tool().into_os_string().into_boxed_os_str())
}

#[test]
fn missing_syscall_is_killed_with_sigsys() {
    let f = write_profile("deny", &broad_profile(&["socket"], vec![]));
    let o = probe(&f, "socket");
    assert_eq!(stopped(&o), (true, "SIGSYS".into()));
}

#[test]
fn landlock_refuses_writes_outside_the_rules() {
    let f = write_profile("ll", &broad_profile(&[], vec![]));
    let o = probe(&f, "create-file");
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("reply");
    assert_eq!(v["escaped"], false, "{v}");
    assert_eq!(v["errno"].as_i64(), Some(EACCES), "{v}");
}

#[test]
fn argument_condition_blocks_anonymous_exec_mapping() {
    // mmap allowed if PROT_EXEC is clear, or if the mapping is file
    // backed (the loader maps code from files).
    let rules = vec![masked_zero(2, 0x4), masked_zero(3, 0x20)];
    let mmap = SyscallRule {
        name: "mmap".into(),
        nr: nr("mmap"),
        rules,
    };
    let f = write_profile("mmap", &broad_profile(&[], vec![mmap]));
    assert_eq!(stopped(&probe(&f, "mmap-exec")), (true, "SIGSYS".into()));
    // and the tool still works under the same filter
    let tp = toolprof();
    let cmd: Vec<&OsStr> = vec![
        tp.as_os_str(),
        OsStr::new("run"),
        OsStr::new("-p"),
        f.as_os_str(),
        OsStr::new("--"),
        calc_tool_os(),
    ];
    let s = suite(
        &["--cases", cases().to_str().unwrap(), "--part", "0/5"],
        &cmd,
    );
    assert_eq!(s["failed"], 0, "{s}");
}

#[test]
fn fd_condition_blocks_stderr() {
    let write = SyscallRule {
        name: "write".into(),
        nr: nr("write"),
        rules: vec![vec![Cond {
            arg: 0,
            width: Width::Dword,
            op: Op::Eq,
            value: 1,
        }]],
    };
    let f = write_profile("fd", &broad_profile(&[], vec![write]));
    assert_eq!(stopped(&probe(&f, "write-stderr")), (true, "SIGSYS".into()));
}

#[test]
fn errno_mode_returns_eperm_instead_of_killing() {
    let f = write_profile("errno", &broad_profile(&["socket"], vec![]));
    let o = std::process::Command::new(toolprof())
        .args(["run", "--errno", "-p"])
        .arg(&f)
        .arg("--")
        .arg(calc_tool())
        .args(["--probe", "socket"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("reply");
    assert_eq!(v["escaped"], false, "{v}");
}

#[test]
fn unconfined_probes_do_escape() {
    // Control: without toolprof the probes succeed, so the tests above
    // measure the profile and not the probes.
    for p in ["open-file", "mmap-exec", "socket"] {
        let o = std::process::Command::new(calc_tool())
            .args(["--probe", p])
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["escaped"], true, "{p}: {v}");
    }
    assert!(Path::new("/etc/hostname").exists());
}
