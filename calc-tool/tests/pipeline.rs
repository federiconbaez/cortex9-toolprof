//! Full pipeline on the real kernel: trace the suite with eBPF, synthesize,
//! enforce, rerun. Needs root (CAP_BPF + CAP_PERFMON), so it is `#[ignore]`
//! and runs with `sudo` as cargo runner:
//!
//! ```sh
//! CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' \
//!   cargo test --release -p calc-tool --test pipeline -- --ignored
//! ```
//!
//! Without root, or if the kernel refuses the program, the test fails.
#![cfg(target_os = "linux")]

mod common;
use common::*;
use std::ffi::OsStr;
use std::process::Command;

fn object_args() -> Vec<String> {
    match std::env::var("TOOLPROF_EBPF_OBJ") {
        Ok(p) => vec!["--object".into(), p],
        Err(_) => vec![],
    }
}

fn trace(out: &std::path::Path, suite_args: &[&str]) {
    let o = Command::new(toolprof())
        .arg("trace")
        .args(object_args())
        .args(["-c", "calc-tool", "-o"])
        .arg(out)
        .arg("--")
        .arg(calc_suite())
        .args(suite_args)
        .arg("--")
        .arg(calc_tool())
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "trace failed (root and BPF required): {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn synth(trace: &std::path::Path, profile: &std::path::Path) {
    let o = Command::new(toolprof())
        .args(["synth", "-c", "calc-tool", "-i"])
        .arg(trace)
        .arg("-o")
        .arg(profile)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

fn confined<'a>(tp: &'a std::path::Path, profile: &'a std::path::Path) -> Vec<&'a OsStr> {
    vec![
        tp.as_os_str(),
        OsStr::new("run"),
        OsStr::new("-p"),
        profile.as_os_str(),
        OsStr::new("--"),
        Box::leak(calc_tool().into_os_string().into_boxed_os_str()),
    ]
}

#[test]
#[ignore = "needs root: loads eBPF"]
fn trace_synthesize_enforce() {
    // SAFETY: plain getter.
    assert_eq!(unsafe { libc::geteuid() }, 0, "must run as root (sudo)");
    let d = tmpdir("pipeline");
    let cases = cases();
    let cases = cases.to_str().unwrap();
    let tp = toolprof();

    let full = d.join("trace.jsonl");
    trace(&full, &["--cases", cases]);
    let n = std::fs::read_to_string(&full).unwrap().lines().count();
    assert!(n > 100, "only {n} events traced");
    let profile = d.join("profile.json");
    synth(&full, &profile);

    // offline gate: nothing in the trace is blocked by its own profile
    let o = Command::new(&tp)
        .args(["diff", "-c", "calc-tool", "-p"])
        .arg(&profile)
        .arg("-i")
        .arg(&full)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));

    // 0 blocks across the suite under the synthesized profile
    let s = suite(&["--cases", cases], &confined(&tp, &profile));
    assert_eq!(s["failed"], 0, "{s}");
    assert_eq!(s["sigsys"], 0, "{s}");

    // every out-of-profile probe is stopped
    for p in [
        "open-file",
        "create-file",
        "mmap-exec",
        "write-stderr",
        "socket",
        "spawn",
    ] {
        let (ok, why) = stopped(&probe(&profile, p));
        assert!(ok, "probe {p} escaped: {why}");
    }

    // attack surface vs Docker's default profile >= 80% on both numbers
    let o = Command::new(&tp)
        .args(["surface", "--json", "-p"])
        .arg(&profile)
        .arg("--docker")
        .arg(workspace().join("data/docker-default.json"))
        .output()
        .unwrap();
    assert!(o.status.success());
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let r = &v["reductions"][0];
    assert_eq!(r["baseline"], "docker-default");
    assert!(r["syscalls"].as_f64().unwrap() >= 0.80, "{r}");
    assert!(r["weighted"].as_f64().unwrap() >= 0.80, "{r}");

    // held out: profile from half of the cases, enforced on the other half
    let half = d.join("trace-half.jsonl");
    trace(&half, &["--cases", cases, "--part", "0/2"]);
    let half_profile = d.join("profile-half.json");
    synth(&half, &half_profile);
    let s = suite(
        &["--cases", cases, "--part", "1/2"],
        &confined(&tp, &half_profile),
    );
    assert_eq!(s["failed"], 0, "held-out half: {s}");
}
