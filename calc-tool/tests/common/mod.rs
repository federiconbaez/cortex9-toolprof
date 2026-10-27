//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub const SIGSYS: i32 = 31;
pub const EACCES: i64 = 13;

pub fn calc_tool() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_calc-tool"))
}

pub fn calc_suite() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_calc-suite"))
}

/// The `toolprof` binary of the same build profile. `cargo test` does not
/// build binaries of other packages, so run `cargo build --workspace --bins`
/// first (CI does); a missing binary is a failure, not a skip.
pub fn toolprof() -> PathBuf {
    let p = calc_tool().with_file_name("toolprof");
    assert!(
        p.is_file(),
        "{} not built: run `cargo build --workspace --bins` before the tests",
        p.display()
    );
    p
}

pub fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

pub fn cases() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("cases.tsv")
}

pub fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("toolprof-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run `calc-tool --probe NAME` under `profile`.
pub fn probe(profile: &Path, name: &str) -> Output {
    Command::new(toolprof())
        .args(["run", "-p"])
        .arg(profile)
        .arg("--")
        .arg(calc_tool())
        .args(["--probe", name])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap()
}

/// `true` when the probe was stopped: killed by SIGSYS, or it reports that
/// it did not escape.
pub fn stopped(o: &Output) -> (bool, String) {
    if o.status.signal() == Some(SIGSYS) {
        return (true, "SIGSYS".into());
    }
    let v: serde_json::Value = match serde_json::from_slice(&o.stdout) {
        Ok(v) => v,
        Err(_) => return (false, format!("status {:?}, no reply", o.status)),
    };
    let escaped = v["escaped"].as_bool().unwrap_or(true);
    (!escaped, v.to_string())
}

/// Run the suite through `cmd`; returns the parsed summary.
pub fn suite(args: &[&str], cmd: &[&std::ffi::OsStr]) -> serde_json::Value {
    let o = Command::new(calc_suite())
        .args(args)
        .arg("--")
        .args(cmd)
        .output()
        .unwrap();
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("suite output: {e}: {}", String::from_utf8_lossy(&o.stdout)))
}
