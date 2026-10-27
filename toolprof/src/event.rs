//! Trace events as read from JSON lines.
//!
//! The format is the `-f json` output of `cortex9-tracer` (fields `pid`,
//! `tid`, `comm`, `nr`, `syscall`, `args`, `ret`, ...) plus the optional
//! fields written by `toolprof trace`: `path`, `path_truncated`,
//! `path_fault` and `noreturn`. A plain `cortex9-tracer` trace is accepted
//! too; it just yields no Landlock rules.

use serde::Deserialize;
use std::io::BufRead;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TraceEvent {
    pub pid: u32,
    #[serde(default)]
    pub tid: u32,
    pub comm: String,
    pub nr: u32,
    #[serde(default)]
    pub syscall: Option<String>,
    pub args: [u64; 6],
    pub ret: i64,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_truncated: bool,
    #[serde(default)]
    pub path_fault: bool,
    #[serde(default)]
    pub noreturn: bool,
}

impl TraceEvent {
    /// `true` when `ret` encodes an error (`-4095..=-1`).
    pub fn failed(&self) -> bool {
        (-4095..=-1).contains(&self.ret)
    }
}

/// Parse a JSON-lines trace. Blank lines are skipped; any other line that
/// does not parse is an error with its line number.
pub fn parse<R: BufRead>(r: R) -> Result<Vec<TraceEvent>, String> {
    let mut out = Vec::new();
    for (i, line) in r.lines().enumerate() {
        let line = line.map_err(|e| format!("line {}: {e}", i + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let e: TraceEvent =
            serde_json::from_str(&line).map_err(|e| format!("line {}: {e}", i + 1))?;
        out.push(e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_plain_tracer_output() {
        let line = r#"{"ts_ns":1,"rel_ns":1,"pid":7,"tid":7,"uid":1000,"comm":"cat","nr":257,"syscall":"openat","args":[4294967196,140000,524288,0,0,0],"ret":-2,"errno":"ENOENT","duration_ns":900,"in_pidns":true}"#;
        let v = parse(line.as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].syscall.as_deref(), Some("openat"));
        assert!(v[0].failed());
        assert_eq!(v[0].path, None);
    }

    #[test]
    fn reads_toolprof_extensions() {
        let line = r#"{"pid":7,"comm":"t","nr":231,"args":[0,0,0,0,0,0],"ret":0,"noreturn":true}
{"pid":7,"comm":"t","nr":257,"args":[1,2,3,4,5,6],"ret":3,"path":"/etc/x"}"#;
        let v = parse(line.as_bytes()).unwrap();
        assert!(v[0].noreturn);
        assert_eq!(v[1].path.as_deref(), Some("/etc/x"));
        assert!(!v[1].failed());
    }

    #[test]
    fn reports_bad_line_number() {
        let err = parse("{}\n".as_bytes()).unwrap_err();
        assert!(err.starts_with("line 1:"), "{err}");
    }
}
