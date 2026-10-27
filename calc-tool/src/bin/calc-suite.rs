//! `calc-suite`: end-to-end test suite of `calc-tool`.
//!
//! ```text
//! calc-suite (--cases FILE | --fuzz N [--seed S]) [--part K/N] [--json] -- CMD...
//! ```
//!
//! Each case starts `CMD...` as a fresh process (empty environment, cwd
//! `/`, like mcp-server-rs starts its worker), writes the expression to its
//! stdin and checks the JSON reply. `CMD` is the tool itself or the tool
//! wrapped by `toolprof run`.
//!
//! Cases file: one case per line, `EXPR<TAB>EXPECTED`, where EXPECTED is a
//! number or `err`. In EXPR, `REPEAT(n,text)` expands to `text` repeated
//! `n` times. Lines starting with `#` are comments.
//!
//! Fuzzing draws random expressions from a fixed seed; the expected reply
//! is computed in-process with the same `mcp_server::calc::eval`.
//!
//! Prints a JSON summary; exit status 1 if any case failed.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SIGSYS: i32 = 31;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq)]
enum Expect {
    Num(f64),
    Err,
}

fn expand(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("REPEAT(") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 7..];
        let comma = after.find(',').expect("REPEAT(n,text)");
        // `text` is at least one byte, so `REPEAT(n,))` repeats ")".
        let close = comma + 2 + after[comma + 2..].find(')').expect("REPEAT(n,text)");
        let n: usize = after[..comma].trim().parse().expect("REPEAT count");
        out.push_str(&after[comma + 1..close].repeat(n));
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

fn parse_cases(text: &str) -> Vec<(String, Expect)> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (e, x) = l.split_once('\t').expect("EXPR<TAB>EXPECTED");
            let x = x.trim();
            let exp = if x == "err" {
                Expect::Err
            } else {
                Expect::Num(x.parse().expect("expected number or err"))
            };
            (expand(e), exp)
        })
        .collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn gen_expr(r: &mut Rng, depth: u32, out: &mut String) {
    let ws = |r: &mut Rng, out: &mut String| {
        if r.below(4) == 0 {
            out.push(' ');
        }
    };
    if depth == 0 || r.below(3) == 0 {
        match r.below(4) {
            0 => out.push_str(&format!("{}.{}", r.below(100), r.below(1000))),
            _ => out.push_str(&r.below(1000).to_string()),
        }
        return;
    }
    match r.below(5) {
        0 => {
            out.push('(');
            gen_expr(r, depth - 1, out);
            out.push(')');
        }
        1 => {
            out.push('-');
            gen_expr(r, depth - 1, out);
        }
        _ => {
            gen_expr(r, depth - 1, out);
            ws(r, out);
            out.push(['+', '-', '*', '/', '%', '^'][r.below(6) as usize]);
            ws(r, out);
            gen_expr(r, depth - 1, out);
        }
    }
}

fn fuzz_cases(n: usize, seed: u64) -> Vec<(String, Expect)> {
    let mut r = Rng(seed | 1);
    (0..n)
        .map(|_| {
            let mut s = String::new();
            match r.below(20) {
                // invalid input
                0 => {
                    s.push_str(["1 +", "2 3", "abc", "(1", "1)", "--", "1e5"][r.below(7) as usize])
                }
                // very long input (some over the 4096-byte limit)
                1 => s = "1+".repeat(1000 + r.below(1500) as usize) + "1",
                // deep nesting
                2 => {
                    let d = r.below(80) as usize;
                    s = "(".repeat(d) + "1" + &")".repeat(d);
                }
                _ => gen_expr(&mut r, 6, &mut s),
            }
            let exp = match mcp_server::calc::eval(&s) {
                Ok(v) => Expect::Num(v),
                Err(_) => Expect::Err,
            };
            (s, exp)
        })
        .collect()
}

#[derive(Debug)]
enum Outcome {
    Pass,
    Blocked,
    Fail(String),
}

fn run_case(cmd: &[String], input: &str, exp: &Expect) -> Outcome {
    let mut child = match Command::new(&cmd[0])
        .args(&cmd[1..])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Outcome::Fail(format!("spawn: {e}")),
    };
    {
        let mut stdin = child.stdin.take().expect("piped");
        let _ = stdin.write_all(input.as_bytes());
    }
    let mut stdout = child.stdout.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Outcome::Fail("timeout".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => return Outcome::Fail(e.to_string()),
        }
    };
    let out = reader.join().unwrap_or_default();
    if status.signal() == Some(SIGSYS) {
        return Outcome::Blocked;
    }
    if !status.success() {
        return Outcome::Fail(format!("status {status}"));
    }
    let v: Value = match serde_json::from_slice(&out) {
        Ok(v) => v,
        Err(e) => return Outcome::Fail(format!("bad reply: {e}")),
    };
    match (exp, v.get("ok").and_then(Value::as_f64), v.get("err")) {
        (Expect::Err, None, Some(_)) => Outcome::Pass,
        (Expect::Num(x), Some(y), None) if (x - y).abs() <= 1e-12 * x.abs().max(1.0) => {
            Outcome::Pass
        }
        _ => Outcome::Fail(format!("expected {exp:?}, got {v}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sep = args
        .iter()
        .position(|a| a == "--")
        .expect("usage: calc-suite (--cases FILE | --fuzz N [--seed S]) [--part K/N] -- CMD...");
    let (opts, cmd) = (&args[..sep], &args[sep + 1..]);
    assert!(!cmd.is_empty(), "missing CMD after --");
    let mut cases = Vec::new();
    let mut seed = 1u64;
    let mut fuzz = None;
    let mut part: Option<(usize, usize)> = None;
    let mut i = 0;
    while i < opts.len() {
        match opts[i].as_str() {
            "--cases" => {
                let text = std::fs::read_to_string(&opts[i + 1]).expect("reading cases");
                cases = parse_cases(&text);
                i += 1;
            }
            "--fuzz" => {
                fuzz = Some(opts[i + 1].parse::<usize>().expect("--fuzz N"));
                i += 1;
            }
            "--seed" => {
                seed = opts[i + 1].parse().expect("--seed S");
                i += 1;
            }
            "--part" => {
                let (k, n) = opts[i + 1].split_once('/').expect("--part K/N");
                part = Some((k.parse().unwrap(), n.parse().unwrap()));
                i += 1;
            }
            other => panic!("unknown option {other}"),
        }
        i += 1;
    }
    if let Some(n) = fuzz {
        cases = fuzz_cases(n, seed);
    }
    if let Some((k, n)) = part {
        cases = cases
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i % n == k)
            .map(|(_, c)| c)
            .collect();
    }
    assert!(!cases.is_empty(), "no cases");

    let mut passed = 0usize;
    let mut blocked = 0usize;
    let mut failures = Vec::new();
    for (input, exp) in &cases {
        match run_case(cmd, input, exp) {
            Outcome::Pass => passed += 1,
            Outcome::Blocked => {
                blocked += 1;
                failures.push(json!({"input": trunc(input), "why": "SIGSYS (seccomp)"}));
            }
            Outcome::Fail(why) => failures.push(json!({"input": trunc(input), "why": why})),
        }
    }
    let failed = cases.len() - passed;
    failures.truncate(10);
    println!(
        "{}",
        json!({
            "cases": cases.len(),
            "passed": passed,
            "failed": failed,
            "sigsys": blocked,
            "first_failures": failures,
        })
    );
    if failed > 0 {
        std::process::exit(1);
    }
}

fn trunc(s: &str) -> String {
    if s.len() > 80 {
        format!("{}... ({} bytes)", &s[..80], s.len())
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_expansion() {
        assert_eq!(expand("REPEAT(3,1+)1"), "1+1+1+1");
        assert_eq!(expand("(REPEAT(2,()1REPEAT(2,))"), "(((1))");
    }

    #[test]
    fn cases_file_format() {
        let c = parse_cases("# c\n1+1\t2\n1/0\terr\n");
        assert_eq!(
            c,
            vec![
                ("1+1".into(), Expect::Num(2.0)),
                ("1/0".into(), Expect::Err)
            ]
        );
    }

    #[test]
    fn fuzz_is_deterministic_and_mixed() {
        let a = fuzz_cases(200, 7);
        assert_eq!(a, fuzz_cases(200, 7));
        assert!(a.iter().any(|(_, e)| *e == Expect::Err));
        assert!(a.iter().any(|(_, e)| matches!(e, Expect::Num(_))));
        assert!(a.iter().any(|(s, _)| s.len() > 4096));
    }
}
