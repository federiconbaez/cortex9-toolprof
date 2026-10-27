//! Import of a Docker/moby seccomp profile (`default.json` format) as the
//! set of syscall rules it grants a container on one architecture with a
//! given capability set.
//!
//! Evaluation follows how moby turns the JSON into a filter: an entry
//! applies when every `includes` condition holds (all listed caps present,
//! arch listed, kernel >= `minKernel`) and no `excludes` condition does; its
//! `args` are AND-ed; several applicable entries for one syscall are OR-ed,
//! and an entry without `args` allows the syscall unconditionally. Only
//! `SCMP_ACT_ALLOW` entries grant anything.

use crate::argspec::Width;
use crate::profile::{Cond, Op, Seccomp, SyscallRule};
use cortex9_tracer::syscalls::Arch;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Capabilities Docker grants a container by default
/// (moby `daemon/pkg/oci/caps/defaults.go`).
pub const DEFAULT_CAPS: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

#[derive(Debug, Deserialize)]
struct File {
    syscalls: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    names: Vec<String>,
    action: String,
    #[serde(default)]
    args: Vec<Arg>,
    #[serde(default)]
    includes: Filter,
    #[serde(default)]
    excludes: Filter,
}

#[derive(Debug, Default, Deserialize)]
struct Filter {
    #[serde(default)]
    caps: Vec<String>,
    #[serde(default)]
    arches: Vec<String>,
    #[serde(default, rename = "minKernel")]
    min_kernel: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Arg {
    index: u8,
    value: u64,
    #[serde(default, rename = "valueTwo")]
    value_two: u64,
    op: String,
}

/// `(name, Some(rules))`, or `(name, None)` when allowed unconditionally.
type Granted = (String, Option<Vec<Vec<Cond>>>);

/// Result of the import.
#[derive(Debug)]
pub struct Imported {
    pub seccomp: Seccomp,
    /// Names granted by the profile that this architecture's table lacks
    /// (syscalls of other ABIs such as `_llseek` or `*_time64`).
    pub unknown_names: Vec<String>,
}

fn docker_arch(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "amd64",
        Arch::Aarch64 => "arm64",
    }
}

fn parse_kernel(s: &str) -> (u32, u32) {
    let mut it = s.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

fn op(a: &Arg) -> Result<Op, String> {
    Ok(match a.op.as_str() {
        "SCMP_CMP_EQ" => Op::Eq,
        "SCMP_CMP_NE" => Op::Ne,
        "SCMP_CMP_LT" => Op::Lt,
        "SCMP_CMP_LE" => Op::Le,
        "SCMP_CMP_GT" => Op::Gt,
        "SCMP_CMP_GE" => Op::Ge,
        "SCMP_CMP_MASKED_EQ" => Op::MaskedEq { mask: a.value },
        other => return Err(format!("unknown op {other}")),
    })
}

/// Import `json` for `arch`, granting `caps`, on a kernel `kernel`
/// (`"major.minor"`).
pub fn import(json: &str, arch: Arch, caps: &[&str], kernel: &str) -> Result<Imported, String> {
    let f: File = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let me = docker_arch(arch);
    let kv = parse_kernel(kernel);
    let mut acc: BTreeMap<u32, Granted> = BTreeMap::new();
    let mut unknown = Vec::new();
    for e in &f.syscalls {
        if e.action != "SCMP_ACT_ALLOW" {
            continue;
        }
        let inc = &e.includes;
        if !inc.caps.iter().all(|c| caps.contains(&c.as_str())) {
            continue;
        }
        if !inc.arches.is_empty() && !inc.arches.iter().any(|a| a == me) {
            continue;
        }
        if let Some(mk) = &inc.min_kernel {
            if kv < parse_kernel(mk) {
                continue;
            }
        }
        let exc = &e.excludes;
        if exc.caps.iter().any(|c| caps.contains(&c.as_str())) {
            continue;
        }
        if exc.arches.iter().any(|a| a == me) {
            continue;
        }
        let conj: Vec<Cond> = e
            .args
            .iter()
            .map(|a| {
                Ok(Cond {
                    arg: a.index,
                    width: Width::Qword,
                    op: op(a)?,
                    value: if a.op == "SCMP_CMP_MASKED_EQ" {
                        a.value_two
                    } else {
                        a.value
                    },
                })
            })
            .collect::<Result<_, String>>()?;
        for name in &e.names {
            let Some(nr) = arch.number(name) else {
                unknown.push(name.clone());
                continue;
            };
            let slot = acc
                .entry(nr)
                .or_insert_with(|| (name.clone(), Some(Vec::new())));
            match (&mut slot.1, conj.is_empty()) {
                (_, true) => slot.1 = None,
                (Some(rules), false) => rules.push(conj.clone()),
                (None, false) => {}
            }
        }
    }
    unknown.sort();
    unknown.dedup();
    Ok(Imported {
        seccomp: Seccomp {
            arch: arch.to_string(),
            syscalls: acc
                .into_iter()
                .map(|(nr, (name, rules))| SyscallRule {
                    name,
                    nr,
                    rules: rules.unwrap_or_default(),
                })
                .collect(),
        },
        unknown_names: unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
      {"names":["read","write","_llseek"],"action":"SCMP_ACT_ALLOW"},
      {"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":3,"op":"SCMP_CMP_LT"}]},
      {"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":45,"op":"SCMP_CMP_EQ"}]},
      {"names":["bpf"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}},
      {"names":["chroot"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_CHROOT"]}},
      {"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW","includes":{"arches":["amd64"]}},
      {"names":["ptrace"],"action":"SCMP_ACT_ALLOW","includes":{"minKernel":"4.8"}},
      {"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}],"excludes":{"caps":["CAP_SYS_ADMIN"]}},
      {"names":["clone3"],"action":"SCMP_ACT_ERRNO"}
    ]}"#;

    #[test]
    fn includes_excludes_and_args() {
        let i = import(SAMPLE, Arch::X86_64, DEFAULT_CAPS, "6.12").unwrap();
        let names: Vec<_> = i.seccomp.syscalls.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "read",
                "write",
                "socket",
                "clone",
                "ptrace",
                "arch_prctl",
                "chroot"
            ]
        );
        assert_eq!(i.unknown_names, ["_llseek"]);
        let sock = i
            .seccomp
            .syscalls
            .iter()
            .find(|s| s.name == "socket")
            .unwrap();
        assert_eq!(sock.rules.len(), 2);
        let clone = i
            .seccomp
            .syscalls
            .iter()
            .find(|s| s.name == "clone")
            .unwrap();
        assert_eq!(clone.rules[0][0].op, Op::MaskedEq { mask: 2114060288 });
        assert_eq!(clone.rules[0][0].value, 0);
    }

    #[test]
    fn old_kernel_and_extra_caps() {
        let i = import(SAMPLE, Arch::X86_64, &["CAP_SYS_ADMIN"], "4.4").unwrap();
        let names: Vec<_> = i.seccomp.syscalls.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"bpf"));
        assert!(!names.contains(&"ptrace"));
        assert!(!names.contains(&"clone"), "excluded when CAP_SYS_ADMIN");
        assert!(!names.contains(&"chroot"));
    }
}
