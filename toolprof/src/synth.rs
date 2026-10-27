//! Profile synthesis from a trace.

use crate::argspec::{self, Kind, AT_FDCWD_DWORD};
use crate::event::TraceEvent;
use crate::profile::{
    Cond, FsAccess, FsRule, Landlock, Op, Profile, Seccomp, SyscallRule, FORMAT_VERSION,
};
use cortex9_tracer::syscalls::Arch;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Options {
    /// Keep only events of these `comm` values (empty: all).
    pub comms: Vec<String>,
    /// Working directory used to resolve relative paths with `AT_FDCWD`.
    pub cwd: PathBuf,
    /// An argument keeps its condition only if it took at most this many
    /// distinct values.
    pub max_variants: usize,
    /// Upper bound on rules (value tuples) per syscall; past it the
    /// argument with most distinct values is dropped.
    pub max_rules: usize,
    pub arch: Arch,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            comms: Vec::new(),
            cwd: PathBuf::from("/"),
            max_variants: 16,
            max_rules: 32,
            arch: Arch::host().unwrap_or(Arch::X86_64),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DroppedArg {
    pub arg: &'static str,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SyscallReport {
    pub name: String,
    pub nr: u32,
    pub calls: usize,
    pub failed: usize,
    pub conditioned_args: Vec<&'static str>,
    pub dropped_args: Vec<DroppedArg>,
    pub rules: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub events_total: usize,
    pub events_used: usize,
    pub processes: usize,
    pub syscalls: Vec<SyscallReport>,
    pub fs_rules: usize,
    /// Paths that could not be turned into a rule, with the reason.
    pub unresolved_paths: Vec<String>,
    /// Observed path operations Landlock cannot restrict (stat, access...).
    pub unrestrictable_path_ops: BTreeMap<String, usize>,
    pub notes: Vec<String>,
}

fn name_of(e: &TraceEvent, arch: Arch) -> String {
    e.syscall
        .clone()
        .or_else(|| arch.name(e.nr).map(str::to_owned))
        .unwrap_or_else(|| format!("syscall_{}", e.nr))
}

/// Synthesize a profile from `events`.
pub fn synthesize(events: &[TraceEvent], opt: &Options) -> (Profile, Report) {
    let used: Vec<&TraceEvent> = events
        .iter()
        .filter(|e| opt.comms.is_empty() || opt.comms.contains(&e.comm))
        .collect();
    let mut report = Report {
        events_total: events.len(),
        events_used: used.len(),
        processes: used.iter().map(|e| e.pid).collect::<BTreeSet<_>>().len(),
        ..Default::default()
    };

    let mut by_nr: BTreeMap<u32, Vec<&TraceEvent>> = BTreeMap::new();
    for e in &used {
        by_nr.entry(e.nr).or_default().push(e);
    }

    let mut syscalls = Vec::new();
    for (nr, evs) in &by_nr {
        let name = name_of(evs[0], opt.arch);
        let (rule, rep) = synth_syscall(*nr, &name, evs, opt);
        syscalls.push(rule);
        report.syscalls.push(rep);
    }

    let landlock = synth_landlock(&used, opt, &mut report);
    report.fs_rules = landlock.fs.len();

    let mut tool: Vec<String> = if opt.comms.is_empty() {
        used.iter()
            .map(|e| e.comm.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        opt.comms.clone()
    };
    tool.sort();
    tool.dedup();

    let profile = Profile {
        version: FORMAT_VERSION,
        tool,
        seccomp: Seccomp {
            arch: opt.arch.to_string(),
            syscalls,
        },
        landlock,
    };
    (profile, report)
}

fn synth_syscall(
    nr: u32,
    name: &str,
    evs: &[&TraceEvent],
    opt: &Options,
) -> (SyscallRule, SyscallReport) {
    let specs = argspec::specs(name);
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for s in specs {
        let values: BTreeSet<u64> = evs
            .iter()
            .map(|e| s.width.mask(e.args[s.index as usize]))
            .collect();
        let stable = match s.kind {
            Kind::Fd => values.iter().all(|&v| v <= 2),
            Kind::DirFd => values.iter().all(|&v| v == AT_FDCWD_DWORD),
            Kind::Flags => values.len() <= opt.max_variants,
        };
        if stable {
            kept.push((*s, values.len()));
        } else {
            let reason = match s.kind {
                Kind::Fd => format!("fd values beyond 0-2 ({} distinct)", values.len()),
                Kind::DirFd => "dirfd other than AT_FDCWD".to_string(),
                Kind::Flags => format!(
                    "{} distinct values > max_variants {}",
                    values.len(),
                    opt.max_variants
                ),
            };
            dropped.push(DroppedArg {
                arg: s.name,
                reason,
            });
        }
    }

    let tuples = |kept: &[(argspec::ArgSpec, usize)]| -> BTreeSet<Vec<u64>> {
        evs.iter()
            .map(|e| {
                kept.iter()
                    .map(|(s, _)| s.width.mask(e.args[s.index as usize]))
                    .collect()
            })
            .collect()
    };
    let mut set = tuples(&kept);
    while !kept.is_empty() && set.len() > opt.max_rules {
        let (i, _) = kept
            .iter()
            .enumerate()
            .max_by_key(|(_, (_, n))| *n)
            .expect("non-empty");
        let (s, n) = kept.remove(i);
        dropped.push(DroppedArg {
            arg: s.name,
            reason: format!(
                "{n} values; value tuples exceeded max_rules {}",
                opt.max_rules
            ),
        });
        set = tuples(&kept);
    }

    let rules: Vec<Vec<Cond>> = if kept.is_empty() {
        Vec::new()
    } else {
        set.iter()
            .map(|t| {
                kept.iter()
                    .zip(t)
                    .map(|((s, _), &v)| Cond {
                        arg: s.index,
                        width: s.width,
                        op: Op::Eq,
                        value: v,
                    })
                    .collect()
            })
            .collect()
    };
    let rep = SyscallReport {
        name: name.to_owned(),
        nr,
        calls: evs.len(),
        failed: evs.iter().filter(|e| e.failed()).count(),
        conditioned_args: kept.iter().map(|(s, _)| s.name).collect(),
        dropped_args: dropped,
        rules: rules.len(),
    };
    (
        SyscallRule {
            name: name.to_owned(),
            nr,
            rules,
        },
        rep,
    )
}

/// Lexical normalization: drops `.` and empty components, applies `..`.
pub fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
            Component::Prefix(_) => {}
        }
    }
    out
}

const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;
const O_DIRECTORY: u64 = 0x10000;
const O_PATH: u64 = 0x200000;
const AT_REMOVEDIR: u64 = 0x200;

fn synth_landlock(used: &[&TraceEvent], opt: &Options, report: &mut Report) -> Landlock {
    let mut rights: BTreeMap<PathBuf, BTreeSet<FsAccess>> = BTreeMap::new();
    let mut grant = |p: PathBuf, a: &[FsAccess]| {
        rights.entry(p).or_default().extend(a.iter().copied());
    };
    let mut net_seen = false;
    let mut foreign_signal = false;
    for e in used {
        let name = name_of(e, opt.arch);
        match name.as_str() {
            "socket" => {
                let domain = e.args[0] & 0xffff_ffff;
                if domain == 2 || domain == 10 {
                    net_seen = true;
                }
            }
            "connect" | "bind" | "sendto" | "sendmsg" => net_seen = true,
            "kill" | "tgkill" if (e.args[0] & 0xffff_ffff) as u32 != e.pid => foreign_signal = true,
            _ => {}
        }
        let Some(raw) = e.path.as_deref() else {
            continue;
        };
        let idx = argspec::PATH_ARGS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, i)| *i);
        let Some(idx) = idx else { continue };
        if e.path_truncated || e.path_fault {
            report
                .unresolved_paths
                .push(format!("{name}: {raw} (truncated or unreadable)"));
            continue;
        }
        let at_variant = idx == 1 && name != "symlink";
        let resolved = if raw.starts_with('/') {
            Some(PathBuf::from(raw))
        } else if !at_variant || (e.args[0] & 0xffff_ffff) == AT_FDCWD_DWORD {
            Some(opt.cwd.join(raw))
        } else {
            None
        };
        let Some(p) = resolved.map(|p| normalize(&p)) else {
            report
                .unresolved_paths
                .push(format!("{name}: {raw} (relative to a dirfd)"));
            continue;
        };
        if e.failed() {
            // A failed lookup (ENOENT...) needs no right; Landlock reports
            // missing files as missing.
            continue;
        }
        let parent = || {
            p.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| p.clone())
        };
        match name.as_str() {
            "open" | "openat" | "creat" => {
                let flags = match name.as_str() {
                    "open" => e.args[1],
                    "openat" => e.args[2],
                    _ => O_CREAT | O_TRUNC | 1,
                };
                if flags & O_PATH != 0 {
                    continue;
                }
                let is_dir = flags & O_DIRECTORY != 0 || p.is_dir();
                let mut a = Vec::new();
                match flags & O_ACCMODE {
                    0 => a.push(if is_dir {
                        FsAccess::ReadDir
                    } else {
                        FsAccess::ReadFile
                    }),
                    1 => a.push(FsAccess::WriteFile),
                    _ => a.extend([FsAccess::ReadFile, FsAccess::WriteFile]),
                }
                if flags & O_TRUNC != 0 {
                    a.push(FsAccess::Truncate);
                }
                if flags & O_CREAT != 0 {
                    grant(parent(), &[FsAccess::MakeReg]);
                }
                grant(p.clone(), &a);
            }
            "openat2" => {
                report.notes.push(format!(
                    "openat2 flags live in a struct (not traced); granted read on {}",
                    p.display()
                ));
                grant(
                    p.clone(),
                    &[if p.is_dir() {
                        FsAccess::ReadDir
                    } else {
                        FsAccess::ReadFile
                    }],
                );
            }
            "execve" | "execveat" => {
                grant(p.clone(), &[FsAccess::Execute, FsAccess::ReadFile]);
                match crate::elf::interpreter(&p) {
                    Ok(Some(i)) => grant(
                        normalize(Path::new(&i)),
                        &[FsAccess::Execute, FsAccess::ReadFile],
                    ),
                    Ok(None) => {}
                    Err(err) => report.notes.push(format!(
                        "could not read {} for its interpreter: {err}",
                        p.display()
                    )),
                }
            }
            "mkdir" | "mkdirat" => grant(parent(), &[FsAccess::MakeDir]),
            "unlink" => grant(parent(), &[FsAccess::RemoveFile]),
            "unlinkat" => grant(
                parent(),
                &[if e.args[2] & AT_REMOVEDIR != 0 {
                    FsAccess::RemoveDir
                } else {
                    FsAccess::RemoveFile
                }],
            ),
            "rmdir" => grant(parent(), &[FsAccess::RemoveDir]),
            "truncate" => grant(p.clone(), &[FsAccess::Truncate]),
            "rename" | "renameat" | "renameat2" | "link" | "symlink" => {
                report.unresolved_paths.push(format!(
                    "{name}: {} (two-path operation, not synthesized)",
                    p.display()
                ));
            }
            other => {
                *report
                    .unrestrictable_path_ops
                    .entry(other.to_owned())
                    .or_default() += 1;
            }
        }
    }
    if net_seen {
        report
            .notes
            .push("TCP/UDP activity observed: Landlock network rules not synthesized".into());
    }
    if foreign_signal {
        report
            .notes
            .push("signal to another process observed: Landlock scoping disabled".into());
    }
    Landlock {
        fs: rights
            .into_iter()
            .map(|(p, a)| FsRule {
                path: p.to_string_lossy().into_owned(),
                access: a.into_iter().collect(),
            })
            .collect(),
        deny_tcp: !net_seen,
        scope: !foreign_signal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(nr: u32, name: &str, args: [u64; 6], ret: i64, path: Option<&str>) -> TraceEvent {
        TraceEvent {
            pid: 10,
            tid: 10,
            comm: "tool".into(),
            nr,
            syscall: Some(name.into()),
            args,
            ret,
            path: path.map(str::to_owned),
            path_truncated: false,
            path_fault: false,
            noreturn: false,
        }
    }

    fn opts() -> Options {
        Options {
            arch: Arch::X86_64,
            ..Default::default()
        }
    }

    #[test]
    fn stable_flags_become_eq_rules() {
        let evs = vec![
            ev(9, "mmap", [0, 4096, 3, 0x22, u64::MAX, 0], 1, None),
            ev(9, "mmap", [0, 8192, 3, 0x22, u64::MAX, 0], 1, None),
            ev(9, "mmap", [0, 4096, 1, 0x802, 3, 0], 1, None),
        ];
        let (p, r) = synthesize(&evs, &opts());
        let m = p.syscall(9).unwrap();
        assert_eq!(m.rules.len(), 2);
        assert!(crate::eval::allows(&p, 9, &[0, 1, 3, 0x22, 0, 0]));
        assert!(!crate::eval::allows(&p, 9, &[0, 1, 7, 0x22, 0, 0]));
        assert_eq!(r.syscalls[0].conditioned_args, vec!["prot", "flags"]);
    }

    #[test]
    fn unstable_fds_are_dropped_and_std_fds_kept() {
        let evs = vec![
            ev(1, "write", [1, 0, 5, 0, 0, 0], 5, None),
            ev(0, "read", [0, 0, 5, 0, 0, 0], 5, None),
            ev(0, "read", [3, 0, 5, 0, 0, 0], 5, None),
        ];
        let (p, r) = synthesize(&evs, &opts());
        assert_eq!(p.syscall(1).unwrap().rules.len(), 1);
        assert!(p.syscall(0).unwrap().rules.is_empty());
        let read = r.syscalls.iter().find(|s| s.name == "read").unwrap();
        assert_eq!(read.dropped_args[0].arg, "fd");
        assert!(!crate::eval::allows(&p, 1, &[2, 0, 5, 0, 0, 0]));
    }

    #[test]
    fn too_many_variants_drop_the_condition() {
        let evs: Vec<_> = (0..20)
            .map(|i| ev(16, "ioctl", [1, 0x5400 + i, 0, 0, 0, 0], 0, None))
            .collect();
        let (p, r) = synthesize(&evs, &opts());
        assert_eq!(p.syscall(16).unwrap().rules.len(), 1, "fd 1 kept");
        assert_eq!(r.syscalls[0].dropped_args[0].arg, "request");
    }

    #[test]
    fn max_rules_drops_the_widest_argument() {
        let mut o = opts();
        o.max_rules = 4;
        let evs: Vec<_> = (0..8u64)
            .map(|i| ev(9, "mmap", [0, 1, i & 1, 0x20 | (i << 8), 0, 0], 1, None))
            .collect();
        let (p, r) = synthesize(&evs, &o);
        assert_eq!(p.syscall(9).unwrap().rules.len(), 2);
        assert_eq!(r.syscalls[0].dropped_args[0].arg, "flags");
    }

    #[test]
    fn dirfd_other_than_cwd_is_dropped() {
        let cwd = AT_FDCWD_DWORD;
        let evs = vec![
            ev(257, "openat", [cwd, 0, 0x80000, 0, 0, 0], 3, Some("/etc/a")),
            ev(257, "openat", [5, 0, 0x80000, 0, 0, 0], 4, Some("b")),
        ];
        let (p, r) = synthesize(&evs, &opts());
        let rules = &p.syscall(257).unwrap().rules;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0][0].arg, 2);
        assert!(r.unresolved_paths[0].contains("relative to a dirfd"));
        assert_eq!(p.landlock.fs[0].path, "/etc/a");
    }

    #[test]
    fn landlock_rights_from_open_flags() {
        let cwd = AT_FDCWD_DWORD;
        let evs = vec![
            ev(257, "openat", [cwd, 0, 0x80000, 0, 0, 0], 3, Some("/x/r")),
            ev(257, "openat", [cwd, 0, 0x241, 0, 0, 0], 3, Some("/x/w")),
            ev(257, "openat", [cwd, 0, 0, 0, 0, 0], -2, Some("/x/missing")),
            ev(257, "openat", [cwd, 0, O_PATH, 0, 0, 0], 3, Some("/x/p")),
            ev(
                257,
                "openat",
                [cwd, 0, 0x10000, 0, 0, 0],
                3,
                Some("rel/./d"),
            ),
        ];
        let mut o = opts();
        o.cwd = "/work".into();
        let (p, _) = synthesize(&evs, &o);
        let get = |path: &str| {
            p.landlock
                .fs
                .iter()
                .find(|r| r.path == path)
                .map(|r| r.access.clone())
        };
        assert_eq!(get("/x/r"), Some(vec![FsAccess::ReadFile]));
        assert_eq!(
            get("/x/w"),
            Some(vec![FsAccess::WriteFile, FsAccess::Truncate])
        );
        assert_eq!(get("/x"), Some(vec![FsAccess::MakeReg]));
        assert_eq!(get("/x/missing"), None);
        assert_eq!(get("/x/p"), None);
        assert_eq!(get("/work/rel/d"), Some(vec![FsAccess::ReadDir]));
        assert!(p.landlock.deny_tcp);
        assert!(p.landlock.scope);
    }

    #[test]
    fn stat_family_is_counted_as_unrestrictable() {
        let evs = vec![ev(
            262,
            "newfstatat",
            [AT_FDCWD_DWORD, 0, 0, 0, 0, 0],
            0,
            Some("/etc"),
        )];
        let (p, r) = synthesize(&evs, &opts());
        assert!(p.landlock.fs.is_empty());
        assert_eq!(r.unrestrictable_path_ops.get("newfstatat"), Some(&1));
    }

    #[test]
    fn comm_filter_and_network_detection() {
        let mut other = ev(41, "socket", [2, 1, 0, 0, 0, 0], 3, None);
        other.comm = "other".into();
        let mine = ev(41, "socket", [1, 1, 0, 0, 0, 0], 3, None);
        let mut o = opts();
        o.comms = vec!["tool".into()];
        let (p, r) = synthesize(&[other.clone(), mine.clone()], &o);
        assert_eq!(r.events_used, 1);
        assert!(p.landlock.deny_tcp, "AF_UNIX only");
        let (p, _) = synthesize(&[other], &opts());
        assert!(!p.landlock.deny_tcp, "AF_INET seen");
    }

    #[test]
    fn normalize_is_lexical() {
        assert_eq!(
            normalize(Path::new("/a/./b/../c//d")),
            PathBuf::from("/a/c/d")
        );
    }
}
