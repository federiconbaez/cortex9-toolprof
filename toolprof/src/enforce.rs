//! Enforcement: compile the seccomp part with seccompiler, apply the
//! Landlock part with rust-landlock, then `execve` the tool.
//!
//! Order matters. Landlock and the filter are installed by the runner
//! itself; after `seccomp(2)` returns, the only syscall left before the
//! tool starts is `execve`, which the profile allows because the trace
//! recorded it. Both restrictions survive `execve` and need no privileges
//! (`PR_SET_NO_NEW_PRIVS` is set).

use crate::profile::{FsAccess, Landlock, Op, Profile, Seccomp};
use anyhow::{bail, Context, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Landlock ABI the profile targets (Linux 6.12: filesystem, TCP, scoping).
pub const LANDLOCK_ABI: ABI = ABI::V6;

/// What to do with a syscall the profile does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// `SECCOMP_RET_KILL_PROCESS`: the process dies with SIGSYS.
    Kill,
    /// `SECCOMP_RET_ERRNO(EPERM)`.
    Errno,
}

pub fn compile_seccomp(s: &Seccomp, on_violation: Violation) -> Result<BpfProgram> {
    let mut map: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for sc in &s.syscalls {
        let mut rules = Vec::new();
        for conj in &sc.rules {
            let conds = conj
                .iter()
                .map(|c| {
                    let len = match c.width {
                        crate::argspec::Width::Dword => SeccompCmpArgLen::Dword,
                        crate::argspec::Width::Qword => SeccompCmpArgLen::Qword,
                    };
                    let op = match c.op {
                        Op::Eq => SeccompCmpOp::Eq,
                        Op::Ne => SeccompCmpOp::Ne,
                        Op::Lt => SeccompCmpOp::Lt,
                        Op::Le => SeccompCmpOp::Le,
                        Op::Gt => SeccompCmpOp::Gt,
                        Op::Ge => SeccompCmpOp::Ge,
                        Op::MaskedEq { mask } => SeccompCmpOp::MaskedEq(mask),
                    };
                    SeccompCondition::new(c.arg, len, op, c.width.mask(c.value))
                        .map_err(|e| anyhow::anyhow!("{}: {e}", sc.name))
                })
                .collect::<Result<Vec<_>>>()?;
            rules.push(SeccompRule::new(conds).map_err(|e| anyhow::anyhow!("{}: {e}", sc.name))?);
        }
        map.insert(sc.nr as i64, rules);
    }
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| anyhow::anyhow!("unsupported arch: {e:?}"))?;
    let mismatch = match on_violation {
        Violation::Kill => SeccompAction::KillProcess,
        Violation::Errno => SeccompAction::Errno(libc::EPERM as u32),
    };
    let filter = SeccompFilter::new(map, mismatch, SeccompAction::Allow, arch)
        .map_err(|e| anyhow::anyhow!("seccomp filter: {e}"))?;
    filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| anyhow::anyhow!("seccomp compile: {e}"))
}

fn fs_access(a: FsAccess) -> AccessFs {
    match a {
        FsAccess::Execute => AccessFs::Execute,
        FsAccess::WriteFile => AccessFs::WriteFile,
        FsAccess::ReadFile => AccessFs::ReadFile,
        FsAccess::ReadDir => AccessFs::ReadDir,
        FsAccess::RemoveDir => AccessFs::RemoveDir,
        FsAccess::RemoveFile => AccessFs::RemoveFile,
        FsAccess::MakeDir => AccessFs::MakeDir,
        FsAccess::MakeReg => AccessFs::MakeReg,
        FsAccess::Truncate => AccessFs::Truncate,
    }
}

#[derive(Debug)]
pub struct LandlockOutcome {
    pub status: RulesetStatus,
    /// Rule paths that did not exist at enforcement time (skipped).
    pub missing: Vec<String>,
}

/// Restrict the calling thread (and its future children) with `l`.
/// With `strict`, anything short of a fully enforced ruleset is an error.
pub fn apply_landlock(l: &Landlock, strict: bool) -> Result<LandlockOutcome> {
    let mut rs = Ruleset::default().handle_access(AccessFs::from_all(LANDLOCK_ABI))?;
    if l.deny_tcp {
        rs = rs.handle_access(AccessNet::from_all(LANDLOCK_ABI))?;
    }
    if l.scope {
        rs = rs.scope(Scope::from_all(LANDLOCK_ABI))?;
    }
    let mut created = rs.create()?;
    let mut missing = Vec::new();
    for r in &l.fs {
        let fd = match PathFd::new(&r.path) {
            Ok(fd) => fd,
            Err(_) => {
                missing.push(r.path.clone());
                continue;
            }
        };
        let access: BitFlags<AccessFs> = r.access.iter().map(|a| fs_access(*a)).collect();
        created = created
            .add_rule(PathBeneath::new(fd, access))
            .with_context(|| format!("landlock rule {}", r.path))?;
    }
    let st = created.restrict_self()?;
    if strict && st.ruleset != RulesetStatus::FullyEnforced {
        bail!(
            "landlock not fully enforced ({:?}); the kernel lacks ABI {:?}",
            st.ruleset,
            LANDLOCK_ABI
        );
    }
    Ok(LandlockOutcome {
        status: st.ruleset,
        missing,
    })
}

/// Resolve `prog` like `execvp` would, once, before any restriction.
pub fn resolve_program(prog: &Path) -> Result<PathBuf> {
    if prog.as_os_str().as_bytes().contains(&b'/') {
        return Ok(prog.to_path_buf());
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(prog);
        if cand.is_file() {
            return Ok(cand);
        }
    }
    bail!("{} not found in PATH", prog.display())
}

fn cstr(s: &[u8]) -> Result<CString> {
    CString::new(s).context("argument contains a NUL byte")
}

/// Options of [`exec_confined`].
#[derive(Clone, Copy, Debug)]
pub struct ExecOptions {
    pub on_violation: Violation,
    pub strict_landlock: bool,
    pub seccomp: bool,
    pub landlock: bool,
}

/// Apply `profile` to this process and `execve` `argv`. Returns only on
/// failure before the restrictions are installed; a failing `execve` after
/// them exits with status 127 without touching anything else.
pub fn exec_confined(profile: &Profile, argv: &[OsString], opt: ExecOptions) -> Result<()> {
    let Some(prog) = argv.first() else {
        bail!("no program given")
    };
    let path = resolve_program(Path::new(prog))?;
    let c_path = cstr(path.as_os_str().as_bytes())?;
    let c_argv: Vec<CString> = argv
        .iter()
        .map(|a| cstr(a.as_bytes()))
        .collect::<Result<_>>()?;
    let c_env: Vec<CString> = std::env::vars_os()
        .map(|(k, v)| {
            let mut b = k.as_bytes().to_vec();
            b.push(b'=');
            b.extend_from_slice(v.as_bytes());
            cstr(&b)
        })
        .collect::<Result<_>>()?;
    let mut p_argv: Vec<*const libc::c_char> = c_argv.iter().map(|c| c.as_ptr()).collect();
    p_argv.push(std::ptr::null());
    let mut p_env: Vec<*const libc::c_char> = c_env.iter().map(|c| c.as_ptr()).collect();
    p_env.push(std::ptr::null());

    let prog_bpf = if opt.seccomp {
        Some(compile_seccomp(&profile.seccomp, opt.on_violation)?)
    } else {
        None
    };
    if opt.landlock {
        let out = apply_landlock(&profile.landlock, opt.strict_landlock)?;
        if !out.missing.is_empty() {
            eprintln!(
                "toolprof: {} landlock rule path(s) missing, skipped: {}",
                out.missing.len(),
                out.missing.join(", ")
            );
        }
    }
    if let Some(bpf) = &prog_bpf {
        seccompiler::apply_filter(bpf).map_err(|e| anyhow::anyhow!("installing seccomp: {e}"))?;
    }
    // SAFETY: all pointers come from live CStrings and NULL-terminated
    // vectors. After the filter, nothing but execve and _exit runs.
    unsafe {
        libc::execve(c_path.as_ptr(), p_argv.as_ptr(), p_env.as_ptr());
        libc::_exit(127);
    }
}
