//! On-disk profile format (JSON).

use crate::argspec::Width;
use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

/// Comparison of one argument, as in `struct seccomp_data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// `(arg & mask) == value`.
    MaskedEq {
        mask: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cond {
    pub arg: u8,
    pub width: Width,
    pub op: Op,
    pub value: u64,
}

/// One allowed syscall. `rules` is a disjunction of conjunctions; an empty
/// list means "allowed with any arguments".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallRule {
    pub name: String,
    pub nr: u32,
    #[serde(default)]
    pub rules: Vec<Vec<Cond>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seccomp {
    pub arch: String,
    pub syscalls: Vec<SyscallRule>,
}

/// Landlock filesystem access rights, named like `LANDLOCK_ACCESS_FS_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    Execute,
    WriteFile,
    ReadFile,
    ReadDir,
    RemoveDir,
    RemoveFile,
    MakeDir,
    MakeReg,
    Truncate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsRule {
    pub path: String,
    pub access: Vec<FsAccess>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Landlock {
    /// Rules on exact paths (a rule on a file covers only that file).
    pub fs: Vec<FsRule>,
    /// Handle TCP bind/connect with no allowed port (no socket activity was
    /// observed). `false` leaves the network unrestricted by Landlock.
    pub deny_tcp: bool,
    /// Scope abstract UNIX sockets and signals to the sandbox (ABI 6).
    pub scope: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub version: u32,
    /// `comm` values the profile was synthesized from.
    pub tool: Vec<String>,
    pub seccomp: Seccomp,
    pub landlock: Landlock,
}

impl Profile {
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serializable")
    }

    pub fn syscall(&self, nr: u32) -> Option<&SyscallRule> {
        self.seccomp.syscalls.iter().find(|s| s.nr == nr)
    }
}
