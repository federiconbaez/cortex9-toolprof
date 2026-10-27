//! Which syscall arguments can carry a seccomp condition, and the reference
//! domain used to measure how much of each argument space a profile allows.
//!
//! seccomp-BPF only sees register values (`struct seccomp_data`), never
//! user memory, so only arguments passed by value are listed: flags,
//! commands, file descriptors. Pointers (paths, buffers, structs) are never
//! filterable; paths are handled by Landlock instead.
//!
//! Names and numbers are x86_64 (`asm/unistd_64.h`, `asm-generic/*.h`).

/// How a by-value argument behaves across calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Bit flags, modes or command numbers: stable per call site.
    Flags,
    /// A file descriptor. Only 0, 1 and 2 are stable across runs; any other
    /// value depends on allocation order, so the condition is dropped.
    Fd,
    /// A `dirfd` of an `*at` syscall: stable only when it is always
    /// `AT_FDCWD`.
    DirFd,
}

/// Width compared by the condition. `int` arguments are compared on their
/// low 32 bits because the upper half of the register is not defined by the
/// C ABI for 32-bit values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Width {
    Dword,
    Qword,
}

impl Width {
    pub fn mask(self, v: u64) -> u64 {
        match self {
            Width::Dword => v & 0xffff_ffff,
            Width::Qword => v,
        }
    }
}

/// One filterable argument.
#[derive(Clone, Copy, Debug)]
pub struct ArgSpec {
    pub index: u8,
    pub name: &'static str,
    pub kind: Kind,
    pub width: Width,
    /// Reference domain of the argument for the surface metric, if one is
    /// defined. `None` means the argument is filtered but not credited.
    pub domain: Option<fn() -> Vec<u64>>,
}

/// `AT_FDCWD` as the low 32 bits of the register.
pub const AT_FDCWD_DWORD: u64 = (-100i32) as u32 as u64;

const fn a(
    index: u8,
    name: &'static str,
    kind: Kind,
    width: Width,
    domain: Option<fn() -> Vec<u64>>,
) -> ArgSpec {
    ArgSpec {
        index,
        name,
        kind,
        width,
        domain,
    }
}

use Kind::{DirFd, Fd, Flags};
use Width::{Dword, Qword};

/// Every subset of `bits` OR-ed onto each value of `base`.
pub fn subsets(base: &[u64], bits: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(base.len() << bits.len());
    for &b in base {
        for m in 0u64..(1 << bits.len()) {
            let mut v = b;
            for (i, bit) in bits.iter().enumerate() {
                if m & (1 << i) != 0 {
                    v |= bit;
                }
            }
            out.push(v);
        }
    }
    out
}

fn prot() -> Vec<u64> {
    // PROT_READ | PROT_WRITE | PROT_EXEC
    (0..8).collect()
}
fn mmap_flags() -> Vec<u64> {
    // MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS, MAP_DENYWRITE,
    // MAP_NORESERVE, MAP_POPULATE, MAP_STACK
    subsets(
        &[0],
        &[0x1, 0x2, 0x10, 0x20, 0x800, 0x4000, 0x8000, 0x20000],
    )
}
fn open_flags() -> Vec<u64> {
    // O_RDONLY/O_WRONLY/O_RDWR x O_CREAT, O_EXCL, O_TRUNC, O_APPEND,
    // O_NONBLOCK, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, O_PATH
    subsets(
        &[0, 1, 2],
        &[
            0x40, 0x80, 0x200, 0x400, 0x800, 0x10000, 0x20000, 0x80000, 0x200000,
        ],
    )
}
fn at_flags() -> Vec<u64> {
    // AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH
    subsets(&[0], &[0x100, 0x800, 0x1000])
}
fn statx_flags() -> Vec<u64> {
    // AT_* above + AT_STATX_FORCE_SYNC, AT_STATX_DONT_SYNC
    subsets(&[0], &[0x100, 0x800, 0x1000, 0x2000, 0x4000])
}
fn access_mode() -> Vec<u64> {
    (0..8).collect()
}
fn whence() -> Vec<u64> {
    // SEEK_SET..SEEK_HOLE
    (0..5).collect()
}
fn madvise_advice() -> Vec<u64> {
    let mut v: Vec<u64> = vec![0, 1, 2, 3, 4, 8, 9, 10, 11, 100, 101];
    v.extend(12..=25);
    v
}
fn fcntl_cmd() -> Vec<u64> {
    let mut v: Vec<u64> = (0..=17).collect();
    v.extend([36, 37, 38]);
    v.extend(1024..=1037);
    v
}
fn socket_domain() -> Vec<u64> {
    // AF_UNSPEC..AF_MCTP
    (0..=45).collect()
}
fn socket_type() -> Vec<u64> {
    // SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET x SOCK_NONBLOCK, SOCK_CLOEXEC
    subsets(&[1, 2, 3, 5], &[0x800, 0x80000])
}
fn prctl_option() -> Vec<u64> {
    (1..=80).collect()
}
fn arch_prctl_code() -> Vec<u64> {
    let mut v = vec![0x1001, 0x1002, 0x1003, 0x1004, 0x1011, 0x1012];
    v.extend(0x1021..=0x1025);
    v.extend(0x2001..=0x2003);
    v.extend(0x4001..=0x4004);
    v.extend(0x5001..=0x5005);
    v
}
fn futex_op() -> Vec<u64> {
    // FUTEX_WAIT..FUTEX_LOCK_PI2 x FUTEX_PRIVATE_FLAG, FUTEX_CLOCK_REALTIME
    subsets(&(0..=13).collect::<Vec<_>>(), &[128, 256])
}
fn sigprocmask_how() -> Vec<u64> {
    (0..3).collect()
}
fn signal_number() -> Vec<u64> {
    (1..=64).collect()
}
fn signal_or_zero() -> Vec<u64> {
    (0..=64).collect()
}
fn getrandom_flags() -> Vec<u64> {
    // GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE
    subsets(&[0], &[1, 2, 4])
}
fn rlimit_resource() -> Vec<u64> {
    (0..16).collect()
}
fn mremap_flags() -> Vec<u64> {
    // MREMAP_MAYMOVE, MREMAP_FIXED, MREMAP_DONTUNMAP
    subsets(&[0], &[1, 2, 4])
}
fn cloexec_nonblock() -> Vec<u64> {
    subsets(&[0], &[0x800, 0x80000])
}
fn pipe2_flags() -> Vec<u64> {
    // O_NONBLOCK, O_DIRECT, O_CLOEXEC
    subsets(&[0], &[0x800, 0x4000, 0x80000])
}
fn seccomp_op() -> Vec<u64> {
    (0..4).collect()
}

static NONE: [ArgSpec; 0] = [];
static FD0: [ArgSpec; 1] = [a(0, "fd", Fd, Dword, None)];
static MMAP: [ArgSpec; 2] = [
    a(2, "prot", Flags, Dword, Some(prot)),
    a(3, "flags", Flags, Dword, Some(mmap_flags)),
];
static MPROTECT: [ArgSpec; 1] = [a(2, "prot", Flags, Dword, Some(prot))];
static MADVISE: [ArgSpec; 1] = [a(2, "advice", Flags, Dword, Some(madvise_advice))];
static MREMAP: [ArgSpec; 1] = [a(3, "flags", Flags, Dword, Some(mremap_flags))];
static OPENAT: [ArgSpec; 2] = [
    a(0, "dirfd", DirFd, Dword, None),
    a(2, "flags", Flags, Dword, Some(open_flags)),
];
static OPEN: [ArgSpec; 1] = [a(1, "flags", Flags, Dword, Some(open_flags))];
static DIRFD0: [ArgSpec; 1] = [a(0, "dirfd", DirFd, Dword, None)];
static NEWFSTATAT: [ArgSpec; 2] = [
    a(0, "dirfd", DirFd, Dword, None),
    a(3, "flags", Flags, Dword, Some(at_flags)),
];
static STATX: [ArgSpec; 2] = [
    a(0, "dirfd", DirFd, Dword, None),
    a(2, "flags", Flags, Dword, Some(statx_flags)),
];
static FACCESSAT: [ArgSpec; 2] = [
    a(0, "dirfd", DirFd, Dword, None),
    a(2, "mode", Flags, Dword, Some(access_mode)),
];
static ACCESS: [ArgSpec; 1] = [a(1, "mode", Flags, Dword, Some(access_mode))];
static LSEEK: [ArgSpec; 2] = [
    a(0, "fd", Fd, Dword, None),
    a(2, "whence", Flags, Dword, Some(whence)),
];
static FCNTL: [ArgSpec; 2] = [
    a(0, "fd", Fd, Dword, None),
    a(1, "cmd", Flags, Dword, Some(fcntl_cmd)),
];
static IOCTL: [ArgSpec; 2] = [
    a(0, "fd", Fd, Dword, None),
    a(1, "request", Flags, Dword, None),
];
static SOCKET: [ArgSpec; 3] = [
    a(0, "domain", Flags, Dword, Some(socket_domain)),
    a(1, "type", Flags, Dword, Some(socket_type)),
    a(2, "protocol", Flags, Dword, None),
];
static PRCTL: [ArgSpec; 1] = [a(0, "option", Flags, Dword, Some(prctl_option))];
static ARCH_PRCTL: [ArgSpec; 1] = [a(0, "code", Flags, Dword, Some(arch_prctl_code))];
static FUTEX: [ArgSpec; 1] = [a(1, "op", Flags, Dword, Some(futex_op))];
static SIGPROCMASK: [ArgSpec; 1] = [a(0, "how", Flags, Dword, Some(sigprocmask_how))];
static SIGACTION: [ArgSpec; 1] = [a(0, "signum", Flags, Dword, Some(signal_number))];
static KILL: [ArgSpec; 1] = [a(1, "sig", Flags, Dword, Some(signal_or_zero))];
static TGKILL: [ArgSpec; 1] = [a(2, "sig", Flags, Dword, Some(signal_or_zero))];
static GETRANDOM: [ArgSpec; 1] = [a(2, "flags", Flags, Dword, Some(getrandom_flags))];
static PRLIMIT64: [ArgSpec; 2] = [
    a(0, "pid", Flags, Dword, None),
    a(1, "resource", Flags, Dword, Some(rlimit_resource)),
];
static CLONE: [ArgSpec; 1] = [a(0, "flags", Flags, Qword, None)];
static UNSHARE: [ArgSpec; 1] = [a(0, "flags", Flags, Qword, None)];
static PERSONALITY: [ArgSpec; 1] = [a(0, "persona", Flags, Dword, None)];
static PIPE2: [ArgSpec; 1] = [a(1, "flags", Flags, Dword, Some(pipe2_flags))];
static FLAGS0_CLOEXEC: [ArgSpec; 1] = [a(0, "flags", Flags, Dword, Some(cloexec_nonblock))];
static EVENTFD2: [ArgSpec; 1] = [a(1, "flags", Flags, Dword, Some(cloexec_nonblock))];
static SECCOMP: [ArgSpec; 1] = [a(0, "op", Flags, Dword, Some(seccomp_op))];
static SCHED_GETAFFINITY: [ArgSpec; 1] = [a(0, "pid", Flags, Dword, None)];
static RSEQ: [ArgSpec; 2] = [
    a(1, "rseq_len", Flags, Dword, None),
    a(2, "flags", Flags, Dword, None),
];

/// Filterable arguments of syscall `name` (empty when none is known).
pub fn specs(name: &str) -> &'static [ArgSpec] {
    match name {
        "read" | "write" | "pread64" | "pwrite64" | "readv" | "writev" | "close" | "fstat"
        | "fsync" | "fdatasync" | "ftruncate" | "getdents64" | "fchdir" | "dup" => &FD0,
        "mmap" => &MMAP,
        "mprotect" | "pkey_mprotect" => &MPROTECT,
        "madvise" => &MADVISE,
        "mremap" => &MREMAP,
        "openat" => &OPENAT,
        "open" => &OPEN,
        "openat2" | "readlinkat" | "mkdirat" | "unlinkat" => &DIRFD0,
        "newfstatat" => &NEWFSTATAT,
        "statx" => &STATX,
        "faccessat" | "faccessat2" => &FACCESSAT,
        "access" => &ACCESS,
        "lseek" => &LSEEK,
        "fcntl" => &FCNTL,
        "ioctl" => &IOCTL,
        "socket" => &SOCKET,
        "prctl" => &PRCTL,
        "arch_prctl" => &ARCH_PRCTL,
        "futex" => &FUTEX,
        "rt_sigprocmask" => &SIGPROCMASK,
        "rt_sigaction" => &SIGACTION,
        "kill" | "tkill" => &KILL,
        "tgkill" => &TGKILL,
        "getrandom" => &GETRANDOM,
        "prlimit64" => &PRLIMIT64,
        "clone" => &CLONE,
        "unshare" => &UNSHARE,
        "personality" => &PERSONALITY,
        "pipe2" => &PIPE2,
        "epoll_create1" | "inotify_init1" => &FLAGS0_CLOEXEC,
        "eventfd2" => &EVENTFD2,
        "seccomp" => &SECCOMP,
        "sched_getaffinity" => &SCHED_GETAFFINITY,
        "rseq" => &RSEQ,
        _ => &NONE,
    }
}

/// Syscalls whose path argument the tracer copies, with its index
/// (x86_64 names). Used both to program the eBPF map and to synthesize
/// Landlock rules.
pub const PATH_ARGS: &[(&str, u32)] = &[
    ("open", 0),
    ("creat", 0),
    ("openat", 1),
    ("openat2", 1),
    ("execve", 0),
    ("execveat", 1),
    ("stat", 0),
    ("lstat", 0),
    ("newfstatat", 1),
    ("statx", 1),
    ("access", 0),
    ("faccessat", 1),
    ("faccessat2", 1),
    ("readlink", 0),
    ("readlinkat", 1),
    ("chdir", 0),
    ("mkdir", 0),
    ("mkdirat", 1),
    ("unlink", 0),
    ("unlinkat", 1),
    ("rmdir", 0),
    ("truncate", 0),
    ("rename", 0),
    ("renameat", 1),
    ("renameat2", 1),
    ("link", 0),
    ("symlink", 1),
    ("chmod", 0),
    ("statfs", 0),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsets_enumerate_every_combination() {
        let v = subsets(&[0, 1], &[4, 8]);
        assert_eq!(v, vec![0, 4, 8, 12, 1, 5, 9, 13]);
    }

    #[test]
    fn domains_have_no_duplicates() {
        for name in [
            "mmap",
            "openat",
            "socket",
            "futex",
            "fcntl",
            "madvise",
            "arch_prctl",
        ] {
            for s in specs(name) {
                if let Some(d) = s.domain {
                    let mut v = d();
                    let n = v.len();
                    v.sort_unstable();
                    v.dedup();
                    assert_eq!(v.len(), n, "{name}.{}", s.name);
                }
            }
        }
        assert_eq!((mmap_flags)().len(), 256);
        assert_eq!((open_flags)().len(), 3 * 512);
    }

    #[test]
    fn pointer_syscalls_have_no_specs() {
        assert!(specs("clone3").is_empty());
        assert!(specs("execve").is_empty());
        assert_eq!(specs("openat")[1].name, "flags");
    }

    #[test]
    fn dword_mask() {
        assert_eq!(Width::Dword.mask(0xffff_ffff_ffff_ff9c), AT_FDCWD_DWORD);
        assert_eq!(Width::Qword.mask(u64::MAX), u64::MAX);
    }
}
