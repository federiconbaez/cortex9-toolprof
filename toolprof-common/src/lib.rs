//! Records shared by the toolprof eBPF program (`no_std`) and the loader.
//!
//! A [`PathEvent`] is the published `cortex9-tracer` record
//! ([`SyscallEvent`], 112 bytes) followed by the first [`PATH_CAP`] bytes of
//! the path argument of path-taking syscalls. Because the base record comes
//! first, `cortex9_tracer::event::Event::decode` reads it unchanged (it
//! ignores trailing bytes) and only the path tail is decoded here.
#![cfg_attr(not(test), no_std)]

pub use cortex9_tracer_common::{
    tp, InFlight, SyscallEvent, ARG_COUNT, COMM_LEN, EVENT_FLAG_IN_PIDNS, EVENT_SIZE,
};

/// Bytes of the path argument copied from user memory (NUL included).
pub const PATH_CAP: usize = 256;

/// Ring buffer size in bytes (power of two, multiple of the page size).
pub const RING_BUF_BYTES: u32 = 1 << 22;

/// Max in-flight syscalls tracked between `sys_enter` and `sys_exit`.
pub const MAX_INFLIGHT: u32 = 16_384;

/// Max entries in the comm and path-argument maps.
pub const MAX_FILTER_ENTRIES: u32 = 1_024;

/// [`PathEvent::flags`]: the path field holds a copied user string.
pub const PATH_FLAG_PRESENT: u32 = 1 << 0;
/// [`PathEvent::flags`]: the string was cut at [`PATH_CAP`] - 1 bytes.
pub const PATH_FLAG_TRUNCATED: u32 = 1 << 1;
/// [`PathEvent::flags`]: reading the user string failed.
pub const PATH_FLAG_FAULT: u32 = 1 << 2;
/// [`PathEvent::flags`]: emitted at `sys_enter` for a syscall that does not
/// return (`exit`, `exit_group`); `ret` and `duration_ns` are 0.
pub const PATH_FLAG_NORETURN: u32 = 1 << 3;

/// Map names, as seen by the loader.
pub mod maps {
    pub const EVENTS: &str = "EVENTS";
    pub const CONFIG: &str = "CONFIG";
    /// `HashMap<[u8; 16], u8>`: `comm` values to keep.
    pub const COMM_FILTER: &str = "COMM_FILTER";
    /// `HashMap<u32, u32>`: syscall number -> index of its path argument.
    pub const PATH_ARG: &str = "PATH_ARG";
    pub const INFLIGHT: &str = "INFLIGHT";
    pub const SCRATCH: &str = "SCRATCH";
    pub const DROPPED: &str = "DROPPED";
}

/// Program names, as seen by the loader.
pub mod programs {
    pub const SYS_ENTER: &str = "toolprof_sys_enter";
    pub const SYS_EXIT: &str = "toolprof_sys_exit";
}

/// Slots in the `CONFIG` array.
pub mod config {
    /// Bit flags, see [`FLAG_COMM_FILTER`].
    pub const FLAGS: u32 = 0;
    /// Thread-group id of the loader; its syscalls are skipped.
    pub const SELF_TGID: u32 = 1;
    /// `execve` number: always recorded at entry because `comm` only
    /// changes when it succeeds.
    pub const EXECVE_NR: u32 = 2;
    /// `execveat` number, same reason.
    pub const EXECVEAT_NR: u32 = 3;
    /// `exit` number (does not return).
    pub const EXIT_NR: u32 = 4;
    /// `exit_group` number (does not return).
    pub const EXIT_GROUP_NR: u32 = 5;
    /// Number of slots.
    pub const LEN: u32 = 6;

    /// Only keep tasks whose `comm` is in `COMM_FILTER`.
    pub const FLAG_COMM_FILTER: u32 = 1 << 0;
}

/// Data saved at `sys_enter` and consumed at `sys_exit`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InFlightPath {
    pub base: InFlight,
    pub path_flags: u32,
    pub path_len: u32,
    pub path: [u8; PATH_CAP],
}

/// One completed syscall plus its path argument, as written to the ring
/// buffer (376 bytes, 8-byte aligned).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PathEvent {
    pub base: SyscallEvent,
    /// `PATH_FLAG_*` bits.
    pub path_flags: u32,
    /// Length of the path in bytes, without the NUL.
    pub path_len: u32,
    pub path: [u8; PATH_CAP],
}

/// Size of a [`PathEvent`] record in bytes.
pub const PATH_EVENT_SIZE: usize = core::mem::size_of::<PathEvent>();

/// Byte offsets of the fields that follow the base record.
pub mod offsets {
    pub const PATH_FLAGS: usize = super::EVENT_SIZE;
    pub const PATH_LEN: usize = super::EVENT_SIZE + 4;
    pub const PATH: usize = super::EVENT_SIZE + 8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn layout_extends_the_tracer_record() {
        assert_eq!(EVENT_SIZE, 112);
        assert_eq!(offset_of!(PathEvent, base), 0);
        assert_eq!(offset_of!(PathEvent, path_flags), offsets::PATH_FLAGS);
        assert_eq!(offset_of!(PathEvent, path_len), offsets::PATH_LEN);
        assert_eq!(offset_of!(PathEvent, path), offsets::PATH);
        assert_eq!(size_of::<PathEvent>(), 112 + 8 + PATH_CAP);
        assert_eq!(align_of::<PathEvent>(), 8);
        assert_eq!(size_of::<InFlightPath>(), 64 + 8 + PATH_CAP);
    }

    #[test]
    fn ring_buffer_holds_many_records() {
        assert!(RING_BUF_BYTES.is_power_of_two());
        assert!(RING_BUF_BYTES as usize / PATH_EVENT_SIZE > 10_000);
    }
}
