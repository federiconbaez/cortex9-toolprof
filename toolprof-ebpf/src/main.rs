//! eBPF program of toolprof, derived from cortex9-ebpf-tracer.
//!
//! Differences with the published tracer:
//!
//! - **comm filter in the kernel**: only tasks whose `comm` is in
//!   `COMM_FILTER` are recorded. `execve`/`execveat` are always recorded at
//!   entry because `comm` changes only when they succeed; the exit handler
//!   checks `comm` again, so the event survives only if the new program
//!   matches.
//! - **path capture**: for syscall numbers listed in `PATH_ARG`, the path
//!   argument is copied from user memory at entry (before `execve` replaces
//!   that memory) with `bpf_probe_read_user_str`.
//! - **non-returning syscalls**: `exit` and `exit_group` never reach
//!   `sys_exit`, so they are emitted at entry with `PATH_FLAG_NORETURN`.
//!   Without this a profile synthesized from the trace would kill every
//!   process at exit.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use toolprof_common::{
    config, tp, InFlight, InFlightPath, PathEvent, SyscallEvent, ARG_COUNT, COMM_LEN,
    EVENT_FLAG_IN_PIDNS, MAX_FILTER_ENTRIES, MAX_INFLIGHT, PATH_CAP, PATH_FLAG_FAULT,
    PATH_FLAG_NORETURN, PATH_FLAG_PRESENT, PATH_FLAG_TRUNCATED, RING_BUF_BYTES,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_BYTES, 0);

#[map]
static CONFIG: Array<u32> = Array::with_max_entries(config::LEN, 0);

#[map]
static COMM_FILTER: HashMap<[u8; COMM_LEN], u8> = HashMap::with_max_entries(MAX_FILTER_ENTRIES, 0);

#[map]
static PATH_ARG: HashMap<u32, u32> = HashMap::with_max_entries(MAX_FILTER_ENTRIES, 0);

#[map]
static INFLIGHT: LruHashMap<u64, InFlightPath> = LruHashMap::with_max_entries(MAX_INFLIGHT, 0);

/// One staging slot per CPU: [`InFlightPath`] does not fit on the stack.
#[map]
static SCRATCH: PerCpuArray<InFlightPath> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DROPPED: Array<u64> = Array::with_max_entries(1, 0);

#[inline(always)]
fn cfg(slot: u32) -> u32 {
    CONFIG.get(slot).copied().unwrap_or(0)
}

/// `(tgid, tid)` of the current task.
///
/// The loader runs in the namespace it traces in, so global ids are kept;
/// `bpf_pidns_info` is only referenced to keep the record layout identical
/// to the tracer's (the in-namespace flag is always set).
#[inline(always)]
fn task_ids(pid_tgid: u64) -> (u32, u32) {
    let _ = core::mem::size_of::<bpf_pidns_info>();
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

#[inline(always)]
fn comm_wanted(comm: &[u8; COMM_LEN]) -> bool {
    if cfg(config::FLAGS) & config::FLAG_COMM_FILTER == 0 {
        return true;
    }
    // SAFETY: read-only lookup; nothing is kept from the value.
    unsafe { COMM_FILTER.get(comm) }.is_some()
}

#[inline(always)]
fn arg_at(args: &[u64; ARG_COUNT], idx: u32) -> u64 {
    match idx {
        0 => args[0],
        1 => args[1],
        2 => args[2],
        3 => args[3],
        4 => args[4],
        _ => args[5],
    }
}

#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
pub fn toolprof_sys_enter(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter(&ctx);
    0
}

fn try_sys_enter(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let (tgid, tid) = task_ids(pid_tgid);
    if tgid == cfg(config::SELF_TGID) {
        return Ok(());
    }
    // SAFETY: offsets come from the stable raw_syscalls tracepoint format.
    let nr: i64 = unsafe { ctx.read_at(tp::ID) }.map_err(i64::from)?;
    if nr < 0 {
        return Ok(());
    }
    let nr = nr as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
    let is_exec = nr == cfg(config::EXECVE_NR) || nr == cfg(config::EXECVEAT_NR);
    if !is_exec && !comm_wanted(&comm) {
        return Ok(());
    }
    let args: [u64; ARG_COUNT] = unsafe { ctx.read_at(tp::ARGS) }.map_err(i64::from)?;
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let slot = SCRATCH.get_ptr_mut(0).ok_or(-1i64)?;
    // SAFETY: per-CPU slot, valid for the whole program run; no other
    // program instance can run on this CPU concurrently.
    let s = unsafe { &mut *slot };
    s.base = InFlight {
        start_ns: now,
        nr: nr as u64,
        args,
    };
    s.path_flags = 0;
    s.path_len = 0;
    // SAFETY: read-only lookup, the value is copied out.
    if let Some(idx) = unsafe { PATH_ARG.get(&nr) }.copied() {
        let ptr = arg_at(&args, idx) as *const u8;
        // SAFETY: the helper validates the user pointer and faults safely.
        match unsafe { bpf_probe_read_user_str_bytes(ptr, &mut s.path) } {
            Ok(bytes) => {
                let len = bytes.len() as u32;
                s.path_len = len;
                s.path_flags = PATH_FLAG_PRESENT;
                if len as usize >= PATH_CAP - 1 {
                    s.path_flags |= PATH_FLAG_TRUNCATED;
                }
            }
            Err(_) => s.path_flags = PATH_FLAG_FAULT,
        }
    }

    if nr == cfg(config::EXIT_NR) || nr == cfg(config::EXIT_GROUP_NR) {
        let uid = bpf_get_current_uid_gid() as u32;
        emit(s, 0, now, comm, uid, tgid, tid, PATH_FLAG_NORETURN);
        return Ok(());
    }
    INFLIGHT.insert(&pid_tgid, s, 0)?;
    Ok(())
}

#[tracepoint(category = "raw_syscalls", name = "sys_exit")]
pub fn toolprof_sys_exit(ctx: TracePointContext) -> u32 {
    let _ = try_sys_exit(&ctx);
    0
}

fn try_sys_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(entry) = INFLIGHT.get_ptr(&pid_tgid) else {
        return Ok(());
    };
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
    if comm_wanted(&comm) {
        let ret: i64 = unsafe { ctx.read_at(tp::RET) }.map_err(i64::from)?;
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let uid = bpf_get_current_uid_gid() as u32;
        let (tgid, tid) = task_ids(pid_tgid);
        // SAFETY: the value stays valid until this thread updates or removes
        // its own key, which happens below.
        let e = unsafe { &*entry };
        emit(e, ret, now, comm, uid, tgid, tid, 0);
    }
    let _ = INFLIGHT.remove(&pid_tgid);
    Ok(())
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn emit(
    e: &InFlightPath,
    ret: i64,
    now: u64,
    comm: [u8; COMM_LEN],
    uid: u32,
    tgid: u32,
    tid: u32,
    extra_flags: u32,
) {
    let Some(mut slot) = EVENTS.reserve::<PathEvent>(0) else {
        if let Some(counter) = DROPPED.get_ptr_mut(0) {
            // SAFETY: single u64 slot; an approximate counter is enough.
            unsafe { *counter += 1 };
        }
        return;
    };
    let p = slot.as_mut_ptr();
    // SAFETY: `p` points to a reserved ring buffer record of the right size.
    unsafe {
        (*p).base = SyscallEvent {
            ts_ns: now,
            duration_ns: if extra_flags & PATH_FLAG_NORETURN != 0 {
                0
            } else {
                now.saturating_sub(e.base.start_ns)
            },
            ret,
            args: e.base.args,
            pid: tgid,
            tid,
            uid,
            nr: e.base.nr as u32,
            comm,
            flags: EVENT_FLAG_IN_PIDNS,
            _pad: 0,
        };
        (*p).path_flags = e.path_flags | extra_flags;
        (*p).path_len = e.path_len;
        if bpf_probe_read_kernel_buf(e.path.as_ptr(), &mut (*p).path).is_err() {
            (*p).path_flags |= PATH_FLAG_FAULT;
        }
    }
    slot.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
