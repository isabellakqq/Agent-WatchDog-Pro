#![no_std]
#![no_main]

//! Agent-WatchDog — eBPF kernel-space program
//!
//! Attaches to the `syscalls/sys_enter_openat` tracepoint and captures
//! every `openat(2)` call system-wide.  Each event is pushed to a
//! `PerfEventArray` for the user-space daemon to consume.
//!
//! # Verifier considerations
//!
//! * We NEVER dereference user-space pointers directly.  All reads go
//!   through `bpf_probe_read_user_str`, which is the only helper the
//!   verifier trusts for accessing user memory.
//! * The program must be compiled with `opt-level >= 2` and `panic = "abort"`
//!   or the verifier will reject it.
//! * Large structs (like `FileOpenEvent` at 276 bytes) must NOT live on the
//!   stack — the eBPF stack limit is 512 bytes.  We use a single-element
//!   `PerCpuArray` as a scratch buffer instead.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{PerCpuArray, PerfEventArray},
    programs::TracePointContext,
};
use agent_watchdog_common::FileOpenEvent;

// ── Map definitions ──────────────────────────────────────────────

/// Per-CPU perf ring buffer shared with user-space.
#[map]
static EVENTS: PerfEventArray<FileOpenEvent> = PerfEventArray::new(0);

/// Per-CPU scratch buffer for building `FileOpenEvent`.
///
/// The eBPF stack is limited to 512 bytes.  `FileOpenEvent` alone is
/// 276 bytes, and with the filename temp buffer that would blow the
/// stack.  By placing the struct in a `PerCpuArray` (one element per
/// CPU, index 0), we move it to map memory which has no size limit.
///
/// This is safe because eBPF programs run with preemption disabled
/// on a single CPU — no other program can clobber our entry while
/// we're using it.
#[map]
static SCRATCH: PerCpuArray<FileOpenEvent> = PerCpuArray::with_max_entries(1, 0);

// ── Tracepoint handler ───────────────────────────────────────────

/// Entry point — attached to `syscalls/sys_enter_openat`.
///
/// The tracepoint args struct for `sys_enter_openat` (both x86_64 and
/// aarch64) has the filename pointer at offset 16:
///
/// ```text
/// struct {
///     int __syscall_nr;       // offset  0  (padded to 8 bytes)
///     int dfd;                // offset  8
///     const char *filename;   // offset 16  ← target
///     int flags;              // offset 24
///     umode_t mode;           // offset 32
/// };
/// ```
#[tracepoint]
pub fn agent_watchdog(ctx: TracePointContext) -> u32 {
    match try_agent_watchdog(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // silently drop on error — never panic in eBPF
    }
}

#[inline(always)]
fn try_agent_watchdog(ctx: &TracePointContext) -> Result<u32, i64> {
    // ── 1. Extract the user-space filename pointer ───────────────
    let filename_ptr: *const u8 = unsafe { ctx.read_at::<u64>(16)? as *const u8 };

    // ── 2. Get a mutable reference to the scratch buffer ─────────
    //
    // `get_ptr_mut(0)` returns a raw pointer to the single element
    // in the per-CPU array.  We check for null (required by the
    // verifier) then use it as our working area.
    let event_ptr = SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
    let event = unsafe { &mut *event_ptr };

    // ── 3. Safely copy the filename from user memory ─────────────
    //
    // CRITICAL: `bpf_probe_read_user_str_bytes` is the ONLY safe way
    // to read user-space strings.  Direct pointer dereference will be
    // rejected by the verifier.
    //
    // Zero the filename buffer first so stale data from a previous
    // event on this CPU doesn't leak through.
    event.filename = [0u8; 256];
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };

    // ── 4. Obtain PID and process name ───────────────────────────
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.comm = bpf_get_current_comm().map_err(|e| e as i64)?;

    // ── 5. Push the event to the perf ring ───────────────────────
    EVENTS.output(ctx, event, 0);

    Ok(0)
}

// ── Panic handler ────────────────────────────────────────────────
/// Required by `#![no_std]` + `#![no_main]`.  eBPF programs must
/// never panic — if we somehow reach this, trap into unreachable.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
