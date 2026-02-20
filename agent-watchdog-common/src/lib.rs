#![no_std]

/// Shared event struct passed from kernel-space eBPF to user-space.
///
/// # Layout
///
/// MUST be `#[repr(C)]` to guarantee a stable, deterministic memory layout
/// that both the eBPF verifier (kernel side) and the user-space deserializer
/// agree on.  Never use Rust enums, `Option`, `String`, `Vec`, or any
/// heap-allocated / dynamically-sized type here.
///
/// | Field      | Type       | Size   | Description                          |
/// |------------|------------|--------|--------------------------------------|
/// | `pid`      | `u32`      | 4 B    | Thread group ID (≈ userspace PID)    |
/// | `comm`     | `[u8; 16]` | 16 B   | Process command name (NUL-padded)    |
/// | `filename` | `[u8; 256]`| 256 B  | Opened file path  (NUL-terminated)   |
///
/// Total: 276 bytes (no padding holes thanks to natural alignment).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    /// Process ID — actually the TGID from `bpf_get_current_pid_tgid() >> 32`.
    pub pid: u32,
    /// Process command name, up to 16 bytes including NUL terminator,
    /// obtained via `bpf_get_current_comm()`.
    pub comm: [u8; 16],
    /// File path being opened, up to 256 bytes including NUL terminator,
    /// read from user-space via `bpf_probe_read_user_str()`.
    pub filename: [u8; 256],
}

/// Implement `aya::Pod` in user-space builds so that `PerfEventArray` can
/// safely reinterpret raw bytes as `FileOpenEvent`.
///
/// # Safety
///
/// `FileOpenEvent` is `#[repr(C)]`, `Copy`, contains only fixed-size
/// integer/byte-array fields, and has no padding holes — it is safe to
/// transmute from an arbitrary byte slice of the correct length.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileOpenEvent {}
