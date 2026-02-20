//! Agent-WatchDog — User-space daemon
//!
//! Loads the compiled eBPF object, attaches it to the
//! `syscalls/sys_enter_openat` tracepoint, and asynchronously polls
//! the `PerfEventArray` for `FileOpenEvent`s.
//!
//! Only events whose filename matches a set of sensitive keywords
//! are printed as high-risk warnings; everything else is silently
//! dropped.

use anyhow::{Context, Result};
use aya::{
    maps::perf::PerfEventArray,
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::signal;

use agent_watchdog_common::FileOpenEvent;

// ── Sensitive-file keywords ──────────────────────────────────────
/// If an opened filename contains ANY of these substrings (case-
/// insensitive), we treat it as a high-risk event.
const SENSITIVE_KEYWORDS: &[&str] = &[
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "shadow",
    "aws/credentials",
    "gcp/application_default_credentials.json",
    ".kube/config",
    ".docker/config.json",
    "secrets.yaml",
    "secrets.yml",
    "master.key",
    ".pgpass",
    ".netrc",
];

// ── CLI ──────────────────────────────────────────────────────────
#[derive(Debug, Parser)]
#[command(
    name = "agent-watchdog",
    about = "AI Agent runtime security monitor — eBPF-based sensitive-file access tracer"
)]
struct Opt {
    /// Path to the compiled eBPF ELF object.
    /// Defaults to the release build produced by `cargo xtask build-ebpf`.
    #[arg(
        short,
        long,
        default_value = "target/bpfel-unknown-none/release/agent-watchdog"
    )]
    bpf_path: String,
}

// ── Entry point ──────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Initialise the env_logger so `RUST_LOG=info` works.
    env_logger::init();

    // ── 1. Load the eBPF object ──────────────────────────────────
    info!("Loading eBPF object from: {}", opt.bpf_path);
    let mut ebpf = Ebpf::load_file(&opt.bpf_path)
        .with_context(|| format!("failed to load eBPF object from '{}'", opt.bpf_path))?;

    // Forward aya-log messages (if the eBPF side uses `info!()` etc.)
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!(
            "aya-log init failed (non-fatal, eBPF-side logs disabled): {}",
            e
        );
    }

    // ── 2. Attach to the tracepoint ──────────────────────────────
    let program: &mut TracePoint = ebpf
        .program_mut("agent_watchdog")
        .context("eBPF program 'agent_watchdog' not found in object file")?
        .try_into()
        .context("program type mismatch — expected TracePoint")?;

    program
        .load()
        .context("failed to load tracepoint program into the kernel")?;
    program
        .attach("syscalls", "sys_enter_openat")
        .context("failed to attach to syscalls/sys_enter_openat")?;

    info!("✅  Attached to tracepoint: syscalls/sys_enter_openat");
    info!("🔍  Monitoring sensitive file access… Press Ctrl-C to stop.\n");

    // ── 3. Open PerfEventArray and spawn per-CPU readers ─────────
    let mut perf_array = PerfEventArray::try_from(
        ebpf.take_map("EVENTS")
            .context("EVENTS map not found in the eBPF object")?,
    )
    .context("failed to create PerfEventArray from EVENTS map")?;

    let cpus = online_cpus().map_err(|(_, e)| e).context("failed to enumerate online CPUs")?;
    info!("Spawning {} perf-event readers (one per CPU)", cpus.len());

    for cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, Some(64)) // 64-page (256 KiB) ring buffer per CPU
            .context("failed to open perf buffer")?;

        // Use tokio's AsyncFd to poll the perf buffer file descriptor for readability.
        let async_fd = AsyncFd::with_interest(
            buf.as_raw_fd(),
            Interest::READABLE,
        ).context("failed to create AsyncFd for perf buffer")?;

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<FileOpenEvent>()))
                .collect::<Vec<_>>();

            loop {
                // Wait until the perf fd is readable (events available).
                let mut guard = match async_fd.readable().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        warn!("CPU {} AsyncFd error: {:#}", cpu_id, e);
                        continue;
                    }
                };

                // Drain all available events.
                loop {
                    if !buf.readable() {
                        break;
                    }

                    let events = match buf.read_events(&mut buffers) {
                        Ok(evts) => evts,
                        Err(e) => {
                            warn!("CPU {} perf read error: {:#}", cpu_id, e);
                            break;
                        }
                    };

                    if events.lost > 0 {
                        warn!(
                            "CPU {} lost {} events (ring buffer full)",
                            cpu_id, events.lost
                        );
                    }

                    for i in 0..events.read {
                        let raw = &buffers[i];
                        if raw.len() < core::mem::size_of::<FileOpenEvent>() {
                            warn!("CPU {} truncated event ({} bytes)", cpu_id, raw.len());
                            continue;
                        }

                        let event: FileOpenEvent = unsafe {
                            core::ptr::read_unaligned(raw.as_ptr() as *const FileOpenEvent)
                        };

                        let filename = c_buf_to_str(&event.filename);
                        let comm = c_buf_to_str(&event.comm);

                        if is_sensitive(&filename) {
                            eprintln!(
                                "\x1b[1;31m[🚨 HIGH RISK]\x1b[0m \
                                 Process \x1b[1;33m{comm}\x1b[0m \
                                 (PID: \x1b[1;36m{pid}\x1b[0m) \
                                 is trying to read \x1b[1;35m{filename}\x1b[0m",
                                comm = comm,
                                pid = event.pid,
                                filename = filename,
                            );
                        }
                    }

                    if events.read == 0 {
                        break;
                    }
                }

                // Clear the readiness so tokio re-polls the fd.
                guard.clear_ready();
            }
        });
    }

    // ── 5. Block until Ctrl-C ────────────────────────────────────
    signal::ctrl_c()
        .await
        .context("failed to listen for Ctrl-C signal")?;
    info!("\n🛑  Shutting down Agent-WatchDog. Goodbye.");

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────

fn c_buf_to_str(buf: &[u8]) -> String {
    let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul_pos]).into_owned()
}

fn is_sensitive(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    SENSITIVE_KEYWORDS.iter().any(|kw| lower.contains(kw))
}
