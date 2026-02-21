//! Agent-WatchDog — User-space daemon
//!
//! Loads the compiled eBPF object, attaches it to the
//! `syscalls/sys_enter_openat` tracepoint, and asynchronously polls
//! the `PerfEventArray` for `FileOpenEvent`s.
//!
//! Exposes an HTTP + WebSocket API (default port 3000) for the
//! React dashboard frontend.

mod api;
mod event_store;

use anyhow::{Context, Result};
use aya::{
    maps::perf::PerfEventArray,
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use chrono::Utc;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;
use tokio::sync::broadcast;
use uuid::Uuid;

use agent_watchdog_common::FileOpenEvent;
use event_store::{AlertEvent, AlertStatus, EventStore, Severity};

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
    #[arg(
        short,
        long,
        default_value = "target/bpfel-unknown-none/release/agent-watchdog"
    )]
    bpf_path: String,

    /// Port for the HTTP/WebSocket API server.
    #[arg(short, long, default_value = "3000")]
    port: u16,
}

// ── Entry point ──────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    // ── 1. Shared state ──────────────────────────────────────────
    let store = EventStore::shared();
    let (tx, _rx) = broadcast::channel::<AlertEvent>(1024);

    // ── 2. Start API server ──────────────────────────────────────
    let api_state = api::AppState {
        store: store.clone(),
        tx: tx.clone(),
    };
    let router = api::create_router(api_state);

    let addr = format!("0.0.0.0:{}", opt.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind to {}", addr))?;
    info!("🌐  API server listening on http://{}", addr);

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            warn!("API server error: {:#}", e);
        }
    });

    // ── 3. Load the eBPF object ──────────────────────────────────
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

    // ── 4. Attach to the tracepoint ──────────────────────────────
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

    // ── 5. Open PerfEventArray and spawn per-CPU readers ─────────
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

        let store = store.clone();
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<FileOpenEvent>()))
                .collect::<Vec<_>>();

            // Poll the perf ring buffer at a short interval.
            // This avoids the AsyncFd issue where perf_event fds are
            // not set to non-blocking mode by default.
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));

            loop {
                interval.tick().await;

                // Drain all available events.
                while buf.readable() {
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

                        // SAFETY: `FileOpenEvent` is `#[repr(C)]`, `Copy`, and
                        // contains only fixed-size fields.  The buffer is at
                        // least `size_of::<FileOpenEvent>()` bytes (checked above).
                        let event: FileOpenEvent = unsafe {
                            core::ptr::read_unaligned(raw.as_ptr() as *const FileOpenEvent)
                        };

                        let filename = c_buf_to_str(&event.filename);
                        let comm = c_buf_to_str(&event.comm);

                        debug!(
                            "CPU {} event: pid={} comm={} file={}",
                            cpu_id, event.pid, comm, filename,
                        );

                        if is_sensitive(&filename) {
                            warn!(
                                "[🚨 HIGH RISK] Process {} (PID: {}) is trying to read {}",
                                comm, event.pid, filename,
                            );

                            let alert = AlertEvent {
                                id: Uuid::new_v4().to_string(),
                                timestamp: Utc::now(),
                                pid: event.pid,
                                comm: comm.clone(),
                                filename: filename.clone(),
                                severity: Severity::High,
                                status: AlertStatus::Active,
                            };

                            // Store the event
                            {
                                let mut s = store.write().await;
                                s.push(alert.clone());
                            }

                            // Broadcast to WebSocket clients (ignore if no receivers)
                            let _ = tx.send(alert);
                        }
                    }

                    if events.read == 0 {
                        break;
                    }
                }
            }
        });
    }

    // ── 6. Block until Ctrl-C ────────────────────────────────────
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
