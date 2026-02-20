# Agent-WatchDog

An AI agent runtime security monitoring tool built with Rust and eBPF (Aya framework).

## Overview

Agent-WatchDog monitors all system processes attempting to open sensitive files
(e.g., `.env`, `id_rsa`, `shadow`, `aws/credentials`) using an eBPF tracepoint
attached to `sys_enter_openat`. High-risk file access events are reported in
real-time via a `PerfEventArray` queue.

## Prerequisites

- **Rust nightly** toolchain (for eBPF compilation): `rustup toolchain install nightly --component rust-src`
- **bpf-linker**: `cargo install bpf-linker`
- **Linux kernel ≥ 5.4** with BTF support
- Root privileges for loading eBPF programs

## Build

```bash
# 1. Build the eBPF kernel-space program
cargo xtask build-ebpf

# 2. Build the user-space daemon
cargo build --release
```

## Run

```bash
# Must run as root to load eBPF programs
RUST_LOG=info sudo -E target/release/agent-watchdog
```

## Test

In another terminal, trigger a sensitive file read:

```bash
cat /etc/shadow
cat ~/.ssh/id_rsa
cat /some/path/.env
cat ~/.aws/credentials
```

You should see highlighted `[🚨 HIGH RISK]` warnings in the Agent-WatchDog terminal.
