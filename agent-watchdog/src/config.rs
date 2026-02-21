//! Configuration loading for Agent-WatchDog.
//!
//! Reads a TOML configuration file that controls dry-run mode,
//! process/PID/path whitelists, and optionally overrides the
//! built-in sensitive keyword list.

use std::path::Path;

use anyhow::{Context, Result};
use log::info;
use serde::Deserialize;

/// Top-level configuration structure.
///
/// Loaded from a TOML file (default: `watchdog.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// When `true`, alerts are logged but `SIGKILL` is never sent.
    pub dry_run: bool,

    /// Process names to ignore (case-insensitive match on `comm`).
    pub whitelist_processes: Vec<String>,

    /// Specific PIDs to ignore.
    pub whitelist_pids: Vec<u32>,

    /// File-path prefixes to ignore.
    pub whitelist_paths: Vec<String>,

    /// Override built-in sensitive keywords.
    /// If `None` (omitted), the compiled-in defaults are used.
    pub sensitive_keywords: Option<Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dry_run: false,
            whitelist_processes: Vec::new(),
            whitelist_pids: Vec::new(),
            whitelist_paths: Vec::new(),
            sensitive_keywords: None,
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// If the file does not exist, returns the default configuration
    /// with a warning.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            info!(
                "Config file '{}' not found — using defaults",
                path.display()
            );
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file '{}'", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file '{}'", path.display()))?;

        info!("📋  Loaded config from '{}'", path.display());
        info!("    dry_run = {}", config.dry_run);
        info!(
            "    whitelist_processes = {:?}",
            config.whitelist_processes
        );
        info!("    whitelist_pids = {:?}", config.whitelist_pids);
        info!("    whitelist_paths = {:?}", config.whitelist_paths);

        Ok(config)
    }

    /// Check whether a process name is whitelisted.
    pub fn is_process_whitelisted(&self, comm: &str) -> bool {
        let lower = comm.to_ascii_lowercase();
        self.whitelist_processes
            .iter()
            .any(|w| lower == w.to_ascii_lowercase())
    }

    /// Check whether a PID is whitelisted.
    pub fn is_pid_whitelisted(&self, pid: u32) -> bool {
        self.whitelist_pids.contains(&pid)
    }

    /// Check whether a file path is whitelisted (by prefix).
    pub fn is_path_whitelisted(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        self.whitelist_paths
            .iter()
            .any(|prefix| lower.starts_with(&prefix.to_ascii_lowercase()))
    }

    /// Check if a filename matches any sensitive keyword.
    ///
    /// Uses the configured keywords if set, otherwise falls back to
    /// the built-in `DEFAULT_SENSITIVE_KEYWORDS`.
    pub fn is_sensitive(&self, filename: &str) -> bool {
        let lower = filename.to_ascii_lowercase();
        match &self.sensitive_keywords {
            Some(keywords) => keywords.iter().any(|kw| lower.contains(kw)),
            None => DEFAULT_SENSITIVE_KEYWORDS
                .iter()
                .any(|kw| lower.contains(kw)),
        }
    }
}

/// Built-in default sensitive keywords.
pub const DEFAULT_SENSITIVE_KEYWORDS: &[&str] = &[
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
