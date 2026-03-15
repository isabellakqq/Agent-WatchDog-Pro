//! Risk Scoring Engine for Agent-WatchDog.
//!
//! Computes a numeric risk score (0–100) for each tool-call request
//! based on three dimensions:
//!
//! 1. **Tool weight** — inherent danger of the tool being called
//! 2. **Argument danger** — how dangerous the specific arguments are
//! 3. **Frequency penalty** — burst detection / rate-based scoring

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::normalizer;
use crate::prompt_detector;

// ── Risk Score ───────────────────────────────────────────────────

/// Composite risk score with breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Total score (0–100). Higher = more dangerous.
    pub total: f64,
    /// Score contribution from tool weight (0–40).
    pub tool_weight: f64,
    /// Score contribution from argument danger (0–40).
    pub arg_danger: f64,
    /// Score contribution from call frequency (0–20).
    pub frequency_penalty: f64,
    /// Human-readable breakdown details.
    pub details: Vec<String>,
}

// ── Tool Weights ─────────────────────────────────────────────────

/// Inherent danger weight per tool category.
/// Scale: 0–40. Unknown tools default to 15.
fn tool_base_weight(tool: &str) -> (f64, &'static str) {
    match tool.to_ascii_lowercase().as_str() {
        // Critical — direct system access
        "shell_exec" | "exec" | "run_command" | "bash" => {
            (40.0, "Shell execution — highest risk")
        }
        "file_write" | "file_delete" | "fs_write" | "write_file" => {
            (35.0, "File write/delete — can corrupt data")
        }
        "file_read" | "fs_read" | "read_file" => {
            (20.0, "File read — can leak secrets")
        }
        "http_request" | "fetch" | "curl" | "api_call" => {
            (25.0, "HTTP request — potential exfiltration")
        }
        "database_query" | "sql_query" | "db_exec" => {
            (30.0, "Database query — can read/modify data")
        }
        "env_read" | "get_env" | "read_env" => {
            (15.0, "Environment read — can leak config")
        }
        "code_exec" | "eval" | "python_exec" => {
            (38.0, "Code execution — near-maximum risk")
        }
        // Low risk — information retrieval
        "search" | "web_search" | "calculator" | "clock" => {
            (5.0, "Information tool — low risk")
        }
        _ => (15.0, "Unknown tool — moderate default risk"),
    }
}

// ── Argument Danger Patterns ─────────────────────────────────────

/// Known dangerous argument patterns with their scores.
/// Each match adds to the argument danger score (capped at 40).
const DANGEROUS_PATTERNS: &[(&str, f64, &str)] = &[
    // ── File paths ───────────────────────────────────────────────
    ("/etc/shadow", 40.0, "Password file access"),
    ("/etc/passwd", 20.0, "User list access"),
    ("id_rsa", 35.0, "SSH private key"),
    ("id_ed25519", 35.0, "SSH private key"),
    (".env", 30.0, "Environment secrets"),
    ("aws/credentials", 35.0, "AWS credentials"),
    (".kube/config", 30.0, "Kubernetes config"),
    ("master.key", 35.0, "Master key access"),
    // ── Shell commands ──────────────────────────────────────────
    ("rm -rf", 40.0, "Recursive force delete"),
    ("chmod 777", 30.0, "Insecure permissions"),
    ("curl", 15.0, "External HTTP call"),
    ("wget", 15.0, "External download"),
    ("nc ", 35.0, "Netcat — possible reverse shell"),
    ("ncat", 35.0, "Ncat — possible reverse shell"),
    ("base64", 20.0, "Encoding — possible obfuscation"),
    ("> /dev/", 35.0, "Writing to device file"),
    ("| bash", 40.0, "Piping to bash — code injection"),
    ("| sh", 35.0, "Piping to sh — code injection"),
    ("eval(", 35.0, "Dynamic code evaluation"),
    ("exec(", 35.0, "Dynamic code execution"),
    ("mkfifo", 30.0, "Named pipe — possible reverse shell"),
    ("/bin/sh -i", 40.0, "Interactive shell — reverse shell"),
    // ── SQL Injection — Classic ─────────────────────────────────
    ("drop table", 40.0, "SQL DROP TABLE"),
    ("drop database", 40.0, "SQL DROP DATABASE"),
    ("delete from", 30.0, "SQL DELETE"),
    ("truncate table", 35.0, "SQL TRUNCATE TABLE"),
    ("truncate ", 30.0, "SQL TRUNCATE"),
    ("alter table", 25.0, "SQL ALTER TABLE"),
    ("' or '1'='1", 40.0, "SQL injection — tautology"),
    ("' or 1=1", 40.0, "SQL injection — tautology"),
    ("or 1=1", 30.0, "SQL injection — tautology"),
    ("' or 'a'='a", 40.0, "SQL injection — tautology"),
    ("' or ''='", 35.0, "SQL injection — tautology"),
    ("having 1=1", 35.0, "SQL injection — HAVING tautology"),
    ("union select", 35.0, "SQL injection — UNION"),
    ("union all select", 35.0, "SQL injection — UNION ALL"),
    ("union%20select", 35.0, "SQL injection — encoded UNION"),
    // ── SQL Injection — Blind / Time-based ──────────────────────
    ("sleep(", 35.0, "SQL injection — time-based blind (SLEEP)"),
    ("benchmark(", 35.0, "SQL injection — time-based blind (BENCHMARK)"),
    ("waitfor delay", 35.0, "SQL injection — MSSQL time-based blind"),
    ("pg_sleep", 35.0, "SQL injection — PostgreSQL time-based blind"),
    ("dbms_lock.sleep", 35.0, "SQL injection — Oracle time-based blind"),
    // ── SQL Injection — Data Exfiltration ────────────────────────
    ("load_file(", 35.0, "SQL injection — file read (LOAD_FILE)"),
    ("into outfile", 35.0, "SQL injection — file write (INTO OUTFILE)"),
    ("into dumpfile", 35.0, "SQL injection — file write (INTO DUMPFILE)"),
    ("information_schema", 30.0, "SQL injection — schema enumeration"),
    ("table_name", 20.0, "SQL injection — table enumeration"),
    ("column_name", 20.0, "SQL injection — column enumeration"),
    ("group_concat(", 25.0, "SQL injection — data extraction"),
    ("concat(", 15.0, "SQL injection — string concatenation"),
    // ── SQL Injection — Stacked Queries ──────────────────────────
    ("; drop", 35.0, "SQL injection — stacked query (DROP)"),
    ("; delete", 30.0, "SQL injection — stacked query (DELETE)"),
    ("; insert", 25.0, "SQL injection — stacked query (INSERT)"),
    ("; update", 25.0, "SQL injection — stacked query (UPDATE)"),
    ("; exec", 30.0, "SQL injection — stacked query (EXEC)"),
    // ── SQL Injection — Stored Procedures ────────────────────────
    ("xp_cmdshell", 40.0, "SQL injection — MSSQL command execution"),
    ("sp_executesql", 30.0, "SQL injection — MSSQL dynamic SQL"),
    ("exec sp_", 30.0, "SQL injection — MSSQL stored procedure"),
    ("exec xp_", 35.0, "SQL injection — MSSQL extended procedure"),
    ("dbms_pipe", 30.0, "SQL injection — Oracle pipe command"),
    // ── SQL Injection — Boolean-based ────────────────────────────
    ("' and '1'='1", 30.0, "SQL injection — boolean test"),
    ("' and 1=1", 30.0, "SQL injection — boolean test"),
    ("' and 1=2", 30.0, "SQL injection — boolean blind probe"),
    ("order by 1", 15.0, "SQL injection — column count probe"),
    ("order by 99", 25.0, "SQL injection — column count probe"),
    // ── Exfiltration ────────────────────────────────────────────
    ("webhook.site", 30.0, "Known exfiltration endpoint"),
    ("ngrok", 25.0, "Tunnel — possible exfiltration"),
    ("pastebin", 25.0, "Paste service — possible data leak"),
    ("requestbin", 25.0, "Request bin — possible exfiltration"),
    ("hookbin", 25.0, "Hook bin — possible exfiltration"),
    ("pipedream", 25.0, "Pipedream — possible exfiltration"),
    ("burpcollaborator", 30.0, "Burp Collaborator — pentest tool"),
    ("oastify.com", 30.0, "OAST interaction — pentest tool"),
];

/// Compute the argument danger score from request arguments.
///
/// Applies normalization to defeat encoding-based evasion, then
/// matches against dangerous patterns AND prompt injection indicators.
fn arg_danger_score(args: &serde_json::Value) -> (f64, Vec<String>) {
    let raw_str = args.to_string();

    // Normalize to defeat evasion: URL decoding, SQL comment stripping,
    // path canonicalization, base64 decoding, hex decoding, etc.
    let normalized = normalizer::normalize(&raw_str);
    debug!("Normalized args for risk scoring: {}", &normalized[..normalized.len().min(200)]);

    let mut score: f64 = 0.0;
    let mut details = Vec::new();

    // 1. Match dangerous patterns against the NORMALIZED string
    for &(pattern, weight, desc) in DANGEROUS_PATTERNS {
        if normalized.contains(&pattern.to_ascii_lowercase()) {
            score += weight;
            details.push(format!("{} (+{:.0})", desc, weight));
        }
    }

    // 2. Prompt injection detection (runs on raw args to preserve structure)
    let pi_result = prompt_detector::detect(args);
    if pi_result.detected {
        score += pi_result.score;
        details.extend(pi_result.details);
    }

    // Cap at 40
    (score.min(40.0), details)
}

// ── Frequency Tracker ────────────────────────────────────────────

/// Tracks per-agent call frequency for burst detection.
pub struct FrequencyTracker {
    /// agent_id → list of recent call timestamps
    windows: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
    /// Time window for frequency counting.
    window_duration: Duration,
    /// Number of calls in window before penalty kicks in.
    burst_threshold: usize,
}

impl FrequencyTracker {
    /// Create a new frequency tracker.
    ///
    /// - `window_seconds`: time window for counting calls
    /// - `burst_threshold`: number of calls before penalty
    pub fn new(window_seconds: i64, burst_threshold: usize) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            window_duration: Duration::seconds(window_seconds),
            burst_threshold,
        }
    }

    /// Record a call and return the frequency penalty (0–20).
    pub fn record_and_score(&self, agent_id: &str) -> (f64, Option<String>) {
        let now = Utc::now();
        let cutoff = now - self.window_duration;

        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());

        // Periodic GC: remove agents with zero recent calls.
        // Run every ~100 calls to avoid overhead.
        if windows.len() > 100 {
            windows.retain(|_id, calls| {
                calls.retain(|t| *t > cutoff);
                !calls.is_empty()
            });
        }

        let calls = windows.entry(agent_id.to_string()).or_default();

        // Remove expired entries for this agent
        calls.retain(|t| *t > cutoff);

        // Record this call
        calls.push(now);

        let count = calls.len();

        if count > self.burst_threshold {
            let ratio = (count - self.burst_threshold) as f64 / self.burst_threshold as f64;
            let penalty = (ratio * 20.0).min(20.0);
            (
                penalty,
                Some(format!(
                    "Burst: {} calls in {}s (threshold: {})",
                    count,
                    self.window_duration.num_seconds(),
                    self.burst_threshold
                )),
            )
        } else {
            (0.0, None)
        }
    }
}

// ── Risk Engine ──────────────────────────────────────────────────

/// Computes composite risk scores for tool-call requests.
pub struct RiskEngine {
    frequency: FrequencyTracker,
}

impl RiskEngine {
    /// Create a new risk engine with default settings.
    pub fn new() -> Self {
        Self {
            // 60-second window, 10 calls before burst penalty
            frequency: FrequencyTracker::new(60, 10),
        }
    }

    /// Compute the full risk score for a tool-call request.
    pub fn score(
        &self,
        tool: &str,
        args: &serde_json::Value,
        agent_id: &str,
    ) -> RiskScore {
        let mut details = Vec::new();

        // 1. Tool weight (0–40)
        let (tool_weight, tool_desc) = tool_base_weight(tool);
        details.push(format!("Tool: {} — {} (+{:.0})", tool, tool_desc, tool_weight));

        // 2. Argument danger (0–40)
        let (arg_danger, arg_details) = arg_danger_score(args);
        details.extend(arg_details);

        // 3. Frequency penalty (0–20)
        let (frequency_penalty, freq_detail) = self.frequency.record_and_score(agent_id);
        if let Some(detail) = freq_detail {
            details.push(detail);
        }

        let total = (tool_weight + arg_danger + frequency_penalty).min(100.0);

        RiskScore {
            total,
            tool_weight,
            arg_danger,
            frequency_penalty,
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_exec_high_weight() {
        let engine = RiskEngine::new();
        let score = engine.score(
            "shell_exec",
            &serde_json::json!({"cmd": "ls"}),
            "agent-1",
        );
        assert!(score.tool_weight >= 40.0);
        assert!(score.total >= 40.0);
    }

    #[test]
    fn safe_tool_low_score() {
        let engine = RiskEngine::new();
        let score = engine.score(
            "calculator",
            &serde_json::json!({"expr": "1+1"}),
            "agent-1",
        );
        assert!(score.total < 20.0);
    }

    #[test]
    fn dangerous_args_add_score() {
        let engine = RiskEngine::new();
        let score = engine.score(
            "file_read",
            &serde_json::json!({"path": "/etc/shadow"}),
            "agent-1",
        );
        // file_read (20) + /etc/shadow (40) = 60
        assert!(score.total >= 55.0);
    }

    #[test]
    fn burst_detection() {
        let engine = RiskEngine::new();
        // Make 15 rapid calls — should trigger burst penalty
        for _ in 0..15 {
            engine.score(
                "file_read",
                &serde_json::json!({"path": "/tmp/ok"}),
                "burst-agent",
            );
        }
        let score = engine.score(
            "file_read",
            &serde_json::json!({"path": "/tmp/ok"}),
            "burst-agent",
        );
        assert!(score.frequency_penalty > 0.0);
    }
}
