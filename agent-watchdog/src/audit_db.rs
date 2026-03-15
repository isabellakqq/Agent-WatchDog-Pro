//! SQLite Persistence Layer for Agent-WatchDog Audit Trail.
//!
//! Provides durable storage for audit records so they survive
//! process restarts. Records are written to both the in-memory
//! ring buffer (for fast queries) and SQLite (for durability).
//!
//! On startup, recent records are loaded from SQLite to warm the
//! in-memory cache.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS audit_records (
//!     id           TEXT PRIMARY KEY,
//!     timestamp    TEXT NOT NULL,
//!     agent_id     TEXT NOT NULL,
//!     user_id      TEXT NOT NULL,
//!     session_id   TEXT,
//!     tool         TEXT NOT NULL,
//!     args         TEXT NOT NULL,
//!     decision     TEXT NOT NULL,
//!     risk_score   REAL NOT NULL,
//!     risk_detail  TEXT NOT NULL,
//!     reason       TEXT NOT NULL,
//!     matched_rule TEXT,
//!     dry_run      INTEGER NOT NULL
//! );
//! ```

use std::path::Path;

use anyhow::{Context, Result};
use log::{info, warn};
use rusqlite::{params, Connection};

use crate::audit::AuditRecord;

/// SQLite-backed audit persistence store.
pub struct AuditDb {
    conn: Connection,
}

impl AuditDb {
    /// Open (or create) the SQLite database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open audit database at '{}'", path.display()))?;

        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .with_context(|| "failed to set SQLite pragmas")?;

        let db = Self { conn };
        db.create_tables()?;

        info!("📦  Audit database opened at '{}'", path.display());
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .with_context(|| "failed to open in-memory audit database")?;
        let db = Self { conn };
        db.create_tables()?;
        Ok(db)
    }

    /// Create the required tables if they don't exist.
    fn create_tables(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS audit_records (
                    id           TEXT PRIMARY KEY,
                    timestamp    TEXT NOT NULL,
                    agent_id     TEXT NOT NULL,
                    user_id      TEXT NOT NULL,
                    session_id   TEXT,
                    tool         TEXT NOT NULL,
                    args         TEXT NOT NULL,
                    decision     TEXT NOT NULL,
                    risk_score   REAL NOT NULL,
                    risk_detail  TEXT NOT NULL,
                    reason       TEXT NOT NULL,
                    matched_rule TEXT,
                    dry_run      INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                    ON audit_records(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_agent_id
                    ON audit_records(agent_id);
                CREATE INDEX IF NOT EXISTS idx_audit_decision
                    ON audit_records(decision);",
            )
            .with_context(|| "failed to create audit_records table")?;

        Ok(())
    }

    /// Persist a single audit record to SQLite.
    pub fn insert(&self, record: &AuditRecord) -> Result<()> {
        let decision_str = match record.decision {
            crate::audit::AuditDecision::Allow => "allow",
            crate::audit::AuditDecision::Block => "block",
        };

        let args_json = serde_json::to_string(&record.args)
            .unwrap_or_else(|_| "{}".to_string());
        let risk_detail = serde_json::to_string(&record.risk_breakdown)
            .unwrap_or_else(|_| "{}".to_string());

        self.conn
            .execute(
                "INSERT OR REPLACE INTO audit_records
                 (id, timestamp, agent_id, user_id, session_id, tool, args,
                  decision, risk_score, risk_detail, reason, matched_rule, dry_run)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    record.id,
                    record.timestamp.to_rfc3339(),
                    record.agent_id,
                    record.user_id,
                    record.session_id,
                    record.tool,
                    args_json,
                    decision_str,
                    record.risk_score,
                    risk_detail,
                    record.reason,
                    record.matched_rule,
                    record.dry_run as i32,
                ],
            )
            .with_context(|| format!("failed to insert audit record {}", record.id))?;

        Ok(())
    }

    /// Load the most recent `limit` records from SQLite.
    ///
    /// Used on startup to warm the in-memory cache.
    pub fn load_recent(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, agent_id, user_id, session_id, tool, args,
                        decision, risk_score, risk_detail, reason, matched_rule, dry_run
                 FROM audit_records
                 ORDER BY timestamp DESC
                 LIMIT ?1",
            )
            .with_context(|| "failed to prepare SELECT statement")?;

        let records = stmt
            .query_map(params![limit as i64], |row| {
                let id: String = row.get(0)?;
                let ts_str: String = row.get(1)?;
                let agent_id: String = row.get(2)?;
                let user_id: String = row.get(3)?;
                let session_id: Option<String> = row.get(4)?;
                let tool: String = row.get(5)?;
                let args_str: String = row.get(6)?;
                let decision_str: String = row.get(7)?;
                let risk_score: f64 = row.get(8)?;
                let risk_detail_str: String = row.get(9)?;
                let reason: String = row.get(10)?;
                let matched_rule: Option<String> = row.get(11)?;
                let dry_run_int: i32 = row.get(12)?;

                Ok(AuditRecordRow {
                    id,
                    ts_str,
                    agent_id,
                    user_id,
                    session_id,
                    tool,
                    args_str,
                    decision_str,
                    risk_score,
                    risk_detail_str,
                    reason,
                    matched_rule,
                    dry_run: dry_run_int != 0,
                })
            })
            .with_context(|| "failed to query audit records")?;

        let mut result = Vec::new();
        for row_result in records {
            match row_result {
                Ok(row) => match row.into_audit_record() {
                    Ok(record) => result.push(record),
                    Err(e) => warn!("Skipping corrupt audit record: {:#}", e),
                },
                Err(e) => warn!("Skipping unreadable audit row: {:#}", e),
            }
        }

        // Reverse so oldest-first (matching VecDeque push order)
        result.reverse();

        info!(
            "📦  Loaded {} audit records from SQLite",
            result.len()
        );
        Ok(result)
    }

    /// Count total records in the database.
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_records", [], |row| row.get(0))
            .with_context(|| "failed to count audit records")?;
        Ok(count as usize)
    }
}

/// Intermediate row type for SQLite → AuditRecord conversion.
struct AuditRecordRow {
    id: String,
    ts_str: String,
    agent_id: String,
    user_id: String,
    session_id: Option<String>,
    tool: String,
    args_str: String,
    decision_str: String,
    risk_score: f64,
    risk_detail_str: String,
    reason: String,
    matched_rule: Option<String>,
    dry_run: bool,
}

impl AuditRecordRow {
    fn into_audit_record(self) -> Result<AuditRecord> {
        use chrono::DateTime;

        let timestamp = DateTime::parse_from_rfc3339(&self.ts_str)
            .with_context(|| format!("invalid timestamp: {}", self.ts_str))?
            .with_timezone(&chrono::Utc);

        let args: serde_json::Value = serde_json::from_str(&self.args_str)
            .unwrap_or(serde_json::Value::Null);

        let decision = match self.decision_str.as_str() {
            "block" => crate::audit::AuditDecision::Block,
            _ => crate::audit::AuditDecision::Allow,
        };

        let risk_breakdown: crate::risk::RiskScore =
            serde_json::from_str(&self.risk_detail_str).unwrap_or_else(|_| {
                crate::risk::RiskScore {
                    total: self.risk_score,
                    tool_weight: 0.0,
                    arg_danger: 0.0,
                    frequency_penalty: 0.0,
                    details: vec![],
                }
            });

        Ok(AuditRecord {
            id: self.id,
            timestamp,
            agent_id: self.agent_id,
            user_id: self.user_id,
            session_id: self.session_id,
            tool: self.tool,
            args,
            decision,
            risk_score: self.risk_score,
            risk_breakdown,
            reason: self.reason,
            matched_rule: self.matched_rule,
            dry_run: self.dry_run,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditDecision, AuditRecord};
    use crate::risk::RiskScore;
    use chrono::Utc;

    fn make_record(id: &str, decision: AuditDecision) -> AuditRecord {
        AuditRecord {
            id: id.to_string(),
            timestamp: Utc::now(),
            agent_id: "test-agent".to_string(),
            user_id: "test-user".to_string(),
            session_id: None,
            tool: "file_read".to_string(),
            args: serde_json::json!({"path": "/etc/shadow"}),
            decision,
            risk_score: 75.0,
            risk_breakdown: RiskScore {
                total: 75.0,
                tool_weight: 20.0,
                arg_danger: 40.0,
                frequency_penalty: 15.0,
                details: vec!["test detail".to_string()],
            },
            reason: "Test reason".to_string(),
            matched_rule: Some("test-rule".to_string()),
            dry_run: false,
        }
    }

    #[test]
    fn insert_and_load() {
        let db = AuditDb::open_in_memory().unwrap();

        let record = make_record("rec-1", AuditDecision::Block);
        db.insert(&record).unwrap();

        let loaded = db.load_recent(10).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "rec-1");
        assert_eq!(loaded[0].decision, AuditDecision::Block);
        assert_eq!(loaded[0].tool, "file_read");
    }

    #[test]
    fn count_records() {
        let db = AuditDb::open_in_memory().unwrap();

        db.insert(&make_record("r1", AuditDecision::Allow)).unwrap();
        db.insert(&make_record("r2", AuditDecision::Block)).unwrap();
        db.insert(&make_record("r3", AuditDecision::Allow)).unwrap();

        assert_eq!(db.count().unwrap(), 3);
    }

    #[test]
    fn load_respects_limit() {
        let db = AuditDb::open_in_memory().unwrap();

        for i in 0..20 {
            db.insert(&make_record(&format!("r{}", i), AuditDecision::Allow))
                .unwrap();
        }

        let loaded = db.load_recent(5).unwrap();
        assert_eq!(loaded.len(), 5);
    }
}
