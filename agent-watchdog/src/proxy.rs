//! Proxy API — The Agent Firewall interceptor endpoint.
//!
//! This is the **core product surface**: an HTTP endpoint that
//! AI agents call INSTEAD of directly invoking tools.
//!
//! ```text
//! Agent ──► POST /v1/intercept ──► PolicyEngine ──► Allow/Block
//!                                       │
//!                                   AuditStore
//! ```
//!
//! ## Integration Modes
//!
//! 1. **Proxy mode**: Agent sends tool calls here; if allowed,
//!    WatchDog forwards to the real tool and returns the result.
//!
//! 2. **Interceptor mode**: Agent SDK wraps tool calls with a
//!    pre-check to `POST /v1/intercept`. If blocked, raises
//!    `SecurityException` before the tool ever executes.
//!
//! Both modes are non-invasive — no need to modify agent core code.

use std::sync::Arc;

use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use crate::audit::SharedAuditStore;
use crate::policy::{Decision, PolicyEngine, PolicyResult, ToolCallRequest};
use crate::risk::RiskEngine;

// ── Proxy State ──────────────────────────────────────────────────

/// Shared state for the proxy/firewall API.
pub struct ProxyState {
    pub policy: PolicyEngine,
    pub risk: RiskEngine,
    pub audit: SharedAuditStore,
}

// ── Request / Response types ─────────────────────────────────────

/// Incoming intercept request from an agent or SDK wrapper.
#[derive(Debug, Deserialize)]
pub struct InterceptRequest {
    /// Agent identifier.
    pub agent_id: String,
    /// User or session owner.
    pub user_id: String,
    /// The tool being called (e.g. "file_read", "shell_exec").
    pub tool: String,
    /// Tool arguments (arbitrary JSON).
    pub args: serde_json::Value,
    /// Optional session ID for grouping.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Intercept response — the enforcement verdict.
#[derive(Debug, Serialize)]
pub struct InterceptResponse {
    /// "allow" or "block"
    pub decision: String,
    /// true if the tool call is permitted to proceed
    pub allowed: bool,
    /// Risk score (0–100)
    pub risk_score: f64,
    /// Risk score breakdown
    pub risk_breakdown: RiskBreakdown,
    /// Human-readable reason
    pub reason: String,
    /// Which rule matched (if any)
    pub matched_rule: Option<String>,
    /// Whether the system is in dry-run mode
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct RiskBreakdown {
    pub total: f64,
    pub tool_weight: f64,
    pub arg_danger: f64,
    pub frequency_penalty: f64,
    pub details: Vec<String>,
}

/// Audit query response.
#[derive(Debug, Serialize)]
pub struct AuditResponse {
    pub records: Vec<crate::audit::AuditRecord>,
    pub stats: crate::audit::AuditStats,
}

// ── Router ───────────────────────────────────────────────────────

/// Build the firewall proxy router.
pub fn create_proxy_router(state: Arc<ProxyState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // ── Core firewall endpoint ──
        .route("/v1/intercept", post(intercept))
        // ── Audit endpoints ──
        .route("/v1/audit", get(get_audit))
        .route("/v1/audit/stats", get(get_audit_stats))
        // ── Health ──
        .route("/v1/health", get(health))
        .layer(cors)
        .with_state(state)
}

// ── Handlers ─────────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

/// **THE CORE FIREWALL ENDPOINT.**
///
/// Receives a tool-call request, evaluates it against the policy
/// engine, records the audit trail, and returns an enforcement
/// decision.
///
/// If `decision == "block"`, the agent MUST NOT proceed with the
/// tool call. The SDK wrapper should raise a `SecurityException`.
async fn intercept(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<InterceptRequest>,
) -> impl IntoResponse {
    let tool_call = ToolCallRequest {
        agent_id: req.agent_id,
        user_id: req.user_id,
        tool: req.tool,
        args: req.args,
        timestamp: Utc::now(),
        session_id: req.session_id,
    };

    // 1. Compute risk score
    let risk = state.risk.score(
        &tool_call.tool,
        &tool_call.args,
        &tool_call.agent_id,
    );

    // 2. Evaluate against policy rules
    let result: PolicyResult = state.policy.evaluate(&tool_call, &risk);

    // 3. Record audit trail
    let audit_record = state.policy.to_audit_record(&tool_call, &result);
    {
        let mut store = state.audit.write().await;
        store.record(audit_record);
    }

    // 4. Log the decision
    match result.decision {
        Decision::Block => {
            warn!(
                "🛑 BLOCKED: agent={} tool={} args={} reason={}",
                tool_call.agent_id,
                tool_call.tool,
                tool_call.args,
                result.reason,
            );
        }
        Decision::Allow => {
            info!(
                "✅ ALLOWED: agent={} tool={} risk={:.1}",
                tool_call.agent_id,
                tool_call.tool,
                result.risk_score.total,
            );
        }
    }

    // 5. Return enforcement verdict
    let response = InterceptResponse {
        decision: match result.decision {
            Decision::Allow => "allow".into(),
            Decision::Block => "block".into(),
        },
        allowed: result.decision == Decision::Allow,
        risk_score: result.risk_score.total,
        risk_breakdown: RiskBreakdown {
            total: result.risk_score.total,
            tool_weight: result.risk_score.tool_weight,
            arg_danger: result.risk_score.arg_danger,
            frequency_penalty: result.risk_score.frequency_penalty,
            details: result.risk_score.details,
        },
        reason: result.reason,
        matched_rule: result.matched_rule,
        dry_run: state.policy.dry_run(),
    };

    // Return 403 for blocked requests, 200 for allowed
    if result.decision == Decision::Block {
        (axum::http::StatusCode::FORBIDDEN, Json(response))
    } else {
        (axum::http::StatusCode::OK, Json(response))
    }
}

/// Get audit records.
async fn get_audit(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let store = state.audit.read().await;
    Json(AuditResponse {
        records: store.recent(100),
        stats: store.stats(),
    })
}

/// Get audit summary stats.
async fn get_audit_stats(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let store = state.audit.read().await;
    Json(store.stats())
}
