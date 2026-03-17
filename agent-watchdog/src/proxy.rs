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

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
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
    pub runtime: SharedRuntimeState,
}

pub type SharedRuntimeState = Arc<RwLock<RuntimeState>>;

#[derive(Debug, Clone, Serialize)]
pub struct AgentHeartbeat {
    pub agent_id: String,
    pub session_id: Option<String>,
    pub model: Option<String>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeState {
    pub started_at: DateTime<Utc>,
    pub mode: String,
    pub intercept_total: u64,
    pub blocked_total: u64,
    pub retry_total: u64,
    pub fallback_activations: u64,
    pub last_error: Option<String>,
    pub heartbeats: HashMap<String, AgentHeartbeat>,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            started_at: Utc::now(),
            mode: "normal".to_string(),
            intercept_total: 0,
            blocked_total: 0,
            retry_total: 0,
            fallback_activations: 0,
            last_error: None,
            heartbeats: HashMap::new(),
        }
    }
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

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub server_time: DateTime<Utc>,
    pub mode: String,
}

#[derive(Debug, Serialize)]
pub struct ReliabilityStatusResponse {
    pub started_at: DateTime<Utc>,
    pub server_time: DateTime<Utc>,
    pub uptime_seconds: i64,
    pub mode: String,
    pub intercept_total: u64,
    pub blocked_total: u64,
    pub retry_total: u64,
    pub fallback_activations: u64,
    pub online_agents: usize,
    pub stale_agents: usize,
    pub last_error: Option<String>,
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
        // ── 24/7 reliability endpoints ──
        .route("/v1/agent/heartbeat", post(agent_heartbeat))
        .route("/v1/reliability/status", get(reliability_status))
        .route("/v1/reliability/fallback/activate", post(activate_fallback))
        .route("/v1/reliability/fallback/deactivate", post(deactivate_fallback))
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

async fn agent_heartbeat(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<HeartbeatRequest>,
) -> impl IntoResponse {
    let mut runtime = state.runtime.write().await;
    runtime.heartbeats.insert(
        req.agent_id.clone(),
        AgentHeartbeat {
            agent_id: req.agent_id,
            session_id: req.session_id,
            model: req.model,
            last_seen: Utc::now(),
        },
    );

    Json(HeartbeatResponse {
        ok: true,
        server_time: Utc::now(),
        mode: runtime.mode.clone(),
    })
}

async fn reliability_status(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let runtime = state.runtime.read().await;
    let now = Utc::now();
    let stale_cutoff = now - chrono::Duration::seconds(120);

    let online_agents = runtime
        .heartbeats
        .values()
        .filter(|hb| hb.last_seen > stale_cutoff)
        .count();
    let stale_agents = runtime.heartbeats.len().saturating_sub(online_agents);

    Json(ReliabilityStatusResponse {
        started_at: runtime.started_at,
        server_time: now,
        uptime_seconds: (now - runtime.started_at).num_seconds(),
        mode: runtime.mode.clone(),
        intercept_total: runtime.intercept_total,
        blocked_total: runtime.blocked_total,
        retry_total: runtime.retry_total,
        fallback_activations: runtime.fallback_activations,
        online_agents,
        stale_agents,
        last_error: runtime.last_error.clone(),
    })
}

async fn activate_fallback(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let mut runtime = state.runtime.write().await;
    runtime.mode = "fallback".to_string();
    runtime.fallback_activations += 1;
    runtime.retry_total += 1;

    Json(HeartbeatResponse {
        ok: true,
        server_time: Utc::now(),
        mode: runtime.mode.clone(),
    })
}

async fn deactivate_fallback(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let mut runtime = state.runtime.write().await;
    runtime.mode = "normal".to_string();

    Json(HeartbeatResponse {
        ok: true,
        server_time: Utc::now(),
        mode: runtime.mode.clone(),
    })
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

    {
        let mut runtime = state.runtime.write().await;
        runtime.intercept_total += 1;
    }

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
            {
                let mut runtime = state.runtime.write().await;
                runtime.blocked_total += 1;
                runtime.last_error = Some(format!(
                    "blocked tool={} agent={} reason={}",
                    tool_call.tool, tool_call.agent_id, result.reason
                ));
            }
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
