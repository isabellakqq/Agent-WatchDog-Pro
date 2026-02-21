//! Axum HTTP + WebSocket server for Agent-WatchDog dashboard.
//!
//! Provides REST endpoints for the React frontend and a WebSocket
//! endpoint for real-time event streaming.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use log::{info, warn};
use serde::Serialize;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};

use crate::event_store::{AlertEvent, SharedEventStore};

// ── App state ────────────────────────────────────────────────────

/// Shared application state passed to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: SharedEventStore,
    pub tx: broadcast::Sender<AlertEvent>,
}

// ── Router ───────────────────────────────────────────────────────

/// Build the Axum router with all API routes.
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Dashboard stats
        .route("/api/stats", get(get_stats))
        // All events (paginated in the future)
        .route("/api/events", get(get_events))
        // Active alerts only
        .route("/api/alerts", get(get_active_alerts))
        // Block a process
        .route("/api/events/{id}/block", post(block_event))
        // Mark as false-positive
        .route("/api/events/{id}/ignore", post(ignore_event))
        // WebSocket for real-time events
        .route("/ws/events", get(ws_handler))
        // Health check
        .route("/api/health", get(health))
        .layer(cors)
        .with_state(Arc::new(state))
}

// ── Handlers ─────────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.stats())
}

async fn get_events(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.all_events())
}

async fn get_active_alerts(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.active_alerts())
}

/// Response for block/ignore actions.
#[derive(Serialize)]
struct ActionResponse {
    success: bool,
    message: String,
    event: Option<AlertEvent>,
}

async fn block_event(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut store = state.store.write().await;

    match store.block_event(&id) {
        Some(event) => {
            // Attempt to kill the process.
            let pid = event.pid;
            drop(store); // release lock before syscall

            // SAFETY: we are sending SIGKILL to the process.
            // This requires root — which Agent-WatchDog already runs as.
            let killed = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            let msg = if killed == 0 {
                info!("🛑 Blocked process {} (PID: {})", event.comm, pid);
                format!("Process {} (PID: {}) has been killed", event.comm, pid)
            } else {
                warn!("Failed to kill PID {} (may have already exited)", pid);
                format!(
                    "Process marked as blocked but kill failed (PID: {} may have exited)",
                    pid
                )
            };

            Json(ActionResponse {
                success: true,
                message: msg,
                event: Some(event),
            })
        }
        None => Json(ActionResponse {
            success: false,
            message: format!("Event {} not found", id),
            event: None,
        }),
    }
}

async fn ignore_event(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut store = state.store.write().await;

    match store.ignore_event(&id) {
        Some(event) => {
            info!("👁 Marked event {} as false positive", id);
            Json(ActionResponse {
                success: true,
                message: "Event marked as false positive".to_string(),
                event: Some(event),
            })
        }
        None => Json(ActionResponse {
            success: false,
            message: format!("Event {} not found", id),
            event: None,
        }),
    }
}

// ── WebSocket ────────────────────────────────────────────────────

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    info!("🔌 WebSocket client connected");

    // Forward broadcast events → WebSocket client
    let send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&event) {
                if sender.send(Message::Text(json.into())).await.is_err() {
                    break; // client disconnected
                }
            }
        }
    });

    // Read from client (we don't expect messages, but drain to detect close)
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(_msg)) = receiver.next().await {
            // ignore client messages for now
        }
    });

    // When either task finishes, abort the other
    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }

    info!("🔌 WebSocket client disconnected");
}
