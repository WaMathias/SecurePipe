mod api;
mod crypto;
mod error;
mod protocol;
mod transport;

use std::env;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tracing::info;
use tracing_subscriber::EnvFilter;

use api::routes::build_router;
use crypto::aes_gcm::SessionKey;
use protocol::registry::DeviceRegistry;
use protocol::replay::ReplayGuard;
use transport::tcp::{run_listener, GatewayState};

// Defaults used when the corresponding env var isn't set. This lets the
// exact same binary run either directly on your PC (defaults are fine
// for local testing) or on a Raspberry Pi / anywhere else, just by
// setting SECUREPIPE_TCP_BIND / SECUREPIPE_HTTP_BIND - no recompile.
const DEFAULT_TCP_BIND: &str = "0.0.0.0:7777";
const DEFAULT_HTTP_BIND: &str = "0.0.0.0:8080";

const TCP_BIND_ENV_VAR: &str = "SECUREPIPE_TCP_BIND";
const HTTP_BIND_ENV_VAR: &str = "SECUREPIPE_HTTP_BIND";

fn bind_addr(env_var: &str, default: &str) -> String {
    env::var(env_var).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() {
    // Set RUST_LOG=debug for verbose output, default is info
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("securepipe=info".parse().unwrap()))
        .init();

    info!("SecurePipe Gateway starting");
    info!("NOTE: Using dev test key - replace with ECDH before production");

    let tcp_bind = bind_addr(TCP_BIND_ENV_VAR, DEFAULT_TCP_BIND);
    let http_bind = bind_addr(HTTP_BIND_ENV_VAR, DEFAULT_HTTP_BIND);

    // Broadcast channels: capacity 64 means up to 64 unread messages
    // before the oldest is dropped. Fine for a dashboard.
    let (readings_tx, _) = broadcast::channel(64);
    let (events_tx, _)   = broadcast::channel(64);

    let state = Arc::new(GatewayState {
        // MVP: hardcoded test key. Replace with ECDH-derived key in Phase 2.
        key: SessionKey::dev_test_key(),
        readings_tx,
        events_tx,
        // Shared across every connection and kept alive for the whole
        // process lifetime - see docs/SECURITY.md for why this must NOT
        // be per-connection.
        replay_guard: Mutex::new(ReplayGuard::new()),
        device_registry: DeviceRegistry::from_env(),
    });

    // Start TCP listener (handles ESP32 connections)
    let tcp_state = Arc::clone(&state);
    let tcp_bind_for_task = tcp_bind.clone();
    tokio::spawn(async move {
        if let Err(e) = run_listener(&tcp_bind_for_task, tcp_state).await {
            tracing::error!("TCP listener error: {}", e);
        }
    });

    let router = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(&http_bind).await.unwrap();
    info!("Dashboard available at http://{}", http_bind);

    axum::serve(listener, router).await.unwrap();
}
