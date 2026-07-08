mod api;
mod crypto;
mod error;
mod protocol;
mod transport;

use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;
use tracing_subscriber::EnvFilter;

use api::routes::build_router;
use crypto::aes_gcm::SessionKey;
use transport::tcp::{GatewayState, run_listener};

const TCP_BIND:  &str = "0.0.0.0:7777";
const HTTP_BIND: &str = "0.0.0.0:8080";

#[tokio::main]
async fn main() {
    // Set RUST_LOG=debug for verbose output, default is info
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("securepipe=info".parse().unwrap()))
        .init();

    info!("SecurePipe Gateway starting");
    info!("NOTE: Using dev test key - replace with ECDH before production");

    // Broadcast channels: capacity 64 means up to 64 unread messages
    // before the oldest is dropped. Fine for a dashboard.
    let (readings_tx, _) = broadcast::channel(64);
    let (events_tx, _)   = broadcast::channel(64);

    let state = Arc::new(GatewayState {
        // MVP: hardcoded test key. Replace with ECDH-derived key in Phase 2.
        key: SessionKey::dev_test_key(),
        readings_tx,
        events_tx,
    });

    // Start TCP listener (handles ESP32 connections)
    let tcp_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = run_listener(TCP_BIND, tcp_state).await {
            tracing::error!("TCP listener error: {}", e);
        }
    });

    let router = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(HTTP_BIND).await.unwrap();
    info!("Dashboard available at http://localhost:8080");

    axum::serve(listener, router).await.unwrap();
}
