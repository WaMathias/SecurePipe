// ============================================================
// SecurePipe - HTTP API (axum)
// ============================================================
// Two endpoints:
//   GET /api/stream   - Server-Sent Events: live readings + security events
//   GET /api/status   - JSON: gateway status
//   GET /             - serves the dashboard HTML

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use futures::stream::{self, Stream};
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;

use crate::transport::tcp::{GatewayState, SecurityEvent, SensorReading};

pub fn build_router(state: Arc<GatewayState>) -> Router {
    Router::new()
        .route("/", get(dashboard_html))
        .route("/api/stream", get(sse_stream))
        .route("/api/status", get(status))
        .layer(CorsLayer::permissive())
        .with_state(state)
}



// SSE stream - combines readings and security events
#[derive(serde::Serialize)]
#[serde(tag = "type", content = "data")]
enum SsePayload {
    Reading(SensorReading),
    SecurityEvent(SecurityEvent),
}

async fn sse_stream(
    State(state): State<Arc<GatewayState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let readings = BroadcastStream::new(state.readings_tx.subscribe())
        .filter_map(|r| r.ok())
        .map(|r| {
            let payload = SsePayload::Reading(r);
            Ok(Event::default()
                .event("message")
                .data(serde_json::to_string(&payload).unwrap()))
        });

    let events = BroadcastStream::new(state.events_tx.subscribe())
        .filter_map(|e| e.ok())
        .map(|e| {
            let payload = SsePayload::SecurityEvent(e);
            Ok(Event::default()
                .event("message")
                .data(serde_json::to_string(&payload).unwrap()))
        });

    // Merge both streams
    let merged = stream::select(readings, events);

    Sse::new(merged).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

// ============================================================
// Status endpoint
// ============================================================

async fn status() -> impl IntoResponse {
    Json(json!({
        "status": "running",
        "protocol": "SecurePipe v1",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ============================================================
// Dashboard HTML - served inline, no separate file needed
// ============================================================

async fn dashboard_html() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

static DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecurePipe Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }
    h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 0.25rem; }
    .subtitle { color: #64748b; font-size: 0.875rem; margin-bottom: 2rem; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
    .card { background: #1e2330; border: 1px solid #2d3748; border-radius: 12px; padding: 1.25rem; }
    .card h2 { font-size: 0.75rem; font-weight: 500; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem; }
    #readings-list, #events-list { list-style: none; display: flex; flex-direction: column; gap: 6px; max-height: 320px; overflow-y: auto; }
    .reading-item { background: #111827; border-radius: 8px; padding: 10px 12px; font-size: 0.875rem; display: flex; justify-content: space-between; align-items: center; }
    .reading-value { font-size: 1.125rem; font-weight: 600; color: #34d399; }
    .reading-meta { color: #64748b; font-size: 0.75rem; }
    .event-item { background: #1a0a0a; border: 1px solid #7f1d1d; border-radius: 8px; padding: 8px 12px; font-size: 0.8rem; }
    .event-type { color: #f87171; font-weight: 600; margin-bottom: 2px; }
    .event-detail { color: #94a3b8; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #64748b; display: inline-block; margin-right: 6px; }
    .status-dot.connected { background: #34d399; box-shadow: 0 0 6px #34d399; }
    #connection-status { font-size: 0.875rem; color: #64748b; margin-bottom: 1.5rem; display: flex; align-items: center; }
    @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>SecurePipe</h1>
  <p class="subtitle">Verschlüsseltes IoT-Sensorprotokoll — Live-Dashboard</p>
  <p id="connection-status"><span class="status-dot" id="dot"></span><span id="status-text">Verbinde...</span></p>

  <div class="grid">
    <div class="card">
      <h2>Sensordaten</h2>
      <ul id="readings-list"><li style="color:#64748b; font-size:0.875rem">Warte auf Daten...</li></ul>
    </div>
    <div class="card">
      <h2>Sicherheitsereignisse</h2>
      <ul id="events-list"><li style="color:#64748b; font-size:0.875rem">Keine Ereignisse</li></ul>
    </div>
  </div>

  <script>
    const readingsList = document.getElementById('readings-list');
    const eventsList   = document.getElementById('events-list');
    const dot          = document.getElementById('dot');
    const statusText   = document.getElementById('status-text');
    let firstReading   = true;
    let firstEvent     = true;

    const es = new EventSource('/api/stream');

    es.onopen = () => {
      dot.classList.add('connected');
      statusText.textContent = 'Verbunden';
    };

    es.onmessage = (e) => {
      const msg = JSON.parse(e.data);

      if (msg.type === 'Reading') {
        if (firstReading) { readingsList.innerHTML = ''; firstReading = false; }
        const d = msg.data;
        const li = document.createElement('li');
        li.className = 'reading-item';
        li.innerHTML = `
          <div>
            <div style="font-weight:500">${d.sensor_type} · Gerät ${d.device_id.toString(16).padStart(4,'0').toUpperCase()}</div>
            <div class="reading-meta">Seq ${d.sequence_nr} · ${new Date(d.timestamp * 1000).toLocaleTimeString()}</div>
          </div>
          <div class="reading-value">${d.value.toFixed(2)} ${d.unit}</div>`;
        readingsList.prepend(li);
        if (readingsList.children.length > 50) readingsList.lastChild.remove();
      }

      if (msg.type === 'SecurityEvent') {
        if (firstEvent) { eventsList.innerHTML = ''; firstEvent = false; }
        const d = msg.data;
        const li = document.createElement('li');
        li.className = 'event-item';
        li.innerHTML = `
          <div class="event-type">${d.event_type.replace(/_/g,' ').toUpperCase()}</div>
          <div class="event-detail">${d.detail}</div>`;
        eventsList.prepend(li);
        if (eventsList.children.length > 30) eventsList.lastChild.remove();
      }
    };

    es.onerror = () => {
      dot.classList.remove('connected');
      statusText.textContent = 'Verbindung unterbrochen — versuche erneut...';
    };
  </script>
</body>
</html>
"#;
