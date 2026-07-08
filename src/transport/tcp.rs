// ============================================================
// SecurePipe - TCP Transport Layer
// ============================================================
// Accepts incoming TCP connections from ESP32 devices.
// Each connection gets its own task and replay guard.
// The transport layer is deliberately thin - it only handles
// bytes on the wire. All protocol logic lives in the
// protocol and crypto modules.

use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::crypto::aes_gcm::{decrypt_payload, SessionKey};
use crate::error::SecurePipeError;
use crate::protocol::frame::{
    SecurePipeFrame, SensorPayload, AUTH_TAG_SIZE, HEADER_SIZE, MIN_FRAME_SIZE,
};
use crate::protocol::replay::ReplayGuard;

// Shared sensor reading - broadcast to all dashboard clients
#[derive(Debug, Clone, serde::Serialize)]
pub struct SensorReading {
    pub device_id: u32,
    pub sensor_type: String,
    pub value: f32,
    pub unit: String,
    pub sequence_nr: u32,
    pub timestamp: u64,
}

// Security event - replay attempt, tampered frame, etc.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SecurityEvent {
    pub device_id: Option<u32>,
    pub event_type: String,
    pub detail: String,
}

pub struct GatewayState {
    pub key: SessionKey,
    pub readings_tx: broadcast::Sender<SensorReading>,
    pub events_tx: broadcast::Sender<SecurityEvent>,
}

/// Start the TCP listener. Spawns a new task per connection.
pub async fn run_listener(
    bind_addr: &str,
    state: Arc<GatewayState>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!("SecurePipe gateway listening on {}", bind_addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!("New connection from {}", peer_addr);

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                match e {
                    SecurePipeError::ConnectionClosed => {
                        info!("Connection from {} closed", peer_addr);
                    }
                    _ => {
                        error!("Connection error from {}: {}", peer_addr, e);
                    }
                }
            }
        });
    }
}

/// Handle a single TCP connection for its entire lifetime.
async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<GatewayState>,
) -> Result<(), SecurePipeError> {
    let mut replay_guard = ReplayGuard::new();

    loop {
        // Read the fixed header first to know the payload length
        let mut header_buf = [0u8; HEADER_SIZE];
        match stream.read_exact(&mut header_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(SecurePipeError::ConnectionClosed);
            }
            Err(e) => return Err(SecurePipeError::Io(e)),
        }

        // Peek at magic before allocating anything else
        if header_buf[0..2] != crate::protocol::frame::MAGIC {
            warn!("Invalid magic bytes - dropping frame");
            emit_security_event(
                &state,
                None,
                "invalid_magic",
                "Frame rejected: bad magic bytes",
            );
            continue;
        }

        // Extract payload length from header
        let payload_len =
            u32::from_be_bytes(header_buf[19..23].try_into().unwrap()) as usize;

        // Read remaining bytes: payload + auth tag
        let remaining = payload_len + AUTH_TAG_SIZE;
        let mut rest_buf = vec![0u8; remaining];
        stream.read_exact(&mut rest_buf).await?;

        // Assemble full frame bytes and parse
        let mut full_frame = header_buf.to_vec();
        full_frame.extend_from_slice(&rest_buf);

        process_frame(&full_frame, &mut replay_guard, &state);
    }
}

/// Parse, verify, replay-check, and decrypt a raw frame.
fn process_frame(
    raw: &[u8],
    replay_guard: &mut ReplayGuard,
    state: &Arc<GatewayState>,
) {
    // Step 1: Parse frame structure
    let frame = match SecurePipeFrame::parse(raw) {
        Ok(f) => f,
        Err(e) => {
            warn!("Frame parse error: {}", e);
            emit_security_event(state, None, "parse_error", &e.to_string());
            return;
        }
    };

    let device_id = frame.device_id;

    // Step 2: Verify auth tag FIRST - before any other processing
    // Combine encrypted payload + auth tag for ring's open_in_place
    let mut payload_with_tag = frame.encrypted_payload.clone();
    payload_with_tag.extend_from_slice(&frame.auth_tag);

    let aad = frame.header_as_aad();

    let plaintext = match decrypt_payload(&state.key, &frame.nonce, &aad, &payload_with_tag) {
        Ok(p) => p,
        Err(_) => {
            // Never reveal WHY verification failed
            warn!("Auth tag verification failed for device {}", device_id);
            emit_security_event(
                state,
                Some(device_id),
                "auth_tag_invalid",
                "Frame rejected: authentication failed",
            );
            return;
        }
    };

    // Step 3: Replay check (after auth tag - never process unauthenticated data)
    if let Err(e) = replay_guard.check(
        device_id,
        frame.sequence_nr,
        frame.timestamp,
        &frame.nonce,
    ) {
        warn!("Replay detected for device {}: {}", device_id, e);
        emit_security_event(state, Some(device_id), "replay_detected", &e.to_string());
        return;
    }

    // Step 4: Parse decrypted sensor payload
    let sensor = match SensorPayload::parse(&plaintext) {
        Ok(s) => s,
        Err(e) => {
            warn!("Payload parse error for device {}: {}", device_id, e);
            return;
        }
    };

    let reading = SensorReading {
        device_id,
        sensor_type: sensor.sensor_type_str().to_string(),
        value: sensor.value_f32(),
        unit: sensor.unit_str().to_string(),
        sequence_nr: frame.sequence_nr,
        timestamp: frame.timestamp,
    };

    info!(
        "Device {:04X} | {} {:.2}{} | seq={}",
        device_id,
        reading.sensor_type,
        reading.value,
        reading.unit,
        reading.sequence_nr,
    );

    // Broadcast to dashboard
    let _ = state.readings_tx.send(reading);
}

fn emit_security_event(
    state: &Arc<GatewayState>,
    device_id: Option<u32>,
    event_type: &str,
    detail: &str,
) {
    let event = SecurityEvent {
        device_id,
        event_type: event_type.to_string(),
        detail: detail.to_string(),
    };
    let _ = state.events_tx.send(event);
}
