// ============================================================
// SecurePipe - TCP Transport Layer
// ============================================================
// Accepts incoming TCP connections from ESP32 devices.
// Each connection gets its own task, but replay protection and the
// device whitelist are shared gateway-wide (see GatewayState) so they
// keep working correctly across reconnects.
// The transport layer is deliberately thin - it only handles
// bytes on the wire. All protocol logic lives in the
// protocol and crypto modules.

use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::crypto::aes_gcm::{decrypt_payload, SessionKey};
use crate::error::SecurePipeError;
use crate::protocol::frame::{
    SecurePipeFrame, SensorPayload, SENSOR_PROXIMITY, AUTH_TAG_SIZE, HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
};
use crate::protocol::registry::DeviceRegistry;
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
    /// Shared across ALL connections, keyed by device_id - not per-connection.
    /// A per-connection guard would forget everything on reconnect (WiFi
    /// drops are routine for ESP32 devices), silently reopening the replay
    /// window right after every reconnect. See docs/SECURITY.md.
    pub replay_guard: Mutex<ReplayGuard>,
    pub device_registry: DeviceRegistry,
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

        // Extract payload length from header - this field is attacker
        // controlled and NOT yet authenticated (the auth tag hasn't been
        // checked yet). Cap it BEFORE allocating anything of that size,
        // otherwise a peer can declare a multi-gigabyte length and force
        // an allocation of that size on every single frame (memory-
        // exhaustion DoS). See docs/SECURITY.md.
        let payload_len =
            u32::from_be_bytes(header_buf[19..23].try_into().unwrap()) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            warn!(
                "Declared payload length {} exceeds max {} - closing connection",
                payload_len, MAX_PAYLOAD_SIZE
            );
            emit_security_event(
                &state,
                None,
                "payload_too_large",
                &format!(
                    "declared payload length {} exceeds max {}",
                    payload_len, MAX_PAYLOAD_SIZE
                ),
            );
            return Err(SecurePipeError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                got: payload_len,
            });
        }

        // Read remaining bytes: payload + auth tag
        let remaining = payload_len + AUTH_TAG_SIZE;
        let mut rest_buf = vec![0u8; remaining];
        stream.read_exact(&mut rest_buf).await?;

        // Assemble full frame bytes and parse
        let mut full_frame = header_buf.to_vec();
        full_frame.extend_from_slice(&rest_buf);

        process_frame(&full_frame, &state);
    }
}

/// Parse, verify, whitelist-check, replay-check, and decrypt a raw frame.
fn process_frame(raw: &[u8], state: &Arc<GatewayState>) {
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

    // Step 3: Device whitelist check (after auth tag, before replay state
    // is touched - an unlisted device shouldn't even get an entry in the
    // replay guard's per-device map).
    if !state.device_registry.is_allowed(device_id) {
        warn!("Device {:08X} is not on the allowed-devices list", device_id);
        emit_security_event(
            state,
            Some(device_id),
            "unknown_device",
            "Frame rejected: device_id not on whitelist",
        );
        return;
    }

    // Step 4: Replay check (after auth tag - never process unauthenticated
    // data). Shared, device_id-keyed guard - survives reconnects.
    {
        let mut replay_guard = state
            .replay_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    }

    // Step 5: Parse decrypted sensor payload
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

    if sensor.sensor_type == SENSOR_PROXIMITY {
        info!(
            "Device {:04X} | proximity {} ({}) | seq={}",
            device_id,
            if sensor.value_raw > 0 { "OBJECT" } else { "none" },
            sensor.value_raw,
            reading.sequence_nr,
        );
    } else {
        info!(
            "Device {:04X} | {} {:.2}{} | seq={}",
            device_id,
            reading.sensor_type,
            reading.value,
            reading.unit,
            reading.sequence_nr,
        );
    }

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
