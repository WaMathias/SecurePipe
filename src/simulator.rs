// ============================================================
// SecurePipe Simulator
// ============================================================
// Imitates an ESP32 sender. Sends valid encrypted frames
// to the gateway, then optionally replays an old frame
// to trigger the replay detection.
//
// Usage:
//   cargo run --bin simulator          # normal mode
//   cargo run --bin simulator replay   # send a replay attack after 5 frames

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

// Import protocol and crypto from the main crate
use securepipe::crypto::aes_gcm::{encrypt_payload, SessionKey};
use securepipe::protocol::frame::{
    MAGIC, PROTOCOL_VERSION,
    SENSOR_TEMPERATURE, UNIT_CELSIUS,
};

const GATEWAY_ADDR: &str = "127.0.0.1:7777";
const DEVICE_ID: u32 = 0x00000001;

#[tokio::main]
async fn main() {
    let replay_mode = env::args().any(|a| a == "replay");

    println!("SecurePipe Simulator");
    println!("Connecting to {}...", GATEWAY_ADDR);

    let mut stream = TcpStream::connect(GATEWAY_ADDR).await.unwrap();
    println!("Connected. Sending frames every 2 seconds.");
    if replay_mode {
        println!("Replay mode: will replay frame #1 after frame #5.");
    }

    let key = SessionKey::dev_test_key();
    let mut sequence_nr: u32 = 0;
    let mut first_frame: Option<Vec<u8>> = None;

    loop {
        sequence_nr += 1;

        // Simulate temperature: 20.00 + small variation
        let temp_raw: i32 = 2000 + (sequence_nr as i32 % 10) * 37;

        let frame_bytes = build_frame(&key, DEVICE_ID, sequence_nr, temp_raw);

        if sequence_nr == 1 {
            first_frame = Some(frame_bytes.clone());
        }

        println!(
            "Sending frame #{} | temp={:.2}°C | {} bytes",
            sequence_nr,
            temp_raw as f32 / 100.0,
            frame_bytes.len()
        );

        stream.write_all(&frame_bytes).await.unwrap();

        // After frame 5, send the replay attack
        if replay_mode && sequence_nr == 5 {
            sleep(Duration::from_millis(500)).await;
            println!("\n[ATTACK] Replaying frame #1 — gateway should reject it.");
            let replay = first_frame.clone().unwrap();
            stream.write_all(&replay).await.unwrap();
            println!("[ATTACK] Replay sent.\n");
        }

        sleep(Duration::from_secs(2)).await;
    }
}

fn build_frame(key: &SessionKey, device_id: u32, sequence_nr: u32, temp_raw: i32) -> Vec<u8> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Random nonce - later in production use rand::thread_rng()
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&sequence_nr.to_be_bytes());
    nonce[4..8].copy_from_slice(&timestamp.to_be_bytes()[4..]);
    nonce[8..12].copy_from_slice(&device_id.to_be_bytes());

    // Build sensor payload
    let mut payload = [0u8; 8];
    payload[0] = SENSOR_TEMPERATURE;
    payload[1..5].copy_from_slice(&temp_raw.to_be_bytes());
    payload[5] = UNIT_CELSIUS;
    let crc = securepipe::protocol::frame::crc16(&payload[0..6]);
    payload[6..8].copy_from_slice(&crc.to_be_bytes());

    // Build header (for AAD computation)
    let payload_len = payload.len() as u32;
    let mut header = Vec::with_capacity(35);
    header.extend_from_slice(&MAGIC);
    header.push(PROTOCOL_VERSION);
    header.extend_from_slice(&device_id.to_be_bytes());
    header.extend_from_slice(&sequence_nr.to_be_bytes());
    header.extend_from_slice(&timestamp.to_be_bytes());
    header.extend_from_slice(&payload_len.to_be_bytes());
    header.extend_from_slice(&nonce);

    let encrypted = encrypt_payload(key, &nonce, &header, &payload).unwrap();

    let mut frame = header;
    frame.extend_from_slice(&encrypted);
    frame
}
