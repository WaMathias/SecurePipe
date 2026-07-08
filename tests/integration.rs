// ============================================================
// SecurePipe - Integration Tests
// ============================================================
// Tests the full pipeline end-to-end, exactly as it happens
// in production: build frame -> encrypt -> parse -> verify ->
// replay-check -> decrypt -> parse payload.
//
// Run with: cargo test --test integration

use securepipe::crypto::aes_gcm::{decrypt_payload, encrypt_payload, SessionKey};
use securepipe::error::SecurePipeError;
use securepipe::protocol::frame::{
    crc16, SecurePipeFrame, SensorPayload, AUTH_TAG_SIZE, HEADER_SIZE, MAGIC, NONCE_SIZE,
    PROTOCOL_VERSION, SENSOR_TEMPERATURE, UNIT_CELSIUS,
};
use securepipe::protocol::replay::ReplayGuard;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Builds a complete, valid, encrypted SecurePipe frame exactly
/// the way the ESP32 would. This is the test equivalent of the
/// simulator's build_frame function.
fn build_test_frame(
    key: &SessionKey,
    device_id: u32,
    sequence_nr: u32,
    timestamp: u64,
    nonce_byte: u8,
    temp_raw: i32,
) -> Vec<u8> {
    let nonce = [nonce_byte; NONCE_SIZE];

    // Build sensor payload
    let mut payload = [0u8; 8];
    payload[0] = SENSOR_TEMPERATURE;
    payload[1..5].copy_from_slice(&temp_raw.to_be_bytes());
    payload[5] = UNIT_CELSIUS;
    let crc = crc16(&payload[0..6]);
    payload[6..8].copy_from_slice(&crc.to_be_bytes());

    // Build header (used as AAD)
    let payload_len = payload.len() as u32;
    let mut header = Vec::with_capacity(HEADER_SIZE);
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

/// Full pipeline: parse raw bytes -> verify -> replay-check -> decrypt -> parse payload.
/// Mirrors exactly what transport::tcp::process_frame does.
fn process_frame(
    raw: &[u8],
    key: &SessionKey,
    replay_guard: &mut ReplayGuard,
) -> Result<SensorPayload, SecurePipeError> {
    let frame = SecurePipeFrame::parse(raw)?;

    let mut payload_with_tag = frame.encrypted_payload.clone();
    payload_with_tag.extend_from_slice(&frame.auth_tag);
    let aad = frame.header_as_aad();

    let plaintext = decrypt_payload(key, &frame.nonce, &aad, &payload_with_tag)?;

    replay_guard.check(frame.device_id, frame.sequence_nr, frame.timestamp, &frame.nonce)?;

    SensorPayload::parse(&plaintext)
}

// ============================================================
// Happy path
// ============================================================

#[test]
fn full_pipeline_valid_frame_succeeds() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    let raw = build_test_frame(&key, 1, 1, now(), 0x01, 2137);
    let result = process_frame(&raw, &key, &mut guard);

    assert!(result.is_ok());
    let sensor = result.unwrap();
    assert_eq!(sensor.sensor_type, SENSOR_TEMPERATURE);
    assert!((sensor.value_f32() - 21.37).abs() < 0.001);
}

#[test]
fn full_pipeline_multiple_sequential_frames_succeed() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    for seq in 1..=10u32 {
        let raw = build_test_frame(&key, 1, seq, now(), seq as u8, 2000 + seq as i32);
        let result = process_frame(&raw, &key, &mut guard);
        assert!(result.is_ok(), "frame #{} should succeed", seq);
    }
}

#[test]
fn full_pipeline_multiple_devices_independent() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    let raw_device1 = build_test_frame(&key, 1, 1, now(), 0x01, 2100);
    let raw_device2 = build_test_frame(&key, 2, 1, now(), 0x02, 6500); // humidity sensor, different device

    assert!(process_frame(&raw_device1, &key, &mut guard).is_ok());
    assert!(process_frame(&raw_device2, &key, &mut guard).is_ok());
}

#[test]
fn replay_attack_is_detected_and_rejected() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    // Frame #1 sent and processed legitimately
    let frame1 = build_test_frame(&key, 1, 1, now(), 0x01, 2137);
    assert!(process_frame(&frame1, &key, &mut guard).is_ok());

    // Frames #2-5 sent normally
    for seq in 2..=5u32 {
        let raw = build_test_frame(&key, 1, seq, now(), seq as u8, 2100 + seq as i32);
        assert!(process_frame(&raw, &key, &mut guard).is_ok());
    }

    let result = process_frame(&frame1, &key, &mut guard);

    assert!(result.is_err());
    match result {
        Err(SecurePipeError::ReplaySequence(seq)) => assert_eq!(seq, 1),
        other => panic!("expected ReplaySequence(1), got {:?}", other),
    }
}

#[test]
fn replay_with_reused_nonce_is_detected() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    // First frame establishes nonce 0x42 as seen
    let frame1 = build_test_frame(&key, 1, 1, now(), 0x42, 2137);
    assert!(process_frame(&frame1, &key, &mut guard).is_ok());
    let frame_reused_nonce = build_test_frame(&key, 1, 2, now(), 0x42, 9999);
    let result = process_frame(&frame_reused_nonce, &key, &mut guard);

    assert!(matches!(result, Err(SecurePipeError::ReplayNonce)));
}

// ============================================================
// Tampering scenarios
// ============================================================

#[test]
fn tampered_payload_is_rejected_before_replay_check() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    let mut raw = build_test_frame(&key, 1, 1, now(), 0x01, 2137);

    let tamper_index = HEADER_SIZE + 2;
    raw[tamper_index] ^= 0xFF;

    let result = process_frame(&raw, &key, &mut guard);
    assert!(matches!(result, Err(SecurePipeError::AuthTagInvalid)));
}

#[test]
fn tampered_sequence_number_in_header_is_rejected() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    let mut raw = build_test_frame(&key, 1, 1, now(), 0x01, 2137);

    raw[10] ^= 0x01; // last byte of sequence_nr field

    let result = process_frame(&raw, &key, &mut guard);
    assert!(matches!(result, Err(SecurePipeError::AuthTagInvalid)));
}

#[test]
fn wrong_key_rejects_all_frames() {
    let key = SessionKey::dev_test_key();
    let wrong_key = SessionKey::from_bytes([0x99u8; 32]);
    let mut guard = ReplayGuard::new();

    let raw = build_test_frame(&key, 1, 1, now(), 0x01, 2137);
    let result = process_frame(&raw, &wrong_key, &mut guard);

    assert!(matches!(result, Err(SecurePipeError::AuthTagInvalid)));
}

// ============================================================
// Staleness
// ============================================================

#[test]
fn stale_frame_is_rejected() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    let old_timestamp = now() - 120;
    let raw = build_test_frame(&key, 1, 1, old_timestamp, 0x01, 2137);

    let result = process_frame(&raw, &key, &mut guard);
    assert!(matches!(result, Err(SecurePipeError::FrameStale(_))));
}

// ============================================================
// Malformed input
// ============================================================

#[test]
fn garbage_bytes_are_rejected_without_panic() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    let garbage = vec![0x00, 0xFF, 0x42, 0x13, 0x37];
    let result = process_frame(&garbage, &key, &mut guard);

    assert!(result.is_err()); 
}

#[test]
fn empty_input_is_rejected_without_panic() {
    let key = SessionKey::dev_test_key();
    let mut guard = ReplayGuard::new();

    let result = process_frame(&[], &key, &mut guard);
    assert!(result.is_err());
}

#[test]
fn frame_size_matches_specification() {
    let key = SessionKey::dev_test_key();
    let raw = build_test_frame(&key, 1, 1, now(), 0x01, 2137);

    // 35 (header) + 8 (payload) + 16 (auth tag) = 59 bytes
    assert_eq!(raw.len(), HEADER_SIZE + 8 + AUTH_TAG_SIZE);
    assert_eq!(raw.len(), 59);
}
