# Changelog

All changes from this review round. Details and background can be found
in [`docs/SECURITY.md`](docs/SECURITY.md) and [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

## Security

- **Memory-Exhaustion DoS fixed**: The declared payload length in the frame header
  is now validated against a maximum (`MAX_PAYLOAD_SIZE = 512` bytes),
  *before* a buffer is allocated for it. Previously an attacker could use
  a manipulated length field to force arbitrarily large memory allocations.
  (`src/protocol/frame.rs`, `src/transport/tcp.rs`)
- **Replay protection now survives reconnects**: The `ReplayGuard` is no longer
  per TCP connection but shared once (behind a `Mutex`) in the
  `GatewayState`, keyed per `device_id`. Previously the sequence-number
  history was cleared on every reconnect (e.g. after a WiFi drop), which
  would have reopened a replay window shortly afterwards.
  (`src/transport/tcp.rs`, `src/main.rs`)
- **Device whitelist added**: New module `src/protocol/registry.rs`.
  Via `SECUREPIPE_ALLOWED_DEVICES` you can define which
  `device_id`s the gateway accepts at all. Without the variable set,
  behavior stays as before (all devices accepted), so that a single
  freshly-flashed ESP32 works without any additional configuration.

## Bugfix (found while testing, independent of the points above)

- **`decrypt_payload` returned too many bytes**: The decrypted buffer
  was not trimmed to the actual plaintext length but still contained
  the (now meaningless) auth-tag bytes at the end. Never noticed in
  practice because `SensorPayload::parse` only reads the first 8 bytes
  anyway - an existing unit test (`encrypt_then_decrypt_roundtrip`)
  uncovered it though. Fixed in `src/crypto/aes_gcm.rs`.

## Configuration instead of hardcoding

- **Rust gateway**: `SECUREPIPE_TCP_BIND` and `SECUREPIPE_HTTP_BIND` as
  environment variables instead of hardcoded constants in `main.rs`. The same
  binary therefore runs unchanged on your own machine or e.g. on a
  Raspberry Pi.
- **ESP32 firmware**: WiFi credentials, gateway host/port and device ID
  are no longer compiled in, but entered via a WiFiManager captive
  portal at runtime and stored in flash (NVS). Switching the target
  system (your own machine ↔ Raspberry Pi) therefore no longer requires
  reflashing. See `arduino/esp32_sender/esp32_sender.ino` and
  `docs/CONFIGURATION.md`.

## Tests

- New unit test for the payload size check
  (`parse_rejects_oversized_payload_len`).
- New test suite for the device whitelist (`src/protocol/registry.rs`,
  6 tests).
- All previous 34 unit and 12 integration tests still pass
  (46 tests in total, `cargo test`).
- Manually verified against a running gateway process: whitelist
  correctly blocks unknown devices, env-var configuration takes effect without
  recompiling, replay detection still works in normal operation.

## Unchanged (deliberately not part of this round)

- The static AES key shared by all devices is still
  active (`SessionKey::dev_test_key()`). Per-device keys via ECDH remain
  an open item for a later phase - see
  `docs/SECURITY.md#open-items`.
- HTTP API authentication and CORS restriction were not implemented in
  this round (they were not part of the selected features).