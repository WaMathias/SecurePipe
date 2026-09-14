# SecurePipe Security Model

This document describes what SecurePipe protects and against whom, what was
fixed in this review round, and what is deliberately still open.

## Threat model in brief

An attacker sits somewhere between the ESP32 and the gateway (same WiFi,
compromised router, or similar) and can read, forge, replay or open
arbitrarily many of your own TCP connections. He does **not** know the AES key
(it is only shared between the firmware and the gateway, never transmitted
over the wire).

## Existing protection mechanisms (unchanged, good)

- **AES-256-GCM (authenticated encryption)**: Payload *and* header are
  protected via AAD - any tampering with any part of the frame
  causes the auth-tag check to fail.
- **Three-way replay protection**: increasing sequence number per device,
  timestamp window (`MAX_FRAME_AGE_SECS = 30s`), nonce cache.
- **Auth-tag check before any further processing**: Never work on
  unauthenticated data before the tag has been verified.

## Fixed in this round

### 1. Memory-exhaustion attack (memory-exhaustion DoS)

**Before**: The payload length in the frame header is a `u32` field controlled
by the attacker and still unauthenticated at that point. The gateway directly
allocated `vec![0u8; payload_len + AUTH_TAG_SIZE]` - with a prepared length
near `u32::MAX` that would have been a buffer in the gigabyte range,
per single frame, entirely without valid encryption.

**Fix**: `MAX_PAYLOAD_SIZE = 512` bytes (generous headroom over the
8 bytes actually needed) is checked *before* any buffer for the payload is
allocated - both directly when reading from the socket
(`transport/tcp.rs`) and defensively again in `SecurePipeFrame::parse`
for every other caller.

### 2. Replay protection that survives reconnects

**Before**: `ReplayGuard::new()` was recreated per TCP connection. Since
ESP32 devices over WiFi occasionally lose the connection for a short time,
every reconnect would have cleared the sequence-number history and the
nonce cache - an attacker replaying an old, recorded message directly after a
(real or forced) reconnect would have gotten through.

**Fix**: The `ReplayGuard` now lives once, shared across all
connections, behind a `Mutex` in the `GatewayState` - still internally
`HashMap<device_id, DeviceState>`, i.e. independent per device, but
persisting across the entire process lifetime instead of per connection.

### 3. Device whitelist

**New**: `SECUREPIPE_ALLOWED_DEVICES` (env var, see
[`CONFIGURATION.md`](CONFIGURATION.md)) restricts which `device_id`s
are accepted at all. Checked *after* auth-tag verification
(never react to unauthenticated data) but *before* the replay check
(an unknown device doesn't even get an entry in the replay state).

Important to understand: This is **defense-in-depth, not
access control in the strict sense**. Since all devices still share
the same static key (see below), anyone who knows this key can
still generate valid-looking frames for any `device_id`. The whitelist
protects against wrong/unknown device IDs (typos, unprovisioned test
devices, stray traffic), not against an attacker who already has the key.

## Independent bugfix: `decrypt_payload`

While testing, it became apparent that `decrypt_payload` (`crypto/aes_gcm.rs`)
did not trim the decrypted buffer to the actual plaintext length -
`ring::open_in_place` returns a slice reference with the correct (shorter)
length, but does not change the length of the passed `Vec` itself. The code
still returned the full (longer) `Vec`, which still contained the now
meaningless auth-tag bytes at the end. Never noticed in practice because
`SensorPayload::parse` only reads the first 8 bytes anyway - but an
existing unit test (`encrypt_then_decrypt_roundtrip`) uncovered it when
compiling with a more recent `ring` version. Now fixed.

## Open Items

Deliberately **not** part of this round, but documented known gaps
that continue to exist:

- **Shared static AES key for all devices**
  (`SessionKey::dev_test_key()`). The biggest remaining security risk:
  whoever knows the key can forge any `device_id`. Planned for a later
  phase: ECDH key exchange at connection setup, an individual key per
  device.
- **No authentication on the HTTP dashboard API**, plus
  `CorsLayer::permissive()` - any website could read the live sensor data and
  security events. Non-critical for a local demo setup, not acceptable for
  operation outside your own network.
- **No read timeout on TCP connections** - a client that never sends
  anything after the header blocks its connection task indefinitely.
- **No resync after invalid magic bytes** - with a real bit error on
  the line, the connection can permanently fall out of sync, instead of
  deliberately searching for the next frame start.