# SecurePipe — Test suite

This test suite runs entirely on the development machine, without any
Arduino, ESP32 or Raspberry Pi. It verifies the entire protocol logic
in isolation: frame parsing, AES-GCM encryption, and replay protection.

## Running

```bash
# All tests (unit + integration tests)
cargo test

# Only the unit tests in the individual modules
cargo test --lib

# Only the integration tests (full frame lifecycle)
cargo test --test integration

# With output, even when tests pass
cargo test -- --nocapture

# Run a single test specifically
cargo test replay_attack_is_detected_and_rejected
```

## What is tested

### Unit tests (`src/protocol/frame.rs`, `src/protocol/replay.rs`, `src/crypto/aes_gcm.rs`)

Each module verifies itself in isolation — the CRC-16 algorithm against a
known test vector, the frame parser against broken magic bytes and
truncated frames, the ReplayGuard against repeated sequence numbers and
nonces, AES-GCM against wrong keys and manipulated ciphertexts.

### Integration tests (`tests/integration.rs`)

Here the **complete path** runs exactly the way the Rust gateway processes
it in production: parse frame → verify auth tag → check replay
→ decrypt → parse payload. This is the actual proof that the
protocol works as a whole — not just its individual parts.

The most important test is `replay_attack_is_detected_and_rejected` — it builds
five legitimate frames, lets them pass normally, and then replays frame #1.
This is exactly the scenario you also demonstrate live in the demo with
the simulator (`cargo run --bin simulator replay`) — only here
automated and reproducible.

## Why this matters for the presentation

A test suite that models attacks as test cases is a strong
argument in the assessment: you don't just show that the system works
under normal conditions, but that you consciously considered the threat
models and tested specifically against them. That is the difference
between "it works" and "I can prove why it is safe".

## Expected runtime

All tests together run in under a second — no hardware, no network and no
database is touched. This is intentional: the protocol core logic is
completely decoupled from transport and persistence
(see the architecture discussion on transport agnosticism).