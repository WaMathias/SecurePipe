use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurePipeError {
    // Frame parsing errors
    #[error("Invalid magic bytes - not a SecurePipe frame")]
    InvalidMagic,

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Frame too short: expected {expected} bytes, got {got}")]
    FrameTooShort { expected: usize, got: usize },

    // Cryptography errors
    #[error("Authentication tag verification failed - frame tampered or wrong key")]
    AuthTagInvalid,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    // Replay protection errors
    #[error("Replay detected: sequence number {0} already seen")]
    ReplaySequence(u32),

    #[error("Replay detected: nonce already seen")]
    ReplayNonce,

    #[error("Frame too old: timestamp {0} seconds in the past")]
    FrameStale(u64),

    // Handshake errors
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Unknown device ID: {0}")]
    UnknownDevice(u32),

    // Transport errors
    #[error("Connection closed by peer")]
    ConnectionClosed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// Convenient result type used throughout the codebase
pub type Result<T> = std::result::Result<T, SecurePipeError>;
