use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurePipeError {
    #[error("Invalid magic bytes - not a SecurePipe frame")]
    InvalidMagic,

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Frame too short: expected {expected} bytes, got {got}")]
    FrameTooShort { expected: usize, got: usize },

    #[error("Declared payload length {got} exceeds maximum of {max} bytes - frame rejected before allocation")]
    PayloadTooLarge { max: usize, got: usize },

    #[error("Device {0:08X} is not on the allowed-devices list - frame rejected")]
    DeviceNotAllowed(u32),

    #[error("Authentication tag verification failed - frame tampered or wrong key")]
    AuthTagInvalid,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Replay detected: sequence number {0} already seen")]
    ReplaySequence(u32),

    #[error("Replay detected: nonce already seen")]
    ReplayNonce,

    #[error("Frame too old: timestamp {0} seconds in the past")]
    FrameStale(u64),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Unknown device ID: {0}")]
    UnknownDevice(u32),

    #[error("Connection closed by peer")]
    ConnectionClosed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SecurePipeError>;
