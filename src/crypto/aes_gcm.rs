// ============================================================
// SecurePipe - AES-256-GCM Cryptography
// ============================================================
// Uses the `ring` crate for all cryptographic operations.
// ring is audited, constant-time, and widely used in production.

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey,
    UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::error::Unspecified;

use crate::error::{Result, SecurePipeError};
use crate::protocol::frame::NONCE_SIZE;

// ============================================================
// Session key - wraps a 32-byte AES-256 key
// ============================================================

#[derive(Clone)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SessionKey(bytes)
    }

    /// Development/MVP helper: hardcoded test key.
    /// NEVER use in production - replace with ECDH-derived key.
    pub fn dev_test_key() -> Self {
        SessionKey([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ])
    }
}

// ============================================================
// Single-use nonce wrapper (ring requires a NonceSequence)
// ============================================================

struct SingleNonce([u8; NONCE_LEN]);

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> std::result::Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

// ============================================================
// Decrypt and verify a SecurePipe frame payload
// ============================================================

/// Decrypts the encrypted payload and verifies the authentication tag.
///
/// `aad` is the frame header serialized as Additional Authenticated Data.
/// The auth tag protects both header and payload - any modification
/// to either will cause this function to return AuthTagInvalid.
///
/// Returns the plaintext payload bytes on success.
pub fn decrypt_payload(
    key: &SessionKey,
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    encrypted_payload_with_tag: &[u8],
) -> Result<Vec<u8>> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| SecurePipeError::DecryptionFailed)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce);

    let mut opening_key = OpeningKey::new(unbound_key, SingleNonce(nonce_bytes));

    let mut in_out = encrypted_payload_with_tag.to_vec();

    opening_key
        .open_in_place(Aad::from(aad), &mut in_out)
        .map_err(|_| SecurePipeError::AuthTagInvalid)?;

    // ring removes the auth tag from in_out after verification
    Ok(in_out)
}

/// Encrypts a payload and appends the authentication tag.
/// Used by the test simulator to generate valid frames.
pub fn encrypt_payload(
    key: &SessionKey,
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| SecurePipeError::DecryptionFailed)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce);

    let mut sealing_key = SealingKey::new(unbound_key, SingleNonce(nonce_bytes));

    let mut in_out = plaintext.to_vec();

    sealing_key
        .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
        .map_err(|_| SecurePipeError::DecryptionFailed)?;

    Ok(in_out)
}
