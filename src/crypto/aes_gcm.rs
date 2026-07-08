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

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use crate::protocol::frame::AUTH_TAG_SIZE;
    use super::*;

    fn test_key() -> SessionKey {
        SessionKey::dev_test_key()
    }

    fn test_nonce(byte: u8) -> [u8; NONCE_SIZE] {
        [byte; NONCE_SIZE]
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let key = test_key();
        let nonce = test_nonce(0x01);
        let aad = b"header_data_here";
        let plaintext = b"temperature: 21.37C";

        let ciphertext = encrypt_payload(&key, &nonce, aad, plaintext).unwrap();
        // Ciphertext should be plaintext_len + 16 (auth tag)
        assert_eq!(ciphertext.len(), plaintext.len() + AUTH_TAG_SIZE);

        let decrypted = decrypt_payload(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decryption_fails_with_wrong_key() {
        let key1 = test_key();
        let key2 = SessionKey::from_bytes([0xFFu8; 32]);
        let nonce = test_nonce(0x01);
        let aad = b"header";
        let plaintext = b"secret data";

        let ciphertext = encrypt_payload(&key1, &nonce, aad, plaintext).unwrap();
        let result = decrypt_payload(&key2, &nonce, aad, &ciphertext);

        assert!(matches!(result, Err(SecurePipeError::AuthTagInvalid)));
    }

    #[test]
    fn decryption_fails_with_tampered_ciphertext() {
        let key = test_key();
        let nonce = test_nonce(0x01);
        let aad = b"header";
        let plaintext = b"original message";

        let mut ciphertext = encrypt_payload(&key, &nonce, aad, plaintext).unwrap();
        // Flip one bit in the ciphertext - simulates an attacker tampering in transit
        ciphertext[0] ^= 0x01;

        let result = decrypt_payload(&key, &nonce, aad, &ciphertext);
        assert!(matches!(result, Err(SecurePipeError::AuthTagInvalid)));
    }

    #[test]
    fn decryption_fails_with_tampered_aad() {
        let key = test_key();
        let nonce = test_nonce(0x01);
        let aad = b"original_header";
        let plaintext = b"some payload";

        let ciphertext = encrypt_payload(&key, &nonce, aad, plaintext).unwrap();

        // Attacker modifies the header (AAD) without touching ciphertext
        let tampered_aad = b"tampered_header!";
        let result = decrypt_payload(&key, &nonce, tampered_aad, &ciphertext);

        assert!(matches!(result, Err(SecurePipeError::AuthTagInvalid)));
    }

    #[test]
    fn decryption_fails_with_wrong_nonce() {
        let key = test_key();
        let nonce1 = test_nonce(0x01);
        let nonce2 = test_nonce(0x02);
        let aad = b"header";
        let plaintext = b"payload data";

        let ciphertext = encrypt_payload(&key, &nonce1, aad, plaintext).unwrap();
        let result = decrypt_payload(&key, &nonce2, aad, &ciphertext);

        assert!(matches!(result, Err(SecurePipeError::AuthTagInvalid)));
    }

    #[test]
    fn same_plaintext_different_nonce_produces_different_ciphertext() {
        let key = test_key();
        let aad = b"header";
        let plaintext = b"identical message";

        let ciphertext1 = encrypt_payload(&key, &test_nonce(0x01), aad, plaintext).unwrap();
        let ciphertext2 = encrypt_payload(&key, &test_nonce(0x02), aad, plaintext).unwrap();

        // Critical security property: same plaintext must never produce
        // the same ciphertext when nonces differ
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn truncated_ciphertext_fails_to_decrypt() {
        let key = test_key();
        let nonce = test_nonce(0x01);
        let aad = b"header";
        let plaintext = b"payload";

        let mut ciphertext = encrypt_payload(&key, &nonce, aad, plaintext).unwrap();
        ciphertext.truncate(ciphertext.len() - 5); // cut off part of the auth tag

        let result = decrypt_payload(&key, &nonce, aad, &ciphertext);
        assert!(result.is_err());
    }
}
