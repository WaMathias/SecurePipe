// ============================================================
// SecurePipe Protocol v1 - Frame definitions and constants
// ============================================================

use crate::error::{Result, SecurePipeError};

// Magic bytes: "SP" in ASCII - identify a SecurePipe frame
pub const MAGIC: [u8; 2] = [0x53, 0x50];

// Magic bytes for handshake frames: "SH" in ASCII
pub const MAGIC_HANDSHAKE: [u8; 2] = [0x53, 0x48];

pub const PROTOCOL_VERSION: u8 = 0x01;

// Fixed sizes in bytes
pub const NONCE_SIZE: usize = 12;       // AES-GCM nonce
pub const AUTH_TAG_SIZE: usize = 16;    // AES-GCM authentication tag
pub const PUBLIC_KEY_SIZE: usize = 32;  // Curve25519 public key

// Header layout (all unencrypted):
//   0- 1  magic          2 bytes
//   2     version        1 byte
//   3- 6  device_id      4 bytes
//   7-10  sequence_nr    4 bytes
//  11-18  timestamp      8 bytes  (Unix seconds, u64)
//  19-22  payload_len    4 bytes
//  23-34  nonce         12 bytes
// -------------------- total header: 35 bytes
// 35-..   encrypted payload  (payload_len bytes)
// ..-end  auth_tag      16 bytes
pub const HEADER_SIZE: usize = 35;
pub const MIN_FRAME_SIZE: usize = HEADER_SIZE + AUTH_TAG_SIZE;

// Sensor payload (before encryption), 8 bytes:
//   0     sensor_type    1 byte
//   1- 4  value_raw      4 bytes  (i32, value * 100, e.g. 2137 = 21.37°C)
//   5     unit           1 byte
//   6- 7  crc16          2 bytes
pub const PAYLOAD_SIZE: usize = 8;

// Sensor type identifiers
pub const SENSOR_TEMPERATURE: u8 = 0x01;
pub const SENSOR_HUMIDITY: u8 = 0x02;
pub const SENSOR_PRESSURE: u8 = 0x03;

// Unit identifiers
pub const UNIT_CELSIUS: u8 = 0x01;
pub const UNIT_PERCENT: u8 = 0x02;
pub const UNIT_HPA: u8 = 0x03;

// Maximum age of a frame before it is considered stale (seconds)
pub const MAX_FRAME_AGE_SECS: u64 = 30;

// Nonce cache window size for replay detection
pub const NONCE_CACHE_SIZE: usize = 64;

// ============================================================
// SecurePipeFrame - the parsed, not-yet-decrypted frame
// ============================================================

#[derive(Debug, Clone)]
pub struct SecurePipeFrame {
    pub version: u8,
    pub device_id: u32,
    pub sequence_nr: u32,
    pub timestamp: u64,
    pub nonce: [u8; NONCE_SIZE],
    pub encrypted_payload: Vec<u8>,
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

impl SecurePipeFrame {
    /// Parse raw bytes from the TCP stream into a SecurePipeFrame.
    /// Validates magic bytes and version before doing anything else.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < MIN_FRAME_SIZE {
            return Err(SecurePipeError::FrameTooShort {
                expected: MIN_FRAME_SIZE,
                got: raw.len(),
            });
        }

        // Check magic bytes first - cheapest check, fail fast
        if raw[0..2] != MAGIC {
            return Err(SecurePipeError::InvalidMagic);
        }

        let version = raw[2];
        if version != PROTOCOL_VERSION {
            return Err(SecurePipeError::UnsupportedVersion(version));
        }

        let device_id = u32::from_be_bytes(raw[3..7].try_into().unwrap());
        let sequence_nr = u32::from_be_bytes(raw[7..11].try_into().unwrap());
        let timestamp = u64::from_be_bytes(raw[11..19].try_into().unwrap());
        let payload_len = u32::from_be_bytes(raw[19..23].try_into().unwrap()) as usize;

        let expected_total = HEADER_SIZE + payload_len + AUTH_TAG_SIZE;
        if raw.len() < expected_total {
            return Err(SecurePipeError::FrameTooShort {
                expected: expected_total,
                got: raw.len(),
            });
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&raw[23..35]);

        let encrypted_payload = raw[35..35 + payload_len].to_vec();

        let mut auth_tag = [0u8; AUTH_TAG_SIZE];
        auth_tag.copy_from_slice(&raw[35 + payload_len..35 + payload_len + AUTH_TAG_SIZE]);

        Ok(SecurePipeFrame {
            version,
            device_id,
            sequence_nr,
            timestamp,
            nonce,
            encrypted_payload,
            auth_tag,
        })
    }

    /// Returns the total expected byte length of this frame
    pub fn total_len(&self) -> usize {
        HEADER_SIZE + self.encrypted_payload.len() + AUTH_TAG_SIZE
    }

    /// Returns the header bytes for use as AAD (Additional Authenticated Data)
    /// in AES-GCM. The auth tag protects the header too, not just the payload.
    pub fn header_as_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_SIZE);
        aad.extend_from_slice(&MAGIC);
        aad.push(self.version);
        aad.extend_from_slice(&self.device_id.to_be_bytes());
        aad.extend_from_slice(&self.sequence_nr.to_be_bytes());
        aad.extend_from_slice(&self.timestamp.to_be_bytes());
        aad.extend_from_slice(&(self.encrypted_payload.len() as u32).to_be_bytes());
        aad.extend_from_slice(&self.nonce);
        aad
    }
}

// ============================================================
// SensorPayload - the decrypted, parsed sensor data
// ============================================================

#[derive(Debug, Clone)]
pub struct SensorPayload {
    pub sensor_type: u8,
    pub value_raw: i32,   // value * 100, e.g. 2137 = 21.37
    pub unit: u8,
}

impl SensorPayload {
    pub fn value_f32(&self) -> f32 {
        self.value_raw as f32 / 100.0
    }

    pub fn sensor_type_str(&self) -> &str {
        match self.sensor_type {
            SENSOR_TEMPERATURE => "temperature",
            SENSOR_HUMIDITY    => "humidity",
            SENSOR_PRESSURE    => "pressure",
            _                  => "unknown",
        }
    }

    pub fn unit_str(&self) -> &str {
        match self.unit {
            UNIT_CELSIUS => "°C",
            UNIT_PERCENT => "%",
            UNIT_HPA     => "hPa",
            _            => "?",
        }
    }

    /// Parse decrypted raw bytes into a SensorPayload.
    /// Verifies the embedded CRC-16.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < PAYLOAD_SIZE {
            return Err(SecurePipeError::FrameTooShort {
                expected: PAYLOAD_SIZE,
                got: raw.len(),
            });
        }

        let sensor_type = raw[0];
        let value_raw = i32::from_be_bytes(raw[1..5].try_into().unwrap());
        let unit = raw[5];
        let received_crc = u16::from_be_bytes(raw[6..8].try_into().unwrap());

        // Verify CRC-16 over the first 6 bytes
        let computed_crc = crc16(&raw[0..6]);
        if received_crc != computed_crc {
            return Err(SecurePipeError::AuthTagInvalid);
        }

        Ok(SensorPayload { sensor_type, value_raw, unit })
    }
}

/// Simple CRC-16/CCITT implementation
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}
