// ============================================================
// SecurePipe - Device Whitelist
// ============================================================
// Restricts which device_ids the gateway will accept frames from.
//
// This is defense-in-depth, not the primary access control: today every
// device still shares one static AES key (see crypto::aes_gcm -
// per-device keys are planned for Phase 2), so anyone holding that key
// can already forge a valid-looking frame for a device_id they don't
// own. What the whitelist buys you is that a stray or malicious sender
// using a device_id you never provisioned gets rejected before it is
// ever treated as a real reading - useful the moment you have more than
// one device, or expose the gateway beyond your own LAN.
//
// Checked AFTER the AES-GCM auth tag is verified (never act on
// unauthenticated bytes), but BEFORE the replay guard, so unknown
// devices never get an entry in the per-device replay state either.

use std::collections::HashSet;
use std::env;

pub const ALLOWED_DEVICES_ENV_VAR: &str = "SECUREPIPE_ALLOWED_DEVICES";

#[derive(Debug, Clone)]
pub enum DeviceRegistry {
    /// No whitelist configured - every device_id is accepted.
    /// This is the default so a single freshly-flashed ESP32 works
    /// out of the box with zero configuration. Set the env var below
    /// once you know which device_id(s) you actually expect.
    Open,
    /// Only device_ids in this set are accepted; everything else is
    /// rejected and logged as a security event.
    Restricted(HashSet<u32>),
}

impl DeviceRegistry {
    /// Build the registry from the SECUREPIPE_ALLOWED_DEVICES env var.
    ///
    /// Format: comma-separated device ids, hex (with 0x prefix) or decimal.
    /// Example: `SECUREPIPE_ALLOWED_DEVICES=0x00000001,0x00000002`
    pub fn from_env() -> Self {
        match env::var(ALLOWED_DEVICES_ENV_VAR) {
            Ok(raw) if !raw.trim().is_empty() => {
                let ids: HashSet<u32> = raw
                    .split(',')
                    .filter_map(|s| parse_device_id(s.trim()))
                    .collect();
                tracing::info!(
                    "Device whitelist active: {} allowed device(s)",
                    ids.len()
                );
                DeviceRegistry::Restricted(ids)
            }
            _ => {
                tracing::warn!(
                    "{} not set - accepting frames from ANY device_id. \
                     Set it (comma-separated, e.g. 0x00000001) to restrict \
                     which devices this gateway trusts.",
                    ALLOWED_DEVICES_ENV_VAR
                );
                DeviceRegistry::Open
            }
        }
    }

    pub fn is_allowed(&self, device_id: u32) -> bool {
        match self {
            DeviceRegistry::Open => true,
            DeviceRegistry::Restricted(ids) => ids.contains(&device_id),
        }
    }
}

fn parse_device_id(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_registry_allows_any_device() {
        let reg = DeviceRegistry::Open;
        assert!(reg.is_allowed(0x1234));
        assert!(reg.is_allowed(0));
        assert!(reg.is_allowed(u32::MAX));
    }

    #[test]
    fn restricted_registry_only_allows_listed_ids() {
        let mut ids = HashSet::new();
        ids.insert(1);
        ids.insert(2);
        let reg = DeviceRegistry::Restricted(ids);

        assert!(reg.is_allowed(1));
        assert!(reg.is_allowed(2));
        assert!(!reg.is_allowed(3));
    }

    #[test]
    fn parses_hex_ids_with_0x_prefix() {
        assert_eq!(parse_device_id("0x00000001"), Some(1));
        assert_eq!(parse_device_id("0XABCDEF00"), Some(0xABCDEF00));
    }

    #[test]
    fn parses_decimal_ids() {
        assert_eq!(parse_device_id("42"), Some(42));
    }

    #[test]
    fn rejects_garbage_ids() {
        assert_eq!(parse_device_id("not_a_number"), None);
        assert_eq!(parse_device_id(""), None);
    }

    // Both env-var-dependent cases live in ONE test function: cargo test
    // runs tests in parallel threads within the same process, and this
    // env var is process-wide global state - splitting these across two
    // tests would make them race with each other.
    #[test]
    fn from_env_behavior() {
        env::remove_var(ALLOWED_DEVICES_ENV_VAR);
        assert!(matches!(DeviceRegistry::from_env(), DeviceRegistry::Open));

        env::set_var(ALLOWED_DEVICES_ENV_VAR, "   ");
        assert!(matches!(DeviceRegistry::from_env(), DeviceRegistry::Open));

        env::set_var(ALLOWED_DEVICES_ENV_VAR, "0x00000001, 42, 0x0A");
        match DeviceRegistry::from_env() {
            DeviceRegistry::Restricted(ids) => {
                assert!(ids.contains(&1));
                assert!(ids.contains(&42));
                assert!(ids.contains(&10));
                assert_eq!(ids.len(), 3);
            }
            DeviceRegistry::Open => panic!("expected Restricted"),
        }

        env::remove_var(ALLOWED_DEVICES_ENV_VAR);
    }
}
