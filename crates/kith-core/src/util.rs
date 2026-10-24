use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub fn b64u(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64u_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| Error::Encoding(format!("base64url: {e}")))
}

pub fn sha256(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Seconds since the Unix epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 128 bits of randomness, base64url encoded. Used for nonces and `jti`s.
pub fn random_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b64u(b)
}

/// A short code for a public key, for people to compare across two screens: the first
/// six bytes of SHA-256 of its `did:key` string, as `xxxx-xxxx-xxxx`. The passkey
/// enrollment page computes the same thing in the browser.
pub fn key_fingerprint(key: &str) -> String {
    let h = sha256(key.as_bytes());
    let hex: String = h[..6].iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_a_short_stable_code() {
        assert_eq!(key_fingerprint("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"), "b473-c406-6da7");
        assert_ne!(key_fingerprint("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2160"), "b473-c406-6da7");
    }
}
