//! RFC 6238 TOTP. TOTP is a *shared secret*, so it can't sign anything and never
//! appears in a KEL: the hub stores the secret and treats a valid code as an extra
//! authentication factor (step-up / MFA).

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::{Error, Result};

pub const STEP: i64 = 30;
pub const DIGITS: u32 = 6;

pub fn generate_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut s = vec![0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

pub fn to_base32(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

pub fn from_base32(s: &str) -> Result<Vec<u8>> {
    data_encoding::BASE32_NOPAD
        .decode(s.trim_end_matches('=').to_ascii_uppercase().as_bytes())
        .map_err(|e| Error::Encoding(format!("base32: {e}")))
}

pub fn code_for_step(secret: &[u8], step: i64, digits: u32) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("any key length");
    mac.update(&(step as u64).to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    format!("{:0width$}", bin % 10u32.pow(digits), width = digits as usize)
}

pub fn code_at(secret: &[u8], unix: i64) -> String {
    code_for_step(secret, unix / STEP, DIGITS)
}

/// Returns the matched time step (store it to reject replays) if `code` is valid
/// within ±`skew` steps.
pub fn verify(secret: &[u8], code: &str, unix: i64, skew: i64) -> Option<i64> {
    let step = unix / STEP;
    (step - skew..=step + skew).find(|s| constant_time_eq(code_for_step(secret, *s, DIGITS).as_bytes(), code.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let enc = |s: &str| s.replace('%', "%25").replace(' ', "%20").replace(':', "%3A").replace('&', "%26").replace('?', "%3F").replace('/', "%2F");
    format!("otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30", enc(issuer), enc(account), to_base32(secret), enc(issuer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        assert_eq!(code_for_step(secret, 59 / 30, 8), "94287082");
        assert_eq!(code_for_step(secret, 1111111109 / 30, 8), "07081804");
        assert_eq!(code_for_step(secret, 1234567890 / 30, 8), "89005924");
    }

    #[test]
    fn verify_with_skew() {
        let s = generate_secret();
        let code = code_at(&s, 1_000_000);
        assert!(verify(&s, &code, 1_000_000 + 30, 1).is_some());
        assert!(verify(&s, &code, 1_000_000 + 90, 1).is_none());
        assert_eq!(from_base32(&to_base32(&s)).unwrap(), s);
    }
}
