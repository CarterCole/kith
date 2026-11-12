//! Recovery keys as browser sign-up makes them (spec §7.11, §7.13): a downloaded file
//! holding a P-256 key as a JWK, or a key derived from secret words. Either one signs
//! the `rotate` that replaces an identity's manage policy.

use hmac::{Hmac, Mac};
use p256::elliptic_curve::bigint::{Encoding, NonZero, U256, U512};
use p256::elliptic_curve::Curve;
use serde_json::{json, Value};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

use crate::keys::{KeyType, LocalSigner, Scheme, SecretKey};
use crate::util::{b64u, b64u_decode};
use crate::{Error, Result};

/// The derivation's fixed salt. It is the same for everyone, so a phrase must be long
/// enough to resist guessing on its own.
pub const WORDS_SALT: &str = "kith/recovery/p256/v1";
pub const WORDS_ROUNDS: u32 = 600_000;
/// The sign-up page refuses fewer.
pub const MIN_WORDS: usize = 5;

/// The words as the derivation reads them: NFKD, lower-cased, split on whitespace and
/// joined with single spaces.
pub fn normalize_words(phrase: &str) -> String {
    let norm: String = phrase.nfkd().collect::<String>().to_lowercase();
    norm.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The recovery key the sign-up page derives from secret words:
/// `d = PBKDF2-HMAC-SHA-256(words, salt, 600000, 64 bytes) mod (n − 1) + 1`.
pub fn from_words(phrase: &str) -> Result<LocalSigner> {
    let words = normalize_words(phrase);
    if words.split(' ').filter(|w| !w.is_empty()).count() < MIN_WORDS {
        return Err(Error::Encoding(format!(
            "a recovery phrase has at least {MIN_WORDS} words"
        )));
    }
    let mut seed = [0u8; 64];
    pbkdf2_sha256(
        words.as_bytes(),
        WORDS_SALT.as_bytes(),
        WORDS_ROUNDS,
        &mut seed,
    );
    let n_minus_1 = p256::NistP256::ORDER.wrapping_sub(&U256::ONE);
    let mut wide = [0u8; 64];
    wide[32..].copy_from_slice(&n_minus_1.to_be_bytes());
    let modulus = NonZero::new(U512::from_be_slice(&wide)).expect("n - 1 is not zero");
    let r = U512::from_be_slice(&seed).rem(&modulus).to_be_bytes();
    let d = U256::from_be_slice(&r[32..]).wrapping_add(&U256::ONE);
    let secret = SecretKey::from_bytes(KeyType::P256, &d.to_be_bytes())?;
    LocalSigner::from_secret(secret, Scheme::Raw, None)
}

/// PBKDF2 with HMAC-SHA-256 (RFC 8018).
fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    let keyed = Hmac::<Sha256>::new_from_slice(password).expect("HMAC takes any key");
    for (i, block) in out.chunks_mut(32).enumerate() {
        let mut mac = keyed.clone();
        mac.update(salt);
        mac.update(&(i as u32 + 1).to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..rounds {
            let mut mac = keyed.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes();
            t.iter_mut().zip(u.iter()).for_each(|(a, b)| *a ^= b);
        }
        block.copy_from_slice(&t[..block.len()]);
    }
}

/// The key in a file the sign-up page downloaded (or [`to_file`] wrote). If the file
/// names its `signer`, the key must be that one.
pub fn from_file(v: &Value) -> Result<LocalSigner> {
    let bad = |m: &str| Error::Encoding(format!("recovery key file: {m}"));
    if v["kith"] != "recovery-key" {
        return Err(bad(
            "not a Kith recovery key (no \"kith\": \"recovery-key\")",
        ));
    }
    let jwk = &v["private_key_jwk"];
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err(bad("only P-256 keys are supported"));
    }
    let d = b64u_decode(jwk["d"].as_str().ok_or_else(|| bad("no private key (d)"))?)?;
    if d.len() > 32 {
        return Err(bad("private key too long"));
    }
    let mut padded = [0u8; 32];
    padded[32 - d.len()..].copy_from_slice(&d);
    let signer = LocalSigner::from_secret(
        SecretKey::from_bytes(KeyType::P256, &padded)?,
        Scheme::Raw,
        None,
    )?;
    if let Some(named) = v["signer"].as_str() {
        if named != signer.id {
            return Err(bad("its private key does not match the signer it names"));
        }
    }
    Ok(signer)
}

/// A new recovery key, as a file in the sign-up page's format.
pub fn to_file(signer: &LocalSigner, hub: Option<&str>, created: &str) -> Result<Value> {
    let SecretKey::P256(k) = &signer.secret else {
        return Err(Error::Unsupported(
            "recovery key files hold P-256 keys".into(),
        ));
    };
    let point = k.verifying_key().to_encoded_point(false);
    let (x, y) = (point.x().expect("x"), point.y().expect("y"));
    Ok(json!({
        "kith": "recovery-key",
        "version": 1,
        "created": created,
        "hub": hub,
        "signer": signer.id,
        "private_key_jwk": {"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y), "d": b64u(k.to_bytes())},
        "note": "Keep this file offline. It is the only key that can change who manages your identity, and anyone who has it can take the identity over.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Computed with Node's own PBKDF2 and P-256, independently of this code.
    #[test]
    fn words_derive_the_same_key_as_the_signup_page() {
        assert_eq!(
            from_words("Correct  horse battery\tstaple ÉCLAIR")
                .unwrap()
                .id,
            "did:key:zDnaejumzvSCmrh2hkXwnT6oNCixR5EYkJ1hZEyqv72eiMPAb"
        );
        assert_eq!(
            from_words("one two three four five six").unwrap().id,
            "did:key:zDnaemNLquLAfK7dML8rogepAp7oLfpNnxpKWt9yzufVgrJhf"
        );
        assert!(from_words("too few words here").is_err());
    }

    #[test]
    fn a_file_round_trips_and_must_match_its_signer() {
        let k = LocalSigner::generate(KeyType::P256);
        let f = to_file(&k, Some("https://hub.example"), "2026-11-11T00:00:00Z").unwrap();
        assert_eq!(from_file(&f).unwrap().id, k.id);

        let mut wrong = f.clone();
        wrong["signer"] = json!(LocalSigner::generate(KeyType::P256).id);
        assert!(from_file(&wrong).is_err());
        let mut other = f.clone();
        other["kith"] = json!("something-else");
        assert!(from_file(&other).is_err());
    }

    #[test]
    fn pbkdf2_matches_rfc_7914_vector() {
        // RFC 7914 §11: PBKDF2-HMAC-SHA256("passwd", "salt", 1, 64).
        let mut out = [0u8; 64];
        pbkdf2_sha256(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            out.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
    }
}
