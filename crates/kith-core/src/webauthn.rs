//! Passkeys (WebAuthn) as Kith signers.
//!
//! A passkey is a P-256 `did:key` whose signatures come wrapped in a WebAuthn
//! assertion. Kith always sets the WebAuthn `challenge` to `SHA-256(message)`, so
//! the same passkey can sign a login challenge, a session grant or a key event
//! (e.g. as one of "2 of my 3 passkeys" in a manage policy).
//!
//! Verification follows WebAuthn L3 §7.2 for the parts that matter to Kith:
//! client data type + challenge (+ origin), RP ID hash, user-present /
//! user-verified flags and the ES256 signature over `authData || SHA-256(clientDataJSON)`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::keys::{KeyType, LocalSigner, PublicKey, SecretKey, Sig};
use crate::util::{b64u, b64u_decode, sha256};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnSigData {
    /// base64url `authenticatorData`.
    pub authenticator_data: String,
    /// base64url `clientDataJSON`.
    pub client_data_json: String,
}

#[derive(Debug, Clone)]
pub struct AssertionCheck<'a> {
    pub challenge: Vec<u8>,
    pub rp_id: Option<&'a str>,
    pub origins: Option<&'a [String]>,
    pub require_uv: bool,
}

impl AssertionCheck<'_> {
    /// Check used for signatures over Kith messages (key events, grants): the challenge
    /// must commit to the message; origin/RP are not meaningful there.
    pub fn for_message(message: &[u8]) -> Self {
        AssertionCheck { challenge: sha256(message).to_vec(), rp_id: None, origins: None, require_uv: false }
    }
}

#[derive(Debug, Clone)]
pub struct AssertionInfo {
    pub user_verified: bool,
    pub sign_count: u32,
    pub origin: String,
}

pub fn verify_assertion(pk: &PublicKey, data: &WebAuthnSigData, sig: &[u8], check: &AssertionCheck) -> Result<AssertionInfo> {
    if pk.kty != KeyType::P256 {
        return Err(Error::Unsupported("only ES256 passkeys are supported".into()));
    }
    let bad = |m: &str| Error::Signature(format!("webauthn: {m}"));
    let auth_data = b64u_decode(&data.authenticator_data)?;
    let client_data_raw = b64u_decode(&data.client_data_json)?;
    let client: Value = serde_json::from_slice(&client_data_raw).map_err(|_| bad("clientDataJSON is not JSON"))?;

    if client["type"] != "webauthn.get" {
        return Err(bad("clientData.type must be webauthn.get"));
    }
    let challenge = client["challenge"].as_str().ok_or_else(|| bad("missing challenge"))?;
    if b64u_decode(challenge)? != check.challenge {
        return Err(bad("challenge mismatch"));
    }
    let origin = client["origin"].as_str().unwrap_or_default().to_string();
    if let Some(origins) = check.origins {
        if !origins.iter().any(|o| o == &origin) {
            return Err(bad(&format!("origin {origin} not allowed")));
        }
    }
    if auth_data.len() < 37 {
        return Err(bad("authenticatorData too short"));
    }
    if let Some(rp_id) = check.rp_id {
        if auth_data[..32] != sha256(rp_id.as_bytes()) {
            return Err(bad("rpIdHash mismatch"));
        }
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(bad("user not present"));
    }
    let user_verified = flags & 0x04 != 0;
    if check.require_uv && !user_verified {
        return Err(bad("user verification required"));
    }
    let sign_count = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha256(&client_data_raw));
    pk.verify(&signed, sig)?;
    Ok(AssertionInfo { user_verified, sign_count, origin })
}

/// A software authenticator that produces real WebAuthn assertions. For tests and
/// demos only – a real passkey lives in a platform authenticator or security key.
pub fn soft_assert(secret: &SecretKey, rp_id: &str, origin: &str, challenge: &[u8], user_verified: bool, counter: u32) -> Result<(WebAuthnSigData, Vec<u8>)> {
    let SecretKey::P256(sk) = secret else {
        return Err(Error::Unsupported("soft authenticator needs a P-256 key".into()));
    };
    let mut auth_data = sha256(rp_id.as_bytes()).to_vec();
    auth_data.push(if user_verified { 0x05 } else { 0x01 });
    auth_data.extend_from_slice(&counter.to_be_bytes());
    let client = serde_json::json!({"type": "webauthn.get", "challenge": b64u(challenge), "origin": origin, "crossOrigin": false});
    let client_raw = serde_json::to_vec(&client)?;
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha256(&client_raw));
    let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(sk, &signed);
    Ok((
        WebAuthnSigData { authenticator_data: b64u(&auth_data), client_data_json: b64u(&client_raw) },
        sig.to_der().as_bytes().to_vec(),
    ))
}

/// Sign a Kith message with a (software) passkey, producing a `WebAuthn` [`Sig`].
pub fn soft_sign_message(passkey: &LocalSigner, rp_id: &str, origin: &str, message: &[u8]) -> Result<Sig> {
    let (data, sig) = soft_assert(&passkey.secret, rp_id, origin, &sha256(message), true, 1)?;
    Ok(Sig { signer: passkey.id.clone(), alg: "WebAuthn".into(), sig: b64u(sig), webauthn: Some(data) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{verify_sig, VerifyOptions};

    #[test]
    fn passkey_signs_kith_message() {
        let pk = LocalSigner::generate(KeyType::P256);
        let sig = soft_sign_message(&pk, "example.com", "https://example.com", b"event").unwrap();
        verify_sig(&sig, b"event", &VerifyOptions::default()).unwrap();
        assert!(verify_sig(&sig, b"tampered", &VerifyOptions::default()).is_err());
    }

    #[test]
    fn login_assertion_checks_origin_and_rp() {
        let key = SecretKey::generate(KeyType::P256);
        let (data, sig) = soft_assert(&key, "example.com", "https://example.com", b"nonce", true, 7).unwrap();
        let origins = vec!["https://example.com".to_string()];
        let ok = AssertionCheck { challenge: b"nonce".to_vec(), rp_id: Some("example.com"), origins: Some(&origins), require_uv: true };
        let info = verify_assertion(&key.public(), &data, &sig, &ok).unwrap();
        assert!(info.user_verified);
        assert_eq!(info.sign_count, 7);
        let wrong_rp = AssertionCheck { rp_id: Some("evil.com"), ..ok.clone() };
        assert!(verify_assertion(&key.public(), &data, &sig, &wrong_rp).is_err());
        let evil = vec!["https://evil.com".to_string()];
        let wrong_origin = AssertionCheck { origins: Some(&evil), ..ok };
        assert!(verify_assertion(&key.public(), &data, &sig, &wrong_origin).is_err());
    }
}
