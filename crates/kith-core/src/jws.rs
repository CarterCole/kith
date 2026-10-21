//! Minimal compact JWS (RFC 7515) for the algorithms Kith uses: `EdDSA` (Ed25519),
//! `ES256`, `ES256K`, plus `WebAuthn` – a Kith-specific alg where the signature
//! segment is `base64url(JSON{authenticator_data, client_data_json, sig})` and the
//! WebAuthn challenge is `SHA-256(signing input)`. That lets a passkey sign a
//! session grant directly.

use serde_json::{json, Value};

use crate::keys::{KeyType, PublicKey, SecretKey};
use crate::util::{b64u, b64u_decode, sha256};
use crate::webauthn::{self, AssertionCheck, WebAuthnSigData};
use crate::{Error, Result};

#[derive(Debug, Clone)]
pub struct Jws {
    pub header: Value,
    pub claims: Value,
    pub signing_input: String,
    pub signature: Vec<u8>,
}

pub fn sign(header: Value, claims: &Value, key: &SecretKey) -> Result<String> {
    sign_with(header, claims, key.kty(), &|input| Ok(key.sign(input)))
}

/// Sign with a key held outside this process (Secure Enclave, TPM, PKCS#11, an
/// agent). `sign` must return the raw signature a `kty` key produces: 64 bytes,
/// Ed25519 or ECDSA `r||s`.
pub fn sign_with(mut header: Value, claims: &Value, kty: KeyType, sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>) -> Result<String> {
    header["alg"] = json!(kty.jws_alg());
    let input = format!("{}.{}", b64u(serde_json::to_vec(&header)?), b64u(serde_json::to_vec(claims)?));
    let sig = sign(input.as_bytes())?;
    Ok(format!("{input}.{}", b64u(sig)))
}

/// Sign with a (software) passkey. Real passkeys do the same thing via
/// `navigator.credentials.get({ publicKey: { challenge: SHA-256(signingInput) } })`.
pub fn sign_webauthn(mut header: Value, claims: &Value, passkey: &SecretKey, rp_id: &str, origin: &str) -> Result<String> {
    header["alg"] = json!("WebAuthn");
    let input = format!("{}.{}", b64u(serde_json::to_vec(&header)?), b64u(serde_json::to_vec(claims)?));
    let (data, sig) = webauthn::soft_assert(passkey, rp_id, origin, &sha256(input.as_bytes()), true, 1)?;
    let seg = json!({"authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "sig": b64u(sig)});
    Ok(format!("{input}.{}", b64u(serde_json::to_vec(&seg)?)))
}

pub fn decode(token: &str) -> Result<Jws> {
    let mut parts = token.split('.');
    let (Some(h), Some(c), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Token("not a compact JWS".into()));
    };
    let header: Value = serde_json::from_slice(&b64u_decode(h)?).map_err(|e| Error::Token(format!("header: {e}")))?;
    let claims: Value = serde_json::from_slice(&b64u_decode(c)?).map_err(|e| Error::Token(format!("claims: {e}")))?;
    Ok(Jws { header, claims, signing_input: format!("{h}.{c}"), signature: b64u_decode(s)? })
}

pub fn verify(jws: &Jws, key: &PublicKey) -> Result<()> {
    let alg = jws.header["alg"].as_str().unwrap_or_default();
    if alg == "WebAuthn" {
        let seg: Value = serde_json::from_slice(&jws.signature).map_err(|_| Error::Signature("bad WebAuthn segment".into()))?;
        let field = |k: &str| seg[k].as_str().map(String::from).ok_or_else(|| Error::Signature(format!("missing {k}")));
        let data = WebAuthnSigData { authenticator_data: field("authenticator_data")?, client_data_json: field("client_data_json")? };
        let sig = b64u_decode(&field("sig")?)?;
        return webauthn::verify_assertion(key, &data, &sig, &AssertionCheck::for_message(jws.signing_input.as_bytes())).map(|_| ());
    }
    if alg != key.kty.jws_alg() {
        return Err(Error::Signature(format!("alg {alg} does not match key type {:?}", key.kty)));
    }
    key.verify(jws.signing_input.as_bytes(), &jws.signature)
}
