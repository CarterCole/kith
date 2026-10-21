//! Device → session key chains, session tokens and delegation.
//!
//! ```text
//! did:kith (KEL) ──lists──▶ device key ──signs──▶ grant JWT { cnf.jwk = session key }
//!                                                      │
//!                            session key ──signs──▶ session / delegation JWT
//!                                                   header.kith_grant = grant JWT
//! ```
//!
//! A verifier resolves the DID's KEL, checks the device is currently active, checks
//! the grant, then checks the outer token with the session key the grant certifies.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::jws;
use crate::kel::{Device, KeyState};
use crate::keys::{KeyType, PublicKey, SecretKey};
use crate::util::{now, random_id};
use crate::{Error, Result};

pub const TYP_GRANT: &str = "kith-grant+jwt";
pub const TYP_SESSION: &str = "kith-session+jwt";
pub const TYP_DELEGATION: &str = "kith-delegation+jwt";
/// Allowed clock skew, seconds.
pub const LEEWAY: i64 = 60;
/// Session proofs are single-use and short lived.
pub const MAX_SESSION_TOKEN_TTL: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    pub jwk: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantClaims {
    pub iss: String,
    pub dev: String,
    pub cnf: Cnf,
    pub aal: u8,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Action name or glob: `Query.invoices`, `Invoice.*`, `*`.
    pub action: String,
    /// Resource (`Type::"id"`) or `*`.
    #[serde(default = "star")]
    pub resource: String,
}

fn star() -> String {
    "*".into()
}

fn glob(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern == value || pattern.strip_suffix('*').is_some_and(|p| value.starts_with(p))
}

impl Capability {
    pub fn new(action: impl Into<String>) -> Self {
        Capability { action: action.into(), resource: star() }
    }
    pub fn allows(&self, action: &str, resource: &str) -> bool {
        glob(&self.action, action) && glob(&self.resource, resource)
    }
}

pub fn caps_allow(caps: &[Capability], action: &str, resource: &str) -> bool {
    caps.iter().any(|c| c.allows(action, resource))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub cap: Vec<Capability>,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

/// Something that can turn a DID into verified key state (a hub, a local cache, …).
pub trait KelResolver {
    fn resolve(&self, did: &str) -> Result<KeyState>;
}

impl KelResolver for HashMap<String, KeyState> {
    fn resolve(&self, did: &str) -> Result<KeyState> {
        self.get(did).cloned().ok_or_else(|| Error::NotFound(did.into()))
    }
}

/// How a device signs a grant.
pub enum DeviceSigner<'a> {
    Key(&'a SecretKey),
    /// A passkey: signs through WebAuthn (software authenticator here).
    Passkey { key: &'a SecretKey, rp_id: &'a str, origin: &'a str },
    /// A key that never enters this process (Secure Enclave, TPM, PKCS#11, an
    /// agent): `sign` returns the raw signature a `kty` key produces.
    External { kty: KeyType, sign: &'a dyn Fn(&[u8]) -> Result<Vec<u8>> },
}

/// A session key certified by a device.
#[derive(Clone)]
pub struct SessionKey {
    pub did: String,
    pub secret: SecretKey,
    pub grant: String,
}

impl SessionKey {
    pub fn create(did: &str, device: &Device, signer: DeviceSigner, ttl: i64) -> Result<Self> {
        let secret = SecretKey::generate(KeyType::Ed25519);
        let iat = now();
        let claims = GrantClaims {
            iss: did.into(),
            dev: device.id.clone(),
            cnf: Cnf { jwk: secret.public().to_jwk() },
            aal: device.aal,
            iat,
            exp: iat + ttl,
            jti: random_id(),
        };
        let header = json!({"typ": TYP_GRANT, "kid": format!("{did}#{}", device.id)});
        let claims = serde_json::to_value(&claims)?;
        let grant = match signer {
            DeviceSigner::Key(k) => jws::sign(header, &claims, k)?,
            DeviceSigner::Passkey { key, rp_id, origin } => jws::sign_webauthn(header, &claims, key, rp_id, origin)?,
            DeviceSigner::External { kty, sign } => jws::sign_with(header, &claims, kty, sign)?,
        };
        Ok(SessionKey { did: did.into(), secret, grant })
    }

    fn sign(&self, typ: &str, claims: Value) -> Result<String> {
        jws::sign(json!({"typ": typ, "kith_grant": self.grant}), &claims, &self.secret)
    }

    /// A short-lived, single-use proof of possession for `aud` (e.g. a hub).
    pub fn session_token(&self, aud: &str, extra: Value) -> Result<String> {
        let iat = now();
        let mut claims = json!({"iss": self.did, "aud": aud, "iat": iat, "exp": iat + 120, "jti": random_id()});
        if let Value::Object(m) = extra {
            for (k, v) in m {
                claims[k] = v;
            }
        }
        self.sign(TYP_SESSION, claims)
    }

    /// Delegate `caps` to another identity (`to`), redeemable at `aud`.
    pub fn delegate(&self, to: &str, aud: &str, caps: Vec<Capability>, ttl: i64) -> Result<String> {
        let iat = now();
        let claims = DelegationClaims { iss: self.did.clone(), sub: to.into(), aud: aud.into(), cap: caps, iat, exp: iat + ttl, jti: random_id() };
        self.sign(TYP_DELEGATION, serde_json::to_value(claims)?)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedChain {
    pub did: String,
    pub device: Device,
    pub aal: u8,
    pub session_key: PublicKey,
    pub header: Value,
    pub claims: Value,
    pub grant: GrantClaims,
}

fn check_times(iat: i64, exp: i64, now: i64) -> Result<()> {
    if exp + LEEWAY < now || iat - LEEWAY > now || exp < iat {
        return Err(Error::Expired);
    }
    Ok(())
}

/// Verify a session-key-signed token of type `typ` and its device grant.
pub fn verify_chain(token: &str, typ: &str, resolver: &dyn KelResolver, now: i64) -> Result<VerifiedChain> {
    let outer = jws::decode(token)?;
    if outer.header["typ"] != typ {
        return Err(Error::Token(format!("expected typ {typ}")));
    }
    let grant_jwt = outer.header["kith_grant"].as_str().ok_or_else(|| Error::Token("missing kith_grant".into()))?;
    let grant = jws::decode(grant_jwt)?;
    if grant.header["typ"] != TYP_GRANT {
        return Err(Error::Token("kith_grant has wrong typ".into()));
    }
    let gc: GrantClaims = serde_json::from_value(grant.claims.clone()).map_err(|e| Error::Token(format!("grant: {e}")))?;
    let state = resolver.resolve(&gc.iss)?;
    let device = state
        .device(&gc.dev)
        .cloned()
        .ok_or_else(|| Error::Token(format!("device {} is not active for {}", gc.dev, gc.iss)))?;
    jws::verify(&grant, &PublicKey::from_did_key(&device.key)?)?;
    check_times(gc.iat, gc.exp, now)?;

    let session_key = PublicKey::from_jwk(&gc.cnf.jwk)?;
    jws::verify(&outer, &session_key)?;
    let iat = outer.claims["iat"].as_i64().ok_or_else(|| Error::Token("missing iat".into()))?;
    let exp = outer.claims["exp"].as_i64().ok_or_else(|| Error::Token("missing exp".into()))?;
    check_times(iat, exp, now)?;
    if exp > gc.exp + LEEWAY {
        return Err(Error::Token("token outlives its grant".into()));
    }
    if typ == TYP_SESSION && exp - iat > MAX_SESSION_TOKEN_TTL {
        return Err(Error::Token("session token lifetime too long".into()));
    }
    if outer.claims["iss"] != gc.iss {
        return Err(Error::Token("iss does not match grant".into()));
    }
    Ok(VerifiedChain { did: gc.iss.clone(), aal: gc.aal.min(device.aal), device, session_key, header: outer.header, claims: outer.claims, grant: gc })
}

pub fn verify_session_token(token: &str, aud: &str, resolver: &dyn KelResolver, now: i64) -> Result<VerifiedChain> {
    let v = verify_chain(token, TYP_SESSION, resolver, now)?;
    if v.claims["aud"] != aud {
        return Err(Error::Token("audience mismatch".into()));
    }
    if !v.device.has_cap("session") {
        return Err(Error::Token("device is not allowed to create sessions".into()));
    }
    Ok(v)
}

pub fn verify_delegation(token: &str, aud: &str, resolver: &dyn KelResolver, now: i64) -> Result<(VerifiedChain, DelegationClaims)> {
    let v = verify_chain(token, TYP_DELEGATION, resolver, now)?;
    let d: DelegationClaims = serde_json::from_value(v.claims.clone()).map_err(|e| Error::Token(format!("delegation: {e}")))?;
    if d.aud != aud {
        return Err(Error::Token("delegation audience mismatch".into()));
    }
    Ok((v, d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kel::{tests::fixture, verify_log};
    use crate::keys::VerifyOptions;

    #[test]
    fn session_chain_roundtrip() {
        let f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let dev = st.device(&f.device_id).unwrap().clone();
        let sk = SessionKey::create(&st.did, &dev, DeviceSigner::Key(&f.device.secret), 3600).unwrap();
        let tok = sk.session_token("https://hub.example", json!({})).unwrap();
        let mut r = HashMap::new();
        r.insert(st.did.clone(), st.clone());
        let v = verify_session_token(&tok, "https://hub.example", &r, now()).unwrap();
        assert_eq!(v.did, st.did);
        assert_eq!(v.aal, 2);
        assert!(verify_session_token(&tok, "https://other", &r, now()).is_err());
        assert!(verify_session_token(&tok, "https://hub.example", &r, now() + 7200).is_err());
    }

    #[test]
    fn revoked_device_breaks_chain() {
        let mut f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let dev = st.device(&f.device_id).unwrap().clone();
        let sk = SessionKey::create(&st.did, &dev, DeviceSigner::Key(&f.device.secret), 3600).unwrap();
        let mut ev = crate::kel::next_event(&st, crate::kel::EventBody::RevokeDevice { device_id: dev.id.clone(), reason: None });
        ev.sign(&f.root).unwrap();
        f.log.push(ev);
        let st2 = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let mut r = HashMap::new();
        r.insert(st2.did.clone(), st2);
        let tok = sk.session_token("aud", json!({})).unwrap();
        assert!(verify_session_token(&tok, "aud", &r, now()).is_err());
    }

    #[test]
    fn delegation_verifies_and_caps_glob() {
        let f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let dev = st.device(&f.device_id).unwrap().clone();
        let sk = SessionKey::create(&st.did, &dev, DeviceSigner::Key(&f.device.secret), 3600).unwrap();
        let tok = sk.delegate("did:kith:someone", "hub", vec![Capability::new("Query.invoice*")], 600).unwrap();
        let mut r = HashMap::new();
        r.insert(st.did.clone(), st);
        let (_, d) = verify_delegation(&tok, "hub", &r, now()).unwrap();
        assert!(caps_allow(&d.cap, "Query.invoices", "*"));
        assert!(!caps_allow(&d.cap, "Mutation.payInvoice", "*"));
    }
}
