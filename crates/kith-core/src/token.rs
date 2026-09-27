//! Hub-issued access tokens: plain RFC 9068 JWT access tokens so any resource
//! server can verify them with nothing but the hub's JWKS.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::jws;
use crate::keys::{KeyType, PublicKey, SecretKey};
use crate::session::{Capability, LEEWAY};
use crate::util::{b64u, b64u_decode};
use crate::{Error, Result};

/// RFC 8693 actor claim: who is acting on behalf of `sub`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<Actor>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    /// RFC 9068: the OAuth client the token was issued to (OIDC logins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub attrs: Map<String, Value>,
    /// Authenticator assurance level achieved for this session (NIST 800-63B, 1-3).
    pub aal: u8,
    /// Authentication methods (RFC 8176 values where they exist: `hwk`, `swk`, `otp`, `mfa`…).
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    /// When delegated: the capabilities the actor may exercise as `sub`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<Vec<Capability>>,
    /// Proof-of-possession binding (RFC 7800 / DPoP `jkt`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Value>,
}

#[derive(Clone)]
pub struct HubSigner {
    pub kid: String,
    pub key: SecretKey,
}

impl HubSigner {
    pub fn generate() -> Self {
        let key = SecretKey::generate(KeyType::Ed25519);
        HubSigner { kid: key.public().jwk_thumbprint(), key }
    }

    pub fn issue(&self, claims: &AccessClaims) -> Result<String> {
        jws::sign(json!({"typ": "at+jwt", "kid": self.kid}), &serde_json::to_value(claims)?, &self.key)
    }

    pub fn jwks(&self) -> Value {
        let mut jwk = self.key.public().to_jwk();
        jwk["kid"] = json!(self.kid);
        jwk["alg"] = json!("EdDSA");
        jwk["use"] = json!("sig");
        json!({"keys": [jwk]})
    }

    pub fn to_json(&self) -> Value {
        json!({"kid": self.kid, "secret": b64u(self.key.to_bytes())})
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let key = SecretKey::from_bytes(KeyType::Ed25519, &b64u_decode(v["secret"].as_str().unwrap_or_default())?)?;
        Ok(HubSigner { kid: v["kid"].as_str().unwrap_or_default().into(), key })
    }
}

pub fn verify_access_token(token: &str, jwks: &Value, issuer: &str, audience: &str, now: i64) -> Result<AccessClaims> {
    let t = jws::decode(token)?;
    if t.header["typ"] != "at+jwt" {
        return Err(Error::Token("expected typ at+jwt".into()));
    }
    let kid = t.header["kid"].as_str().unwrap_or_default();
    let jwk = jwks["keys"]
        .as_array()
        .and_then(|ks| ks.iter().find(|k| k["kid"] == kid))
        .ok_or_else(|| Error::Token(format!("unknown kid {kid}")))?;
    jws::verify(&t, &PublicKey::from_jwk(jwk)?)?;
    let c: AccessClaims = serde_json::from_value(t.claims).map_err(|e| Error::Token(e.to_string()))?;
    if c.iss != issuer || c.aud != audience {
        return Err(Error::Token("issuer or audience mismatch".into()));
    }
    if c.exp + LEEWAY < now || c.iat - LEEWAY > now {
        return Err(Error::Expired);
    }
    Ok(c)
}
