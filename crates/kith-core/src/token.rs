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

/// JOSE `typ` of an account attestation. Nothing else the hub signs has this type, so
/// an access or ID token can't stand in for one.
pub const ATTESTATION_TYP: &str = "kith-account+jwt";

/// The hub's signed statement that `sub` signed in as `account` at `provider_iss`
/// (spec 7.8.1). It comes from a verified login. A KEL alias alone never produces one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAttestation {
    pub iss: String,
    /// The identity, or its pairwise subject for this client.
    pub sub: String,
    /// The client it was issued to.
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    /// The hub's id for the provider, e.g. `facebook`.
    pub provider: String,
    /// The provider's issuer. This, not `provider`, is what identifies it across hubs.
    pub provider_iss: String,
    /// The `sub` the provider's ID token carried. Facebook's is per app.
    pub account: String,
    /// When the provider's ID token was verified. A refresh does not move this.
    pub verified_at: i64,
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

    pub fn issue_attestation(&self, claims: &AccountAttestation) -> Result<String> {
        jws::sign(json!({"typ": ATTESTATION_TYP, "kid": self.kid}), &serde_json::to_value(claims)?, &self.key)
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

/// Verify a hub access token as a resource server must (spec 3.5): `typ` is `at+jwt`,
/// `alg` is `EdDSA`, the token names a `kid` in `jwks` and the signature holds, `iss`
/// and `aud` match (`aud` is one string), `sub`, `jti`, `exp`, `iat` and `aal` are all
/// there, and the times fit `now` with [`LEEWAY`] seconds of tolerance. The shared
/// vectors in `spec/test-vectors/tokens.json` run against this.
pub fn verify_access_token(token: &str, jwks: &Value, issuer: &str, audience: &str, now: i64) -> Result<AccessClaims> {
    let (claims, nbf) = verify_signed(token, jwks, "at+jwt")?;
    let c: AccessClaims = serde_json::from_value(claims).map_err(|e| Error::Token(e.to_string()))?;
    if c.iss != issuer || c.aud != audience {
        return Err(Error::Token("issuer or audience mismatch".into()));
    }
    if c.sub.is_empty() || c.jti.is_empty() {
        return Err(Error::Token("sub and jti must not be empty".into()));
    }
    if !(1..=3).contains(&c.aal) {
        return Err(Error::Token("aal must be 1, 2 or 3".into()));
    }
    check_times(c.iat, c.exp, nbf, now)?;
    Ok(c)
}

/// Verify an account attestation as an app must (spec 7.8.1). The rules are those of
/// [`verify_access_token`] with `typ` [`ATTESTATION_TYP`] and `audience` the client id;
/// `provider`, `provider_iss` and `account` must not be empty, and `verified_at` must
/// not be in the future. How recent it has to be is the app's call. The shared vectors
/// in `spec/test-vectors/attestations.json` run against this.
pub fn verify_account_attestation(token: &str, jwks: &Value, issuer: &str, audience: &str, now: i64) -> Result<AccountAttestation> {
    let (claims, nbf) = verify_signed(token, jwks, ATTESTATION_TYP)?;
    let c: AccountAttestation = serde_json::from_value(claims).map_err(|e| Error::Token(e.to_string()))?;
    if c.iss != issuer || c.aud != audience {
        return Err(Error::Token("issuer or audience mismatch".into()));
    }
    if [&c.sub, &c.jti, &c.provider, &c.provider_iss, &c.account].iter().any(|s| s.is_empty()) {
        return Err(Error::Token("sub, jti, provider, provider_iss and account must not be empty".into()));
    }
    check_times(c.iat, c.exp, nbf, now)?;
    if c.verified_at.saturating_sub(LEEWAY) > now {
        return Err(Error::Expired);
    }
    Ok(c)
}

/// The checks every hub JWT shares: `typ`, `alg` is `EdDSA`, a `kid` in `jwks`, the
/// signature. Returns the claims and `nbf`.
fn verify_signed(token: &str, jwks: &Value, want_typ: &str) -> Result<(Value, Option<i64>)> {
    let t = jws::decode(token)?;
    // RFC 7515 4.1.9: media types are case-insensitive and "application/" may be left off.
    let typ = t.header["typ"].as_str().unwrap_or_default().to_ascii_lowercase();
    if typ.strip_prefix("application/").unwrap_or(&typ) != want_typ {
        return Err(Error::Token(format!("expected typ {want_typ}")));
    }
    if t.header["alg"] != "EdDSA" {
        return Err(Error::Token("hub tokens are signed with EdDSA".into()));
    }
    let kid = t.header["kid"].as_str().filter(|k| !k.is_empty()).ok_or_else(|| Error::Token("the token has no kid".into()))?;
    let jwk = jwks["keys"]
        .as_array()
        .and_then(|ks| ks.iter().find(|k| k["kid"] == kid))
        .ok_or_else(|| Error::Token(format!("unknown kid {kid}")))?;
    jws::verify(&t, &PublicKey::from_jwk(jwk)?)?;
    let nbf = match t.claims.get("nbf") {
        None => None,
        Some(n) => Some(n.as_i64().ok_or_else(|| Error::Token("nbf must be a number".into()))?),
    };
    Ok((t.claims, nbf))
}

/// Claim times are signed but not trusted: saturate rather than overflow. RFC 7519:
/// now must be before exp, so a token is expired once exp + leeway is reached.
fn check_times(iat: i64, exp: i64, nbf: Option<i64>, now: i64) -> Result<()> {
    if exp.saturating_add(LEEWAY) <= now || iat.saturating_sub(LEEWAY) > now || nbf.is_some_and(|n| n.saturating_sub(LEEWAY) > now) {
        return Err(Error::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://hub.example";
    const AUD: &str = "api://invoices";
    const NOW: i64 = 1_800_000_000;

    fn claims(iat: i64, exp: i64) -> AccessClaims {
        AccessClaims {
            iss: ISS.into(),
            sub: "did:kith:ada".into(),
            aud: AUD.into(),
            iat,
            exp,
            jti: "t1".into(),
            client_id: None,
            scope: None,
            groups: vec![],
            roles: vec![],
            attrs: Map::new(),
            aal: 1,
            amr: vec!["swk".into()],
            dev: None,
            act: None,
            cap: None,
            cnf: None,
        }
    }

    fn check(signer: &HubSigner, c: &AccessClaims) -> Result<AccessClaims> {
        verify_access_token(&signer.issue(c)?, &signer.jwks(), ISS, AUD, NOW)
    }

    #[test]
    fn accepts_a_good_token_and_the_rejections_are_specific() {
        let h = HubSigner::generate();
        let good = claims(NOW - 10, NOW + 890);
        assert_eq!(check(&h, &good).unwrap(), good);

        let wrong = |f: &dyn Fn(&mut AccessClaims)| {
            let mut c = good.clone();
            f(&mut c);
            check(&h, &c)
        };
        assert!(matches!(wrong(&|c| c.iss = "https://evil.example".into()), Err(Error::Token(_))), "issuer");
        assert!(matches!(wrong(&|c| c.aud = "api://other".into()), Err(Error::Token(_))), "audience");
        assert!(matches!(wrong(&|c| c.exp = NOW - 61), Err(Error::Expired)), "expired past the leeway");
        assert!(check(&h, &claims(NOW - 100, NOW - 59)).is_ok(), "expired within the leeway");
        assert!(matches!(check(&h, &claims(NOW - 100, NOW - 60)), Err(Error::Expired)), "the leeway is used up");
        assert!(matches!(wrong(&|c| c.iat = NOW + 61), Err(Error::Expired)), "issued in the future");
        assert!(check(&h, &claims(NOW + 60, NOW + 900)).is_ok(), "issued in the future within the leeway");
    }

    #[test]
    fn rejects_other_keys_types_and_tampering() {
        let h = HubSigner::generate();
        let c = claims(NOW, NOW + 900);
        // Signed by a key that is not in the JWKS, even with the right kid.
        let other = HubSigner { kid: h.kid.clone(), ..HubSigner::generate() };
        assert!(verify_access_token(&other.issue(&c).unwrap(), &h.jwks(), ISS, AUD, NOW).is_err());
        // A kid the JWKS doesn't have.
        let stranger = HubSigner::generate();
        assert!(verify_access_token(&stranger.issue(&c).unwrap(), &h.jwks(), ISS, AUD, NOW).is_err());
        // Another token type, signed by the right key.
        let jwt = jws::sign(json!({"typ": "JWT", "kid": h.kid}), &serde_json::to_value(&c).unwrap(), &h.key).unwrap();
        assert!(verify_access_token(&jwt, &h.jwks(), ISS, AUD, NOW).is_err());
        // Claims changed after signing.
        let tok = h.issue(&c).unwrap();
        let mut parts: Vec<String> = tok.split('.').map(String::from).collect();
        parts[1] = b64u(serde_json::to_vec(&claims(NOW, NOW + 90_000)).unwrap());
        assert!(verify_access_token(&parts.join("."), &h.jwks(), ISS, AUD, NOW).is_err());
        // Not a JWS at all.
        for junk in ["", "a.b", "a.b.c.d", "....", "e30.e30.AA"] {
            assert!(verify_access_token(junk, &h.jwks(), ISS, AUD, NOW).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn extreme_times_neither_panic_nor_wrap() {
        let h = HubSigner::generate();
        assert!(check(&h, &claims(0, i64::MAX)).is_ok(), "valid until the end of time");
        assert!(matches!(check(&h, &claims(0, i64::MIN)), Err(Error::Expired)));
        assert!(matches!(check(&h, &claims(i64::MAX, i64::MAX)), Err(Error::Expired)), "issued at the end of time");
        assert!(check(&h, &claims(i64::MIN, NOW + 900)).is_ok());
    }

    /// The cases every implementation runs (spec 3.5, `tokens.json`): a token is
    /// accepted if and only if the vector says so.
    #[test]
    fn shared_token_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/tokens.json")).unwrap();
        assert_eq!(v["leeway"].as_i64(), Some(LEEWAY));
        let (now, iss, aud) = (v["now"].as_i64().unwrap(), v["issuer"].as_str().unwrap(), v["audience"].as_str().unwrap());
        for c in v["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let got = verify_access_token(c["token"].as_str().unwrap(), &v["jwks"], iss, aud, now);
            match (c["valid"].as_bool().unwrap(), got) {
                (true, Ok(claims)) => {
                    let want = &c["claims"];
                    assert_eq!(claims.sub, want["sub"].as_str().unwrap(), "{name}");
                    assert_eq!(i64::from(claims.aal), want["aal"].as_i64().unwrap(), "{name}");
                    assert_eq!(claims.jti, want["jti"].as_str().unwrap(), "{name}");
                    assert_eq!(json!(claims.groups), want["groups"], "{name}");
                }
                (false, Err(_)) => {}
                (true, Err(e)) => panic!("{name}: refused: {e}"),
                (false, Ok(_)) => panic!("{name}: accepted, but the vector says it is not valid"),
            }
        }
    }

    /// An app accepts "this is that account" if and only if the vector says so (spec
    /// 7.8.1 and 7.8.2, `attestations.json`).
    #[test]
    fn shared_attestation_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/attestations.json")).unwrap();
        assert_eq!(v["leeway"].as_i64(), Some(LEEWAY));
        let (now, iss, aud) = (v["now"].as_i64().unwrap(), v["issuer"].as_str().unwrap(), v["audience"].as_str().unwrap());
        for c in v["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let aud = c["audience"].as_str().unwrap_or(aud);
            match (c["valid"].as_bool().unwrap(), verify_account_attestation(c["token"].as_str().unwrap(), &v["jwks"], iss, aud, now)) {
                (true, Ok(got)) => {
                    let got = serde_json::to_value(got).unwrap();
                    for (k, want) in c["claims"].as_object().unwrap() {
                        assert_eq!(&got[k], want, "{name}: {k}");
                    }
                }
                (false, Err(_)) => {}
                (true, Err(e)) => panic!("{name}: refused: {e}"),
                (false, Ok(_)) => panic!("{name}: accepted, but the vector says it is not valid"),
            }
        }
    }
}
