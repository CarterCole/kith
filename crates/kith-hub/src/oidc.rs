//! OpenID Connect provider: "Sign in with Kith" for any existing app.
//!
//! * Authorization code flow with **PKCE (S256) required** for every client.
//! * Username-less **passkey** login: the passkey's user handle is the DID, and the
//!   hub checks the assertion against that identity's passkey devices in its KEL.
//!   Wallet signatures and TOTP step-up are accepted too.
//! * Upstream providers ("Sign in with Telegram") as a login factor, see
//!   [`crate::upstream`].
//! * **SSO** across clients via a hub session cookie; `prompt=login|none`,
//!   `max_age` and `acr_values` (`urn:kith:acr:aal2`) are honoured.
//! * ID tokens are **RS256** by default (OIDC Core §15.1 requires it) or EdDSA per
//!   client; access tokens are the usual EdDSA RFC 9068 tokens with `client_id`.
//! * **Pairwise** subject identifiers per client, so apps can't correlate users.
//! * Rotating refresh tokens (`offline_access`) that die when the device that
//!   logged in is revoked in the KEL.
//! * A **consent** page before claims are released to a client, with remembered
//!   grants; `prompt=consent` asks again.
//! * Dynamic client registration (RFC 7591) behind an initial access token.
//! * Front- and back-channel logout, and ID tokens encrypted to the client
//!   ([`crate::jwe`]).
//! * Sessions, codes, refresh tokens, pending requests and remembered consent are in
//!   the hub's SQLite store ([`crate::store`]), so a restart signs nobody out.
//! * `/oauth/login` and `/oauth/register` are rate limited per client address.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use kith_core::jws;
use kith_core::session::KelResolver;
use kith_core::token::AccessClaims;
use kith_core::util::{b64u, b64u_decode, now, random_id, sha256};

use crate::upstream::{self, Federated};
use crate::{jwe, pages, store, ApiError, ApiResult, Authn, ClientIp, Factor, Hub, TokenReq, TOKEN_TTL};

pub const SESSION_COOKIE: &str = "kith_session";
pub const SESSION_TTL: i64 = 12 * 3600;
pub const CODE_TTL: i64 = 60;
pub const REFRESH_TTL: i64 = 30 * 24 * 3600;
pub const ACR_PREFIX: &str = "urn:kith:acr:aal";
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
const LOGOUT_TOKEN_TTL: i64 = 120;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    #[default]
    Public,
    Pairwise,
}

/// Whether the user is asked before claims are released to a client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consent {
    /// Ask once for each set of scopes, and again on `prompt=consent`.
    #[default]
    Explicit,
    /// A first-party app the hub's operator vouches for: never ask unless the
    /// request says `prompt=consent`.
    Implied,
}

fn default_alg() -> String {
    "RS256".into()
}

fn default_enc() -> String {
    "A256GCM".into()
}

fn loopback(u: &str) -> bool {
    ["http://localhost", "http://127.0.0.1", "http://[::1]"].iter().any(|p| u.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/', '?'])))
}

/// A registered relying party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    /// Confidential clients authenticate with this secret (basic or post);
    /// public clients (SPAs, native apps) omit it and rely on PKCE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `aud` of access tokens issued to this client (default: the client id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default)]
    pub subject_type: SubjectType,
    #[serde(default = "default_alg")]
    pub id_token_signed_response_alg: String,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// Minimum authenticator assurance level this client always requires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_aal: Option<u8>,
    #[serde(default)]
    pub consent: Consent,
    /// The hub POSTs a signed logout token here when the user's session ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    /// The sign-out page loads this in a hidden iframe, with `iss` and `sid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    /// Encrypt ID tokens to a key in `jwks`: `RSA-OAEP-256` or `ECDH-ES`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default = "default_enc")]
    pub id_token_encrypted_response_enc: String,
    /// The client's public keys (a JWK Set), for encrypted ID tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            client_id: String::new(),
            client_secret: None,
            redirect_uris: vec![],
            name: None,
            audience: None,
            subject_type: SubjectType::Public,
            id_token_signed_response_alg: default_alg(),
            post_logout_redirect_uris: vec![],
            min_aal: None,
            consent: Consent::Explicit,
            backchannel_logout_uri: None,
            frontchannel_logout_uri: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: default_enc(),
            jwks: None,
        }
    }
}

impl Client {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.redirect_uris.is_empty() {
            anyhow::bail!("client {} has no redirect_uris", self.client_id);
        }
        for u in &self.redirect_uris {
            if u.contains('#') || !(u.starts_with("https://") || loopback(u) || (!u.starts_with("http:") && u.contains(":/"))) {
                anyhow::bail!("client {}: redirect_uri {u} must be https, loopback http, or a private-use scheme, with no fragment", self.client_id);
            }
        }
        if !["RS256", "EdDSA"].contains(&self.id_token_signed_response_alg.as_str()) {
            anyhow::bail!("client {}: id_token_signed_response_alg must be RS256 or EdDSA", self.client_id);
        }
        // The hub (back channel) or the user's browser (front channel) calls these.
        for u in self.backchannel_logout_uri.iter().chain(&self.frontchannel_logout_uri) {
            if u.contains('#') || !(u.starts_with("https://") || loopback(u)) {
                anyhow::bail!("client {}: logout URI {u} must be https or loopback http, with no fragment", self.client_id);
            }
        }
        if let Some(alg) = &self.id_token_encrypted_response_alg {
            jwe::recipient_key(self.jwks.as_ref().unwrap_or(&Value::Null), alg, &self.id_token_encrypted_response_enc)
                .map_err(|e| anyhow::anyhow!("client {}: {e}", self.client_id))?;
        }
        Ok(())
    }

    fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.client_id.clone())
    }

    fn access_audience(&self) -> String {
        self.audience.clone().unwrap_or_else(|| self.client_id.clone())
    }
}

/// RS256 signer for ID tokens (widest RP compatibility).
pub struct RsaSigner {
    pub kid: String,
    key: RsaPrivateKey,
}

impl RsaSigner {
    pub fn generate() -> anyhow::Result<Self> {
        Ok(Self::from_key(RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?))
    }

    fn from_key(key: RsaPrivateKey) -> Self {
        let n = b64u(key.n().to_bytes_be());
        let e = b64u(key.e().to_bytes_be());
        let kid = b64u(sha256(format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)));
        RsaSigner { kid, key }
    }

    pub fn to_json(&self) -> anyhow::Result<Value> {
        Ok(json!({"pkcs8": b64u(self.key.to_pkcs8_der()?.as_bytes())}))
    }

    pub fn from_json(v: &Value) -> anyhow::Result<Self> {
        Ok(Self::from_key(RsaPrivateKey::from_pkcs8_der(&b64u_decode(v["pkcs8"].as_str().unwrap_or_default())?)?))
    }

    pub fn jwk(&self) -> Value {
        json!({"kty": "RSA", "n": b64u(self.key.n().to_bytes_be()), "e": b64u(self.key.e().to_bytes_be()), "kid": self.kid, "alg": "RS256", "use": "sig"})
    }

    pub fn sign_jwt(&self, claims: &Value) -> anyhow::Result<String> {
        self.sign_typed("JWT", claims)
    }

    /// A JWT with another `typ`, e.g. `logout+jwt`.
    pub fn sign_typed(&self, typ: &str, claims: &Value) -> anyhow::Result<String> {
        let header = json!({"alg": "RS256", "typ": typ, "kid": self.kid});
        let input = format!("{}.{}", b64u(serde_json::to_vec(&header)?), b64u(serde_json::to_vec(claims)?));
        let sig = rsa::pkcs1v15::SigningKey::<Sha256>::new(self.key.clone()).sign(input.as_bytes());
        Ok(format!("{input}.{}", b64u(sig.to_vec())))
    }
}

/// A sign-in request on the login or consent page. Stored under its `request_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthRequest {
    pub(crate) client_id: String,
    redirect_uri: String,
    state: Option<String>,
    nonce: Option<String>,
    scope: String,
    code_challenge: String,
    pub(crate) min_aal: u8,
    pub(crate) created: i64,
    /// A verified upstream login that still needs step-up (see [`upstream`]).
    pub(crate) federated: Option<Federated>,
    /// `prompt=consent`: ask even when a grant is remembered.
    ask_consent: bool,
    /// Authenticated, waiting on the consent page: the login and its hub session
    /// (the hash of the cookie value, never the value).
    pub(crate) pending: Option<(Authn, String)>,
}

/// An authorization code waiting to be redeemed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CodeGrant {
    req: AuthRequest,
    authn: Authn,
    /// The hub session's public id, for the `sid` claim.
    pub(crate) sid: Option<String>,
    pub(crate) expires: i64,
}

/// A hub (SSO) session. Stored under the hash of its cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SsoSession {
    /// The `sid` clients see. Never the cookie value.
    pub(crate) id: String,
    pub(crate) authn: Authn,
    pub(crate) expires: i64,
    /// Clients that got tokens in this session; they are told when it ends.
    pub(crate) clients: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RefreshGrant {
    pub(crate) client_id: String,
    scope: String,
    pub(crate) authn: Authn,
    pub(crate) sid: Option<String>,
    pub(crate) expires: i64,
}

impl Hub {
    /// A configured client, or one registered through `/oauth/register`.
    pub fn client(&self, id: &str) -> Option<Client> {
        let configured = self.cfg.clients.iter().find(|c| c.client_id == id).cloned();
        configured.or_else(|| self.store.client(id).ok().flatten())
    }

    /// The `sub` a client sees: the DID, or a stable per-sector pseudonym.
    pub fn subject_for(&self, client: &Client, did: &str) -> String {
        match client.subject_type {
            SubjectType::Public => did.to_string(),
            SubjectType::Pairwise => {
                let sector = crate::host_of(&client.redirect_uris[0]).unwrap_or_else(|| client.client_id.clone());
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.pairwise_secret).expect("hmac key");
                mac.update(format!("kith-pairwise-v1|{sector}|{did}").as_bytes());
                b64u(mac.finalize().into_bytes())
            }
        }
    }

    /// Sign a JWT for a client with the algorithm it registered for ID tokens.
    fn sign_for(&self, client: &Client, typ: &str, claims: &Value) -> anyhow::Result<String> {
        Ok(match client.id_token_signed_response_alg.as_str() {
            "EdDSA" => jws::sign(json!({"typ": typ, "kid": self.signer.kid}), claims, &self.signer.key)?,
            _ => self.rsa.sign_typed(typ, claims)?,
        })
    }

    /// Whether the user still has to agree before `ar`'s scopes go to `client`.
    fn needs_consent(&self, client: &Client, did: &str, ar: &AuthRequest) -> bool {
        if ar.ask_consent {
            return true;
        }
        if client.consent == Consent::Implied {
            return false;
        }
        let granted = self.store.granted_scopes(did, &client.client_id).unwrap_or_default();
        !ar.scope.split_whitespace().all(|s| granted.contains(s))
    }

    fn secure_cookies(&self) -> bool {
        self.cfg.issuer.starts_with("https://")
    }

    fn oidc_message(&self, client: &str, id: &str, iat: i64, exp: i64) -> String {
        format!(
            "{} wants you to sign in to {client} with your Kith identity.\n\nURI: {}\nVersion: 1\nNonce: {id}\nIssued At: {iat}\nExpiration Time: {exp}",
            self.cfg.rp_id, self.cfg.issuer
        )
    }
}

pub(crate) fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn dec(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn with_params(base: &str, params: &[(&str, Option<&str>)]) -> String {
    let q: Vec<String> = params.iter().filter_map(|(k, v)| v.map(|v| format!("{k}={}", enc(v)))).collect();
    if q.is_empty() {
        return base.to_string();
    }
    format!("{base}{}{}", if base.contains('?') { '&' } else { '?' }, q.join("&"))
}

pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

pub fn parse_acr(values: &str) -> Option<u8> {
    values
        .split_whitespace()
        .filter_map(|v| {
            v.strip_prefix(ACR_PREFIX)
                .or_else(|| v.strip_prefix("aal"))
                .or_else(|| v.strip_prefix("http://idmanagement.gov/ns/assurance/aal/"))
                .and_then(|n| n.parse::<u8>().ok())
        })
        .min()
}

// ---------------------------------------------------------------- discovery

pub async fn discovery(State(h): State<Arc<Hub>>) -> Json<Value> {
    let i = &h.cfg.issuer;
    let mut d = json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/oauth/authorize"),
        "token_endpoint": format!("{i}/oauth/token"),
        "userinfo_endpoint": format!("{i}/oauth/userinfo"),
        "end_session_endpoint": format!("{i}/oauth/logout"),
        "jwks_uri": format!("{i}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": ["RS256", "EdDSA"],
        "id_token_encryption_alg_values_supported": jwe::ALGS,
        "id_token_encryption_enc_values_supported": jwe::ENCS,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email", "groups", "offline_access"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid", "name", "preferred_username", "email", "email_verified", "groups", "roles"],
        "acr_values_supported": [format!("{ACR_PREFIX}1"), format!("{ACR_PREFIX}2"), format!("{ACR_PREFIX}3")],
        "prompt_values_supported": ["none", "login", "consent"],
        "authorization_response_iss_parameter_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "frontchannel_logout_supported": true,
        "frontchannel_logout_session_supported": true,
        "kith": {
            "kel_endpoint": format!("{i}/v1/kel/{{did}}"),
            "challenge_endpoint": format!("{i}/v1/auth/challenge"),
            "verify_endpoint": format!("{i}/v1/auth/verify"),
            "factors_supported": ["signature", "webauthn", "totp"],
            "upstreams": upstream::summary(&h),
            "signers_supported": ["did:key (Ed25519, P-256, secp256k1)", "passkey (WebAuthn ES256)", "eip155 (EIP-191; EIP-1271 with RPC)"],
            "rp_id": h.cfg.rp_id,
        }
    });
    if h.cfg.registration_token.is_some() {
        d["registration_endpoint"] = json!(format!("{i}/oauth/register"));
    }
    Json(d)
}

// ---------------------------------------------------------------- authorize

pub async fn authorize(State(h): State<Arc<Hub>>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let get = |k: &str| q.get(k).cloned().filter(|v| !v.is_empty());
    // Errors before the client and redirect URI are known must not redirect.
    let Some(client) = get("client_id").and_then(|id| h.client(&id)) else {
        return pages::message(StatusCode::BAD_REQUEST, "Unknown application", "This sign-in link names an application the hub doesn't know.");
    };
    let redirect_uri = match get("redirect_uri") {
        Some(u) if client.redirect_uris.contains(&u) => u,
        None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
        _ => return pages::message(StatusCode::BAD_REQUEST, "Invalid redirect", "The redirect URI is not registered for this application."),
    };
    let state = get("state");
    let iss = h.cfg.issuer.clone();
    let fail = |error: &str, desc: &str| -> Response {
        Redirect::to(&with_params(&redirect_uri, &[("error", Some(error)), ("error_description", Some(desc)), ("state", state.as_deref()), ("iss", Some(&iss))])).into_response()
    };
    if get("response_type").as_deref() != Some("code") {
        return fail("unsupported_response_type", "only response_type=code is supported");
    }
    let scope = get("scope").unwrap_or_default();
    if !scope.split_whitespace().any(|s| s == "openid") {
        return fail("invalid_scope", "scope must include openid");
    }
    let Some(code_challenge) = get("code_challenge") else {
        return fail("invalid_request", "PKCE is required: send code_challenge and code_challenge_method=S256");
    };
    if get("code_challenge_method").as_deref() != Some("S256") {
        return fail("invalid_request", "code_challenge_method must be S256");
    }
    let prompt = get("prompt").unwrap_or_default();
    let prompts: Vec<&str> = prompt.split_whitespace().collect();
    let min_aal = get("acr_values").and_then(|a| parse_acr(&a)).unwrap_or(1).max(client.min_aal.unwrap_or(1));
    let max_age = get("max_age").and_then(|m| m.parse::<i64>().ok());
    let req = AuthRequest {
        client_id: client.client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        state: state.clone(),
        nonce: get("nonce"),
        scope,
        code_challenge,
        min_aal,
        created: now(),
        federated: None,
        ask_consent: prompts.contains(&"consent"),
        pending: None,
    };

    let _ = h.store.sweep(now());
    // SSO: reuse the hub session when it is strong and fresh enough.
    if !prompts.contains(&"login") {
        let existing = cookie(&headers, SESSION_COOKIE).and_then(|sid| h.store.session(&sid).ok().flatten().map(|s| (s.authn, sid)));
        if let Some((a, sid)) = existing {
            let fresh = max_age.is_none_or(|m| now() - a.auth_time <= m);
            // The device, or the alias of a federated login, must still be in the KEL.
            let st = h.resolve(&a.st.did).ok();
            let device_ok = a.dev.as_ref().is_none_or(|d| st.as_ref().is_some_and(|st| st.device(d).is_some()));
            let alias_ok = a.alias.as_ref().is_none_or(|al| st.as_ref().is_some_and(|st| st.aliases.contains(al)));
            if fresh && device_ok && alias_ok && a.aal >= min_aal {
                if !h.needs_consent(&client, &a.st.did, &req) {
                    return match issue_code(&h, req, a, &sid) {
                        Ok(url) => Redirect::to(&url).into_response(),
                        Err(_) => fail("server_error", "could not issue a code"),
                    };
                }
                if prompts.contains(&"none") {
                    return fail("consent_required", "the user has not agreed to share this with the application");
                }
                let request_id = random_id();
                if h.store.put_request(&request_id, &AuthRequest { pending: Some((a, store::hash(&sid))), ..req }).is_err() {
                    return fail("server_error", "could not save the sign-in request");
                }
                return Redirect::to(&consent_url(&request_id)).into_response();
            }
        }
    }
    if prompts.contains(&"none") {
        return fail("login_required", "no hub session satisfies this request");
    }

    let request_id = random_id();
    if h.store.put_request(&request_id, &req).is_err() {
        return fail("server_error", "could not save the sign-in request");
    }
    login_page(&h, &request_id, &req, None).unwrap_or_else(|| fail("server_error", "sign-in request was lost"))
}

/// Render the login page for a stored request. With `federated` (and the provider's
/// display name), the page only asks for the step-up that login still needs.
pub(crate) fn login_page(h: &Hub, request_id: &str, ar: &AuthRequest, federated: Option<(&Federated, &str)>) -> Option<Response> {
    let name = h.client(&ar.client_id).map(|c| c.display_name()).unwrap_or_default();
    if let Some((f, _)) = federated {
        // The page gets the token; the store only ever sees its hash.
        let stored = Federated { token: store::hash(&f.token), ..f.clone() };
        if !h.store.update_request(request_id, |r| r.federated = Some(stored)).ok()? {
            return None;
        }
    }
    let (challenge_id, message, _) = h.new_challenge(None, |id, iat, exp| h.oidc_message(&name, id, iat, exp));
    Some(pages::login(json!({
        "request_id": request_id,
        "challenge_id": challenge_id,
        "message": message,
        "rp_id": h.cfg.rp_id,
        "client_name": name,
        "min_aal": ar.min_aal,
        "upstreams": upstream::summary(h),
        "federated": federated.map(|(f, provider)| json!({"did": f.did, "provider": provider, "token": f.token})),
    })))
}

/// Finish a login: start the hub session, then mint the code or stop at the consent
/// page. Returns where the browser goes next and the session cookie, or `None` when
/// the request was already used.
pub(crate) fn complete_login(h: &Hub, request_id: &str, ar: AuthRequest, a: Authn) -> Option<(String, HeaderValue)> {
    let client = h.client(&ar.client_id)?;
    let ask = h.needs_consent(&client, &a.st.did, &ar);
    let sid = random_id();
    let still_there = if ask {
        h.store.update_request(request_id, |r| r.pending = Some((a.clone(), store::hash(&sid)))).ok()?
    } else {
        h.store.take_request(request_id).ok()?.is_some()
    };
    if !still_there {
        return None;
    }
    // `id` is what clients see as `sid`; the cookie value is only ever stored hashed.
    h.store.put_session(&sid, &SsoSession { id: random_id(), authn: a.clone(), expires: now() + SESSION_TTL, clients: BTreeSet::new() }).ok()?;
    let cookie = format!(
        "{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}{}",
        if h.secure_cookies() { "; Secure" } else { "" }
    );
    let next = if ask { consent_url(request_id) } else { issue_code(h, ar, a, &sid).ok()? };
    Some((next, HeaderValue::from_str(&cookie).expect("cookie")))
}

/// Mint the code for hub session `session` (its cookie value) and remember that the
/// client is part of that session.
fn issue_code(h: &Hub, req: AuthRequest, authn: Authn, session: &str) -> anyhow::Result<String> {
    let code = random_id();
    let url = with_params(&req.redirect_uri, &[("code", Some(&code)), ("state", req.state.as_deref()), ("iss", Some(&h.cfg.issuer))]);
    let sid = h.store.session_add_client(session, &req.client_id)?;
    h.store.put_code(&code, &CodeGrant { req, authn, sid, expires: now() + CODE_TTL })?;
    Ok(url)
}

// ---------------------------------------------------------------- consent

fn consent_url(request_id: &str) -> String {
    format!("/oauth/consent?request_id={}", enc(request_id))
}

/// The request waiting on the consent page, when this browser holds the hub session
/// that authenticated for it.
fn pending_consent(h: &Hub, headers: &HeaderMap, request_id: &str) -> Option<(AuthRequest, Authn, String)> {
    let sid = cookie(headers, SESSION_COOKIE)?;
    let ar = h.store.request(request_id).ok()??;
    let (a, session) = ar.pending.clone()?;
    (session == store::hash(&sid) && h.store.session(&sid).ok()?.is_some()).then_some((ar, a, sid))
}

/// `GET /oauth/consent?request_id=…`: what the app asks for, and Allow / Deny.
pub async fn consent_page(State(h): State<Arc<Hub>>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let expired = || pages::message(StatusCode::BAD_REQUEST, "Sign-in expired", "This sign-in request expired or was already used. Go back to the app and try again.");
    let request_id = q.get("request_id").cloned().unwrap_or_default();
    let Some((ar, a, _)) = pending_consent(&h, &headers, &request_id) else {
        return expired();
    };
    let Some(client) = h.client(&ar.client_id) else {
        return expired();
    };
    // Show the values the app would receive, not only the names of the scopes.
    let claims = h.access_claims(&a, &client.access_audience(), None).map(|c| scoped_claims(&ar.scope, &c)).unwrap_or_default();
    pages::consent(json!({
        "request_id": request_id,
        "client_name": client.display_name(),
        "redirect_host": crate::host_of(&ar.redirect_uri),
        "did": a.st.did,
        "pairwise": client.subject_type == SubjectType::Pairwise,
        "scopes": ar.scope.split_whitespace().collect::<Vec<_>>(),
        "claims": claims,
    }))
}

#[derive(Deserialize)]
pub struct ConsentReq {
    request_id: String,
    allow: bool,
}

/// The consent page posts the decision here. Allow is remembered for those scopes.
pub async fn consent(State(h): State<Arc<Hub>>, headers: HeaderMap, Json(req): Json<ConsentReq>) -> Response {
    let expired = || ApiError::bad("invalid_request", "this sign-in request expired; go back to the app and try again").into_response();
    let Some((ar, a, sid)) = pending_consent(&h, &headers, &req.request_id) else {
        return expired();
    };
    if !h.store.take_request(&req.request_id).is_ok_and(|r| r.is_some()) {
        return expired();
    }
    let redirect = if req.allow {
        let saved = h.store.grant(&a.st.did, &ar.client_id, ar.scope.split_whitespace()).and_then(|()| issue_code(&h, ar, a, &sid));
        match saved {
            Ok(url) => url,
            Err(e) => return ApiError::from(e).into_response(),
        }
    } else {
        let params = [("error", Some("access_denied")), ("error_description", Some("the user declined to share this")), ("state", ar.state.as_deref()), ("iss", Some(h.cfg.issuer.as_str()))];
        with_params(&ar.redirect_uri, &params)
    };
    Json(json!({"redirect": redirect})).into_response()
}

#[derive(Deserialize)]
pub struct LoginReq {
    request_id: String,
    challenge_id: String,
    did: String,
    factors: Vec<Factor>,
    /// Continues an upstream login that needed step-up: the token from the page.
    #[serde(default)]
    federated: Option<String>,
}

/// The login page posts here. On failure the response carries a fresh challenge so
/// the page can retry (e.g. after asking for a TOTP code for step-up).
pub async fn login(State(h): State<Arc<Hub>>, ip: ClientIp, Json(req): Json<LoginReq>) -> Response {
    if let Err(r) = h.rate_limit("login", &ip, h.cfg.login_limit) {
        return r;
    }
    let Some(ar) = h.store.request(&req.request_id).ok().flatten() else {
        return ApiError::bad("invalid_request", "this sign-in request expired; go back to the app and try again").into_response();
    };
    let name = h.client(&ar.client_id).map(|c| c.display_name()).unwrap_or_default();
    let retry = |e: ApiError| -> Response {
        let (challenge_id, message, _) = h.new_challenge(None, |id, iat, exp| h.oidc_message(&name, id, iat, exp));
        e.with(json!({"challenge_id": challenge_id, "message": message})).into_response()
    };
    let ch = match h.take_challenge(&req.challenge_id) {
        Ok(c) => c,
        Err(e) => return retry(e),
    };
    let mut factors = req.factors.clone();
    let mut attrs = Map::new();
    if let Some(token) = &req.federated {
        match &ar.federated {
            Some(f) if f.token == store::hash(token) && f.did == req.did => {
                factors.push(Factor::Federated { provider: f.provider.clone(), alias: f.alias.clone() });
                attrs = f.attrs.clone();
            }
            _ => return retry(ApiError::unauthorized("that upstream sign-in is no longer valid; start again")),
        }
    }
    let a = match h.authenticate(&req.did, &ch.message, &factors) {
        Ok(a) => Authn { attrs, ..a },
        Err(e) => return retry(e),
    };
    if a.aal < ar.min_aal {
        return retry(
            ApiError(StatusCode::UNAUTHORIZED, "step_up_required".into(), format!("this app needs assurance level {}; you reached {}", ar.min_aal, a.aal), None)
                .with(json!({"aal": a.aal, "required_aal": ar.min_aal})),
        );
    }
    let Some((redirect, cookie)) = complete_login(&h, &req.request_id, ar, a) else {
        return ApiError::bad("invalid_request", "this sign-in request was already used").into_response();
    };
    let mut r = Json(json!({"redirect": redirect})).into_response();
    r.headers_mut().insert(header::SET_COOKIE, cookie);
    r
}

// ---------------------------------------------------------------- token

fn authenticate_client(h: &Hub, headers: &HeaderMap, req: &TokenReq) -> ApiResult<Client> {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b.trim()).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.split_once(':').map(|(i, p)| (dec(i), dec(p))));
    let (id, secret) = match basic {
        Some((i, p)) => (Some(i), Some(p)),
        None => (req.client_id.clone(), req.client_secret.clone()),
    };
    let invalid = || ApiError(StatusCode::UNAUTHORIZED, "invalid_client".into(), "client authentication failed".into(), None);
    let client = id.as_deref().and_then(|i| h.client(i)).ok_or_else(invalid)?;
    if let Some(expected) = &client.client_secret {
        let given = secret.unwrap_or_default();
        let eq = given.len() == expected.len() && given.bytes().zip(expected.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
        if !eq {
            return Err(invalid());
        }
    }
    Ok(client)
}

fn scope_has(scope: &str, s: &str) -> bool {
    scope.split_whitespace().any(|x| x == s)
}

/// Claims released for `scope` (ID token and userinfo).
fn scoped_claims(scope: &str, c: &AccessClaims) -> Map<String, Value> {
    let mut out = Map::new();
    let attr = |k: &str| c.attrs.get(k).cloned();
    if scope_has(scope, "profile") {
        if let Some(n) = attr("name") {
            out.insert("name".into(), n);
        }
        if let Some(u) = attr("preferred_username").or_else(|| attr("name")) {
            out.insert("preferred_username".into(), u);
        }
    }
    if scope_has(scope, "email") {
        if let Some(e) = attr("email") {
            out.insert("email".into(), e);
            // Directory attributes are admin-asserted.
            out.insert("email_verified".into(), attr("email_verified").unwrap_or(json!(true)));
        }
    }
    if scope_has(scope, "groups") {
        out.insert("groups".into(), json!(c.groups));
        out.insert("roles".into(), json!(c.roles));
    }
    out
}

fn issue_tokens(h: &Hub, client: &Client, scope: &str, authn: &Authn, nonce: Option<&str>, sid: Option<&str>) -> ApiResult<Value> {
    let mut at = h.access_claims(authn, &client.access_audience(), None)?;
    at.sub = h.subject_for(client, &authn.st.did);
    at.client_id = Some(client.client_id.clone());
    at.scope = Some(scope.to_string());
    if client.subject_type == SubjectType::Pairwise {
        at.attrs.remove("aliases"); // would link the pseudonym to the DID
    }
    let iat = now();
    let mut id = json!({
        "iss": h.cfg.issuer,
        "sub": at.sub,
        "aud": client.client_id,
        "azp": client.client_id,
        "iat": iat,
        "exp": iat + TOKEN_TTL,
        "auth_time": authn.auth_time,
        "acr": format!("{ACR_PREFIX}{}", authn.aal),
        "amr": authn.amr,
    });
    if let Some(n) = nonce {
        id["nonce"] = json!(n);
    }
    if let Some(sid) = sid {
        id["sid"] = json!(sid);
    }
    for (k, v) in scoped_claims(scope, &at) {
        id[k] = v;
    }
    let mut id_token = h.sign_for(client, "JWT", &id)?;
    if let Some(alg) = &client.id_token_encrypted_response_alg {
        // Sign, then encrypt (OIDC Core §16.14).
        let key = jwe::recipient_key(client.jwks.as_ref().unwrap_or(&Value::Null), alg, &client.id_token_encrypted_response_enc)?;
        id_token = jwe::encrypt(&key, id_token.as_bytes())?;
    }
    let mut resp = json!({
        "access_token": h.signer.issue(&at)?,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "id_token": id_token,
        "scope": scope,
    });
    if scope_has(scope, "offline_access") {
        let rt = random_id();
        h.store.put_refresh(&rt, &RefreshGrant { client_id: client.client_id.clone(), scope: scope.into(), authn: authn.clone(), sid: sid.map(String::from), expires: now() + REFRESH_TTL })?;
        resp["refresh_token"] = json!(rt);
    }
    Ok(resp)
}

pub(crate) fn code_grant(h: &Hub, headers: &HeaderMap, req: &TokenReq) -> ApiResult<Value> {
    let client = authenticate_client(h, headers, req)?;
    let code = req.code.as_deref().ok_or_else(|| ApiError::bad("invalid_request", "code required"))?;
    let grant = h.store.take_code(code)?.ok_or_else(|| ApiError::grant("unknown, expired or already used code"))?;
    if grant.req.client_id != client.client_id {
        return Err(ApiError::grant("code was issued to another client"));
    }
    if grant.expires < now() {
        return Err(ApiError::grant("code expired"));
    }
    if req.redirect_uri.as_deref().unwrap_or(&grant.req.redirect_uri) != grant.req.redirect_uri {
        return Err(ApiError::grant("redirect_uri mismatch"));
    }
    let verifier = req.code_verifier.as_deref().ok_or_else(|| ApiError::grant("code_verifier required (PKCE)"))?;
    if b64u(sha256(verifier.as_bytes())) != grant.req.code_challenge {
        return Err(ApiError::grant("PKCE verification failed"));
    }
    issue_tokens(h, &client, &grant.req.scope, &grant.authn, grant.req.nonce.as_deref(), grant.sid.as_deref())
}

pub(crate) fn refresh_grant(h: &Hub, headers: &HeaderMap, req: &TokenReq) -> ApiResult<Value> {
    let client = authenticate_client(h, headers, req)?;
    let rt = req.refresh_token.as_deref().ok_or_else(|| ApiError::bad("invalid_request", "refresh_token required"))?;
    // Rotating: every refresh token is single use.
    let g = h.store.take_refresh(rt)?.ok_or_else(|| ApiError::grant("unknown or used refresh token"))?;
    if g.client_id != client.client_id || g.expires < now() {
        return Err(ApiError::grant("refresh token invalid for this client"));
    }
    let st = h.resolve(&g.authn.st.did).map_err(ApiError::grant)?;
    if let Some(dev) = &g.authn.dev {
        if st.device(dev).is_none() {
            return Err(ApiError::grant("the device this session was created on has been revoked"));
        }
    }
    if g.authn.alias.as_ref().is_some_and(|al| !st.aliases.contains(al)) {
        return Err(ApiError::grant("the account this session signed in with has been unlinked"));
    }
    let scope = match &req.scope {
        Some(s) if s.split_whitespace().all(|x| scope_has(&g.scope, x)) => s.clone(),
        Some(_) => return Err(ApiError::bad("invalid_scope", "cannot widen scope on refresh")),
        None => g.scope.clone(),
    };
    let authn = Authn { st, ..g.authn };
    issue_tokens(h, &client, &scope, &authn, None, g.sid.as_deref())
}

// ---------------------------------------------------------------- userinfo / logout

pub async fn userinfo(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let c = h.bearer_any(&headers)?;
    if c.client_id.is_none() {
        return Err(ApiError::unauthorized("not an OpenID Connect access token"));
    }
    let mut out = json!({"sub": c.sub});
    for (k, v) in scoped_claims(c.scope.as_deref().unwrap_or_default(), &c) {
        out[k] = v;
    }
    Ok(Json(out))
}

/// RP-initiated logout. Ends the hub session and tells the clients that were part
/// of it: a signed logout token to each `backchannel_logout_uri`, a hidden iframe
/// for each `frontchannel_logout_uri`.
pub async fn logout(State(h): State<Arc<Hub>>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let ended = cookie(&headers, SESSION_COOKIE).and_then(|sid| h.store.take_session(&sid).ok().flatten());
    let client_id = q.get("client_id").cloned().or_else(|| {
        q.get("id_token_hint").and_then(|t| jws::decode(t).ok()).and_then(|t| t.claims["aud"].as_str().map(String::from))
    });
    let target = q
        .get("post_logout_redirect_uri")
        .filter(|u| client_id.as_deref().and_then(|c| h.client(c)).is_some_and(|c| c.post_logout_redirect_uris.contains(u)))
        .map(|u| with_params(u, &[("state", q.get("state").map(String::as_str))]));
    let frames = ended.as_ref().map(|s| end_session(&h, s).0).unwrap_or_default();
    let mut r = match (frames.is_empty(), &target) {
        (true, Some(u)) => Redirect::to(u).into_response(),
        (true, None) => pages::message(StatusCode::OK, "Signed out", "You are signed out of the Kith hub."),
        (false, _) => pages::logout(&frames, target.as_deref()),
    };
    r.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static("kith_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"));
    r
}

/// Finish ending a hub session that was already removed from the store: its
/// unredeemed codes die, and each client that took part is told. Returns the
/// front-channel URLs for the sign-out page to load, and the clients notified over
/// the back channel.
pub(crate) fn end_session(h: &Arc<Hub>, s: &SsoSession) -> (Vec<String>, Vec<String>) {
    let _ = h.store.delete_codes_of_session(&s.id);
    let (mut frames, mut notified) = (vec![], vec![]);
    for c in s.clients.iter().filter_map(|id| h.client(id)) {
        if let Some(uri) = &c.frontchannel_logout_uri {
            frames.push(with_params(uri, &[("iss", Some(&h.cfg.issuer)), ("sid", Some(&s.id))]));
        }
        if c.backchannel_logout_uri.is_some() {
            notified.push(c.client_id.clone());
            tokio::spawn(send_logout_token(h.clone(), c, s.id.clone(), s.authn.st.did.clone()));
        }
    }
    (frames, notified)
}

/// The logout token for one client (OpenID Connect Back-Channel Logout 1.0 §2.4).
pub(crate) fn logout_token(h: &Hub, client: &Client, sid: &str, did: &str) -> anyhow::Result<String> {
    let iat = now();
    let claims = json!({
        "iss": h.cfg.issuer,
        "aud": client.client_id,
        "sub": h.subject_for(client, did),
        "iat": iat,
        "exp": iat + LOGOUT_TOKEN_TTL,
        "jti": random_id(),
        "sid": sid,
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    });
    h.sign_for(client, "logout+jwt", &claims)
}

/// Best effort: a client that is down misses the notice. Its tokens still expire.
async fn send_logout_token(h: Arc<Hub>, client: Client, sid: String, did: String) {
    let Some(uri) = &client.backchannel_logout_uri else {
        return;
    };
    let sent = match logout_token(&h, &client, &sid, &did) {
        Ok(t) => h.http.post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(format!("logout_token={}", enc(&t))).send().await.and_then(|r| r.error_for_status()).map(|_| ()).map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    if let Err(e) = sent {
        eprintln!("back-channel logout: could not notify {}: {e}", client.client_id);
    }
}

// ---------------------------------------------------------------- registration

/// Client metadata accepted by `/oauth/register` (RFC 7591 §2, OIDC Registration §2).
/// Members the hub doesn't know are ignored.
#[derive(Deserialize)]
pub struct Registration {
    redirect_uris: Option<Vec<String>>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    #[serde(default)]
    subject_type: SubjectType,
    id_token_signed_response_alg: Option<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    backchannel_logout_uri: Option<String>,
    frontchannel_logout_uri: Option<String>,
    id_token_encrypted_response_alg: Option<String>,
    id_token_encrypted_response_enc: Option<String>,
    jwks: Option<Value>,
    // Not supported: each makes the hub fetch a URL the client chose.
    jwks_uri: Option<String>,
    sector_identifier_uri: Option<String>,
    request_uris: Option<Vec<String>>,
}

const GRANT_TYPES: [&str; 2] = ["authorization_code", "refresh_token"];

pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `POST /oauth/register`: dynamic client registration. Off unless the hub has a
/// registration token; the caller presents it as a bearer (an RFC 7591 "initial
/// access token"). Registered clients always go through the consent page.
pub async fn register(State(h): State<Arc<Hub>>, headers: HeaderMap, ip: ClientIp, Json(m): Json<Registration>) -> ApiResult<Response> {
    let Some(expected) = &h.cfg.registration_token else {
        return Err(ApiError(StatusCode::NOT_FOUND, "not_found".into(), "client registration is not enabled on this hub".into(), None));
    };
    if let Err(r) = h.rate_limit("registration", &ip, h.cfg.register_limit) {
        return Ok(r);
    }
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let given = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")).unwrap_or_default();
    if !ct_eq(given, expected) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid_token".into(), "a registration token is required".into(), None));
    }
    let meta = |msg: String| ApiError::bad("invalid_client_metadata", msg);
    let method = m.token_endpoint_auth_method.unwrap_or_else(|| "client_secret_basic".into());
    if !["client_secret_basic", "client_secret_post", "none"].contains(&method.as_str()) {
        return Err(meta(format!("unsupported token_endpoint_auth_method {method}")));
    }
    if m.response_types.as_ref().is_some_and(|r| r.iter().any(|x| x != "code")) {
        return Err(meta("only response_type code is supported".into()));
    }
    let grant_types = m.grant_types.unwrap_or_else(|| vec!["authorization_code".into()]);
    if grant_types.iter().any(|g| !GRANT_TYPES.contains(&g.as_str())) {
        return Err(meta("grant_types may be authorization_code and refresh_token".into()));
    }
    if m.jwks_uri.is_some() || m.sector_identifier_uri.is_some() || m.request_uris.is_some() {
        return Err(meta("jwks_uri, sector_identifier_uri and request_uris are not supported; send jwks inline".into()));
    }
    let redirect_uris = m.redirect_uris.unwrap_or_default();
    let client_id = random_id();
    let redirects = Client { client_id: client_id.clone(), redirect_uris: redirect_uris.clone(), ..Default::default() };
    redirects.validate().map_err(|e| ApiError::bad("invalid_redirect_uri", e.to_string()))?;
    // Without a sector_identifier_uri, a pairwise sector is one host.
    let hosts: BTreeSet<_> = redirect_uris.iter().map(|u| crate::host_of(u)).collect();
    if m.subject_type == SubjectType::Pairwise && hosts.len() != 1 {
        return Err(meta("pairwise clients must keep all redirect_uris on one host".into()));
    }
    let client = Client {
        client_secret: (method != "none").then(|| format!("{}{}", random_id(), random_id())),
        name: m.client_name.filter(|n| !n.trim().is_empty()),
        subject_type: m.subject_type,
        id_token_signed_response_alg: m.id_token_signed_response_alg.unwrap_or_else(default_alg),
        post_logout_redirect_uris: m.post_logout_redirect_uris,
        backchannel_logout_uri: m.backchannel_logout_uri,
        frontchannel_logout_uri: m.frontchannel_logout_uri,
        id_token_encrypted_response_alg: m.id_token_encrypted_response_alg,
        id_token_encrypted_response_enc: m.id_token_encrypted_response_enc.unwrap_or_else(default_enc),
        jwks: m.jwks,
        ..redirects
    };
    client.validate().map_err(|e| meta(e.to_string()))?;
    h.store.put_client(&client)?;
    let mut out = json!(client);
    for k in ["name", "consent"] {
        out.as_object_mut().expect("object").remove(k);
    }
    out["client_name"] = json!(client.name);
    out["client_id_issued_at"] = json!(now());
    out["token_endpoint_auth_method"] = json!(method);
    out["grant_types"] = json!(grant_types);
    out["response_types"] = json!(["code"]);
    if client.client_secret.is_some() {
        out["client_secret_expires_at"] = json!(0);
    }
    let mut r = (StatusCode::CREATED, Json(out)).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acr_parsing() {
        assert_eq!(parse_acr("urn:kith:acr:aal2"), Some(2));
        assert_eq!(parse_acr("aal3 urn:kith:acr:aal2"), Some(2));
        assert_eq!(parse_acr("http://idmanagement.gov/ns/assurance/aal/3"), Some(3));
        assert_eq!(parse_acr("something-else"), None);
    }

    #[test]
    fn url_helpers() {
        assert_eq!(with_params("https://a/cb", &[("code", Some("x y")), ("state", None)]), "https://a/cb?code=x%20y");
        assert_eq!(with_params("https://a/cb?x=1", &[("code", Some("c"))]), "https://a/cb?x=1&code=c");
        assert_eq!(with_params("https://a/", &[("state", None)]), "https://a/");
        assert_eq!(dec("a%3Ab+c"), "a:b c");
    }

    #[test]
    fn client_validation() {
        let mut c = Client {
            client_id: "app".into(),
            client_secret: None,
            redirect_uris: vec!["http://localhost:3000/cb".into()],
            name: None,
            audience: None,
            ..Default::default()
        };
        c.validate().unwrap();
        // Not loopback, only a name that starts like it.
        c.redirect_uris = vec!["http://localhost.evil.example/cb".into()];
        assert!(c.validate().is_err());
        c.redirect_uris = vec!["http://evil.example/cb".into()];
        assert!(c.validate().is_err());
        c.redirect_uris = vec!["com.example.app:/cb".into()];
        c.validate().unwrap();
    }
}
