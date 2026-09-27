//! OpenID Connect provider: "Sign in with Kith" for any existing app.
//!
//! * Authorization code flow with **PKCE (S256) required** for every client.
//! * Username-less **passkey** login: the passkey's user handle is the DID, and the
//!   hub checks the assertion against that identity's passkey devices in its KEL.
//!   Wallet signatures and TOTP step-up are accepted too.
//! * **SSO** across clients via a hub session cookie; `prompt=login|none`,
//!   `max_age` and `acr_values` (`urn:kith:acr:aal2`) are honoured.
//! * ID tokens are **RS256** by default (OIDC Core §15.1 requires it) or EdDSA per
//!   client; access tokens are the usual EdDSA RFC 9068 tokens with `client_id`.
//! * **Pairwise** subject identifiers per client, so apps can't correlate users.
//! * Rotating refresh tokens (`offline_access`) that die when the device that
//!   logged in is revoked in the KEL.

use std::collections::HashMap;
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

use crate::{pages, ApiError, ApiResult, Authn, Factor, Hub, TokenReq, TOKEN_TTL};

pub const SESSION_COOKIE: &str = "kith_session";
pub const SESSION_TTL: i64 = 12 * 3600;
pub const CODE_TTL: i64 = 60;
pub const REFRESH_TTL: i64 = 30 * 24 * 3600;
pub const ACR_PREFIX: &str = "urn:kith:acr:aal";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    #[default]
    Public,
    Pairwise,
}

fn default_alg() -> String {
    "RS256".into()
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
}

impl Client {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.redirect_uris.is_empty() {
            anyhow::bail!("client {} has no redirect_uris", self.client_id);
        }
        for u in &self.redirect_uris {
            let loopback = ["http://localhost", "http://127.0.0.1", "http://[::1]"].iter().any(|p| u.starts_with(p));
            if !(u.starts_with("https://") || loopback || (!u.starts_with("http:") && u.contains(":/"))) {
                anyhow::bail!("client {}: redirect_uri {u} must be https, loopback http, or a private-use scheme", self.client_id);
            }
        }
        if !["RS256", "EdDSA"].contains(&self.id_token_signed_response_alg.as_str()) {
            anyhow::bail!("client {}: id_token_signed_response_alg must be RS256 or EdDSA", self.client_id);
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
        let header = json!({"alg": "RS256", "typ": "JWT", "kid": self.kid});
        let input = format!("{}.{}", b64u(serde_json::to_vec(&header)?), b64u(serde_json::to_vec(claims)?));
        let sig = rsa::pkcs1v15::SigningKey::<Sha256>::new(self.key.clone()).sign(input.as_bytes());
        Ok(format!("{input}.{}", b64u(sig.to_vec())))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuthRequest {
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    nonce: Option<String>,
    scope: String,
    code_challenge: String,
    min_aal: u8,
    created: i64,
}

pub(crate) struct CodeGrant {
    req: AuthRequest,
    authn: Authn,
    expires: i64,
}

pub(crate) struct SsoSession {
    authn: Authn,
    expires: i64,
}

pub(crate) struct RefreshGrant {
    client_id: String,
    scope: String,
    authn: Authn,
    expires: i64,
}

#[derive(Default)]
pub struct OidcState {
    pub(crate) requests: HashMap<String, AuthRequest>,
    pub(crate) codes: HashMap<String, CodeGrant>,
    pub(crate) sessions: HashMap<String, SsoSession>,
    pub(crate) refresh: HashMap<String, RefreshGrant>,
}

impl OidcState {
    fn sweep(&mut self) {
        let t = now();
        self.requests.retain(|_, r| r.created + 900 > t);
        self.codes.retain(|_, c| c.expires > t);
        self.sessions.retain(|_, s| s.expires > t);
        self.refresh.retain(|_, r| r.expires > t);
    }
}

impl Hub {
    pub fn client(&self, id: &str) -> Option<&Client> {
        self.cfg.clients.iter().find(|c| c.client_id == id)
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

fn enc(s: &str) -> String {
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

fn with_params(base: &str, params: &[(&str, Option<&str>)]) -> String {
    let q: Vec<String> = params.iter().filter_map(|(k, v)| v.map(|v| format!("{k}={}", enc(v)))).collect();
    if q.is_empty() {
        return base.to_string();
    }
    format!("{base}{}{}", if base.contains('?') { '&' } else { '?' }, q.join("&"))
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
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
    Json(json!({
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
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email", "groups", "offline_access"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "name", "preferred_username", "email", "email_verified", "groups", "roles"],
        "acr_values_supported": [format!("{ACR_PREFIX}1"), format!("{ACR_PREFIX}2"), format!("{ACR_PREFIX}3")],
        "prompt_values_supported": ["none", "login"],
        "authorization_response_iss_parameter_supported": true,
        "kith": {
            "kel_endpoint": format!("{i}/v1/kel/{{did}}"),
            "challenge_endpoint": format!("{i}/v1/auth/challenge"),
            "verify_endpoint": format!("{i}/v1/auth/verify"),
            "factors_supported": ["signature", "webauthn", "totp"],
            "signers_supported": ["did:key (Ed25519, P-256, secp256k1)", "passkey (WebAuthn ES256)", "eip155 (EIP-191; EIP-1271 with RPC)"],
            "rp_id": h.cfg.rp_id,
        }
    }))
}

// ---------------------------------------------------------------- authorize

pub async fn authorize(State(h): State<Arc<Hub>>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let get = |k: &str| q.get(k).cloned().filter(|v| !v.is_empty());
    // Errors before the client and redirect URI are known must not redirect.
    let Some(client) = get("client_id").and_then(|id| h.client(&id).cloned()) else {
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
    };

    // SSO: reuse the hub session when it is strong and fresh enough.
    if !prompt.split_whitespace().any(|p| p == "login") {
        let existing = cookie(&headers, SESSION_COOKIE).and_then(|sid| {
            let o = h.oidc.lock().unwrap();
            o.sessions.get(&sid).filter(|s| s.expires > now()).map(|s| s.authn.clone())
        });
        if let Some(a) = existing {
            let fresh = max_age.is_none_or(|m| now() - a.auth_time <= m);
            let device_ok = a.dev.as_ref().is_none_or(|d| h.resolve(&a.st.did).is_ok_and(|st| st.device(d).is_some()));
            if fresh && device_ok && a.aal >= min_aal {
                return Redirect::to(&issue_code(&h, req, a)).into_response();
            }
        }
    }
    if prompt.split_whitespace().any(|p| p == "none") {
        return fail("login_required", "no hub session satisfies this request");
    }

    let request_id = random_id();
    let name = client.display_name();
    let (challenge_id, message, _) = h.new_challenge(None, |id, iat, exp| h.oidc_message(&name, id, iat, exp));
    {
        let mut o = h.oidc.lock().unwrap();
        o.sweep();
        o.requests.insert(request_id.clone(), req);
    }
    pages::login(json!({
        "request_id": request_id,
        "challenge_id": challenge_id,
        "message": message,
        "rp_id": h.cfg.rp_id,
        "client_name": name,
        "min_aal": min_aal,
    }))
}

fn issue_code(h: &Hub, req: AuthRequest, authn: Authn) -> String {
    let code = random_id();
    let url = with_params(&req.redirect_uri, &[("code", Some(&code)), ("state", req.state.as_deref()), ("iss", Some(&h.cfg.issuer))]);
    h.oidc.lock().unwrap().codes.insert(code, CodeGrant { req, authn, expires: now() + CODE_TTL });
    url
}

#[derive(Deserialize)]
pub struct LoginReq {
    request_id: String,
    challenge_id: String,
    did: String,
    factors: Vec<Factor>,
}

/// The login page posts here. On failure the response carries a fresh challenge so
/// the page can retry (e.g. after asking for a TOTP code for step-up).
pub async fn login(State(h): State<Arc<Hub>>, Json(req): Json<LoginReq>) -> Response {
    let ar = h.oidc.lock().unwrap().requests.get(&req.request_id).cloned();
    let Some(ar) = ar else {
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
    let a = match h.authenticate(&req.did, &ch.message, &req.factors) {
        Ok(a) => a,
        Err(e) => return retry(e),
    };
    if a.aal < ar.min_aal {
        return retry(
            ApiError(StatusCode::UNAUTHORIZED, "step_up_required".into(), format!("this app needs assurance level {}; you reached {}", ar.min_aal, a.aal), None)
                .with(json!({"aal": a.aal, "required_aal": ar.min_aal})),
        );
    }
    h.oidc.lock().unwrap().requests.remove(&req.request_id);
    let sid = random_id();
    h.oidc.lock().unwrap().sessions.insert(sid.clone(), SsoSession { authn: a.clone(), expires: now() + SESSION_TTL });
    let redirect = issue_code(&h, ar, a);
    let mut r = Json(json!({"redirect": redirect})).into_response();
    let cookie = format!(
        "{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}{}",
        if h.secure_cookies() { "; Secure" } else { "" }
    );
    r.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).expect("cookie"));
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
    let client = id.as_deref().and_then(|i| h.client(i)).cloned().ok_or_else(invalid)?;
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

fn issue_tokens(h: &Hub, client: &Client, scope: &str, authn: &Authn, nonce: Option<&str>) -> ApiResult<Value> {
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
    for (k, v) in scoped_claims(scope, &at) {
        id[k] = v;
    }
    let id_token = match client.id_token_signed_response_alg.as_str() {
        "EdDSA" => jws::sign(json!({"typ": "JWT", "kid": h.signer.kid}), &id, &h.signer.key)?,
        _ => h.rsa.sign_jwt(&id)?,
    };
    let mut resp = json!({
        "access_token": h.signer.issue(&at)?,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "id_token": id_token,
        "scope": scope,
    });
    if scope_has(scope, "offline_access") {
        let rt = random_id();
        h.oidc.lock().unwrap().refresh.insert(
            rt.clone(),
            RefreshGrant { client_id: client.client_id.clone(), scope: scope.into(), authn: authn.clone(), expires: now() + REFRESH_TTL },
        );
        resp["refresh_token"] = json!(rt);
    }
    Ok(resp)
}

pub(crate) fn code_grant(h: &Hub, headers: &HeaderMap, req: &TokenReq) -> ApiResult<Value> {
    let client = authenticate_client(h, headers, req)?;
    let code = req.code.as_deref().ok_or_else(|| ApiError::bad("invalid_request", "code required"))?;
    let grant = h.oidc.lock().unwrap().codes.remove(code).ok_or_else(|| ApiError::grant("unknown, expired or already used code"))?;
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
    issue_tokens(h, &client, &grant.req.scope, &grant.authn, grant.req.nonce.as_deref())
}

pub(crate) fn refresh_grant(h: &Hub, headers: &HeaderMap, req: &TokenReq) -> ApiResult<Value> {
    let client = authenticate_client(h, headers, req)?;
    let rt = req.refresh_token.as_deref().ok_or_else(|| ApiError::bad("invalid_request", "refresh_token required"))?;
    // Rotating: every refresh token is single use.
    let g = h.oidc.lock().unwrap().refresh.remove(rt).ok_or_else(|| ApiError::grant("unknown or used refresh token"))?;
    if g.client_id != client.client_id || g.expires < now() {
        return Err(ApiError::grant("refresh token invalid for this client"));
    }
    let st = h.resolve(&g.authn.st.did).map_err(ApiError::grant)?;
    if let Some(dev) = &g.authn.dev {
        if st.device(dev).is_none() {
            return Err(ApiError::grant("the device this session was created on has been revoked"));
        }
    }
    let scope = match &req.scope {
        Some(s) if s.split_whitespace().all(|x| scope_has(&g.scope, x)) => s.clone(),
        Some(_) => return Err(ApiError::bad("invalid_scope", "cannot widen scope on refresh")),
        None => g.scope.clone(),
    };
    let authn = Authn { st, ..g.authn };
    issue_tokens(h, &client, &scope, &authn, None)
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

pub async fn logout(State(h): State<Arc<Hub>>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(sid) = cookie(&headers, SESSION_COOKIE) {
        h.oidc.lock().unwrap().sessions.remove(&sid);
    }
    let client_id = q.get("client_id").cloned().or_else(|| {
        q.get("id_token_hint").and_then(|t| jws::decode(t).ok()).and_then(|t| t.claims["aud"].as_str().map(String::from))
    });
    let target = q
        .get("post_logout_redirect_uri")
        .filter(|u| client_id.as_deref().and_then(|c| h.client(c)).is_some_and(|c| c.post_logout_redirect_uris.contains(u)));
    let mut r = match target {
        Some(u) => Redirect::to(&with_params(u, &[("state", q.get("state").map(String::as_str))])).into_response(),
        None => pages::message(StatusCode::OK, "Signed out", "You are signed out of the Kith hub."),
    };
    r.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static("kith_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"));
    r
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
            subject_type: SubjectType::Public,
            id_token_signed_response_alg: "RS256".into(),
            post_logout_redirect_uris: vec![],
            min_aal: None,
        };
        c.validate().unwrap();
        c.redirect_uris = vec!["http://evil.example/cb".into()];
        assert!(c.validate().is_err());
        c.redirect_uris = vec!["com.example.app:/cb".into()];
        c.validate().unwrap();
    }
}
