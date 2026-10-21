//! Upstream OpenID Connect providers as login factors: "Sign in with Telegram"
//! (<https://core.telegram.org/bots/telegram-login>), and any other provider that
//! speaks authorization code + PKCE.
//!
//! * The hub is the relying party. It runs the code flow with **PKCE (S256)**,
//!   `state` and `nonce`, exchanges the code server-side and verifies the ID token
//!   against the provider's JWKS (`RS256`, `ES256`, `EdDSA`, `ES256K`).
//! * The verified `(iss, sub)` becomes the alias `{iss}#{sub}`. It signs in the
//!   identity whose KEL carries a matching `alias_link`: the identity said, with its
//!   manage policy, that this upstream account may log in as it.
//! * Only the hub can check the evidence, so a federated login is **AAL1** (`amr:
//!   fed`). It never signs anything; TOTP can be added for step-up.
//! * The session ends when the alias is unlinked, the way a device session ends when
//!   the device is revoked.
//! * A provider supplies **attributes** only when its entry lists them. The hub then
//!   reads the ID token and the UserInfo endpoint, and keeps just the listed claims.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use kith_core::jws;
use kith_core::keys::PublicKey;
use kith_core::session::LEEWAY;
use kith_core::util::{b64u, b64u_decode, now, random_id, sha256};

use crate::oidc::{cookie, enc, with_params};
use crate::{pages, ApiError, ApiResult, Factor, Hub};

pub const STATE_COOKIE: &str = "kith_upstream";
pub const PENDING_TTL: i64 = 600;
const JWKS_TTL: i64 = 3600;
const JWKS_MIN_REFETCH: i64 = 60;
/// Attributes the KEL and the login decide. No provider may assert them.
const RESERVED_ATTRIBUTES: [&str; 3] = ["aliases", "aal", "email_verified"];

fn default_scope() -> String {
    "openid".into()
}

/// An upstream OpenID Connect provider the hub accepts logins from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    /// Path segment in `/oauth/upstream/{id}/…`, e.g. `telegram`.
    pub id: String,
    /// Shown on the login button (default: the id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Expected `iss` of ID tokens, e.g. `https://oauth.telegram.org`.
    pub issuer: String,
    /// For Telegram: the Client ID @BotFather shows under Login Widget.
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Endpoints; any left out come from `{issuer}/.well-known/openid-configuration`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    /// Claims this provider is trusted to assert, and the attribute each becomes:
    /// `{"name": "name", "phone_number": "phone"}`. Empty (the default) means the
    /// provider only proves who signed in, and UserInfo is never called.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

fn secure_url(u: &str) -> bool {
    u.starts_with("https://") || ["http://localhost", "http://127.0.0.1", "http://[::1]"].iter().any(|p| u.starts_with(p))
}

impl Upstream {
    /// Telegram Login with the endpoints from its discovery document.
    pub fn telegram(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Upstream {
            id: "telegram".into(),
            name: Some("Telegram".into()),
            issuer: "https://oauth.telegram.org".into(),
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            scope: default_scope(),
            authorization_endpoint: Some("https://oauth.telegram.org/auth".into()),
            token_endpoint: Some("https://oauth.telegram.org/token".into()),
            jwks_uri: Some("https://oauth.telegram.org/.well-known/jwks.json".into()),
            userinfo_endpoint: None,
            attributes: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.id.is_empty() || !self.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            anyhow::bail!("upstream id {:?} must be lowercase letters, digits and '-'", self.id);
        }
        if self.issuer.ends_with('/') || self.issuer.contains(['#', '?']) {
            anyhow::bail!("upstream {}: issuer must have no trailing slash, query or fragment", self.id);
        }
        let urls = [Some(&self.issuer), self.authorization_endpoint.as_ref(), self.token_endpoint.as_ref(), self.jwks_uri.as_ref(), self.userinfo_endpoint.as_ref()];
        for u in urls.into_iter().flatten() {
            if !secure_url(u) {
                anyhow::bail!("upstream {}: {u} must be https or loopback http", self.id);
            }
        }
        if !self.scope.split_whitespace().any(|s| s == "openid") {
            anyhow::bail!("upstream {}: scope must include openid", self.id);
        }
        for (claim, attr) in &self.attributes {
            if claim.is_empty() || attr.is_empty() || RESERVED_ATTRIBUTES.contains(&attr.as_str()) {
                anyhow::bail!("upstream {}: claim {claim:?} cannot become attribute {attr:?}", self.id);
            }
        }
        Ok(())
    }

    /// The attributes this provider may assert, out of `claims` (the ID token's,
    /// with UserInfo's filling gaps). Only plain values are kept.
    ///
    /// `email` needs `email_verified: true`, because group rules often match on
    /// the address. `phone_number` is dropped when the provider says it is
    /// unverified.
    pub fn attributes_from(&self, claims: &Value) -> Map<String, Value> {
        let mut out = Map::new();
        for (claim, attr) in &self.attributes {
            let unverified = match claim.as_str() {
                "email" => claims["email_verified"] != true,
                "phone_number" => claims["phone_number_verified"] == false,
                _ => false,
            };
            match &claims[claim] {
                v @ (Value::String(_) | Value::Number(_) | Value::Bool(_)) if !unverified => {
                    out.insert(attr.clone(), v.clone());
                }
                _ => {}
            }
        }
        out
    }

    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.id.clone())
    }

    /// The alias an identity links to let this upstream account sign in (spec §5.1).
    pub fn alias(&self, sub: &str) -> String {
        format!("{}#{}", self.issuer, enc(sub))
    }
}

#[derive(Debug, Clone)]
struct Meta {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
}

struct Pending {
    provider: String,
    request_id: String,
    verifier: String,
    nonce: String,
    did: Option<String>,
    created: i64,
}

#[derive(Default)]
pub struct UpstreamState {
    pending: HashMap<String, Pending>,
    meta: HashMap<String, Meta>,
    jwks: HashMap<String, (i64, Value)>,
}

/// A verified upstream login waiting for step-up on the login page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Federated {
    pub did: String,
    pub provider: String,
    pub alias: String,
    /// What the provider asserted, already filtered ([`Upstream::attributes_from`]).
    pub attrs: Map<String, Value>,
    /// Known only to the browser that came back from the provider.
    pub token: String,
}

fn claim_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Verify an upstream ID token (OIDC Core §3.1.3.7) and return its claims.
///
/// A missing `nonce` is tolerated: the token came straight from the token endpoint
/// over TLS in exchange for a PKCE-bound code, so it cannot have been injected. A
/// `nonce` that is present must match.
pub fn verify_id_token(p: &Upstream, jwks: &Value, token: &str, nonce: &str, t: i64) -> ApiResult<Value> {
    let bad = |m: &str| ApiError::unauthorized(format!("{} ID token: {m}", p.display_name()));
    let tok = jws::decode(token).map_err(|e| bad(&e.to_string()))?;
    let alg = tok.header["alg"].as_str().unwrap_or_default();
    let key = find_key(jwks, &tok.header).ok_or_else(|| bad("no matching key in the provider's JWKS"))?;
    match alg {
        "RS256" => {
            let part = |k: &str| key[k].as_str().and_then(|s| b64u_decode(s).ok()).map(|b| BigUint::from_bytes_be(&b));
            let (n, e) = part("n").zip(part("e")).ok_or_else(|| bad("malformed RSA key"))?;
            let vk = VerifyingKey::<Sha256>::new(RsaPublicKey::new(n, e).map_err(|e| bad(&e.to_string()))?);
            let sig = Signature::try_from(tok.signature.as_slice()).map_err(|_| bad("malformed signature"))?;
            vk.verify(tok.signing_input.as_bytes(), &sig).map_err(|_| bad("bad signature"))?;
        }
        "ES256" | "EdDSA" | "ES256K" => {
            let pk = PublicKey::from_jwk(key).map_err(|e| bad(&e.to_string()))?;
            jws::verify(&tok, &pk).map_err(|_| bad("bad signature"))?;
        }
        other => return Err(bad(&format!("unsupported alg {other:?}"))),
    }
    let c = tok.claims;
    if c["iss"] != p.issuer.as_str() {
        return Err(bad("wrong issuer"));
    }
    let aud_ok = match &c["aud"] {
        Value::Array(a) => a.iter().any(|v| claim_str(v).as_deref() == Some(&p.client_id)),
        v => claim_str(v).as_deref() == Some(&p.client_id),
    };
    if !aud_ok {
        return Err(bad("not issued to this hub"));
    }
    if c["exp"].as_i64().is_none_or(|exp| exp + LEEWAY < t) {
        return Err(bad("expired"));
    }
    if c["iat"].as_i64().is_some_and(|iat| iat - LEEWAY > t) {
        return Err(bad("issued in the future"));
    }
    if !c["nonce"].is_null() && c["nonce"] != nonce {
        return Err(bad("nonce mismatch"));
    }
    if claim_str(&c["sub"]).is_none() {
        return Err(bad("no subject"));
    }
    Ok(c)
}

/// The JWK for a token header: by `kid`, else the only key of the right algorithm.
fn find_key<'a>(jwks: &'a Value, header: &Value) -> Option<&'a Value> {
    let alg = header["alg"].as_str()?;
    let fits = |k: &&Value| {
        let kty_ok = match alg {
            "RS256" => k["kty"] == "RSA",
            "ES256" => k["crv"] == "P-256",
            "ES256K" => k["crv"] == "secp256k1",
            "EdDSA" => k["crv"] == "Ed25519",
            _ => false,
        };
        kty_ok && (k["alg"].is_null() || k["alg"] == alg) && k["use"] != "enc"
    };
    let keys = jwks["keys"].as_array()?;
    match header["kid"].as_str() {
        Some(kid) => keys.iter().filter(fits).find(|k| k["kid"] == kid),
        None => {
            let mut fit = keys.iter().filter(fits);
            fit.next().filter(|_| fit.next().is_none())
        }
    }
}

impl Hub {
    pub fn upstream(&self, id: &str) -> Option<&Upstream> {
        self.cfg.upstreams.iter().find(|u| u.id == id)
    }

    fn upstream_callback(&self, p: &Upstream) -> String {
        format!("{}/oauth/upstream/{}/callback", self.cfg.issuer, p.id)
    }

    async fn fetch_json(&self, url: &str) -> anyhow::Result<Value> {
        Ok(self.http.get(url).send().await?.error_for_status()?.json().await?)
    }

    async fn upstream_meta(&self, p: &Upstream) -> anyhow::Result<Meta> {
        if let Some(m) = self.upstream.lock().unwrap().meta.get(&p.id) {
            return Ok(m.clone());
        }
        let configured = (p.authorization_endpoint.clone(), p.token_endpoint.clone(), p.jwks_uri.clone());
        // UserInfo is only looked up when the provider is trusted for attributes.
        let wants_userinfo = !p.attributes.is_empty() && p.userinfo_endpoint.is_none();
        let meta = match configured {
            (Some(authorization_endpoint), Some(token_endpoint), Some(jwks_uri)) if !wants_userinfo => {
                Meta { authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint: p.userinfo_endpoint.clone() }
            }
            (a, t, j) => {
                let d = self.fetch_json(&format!("{}/.well-known/openid-configuration", p.issuer)).await?;
                if d["issuer"] != p.issuer.as_str() {
                    anyhow::bail!("discovery document is for another issuer");
                }
                let pick = |have: Option<String>, k: &str| -> anyhow::Result<String> {
                    let u = have.or_else(|| d[k].as_str().map(String::from)).ok_or_else(|| anyhow::anyhow!("discovery document has no {k}"))?;
                    if !secure_url(&u) {
                        anyhow::bail!("{k} must be https");
                    }
                    Ok(u)
                };
                Meta {
                    authorization_endpoint: pick(a, "authorization_endpoint")?,
                    token_endpoint: pick(t, "token_endpoint")?,
                    jwks_uri: pick(j, "jwks_uri")?,
                    // Optional in discovery (OIDC Discovery §3).
                    userinfo_endpoint: if p.attributes.is_empty() { None } else { pick(p.userinfo_endpoint.clone(), "userinfo_endpoint").ok() },
                }
            }
        };
        self.upstream.lock().unwrap().meta.insert(p.id.clone(), meta.clone());
        Ok(meta)
    }

    /// The provider's JWKS, cached. `kid` forces a refetch when the cached set lacks
    /// it (key rotation), at most once a minute.
    async fn upstream_jwks(&self, p: &Upstream, meta: &Meta, header: &Value) -> anyhow::Result<Value> {
        let t = now();
        let cached = self.upstream.lock().unwrap().jwks.get(&p.id).cloned();
        if let Some((at, jwks)) = cached {
            let stale = at + JWKS_TTL < t || (find_key(&jwks, header).is_none() && at + JWKS_MIN_REFETCH < t);
            if !stale {
                return Ok(jwks);
            }
        }
        let jwks = self.fetch_json(&meta.jwks_uri).await?;
        self.upstream.lock().unwrap().jwks.insert(p.id.clone(), (t, jwks.clone()));
        Ok(jwks)
    }

    async fn upstream_exchange(&self, p: &Upstream, meta: &Meta, code: &str, pending: &Pending) -> ApiResult<Value> {
        let callback = self.upstream_callback(p);
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", callback.as_str()),
            ("client_id", p.client_id.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ];
        // Basic for confidential clients (what Telegram documents); public ones rely on PKCE.
        let body = form.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect::<Vec<_>>().join("&");
        let mut req = self.http.post(&meta.token_endpoint).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(body);
        if let Some(secret) = &p.client_secret {
            req = req.basic_auth(&p.client_id, Some(secret));
        }
        let unavailable = |e: String| ApiError(StatusCode::BAD_GATEWAY, "upstream_error".into(), e, None);
        let resp = req.send().await.map_err(|e| unavailable(e.to_string()))?;
        let status = resp.status();
        let v: Value = resp.json().await.map_err(|e| unavailable(e.to_string()))?;
        if !status.is_success() {
            return Err(unavailable(format!("token endpoint refused the code: {}", v["error"].as_str().unwrap_or(status.as_str()))));
        }
        let token = v["id_token"].as_str().ok_or_else(|| unavailable("token response has no id_token".into()))?;
        let header = jws::decode(token).map_err(ApiError::unauthorized)?.header;
        let jwks = self.upstream_jwks(p, meta, &header).await.map_err(|e| unavailable(e.to_string()))?;
        let mut claims = verify_id_token(p, &jwks, token, &pending.nonce, now())?;
        if let (Some(endpoint), Some(access_token)) = (&meta.userinfo_endpoint, v["access_token"].as_str()) {
            match self.upstream_userinfo(endpoint, access_token).await {
                // OIDC Core §5.3.2: an answer about another subject must not be used.
                Ok(info) if claim_str(&info["sub"]) != claim_str(&claims["sub"]) => {
                    return Err(ApiError::unauthorized(format!("{} UserInfo is about another account", p.display_name())));
                }
                Ok(Value::Object(info)) => {
                    // The signed ID token wins; UserInfo only adds what it lacks.
                    let have = claims.as_object_mut().expect("verified claims are an object");
                    for (k, val) in info {
                        have.entry(k).or_insert(val);
                    }
                }
                Ok(_) => {}
                // The login stands on the ID token; it just carries fewer attributes.
                Err(e) => eprintln!("upstream {}: UserInfo failed, continuing without it: {e}", p.id),
            }
        }
        Ok(claims)
    }

    async fn upstream_userinfo(&self, endpoint: &str, access_token: &str) -> anyhow::Result<Value> {
        Ok(self.http.get(endpoint).bearer_auth(access_token).send().await?.error_for_status()?.json().await?)
    }

    /// The identity an upstream account signs in: the one whose KEL links `alias`.
    /// Anyone can link any alias, so when several identities do, the browser has to
    /// say which one it means.
    fn identity_for_alias(&self, alias: &str, hint: Option<&str>) -> Result<String, &'static str> {
        let mut linked: Vec<String> = self.kel_dids().into_iter().filter(|d| self.resolve_aliases(d).is_some_and(|a| a.contains(alias))).collect();
        match hint {
            Some(did) if linked.iter().any(|d| d == did) => Ok(did.to_string()),
            Some(_) => Err("not_linked"),
            None if linked.len() == 1 => Ok(linked.remove(0)),
            None if linked.is_empty() => Err("not_linked"),
            None => Err("ambiguous"),
        }
    }

    fn resolve_aliases(&self, did: &str) -> Option<std::collections::BTreeSet<String>> {
        use kith_core::session::KelResolver;
        self.resolve(did).ok().map(|st| st.aliases)
    }
}

fn state_cookie(h: &Hub, value: &str, max_age: i64) -> HeaderValue {
    let secure = if h.cfg.issuer.starts_with("https://") { "; Secure" } else { "" };
    HeaderValue::from_str(&format!("{STATE_COOKIE}={value}; Path=/oauth/upstream; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}")).expect("cookie")
}

/// `GET /oauth/upstream/{id}/start?request_id=…[&did=…]`: the login page sends the
/// browser here; it leaves for the provider's authorization endpoint.
pub async fn start(State(h): State<Arc<Hub>>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(p) = h.upstream(&id).cloned() else {
        return pages::message(StatusCode::NOT_FOUND, "Unknown sign-in method", "This hub doesn't accept that sign-in method.");
    };
    let request_id = q.get("request_id").cloned().unwrap_or_default();
    if h.store.request(&request_id).ok().flatten().is_none() {
        return pages::message(StatusCode::BAD_REQUEST, "Sign-in expired", "This sign-in request expired. Go back to the app and try again.");
    }
    let meta = match h.upstream_meta(&p).await {
        Ok(m) => m,
        Err(e) => return pages::message(StatusCode::BAD_GATEWAY, "Sign-in unavailable", &format!("{} can't be reached right now ({e}).", p.display_name())),
    };
    let (state, nonce) = (random_id(), random_id());
    let verifier = format!("{}{}", random_id(), random_id());
    let url = with_params(
        &meta.authorization_endpoint,
        &[
            ("response_type", Some("code")),
            ("client_id", Some(&p.client_id)),
            ("redirect_uri", Some(&h.upstream_callback(&p))),
            ("scope", Some(&p.scope)),
            ("state", Some(&state)),
            ("nonce", Some(&nonce)),
            ("code_challenge", Some(&b64u(sha256(verifier.as_bytes())))),
            ("code_challenge_method", Some("S256")),
        ],
    );
    {
        let mut u = h.upstream.lock().unwrap();
        let t = now();
        u.pending.retain(|_, x| x.created + PENDING_TTL > t);
        let did = q.get("did").cloned().filter(|d| !d.is_empty());
        u.pending.insert(state.clone(), Pending { provider: p.id.clone(), request_id, verifier, nonce, did, created: t });
    }
    let mut r = Redirect::to(&url).into_response();
    r.headers_mut().insert(header::SET_COOKIE, state_cookie(&h, &state, PENDING_TTL));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// `GET /oauth/upstream/{id}/callback?code=…&state=…`: the provider sends the
/// browser back here.
pub async fn callback(State(h): State<Arc<Hub>>, Path(id): Path<String>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let mut r = finish(&h, &id, &headers, &q).await;
    r.headers_mut().append(header::SET_COOKIE, state_cookie(&h, "", 0));
    r
}

async fn finish(h: &Arc<Hub>, id: &str, headers: &HeaderMap, q: &HashMap<String, String>) -> Response {
    let expired = || pages::message(StatusCode::BAD_REQUEST, "Sign-in expired", "This sign-in request expired or was already used. Go back to the app and try again.");
    let Some(p) = h.upstream(id).cloned() else {
        return pages::message(StatusCode::NOT_FOUND, "Unknown sign-in method", "This hub doesn't accept that sign-in method.");
    };
    let name = p.display_name();
    // `state` must be one this hub issued, for this provider, to this browser.
    let state = q.get("state").cloned().unwrap_or_default();
    let Some(pending) = h.upstream.lock().unwrap().pending.remove(&state) else {
        return expired();
    };
    if pending.provider != p.id || pending.created + PENDING_TTL < now() || cookie(headers, STATE_COOKIE).as_deref() != Some(state.as_str()) {
        return expired();
    }
    if q.contains_key("error") {
        return pages::message(StatusCode::UNAUTHORIZED, "Sign-in cancelled", &format!("{name} did not sign you in. Go back to the app and try again."));
    }
    let Some(code) = q.get("code") else {
        return expired();
    };
    let Some(ar) = h.store.request(&pending.request_id).ok().flatten() else {
        return expired();
    };
    let meta = match h.upstream_meta(&p).await {
        Ok(m) => m,
        Err(e) => return pages::message(StatusCode::BAD_GATEWAY, "Sign-in unavailable", &format!("{name} can't be reached right now ({e}).")),
    };
    let claims = match h.upstream_exchange(&p, &meta, code, &pending).await {
        Ok(c) => c,
        Err(e) => return pages::message(e.0, "Sign-in failed", &format!("{name} sign-in could not be verified: {}", e.2)),
    };
    let alias = p.alias(&claim_str(&claims["sub"]).unwrap_or_default());
    let did = match h.identity_for_alias(&alias, pending.did.as_deref()) {
        Ok(d) => d,
        Err("ambiguous") => {
            return pages::message(
                StatusCode::UNAUTHORIZED,
                "Which identity?",
                &format!("More than one Kith identity links this {name} account. Go back, enter your Kith identity under \"Other ways to sign in\", and try again."),
            )
        }
        Err(_) => {
            return pages::message(
                StatusCode::UNAUTHORIZED,
                "Account not linked",
                &format!("This {name} account isn't linked to a Kith identity yet. Link it once from a device you already use: kith alias link '{alias}'"),
            )
        }
    };
    let factor = Factor::Federated { provider: p.id.clone(), alias: alias.clone() };
    let attrs = p.attributes_from(&claims);
    let a = match h.authenticate(&did, "", &[factor]) {
        Ok(a) => crate::Authn { attrs: attrs.clone(), ..a },
        Err(e) => return pages::message(e.0, "Sign-in failed", &e.2),
    };
    if a.aal >= ar.min_aal {
        let Some((url, session)) = crate::oidc::complete_login(h, &pending.request_id, ar, a) else {
            return expired();
        };
        let mut r = Redirect::to(&url).into_response();
        r.headers_mut().insert(header::SET_COOKIE, session);
        return r;
    }
    // Not strong enough alone: back to the login page to add a one-time code.
    let fed = Federated { did, provider: p.id.clone(), alias, attrs, token: random_id() };
    crate::oidc::login_page(h, &pending.request_id, &ar, Some((&fed, &name))).unwrap_or_else(expired)
}

/// What discovery and the login page say about the configured providers.
pub(crate) fn summary(h: &Hub) -> Value {
    json!(h.cfg.upstreams.iter().map(|u| json!({"id": u.id, "name": u.display_name(), "issuer": u.issuer})).collect::<Vec<_>>())
}
