//! Reference Kith hub.
//!
//! A hub is an *optional* convenience: it stores KELs (anyone can mirror them, they
//! are self-verifying), authenticates people with whatever they have, evaluates
//! group/role membership, and mints ordinary JWTs so resource servers only need a
//! JWKS URL. It is also a standard OpenID Connect provider, so existing apps can
//! "Sign in with Kith" (see [`oidc`]).
//!
//! | endpoint                                  | purpose                                         |
//! |-------------------------------------------|-------------------------------------------------|
//! | `GET  /.well-known/openid-configuration`  | OIDC / OAuth discovery                          |
//! | `GET  /.well-known/jwks.json`             | token verification keys (EdDSA + RS256)         |
//! | `GET  /oauth/authorize`                   | OIDC authorization endpoint (code + PKCE)       |
//! | `POST /oauth/login`                       | login page posts passkey / wallet / TOTP here   |
//! | `POST /oauth/token`                       | code, refresh and RFC 8693 token exchange       |
//! | `GET  /oauth/userinfo`                    | OIDC userinfo                                   |
//! | `GET  /oauth/logout`                      | RP-initiated logout                             |
//! | `GET/PUT /v1/kel/{did}`                   | fetch / append a key event log                  |
//! | `GET  /v1/did/{did}`                      | DID document                                    |
//! | `POST /v1/auth/challenge`, `/v1/auth/verify` | API challenge login (signature/passkey/TOTP) |
//! | `POST /v1/totp/enroll`, `/v1/totp/confirm`| TOTP factor (bearer)                            |
//! | `POST /v1/cosigner`, `/v1/cosign`         | TOTP-gated co-signer                            |
//! | `POST /v1/enroll`, `GET /enroll/{id}`     | enroll a browser passkey as a device            |

// ApiError carries an HTTP status plus a JSON body; boxing it buys nothing here.
#![allow(clippy::result_large_err)]

pub mod enroll;
pub mod oidc;
mod pages;

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use kith_core::authz::{Bundle, Engine};
use kith_core::kel::{extends, verify_log, DeviceKind, Event, KeyState};
use kith_core::keys::{verify_sig, KeyType, LocalSigner, PublicKey, Sig, VerifyOptions};
use kith_core::session::{self, Capability, KelResolver};
use kith_core::token::{verify_access_token, AccessClaims, Actor, HubSigner};
use kith_core::util::{b64u, b64u_decode, now, random_id, sha256};
use kith_core::{totp, webauthn};

pub const TOKEN_TTL: i64 = 900;
pub const TT_SESSION: &str = "urn:kith:params:oauth:token-type:session";
pub const TT_DELEGATION: &str = "urn:kith:params:oauth:token-type:delegation";

#[derive(Debug, Clone)]
pub struct HubConfig {
    /// Public base URL; the token issuer and the audience for session proofs.
    pub issuer: String,
    pub data_dir: PathBuf,
    pub bundle_path: Option<PathBuf>,
    /// WebAuthn relying party id and allowed origins for passkey login.
    pub rp_id: String,
    pub origins: Vec<String>,
    /// Registered OIDC clients.
    pub clients: Vec<oidc::Client>,
}

impl HubConfig {
    /// Sensible local defaults: rp id = issuer host, origins = issuer origin.
    pub fn new(issuer: impl Into<String>, data_dir: impl Into<PathBuf>) -> Self {
        let issuer: String = issuer.into();
        let issuer = issuer.trim_end_matches('/').to_string();
        let rp_id = host_of(&issuer).unwrap_or_else(|| "localhost".into());
        HubConfig { origins: vec![issuer.clone()], issuer, data_dir: data_dir.into(), bundle_path: None, rp_id, clients: vec![] }
    }
}

pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let hostport = rest.split(['/', '?', '#']).next()?;
    let host = hostport.rsplit_once(':').map(|(h, p)| if p.chars().all(|c| c.is_ascii_digit()) { h } else { hostport }).unwrap_or(hostport);
    Some(host.trim_matches(['[', ']']).to_string())
}

struct TotpRecord {
    secret: Vec<u8>,
    confirmed: bool,
    last_step: i64,
    failures: u32,
}

pub(crate) struct Challenge {
    /// Bound identity (API login). OIDC passkey login learns it from the passkey.
    pub did: Option<String>,
    pub message: String,
    pub expires: i64,
}

/// The result of a successful authentication.
#[derive(Debug, Clone)]
pub struct Authn {
    pub st: KeyState,
    pub dev: Option<String>,
    pub aal: u8,
    pub amr: Vec<String>,
    pub auth_time: i64,
}

pub struct Hub {
    pub cfg: HubConfig,
    pub signer: HubSigner,
    pub(crate) rsa: oidc::RsaSigner,
    pub(crate) pairwise_secret: Vec<u8>,
    kels: RwLock<HashMap<String, Vec<Event>>>,
    engine: RwLock<(Option<std::time::SystemTime>, Arc<Engine>)>,
    pub(crate) challenges: Mutex<HashMap<String, Challenge>>,
    seen_jti: Mutex<HashMap<String, i64>>,
    totp: Mutex<HashMap<String, TotpRecord>>,
    cosigners: Mutex<HashMap<String, LocalSigner>>,
    pub(crate) oidc: Mutex<oidc::OidcState>,
    pub(crate) enrollments: Mutex<HashMap<String, enroll::Enrollment>>,
}

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String, pub String, pub Option<Value>);

impl ApiError {
    pub fn bad(code: &str, msg: impl ToString) -> Self {
        ApiError(StatusCode::BAD_REQUEST, code.into(), msg.to_string(), None)
    }
    pub fn unauthorized(msg: impl ToString) -> Self {
        ApiError(StatusCode::UNAUTHORIZED, "invalid_token".into(), msg.to_string(), None)
    }
    pub fn grant(msg: impl ToString) -> Self {
        ApiError(StatusCode::BAD_REQUEST, "invalid_grant".into(), msg.to_string(), None)
    }
    /// Add fields to the error body (merged with any already present).
    pub fn with(mut self, extra: Value) -> Self {
        match (&mut self.3, extra) {
            (Some(Value::Object(have)), Value::Object(more)) => have.extend(more),
            (slot, extra) => *slot = Some(extra),
        }
        self
    }
}

impl From<kith_core::Error> for ApiError {
    fn from(e: kith_core::Error) -> Self {
        ApiError::bad("invalid_request", e)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "server_error".into(), e.to_string(), None)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({"error": self.1, "error_description": self.2});
        if let Some(Value::Object(extra)) = self.3 {
            for (k, v) in extra {
                body[k] = v;
            }
        }
        let mut r = (self.0, Json(body)).into_response();
        r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        r
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub(crate) fn read_json(path: &std::path::Path) -> Option<Value> {
    std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok())
}

pub(crate) fn write_json(path: &std::path::Path, v: &Value) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(v)?)?;
    Ok(())
}

/// Authentication evidence submitted to `/v1/auth/verify` or `/oauth/login`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Factor {
    /// Any signer on the identity (device key, wallet, manage key) signs the challenge.
    Signature { sig: Sig },
    /// A passkey answers `navigator.credentials.get({challenge: SHA-256(message)})`.
    /// `device_id` may be omitted; every passkey device of the identity is tried.
    Webauthn {
        #[serde(default)]
        device_id: Option<String>,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
    Totp { code: String },
}

impl Hub {
    pub fn open(cfg: HubConfig) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(cfg.data_dir.join("kels"))?;
        let key_path = cfg.data_dir.join("hub-key.json");
        let signer = match read_json(&key_path) {
            Some(v) => HubSigner::from_json(&v)?,
            None => {
                let s = HubSigner::generate();
                write_json(&key_path, &s.to_json())?;
                s
            }
        };
        let rsa_path = cfg.data_dir.join("hub-rsa-key.json");
        let rsa = match read_json(&rsa_path) {
            Some(v) => oidc::RsaSigner::from_json(&v)?,
            None => {
                let s = oidc::RsaSigner::generate()?;
                write_json(&rsa_path, &s.to_json()?)?;
                s
            }
        };
        let secret_path = cfg.data_dir.join("hub-secret.json");
        let pairwise_secret = match read_json(&secret_path) {
            Some(v) => b64u_decode(v["pairwise"].as_str().unwrap_or_default())?,
            None => {
                let s = totp::generate_secret();
                write_json(&secret_path, &json!({"pairwise": b64u(&s)}))?;
                s
            }
        };
        let mut kels = HashMap::new();
        for entry in std::fs::read_dir(cfg.data_dir.join("kels"))? {
            if let Some(v) = read_json(&entry?.path()) {
                let events: Vec<Event> = serde_json::from_value(v)?;
                let st = verify_log(&events, &VerifyOptions::default())?;
                kels.insert(st.did, events);
            }
        }
        let mut totp_map = HashMap::new();
        if let Some(Value::Object(m)) = read_json(&cfg.data_dir.join("totp.json")) {
            for (did, r) in m {
                let secret = b64u_decode(r["secret"].as_str().unwrap_or_default())?;
                totp_map.insert(did, TotpRecord { secret, confirmed: r["confirmed"].as_bool().unwrap_or(false), last_step: r["last_step"].as_i64().unwrap_or(0), failures: 0 });
            }
        }
        let mut cosigners = HashMap::new();
        if let Some(Value::Object(m)) = read_json(&cfg.data_dir.join("cosigners.json")) {
            for (did, s) in m {
                cosigners.insert(did, LocalSigner::from_json(&s)?);
            }
        }
        for c in &cfg.clients {
            c.validate()?;
        }
        let hub = Hub {
            cfg,
            signer,
            rsa,
            pairwise_secret,
            kels: RwLock::new(kels),
            engine: RwLock::new((None, Arc::new(Engine::new(Bundle { version: 1, ..Default::default() })?))),
            challenges: Mutex::new(HashMap::new()),
            seen_jti: Mutex::new(HashMap::new()),
            totp: Mutex::new(totp_map),
            cosigners: Mutex::new(cosigners),
            oidc: Mutex::new(oidc::OidcState::default()),
            enrollments: Mutex::new(HashMap::new()),
        };
        hub.engine()?;
        Ok(Arc::new(hub))
    }

    /// The policy engine, reloaded whenever the bundle file changes.
    pub fn engine(&self) -> anyhow::Result<Arc<Engine>> {
        let Some(path) = &self.cfg.bundle_path else {
            return Ok(self.engine.read().unwrap().1.clone());
        };
        let mtime = std::fs::metadata(path)?.modified()?;
        if self.engine.read().unwrap().0 != Some(mtime) {
            let engine = Arc::new(Engine::from_json(&std::fs::read_to_string(path)?)?);
            *self.engine.write().unwrap() = (Some(mtime), engine);
        }
        Ok(self.engine.read().unwrap().1.clone())
    }

    /// Verification keys: EdDSA (access tokens) and RS256 (ID tokens).
    pub fn jwks(&self) -> Value {
        let mut keys = self.signer.jwks();
        keys["keys"].as_array_mut().expect("keys").push(self.rsa.jwk());
        keys
    }

    fn persist_totp(&self, map: &HashMap<String, TotpRecord>) -> anyhow::Result<()> {
        let v: Map<String, Value> = map
            .iter()
            .map(|(d, r)| (d.clone(), json!({"secret": b64u(&r.secret), "confirmed": r.confirmed, "last_step": r.last_step})))
            .collect();
        write_json(&self.cfg.data_dir.join("totp.json"), &Value::Object(v))
    }

    pub fn put_kel(&self, did: &str, events: Vec<Event>) -> ApiResult<KeyState> {
        let st = verify_log(&events, &VerifyOptions::default())?;
        if st.did != did {
            return Err(ApiError::bad("invalid_request", "log does not belong to this DID"));
        }
        let mut kels = self.kels.write().unwrap();
        if let Some(old) = kels.get(did) {
            if !extends(old, &events)? {
                // Duplicity: two different histories signed by the same identity.
                return Err(ApiError(StatusCode::CONFLICT, "duplicity".into(), "log forks from the stored history".into(), None));
            }
        }
        let file = self.cfg.data_dir.join("kels").join(format!("{}.json", did.replace(':', "_")));
        write_json(&file, &serde_json::to_value(&events).map_err(kith_core::Error::from)?)?;
        kels.insert(did.into(), events);
        Ok(st)
    }

    pub fn get_kel(&self, did: &str) -> Option<Vec<Event>> {
        self.kels.read().unwrap().get(did).cloned()
    }

    fn check_jti(&self, jti: &str, exp: i64) -> ApiResult<()> {
        let mut seen = self.seen_jti.lock().unwrap();
        let t = now();
        seen.retain(|_, e| *e + session::LEEWAY > t);
        if seen.insert(jti.into(), exp).is_some() {
            return Err(ApiError::unauthorized("token replayed"));
        }
        Ok(())
    }

    /// Check a TOTP code for `did`, with replay protection and a failure lockout.
    fn check_totp(&self, did: &str, code: &str, require_confirmed: bool) -> ApiResult<()> {
        let mut map = self.totp.lock().unwrap();
        let rec = map.get_mut(did).ok_or_else(|| ApiError::unauthorized("no TOTP enrolled"))?;
        if require_confirmed && !rec.confirmed {
            return Err(ApiError::unauthorized("TOTP not confirmed"));
        }
        if rec.failures >= 5 {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "locked".into(), "too many TOTP failures".into(), None));
        }
        match totp::verify(&rec.secret, code, now(), 1) {
            Some(step) if step > rec.last_step => {
                rec.last_step = step;
                rec.failures = 0;
                rec.confirmed = true;
                self.persist_totp(&map)?;
                Ok(())
            }
            Some(_) => Err(ApiError::unauthorized("TOTP code already used")),
            None => {
                rec.failures += 1;
                Err(ApiError::unauthorized("invalid TOTP code"))
            }
        }
    }

    pub(crate) fn new_challenge(&self, did: Option<String>, message_for: impl FnOnce(&str, i64, i64) -> String) -> (String, String, i64) {
        let id = random_id();
        let iat = now();
        let exp = iat + 300;
        let message = message_for(&id, iat, exp);
        let mut ch = self.challenges.lock().unwrap();
        ch.retain(|_, c| c.expires > iat);
        ch.insert(id.clone(), Challenge { did, message: message.clone(), expires: exp });
        (id, message, exp)
    }

    pub(crate) fn take_challenge(&self, id: &str) -> ApiResult<Challenge> {
        let ch = self.challenges.lock().unwrap().remove(id).ok_or_else(|| ApiError::unauthorized("unknown or used challenge"))?;
        if ch.expires < now() {
            return Err(ApiError::unauthorized("challenge expired"));
        }
        Ok(ch)
    }

    /// Verify authentication `factors` for `did` over a challenge `message`.
    pub fn authenticate(&self, did: &str, message: &str, factors: &[Factor]) -> ApiResult<Authn> {
        let st = self.resolve(did).map_err(|e| ApiError::unauthorized(format!("unknown identity: {e}")))?;
        let mut aal = 0u8;
        let mut amr = Vec::<String>::new();
        let mut kinds = BTreeSet::new();
        let mut dev = None;
        for f in factors {
            match f {
                Factor::Signature { sig } => {
                    if !st.is_authentication_signer(&sig.signer) {
                        return Err(ApiError::unauthorized("signer is not a device or manage key of this identity"));
                    }
                    if sig.alg == "WebAuthn" {
                        return Err(ApiError::bad("invalid_request", "use the webauthn factor for passkeys"));
                    }
                    verify_sig(sig, message.as_bytes(), &VerifyOptions::default()).map_err(ApiError::unauthorized)?;
                    let d = st.devices.values().find(|d| d.key == sig.signer);
                    aal = aal.max(d.map(|d| d.aal).unwrap_or(2));
                    amr.push(if sig.alg.starts_with("EIP") {
                        "wallet".into()
                    } else if d.is_some_and(|d| d.kind == DeviceKind::Hardware) {
                        "hwk".into()
                    } else {
                        "swk".into()
                    });
                    dev = dev.or(d.map(|d| d.id.clone()));
                    kinds.insert("possession");
                }
                Factor::Webauthn { device_id, authenticator_data, client_data_json, signature } => {
                    let data = webauthn::WebAuthnSigData { authenticator_data: authenticator_data.clone(), client_data_json: client_data_json.clone() };
                    let sig = b64u_decode(signature)?;
                    let challenge = sha256(message.as_bytes()).to_vec();
                    let candidates: Vec<_> = st
                        .devices
                        .values()
                        .filter(|d| d.kind == DeviceKind::Passkey && device_id.as_ref().is_none_or(|id| &d.id == id))
                        .collect();
                    let mut matched = None;
                    for d in candidates {
                        let pk = PublicKey::from_did_key(&d.key)?;
                        let check = webauthn::AssertionCheck {
                            challenge: challenge.clone(),
                            rp_id: Some(d.rp_id.as_deref().unwrap_or(&self.cfg.rp_id)),
                            origins: Some(&self.cfg.origins),
                            require_uv: false,
                        };
                        if let Ok(info) = webauthn::verify_assertion(&pk, &data, &sig, &check) {
                            matched = Some((d, info));
                            break;
                        }
                    }
                    let (d, info) = matched.ok_or_else(|| ApiError::unauthorized("passkey assertion did not verify for any passkey device of this identity"))?;
                    // A user-verified passkey is multi-factor by itself (possession + PIN/biometric).
                    aal = aal.max(if info.user_verified { d.aal } else { d.aal.min(1) });
                    amr.push("hwk".into());
                    if info.user_verified {
                        amr.push("user".into());
                        kinds.insert("inherence");
                    }
                    dev = Some(d.id.clone());
                    kinds.insert("possession");
                }
                Factor::Totp { code } => {
                    self.check_totp(&st.did, code, true)?;
                    aal = aal.max(1);
                    amr.push("otp".into());
                    kinds.insert("otp");
                }
            }
        }
        if aal == 0 {
            return Err(ApiError::unauthorized("no factors"));
        }
        if kinds.len() >= 2 {
            aal = aal.max(2);
            amr.push("mfa".into());
        }
        Ok(Authn { st, dev, aal, amr, auth_time: now() })
    }

    /// Access token claims for an authenticated principal.
    pub fn access_claims(&self, a: &Authn, audience: &str, delegation: Option<(String, Vec<Capability>)>) -> ApiResult<AccessClaims> {
        let engine = self.engine()?;
        let mut kel_attrs = Map::new();
        kel_attrs.insert("aliases".into(), json!(a.st.aliases));
        let mut attrs = engine.attributes(&a.st.did, &kel_attrs);
        attrs.insert("aal".into(), json!(a.aal));
        let m = engine.memberships(&a.st.did, &attrs)?;
        let iat = now();
        let (act, cap) = match delegation {
            Some((actor, caps)) => (Some(Actor { sub: actor, act: None }), Some(caps)),
            None => (None, None),
        };
        Ok(AccessClaims {
            iss: self.cfg.issuer.clone(),
            sub: a.st.did.clone(),
            aud: audience.into(),
            iat,
            exp: iat + TOKEN_TTL,
            jti: random_id(),
            client_id: None,
            scope: None,
            groups: m.groups,
            roles: m.roles,
            attrs,
            aal: a.aal,
            amr: a.amr.clone(),
            dev: a.dev.clone(),
            act,
            cap,
            cnf: None,
        })
    }

    pub fn token_response(&self, claims: &AccessClaims) -> ApiResult<Value> {
        Ok(json!({
            "access_token": self.signer.issue(claims)?,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL,
        }))
    }

    /// Mint an access token after authentication.
    pub fn issue(&self, a: &Authn, audience: &str, delegation: Option<(String, Vec<Capability>)>) -> ApiResult<Value> {
        self.token_response(&self.access_claims(a, audience, delegation)?)
    }

    pub(crate) fn bearer_any(&self, headers: &HeaderMap) -> ApiResult<AccessClaims> {
        let h = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
        let tok = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")).ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
        let t = kith_core::jws::decode(tok).map_err(ApiError::unauthorized)?;
        let aud = t.claims["aud"].as_str().unwrap_or_default().to_string();
        verify_access_token(tok, &self.signer.jwks(), &self.cfg.issuer, &aud, now()).map_err(ApiError::unauthorized)
    }

    /// Bearer token issued for the hub itself (CLI management calls).
    pub(crate) fn bearer(&self, headers: &HeaderMap) -> ApiResult<AccessClaims> {
        let c = self.bearer_any(headers)?;
        if c.aud != self.cfg.issuer || c.act.is_some() {
            return Err(ApiError::unauthorized("token is not for this hub"));
        }
        Ok(c)
    }
}

impl KelResolver for Hub {
    fn resolve(&self, did: &str) -> kith_core::Result<KeyState> {
        let events = self.get_kel(did).ok_or_else(|| kith_core::Error::NotFound(format!("no KEL for {did}")))?;
        verify_log(&events, &VerifyOptions::default())
    }
}

// ---------------------------------------------------------------- handlers

async fn jwks(State(h): State<Arc<Hub>>) -> Json<Value> {
    Json(h.jwks())
}

async fn get_kel(State(h): State<Arc<Hub>>, Path(did): Path<String>) -> ApiResult<Json<Value>> {
    let events = h.get_kel(&did).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), did.clone(), None))?;
    Ok(Json(json!(events)))
}

async fn put_kel(State(h): State<Arc<Hub>>, Path(did): Path<String>, Json(events): Json<Vec<Event>>) -> ApiResult<Json<Value>> {
    let st = h.put_kel(&did, events)?;
    Ok(Json(json!({"did": st.did, "seq": st.seq, "digest": st.digest})))
}

async fn did_doc(State(h): State<Arc<Hub>>, Path(did): Path<String>) -> ApiResult<Json<Value>> {
    let st = h.resolve(&did).map_err(|e| ApiError(StatusCode::NOT_FOUND, "not_found".into(), e.to_string(), None))?;
    Ok(Json(st.did_document(Some(&h.cfg.issuer))))
}

#[derive(Deserialize)]
struct ChallengeReq {
    did: String,
}

async fn challenge(State(h): State<Arc<Hub>>, Json(req): Json<ChallengeReq>) -> ApiResult<Json<Value>> {
    h.resolve(&req.did).map_err(|e| ApiError::bad("unknown_identity", e))?;
    let (rp, iss, did) = (h.cfg.rp_id.clone(), h.cfg.issuer.clone(), req.did.clone());
    // CAIP-122 / SIWE-shaped so wallets render it sensibly.
    let (id, message, exp) = h.new_challenge(Some(req.did.clone()), |id, iat, exp| {
        format!("{rp} wants you to sign in with your Kith identity:\n{did}\n\nURI: {iss}\nVersion: 1\nNonce: {id}\nIssued At: {iat}\nExpiration Time: {exp}")
    });
    Ok(Json(json!({"challenge_id": id, "message": message, "expires_at": exp})))
}

#[derive(Deserialize)]
struct VerifyReq {
    challenge_id: String,
    audience: String,
    factors: Vec<Factor>,
}

async fn verify(State(h): State<Arc<Hub>>, Json(req): Json<VerifyReq>) -> ApiResult<Json<Value>> {
    let ch = h.take_challenge(&req.challenge_id)?;
    let did = ch.did.ok_or_else(|| ApiError::bad("invalid_request", "challenge is not bound to an identity"))?;
    let a = h.authenticate(&did, &ch.message, &req.factors)?;
    Ok(Json(h.issue(&a, &req.audience, None)?))
}

/// `POST /oauth/token` (and legacy `/v1/oauth/token`): every grant type.
#[derive(Debug, Default, Deserialize)]
pub struct TokenReq {
    pub grant_type: String,
    // RFC 8693 token exchange
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub audience: Option<String>,
    /// Kith extension: TOTP step-up alongside a session chain.
    pub totp: Option<String>,
    // authorization_code / refresh_token
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

async fn token(State(h): State<Arc<Hub>>, headers: HeaderMap, Form(req): Form<TokenReq>) -> ApiResult<Response> {
    let body = match req.grant_type.as_str() {
        "urn:ietf:params:oauth:grant-type:token-exchange" => token_exchange(&h, &req)?,
        "authorization_code" => oidc::code_grant(&h, &headers, &req)?,
        "refresh_token" => oidc::refresh_grant(&h, &headers, &req)?,
        other => return Err(ApiError::bad("unsupported_grant_type", other)),
    };
    let mut r = Json(body).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(r)
}

fn token_exchange(h: &Hub, req: &TokenReq) -> ApiResult<Value> {
    let audience = req.audience.clone().unwrap_or_else(|| h.cfg.issuer.clone());
    let subject = req.subject_token.as_deref().ok_or_else(|| ApiError::bad("invalid_request", "subject_token required"))?;
    let t = now();
    match req.subject_token_type.as_deref().unwrap_or_default() {
        TT_SESSION => {
            let v = session::verify_session_token(subject, &h.cfg.issuer, h, t).map_err(ApiError::unauthorized)?;
            h.check_jti(v.claims["jti"].as_str().unwrap_or_default(), v.claims["exp"].as_i64().unwrap_or(t))?;
            let st = h.resolve(&v.did)?;
            let mut a = Authn {
                st,
                dev: Some(v.device.id.clone()),
                aal: v.aal,
                amr: vec![match v.device.kind {
                    DeviceKind::Passkey | DeviceKind::Hardware => "hwk".to_string(),
                    _ => "swk".to_string(),
                }],
                auth_time: t,
            };
            if let Some(code) = &req.totp {
                h.check_totp(&v.did, code, true)?;
                a.amr.push("otp".into());
                a.amr.push("mfa".into());
                a.aal = a.aal.max(2);
            }
            h.issue(&a, &audience, None)
        }
        TT_DELEGATION => {
            let actor_token = req.actor_token.as_deref().ok_or_else(|| ApiError::bad("invalid_request", "delegation requires actor_token"))?;
            let actor = session::verify_session_token(actor_token, &h.cfg.issuer, h, t).map_err(ApiError::unauthorized)?;
            h.check_jti(actor.claims["jti"].as_str().unwrap_or_default(), actor.claims["exp"].as_i64().unwrap_or(t))?;
            let (_, d) = session::verify_delegation(subject, &h.cfg.issuer, h, t).map_err(ApiError::unauthorized)?;
            if d.sub != actor.did {
                return Err(ApiError::unauthorized("delegation was issued to someone else"));
            }
            let st = h.resolve(&d.iss)?;
            // The delegate's assurance, not the delegator's, describes this session.
            let a = Authn { st, dev: None, aal: actor.aal, amr: vec!["delegated".into()], auth_time: t };
            h.issue(&a, &audience, Some((actor.did.clone(), d.cap.clone())))
        }
        other => Err(ApiError::bad("invalid_request", format!("unsupported subject_token_type {other}"))),
    }
}

async fn totp_enroll(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let mut map = h.totp.lock().unwrap();
    if map.get(&c.sub).is_some_and(|r| r.confirmed) {
        return Err(ApiError(StatusCode::CONFLICT, "exists".into(), "TOTP already enrolled".into(), None));
    }
    let secret = totp::generate_secret();
    let uri = totp::otpauth_uri(&secret, &h.cfg.rp_id, &c.sub);
    let b32 = totp::to_base32(&secret);
    map.insert(c.sub.clone(), TotpRecord { secret, confirmed: false, last_step: 0, failures: 0 });
    h.persist_totp(&map)?;
    Ok(Json(json!({"secret": b32, "otpauth_uri": uri})))
}

#[derive(Deserialize)]
struct CodeReq {
    code: String,
}

async fn totp_confirm(State(h): State<Arc<Hub>>, headers: HeaderMap, Json(req): Json<CodeReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    h.check_totp(&c.sub, &req.code, false)?;
    Ok(Json(json!({"confirmed": true})))
}

/// Returns (creating on first call) the hub-held co-signer key for the caller.
/// Put its id in your manage or rotation policy – e.g. `2 of [passkey, ledger,
/// cosigner]` – and TOTP becomes a real signer in your multisig.
async fn cosigner(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let mut map = h.cosigners.lock().unwrap();
    let s = map.entry(c.sub.clone()).or_insert_with(|| LocalSigner::generate(KeyType::Ed25519)).clone();
    let v: Map<String, Value> = map.iter().map(|(d, s)| (d.clone(), s.to_json())).collect();
    write_json(&h.cfg.data_dir.join("cosigners.json"), &Value::Object(v))?;
    Ok(Json(json!({"signer": s.id, "gated_by": "totp"})))
}

#[derive(Deserialize)]
struct CosignReq {
    did: String,
    code: String,
    event: Event,
}

async fn cosign(State(h): State<Arc<Hub>>, Json(req): Json<CosignReq>) -> ApiResult<Json<Value>> {
    let st = h.resolve(&req.did)?;
    if req.event.did.as_deref() != Some(st.did.as_str()) || req.event.seq != st.seq + 1 || req.event.prev.as_deref() != Some(st.digest.as_str()) {
        return Err(ApiError::bad("invalid_request", "event must be the next event of this identity's KEL"));
    }
    let signer = h.cosigners.lock().unwrap().get(&st.did).cloned().ok_or_else(|| ApiError::bad("invalid_request", "no co-signer for this identity"))?;
    h.check_totp(&st.did, &req.code, true)?;
    let sig = signer.sign(&req.event.signing_message()?)?;
    Ok(Json(json!(sig)))
}

pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/.well-known/oauth-authorization-server", get(oidc::discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/authorize", get(oidc::authorize))
        .route("/oauth/login", post(oidc::login))
        .route("/oauth/token", post(token))
        .route("/oauth/userinfo", get(oidc::userinfo).post(oidc::userinfo))
        .route("/oauth/logout", get(oidc::logout))
        .route("/v1/oauth/token", post(token))
        .route("/v1/kel/{did}", get(get_kel).put(put_kel))
        .route("/v1/did/{did}", get(did_doc))
        .route("/v1/auth/challenge", post(challenge))
        .route("/v1/auth/verify", post(verify))
        .route("/v1/totp/enroll", post(totp_enroll))
        .route("/v1/totp/confirm", post(totp_confirm))
        .route("/v1/cosigner", post(cosigner))
        .route("/v1/cosign", post(cosign))
        .route("/v1/enroll", post(enroll::start))
        .route("/v1/enroll/{id}", get(enroll::status))
        .route("/v1/enroll/{id}/key", post(enroll::submit_key))
        .route("/v1/enroll/{id}/event", post(enroll::submit_event))
        .route("/v1/enroll/{id}/sig", post(enroll::submit_sig))
        .route("/enroll/{id}", get(enroll::page))
        .with_state(hub)
}

pub async fn serve(cfg: HubConfig, addr: &str) -> anyhow::Result<()> {
    let hub = Hub::open(cfg)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("kith hub listening on http://{addr} (issuer {}, rp id {}, {} OIDC clients)", hub.cfg.issuer, hub.cfg.rp_id, hub.cfg.clients.len());
    axum::serve(listener, router(hub)).await?;
    Ok(())
}
