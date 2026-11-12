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
//! | `GET, POST /oauth/consent`                | consent page, and its Allow / Deny decision     |
//! | `POST /oauth/register`                    | dynamic client registration (RFC 7591), if enabled |
//! | `GET  /oauth/upstream/{id}/start`, `…/callback` | sign in through Telegram or another upstream OIDC provider (see [`upstream`]) |
//! | `POST /oauth/token`                       | code, refresh and RFC 8693 token exchange; `account_attestation` with the `linked_account` scope, `contact_attestations` with `email` or `phone` |
//! | `GET  /oauth/userinfo`                    | OIDC userinfo                                   |
//! | `GET  /oauth/logout`                      | RP-initiated logout                             |
//! | `GET, POST /whoami`                       | the account page, and its passkey sign-in (see [`account`]) |
//! | `GET  /login`                             | redirects to `/whoami`                          |
//! | `GET/PUT /v1/kel/{did}`                   | fetch / append a key event log                  |
//! | `GET  /v1/did/{did}`                      | DID document                                    |
//! | `GET  /.well-known/webfinger`             | WebFinger for names in a verified domain, `ada@example.com` (see [`namespace`]) |
//! | `PUT, DELETE /v1/namespaces/{domain}/{local}`, `GET /v1/namespaces/{domain}` | the domain's holder gives out, takes back and lists names (bearer) |
//! | `GET  /v1/profile/{did}`                  | what the KEL makes public: events, devices, recovery commitment (no token; see [`profile`]) |
//! | `GET  /v1/whoami`                         | the same, plus your sessions, authenticator and co-signer (bearer) |
//! | `POST /v1/auth/challenge`, `/v1/auth/verify` | API challenge login (signature/passkey/TOTP) |
//! | `POST /v1/totp/enroll`, `/v1/totp/confirm`| TOTP factor (bearer)                            |
//! | `DELETE /v1/totp`                         | forget the authenticator: a current code, or an AAL 2 sign-in |
//! | `POST /v1/cosigner`, `/v1/cosign`         | TOTP-gated co-signer                            |
//! | `POST, GET, DELETE /v1/contacts`, `POST /v1/contacts/confirm`, `PUT /v1/contacts/public` | verified email and phone contacts (bearer; see [`contacts`]) |
//! | `GET  /v1/contacts/lookup`                | who holds a published contact, signed           |
//! | `POST /v1/domains`, `POST /v1/domains/verify` | what to publish, and proving a domain by TXT, CNAME or HTML file (bearer; see [`domains`]) |
//! | `GET  /v1/domains/attest`                 | witness any DID's proof of a domain, signed (no token) |
//! | `POST /v1/enroll`, `GET /enroll/{id}`     | enroll a browser passkey as a device            |
//! | `POST /v1/join`, `/v1/join/invite`, `GET /join/{id}` | join a device, from a terminal or by QR code, approved by manage signers (see [`join`]) |
//! | `/v1/blocks`, `/v1/policy`, `/v1/revocations` | policy DAGs and revocations (see [`org`])   |
//! | `/v1/admin/…`                             | identities, sessions, consent, clients, TOTP resets and the bundle in force, for the operator (see [`admin`]) |
//!
//! State that must outlive a restart is in one SQLite file in the data directory
//! (see [`store`]).

// ApiError carries an HTTP status plus a JSON body; boxing it buys nothing here.
#![allow(clippy::result_large_err)]

pub mod account;
pub mod admin;
pub mod contacts;
pub mod domains;
pub mod enroll;
pub mod join;
pub mod jwe;
pub mod namespace;
pub mod oidc;
pub mod org;
pub mod pages;
pub mod profile;
pub mod qr;
pub mod signup;
pub mod store;
pub mod upstream;
pub mod work;

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Form, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use kith_core::authz::{Bundle, Engine, Memberships};
use kith_core::kel::{extends, verify_log, DeviceKind, Event, KeyState};
use kith_core::keys::{verify_sig, PublicKey, Sig, VerifyOptions};
use kith_core::session::{self, Capability, KelResolver};
use kith_core::token::{verify_access_token, AccessClaims, Actor, HubSigner};
use kith_core::util::{b64u, b64u_decode, now, random_id, sha256};
use kith_core::{totp, webauthn};

pub const TOKEN_TTL: i64 = 900;
pub const TT_SESSION: &str = "urn:kith:params:oauth:token-type:session";
pub const TT_DELEGATION: &str = "urn:kith:params:oauth:token-type:delegation";
/// Wrong TOTP codes before the factor is locked, and for how long.
pub const TOTP_MAX_FAILURES: u32 = 5;
pub const TOTP_LOCKOUT: i64 = 15 * 60;

/// At most `max` attempts per `window_secs`, per client address. `max: 0` turns the
/// limit off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub max: u32,
    pub window_secs: i64,
}

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
    /// Upstream OIDC providers accepted as a login factor (Telegram, …).
    pub upstreams: Vec<upstream::Upstream>,
    /// Turns on `/oauth/register` for callers that present this bearer token.
    pub registration_token: Option<String>,
    /// Take groups and roles from this org's policy DAG (with its revocations
    /// applied) instead of `bundle_path`.
    pub policy_org: Option<String>,
    /// Where heartbeats get their beacon value, and how often they are signed.
    pub beacon: org::BeaconSource,
    pub heartbeat_secs: u64,
    /// Attempts allowed on `/oauth/login` and `/oauth/register`, per client address.
    pub login_limit: RateLimit,
    pub register_limit: RateLimit,
    /// Attempts with a TOTP code (`/v1/auth/verify`, `/v1/cosign`, token exchange),
    /// per client address. The per-identity lockout still applies on top.
    pub totp_limit: RateLimit,
    /// The hub is behind exactly one reverse proxy: the client address is the last
    /// `X-Forwarded-For` entry, which that proxy appended.
    pub behind_proxy: bool,
    /// Turns on the admin API for callers that present this bearer token.
    pub admin_token: Option<String>,
    /// Hub access tokens (`aud` = issuer) whose roles include this one may use the
    /// admin API too. The policy bundle decides who is in the role.
    pub admin_role: Option<String>,
    /// Let anyone create an identity in the browser (`/signup`, spec §7.11). Off by
    /// default: it makes a public hub an open registry.
    pub signup: bool,
    /// Sign-up attempts allowed per client address.
    pub signup_limit: RateLimit,
    /// Join requests a terminal may open per client address (spec §7.13).
    pub join_limit: RateLimit,
    /// Proofs of work submitted per client address (spec §7.12).
    pub work_limit: RateLimit,
    /// Verified email addresses and phone numbers (spec 7.8.2): how codes are sent,
    /// how long a verification lasts, and limits.
    pub contacts: contacts::ContactConfig,
    /// Verified domains (spec 7.8.3): which proofs are accepted, how long they last, and
    /// how DNS and HTTP are asked.
    pub domains: domains::DomainConfig,
}

impl HubConfig {
    /// Sensible local defaults: rp id = issuer host, origins = issuer origin.
    pub fn new(issuer: impl Into<String>, data_dir: impl Into<PathBuf>) -> Self {
        let issuer: String = issuer.into();
        let issuer = issuer.trim_end_matches('/').to_string();
        let rp_id = host_of(&issuer).unwrap_or_else(|| "localhost".into());
        HubConfig {
            origins: vec![issuer.clone()],
            issuer,
            data_dir: data_dir.into(),
            bundle_path: None,
            rp_id,
            clients: vec![],
            upstreams: vec![],
            registration_token: None,
            policy_org: None,
            beacon: org::BeaconSource::None,
            heartbeat_secs: 15,
            login_limit: RateLimit {
                max: 20,
                window_secs: 60,
            },
            register_limit: RateLimit {
                max: 20,
                window_secs: 3600,
            },
            totp_limit: RateLimit {
                max: 20,
                window_secs: 60,
            },
            behind_proxy: false,
            admin_token: None,
            admin_role: Some("hub-admin".into()),
            signup: false,
            signup_limit: RateLimit {
                max: 5,
                window_secs: 3600,
            },
            join_limit: RateLimit {
                max: 20,
                window_secs: 3600,
            },
            work_limit: RateLimit {
                max: 120,
                window_secs: 60,
            },
            contacts: contacts::ContactConfig::default(),
            domains: domains::DomainConfig::default(),
        }
    }
}

pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let hostport = rest.split(['/', '?', '#']).next()?;
    let host = hostport
        .rsplit_once(':')
        .map(|(h, p)| {
            if p.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                hostport
            }
        })
        .unwrap_or(hostport);
    Some(host.trim_matches(['[', ']']).to_string())
}

pub(crate) struct Challenge {
    /// Bound identity (API login). OIDC passkey login learns it from the passkey.
    pub did: Option<String>,
    pub message: String,
    pub expires: i64,
}

/// The result of a successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authn {
    pub st: KeyState,
    pub dev: Option<String>,
    pub aal: u8,
    pub amr: Vec<String>,
    pub auth_time: i64,
    /// The linked alias a federated login came through; the session ends when it
    /// is unlinked.
    pub alias: Option<String>,
    /// Attributes an upstream provider asserted in this login, already filtered by
    /// that provider's `attributes` allowlist. The directory overrides them.
    pub attrs: Map<String, Value>,
}

/// The policy engine in force, and what became of the last attempt to load the file.
struct EngineSlot {
    /// Modification time and length of the file last read, whether or not it loaded.
    seen: Option<(std::time::SystemTime, u64)>,
    engine: Arc<Engine>,
    /// When `engine` was loaded; 0 for the empty bundle a hub without a file uses.
    loaded_at: i64,
    /// Why the file as it is now is not the one in force.
    error: Option<String>,
}

pub struct Hub {
    pub cfg: HubConfig,
    pub signer: HubSigner,
    pub(crate) rsa: oidc::RsaSigner,
    pub(crate) pairwise_secret: Vec<u8>,
    kels: RwLock<HashMap<String, Vec<Event>>>,
    engine: RwLock<EngineSlot>,
    /// Login challenges live five minutes; a page whose challenge was lost to a
    /// restart is handed a fresh one and retries.
    pub(crate) challenges: Mutex<HashMap<String, Challenge>>,
    /// Everything that must survive a restart.
    pub store: store::Store,
    pub(crate) enrollments: Mutex<HashMap<String, enroll::Enrollment>>,
    pub(crate) signups: Mutex<HashMap<String, signup::Attempt>>,
    pub(crate) joins: Mutex<HashMap<String, join::Join>>,
    pub(crate) upstream: Mutex<upstream::UpstreamState>,
    pub(crate) http: reqwest::Client,
    pub orgs: org::Orgs,
    pub started: i64,
    #[cfg(feature = "aws")]
    pub(crate) aws: contacts::aws::Clients,
}

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String, pub String, pub Option<Value>);

impl ApiError {
    pub fn bad(code: &str, msg: impl ToString) -> Self {
        ApiError(StatusCode::BAD_REQUEST, code.into(), msg.to_string(), None)
    }
    pub fn unauthorized(msg: impl ToString) -> Self {
        ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid_token".into(),
            msg.to_string(),
            None,
        )
    }
    pub fn grant(msg: impl ToString) -> Self {
        ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_grant".into(),
            msg.to_string(),
            None,
        )
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
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error".into(),
            e.to_string(),
            None,
        )
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
        r.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        r
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub(crate) fn read_json(path: &std::path::Path) -> Option<Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
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
    Signature {
        sig: Sig,
    },
    /// A passkey answers `navigator.credentials.get({challenge: SHA-256(message)})`.
    /// `device_id` may be omitted; every passkey device of the identity is tried.
    Webauthn {
        #[serde(default)]
        device_id: Option<String>,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
    Totp {
        code: String,
    },
    /// An upstream provider vouched for the account behind `alias`. Only the hub's
    /// own callback creates this; it cannot be submitted.
    #[serde(skip)]
    Federated {
        provider: String,
        alias: String,
    },
}

impl Authn {
    /// Nothing but an authenticator code vouches for this sign-in: no device that could
    /// be revoked and no linked account that could be unlinked.
    pub(crate) fn rests_on_totp_alone(&self) -> bool {
        self.dev.is_none() && self.alias.is_none() && self.amr == ["otp"]
    }
}

impl Hub {
    /// A sign-in that rests on the authenticator alone ends when it is reset, so that
    /// resetting it is a way to cut off whoever enrolled it. Anything else is unaffected.
    pub(crate) fn totp_session_alive(&self, a: &Authn) -> bool {
        if !a.rests_on_totp_alone() {
            return true;
        }
        match self.store.totp_reset_at(&a.st.did) {
            Ok(Some(reset)) => a.auth_time > reset,
            Ok(None) => true,
            Err(_) => false,
        }
    }

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
        let store = store::Store::open(&cfg.data_dir.join(store::FILE))?;
        store.import_json_files(&cfg.data_dir)?;
        store.sweep(now())?;
        for c in &cfg.clients {
            c.validate()?;
        }
        for (i, u) in cfg.upstreams.iter().enumerate() {
            u.validate()?;
            if cfg.upstreams[..i].iter().any(|o| o.id == u.id) {
                anyhow::bail!("duplicate upstream id {}", u.id);
            }
        }
        cfg.contacts.validate()?;
        cfg.domains.validate()?;
        let cfg_dir = cfg.data_dir.clone();
        let hub = Hub {
            cfg,
            signer,
            rsa,
            pairwise_secret,
            kels: RwLock::new(kels),
            engine: RwLock::new(EngineSlot {
                seen: None,
                engine: Arc::new(Engine::new(Bundle {
                    version: 1,
                    ..Default::default()
                })?),
                loaded_at: 0,
                error: None,
            }),
            challenges: Mutex::new(HashMap::new()),
            store,
            enrollments: Mutex::new(HashMap::new()),
            signups: Mutex::new(HashMap::new()),
            joins: Mutex::new(HashMap::new()),
            upstream: Mutex::new(upstream::UpstreamState::default()),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
            orgs: org::Orgs::open(&cfg_dir)?,
            started: now(),
            #[cfg(feature = "aws")]
            aws: Default::default(),
        };
        hub.load_bundle(true)?;
        Ok(Arc::new(hub))
    }

    /// The policy engine, reloaded whenever the bundle file changes. A file that
    /// fails to load (half written, invalid, gone) leaves the last good one in force,
    /// and [`Hub::bundle_status`] says why.
    pub fn engine(&self) -> anyhow::Result<Arc<Engine>> {
        self.load_bundle(false)
    }

    /// Load the bundle file if it changed since it was last read. `strict` is for
    /// startup, when there is no good bundle to keep.
    fn load_bundle(&self, strict: bool) -> anyhow::Result<Arc<Engine>> {
        let Some(path) = &self.cfg.bundle_path else {
            return Ok(self.engine.read().unwrap().engine.clone());
        };
        let seen = std::fs::metadata(path).and_then(|m| Ok((m.modified()?, m.len())));
        let key = seen.as_ref().ok().copied();
        {
            let slot = self.engine.read().unwrap();
            if key.is_some() && slot.seen == key {
                return Ok(slot.engine.clone());
            }
        }
        let loaded = seen
            .map_err(anyhow::Error::from)
            .and_then(|_| Ok(Engine::from_json(&std::fs::read_to_string(path)?)?));
        let mut slot = self.engine.write().unwrap();
        match loaded {
            Ok(engine) => {
                *slot = EngineSlot {
                    seen: key,
                    engine: Arc::new(engine),
                    loaded_at: now(),
                    error: None,
                };
            }
            Err(e) if strict => {
                return Err(e.context(format!("policy bundle {}", path.display())))
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if slot.error.as_deref() != Some(msg.as_str()) {
                    eprintln!(
                        "policy bundle {}: {msg}; still using the one loaded at {}",
                        path.display(),
                        slot.loaded_at
                    );
                }
                slot.seen = key;
                slot.error = Some(msg);
            }
        }
        Ok(slot.engine.clone())
    }

    /// Which bundle is in force, for `/v1/admin/stats`.
    pub fn bundle_status(&self) -> Value {
        let _ = self.engine();
        let slot = self.engine.read().unwrap();
        json!({
            "path": self.cfg.bundle_path,
            "loaded_at": slot.loaded_at,
            "error": slot.error,
            "groups": slot.engine.bundle.groups.len(),
            "roles": slot.engine.bundle.roles.len(),
        })
    }

    /// Verification keys: EdDSA (access tokens) and RS256 (ID tokens).
    pub fn jwks(&self) -> Value {
        let mut keys = self.signer.jwks();
        keys["keys"]
            .as_array_mut()
            .expect("keys")
            .push(self.rsa.jwk());
        keys
    }

    pub fn put_kel(&self, did: &str, events: Vec<Event>) -> ApiResult<KeyState> {
        let st = verify_log(&events, &VerifyOptions::default())?;
        if st.did != did {
            return Err(ApiError::bad(
                "invalid_request",
                "log does not belong to this DID",
            ));
        }
        let mut kels = self.kels.write().unwrap();
        if let Some(old) = kels.get(did) {
            if !extends(old, &events)? {
                // Duplicity: two different histories signed by the same identity.
                return Err(ApiError(
                    StatusCode::CONFLICT,
                    "duplicity".into(),
                    "log forks from the stored history".into(),
                    None,
                ));
            }
        }
        let file = self
            .cfg
            .data_dir
            .join("kels")
            .join(format!("{}.json", did.replace(':', "_")));
        write_json(
            &file,
            &serde_json::to_value(&events).map_err(kith_core::Error::from)?,
        )?;
        kels.insert(did.into(), events);
        Ok(st)
    }

    pub fn get_kel(&self, did: &str) -> Option<Vec<Event>> {
        self.kels.read().unwrap().get(did).cloned()
    }

    pub fn kel_dids(&self) -> Vec<String> {
        self.kels.read().unwrap().keys().cloned().collect()
    }

    fn check_jti(&self, jti: &str, exp: i64) -> ApiResult<()> {
        if !self.store.first_use(jti, exp + session::LEEWAY, now())? {
            return Err(ApiError::unauthorized("token replayed"));
        }
        Ok(())
    }

    /// Check a TOTP code for `did`, with replay protection and a failure lockout:
    /// after [`TOTP_MAX_FAILURES`] wrong codes the factor is refused for
    /// [`TOTP_LOCKOUT`] seconds. The lockout survives a restart.
    fn check_totp(&self, did: &str, code: &str, require_confirmed: bool) -> ApiResult<()> {
        enum Verdict {
            Accepted,
            Unconfirmed,
            Locked(i64),
            Used,
            Wrong,
        }
        let t = now();
        // One read-modify-write: parallel attempts can't share a failure count or a step.
        let verdict = self
            .store
            .update_totp(did, |rec| {
                if require_confirmed && !rec.confirmed {
                    return Verdict::Unconfirmed;
                }
                if rec.locked_until > t {
                    return Verdict::Locked(rec.locked_until - t);
                }
                match totp::verify(&rec.secret, code, t, 1) {
                    Some(step) if step > rec.last_step => {
                        rec.last_step = step;
                        rec.failures = 0;
                        rec.confirmed = true;
                        Verdict::Accepted
                    }
                    Some(_) => Verdict::Used,
                    None => {
                        rec.failures += 1;
                        if rec.failures >= TOTP_MAX_FAILURES {
                            rec.failures = 0;
                            rec.locked_until = t + TOTP_LOCKOUT;
                        }
                        Verdict::Wrong
                    }
                }
            })?
            .ok_or_else(|| ApiError::unauthorized("no TOTP enrolled"))?;
        match verdict {
            Verdict::Accepted => Ok(()),
            Verdict::Unconfirmed => Err(ApiError::unauthorized("TOTP not confirmed")),
            Verdict::Locked(retry) => Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "locked".into(),
                "too many TOTP failures".into(),
                Some(json!({"retry_after": retry})),
            )),
            Verdict::Used => Err(ApiError::unauthorized("TOTP code already used")),
            Verdict::Wrong => Err(ApiError::unauthorized("invalid TOTP code")),
        }
    }

    /// Count a TOTP attempt from `ip` against [`HubConfig::totp_limit`]. The identity's
    /// own lockout still applies; this stops one address from trying many identities.
    pub(crate) fn limit_totp(&self, ip: &ClientIp) -> ApiResult<()> {
        match self
            .store
            .hit(&format!("totp|{}", ip.0), self.cfg.totp_limit, now())?
        {
            None => Ok(()),
            Some(retry) => Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited".into(),
                format!("too many TOTP attempts from your address; try again in {retry}s"),
                Some(json!({"retry_after": retry})),
            )),
        }
    }

    /// Whether the upstream account `alias` may still sign in as `st`: linked in the
    /// identity's own log, or at sign-up with that provider (spec §7.11).
    pub(crate) fn alias_linked(&self, st: &KeyState, alias: &str) -> bool {
        st.aliases.contains(alias)
            || self.store.provider_link(alias).ok().flatten().as_deref() == Some(st.did.as_str())
    }

    /// Count an attempt at `what` from `ip`; `Err` is the `429` to return when it
    /// is one too many.
    pub(crate) fn rate_limit(
        &self,
        what: &str,
        ip: &ClientIp,
        limit: RateLimit,
    ) -> Result<(), Response> {
        match self.store.hit(&format!("{what}|{}", ip.0), limit, now()) {
            Ok(None) => Ok(()),
            Ok(Some(retry)) => {
                let e = ApiError(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited".into(),
                    format!("too many {what} attempts from your address; try again in {retry}s"),
                    Some(json!({"retry_after": retry})),
                );
                let mut r = e.into_response();
                r.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from_str(&retry.to_string()).expect("retry-after"),
                );
                Err(r)
            }
            Err(e) => Err(ApiError::from(e).into_response()),
        }
    }

    pub(crate) fn new_challenge(
        &self,
        did: Option<String>,
        message_for: impl FnOnce(&str, i64, i64) -> String,
    ) -> (String, String, i64) {
        let id = random_id();
        let iat = now();
        let exp = iat + 300;
        let message = message_for(&id, iat, exp);
        let mut ch = self.challenges.lock().unwrap();
        ch.retain(|_, c| c.expires > iat);
        ch.insert(
            id.clone(),
            Challenge {
                did,
                message: message.clone(),
                expires: exp,
            },
        );
        (id, message, exp)
    }

    pub(crate) fn take_challenge(&self, id: &str) -> ApiResult<Challenge> {
        let ch = self
            .challenges
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| ApiError::unauthorized("unknown or used challenge"))?;
        if ch.expires < now() {
            return Err(ApiError::unauthorized("challenge expired"));
        }
        Ok(ch)
    }

    /// Verify authentication `factors` for `did` over a challenge `message`.
    pub fn authenticate(&self, did: &str, message: &str, factors: &[Factor]) -> ApiResult<Authn> {
        let st = self
            .resolve(did)
            .map_err(|e| ApiError::unauthorized(format!("unknown identity: {e}")))?;
        let mut aal = 0u8;
        let mut amr = Vec::<String>::new();
        let mut kinds = BTreeSet::new();
        let mut dev = None;
        let mut alias = None;
        for f in factors {
            match f {
                Factor::Signature { sig } => {
                    if !st.is_authentication_signer(&sig.signer) {
                        return Err(ApiError::unauthorized(
                            "signer is not a device or manage key of this identity",
                        ));
                    }
                    if sig.alg == "WebAuthn" {
                        return Err(ApiError::bad(
                            "invalid_request",
                            "use the webauthn factor for passkeys",
                        ));
                    }
                    verify_sig(sig, message.as_bytes(), &VerifyOptions::default())
                        .map_err(ApiError::unauthorized)?;
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
                Factor::Webauthn {
                    device_id,
                    authenticator_data,
                    client_data_json,
                    signature,
                } => {
                    let data = webauthn::WebAuthnSigData {
                        authenticator_data: authenticator_data.clone(),
                        client_data_json: client_data_json.clone(),
                    };
                    let sig = b64u_decode(signature)?;
                    let challenge = sha256(message.as_bytes()).to_vec();
                    let candidates: Vec<_> = st
                        .devices
                        .values()
                        .filter(|d| {
                            d.kind == DeviceKind::Passkey
                                && d.has_cap("session")
                                && device_id.as_ref().is_none_or(|id| &d.id == id)
                        })
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
                    aal = aal.max(if info.user_verified {
                        d.aal
                    } else {
                        d.aal.min(1)
                    });
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
                Factor::Federated { alias: linked, .. } => {
                    if !self.alias_linked(&st, linked) {
                        return Err(ApiError::unauthorized(
                            "that account is not linked to this identity",
                        ));
                    }
                    // The hub can't see how the provider authenticated the user.
                    aal = aal.max(1);
                    amr.push("fed".into());
                    alias = Some(linked.clone());
                    kinds.insert("federated");
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
        Ok(Authn {
            st,
            dev,
            aal,
            amr,
            auth_time: now(),
            alias,
            attrs: Map::new(),
        })
    }

    /// Groups, roles and merged attributes for `did`: from the org's policy DAG when
    /// the hub follows one, otherwise from the bundle file.
    pub(crate) fn memberships_for(
        &self,
        did: &str,
        dev: Option<&str>,
        kel_attrs: &Map<String, Value>,
    ) -> ApiResult<(Memberships, Map<String, Value>)> {
        Ok(match self.org_memberships(did, dev, kel_attrs)? {
            Some(found) => (found.memberships, found.attrs),
            None => {
                let engine = self.engine()?;
                let attrs = engine.attributes(did, kel_attrs);
                (engine.memberships(did, &attrs)?, attrs)
            }
        })
    }

    /// Access token claims for an authenticated principal.
    pub fn access_claims(
        &self,
        a: &Authn,
        audience: &str,
        delegation: Option<(String, Vec<Capability>)>,
    ) -> ApiResult<AccessClaims> {
        let mut kel_attrs = Map::new();
        kel_attrs.insert("aliases".into(), json!(a.st.aliases));
        kel_attrs.insert("aal".into(), json!(a.aal));
        // Compute spent on this account (spec §7.12); 0 for one that has spent none.
        kel_attrs.insert(
            "work".into(),
            json!(self.store.work_for(&a.st.did)?.map_or(0, |(bits, _)| bits)),
        );
        // Memberships from an org carry its name and the root they came from (spec §10.8).
        // Memberships from the bundle file carry nothing: they have no provenance.
        let resolve = |kel_attrs: &Map<String, Value>| -> ApiResult<_> {
            Ok(match self.org_memberships(&a.st.did, a.dev.as_deref(), kel_attrs)? {
                Some(found) => (found.memberships, found.attrs, Some((found.org, found.pol))),
                None => {
                    let engine = self.engine()?;
                    let attrs = engine.attributes(&a.st.did, kel_attrs);
                    (engine.memberships(&a.st.did, &attrs)?, attrs, None)
                }
            })
        };
        let (mut m, mut attrs, mut provenance) = resolve(&kel_attrs)?;
        // Upstream attributes only fill gaps: they never replace what the directory
        // or the KEL says. Group rules see them, so memberships are worked out again.
        let extra: Vec<_> = a
            .attrs
            .iter()
            .filter(|(k, _)| !attrs.contains_key(*k))
            .collect();
        if !extra.is_empty() {
            kel_attrs.extend(extra.into_iter().map(|(k, v)| (k.clone(), v.clone())));
            (m, attrs, provenance) = resolve(&kel_attrs)?;
        }
        let iat = now();
        let (act, cap) = match delegation {
            Some((actor, caps)) => (
                Some(Actor {
                    sub: actor,
                    act: None,
                }),
                Some(caps),
            ),
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
            org: provenance.as_ref().map(|(org, _)| org.clone()),
            pol: provenance.map(|(_, pol)| pol),
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
    pub fn issue(
        &self,
        a: &Authn,
        audience: &str,
        delegation: Option<(String, Vec<Capability>)>,
    ) -> ApiResult<Value> {
        self.token_response(&self.access_claims(a, audience, delegation)?)
    }

    pub(crate) fn bearer_any(&self, headers: &HeaderMap) -> ApiResult<AccessClaims> {
        let h = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let tok = h
            .strip_prefix("Bearer ")
            .or_else(|| h.strip_prefix("bearer "))
            .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
        let t = kith_core::jws::decode(tok).map_err(ApiError::unauthorized)?;
        let aud = t.claims["aud"].as_str().unwrap_or_default().to_string();
        verify_access_token(tok, &self.signer.jwks(), &self.cfg.issuer, &aud, now())
            .map_err(ApiError::unauthorized)
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
        let events = self
            .get_kel(did)
            .ok_or_else(|| kith_core::Error::NotFound(format!("no KEL for {did}")))?;
        verify_log(&events, &VerifyOptions::default())
    }
}

/// The address a request came from, for rate limits: the peer, or behind a trusted
/// proxy ([`HubConfig::behind_proxy`]) the entry that proxy appended to
/// `X-Forwarded-For`. Earlier entries are whatever the client claimed.
pub struct ClientIp(pub String);

impl FromRequestParts<Arc<Hub>> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, h: &Arc<Hub>) -> Result<Self, Self::Rejection> {
        if h.cfg.behind_proxy {
            let forwarded = parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .map(str::trim)
                .rfind(|s| !s.is_empty());
            if let Some(ip) = forwarded {
                return Ok(ClientIp(ip.to_string()));
            }
        }
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string());
        Ok(ClientIp(peer.unwrap_or_else(|| "local".into())))
    }
}

// ---------------------------------------------------------------- handlers

async fn jwks(State(h): State<Arc<Hub>>) -> Json<Value> {
    Json(h.jwks())
}

async fn get_kel(State(h): State<Arc<Hub>>, Path(did): Path<String>) -> ApiResult<Json<Value>> {
    let events = h
        .get_kel(&did)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), did.clone(), None))?;
    Ok(Json(json!(events)))
}

async fn put_kel(
    State(h): State<Arc<Hub>>,
    Path(did): Path<String>,
    Json(events): Json<Vec<Event>>,
) -> ApiResult<Json<Value>> {
    let st = h.put_kel(&did, events)?;
    Ok(Json(
        json!({"did": st.did, "seq": st.seq, "digest": st.digest}),
    ))
}

async fn did_doc(State(h): State<Arc<Hub>>, Path(did): Path<String>) -> ApiResult<Json<Value>> {
    let st = h.resolve(&did).map_err(|e| {
        ApiError(
            StatusCode::NOT_FOUND,
            "not_found".into(),
            e.to_string(),
            None,
        )
    })?;
    Ok(Json(st.did_document(Some(&h.cfg.issuer))))
}

#[derive(Deserialize)]
struct ChallengeReq {
    did: String,
}

async fn challenge(
    State(h): State<Arc<Hub>>,
    Json(req): Json<ChallengeReq>,
) -> ApiResult<Json<Value>> {
    h.resolve(&req.did)
        .map_err(|e| ApiError::bad("unknown_identity", e))?;
    let (rp, iss, did) = (h.cfg.rp_id.clone(), h.cfg.issuer.clone(), req.did.clone());
    // CAIP-122 / SIWE-shaped so wallets render it sensibly.
    let (id, message, exp) = h.new_challenge(Some(req.did.clone()), |id, iat, exp| {
        session::login_challenge(&rp, &did, &iss, id, iat, exp)
    });
    Ok(Json(
        json!({"challenge_id": id, "message": message, "expires_at": exp}),
    ))
}

#[derive(Deserialize)]
struct VerifyReq {
    challenge_id: String,
    audience: String,
    factors: Vec<Factor>,
}

async fn verify(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    Json(req): Json<VerifyReq>,
) -> ApiResult<Json<Value>> {
    if req.factors.iter().any(|f| matches!(f, Factor::Totp { .. })) {
        h.limit_totp(&ip)?;
    }
    let ch = h.take_challenge(&req.challenge_id)?;
    let did = ch
        .did
        .ok_or_else(|| ApiError::bad("invalid_request", "challenge is not bound to an identity"))?;
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

async fn token(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    headers: HeaderMap,
    Form(req): Form<TokenReq>,
) -> ApiResult<Response> {
    if req.totp.is_some() {
        h.limit_totp(&ip)?;
    }
    let body = match req.grant_type.as_str() {
        "urn:ietf:params:oauth:grant-type:token-exchange" => token_exchange(&h, &req)?,
        "authorization_code" => oidc::code_grant(&h, &headers, &req)?,
        "refresh_token" => oidc::refresh_grant(&h, &headers, &req)?,
        other => return Err(ApiError::bad("unsupported_grant_type", other)),
    };
    let mut r = Json(body).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(r)
}

fn token_exchange(h: &Hub, req: &TokenReq) -> ApiResult<Value> {
    let audience = req.audience.clone().unwrap_or_else(|| h.cfg.issuer.clone());
    let subject = req
        .subject_token
        .as_deref()
        .ok_or_else(|| ApiError::bad("invalid_request", "subject_token required"))?;
    let t = now();
    match req.subject_token_type.as_deref().unwrap_or_default() {
        TT_SESSION => {
            let v = session::verify_session_token(subject, &h.cfg.issuer, h, t)
                .map_err(ApiError::unauthorized)?;
            h.check_jti(
                v.claims["jti"].as_str().unwrap_or_default(),
                v.claims["exp"].as_i64().unwrap_or(t),
            )?;
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
                alias: None,
                attrs: Map::new(),
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
            let (chain, d) = session::verify_delegation(subject, &h.cfg.issuer, h, t).map_err(ApiError::unauthorized)?;
            if d.sub != actor.did {
                return Err(ApiError::unauthorized(
                    "delegation was issued to someone else",
                ));
            }
            // The org's revocations bind the actor as well as the principal (spec §8.7).
            h.check_org_revocations(&actor.did, Some(&actor.device.id))?;
            let st = h.resolve(&d.iss)?;
            // The delegate's assurance, not the delegator's, describes this session. `dev`
            // is the delegator's device that signed the grant, so a `device` revocation
            // stops its delegations here and at followers, as it stops its sign-ins.
            let a = Authn { st, dev: Some(chain.device.id.clone()), aal: actor.aal, amr: vec!["delegated".into()], auth_time: t, alias: None, attrs: Map::new() };
            h.issue(&a, &audience, Some((actor.did.clone(), d.cap.clone())))
        }
        other => Err(ApiError::bad(
            "invalid_request",
            format!("unsupported subject_token_type {other}"),
        )),
    }
}

async fn totp_enroll(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    if h.store.totp(&c.sub)?.is_some_and(|r| r.confirmed) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "exists".into(),
            "TOTP already enrolled".into(),
            None,
        ));
    }
    let secret = totp::generate_secret();
    let uri = totp::otpauth_uri(&secret, &h.cfg.rp_id, &c.sub);
    let b32 = totp::to_base32(&secret);
    h.store.put_totp(
        &c.sub,
        &store::TotpRecord {
            secret,
            confirmed: false,
            last_step: 0,
            failures: 0,
            locked_until: 0,
        },
    )?;
    Ok(Json(json!({"secret": b32, "otpauth_uri": uri})))
}

#[derive(Deserialize)]
struct CodeReq {
    code: String,
}

async fn totp_confirm(
    State(h): State<Arc<Hub>>,
    headers: HeaderMap,
    Json(req): Json<CodeReq>,
) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    h.check_totp(&c.sub, &req.code, false)?;
    Ok(Json(json!({"confirmed": true})))
}

#[derive(Deserialize, Default)]
struct ResetReq {
    #[serde(default)]
    code: Option<String>,
}

/// `DELETE /v1/totp`: forget the caller's authenticator so a new one can be enrolled.
/// The caller shows the current code, or has signed in strongly (AAL 2). Otherwise a
/// weak session, a stolen laptop's say, could swap in its own authenticator and with
/// it the TOTP gate on the co-signer. Sign-ins that rested on the authenticator alone
/// end with it. An operator without either uses `DELETE /v1/admin/identities/{did}/totp`.
async fn totp_reset(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    headers: HeaderMap,
    body: Option<Json<ResetReq>>,
) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    match body.and_then(|Json(b)| b.code) {
        Some(code) => {
            h.limit_totp(&ip)?;
            h.check_totp(&c.sub, &code, true)?;
        }
        None if c.aal >= 2 => {}
        None => {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "forbidden".into(),
                "resetting the authenticator needs a current code or an AAL 2 sign-in".into(),
                None,
            ))
        }
    }
    Ok(Json(json!({"reset": h.store.delete_totp(&c.sub, now())?})))
}

/// Returns (creating on first call) the hub-held co-signer key for the caller.
/// Put its id in your manage or rotation policy – e.g. `2 of [passkey, ledger,
/// cosigner]` – and TOTP becomes a real signer in your multisig.
async fn cosigner(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let s = h.store.cosigner_or_create(&c.sub)?;
    Ok(Json(json!({"signer": s.id, "gated_by": "totp"})))
}

#[derive(Deserialize)]
struct CosignReq {
    did: String,
    code: String,
    event: Event,
}

async fn cosign(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    Json(req): Json<CosignReq>,
) -> ApiResult<Json<Value>> {
    h.limit_totp(&ip)?;
    let st = h.resolve(&req.did)?;
    if req.event.did.as_deref() != Some(st.did.as_str())
        || req.event.seq != st.seq + 1
        || req.event.prev.as_deref() != Some(st.digest.as_str())
    {
        return Err(ApiError::bad(
            "invalid_request",
            "event must be the next event of this identity's KEL",
        ));
    }
    let signer = h
        .store
        .cosigner(&st.did)?
        .ok_or_else(|| ApiError::bad("invalid_request", "no co-signer for this identity"))?;
    h.check_totp(&st.did, &req.code, true)?;
    let sig = signer.sign(&req.event.signing_message()?)?;
    Ok(Json(json!(sig)))
}

/// The bare hostname: sign-up when this hub takes it, otherwise a plain note.
async fn home(State(h): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    if account::current(&h, &headers).is_some() {
        axum::response::Redirect::to("/whoami").into_response()
    } else if h.cfg.signup {
        axum::response::Redirect::to("/signup").into_response()
    } else {
        pages::message(
            StatusCode::OK,
            "Kith hub",
            "This is an identity service. Apps send people here to sign in.",
        )
    }
}

pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oidc::discovery),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/authorize", get(oidc::authorize))
        .route("/oauth/login", post(oidc::login))
        .route(
            "/oauth/consent",
            get(oidc::consent_page).post(oidc::consent),
        )
        .route("/oauth/register", post(oidc::register))
        .route("/oauth/upstream/{id}/start", get(upstream::start))
        .route("/oauth/upstream/{id}/callback", get(upstream::callback))
        .route("/oauth/token", post(token))
        .route("/oauth/userinfo", get(oidc::userinfo).post(oidc::userinfo))
        .route("/oauth/logout", get(oidc::logout))
        .route("/v1/oauth/token", post(token))
        .route("/v1/kel/{did}", get(get_kel).put(put_kel))
        .route("/v1/did/{did}", get(did_doc))
        .route("/.well-known/webfinger", get(namespace::webfinger))
        .route("/v1/namespaces/{domain}", get(namespace::list))
        .route("/v1/namespaces/{domain}/{local}", axum::routing::put(namespace::give).delete(namespace::remove))
        .route("/v1/profile/{did}", get(profile::profile))
        .route("/v1/whoami", get(profile::whoami))
        .route("/v1/auth/challenge", post(challenge))
        .route("/v1/auth/verify", post(verify))
        .route("/v1/totp/enroll", post(totp_enroll))
        .route("/v1/totp/confirm", post(totp_confirm))
        .route("/v1/totp", delete(totp_reset))
        .route("/v1/cosigner", post(cosigner))
        .route("/v1/cosign", post(cosign))
        .route(
            "/v1/contacts",
            post(contacts::request_code)
                .get(contacts::list)
                .delete(contacts::remove),
        )
        .route("/v1/contacts/confirm", post(contacts::confirm))
        .route(
            "/v1/contacts/public",
            axum::routing::put(contacts::set_public),
        )
        .route("/v1/contacts/lookup", get(contacts::lookup))
        .route("/v1/domains", post(domains::records))
        .route("/v1/domains/verify", post(domains::verify))
        .route("/v1/domains/attest", get(domains::attest))
        .route("/v1/enroll", post(enroll::start))
        .route("/v1/enroll/{id}", get(enroll::status))
        .route("/v1/enroll/{id}/key", post(enroll::submit_key))
        .route("/v1/enroll/{id}/event", post(enroll::submit_event))
        .route("/v1/enroll/{id}/sig", post(enroll::submit_sig))
        .route("/enroll/{id}", get(enroll::page))
        .route("/v1/join", post(join::start))
        .route("/v1/join/invite", post(join::invite))
        .route("/v1/join/{id}", get(join::status))
        .route("/v1/join/{id}/claim", post(join::claim))
        .route("/v1/join/{id}/device", post(join::submit_device))
        .route("/v1/join/{id}/approve", post(join::approve))
        .route("/v1/join/{id}/pop", post(join::pop))
        .route("/join/{id}", get(join::page))
        .route("/join/{id}/qr.svg", get(join::qr_svg))
        .route("/", get(home))
        .route("/whoami", get(account::page).post(account::login))
        .route(
            "/login",
            get(|| async { axum::response::Redirect::to("/whoami") }),
        )
        .route("/signup", get(signup::page))
        .route("/v1/signup", post(signup::begin))
        .route("/v1/signup/check", post(signup::check))
        .route("/v1/work", post(work::submit))
        .route("/v1/work/{did}", get(work::get))
        .route("/v1/signup/{id}/key", post(signup::submit_key))
        .route("/v1/signup/{id}/sig", post(signup::submit_sig))
        .route("/v1/hub", get(org::info))
        .route("/v1/hub/revoker", post(org::sign_revoker))
        .route("/v1/blocks", axum::routing::put(org::put_blocks))
        .route("/v1/blocks/{cid}", get(org::get_block))
        .route("/ipfs/{cid}", get(org::get_block))
        .route("/v1/policy/{org}", get(org::policy))
        .route("/v1/policy/{org}/slice", post(org::slice))
        .route(
            "/v1/revocations/{org}",
            get(org::get_revocations).post(org::post_revocation),
        )
        .route("/v1/revocations/{org}/heartbeat", get(org::get_heartbeat))
        .route("/v1/revocations/{org}/events", get(org::events))
        .route("/v1/admin/stats", get(admin::stats))
        .route("/v1/admin/sessions", get(admin::sessions))
        .route("/v1/admin/sessions/{sid}", delete(admin::end_session))
        .route("/v1/admin/identities", get(admin::identities))
        .route(
            "/v1/admin/identities/{did}/sessions",
            delete(admin::end_sessions_of),
        )
        .route("/v1/admin/identities/{did}/totp", delete(admin::reset_totp))
        .route("/v1/admin/clients", get(admin::clients))
        .route("/v1/admin/clients/{id}", delete(admin::delete_client))
        .route("/v1/admin/grants/{did}", get(admin::grants))
        .route(
            "/v1/admin/grants/{did}/{client_id}",
            delete(admin::revoke_grant),
        )
        .with_state(hub)
}

pub async fn serve(cfg: HubConfig, addr: &str) -> anyhow::Result<()> {
    let hub = Hub::open(cfg)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tokio::spawn(org::heartbeat_loop(hub.clone()));
    tokio::spawn({
        let hub = hub.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                if let Err(e) = hub.store.sweep(now()) {
                    eprintln!("store sweep failed: {e}");
                }
            }
        }
    });
    eprintln!(
        "kith hub listening on http://{addr} (issuer {}, rp id {}, {} OIDC clients, {} upstream providers, state in {})",
        hub.cfg.issuer,
        hub.cfg.rp_id,
        hub.cfg.clients.len(),
        hub.cfg.upstreams.len(),
        hub.cfg.data_dir.join(store::FILE).display()
    );
    axum::serve(
        listener,
        router(hub).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    fn hub() -> Arc<Hub> {
        let dir = std::env::temp_dir().join(format!("kith-hub-unit-{}", random_id()));
        Hub::open(HubConfig::new("http://localhost:7777", dir)).unwrap()
    }

    fn enrolled(h: &Hub, did: &str) -> Vec<u8> {
        let secret = totp::generate_secret();
        h.store
            .put_totp(
                did,
                &store::TotpRecord {
                    secret: secret.clone(),
                    confirmed: true,
                    last_step: 0,
                    failures: 0,
                    locked_until: 0,
                },
            )
            .unwrap();
        secret
    }

    /// Run `f(i)` on `n` threads released at the same moment.
    fn together<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
        let gate = Barrier::new(n);
        std::thread::scope(|s| {
            let threads: Vec<_> = (0..n)
                .map(|i| {
                    let (gate, f) = (&gate, &f);
                    s.spawn(move || {
                        gate.wait();
                        f(i)
                    })
                })
                .collect();
            threads.into_iter().map(|t| t.join().unwrap()).collect()
        })
    }

    #[test]
    fn a_totp_code_works_once_even_when_presented_together() {
        let h = hub();
        for round in 0..300 {
            let did = format!("did:kith:race{round}");
            let code = totp::code_at(&enrolled(&h, &did), now());
            let accepted = together(4, |_| h.check_totp(&did, &code, true).is_ok())
                .into_iter()
                .filter(|ok| *ok)
                .count();
            assert_eq!(
                accepted, 1,
                "round {round}: one code, accepted {accepted} times"
            );
        }
    }

    #[test]
    fn wrong_totp_codes_presented_together_are_all_counted() {
        let h = hub();
        for round in 0..300 {
            let did = format!("did:kith:count{round}");
            let secret = enrolled(&h, &did);
            let valid: Vec<String> = [-30, 0, 30]
                .iter()
                .map(|d| totp::code_at(&secret, now() + d))
                .collect();
            let wrong = ["000000", "000001"]
                .iter()
                .find(|c| !valid.iter().any(|v| v == *c))
                .unwrap()
                .to_string();
            together(4, |_| h.check_totp(&did, &wrong, true).is_err());
            let failures = h.store.totp(&did).unwrap().unwrap().failures;
            assert_eq!(
                failures, 4,
                "round {round}: four wrong codes, {failures} counted"
            );
        }
    }
}
