//! Enroll a browser passkey as a device of your identity.
//!
//! The browser can create a passkey but can't sign KEL events with your manage key;
//! the CLI holds the manage key but can't create a passkey for the hub's origin. The
//! hub brokers the two halves:
//!
//! ```text
//! CLI:     POST /v1/enroll (bearer)                    → {id, url}; opens url
//! Browser: GET  /enroll/{id}; navigator.credentials.create(user.id = DID)
//!          POST /v1/enroll/{id}/key {key, credential_id}
//! CLI:     polls; builds add_device, signs with manage key
//!          POST /v1/enroll/{id}/event {device_id, message} (bearer)
//! Browser: polls; navigator.credentials.get(challenge = SHA-256(message))
//!          POST /v1/enroll/{id}/sig {sig}              (hub verifies it)
//! CLI:     polls; appends the proof-of-possession sig, publishes the KEL
//! ```
//!
//! The enrollment id is a 128-bit capability and expires after 10 minutes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::keys::{verify_sig, KeyType, PublicKey, Sig, VerifyOptions};
use kith_core::util::{now, random_id};

use crate::{pages, ApiError, ApiResult, Hub};

pub const ENROLL_TTL: i64 = 600;

#[derive(Debug, Clone)]
pub struct Enrollment {
    did: String,
    name: String,
    created: i64,
    key: Option<String>,
    credential_id: Option<String>,
    device_id: Option<String>,
    message: Option<String>,
    sig: Option<Sig>,
}

impl Enrollment {
    fn state(&self) -> &'static str {
        match (&self.key, &self.message, &self.sig) {
            (None, _, _) => "waiting_for_passkey",
            (Some(_), None, _) => "waiting_for_approval",
            (Some(_), Some(_), None) => "waiting_for_signature",
            _ => "signed",
        }
    }

    fn json(&self) -> Value {
        json!({
            "state": self.state(), "did": self.did, "name": self.name, "key": self.key,
            "credential_id": self.credential_id, "device_id": self.device_id,
            "message": self.message, "sig": self.sig,
        })
    }
}

fn get(h: &Hub, id: &str) -> ApiResult<Enrollment> {
    let mut m = h.enrollments.lock().unwrap();
    m.retain(|_, e| e.created + ENROLL_TTL > now());
    m.get(id).cloned().ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), "unknown or expired enrollment".into(), None))
}

fn put(h: &Hub, id: &str, e: Enrollment) {
    h.enrollments.lock().unwrap().insert(id.into(), e);
}

#[derive(Deserialize, Default)]
pub struct StartReq {
    #[serde(default)]
    name: Option<String>,
}

pub async fn start(State(h): State<Arc<Hub>>, headers: HeaderMap, body: Option<Json<StartReq>>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let id = random_id();
    let name = body.and_then(|b| b.0.name).unwrap_or_else(|| "passkey".into());
    put(&h, &id, Enrollment { did: c.sub.clone(), name, created: now(), key: None, credential_id: None, device_id: None, message: None, sig: None });
    Ok(Json(json!({"id": id, "url": format!("{}/enroll/{id}", h.cfg.issuer), "rp_id": h.cfg.rp_id, "expires_in": ENROLL_TTL})))
}

pub async fn status(State(h): State<Arc<Hub>>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    Ok(Json(get(&h, &id)?.json()))
}

#[derive(Deserialize)]
pub struct KeyReq {
    key: String,
    credential_id: String,
}

pub async fn submit_key(State(h): State<Arc<Hub>>, Path(id): Path<String>, Json(req): Json<KeyReq>) -> ApiResult<Json<Value>> {
    let mut e = get(&h, &id)?;
    if e.key.is_some() {
        return Err(ApiError(StatusCode::CONFLICT, "exists".into(), "a passkey was already submitted".into(), None));
    }
    if PublicKey::from_did_key(&req.key)?.kty != KeyType::P256 {
        return Err(ApiError::bad("invalid_request", "passkeys must be ES256 (P-256)"));
    }
    e.key = Some(req.key);
    e.credential_id = Some(req.credential_id);
    put(&h, &id, e.clone());
    Ok(Json(e.json()))
}

#[derive(Deserialize)]
pub struct EventReq {
    device_id: String,
    message: String,
}

pub async fn submit_event(State(h): State<Arc<Hub>>, headers: HeaderMap, Path(id): Path<String>, Json(req): Json<EventReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let mut e = get(&h, &id)?;
    if c.sub != e.did {
        return Err(ApiError::unauthorized("enrollment belongs to another identity"));
    }
    if e.key.is_none() || e.message.is_some() {
        return Err(ApiError::bad("invalid_request", "enrollment is not waiting for approval"));
    }
    e.device_id = Some(req.device_id);
    e.message = Some(req.message);
    put(&h, &id, e.clone());
    Ok(Json(e.json()))
}

#[derive(Deserialize)]
pub struct SigReq {
    sig: Sig,
}

pub async fn submit_sig(State(h): State<Arc<Hub>>, Path(id): Path<String>, Json(req): Json<SigReq>) -> ApiResult<Json<Value>> {
    let mut e = get(&h, &id)?;
    let (Some(key), Some(message)) = (&e.key, &e.message) else {
        return Err(ApiError::bad("invalid_request", "nothing to sign yet"));
    };
    if &req.sig.signer != key || req.sig.alg != "WebAuthn" {
        return Err(ApiError::bad("invalid_request", "signature must come from the enrolled passkey"));
    }
    verify_sig(&req.sig, message.as_bytes(), &VerifyOptions::default()).map_err(ApiError::unauthorized)?;
    e.sig = Some(req.sig);
    put(&h, &id, e.clone());
    Ok(Json(e.json()))
}

pub async fn page(State(h): State<Arc<Hub>>, Path(id): Path<String>) -> Response {
    match get(&h, &id) {
        Ok(e) => pages::enroll(json!({"id": id, "did": e.did, "name": e.name, "rp_id": h.cfg.rp_id, "state": e.state()})),
        Err(_) => pages::message(StatusCode::NOT_FOUND, "Link expired", "This enrollment link is unknown or has expired. Run `kith passkey enroll` again."),
    }
}
