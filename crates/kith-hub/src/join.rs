//! Join a device to an identity (spec §7.13).
//!
//! A join request holds one `add_device` event. The identity's manage signers approve
//! it, the new device proves it holds its key, and once both are in the hub appends the
//! event to the log. This is how an identity made in the browser, whose only manage key
//! is a passkey, gains devices. There are two ways in:
//!
//! ```text
//! Terminal: POST /v1/join {device}                 → {id, url}; prints url, QR, fingerprint
//! Browser:  GET  /join/{id}, signed in; POST /v1/join/{id}/claim → {event, message}
//! Terminal: polls; checks the event; POST /v1/join/{id}/pop {sig}
//! Browser:  credentials.get(challenge = SHA-256(message)); POST /v1/join/{id}/approve
//!
//! Account:  POST /v1/join/invite (session)          → {id, url}; shows a QR code
//! Phone:    GET  /join/{id}; credentials.create; POST /v1/join/{id}/device {key}
//!           credentials.get(challenge = SHA-256(message)); POST /v1/join/{id}/pop
//! Account:  polls; credentials.get(…); POST /v1/join/{id}/approve
//! ```
//!
//! The hub builds the event and assembles the signatures; it holds no key. Requests
//! live in memory for 15 minutes.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::kel::{next_event, Device, DeviceKind, Event, EventBody};
use kith_core::keys::{verify_sig, KeyType, PublicKey, Sig, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::util::{b64u_decode, key_fingerprint, now, random_id, sha256};
use kith_core::webauthn::{self, AssertionCheck, WebAuthnSigData};

use kith_core::session::KelResolver;

use crate::{account, pages, qr, ApiError, ApiResult, ClientIp, Hub};

pub const JOIN_TTL: i64 = 900;
/// Requests held in memory at once; a flood past the rate limit can't grow it.
const MAX_PENDING: usize = 1000;

#[derive(Debug, Clone)]
pub struct Join {
    created: i64,
    /// Opened from the account page: the identity is known, the passkey is not yet.
    invite: bool,
    did: Option<String>,
    device: Option<Device>,
    /// The `add_device` event without signatures, once identity and device are known.
    event: Option<Event>,
    /// The manage policy of the log the event was built on.
    manage: Option<SignerPolicy>,
    approvals: Vec<Sig>,
    pop: Option<Sig>,
    done: bool,
    error: Option<String>,
}

impl Join {
    fn new(invite: bool, did: Option<String>, device: Option<Device>) -> Self {
        Join {
            created: now(),
            invite,
            did,
            device,
            event: None,
            manage: None,
            approvals: vec![],
            pop: None,
            done: false,
            error: None,
        }
    }

    fn approvers(&self) -> BTreeSet<String> {
        self.approvals.iter().map(|s| s.signer.clone()).collect()
    }

    fn approved(&self) -> bool {
        self.manage
            .as_ref()
            .is_some_and(|m| m.is_satisfied_by(&self.approvers()))
    }

    fn state(&self) -> &'static str {
        if self.error.is_some() {
            "failed"
        } else if self.done {
            "done"
        } else if self.event.is_some() {
            "waiting_for_approval"
        } else if self.invite {
            "waiting_for_device"
        } else {
            "waiting_for_identity"
        }
    }

    fn message(&self) -> Option<String> {
        let ev = self.event.as_ref()?;
        Some(String::from_utf8_lossy(&ev.signing_message().ok()?).into_owned())
    }

    fn json(&self, h: &Hub, id: &str) -> Value {
        let device = self.device.as_ref().map(|d| {
            let mut v = serde_json::to_value(d).unwrap_or(Value::Null);
            v["fingerprint"] = json!(key_fingerprint(&d.key));
            v
        });
        json!({
            "id": id,
            "url": url(h, id),
            "state": self.state(),
            "did": self.did,
            "device": device,
            "event": self.event,
            "message": self.message(),
            "manage": self.manage,
            "approvals": self.approvals.iter().map(|s| s.signer.as_str()).collect::<Vec<_>>(),
            "approved": self.approved(),
            "pop": self.pop.is_some(),
            "expires_at": self.created + JOIN_TTL,
            "error": self.error,
        })
    }
}

fn url(h: &Hub, id: &str) -> String {
    format!("{}/join/{id}", h.cfg.issuer)
}

fn not_found() -> ApiError {
    ApiError(
        StatusCode::NOT_FOUND,
        "not_found".into(),
        "unknown or expired join request; start again".into(),
        None,
    )
}

fn conflict(msg: &str) -> ApiError {
    ApiError(StatusCode::CONFLICT, "conflict".into(), msg.into(), None)
}

fn insert(h: &Hub, j: Join) -> ApiResult<String> {
    let mut m = h.joins.lock().unwrap();
    m.retain(|_, j| j.created + JOIN_TTL > now());
    if m.len() >= MAX_PENDING {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy".into(),
            "too many devices are joining right now; try again shortly".into(),
            None,
        ));
    }
    let id = random_id();
    m.insert(id.clone(), j);
    Ok(id)
}

/// Read or change one request under the lock, so two approvals can't race.
fn with<T>(h: &Hub, id: &str, f: impl FnOnce(&mut Join) -> ApiResult<T>) -> ApiResult<T> {
    let mut m = h.joins.lock().unwrap();
    m.retain(|_, j| j.created + JOIN_TTL > now());
    f(m.get_mut(id).ok_or_else(not_found)?)
}

fn device_id() -> String {
    format!("dev_{}", &random_id()[..8])
}

/// A device name goes into the public log: short, printable, and not much else.
fn clean_name(name: Option<&str>, default: &str) -> ApiResult<String> {
    let n = name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default);
    if n.chars().count() > 40 || n.chars().any(char::is_control) {
        return Err(ApiError::bad(
            "invalid_request",
            "a device name is at most 40 characters, with no control characters",
        ));
    }
    Ok(n.to_string())
}

/// Build the event on the log as it stands. Fails if the key is already a device.
fn build(h: &Hub, j: &mut Join, did: &str) -> ApiResult<()> {
    let st = h
        .resolve(did)
        .map_err(|e| ApiError::bad("unknown_identity", e))?;
    let device = j.device.clone().expect("a device before the event");
    if st.devices.values().any(|d| d.key == device.key) {
        return Err(ApiError::bad(
            "invalid_request",
            "that key is already a device of this identity",
        ));
    }
    j.did = Some(did.to_string());
    j.manage = Some(st.manage.clone());
    j.event = Some(next_event(&st, EventBody::AddDevice { device }));
    Ok(())
}

/// Append the event once the manage policy has approved it and the device has proved
/// possession. The log is checked again on the way in; if it moved, the request fails.
fn finish(h: &Hub, j: &mut Join) {
    if j.done || j.error.is_some() || j.pop.is_none() || !j.approved() {
        return;
    }
    let (Some(did), Some(mut ev)) = (j.did.clone(), j.event.clone()) else {
        return;
    };
    for s in j.approvals.iter().chain(j.pop.iter()) {
        ev.add_sig(s.clone());
    }
    let mut kel = h.get_kel(&did).unwrap_or_default();
    kel.push(ev);
    match h.put_kel(&did, kel) {
        Ok(_) => j.done = true,
        Err(e) => j.error = Some(e.2),
    }
}

// ------------------------------------------------------------------ opening

#[derive(Deserialize)]
pub struct NewDevice {
    key: String,
    #[serde(default)]
    xkey: Option<String>,
    name: String,
    kind: DeviceKind,
    aal: u8,
}

#[derive(Deserialize)]
pub struct StartReq {
    device: NewDevice,
}

/// A terminal asks to join with a key it already holds. Nobody is named yet: a browser
/// signed in to the hub claims the request for its identity.
pub async fn start(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    Json(req): Json<StartReq>,
) -> Result<Json<Value>, Response> {
    h.rate_limit("join", &ip, h.cfg.join_limit)?;
    let d = req.device;
    let ok = match d.kind {
        DeviceKind::Software => d.aal == 1,
        DeviceKind::Hardware => (1..=3).contains(&d.aal),
        _ => false,
    };
    if !ok {
        return Err(ApiError::bad(
            "invalid_request",
            "a terminal joins as a software device at aal 1, or a hardware device at aal 1 to 3",
        )
        .into_response());
    }
    if PublicKey::from_did_key(&d.key).is_err() {
        return Err(
            ApiError::bad("invalid_request", "the device key must be a did:key").into_response(),
        );
    }
    if let Some(x) = &d.xkey {
        if kith_core::vault::decode_xkey(x).is_err() {
            return Err(
                ApiError::bad("invalid_request", "xkey must be an X25519 did:key").into_response(),
            );
        }
    }
    let device = Device {
        id: device_id(),
        key: d.key,
        name: clean_name(Some(&d.name), "device").map_err(IntoResponse::into_response)?,
        kind: d.kind,
        aal: d.aal,
        caps: vec!["session".into(), "alias".into()],
        rp_id: None,
        xkey: d.xkey,
    };
    let id =
        insert(&h, Join::new(false, None, Some(device))).map_err(IntoResponse::into_response)?;
    Ok(Json(
        json!({"id": id, "url": url(&h, &id), "expires_in": JOIN_TTL}),
    ))
}

/// The account page opens a request for its identity, for a passkey to be made on
/// another device (a phone that scans the QR code).
pub async fn invite(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let (_, st) = account::current(&h, &headers)
        .ok_or_else(|| ApiError::unauthorized("sign in on the account page first"))?;
    let id = insert(&h, Join::new(true, Some(st.did), None))?;
    Ok(Json(
        json!({"id": id, "url": url(&h, &id), "expires_in": JOIN_TTL}),
    ))
}

pub async fn status(State(h): State<Arc<Hub>>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    with(&h, &id, |j| Ok(Json(j.json(&h, &id))))
}

/// A browser signed in to the hub takes a terminal's request for its identity.
pub async fn claim(
    State(h): State<Arc<Hub>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (_, st) = account::current(&h, &headers)
        .ok_or_else(|| ApiError::unauthorized("sign in to claim this device"))?;
    with(&h, &id, |j| {
        if j.invite || j.did.is_some() {
            return Err(conflict("this request already belongs to an identity"));
        }
        build(&h, j, &st.did)?;
        Ok(Json(j.json(&h, &id)))
    })
}

#[derive(Deserialize)]
pub struct DeviceReq {
    /// The new passkey, as a `did:key`.
    key: String,
    #[serde(default)]
    name: Option<String>,
}

/// The phone that scanned an invite supplies the passkey it just made.
pub async fn submit_device(
    State(h): State<Arc<Hub>>,
    Path(id): Path<String>,
    Json(req): Json<DeviceReq>,
) -> ApiResult<Json<Value>> {
    if PublicKey::from_did_key(&req.key)?.kty != KeyType::P256 {
        return Err(ApiError::bad(
            "invalid_request",
            "passkeys must be ES256 (P-256)",
        ));
    }
    let name = clean_name(req.name.as_deref(), "phone")?;
    with(&h, &id, |j| {
        if !j.invite || j.device.is_some() {
            return Err(conflict("a device was already supplied for this request"));
        }
        j.device = Some(Device {
            id: device_id(),
            key: req.key,
            name,
            kind: DeviceKind::Passkey,
            aal: 2,
            caps: vec!["session".into()],
            rp_id: Some(h.cfg.rp_id.clone()),
            xkey: None,
        });
        let did = j.did.clone().expect("an invite names its identity");
        if let Err(e) = build(&h, j, &did) {
            j.device = None;
            return Err(e);
        }
        Ok(Json(j.json(&h, &id)))
    })
}

// ------------------------------------------------------------------ signatures

/// A WebAuthn assertion as the browser has it: it doesn't know its passkey's `did:key`.
#[derive(Deserialize)]
pub struct Assertion {
    authenticator_data: String,
    client_data_json: String,
    signature: String,
}

#[derive(Deserialize)]
pub struct SigReq {
    #[serde(default)]
    sig: Option<Sig>,
    #[serde(default)]
    webauthn: Option<Assertion>,
}

/// An assertion by `key` over `message`, checked as a login is: this hub's RP id and
/// origins, and a challenge of SHA-256(message).
fn check_assertion(h: &Hub, key: &str, message: &[u8], a: &Assertion) -> ApiResult<Sig> {
    let pk = PublicKey::from_did_key(key)?;
    if pk.kty != KeyType::P256 {
        return Err(ApiError::bad("invalid_request", "passkeys are P-256 keys"));
    }
    let data = WebAuthnSigData {
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: a.client_data_json.clone(),
    };
    let check = AssertionCheck {
        challenge: sha256(message).to_vec(),
        rp_id: Some(&h.cfg.rp_id),
        origins: Some(&h.cfg.origins),
        require_uv: false,
    };
    webauthn::verify_assertion(&pk, &data, &b64u_decode(&a.signature)?, &check)
        .map_err(ApiError::unauthorized)?;
    Ok(Sig {
        signer: key.to_string(),
        alg: "WebAuthn".into(),
        sig: a.signature.clone(),
        webauthn: Some(data),
    })
}

/// A signature that names its signer: WebAuthn ones get the login checks too.
fn check_sig(h: &Hub, sig: Sig, message: &[u8]) -> ApiResult<Sig> {
    if sig.alg == "WebAuthn" {
        let data = sig
            .webauthn
            .as_ref()
            .ok_or_else(|| ApiError::bad("invalid_request", "missing WebAuthn data"))?;
        let a = Assertion {
            authenticator_data: data.authenticator_data.clone(),
            client_data_json: data.client_data_json.clone(),
            signature: sig.sig.clone(),
        };
        return check_assertion(h, &sig.signer, message, &a);
    }
    verify_sig(&sig, message, &VerifyOptions::default()).map_err(ApiError::unauthorized)?;
    Ok(sig)
}

fn finished(j: &Join) -> ApiResult<()> {
    if j.done || j.error.is_some() {
        return Err(conflict("this request is already finished"));
    }
    Ok(())
}

/// One manage signer approves the event.
pub async fn approve(
    State(h): State<Arc<Hub>>,
    Path(id): Path<String>,
    Json(req): Json<SigReq>,
) -> ApiResult<Json<Value>> {
    with(&h, &id, |j| {
        finished(j)?;
        let (Some(message), Some(manage)) = (j.message(), j.manage.clone()) else {
            return Err(ApiError::bad("invalid_request", "nothing to approve yet"));
        };
        let msg = message.as_bytes();
        let signers = manage.signers();
        let sig = match (req.sig, req.webauthn) {
            (Some(sig), _) => {
                if !signers.contains(&sig.signer) {
                    return Err(ApiError::unauthorized(
                        "that key does not manage this identity, so it can't approve devices",
                    ));
                }
                check_sig(&h, sig, msg)?
            }
            // The browser can't say which key its passkey is, so try each passkey-shaped
            // manage signer; only the right one verifies.
            (None, Some(a)) => signers
                .iter()
                .filter(|s| s.starts_with("did:key:zDn"))
                .find_map(|s| check_assertion(&h, s, msg, &a).ok())
                .ok_or_else(|| {
                    ApiError::unauthorized(
                        "that passkey does not manage this identity, so it can't approve devices",
                    )
                })?,
            (None, None) => {
                return Err(ApiError::bad(
                    "invalid_request",
                    "send a sig or a webauthn assertion",
                ))
            }
        };
        if !j.approvals.iter().any(|s| s.signer == sig.signer) {
            j.approvals.push(sig);
        }
        finish(&h, j);
        Ok(Json(j.json(&h, &id)))
    })
}

/// The new device proves it holds its key, by signing the same event.
pub async fn pop(
    State(h): State<Arc<Hub>>,
    Path(id): Path<String>,
    Json(req): Json<SigReq>,
) -> ApiResult<Json<Value>> {
    with(&h, &id, |j| {
        finished(j)?;
        let (Some(message), Some(device)) = (j.message(), j.device.clone()) else {
            return Err(ApiError::bad("invalid_request", "nothing to sign yet"));
        };
        let msg = message.as_bytes();
        let sig = match (req.sig, req.webauthn) {
            (_, Some(a)) if device.kind == DeviceKind::Passkey => {
                check_assertion(&h, &device.key, msg, &a)?
            }
            (Some(sig), None) if device.kind != DeviceKind::Passkey => {
                if sig.signer != device.key {
                    return Err(ApiError::unauthorized(
                        "the proof must come from the joining device's key",
                    ));
                }
                check_sig(&h, sig, msg)?
            }
            _ => {
                return Err(ApiError::bad(
                    "invalid_request",
                    "a passkey proves with a webauthn assertion, any other device with a sig",
                ))
            }
        };
        j.pop = Some(sig);
        finish(&h, j);
        Ok(Json(j.json(&h, &id)))
    })
}

// ------------------------------------------------------------------ pages

pub async fn page(
    State(h): State<Arc<Hub>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(join) = with(&h, &id, |j| Ok(j.json(&h, &id))) else {
        return pages::message(
            StatusCode::NOT_FOUND,
            "Link expired",
            "This link to add a device is unknown or has expired. Start again from your account page, or run `kith device join` again.",
        );
    };
    let session_did = account::current(&h, &headers).map(|(_, st)| st.did);
    let mut data = json!({"join": join, "rp_id": h.cfg.rp_id, "session_did": session_did});
    if session_did.is_none() {
        // For signing in on this page, as the account page does.
        let (challenge_id, message) = account::challenge(&h);
        data["challenge_id"] = json!(challenge_id);
        data["message"] = json!(message);
    }
    pages::join(data)
}

pub async fn qr_svg(State(h): State<Arc<Hub>>, Path(id): Path<String>) -> Response {
    if with(&h, &id, |_| Ok(())).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match qr::svg(&url(&h, &id)) {
        Some(svg) => (
            [
                (header::CONTENT_TYPE, "image/svg+xml"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            svg,
        )
            .into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
