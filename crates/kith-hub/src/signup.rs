//! Create an identity in the browser, with a passkey and nothing else (spec §7.11).
//!
//! The passkey is the identity's manage key and its first device, and it signs the
//! inception event itself, so the hub never holds a key. The pre-rotation commitment
//! is a recovery key the browser generated; the visitor saves it before the passkey
//! is created and the hub only ever sees its public half. The visitor can also derive
//! that key from secret words, or bring any public `did:key` of their own.
//!
//! ```text
//! Browser: POST /v1/signup                  → {id, handle, rp_id}
//!          navigator.credentials.create(user.id = handle)
//!          POST /v1/signup/{id}/key {key, recovery_key}
//!                                           → {message}   (the inception to sign)
//!          navigator.credentials.get(challenge = SHA-256(message))
//!          POST /v1/signup/{id}/sig {sig}   → {did}
//! ```
//!
//! A passkey's user handle is fixed when it is created, but the DID is a hash of the
//! inception, which contains the passkey's public key. The handle therefore can't be
//! the DID, as it is for passkeys added with `kith passkey enroll`. It is a random
//! value the hub maps to the DID once the identity exists; the login page sends it
//! where it would send the DID.
//!
//! Nothing personal goes into the key log: it is public and mirrored. The device is
//! simply called "passkey".

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::kel::{did_for_inception, new_inception, Device, DeviceKind, Event};
use kith_core::keys::{KeyType, PublicKey, Sig};
use kith_core::policy::SignerPolicy;
use kith_core::util::{b64u_decode, now, random_id, sha256};
use kith_core::webauthn::{self, AssertionCheck};

use crate::oidc::{self, cookie};
use crate::upstream::{ticket_cookie, Ticket, TICKET_COOKIE};
use crate::{pages, ApiError, Authn, ClientIp, Factor, Hub};

pub const SIGNUP_TTL: i64 = 600;
/// Attempts held in memory at once; a flood past the rate limit can't grow it.
const MAX_PENDING: usize = 1000;

#[derive(Debug, Clone)]
pub struct Attempt {
    handle: String,
    created: i64,
    /// The passkey, and the inception it has to sign.
    pending: Option<(String, Event)>,
    /// A provider account that signed in first and is to be linked to the new identity.
    ticket: Option<Ticket>,
}

type Reply = Result<Json<Value>, Response>;

fn api(e: impl Into<ApiError>) -> Response {
    e.into().into_response()
}

fn closed(h: &Hub) -> Result<(), Response> {
    if h.cfg.signup {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::NOT_FOUND,
            "signup_closed".into(),
            "this hub does not take sign-ups".into(),
            None,
        )
        .into_response())
    }
}

fn expired() -> Response {
    ApiError(
        StatusCode::NOT_FOUND,
        "not_found".into(),
        "unknown or expired sign-up; start again".into(),
        None,
    )
    .into_response()
}

pub async fn page(State(h): State<Arc<Hub>>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !h.cfg.signup {
        return pages::message(
            StatusCode::NOT_FOUND,
            "Sign-up is closed",
            "This hub does not take new sign-ups.",
        );
    }
    // Sent here by a provider sign-in that has no identity yet: say which one.
    let provider = q.get("ticket").and_then(|t| h.ticket_name(t));
    pages::signup(
        json!({"rp_id": h.cfg.rp_id, "provider": provider}),
    )
}

/// The recovery key may be any key the visitor derived or holds, of any type the log
/// supports; only its public `did:key` ever reaches the hub.
fn check_recovery(key: &str) -> Result<(), Response> {
    PublicKey::from_did_key(key).map(|_| ()).map_err(|_| {
        ApiError::bad(
            "invalid_request",
            "the recovery key must be a valid did:key",
        )
        .into_response()
    })
}

#[derive(Deserialize, Default)]
pub struct BeginReq {
    /// Optional: have the key checked now, so a typo is caught before a passkey is made.
    #[serde(default)]
    recovery_key: Option<String>,
    /// From a provider sign-in that found no identity; must match this browser's cookie.
    #[serde(default)]
    ticket: Option<String>,
}

/// Stateless: lets the page vet a pasted key before it makes a passkey.
pub async fn check(State(h): State<Arc<Hub>>, Json(req): Json<KeyCheck>) -> Reply {
    closed(&h)?;
    check_recovery(&req.recovery_key)?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
pub struct KeyCheck {
    recovery_key: String,
}

pub async fn begin(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    headers: HeaderMap,
    Json(req): Json<BeginReq>,
) -> Reply {
    closed(&h)?;
    if let Some(key) = &req.recovery_key {
        check_recovery(key)?;
    }
    h.rate_limit("signup", &ip, h.cfg.signup_limit)?;
    // The ticket is a bearer value in a URL: it only counts in the browser that came
    // back from the provider, or anyone who saw the URL could claim the account's link.
    let ticket = match &req.ticket {
        Some(t) if cookie(&headers, TICKET_COOKIE).as_deref() == Some(t.as_str()) => {
            Some(h.take_ticket(t).ok_or_else(expired)?)
        }
        Some(_) => return Err(expired()),
        None => None,
    };
    let id = random_id();
    let handle = format!("h_{}", random_id());
    {
        let mut m = h.signups.lock().unwrap();
        m.retain(|_, a| a.created + SIGNUP_TTL > now());
        if m.len() >= MAX_PENDING {
            return Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy".into(),
                "too many sign-ups in progress; try again shortly".into(),
                None,
            )
            .into_response());
        }
        m.insert(
            id.clone(),
            Attempt {
                handle: handle.clone(),
                created: now(),
                pending: None,
                ticket,
            },
        );
    }
    Ok(Json(
        json!({"id": id, "handle": handle, "rp_id": h.cfg.rp_id, "expires_in": SIGNUP_TTL}),
    ))
}

#[derive(Deserialize)]
pub struct KeyReq {
    /// The new passkey, as a `did:key`.
    key: String,
    /// The public half of the recovery key the browser made. Its policy is the
    /// identity's pre-rotation commitment.
    recovery_key: String,
}

pub async fn submit_key(
    State(h): State<Arc<Hub>>,
    Path(id): Path<String>,
    Json(req): Json<KeyReq>,
) -> Reply {
    closed(&h)?;
    if PublicKey::from_did_key(&req.key).map_err(api)?.kty != KeyType::P256 {
        return Err(
            ApiError::bad("invalid_request", "passkeys must be ES256 (P-256)").into_response(),
        );
    }
    check_recovery(&req.recovery_key)?;
    if req.key == req.recovery_key {
        return Err(ApiError::bad(
            "invalid_request",
            "the recovery key must be a different key",
        )
        .into_response());
    }
    let device = Device {
        id: format!("dev_{}", &random_id()[..8]),
        key: req.key.clone(),
        name: "passkey".into(),
        kind: DeviceKind::Passkey,
        aal: 2,
        caps: vec!["session".into(), "alias".into()],
        rp_id: Some(h.cfg.rp_id.clone()),
        xkey: None,
    };
    let inception = new_inception(
        SignerPolicy::single(&req.key),
        &SignerPolicy::single(&req.recovery_key),
        vec![device],
    );
    let message = String::from_utf8_lossy(&inception.signing_message().map_err(api)?).into_owned();

    let mut m = h.signups.lock().unwrap();
    m.retain(|_, a| a.created + SIGNUP_TTL > now());
    let attempt = m.get_mut(&id).ok_or_else(expired)?;
    if attempt.pending.is_some() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "exists".into(),
            "a passkey was already submitted".into(),
            None,
        )
        .into_response());
    }
    attempt.pending = Some((req.key, inception));
    Ok(Json(json!({"message": message})))
}

#[derive(Deserialize)]
pub struct SigReq {
    sig: Sig,
}

pub async fn submit_sig(
    State(h): State<Arc<Hub>>,
    Path(id): Path<String>,
    Json(req): Json<SigReq>,
) -> Result<Response, Response> {
    closed(&h)?;
    let (handle, key, mut inception, ticket) = {
        let mut m = h.signups.lock().unwrap();
        m.retain(|_, a| a.created + SIGNUP_TTL > now());
        let a = m.get(&id).ok_or_else(expired)?;
        let Some((key, inception)) = a.pending.clone() else {
            return Err(ApiError::bad("invalid_request", "nothing to sign yet").into_response());
        };
        (
            a.handle.clone(),
            key,
            inception,
            a.ticket.clone(),
        )
    };
    if req.sig.signer != key || req.sig.alg != "WebAuthn" {
        return Err(ApiError::bad(
            "invalid_request",
            "the inception must be signed by the new passkey",
        )
        .into_response());
    }
    // The same check a login gets: this hub's relying party and origins.
    let data =
        req.sig.webauthn.as_ref().ok_or_else(|| {
            ApiError::bad("invalid_request", "missing WebAuthn data").into_response()
        })?;
    let check = AssertionCheck {
        challenge: sha256(&inception.signing_message().map_err(api)?).to_vec(),
        rp_id: Some(&h.cfg.rp_id),
        origins: Some(&h.cfg.origins),
        require_uv: false,
    };
    let raw = b64u_decode(&req.sig.sig).map_err(api)?;
    let pk = PublicKey::from_did_key(&key).map_err(api)?;
    webauthn::verify_assertion(&pk, data, &raw, &check)
        .map_err(|e| ApiError::unauthorized(e).into_response())?;

    inception.add_sig(req.sig);
    let did = did_for_inception(&inception).map_err(api)?;
    // The handle first: pointing at an identity that doesn't exist yet is harmless,
    // whereas an identity nobody can sign in to is not.
    h.store.put_handle(&handle, &did).map_err(api)?;
    if let Some(t) = &ticket {
        // The same ordering reason: a link to an identity that never appears is undone below.
        if !h.store.put_provider_link(&t.alias, &did).map_err(api)? {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "exists".into(),
                "that account was linked to an identity in the meantime".into(),
                None,
            )
            .into_response());
        }
    }
    if let Err(e) = h.put_kel(&did, vec![inception]) {
        if let Some(t) = &ticket {
            let _ = h.store.del_provider_link(&t.alias);
        }
        return Err(e.into_response());
    }
    h.signups.lock().unwrap().remove(&id);

    let mut out = json!({"did": did});
    let mut session = None;
    if let Some(t) = &ticket {
        // The provider already vouched for this person, so finish the sign-in the app
        // started; if that can't be done (expired, needs more than AAL1) they sign in.
        if let Some((url, cookie)) = finish_login(&h, &did, t) {
            out["redirect"] = json!(url);
            session = Some(cookie);
        }
    }
    let mut res = Json(out).into_response();
    if let Some(cookie) = session {
        res.headers_mut().append(header::SET_COOKIE, cookie);
    }
    if ticket.is_some() {
        res.headers_mut()
            .append(header::SET_COOKIE, ticket_cookie(&h, "", 0));
    }
    Ok(res)
}

fn finish_login(h: &Hub, did: &str, t: &Ticket) -> Option<(String, header::HeaderValue)> {
    let ar = h.store.request(&t.request_id).ok().flatten()?;
    let factor = Factor::Federated {
        provider: t.provider.clone(),
        alias: t.alias.clone(),
    };
    let a = Authn {
        attrs: t.attrs.clone(),
        ..h.authenticate(did, "", &[factor]).ok()?
    };
    if a.aal < ar.min_aal {
        return None;
    }
    oidc::complete_login(h, &t.request_id, ar, a)
}
