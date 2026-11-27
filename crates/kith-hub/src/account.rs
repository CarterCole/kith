//! The account page, `GET /whoami`: who this browser is signed in as (spec §7.11).
//!
//! It uses the hub session that apps already reuse for SSO. Signed out, the page asks
//! for a passkey and posts the assertion to `POST /whoami`, which starts that session
//! with no app involved. Signed in, it shows the identity, its devices, how this
//! session signed in, and what the hub keeps about the identity (a verified email,
//! linked provider accounts, work). A session that rests on a device can set up an
//! authenticator app there (`POST /v1/account/totp`, then `/v1/account/totp/confirm`).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use base64::Engine as _;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::kel::KeyState;
use kith_core::util::{now, random_id};

use crate::oidc::{self, cookie, SsoSession, SESSION_COOKIE};
use crate::{pages, qr, ApiError, ApiResult, ClientIp, Factor, Hub};

/// The hub session behind this request's cookie, and its identity, while it holds.
pub(crate) fn current(h: &Hub, headers: &HeaderMap) -> Option<(SsoSession, KeyState)> {
    let sid = cookie(headers, SESSION_COOKIE)?;
    let s = h.store.session(&sid).ok().flatten()?;
    let st = oidc::session_holds(h, &s.authn)?;
    Some((s, st))
}

pub(crate) fn challenge(h: &Hub) -> (String, String) {
    let name = pages::brand();
    let (id, message, _) = h.new_challenge(None, |id, iat, exp| h.oidc_message(name, id, iat, exp));
    (id, message)
}

pub async fn page(State(h): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    let Some((s, st)) = current(&h, &headers) else {
        let (challenge_id, message) = challenge(&h);
        return pages::whoami(json!({
            "signed_in": false,
            "challenge_id": challenge_id,
            "message": message,
            "rp_id": h.cfg.rp_id,
            "signup": h.cfg.signup,
            "phone": true,
        }));
    };
    let a = &s.authn;
    let devices: Vec<Value> = st
        .devices
        .values()
        .map(|d| {
            json!({
                "name": d.name,
                "kind": d.kind,
                "aal": d.aal,
                "current": a.dev.as_deref() == Some(d.id.as_str()),
            })
        })
        .collect();
    // Provider accounts that sign in as this identity: linked in its log or at sign-up.
    let mut linked: BTreeSet<String> = st.aliases.clone();
    linked.extend(h.store.provider_links_of(&st.did).unwrap_or_default());
    pages::whoami(json!({
        "signed_in": true,
        "did": st.did,
        "created": st.created,
        "devices": devices,
        "session": {
            "aal": a.aal,
            "amr": a.amr,
            "auth_time": a.auth_time,
            "expires": s.expires,
            "via": a.alias,
        },
        "email": h.store.contacts_of(&st.did).ok().and_then(|cs| cs.into_iter().find(|c| c.address.starts_with("mailto:")).map(|c| c.address.trim_start_matches("mailto:").to_string())),
        "work": h.store.work_for(&st.did).ok().flatten().map_or(0, |(bits, _)| bits),
        "linked": linked,
        "totp": h.store.totp(&st.did).ok().flatten().is_some_and(|r| r.confirmed),
    }))
}

/// The session behind this request, if it may change the identity's sign-in factors:
/// it rests on one of the identity's devices. A sign-in through a provider alone, or
/// through a one-time code alone, may not choose a second factor for the account.
fn device_session(h: &Hub, headers: &HeaderMap) -> ApiResult<KeyState> {
    let (s, st) = current(h, headers).ok_or_else(|| ApiError::unauthorized("sign in on the account page first"))?;
    if s.authn.dev.is_none() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "forbidden".into(),
            "sign in with a passkey or another device of this identity to set up an authenticator".into(),
            None,
        ));
    }
    Ok(st)
}

/// `POST /v1/account/totp`: start setting up an authenticator app (spec §7.11.1). The
/// reply has the secret, its `otpauth://` URI and that URI as a QR code to scan.
pub async fn totp_enroll(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let st = device_session(&h, &headers)?;
    let mut out = h.totp_begin(&st.did)?;
    let svg = qr::svg(out["otpauth_uri"].as_str().unwrap_or_default())
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("could not draw the QR code")))?;
    out["qr"] = json!(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg)));
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct CodeReq {
    code: String,
}

/// `POST /v1/account/totp/confirm`: a code from the app finishes the setup.
pub async fn totp_confirm(State(h): State<Arc<Hub>>, ip: ClientIp, headers: HeaderMap, Json(req): Json<CodeReq>) -> ApiResult<Json<Value>> {
    let st = device_session(&h, &headers)?;
    h.limit_totp(&ip)?;
    h.check_totp(&st.did, &req.code, false)?;
    Ok(Json(json!({"confirmed": true})))
}

#[derive(Deserialize)]
pub struct LoginReq {
    challenge_id: String,
    /// The DID, or the handle of a passkey made at sign-up.
    did: String,
    factors: Vec<Factor>,
}

/// The signed-out page posts here. One of the identity's devices has to sign: this
/// page is open to anyone, so a one-time code alone does not start a session. On
/// failure the reply carries a fresh challenge so the page can retry.
pub async fn login(State(h): State<Arc<Hub>>, ip: ClientIp, Json(req): Json<LoginReq>) -> Response {
    if let Err(r) = h.rate_limit("login", &ip, h.cfg.login_limit) {
        return r;
    }
    let retry = |e: ApiError| -> Response {
        let (challenge_id, message) = challenge(&h);
        e.with(json!({"challenge_id": challenge_id, "message": message}))
            .into_response()
    };
    let ch = match h.take_challenge(&req.challenge_id) {
        Ok(c) => c,
        Err(e) => return retry(e),
    };
    let did = match h.store.did_for_handle(&req.did) {
        Ok(Some(did)) => did,
        _ => req.did.clone(),
    };
    let a = match h.authenticate(&did, &ch.message, &req.factors) {
        Ok(a) => a,
        Err(e) => return retry(e),
    };
    if a.dev.is_none() {
        return retry(ApiError::unauthorized(
            "sign in with a passkey or another device of this identity",
        ));
    }
    let Some(set_cookie) = oidc::start_session(&h, &random_id(), &a) else {
        return ApiError::from(anyhow::anyhow!("could not start a session")).into_response();
    };
    let _ = h.store.sweep(now());
    let mut r = Json(json!({"did": a.st.did})).into_response();
    r.headers_mut().insert(header::SET_COOKIE, set_cookie);
    r
}
