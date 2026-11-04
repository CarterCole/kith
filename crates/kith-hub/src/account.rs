//! The account page, `GET /whoami`: who this browser is signed in as (spec §7.11).
//!
//! It uses the hub session that apps already reuse for SSO. Signed out, the page asks
//! for a passkey and posts the assertion to `POST /whoami`, which starts that session
//! with no app involved. Signed in, it shows the identity, its devices, how this
//! session signed in, and what the hub keeps about the identity (a verified email,
//! linked provider accounts, work).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::kel::KeyState;
use kith_core::util::{now, random_id};

use crate::oidc::{self, cookie, SsoSession, SESSION_COOKIE};
use crate::{pages, ApiError, ClientIp, Factor, Hub};

/// The hub session behind this request's cookie, and its identity, while it holds.
pub(crate) fn current(h: &Hub, headers: &HeaderMap) -> Option<(SsoSession, KeyState)> {
    let sid = cookie(headers, SESSION_COOKIE)?;
    let s = h.store.session(&sid).ok().flatten()?;
    let st = oidc::session_holds(h, &s.authn)?;
    Some((s, st))
}

fn challenge(h: &Hub) -> (String, String) {
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
        "email": h.store.email_for(&st.did).ok().flatten(),
        "work": h.store.work_for(&st.did).ok().flatten().map_or(0, |(bits, _)| bits),
        "linked": linked,
    }))
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
