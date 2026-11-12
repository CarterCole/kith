//! One identity's key event log, devices, sessions and recovery state, in one place.
//!
//! | method, path               | who         | what                                                    |
//! |----------------------------|-------------|---------------------------------------------------------|
//! | `GET /v1/whoami`           | the owner (hub bearer token) | everything below, plus what only the hub holds |
//! | `GET /v1/profile/{did}`    | anyone      | what the key event log already makes public, and the names in verified domains (`ada@example.com`) that both the domain and the root vouch for; the path may be such a name |
//!
//! Both are built by [`view`] from the stored KEL, so a mirror can check the public one
//! against `GET /v1/kel/{did}`. The owner's view adds hub state: live sessions, whether
//! an authenticator is enrolled, and the co-signer's id. Secrets (TOTP seeds, cookies,
//! refresh tokens) are never in either.
//!
//! The hub cannot see recovery ("paper") keys. `next` is a hash until a rotation reveals
//! the policy, so `recovery.rotations` lists only the policies that were already used.
//! `kith whoami --full` adds what this machine holds and checks it against `next`.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use kith_core::kel::{verify_log, Event, EventBody, KeyState};
use kith_core::keys::VerifyOptions;
use kith_core::util::now;

use crate::admin::session_json;
use crate::namespace;
use crate::{ApiError, ApiResult, Hub};

/// The events of a log, oldest first: who signed each one and what it said.
fn events_json(events: &[Event]) -> Vec<Value> {
    events
        .iter()
        .map(|e| {
            let mut detail = json!(e);
            if let Some(o) = detail.as_object_mut() {
                for k in ["v", "did", "seq", "prev", "ts", "kind", "sigs"] {
                    o.remove(k);
                }
            }
            json!({
                "seq": e.seq,
                "ts": e.ts,
                "kind": e.body.kind(),
                "digest": e.digest().ok(),
                "signers": e.sigs.iter().map(|s| s.signer.clone()).collect::<Vec<_>>(),
                "detail": detail,
            })
        })
        .collect()
}

/// Every rotation so far. A rotation reveals the policy that was committed in `next`, so
/// these are the only recovery signers the log ever shows.
fn rotations_json(events: &[Event]) -> Vec<Value> {
    events
        .iter()
        .filter_map(|e| match &e.body {
            EventBody::Rotate { rotation, revoke_devices, .. } => Some(json!({
                "seq": e.seq,
                "ts": e.ts,
                "rotation": rotation,
                "signers": e.sigs.iter().map(|s| s.signer.clone()).collect::<Vec<_>>(),
                "revoked_devices": revoke_devices,
            })),
            _ => None,
        })
        .collect()
}

/// What the log makes public about a DID. `recovery` is the commitment and its history.
fn view(st: &KeyState, events: &[Event]) -> Value {
    json!({
        "did": st.did,
        "state": st,
        "events": events_json(events),
        "recovery": {"next": st.next, "rotations": rotations_json(events)},
    })
}

fn load(h: &Hub, did: &str) -> ApiResult<(KeyState, Vec<Event>)> {
    let events = h.get_kel(did).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), format!("no KEL for {did}"), None))?;
    let st = verify_log(&events, &VerifyOptions::default())?;
    Ok((st, events))
}

/// `GET /v1/profile/{did}` or `GET /v1/profile/{name}`: the public view. No token. A name
/// (`ada@example.com`, `acct:` or `mailto:`) is found the way WebFinger finds it (spec
/// 7.8.4): given by a live holder of the domain and linked by the root itself.
pub async fn profile(State(h): State<Arc<Hub>>, Path(who): Path<String>) -> ApiResult<Json<Value>> {
    let did = if who.starts_with("did:") { who } else { namespace::root_of(&h, &who)?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), "no such name here".into(), None))? };
    let (st, events) = load(&h, &did)?;
    let mut v = view(&st, &events);
    v["namespaces"] = json!(namespace::names_of(&h, &st, false)?);
    Ok(Json(v))
}

/// `GET /v1/whoami`: the caller's own view, from a token issued for this hub. Looking
/// creates nothing: no co-signer, no authenticator.
pub async fn whoami(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Response> {
    let c = h.bearer(&headers)?;
    let (st, events) = load(&h, &c.sub)?;
    let mut v = view(&st, &events);
    v["namespaces"] = json!(namespace::names_of(&h, &st, true)?);
    let totp = h.store.totp(&st.did)?;
    v["token"] = json!({"aal": c.aal, "amr": c.amr, "dev": c.dev, "iat": c.iat, "exp": c.exp, "roles": c.roles, "groups": c.groups});
    v["sessions"] = json!(h.store.sessions(Some(&st.did))?.iter().map(session_json).collect::<Vec<_>>());
    v["recovery"]["totp"] = json!({
        "enrolled": totp.as_ref().is_some_and(|t| t.confirmed),
        "locked_until": totp.as_ref().map(|t| t.locked_until).filter(|&t| t > now()),
    });
    v["recovery"]["cosigner"] = json!(h.store.cosigner(&st.did)?.map(|s| s.id));
    let mut r = Json(v).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(r)
}
