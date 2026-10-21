//! Admin API for the hub's operator: `/v1/admin/…`.
//!
//! Who may call it (see [`HubConfig::admin_token`](crate::HubConfig::admin_token)
//! and [`HubConfig::admin_role`](crate::HubConfig::admin_role)):
//! * a caller presenting the configured admin token as a bearer;
//! * a hub access token (`aud` = issuer, no actor) whose roles include the admin
//!   role, so the policy bundle decides who runs the hub.
//!
//! | method, path                                   | what                                                                 |
//! |------------------------------------------------|----------------------------------------------------------------------|
//! | `GET /v1/admin/stats`                          | counts of stored state, uptime                                       |
//! | `GET /v1/admin/sessions[?did=…]`               | live hub sessions (never their cookies)                              |
//! | `DELETE /v1/admin/sessions/{sid}`              | end one session: its codes and refresh tokens die, clients are told |
//! | `DELETE /v1/admin/identities/{did}/sessions`   | sign an identity out everywhere                                      |
//! | `GET /v1/admin/clients`                        | configured and registered clients, without secrets                   |
//! | `DELETE /v1/admin/clients/{id}`                | delete a registered client (configured ones live in the clients file)|
//! | `GET /v1/admin/grants/{did}`                   | what an identity agreed to share, per client                         |
//! | `DELETE /v1/admin/grants/{did}/{client_id}`    | withdraw that consent; the client's refresh tokens for them die      |

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use kith_core::util::now;

use crate::oidc::{self, ct_eq, Client, SsoSession};
use crate::{ApiError, ApiResult, Hub};

/// Who is calling: `admin-token`, or the DID behind a hub token in the admin role.
fn authorize(h: &Hub, headers: &HeaderMap) -> ApiResult<String> {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let given = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")).unwrap_or_default();
    if let Some(expected) = &h.cfg.admin_token {
        if !given.is_empty() && ct_eq(given, expected) {
            return Ok("admin-token".into());
        }
    }
    if let Some(role) = &h.cfg.admin_role {
        if let Ok(c) = h.bearer(headers) {
            if c.roles.contains(role) {
                return Ok(c.sub);
            }
            return Err(ApiError(StatusCode::FORBIDDEN, "forbidden".into(), format!("this identity is not in the {role} role"), None));
        }
    }
    Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized".into(), "the admin API takes the admin token, or a hub access token for an identity in the admin role".into(), None))
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not_found".into(), what.into(), None)
}

fn ok(v: Value) -> Response {
    let mut r = Json(v).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn session_json(s: &SsoSession) -> Value {
    json!({
        "sid": s.id,
        "did": s.authn.st.did,
        "device": s.authn.dev,
        "alias": s.authn.alias,
        "aal": s.authn.aal,
        "amr": s.authn.amr,
        "auth_time": s.authn.auth_time,
        "expires": s.expires,
        "clients": s.clients,
    })
}

fn client_json(c: &Client, source: &str) -> Value {
    let mut v = json!(c);
    v.as_object_mut().expect("object").remove("client_secret");
    v["has_secret"] = json!(c.client_secret.is_some());
    v["source"] = json!(source);
    v
}

pub async fn stats(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Response> {
    authorize(&h, &headers)?;
    h.store.sweep(now())?;
    let mut v = h.store.counts()?;
    v["configured_clients"] = json!(h.cfg.clients.len());
    v["kels"] = json!(h.kel_dids().len());
    v["started"] = json!(h.started);
    v["uptime"] = json!(now() - h.started);
    Ok(ok(v))
}

pub async fn sessions(State(h): State<Arc<Hub>>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> ApiResult<Response> {
    authorize(&h, &headers)?;
    let did = q.get("did").map(String::as_str).filter(|d| !d.is_empty());
    Ok(ok(json!(h.store.sessions(did)?.iter().map(session_json).collect::<Vec<_>>())))
}

pub async fn end_session(State(h): State<Arc<Hub>>, headers: HeaderMap, Path(sid): Path<String>) -> ApiResult<Response> {
    authorize(&h, &headers)?;
    let s = h.store.take_session_by_sid(&sid)?.ok_or_else(|| not_found("no such session"))?;
    let revoked = h.store.revoke_refresh(None, None, Some(&s.id))?;
    let (_, notified) = oidc::end_session(&h, &s);
    Ok(ok(json!({"ended": [session_json(&s)], "refresh_tokens_revoked": revoked, "notified": notified})))
}

pub async fn end_sessions_of(State(h): State<Arc<Hub>>, headers: HeaderMap, Path(did): Path<String>) -> ApiResult<Response> {
    authorize(&h, &headers)?;
    let sessions = h.store.take_sessions_of(&did)?;
    // Offline access ends too, including tokens whose session already expired.
    let revoked = h.store.revoke_refresh(Some(&did), None, None)?;
    let mut notified = BTreeSet::new();
    for s in &sessions {
        notified.extend(oidc::end_session(&h, s).1);
    }
    Ok(ok(json!({"ended": sessions.iter().map(session_json).collect::<Vec<_>>(), "refresh_tokens_revoked": revoked, "notified": notified})))
}

pub async fn clients(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Response> {
    authorize(&h, &headers)?;
    let mut out: Vec<Value> = h.cfg.clients.iter().map(|c| client_json(c, "configured")).collect();
    out.extend(h.store.clients()?.iter().map(|c| client_json(c, "registered")));
    Ok(ok(json!(out)))
}

pub async fn delete_client(State(h): State<Arc<Hub>>, headers: HeaderMap, Path(id): Path<String>) -> ApiResult<Response> {
    authorize(&h, &headers)?;
    if h.cfg.clients.iter().any(|c| c.client_id == id) {
        return Err(ApiError(StatusCode::CONFLICT, "configured".into(), "this client comes from the hub's clients file; remove it there".into(), None));
    }
    if !h.store.delete_client(&id)? {
        return Err(not_found("no such registered client"));
    }
    Ok(ok(json!({"deleted": id})))
}

pub async fn grants(State(h): State<Arc<Hub>>, headers: HeaderMap, Path(did): Path<String>) -> ApiResult<Response> {
    authorize(&h, &headers)?;
    let list: Vec<Value> = h
        .store
        .grants_of(&did)?
        .into_iter()
        .map(|(client_id, scopes, granted)| json!({"client_id": client_id, "client_name": h.client(&client_id).and_then(|c| c.name), "scopes": scopes, "granted": granted}))
        .collect();
    Ok(ok(json!(list)))
}

pub async fn revoke_grant(State(h): State<Arc<Hub>>, headers: HeaderMap, Path((did, client_id)): Path<(String, String)>) -> ApiResult<Response> {
    authorize(&h, &headers)?;
    let scopes = h.store.revoke_grant(&did, &client_id)?;
    let revoked = h.store.revoke_refresh(Some(&did), Some(&client_id), None)?;
    Ok(ok(json!({"revoked": scopes > 0, "refresh_tokens_revoked": revoked})))
}
