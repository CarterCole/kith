//! Org pages and policy drafts (spec §8.6.1).
//!
//! An org named on the hub (`--org cartertech=did:kith:…`) gets a page at
//! `/orgs/{name}`. Its members see the org's log as the hub holds it (devices, manage
//! policy, aliases) and its current policy: every group, role, policy and directory
//! entry, read back from the signed root. Who is a member comes from that same root.
//!
//! Holders of the org's `god` role can save a **draft**: a whole new bundle. The hub
//! checks it, builds its policy DAG and keeps the root and the changes from the current
//! root, but signs nothing and serves nothing from it. A draft takes effect only when
//! the org's manage keys sign its root into the org's log, which `kith org approve
//! <link>` does after rebuilding the root itself. Until then the hub's word about a
//! draft is worth nothing, and that is the point: whoever controls the hub can write
//! drafts, not policy.
//!
//! | endpoint | who | does |
//! |----------|-----|------|
//! | `GET /orgs`, `/orgs/{name}`, `/orgs/{name}/drafts/{id}` | a browser | the pages; they read the API below with the hub session |
//! | `GET /v1/orgs` | a hub session or hub token | the named orgs the caller belongs to |
//! | `GET /v1/orgs/{name}` | a member | the org, its policy, the caller's groups and roles, open drafts |
//! | `POST /v1/orgs/{name}/drafts` `{bundle}` | the org's `god` role | check and save a draft |
//! | `GET /v1/orgs/{name}/drafts/{id}` | a member | the draft, its root, changes and state |
//! | `DELETE /v1/orgs/{name}/drafts/{id}` | the org's `god` role | discard it |

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use kith_core::authz::{Bundle, Memberships};
use kith_core::dag::MemStore;
use kith_core::kel::{EventBody, KeyState};
use kith_core::pdag;
use kith_core::session::KelResolver;
use kith_core::util::{now, random_id};

use crate::{account, pages, ApiError, ApiResult, Hub};

/// The role whose holders may save and discard drafts.
pub const EDITOR_ROLE: &str = "god";
/// How long a draft is kept, and how many an org keeps.
const DRAFT_TTL: i64 = 30 * 86_400;
const DRAFT_CAP: usize = 50;

/// Who is asking: from the browser's hub session or a hub access token.
struct Viewer {
    did: String,
    dev: Option<String>,
    aal: u8,
}

fn viewer(h: &Hub, headers: &HeaderMap) -> ApiResult<Viewer> {
    if let Some((s, _)) = account::current(h, headers) {
        return Ok(Viewer { did: s.authn.st.did.clone(), dev: s.authn.dev.clone(), aal: s.authn.aal });
    }
    if headers.contains_key(header::AUTHORIZATION) {
        let c = h.bearer(headers)?;
        return Ok(Viewer { did: c.sub, dev: c.dev, aal: c.aal });
    }
    Err(ApiError::unauthorized("sign in to see this org"))
}

fn not_found(msg: impl ToString) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not_found".into(), msg.to_string(), None)
}

fn forbidden(msg: impl ToString) -> ApiError {
    ApiError(StatusCode::FORBIDDEN, "forbidden".into(), msg.to_string(), None)
}

fn org_did(h: &Hub, name: &str) -> ApiResult<String> {
    h.cfg.orgs.get(name).cloned().ok_or_else(|| not_found(format!("no org called {name} on this hub")))
}

/// The viewer's groups and roles in `org`. `None`: not a member, or revoked there.
fn memberships(h: &Hub, org: &str, v: &Viewer) -> ApiResult<Option<Memberships>> {
    let mut attrs = Map::new();
    attrs.insert("aal".into(), json!(v.aal));
    attrs.insert("aliases".into(), json!(h.resolve(&v.did).map(|st| st.aliases).unwrap_or_default()));
    attrs.insert("work".into(), json!(h.store.work_for(&v.did)?.map_or(0, |(bits, _)| bits)));
    match h.memberships_in(org, &v.did, v.dev.as_deref(), &attrs, None) {
        Ok(m) if m.memberships.groups.is_empty() && m.memberships.roles.is_empty() => Ok(None),
        Ok(m) => Ok(Some(m.memberships)),
        // Revoked by the org: as good as not a member.
        Err(ApiError(StatusCode::UNAUTHORIZED, ..)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn member(h: &Hub, org: &str, v: &Viewer) -> ApiResult<Memberships> {
    // The org itself reads its own page and drafts: `kith org approve` signs in as it.
    if v.did == org {
        return Ok(Memberships::default());
    }
    memberships(h, org, v)?.ok_or_else(|| forbidden("only members of this org can see it"))
}

fn editor(h: &Hub, org: &str, v: &Viewer) -> ApiResult<Memberships> {
    let m = member(h, org, v)?;
    if !m.roles.iter().any(|r| r == EDITOR_ROLE) {
        return Err(forbidden(format!("drafts need the org's {EDITOR_ROLE} role")));
    }
    Ok(m)
}

fn no_store(v: Value) -> Response {
    let mut r = Json(v).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// Where a draft stands: `applied` once a `policy_root` after its base committed its
/// root, `stale` when the policy moved on without it, else `open`.
fn draft_state(h: &Hub, org: &str, d: &Value) -> String {
    let base_seq = d["base"]["seq"].as_u64().unwrap_or(0);
    let applied = h.get_kel(org).into_iter().flatten().any(|e| {
        e.seq > base_seq && matches!(&e.body, EventBody::PolicyRoot { root, .. } if d["root"].as_str() == Some(root.as_str()))
    });
    if applied {
        return "applied".into();
    }
    match h.policy_head(org) {
        Ok((_, head)) if d["base"]["root"].as_str() == Some(head.root.as_str()) => "open".into(),
        _ => "stale".into(),
    }
}

fn draft_view(h: &Hub, org: &str, mut d: Value, full: bool) -> Value {
    d["state"] = json!(draft_state(h, org, &d));
    if !full {
        if let Some(o) = d.as_object_mut() {
            o.remove("bundle");
        }
    }
    d
}

fn org_view(h: &Hub, name: &str, org: &str, st: &KeyState, v: &Viewer, m: &Memberships) -> ApiResult<Value> {
    let (_, head) = h.policy_head(org)?;
    let bundle = pdag::bundle_of(&h.orgs.blocks, &head.root)?;
    let signer = |id: &String| json!({"id": id, "device": st.devices.values().find(|d| d.key == *id).map(|d| d.name.clone())});
    let drafts: Vec<Value> = h
        .store
        .drafts(org)?
        .into_iter()
        .map(|d| draft_view(h, org, d, false))
        .filter(|d| d["state"] == "open")
        .collect();
    Ok(json!({
        "name": name,
        "did": org,
        "manage": {"policy": st.manage, "signers": st.manage.signers().iter().map(signer).collect::<Vec<_>>()},
        "devices": st.devices.values().map(|d| json!({"id": d.id, "name": d.name, "kind": d.kind, "aal": d.aal, "caps": d.caps})).collect::<Vec<_>>(),
        "aliases": st.aliases,
        "policy": {"root": head.root, "seq": head.seq, "ts": head.ts, "signers": head.signers, "revocations_through": head.revocations_through},
        "bundle": bundle,
        "viewer": {"did": v.did, "aal": v.aal, "groups": m.groups, "roles": m.roles, "can_edit": m.roles.iter().any(|r| r == EDITOR_ROLE)},
        "drafts": drafts,
    }))
}

/// `GET /v1/orgs`: the named orgs the caller belongs to.
pub async fn list(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Response> {
    let v = viewer(&h, &headers)?;
    let mut orgs = vec![];
    for (name, did) in &h.cfg.orgs {
        // An org with no policy yet has no members.
        if h.policy_head(did).is_ok() && memberships(&h, did, &v)?.is_some() {
            orgs.push(json!({"name": name, "did": did}));
        }
    }
    Ok(no_store(json!({"orgs": orgs})))
}

/// `GET /v1/orgs/{name}`.
pub async fn get(State(h): State<Arc<Hub>>, headers: HeaderMap, Path(name): Path<String>) -> ApiResult<Response> {
    let org = org_did(&h, &name)?;
    let v = viewer(&h, &headers)?;
    let st = h.resolve(&org).map_err(not_found)?;
    let m = member(&h, &org, &v)?;
    Ok(no_store(org_view(&h, &name, &org, &st, &v, &m)?))
}

#[derive(Deserialize)]
pub struct DraftReq {
    bundle: Value,
}

/// `POST /v1/orgs/{name}/drafts`: check a whole new bundle and keep it as a draft.
pub async fn create_draft(State(h): State<Arc<Hub>>, headers: HeaderMap, Path(name): Path<String>, Json(req): Json<DraftReq>) -> ApiResult<Response> {
    let org = org_did(&h, &name)?;
    let v = viewer(&h, &headers)?;
    editor(&h, &org, &v)?;
    let text = serde_json::to_string(&req.bundle).map_err(kith_core::Error::from)?;
    let report = kith_core::bundle::check(&text);
    if !report.ok() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_bundle".into(), report.errors.join("; "), None).with(json!({"errors": report.errors, "warnings": report.warnings})));
    }
    let bundle: Bundle = serde_json::from_value(req.bundle).map_err(|e| ApiError::bad("invalid_bundle", e))?;
    let root = pdag::build(&MemStore::new(), &bundle)?;
    let (_, head) = h.policy_head(&org)?;
    let current = pdag::bundle_of(&h.orgs.blocks, &head.root)?;
    let changes = kith_core::bundle::changes(&current, &bundle)?;
    if changes.is_empty() {
        return Err(ApiError::bad("no_changes", "this is the policy in force already"));
    }
    let id = random_id();
    let d = json!({
        "id": id,
        "org": org,
        "name": name,
        "url": format!("{}/orgs/{name}/drafts/{id}", h.cfg.issuer),
        "author": v.did,
        "created": now(),
        "root": root,
        "base": {"root": head.root, "seq": head.seq},
        "changes": changes,
        "warnings": report.warnings,
        "bundle": bundle,
    });
    h.store.put_draft(&id, &org, now(), &d, DRAFT_TTL, DRAFT_CAP)?;
    Ok(no_store(draft_view(&h, &org, d, false)))
}

fn find_draft(h: &Hub, org: &str, id: &str) -> ApiResult<Value> {
    h.store
        .draft(id)?
        .filter(|d| d["org"] == org && d["created"].as_i64().is_some_and(|t| t.saturating_add(DRAFT_TTL) > now()))
        .ok_or_else(|| not_found("no such draft"))
}

/// `GET /v1/orgs/{name}/drafts/{id}`.
pub async fn get_draft(State(h): State<Arc<Hub>>, headers: HeaderMap, Path((name, id)): Path<(String, String)>) -> ApiResult<Response> {
    let org = org_did(&h, &name)?;
    let v = viewer(&h, &headers)?;
    member(&h, &org, &v)?;
    Ok(no_store(draft_view(&h, &org, find_draft(&h, &org, &id)?, true)))
}

/// `DELETE /v1/orgs/{name}/drafts/{id}`.
pub async fn delete_draft(State(h): State<Arc<Hub>>, headers: HeaderMap, Path((name, id)): Path<(String, String)>) -> ApiResult<StatusCode> {
    let org = org_did(&h, &name)?;
    let v = viewer(&h, &headers)?;
    editor(&h, &org, &v)?;
    find_draft(&h, &org, &id)?;
    h.store.delete_draft(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /orgs`, `/orgs/{name}`, `/orgs/{name}/drafts/{id}`: the page shells. What they
/// show comes from the API above, with the browser's hub session.
pub async fn page_list() -> Response {
    pages::orgs(json!({"view": "list"}))
}

pub async fn page(State(h): State<Arc<Hub>>, Path(name): Path<String>) -> Response {
    match h.cfg.orgs.get(&name) {
        Some(did) => pages::orgs(json!({"view": "org", "name": name, "did": did})),
        None => pages::message(StatusCode::NOT_FOUND, "No such org", "This hub has no org by that name."),
    }
}

pub async fn page_draft(State(h): State<Arc<Hub>>, Path((name, id)): Path<(String, String)>) -> Response {
    match h.cfg.orgs.get(&name) {
        Some(did) => pages::orgs(json!({"view": "draft", "name": name, "did": did, "draft": id, "issuer": h.cfg.issuer})),
        None => pages::message(StatusCode::NOT_FOUND, "No such org", "This hub has no org by that name."),
    }
}
