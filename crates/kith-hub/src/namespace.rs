//! Names in a verified domain's namespace (spec 7.8.4): `ada@example.com`.
//!
//! Whoever holds `dns:example.com` (spec 7.8.3) gives out names under it, and the hub
//! answers WebFinger for them, so a name finds its root the way spec 5.1.1 says an
//! alias does: `GET /.well-known/webfinger?resource=acct:ada@example.com` names a root
//! (`urn:kith:root`), and the resolver then checks that the root's own KEL links the alias.
//! The domain's word alone proves nothing, and neither does the root's.
//!
//! | endpoint                                  | purpose                                              |
//! |-------------------------------------------|------------------------------------------------------|
//! | `GET /.well-known/webfinger?resource=…`   | the JRD for a name the hub holds (no token)          |
//! | `PUT /v1/namespaces/{domain}/{local}`     | give a name to a DID; replaces (bearer, the holder)  |
//! | `DELETE /v1/namespaces/{domain}/{local}`  | take it back (bearer, the holder)                    |
//! | `GET /v1/namespaces/{domain}`             | the names the holder gave out (bearer, the holder)   |
//!
//! A name is served only while the identity who gave it still holds the domain, fresh:
//! when a domain changes hands or goes unchecked, its names stop at once, and they come
//! back if that holder proves the domain again. Nothing is deleted behind anyone's back.
//!
//! For `kith resolve ada@example.com` to find the hub, the domain sends
//! `/.well-known/webfinger` to it (a redirect or a proxy); `kith finger` asks the hub
//! directly.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::domain;
use kith_core::kel::KeyState;
use kith_core::resolve;
use kith_core::session::KelResolver;
use kith_core::util::now;

use crate::{ApiError, ApiResult, Hub};

/// The most names one holder gives out under one domain.
pub const MAX_NAMES: i64 = 1000;
/// WebFinger link relation for a page about the subject (RFC 7033 / OpenID Connect).
pub const REL_PROFILE: &str = "http://webfinger.net/rel/profile-page";

/// One name: `local@domain` names `did`, on the word of `set_by`, who held the domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRecord {
    pub domain: String,
    pub local: String,
    pub did: String,
    pub set_by: String,
    pub created: i64,
}

impl NameRecord {
    /// The alias in the form a WebFinger subject takes (RFC 7565).
    pub fn alias(&self) -> String {
        format!("acct:{}@{}", self.local, self.domain)
    }
}

/// A local part is plain and lowercase: `[a-z0-9._+-]`, 1 to 64 long, starting with a
/// letter or digit. One spelling per name keeps the string the log links and the string
/// the hub returns the same (spec 5.1.1 normalizes nothing else).
fn valid_local(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '+' | '-'))
}

/// `local@domain` from `acct:`, `mailto:` or a bare address; `None` if it is not a name
/// in a domain the hub could hold. The local part is lowercased, as the domain is.
fn parse_name(s: &str) -> Option<(String, String)> {
    let addr = s.strip_prefix("acct:").or_else(|| s.strip_prefix("mailto:")).unwrap_or(s);
    let (local, host) = addr.rsplit_once('@')?;
    Some((local.to_ascii_lowercase(), domain::normalize(host).ok()?))
}

fn bad(msg: impl std::fmt::Display) -> ApiError {
    ApiError::bad("invalid_request", msg)
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not_found".into(), what.into(), None)
}

impl Hub {
    /// Whether `did` holds `domain` right now: it proved it last, and the proof is fresh.
    fn holds_domain(&self, domain: &str, did: &str) -> ApiResult<bool> {
        Ok(self.store.contact(&format!("{}{domain}", domain::SCHEME))?.is_some_and(|c| c.did == did && now() < self.fresh_until(&c)))
    }

    /// Whether a name may be served: the one who gave it still holds the domain.
    fn name_is_live(&self, n: &NameRecord) -> ApiResult<bool> {
        self.holds_domain(&n.domain, &n.set_by)
    }

    /// Whether the named root's own log links the alias: the second direction (spec 5.1.1).
    fn name_is_linked(&self, n: &NameRecord) -> bool {
        self.resolve(&n.did).is_ok_and(|st| resolve::links_back(&st, &n.alias()))
    }
}

fn require_holder(h: &Hub, domain: &str, did: &str) -> ApiResult<()> {
    if h.holds_domain(domain, did)? {
        return Ok(());
    }
    Err(ApiError(StatusCode::FORBIDDEN, "forbidden".into(), format!("you do not hold {domain}; prove it with `kith domain verify {domain}`"), None))
}

fn name_json(n: &NameRecord, linked: bool) -> Value {
    json!({"alias": n.alias(), "domain": n.domain, "local": n.local, "did": n.did, "held_by": n.set_by, "linked": linked, "created": n.created})
}

/// The names under live domains that point at this identity. The owner sees offers the
/// root has not linked yet; everyone else sees only names both sides agree on.
pub(crate) fn names_of(h: &Hub, st: &KeyState, owner: bool) -> ApiResult<Vec<Value>> {
    let mut out = Vec::new();
    for n in h.store.names_for(&st.did)? {
        if !h.name_is_live(&n)? {
            continue;
        }
        let linked = resolve::links_back(st, &n.alias());
        if owner || linked {
            out.push(json!({"alias": n.alias(), "domain": n.domain, "held_by": n.set_by, "linked": linked}));
        }
    }
    Ok(out)
}

/// The root a name resolves to on this hub: given by a live holder and linked by the root.
pub(crate) fn root_of(h: &Hub, name: &str) -> ApiResult<Option<String>> {
    let Some((local, domain)) = parse_name(name) else { return Ok(None) };
    let Some(n) = h.store.name(&domain, &local)? else { return Ok(None) };
    Ok((h.name_is_live(&n)? && h.name_is_linked(&n)).then_some(n.did))
}

// ------------------------------------------------------------------ WebFinger

/// `GET /.well-known/webfinger?resource=acct:ada@example.com[&rel=…]`. No token: a name
/// is public the moment it is looked up. A resource that is absent or not a URI is a
/// `400` (RFC 7033 4.2); one the hub does not hold is a `404`.
pub async fn webfinger(State(h): State<Arc<Hub>>, Query(q): Query<Vec<(String, String)>>) -> ApiResult<Response> {
    let resource = q.iter().find(|(k, _)| k == "resource").map(|(_, v)| v.as_str()).unwrap_or_default();
    let Some((scheme, rest)) = resource.split_once(':').filter(|(s, _)| !s.is_empty()) else {
        return Err(bad("resource is required, as a URI such as acct:ada@example.com"));
    };
    let held = match scheme.to_ascii_lowercase().as_str() {
        "acct" | "mailto" => {
            if !rest.contains('@') {
                return Err(bad("an acct: or mailto: resource is user@host"));
            }
            parse_name(resource)
        }
        _ => None,
    };
    let miss = || not_found("this hub holds no such name");
    let (local, domain) = held.ok_or_else(miss)?;
    let n = h.store.name(&domain, &local)?.ok_or_else(miss)?;
    if !h.name_is_live(&n)? {
        return Err(miss());
    }

    let issuer = h.cfg.issuer.trim_end_matches('/');
    let mut links = vec![
        json!({"rel": resolve::REL_ROOT, "href": n.did, "properties": {resolve::PROP_HUB: issuer}}),
        json!({"rel": REL_PROFILE, "type": "application/json", "href": format!("{issuer}/v1/profile/{}", n.did)}),
    ];
    let rels: Vec<&str> = q.iter().filter(|(k, _)| k == "rel").map(|(_, v)| v.as_str()).collect();
    if !rels.is_empty() {
        links.retain(|l| rels.contains(&l["rel"].as_str().unwrap_or_default()));
    }
    let mut r = Json(json!({"subject": n.alias(), "links": links})).into_response();
    let hd = r.headers_mut();
    hd.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/jrd+json"));
    // RFC 7033 5: browser clients may ask.
    hd.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    hd.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=60"));
    Ok(r)
}

// ------------------------------------------------------------------ the holder's side

#[derive(Deserialize)]
pub struct GiveReq {
    did: String,
}

fn domain_of(input: &str) -> ApiResult<String> {
    domain::normalize(input).map_err(bad)
}

/// `PUT /v1/namespaces/{domain}/{local}` with `{"did": "did:kith:…"}`: give the name to
/// that root, replacing whoever had it. The root must have a log on this hub (so the
/// JRD's `urn:kith:hub` is true). The root still has to link the alias itself.
pub async fn give(State(h): State<Arc<Hub>>, headers: HeaderMap, Path((domain, local)): Path<(String, String)>, Json(req): Json<GiveReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let domain = domain_of(&domain)?;
    require_holder(&h, &domain, &c.sub)?;
    if !valid_local(&local) {
        return Err(bad("a name is 1-64 of a-z, 0-9, '.', '_', '+' and '-', starting with a letter or digit"));
    }
    if !domain::valid_did(&req.did) {
        return Err(bad("did is not a DID"));
    }
    if h.get_kel(&req.did).is_none() {
        return Err(bad("this hub has no log for that DID; its owner publishes it first (`kith publish`)"));
    }
    let replacing = h.store.name(&domain, &local)?.is_some_and(|n| n.set_by == c.sub);
    if !replacing && h.store.count_names_by(&domain, &c.sub)? >= MAX_NAMES {
        return Err(ApiError(StatusCode::CONFLICT, "limit".into(), format!("{domain} already has {MAX_NAMES} names from you"), None));
    }
    let rec = NameRecord { domain, local, did: req.did, set_by: c.sub, created: now() };
    h.store.put_name(&rec)?;
    let linked = h.name_is_linked(&rec);
    Ok(Json(name_json(&rec, linked)))
}

/// `DELETE /v1/namespaces/{domain}/{local}`: take a name back. The holder may remove any
/// name under the domain, including one a former holder gave.
pub async fn remove(State(h): State<Arc<Hub>>, headers: HeaderMap, Path((domain, local)): Path<(String, String)>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let domain = domain_of(&domain)?;
    require_holder(&h, &domain, &c.sub)?;
    if !h.store.delete_name(&domain, &local.to_ascii_lowercase())? {
        return Err(not_found("no such name"));
    }
    Ok(Json(json!({"removed": format!("acct:{}@{domain}", local.to_ascii_lowercase())})))
}

/// `GET /v1/namespaces/{domain}`: the names the caller gave out. A list of people is not
/// public, so it is the holder's alone.
pub async fn list(State(h): State<Arc<Hub>>, headers: HeaderMap, Path(domain): Path<String>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let domain = domain_of(&domain)?;
    require_holder(&h, &domain, &c.sub)?;
    // Many names point at few roots; replay each root's log once.
    let mut linked: std::collections::HashMap<String, Option<KeyState>> = std::collections::HashMap::new();
    let names = h.store.names_in(&domain, &c.sub)?;
    let out: Vec<Value> = names
        .iter()
        .map(|n| {
            let st = linked.entry(n.did.clone()).or_insert_with(|| h.resolve(&n.did).ok());
            name_json(n, st.as_ref().is_some_and(|st| resolve::links_back(st, &n.alias())))
        })
        .collect();
    Ok(Json(json!(out)))
}
