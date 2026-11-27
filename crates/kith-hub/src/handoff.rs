//! Sign in on one screen with a passkey on another (spec §7.15).
//!
//! The login page, or the signed-out account page, opens a handoff and shows a QR code
//! of its link. A phone that scans it signs in there with its own passkey, which
//! approves the handoff. The page that opened it is polling, and finishes the sign-in
//! with a secret only it holds: the link in the QR code approves, it never finishes.
//!
//! ```text
//! Computer: POST /v1/handoff {request_id?}         → {id, url, secret}; shows the QR code
//! Phone:    GET  /handoff/{id}                     names the app and the computer
//!           credentials.get(challenge = SHA-256(message)); POST /v1/handoff/{id}/approve
//!           (or POST /v1/handoff/{id}/deny)
//! Computer: polls GET /v1/handoff/{id}; POST /v1/handoff/{id}/finish {secret}
//!           → {redirect} and the hub session cookie
//! ```
//!
//! Handoffs live in memory for five minutes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::util::{now, random_id};

use crate::oidc::{self, ct_eq};
use crate::{pages, qr, store, ApiError, ApiResult, Authn, ClientIp, Factor, Hub};

pub const HANDOFF_TTL: i64 = 300;
/// Handoffs held in memory at once; a flood past the rate limit can't grow it.
const MAX_PENDING: usize = 1000;
/// The most a session started by another device's passkey is worth: the computer
/// proved nothing itself, and a QR code can be relayed (spec §7.15).
pub const MAX_AAL: u8 = 2;

#[derive(Debug, Clone)]
pub struct Handoff {
    created: i64,
    /// The sign-in request on the login page; `None` for the account page.
    request_id: Option<String>,
    /// The hash of the secret the opening page holds.
    secret: String,
    /// The computer, as the phone is shown it.
    ip: String,
    browser: String,
    scanned: bool,
    denied: bool,
    authn: Option<Authn>,
}

impl Handoff {
    fn state(&self) -> &'static str {
        if self.denied {
            "denied"
        } else if self.authn.is_some() {
            "approved"
        } else if self.scanned {
            "scanned"
        } else {
            "waiting"
        }
    }

    fn open(&self) -> ApiResult<()> {
        match self.state() {
            "denied" => Err(conflict("this sign-in was declined on the phone")),
            "approved" => Err(conflict("this sign-in was already approved")),
            _ => Ok(()),
        }
    }
}

fn url(h: &Hub, id: &str) -> String {
    format!("{}/handoff/{id}", h.cfg.issuer)
}

fn not_found() -> ApiError {
    ApiError(
        StatusCode::NOT_FOUND,
        "not_found".into(),
        "unknown or expired sign-in code; show a new one".into(),
        None,
    )
}

fn conflict(msg: &str) -> ApiError {
    ApiError(StatusCode::CONFLICT, "conflict".into(), msg.into(), None)
}

/// Read or change one handoff under the lock, so an approval and a denial can't race.
fn with<T>(h: &Hub, id: &str, f: impl FnOnce(&mut Handoff) -> ApiResult<T>) -> ApiResult<T> {
    let mut m = h.handoffs.lock().unwrap();
    m.retain(|_, x| x.created + HANDOFF_TTL > now());
    f(m.get_mut(id).ok_or_else(not_found)?)
}

/// "Chrome on macOS", from a User-Agent, for the phone to show. Best effort: the
/// header is whatever the computer says.
pub(crate) fn browser(ua: &str) -> String {
    const BROWSERS: &[(&str, &str)] = &[
        ("Edg", "Edge"),
        ("OPR/", "Opera"),
        ("Firefox/", "Firefox"),
        ("FxiOS/", "Firefox"),
        ("CriOS/", "Chrome"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
    ];
    const SYSTEMS: &[(&str, &str)] = &[
        ("iPhone", "iPhone"),
        ("iPad", "iPad"),
        ("Android", "Android"),
        ("CrOS", "ChromeOS"),
        ("Mac OS X", "macOS"),
        ("Windows", "Windows"),
        ("Linux", "Linux"),
    ];
    let find =
        |list: &[(&str, &'static str)]| list.iter().find(|(k, _)| ua.contains(k)).map(|(_, v)| *v);
    match (find(BROWSERS), find(SYSTEMS)) {
        (Some(b), Some(s)) => format!("{b} on {s}"),
        (Some(x), None) | (None, Some(x)) => x.to_string(),
        (None, None) => "a browser".into(),
    }
}

/// The app a handoff signs in to, by name; `None` for the account page.
fn client_name(h: &Hub, x: &Handoff) -> Option<String> {
    let ar = h.store.request(x.request_id.as_deref()?).ok()??;
    Some(h.client(&ar.client_id)?.display_name())
}

/// The message the phone's passkey signs. It names this handoff, so an assertion made
/// for another page can't approve it.
fn message(h: &Hub, id: &str, client: &str) -> (String, String) {
    let (cid, message, _) = h.new_challenge(None, |nonce, iat, exp| {
        format!(
            "{} wants you to sign in to {client} on another device with your {} identity.\n\nURI: {}\nVersion: 1\nNonce: {nonce}\nIssued At: {iat}\nExpiration Time: {exp}",
            h.cfg.rp_id,
            pages::brand(),
            url(h, id),
        )
    });
    (cid, message)
}

// ------------------------------------------------------------------ the computer

#[derive(Deserialize)]
pub struct StartReq {
    #[serde(default)]
    request_id: Option<String>,
}

/// The login page (with its `request_id`) or the account page opens a handoff.
pub async fn start(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    headers: HeaderMap,
    Json(req): Json<StartReq>,
) -> Result<Json<Value>, Response> {
    h.rate_limit("handoff", &ip, h.cfg.login_limit)?;
    if let Some(rid) = &req.request_id {
        if h.store.request(rid).ok().flatten().is_none() {
            return Err(ApiError::bad(
                "invalid_request",
                "this sign-in request expired; go back to the app and try again",
            )
            .into_response());
        }
    }
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let secret = random_id();
    let x = Handoff {
        created: now(),
        request_id: req.request_id,
        secret: store::hash(&secret),
        ip: ip.0,
        browser: browser(ua),
        scanned: false,
        denied: false,
        authn: None,
    };
    let id = random_id();
    {
        let mut m = h.handoffs.lock().unwrap();
        m.retain(|_, x| x.created + HANDOFF_TTL > now());
        if m.len() >= MAX_PENDING {
            return Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy".into(),
                "too many sign-ins by phone right now; try again shortly".into(),
                None,
            )
            .into_response());
        }
        m.insert(id.clone(), x);
    }
    Ok(Json(json!({
        "id": id,
        "url": url(&h, &id),
        "secret": secret,
        "expires_in": HANDOFF_TTL,
    })))
}

/// Where a handoff stands. Anyone with the id may ask; it says nothing about who.
pub async fn status(State(h): State<Arc<Hub>>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    with(&h, &id, |x| {
        Ok(Json(json!({
            "state": x.state(),
            "expires_at": x.created + HANDOFF_TTL,
        })))
    })
}

#[derive(Deserialize)]
pub struct FinishReq {
    secret: String,
}

/// The page that opened the handoff takes the phone's sign-in as its own: the app's
/// request continues as `/oauth/login` would, or the account page gets a session.
pub async fn finish(
    State(h): State<Arc<Hub>>,
    Path(id): Path<String>,
    Json(req): Json<FinishReq>,
) -> Response {
    let taken = {
        let mut m = h.handoffs.lock().unwrap();
        m.retain(|_, x| x.created + HANDOFF_TTL > now());
        match m.get(&id) {
            None => Err(not_found()),
            Some(x) if !ct_eq(&x.secret, &store::hash(&req.secret)) => Err(ApiError::unauthorized(
                "that is not the secret of this sign-in code",
            )),
            Some(x) if x.denied => Err(conflict("this sign-in was declined on the phone")),
            Some(x) if x.authn.is_none() => {
                Err(conflict("the phone hasn't approved this sign-in yet"))
            }
            Some(_) => Ok(m.remove(&id).expect("present")),
        }
    };
    let x = match taken {
        Ok(x) => x,
        Err(e) => return e.into_response(),
    };
    let a = x.authn.expect("approved");
    let (redirect, cookie) = match &x.request_id {
        Some(rid) => {
            let expired = || {
                ApiError::bad(
                    "invalid_request",
                    "this sign-in request expired; go back to the app and try again",
                )
                .into_response()
            };
            let Some(ar) = h.store.request(rid).ok().flatten() else {
                return expired();
            };
            if a.aal < ar.min_aal {
                return step_up(a.aal, ar.min_aal).into_response();
            }
            match oidc::complete_login(&h, rid, ar, a) {
                Some(done) => done,
                None => return expired(),
            }
        }
        None => match oidc::start_session(&h, &random_id(), &a) {
            Some(cookie) => ("/whoami".to_string(), cookie),
            None => {
                return ApiError::from(anyhow::anyhow!("could not start a session")).into_response()
            }
        },
    };
    let mut r = Json(json!({"redirect": redirect})).into_response();
    r.headers_mut().insert(header::SET_COOKIE, cookie);
    r
}

fn step_up(aal: u8, required: u8) -> ApiError {
    let why = if required > MAX_AAL {
        format!("this app needs assurance level {required}, which takes a security key on the computer itself; a phone can reach {MAX_AAL}")
    } else {
        format!("this app needs assurance level {required}; you reached {aal}")
    };
    ApiError(
        StatusCode::UNAUTHORIZED,
        "step_up_required".into(),
        why,
        None,
    )
    .with(json!({"aal": aal, "required_aal": required}))
}

// ------------------------------------------------------------------ the phone

#[derive(Deserialize)]
pub struct ApproveReq {
    challenge_id: String,
    /// The DID, or the handle of a passkey made at sign-up.
    did: String,
    factors: Vec<Factor>,
}

/// The phone signs in with its passkey, over this handoff's message. As on the account
/// page, one of the identity's devices has to sign; a one-time code alone does not.
pub async fn approve(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    Path(id): Path<String>,
    Json(req): Json<ApproveReq>,
) -> Response {
    if let Err(r) = h.rate_limit("login", &ip, h.cfg.login_limit) {
        return r;
    }
    let result = (|| {
        let (x, name) = {
            let x = with(&h, &id, |x| {
                x.open()?;
                Ok(x.clone())
            })?;
            let name = client_name(&h, &x);
            (x, name)
        };
        let retry = |e: ApiError| -> ApiError {
            let (cid, message) = message(&h, &id, name.as_deref().unwrap_or(pages::brand()));
            e.with(json!({"challenge_id": cid, "message": message}))
        };
        let ch = h.take_challenge(&req.challenge_id).map_err(retry)?;
        if !ch.message.contains(&format!("\nURI: {}\n", url(&h, &id))) {
            return Err(retry(ApiError::unauthorized(
                "that signature was made for another page",
            )));
        }
        let did = match h.store.did_for_handle(&req.did) {
            Ok(Some(did)) => did,
            _ => req.did.clone(),
        };
        let mut a = h
            .authenticate(&did, &ch.message, &req.factors)
            .map_err(retry)?;
        if a.dev.is_none() {
            return Err(retry(ApiError::unauthorized(
                "sign in with a passkey or another device of this identity",
            )));
        }
        a.aal = a.aal.min(MAX_AAL);
        if let Some(ar) = x
            .request_id
            .as_ref()
            .and_then(|r| h.store.request(r).ok().flatten())
        {
            if a.aal < ar.min_aal {
                return Err(retry(step_up(a.aal, ar.min_aal)));
            }
        }
        with(&h, &id, |x| {
            x.open()?;
            x.authn = Some(a);
            Ok(Json(json!({"state": x.state()})))
        })
    })();
    match result {
        Ok(r) => r.into_response(),
        Err(e) => e.into_response(),
    }
}

/// The phone declines: the computer is told, and the code can't be used again.
pub async fn deny(State(h): State<Arc<Hub>>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    with(&h, &id, |x| {
        x.open()?;
        x.denied = true;
        Ok(Json(json!({"state": x.state()})))
    })
}

// ------------------------------------------------------------------ pages

/// The page the QR code opens, on the phone. Opening it tells the computer it was
/// scanned.
pub async fn page(State(h): State<Arc<Hub>>, ip: ClientIp, Path(id): Path<String>) -> Response {
    let Ok(x) = with(&h, &id, |x| {
        x.scanned = true;
        Ok(x.clone())
    }) else {
        return pages::message(
            StatusCode::NOT_FOUND,
            "Code expired",
            "This sign-in code is unknown or has expired. Show a new one on the other screen and scan it again.",
        );
    };
    let name = client_name(&h, &x);
    let (challenge_id, message) = message(&h, &id, name.as_deref().unwrap_or(pages::brand()));
    let min_aal = x
        .request_id
        .as_ref()
        .and_then(|r| h.store.request(r).ok().flatten())
        .map_or(1, |ar| ar.min_aal);
    pages::handoff(json!({
        "id": id,
        "state": x.state(),
        "client_name": name,
        "browser": x.browser,
        "ip": x.ip,
        "phone_ip": ip.0,
        "created": x.created,
        "expires_at": x.created + HANDOFF_TTL,
        "challenge_id": challenge_id,
        "message": message,
        "rp_id": h.cfg.rp_id,
        "min_aal": min_aal,
        "max_aal": MAX_AAL,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_by_name() {
        let mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15";
        let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";
        let ios_chrome = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0 Mobile/15E148 Safari/604.1";
        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0";
        assert_eq!(browser(mac), "Safari on macOS");
        assert_eq!(browser(edge), "Edge on Windows");
        assert_eq!(browser(ios_chrome), "Chrome on iPhone");
        assert_eq!(browser(firefox), "Firefox on Linux");
        assert_eq!(browser("curl/8.7.1"), "a browser");
    }
}
