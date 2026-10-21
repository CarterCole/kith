//! Server-rendered pages. Data is embedded as JSON (with `<` escaped) and read with
//! `textContent`, never interpolated into HTML. Each response gets a CSP nonce.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde_json::Value;

const STYLE: &str = include_str!("pages/style.css");
const LOGIN: &str = include_str!("pages/login.html");
const ENROLL: &str = include_str!("pages/enroll.html");
const MESSAGE: &str = include_str!("pages/message.html");
const CONSENT: &str = include_str!("pages/consent.html");
const LOGOUT: &str = include_str!("pages/logout.html");
const COMMON_JS: &str = include_str!("pages/common.js");

fn render(status: StatusCode, template: &str, data: &Value) -> Response {
    render_framing(status, template, data, &[])
}

/// `frames` are the origins the page may load in iframes (none by default).
fn render_framing(status: StatusCode, template: &str, data: &Value, frames: &[String]) -> Response {
    let nonce = kith_core::util::random_id();
    let json = serde_json::to_string(data).unwrap_or_else(|_| "{}".into()).replace('<', "\\u003c");
    let html = template
        .replace("{{STYLE}}", STYLE)
        .replace("{{COMMON_JS}}", COMMON_JS)
        .replace("{{NONCE}}", &nonce)
        .replace("{{DATA}}", &json);
    let mut r = (status, Html(html)).into_response();
    let frame_src = if frames.is_empty() { String::new() } else { format!("; frame-src {}", frames.join(" ")) };
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'{frame_src}"
    );
    let h = r.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&csp).expect("csp"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    r
}

pub fn login(data: Value) -> Response {
    render(StatusCode::OK, LOGIN, &data)
}

pub fn enroll(data: Value) -> Response {
    render(StatusCode::OK, ENROLL, &data)
}

pub fn message(status: StatusCode, title: &str, text: &str) -> Response {
    render(status, MESSAGE, &serde_json::json!({"title": title, "text": text}))
}

pub fn consent(data: Value) -> Response {
    render(StatusCode::OK, CONSENT, &data)
}

/// `scheme://host[:port]` of a URL, when it is plain enough to put in a CSP header.
fn csp_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let plain = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b));
    (["http", "https"].contains(&scheme) && plain(authority)).then(|| format!("{scheme}://{authority}"))
}

/// The sign-out page for front-channel logout: loads each client's logout URL in a
/// hidden iframe, then goes to `redirect`. A URL with an odd origin is left out.
pub fn logout(frames: &[String], redirect: Option<&str>) -> Response {
    let (urls, origins): (Vec<_>, Vec<_>) = frames.iter().filter_map(|u| csp_origin(u).map(|o| (u.clone(), o))).unzip();
    render_framing(StatusCode::OK, LOGOUT, &serde_json::json!({"frames": urls, "redirect": redirect}), &origins)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_origins() {
        assert_eq!(csp_origin("https://app.example/logout?x=1").as_deref(), Some("https://app.example"));
        assert_eq!(csp_origin("http://[::1]:3000/out").as_deref(), Some("http://[::1]:3000"));
        // Nothing that could add a directive to the header.
        assert_eq!(csp_origin("https://a.example;script-src *"), None);
        assert_eq!(csp_origin("https://a.example b.example/"), None);
        assert_eq!(csp_origin("javascript://x/"), None);
    }
}
