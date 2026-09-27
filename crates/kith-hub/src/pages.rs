//! Server-rendered pages. Data is embedded as JSON (with `<` escaped) and read with
//! `textContent`, never interpolated into HTML. Each response gets a CSP nonce.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde_json::Value;

const STYLE: &str = include_str!("pages/style.css");
const LOGIN: &str = include_str!("pages/login.html");
const ENROLL: &str = include_str!("pages/enroll.html");
const MESSAGE: &str = include_str!("pages/message.html");
const COMMON_JS: &str = include_str!("pages/common.js");

fn render(status: StatusCode, template: &str, data: &Value) -> Response {
    let nonce = kith_core::util::random_id();
    let json = serde_json::to_string(data).unwrap_or_else(|_| "{}".into()).replace('<', "\\u003c");
    let html = template
        .replace("{{STYLE}}", STYLE)
        .replace("{{COMMON_JS}}", COMMON_JS)
        .replace("{{NONCE}}", &nonce)
        .replace("{{DATA}}", &json);
    let mut r = (status, Html(html)).into_response();
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
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
