//! Cross-origin requests from browser apps (spec §7.1.1).
//!
//! A single-page app redeems its code and refreshes its tokens with `fetch`, from its
//! own origin, so the token endpoint must answer CORS. The rule:
//!
//! | paths | origins | why |
//! |-------|---------|-----|
//! | discovery, JWKS | any (`*`) | public documents |
//! | `/oauth/token`, `/oauth/userinfo` | the origin of a registered redirect URI, echoed with `Vary: Origin` | the apps the hub already knows |
//!
//! Never with credentials: these endpoints read no cookies. Every other path, the login
//! and consent pages included, answers no CORS at all.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::oidc::Client;
use crate::Hub;

const PUBLIC: &[&str] = &[
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
];
const FOR_CLIENTS: &[&str] = &["/oauth/token", "/oauth/userinfo"];

/// How long a browser may reuse a preflight. Short, so deleting a client takes effect.
const MAX_AGE: &str = "600";

/// The middleware: answers preflights and adds `Access-Control-*` to responses.
pub async fn layer(State(h): State<Arc<Hub>>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let public = PUBLIC.contains(&path);
    if !public && !FOR_CLIENTS.contains(&path) {
        return next.run(req).await;
    }
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let allow = if public {
        Some(HeaderValue::from_static("*"))
    } else {
        origin
            .as_deref()
            .filter(|o| h.web_origin_registered(o))
            .and_then(|o| HeaderValue::from_str(o).ok())
    };

    let is_preflight = req.method() == Method::OPTIONS
        && origin.is_some()
        && req
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
    let mut res = if is_preflight {
        let Some(allow) = allow else {
            let mut r = StatusCode::FORBIDDEN.into_response();
            vary(r.headers_mut());
            return r;
        };
        let mut r = StatusCode::NO_CONTENT.into_response();
        let hs = r.headers_mut();
        hs.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
        hs.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(if public { "GET" } else { "GET, POST" }),
        );
        hs.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, content-type"),
        );
        hs.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(MAX_AGE),
        );
        r
    } else {
        let mut r = next.run(req).await;
        if let Some(allow) = allow {
            let hs = r.headers_mut();
            hs.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
            if !public {
                hs.insert(
                    header::ACCESS_CONTROL_EXPOSE_HEADERS,
                    HeaderValue::from_static("www-authenticate"),
                );
            }
        }
        r
    };
    if !public {
        vary(res.headers_mut());
    }
    res
}

/// The answer depends on `Origin`, so a cache must not hand it to another origin.
fn vary(hs: &mut HeaderMap) {
    hs.append(header::VARY, HeaderValue::from_static("origin"));
}

impl Hub {
    /// Whether `origin` is the web origin of a configured or registered client's
    /// redirect URI.
    pub(crate) fn web_origin_registered(&self, origin: &str) -> bool {
        let has = |c: &Client| {
            c.redirect_uris
                .iter()
                .any(|u| web_origin(u).as_deref() == Some(origin))
        };
        self.cfg.clients.iter().any(has)
            || match self.store.clients() {
                Ok(cs) => cs.iter().any(has),
                Err(e) => {
                    eprintln!("cors: cannot list clients: {e}");
                    false
                }
            }
    }
}

/// `scheme://host[:port]` of an `https` or `http` URI, spelled as a browser spells its
/// `Origin` header: lower case, without the default port. `None` for private-use
/// schemes (native apps), which have no web origin.
pub fn web_origin(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => "443",
        "http" => "80",
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = match authority.rsplit_once(':') {
        Some((host, port)) if port == default_port => host.to_string(),
        _ => authority,
    };
    Some(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::web_origin;

    #[test]
    fn web_origins() {
        for (uri, origin) in [
            ("https://app.example/cb", Some("https://app.example")),
            (
                "https://App.Example:443/cb?x=1",
                Some("https://app.example"),
            ),
            (
                "https://app.example:8443/cb",
                Some("https://app.example:8443"),
            ),
            ("HTTP://localhost:3000/cb", Some("http://localhost:3000")),
            ("http://localhost:80/cb", Some("http://localhost")),
            ("http://[::1]:5173/cb", Some("http://[::1]:5173")),
            ("http://[::1]/cb", Some("http://[::1]")),
            ("https://good.example@evil.example/cb", None),
            ("com.example.app:/cb", None),
            ("https:///cb", None),
        ] {
            assert_eq!(web_origin(uri).as_deref(), origin, "{uri}");
        }
    }
}
