//! Verified email addresses (spec §7.14).
//!
//! The hub mails a six-digit code to prove the visitor can read the address. A correct
//! code buys a one-time proof, which sign-up carries to the new identity. The address
//! lives in the hub's own store, never in the public key log, and reaches an app only
//! through the `email` scope.
//!
//! ```text
//! Browser: POST /v1/email/start {email}        → {id}      (code mailed)
//!          POST /v1/email/verify {id, code}    → {proof}
//!          POST /v1/signup {email_proof}       … the identity gets the address
//! ```

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::util::{now, random_id, sha256};

use crate::{pages, ApiError, ClientIp, Hub};

pub const CODE_TTL: i64 = 600;
pub const PROOF_TTL: i64 = 1800;
const MAX_TRIES: u32 = 5;
const MAX_PENDING: usize = 2000;

#[derive(Debug, Clone)]
pub struct Pending {
    email: String,
    code_hash: [u8; 32],
    created: i64,
    tries: u32,
}

type Reply = Result<Json<Value>, Response>;

fn err(status: StatusCode, code: &str, text: &str) -> Response {
    ApiError(status, code.into(), text.into(), None).into_response()
}

/// A plain address: one `@`, no spaces or characters that matter in a header.
pub fn normalize(raw: &str) -> Option<String> {
    let e = raw.trim().to_lowercase();
    let (local, domain) = e.split_once('@')?;
    let bad = |c: char| c.is_whitespace() || c.is_control() || "<>(),;:\"\\[]@".contains(c);
    let ok = e.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && !e.chars().any(|c| c != '@' && bad(c))
        && e.matches('@').count() == 1;
    ok.then_some(e)
}

fn code_hash(id: &str, code: &str) -> [u8; 32] {
    sha256(format!("{id}\0{code}").as_bytes())
}

#[derive(Deserialize)]
pub struct StartReq {
    email: String,
}

pub async fn start(State(h): State<Arc<Hub>>, ip: ClientIp, Json(req): Json<StartReq>) -> Reply {
    if h.cfg.mailer.is_none() {
        return Err(err(
            StatusCode::NOT_FOUND,
            "email_unavailable",
            "this hub does not send email",
        ));
    }
    let email = normalize(&req.email).ok_or_else(|| {
        ApiError::bad("invalid_request", "that doesn't look like an email address").into_response()
    })?;
    h.rate_limit("email", &ip, h.cfg.email_limit)?;
    // Mail to one address is limited too, or the form could be used to flood someone.
    let per_addr = crate::RateLimit {
        max: 3,
        window_secs: 3600,
    };
    let bucket = format!(
        "emailaddr|{}",
        kith_core::util::b64u(sha256(email.as_bytes()))
    );
    if let Ok(Some(retry)) = h.store.hit(&bucket, per_addr, now()) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            &format!("too many codes sent to that address; try again in {retry}s"),
        ));
    }
    if h.store
        .email_taken(&email)
        .map_err(|e| ApiError::from(e).into_response())?
    {
        return Err(err(
            StatusCode::CONFLICT,
            "exists",
            "that address is already on an account",
        ));
    }
    let id = random_id();
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    {
        let mut m = h.email_codes.lock().unwrap();
        m.retain(|_, p| p.created + CODE_TTL > now());
        if m.len() >= MAX_PENDING {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "try again shortly",
            ));
        }
        m.insert(
            id.clone(),
            Pending {
                email: email.clone(),
                code_hash: code_hash(&id, &code),
                created: now(),
                tries: 0,
            },
        );
    }
    let brand = pages::brand();
    let body = format!(
        "Your {brand} code is {code}.\n\nIt works for {} minutes. If you didn't ask for it, you can ignore this message.\n",
        CODE_TTL / 60
    );
    let sent = h
        .cfg
        .mailer
        .as_ref()
        .expect("checked above")
        .send(&email, &format!("Your {brand} code: {code}"), &body)
        .await;
    if let Err(e) = sent {
        h.email_codes.lock().unwrap().remove(&id);
        eprintln!("mail: could not send a code: {e}");
        return Err(err(
            StatusCode::BAD_GATEWAY,
            "mail_failed",
            "could not send the email; try again later",
        ));
    }
    Ok(Json(json!({"id": id, "expires_in": CODE_TTL})))
}

#[derive(Deserialize)]
pub struct VerifyReq {
    id: String,
    code: String,
}

pub async fn verify(State(h): State<Arc<Hub>>, Json(req): Json<VerifyReq>) -> Reply {
    let wrong = || {
        err(
            StatusCode::UNAUTHORIZED,
            "invalid_code",
            "that code is wrong or has expired",
        )
    };
    let email = {
        let mut m = h.email_codes.lock().unwrap();
        m.retain(|_, p| p.created + CODE_TTL > now());
        let p = m.get_mut(&req.id).ok_or_else(wrong)?;
        p.tries += 1;
        if p.tries > MAX_TRIES {
            m.remove(&req.id);
            return Err(wrong());
        }
        if p.code_hash != code_hash(&req.id, req.code.trim()) {
            return Err(wrong());
        }
        m.remove(&req.id).expect("just found").email
    };
    let proof = random_id();
    let mut proofs = h.email_proofs.lock().unwrap();
    proofs.retain(|_, (_, t)| *t + PROOF_TTL > now());
    proofs.insert(proof.clone(), (email.clone(), now()));
    Ok(Json(json!({"proof": proof, "email": email})))
}

impl Hub {
    /// Spend a proof from `verify`; the address it proved, once.
    pub(crate) fn take_email_proof(&self, proof: &str) -> Option<String> {
        let mut m = self.email_proofs.lock().unwrap();
        let (email, t) = m.remove(proof)?;
        (t + PROOF_TTL > now()).then_some(email)
    }
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn accepts_plain_addresses_and_rejects_the_rest() {
        assert_eq!(
            normalize(" Ada@Example.com "),
            Some("ada@example.com".into())
        );
        for bad in [
            "",
            "ada",
            "ada@",
            "@example.com",
            "ada@example",
            "a b@example.com",
            "ada@@example.com",
            "ada@exa mple.com",
            "ada@example..com",
            "a,b@example.com",
            "<ada>@example.com",
            "ada@example.com\r\nBcc: x@y.z",
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }
}
