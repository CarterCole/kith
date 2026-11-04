//! Proof of work for an account (spec §7.12): spend compute, raise the `work` attribute.
//!
//! Anyone may submit a proof for any identity; it can only raise that identity's work,
//! and a proof is worthless for any other DID. The hub keeps the best one and puts its
//! bit count in the `work` attribute of access tokens, where policies can use it
//! (`principal.work >= 24`).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::work::work_bits;

use crate::{ApiError, ApiResult, ClientIp, Hub};

/// Proofs below this are noise: not worth a database write.
pub const MIN_BITS: u32 = 12;

#[derive(Deserialize)]
pub struct WorkReq {
    did: String,
    nonce: u64,
}

pub async fn submit(
    State(h): State<Arc<Hub>>,
    ip: ClientIp,
    Json(req): Json<WorkReq>,
) -> Result<Json<Value>, axum::response::Response> {
    h.rate_limit("work", &ip, h.cfg.work_limit)?;
    let api = |e: ApiError| e.into_response();
    if h.get_kel(&req.did).is_none() {
        return Err(api(ApiError(
            StatusCode::NOT_FOUND,
            "not_found".into(),
            "unknown identity".into(),
            None,
        )));
    }
    let bits = work_bits(&req.did, req.nonce);
    if bits < MIN_BITS {
        return Err(api(ApiError::bad(
            "invalid_request",
            format!("that proof has {bits} bits of work; at least {MIN_BITS} are needed"),
        )));
    }
    let best = h
        .store
        .put_work(&req.did, bits, req.nonce)
        .map_err(|e| api(e.into()))?;
    Ok(Json(json!({"bits": bits, "work": best})))
}

/// The best proof on record, so anyone can check it with one hash.
pub async fn get(State(h): State<Arc<Hub>>, Path(did): Path<String>) -> ApiResult<Json<Value>> {
    Ok(Json(match h.store.work_for(&did)? {
        Some((bits, nonce)) => json!({"did": did, "work": bits, "nonce": nonce}),
        None => json!({"did": did, "work": 0}),
    }))
}
