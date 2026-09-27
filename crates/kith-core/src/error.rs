use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("invalid signature: {0}")]
    Signature(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("invalid key event log: {0}")]
    Kel(String),
    #[error("invalid token: {0}")]
    Token(String),
    #[error("token expired or not yet valid")]
    Expired,
    #[error("authorization error: {0}")]
    Authz(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
