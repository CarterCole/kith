//! Kith protocol core.
//!
//! Layers (see `spec/`):
//! * [`keys`]      – signer identifiers (did:key, CAIP-10 wallets) and signature verification
//! * [`webauthn`]  – passkey (WebAuthn) assertion verification
//! * [`policy`]    – threshold signer policies ("2 of my 3 devices")
//! * [`kel`]       – the key event log that defines a `did:kith` identity
//! * [`alias`]     – private, provable aliases of a root identity
//! * [`jws`]       – compact JWS helpers
//! * [`session`]   – device → session key grants, session tokens, delegation
//! * [`token`]     – hub-issued access tokens (RFC 9068 profile)
//! * [`totp`]      – RFC 6238 one-time codes (a hub-side factor)
//! * [`vault`]     – crypto-enforced access: skip-ratchet group keys sealed to devices
//! * [`authz`]     – groups (explicit + dynamic), roles and Cedar policy evaluation

pub mod alias;
pub mod authz;
pub mod canon;
pub mod error;
pub mod jws;
pub mod kel;
pub mod keys;
pub mod policy;
pub mod session;
pub mod token;
pub mod totp;
pub mod util;
pub mod vault;
pub mod webauthn;

pub use error::{Error, Result};
