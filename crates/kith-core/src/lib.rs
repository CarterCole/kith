//! Kith protocol core.
//!
//! Layers (see `spec/`):
//! * [`keys`]      – signer identifiers (did:key, CAIP-10 wallets) and signature verification
//! * [`webauthn`]  – passkey (WebAuthn) assertion verification
//! * [`sshsig`]    – OpenSSH `SSHSIG` signatures: SSH keys as signers
//! * [`policy`]    – threshold signer policies ("2 of my 3 devices")
//! * [`kel`]       – the key event log that defines a `did:kith` identity
//! * [`alias`]     – private, provable aliases of a root identity
//! * [`resolve`]   – public aliases back to their root: WebFinger, DNS and did:web back-links
//! * [`jws`]       – compact JWS helpers
//! * [`session`]   – device → session key grants, session tokens, delegation
//! * [`token`]     – hub-issued access tokens (RFC 9068 profile)
//! * [`totp`]      – RFC 6238 one-time codes (a hub-side factor)
//! * [`vault`]     – crypto-enforced access: skip-ratchet group keys sealed to devices
//! * [`authz`]     – groups (explicit + dynamic), roles and Cedar policy evaluation
//! * [`dag`]       – content-addressed blocks (DAG-JSON CIDs) and a Merkle map
//! * [`pdag`]      – the policy DAG: bundles as blocks, provable slices
//! * [`revoke`]    – signed revocation chains, heartbeats and freshness
//! * [`beacon`]    – public randomness beacons (drand, NIST 2.0) as proof of recency
//! * [`ots`]       – OpenTimestamps proofs (Bitcoin-anchored "existed by")

pub mod alias;
pub mod authz;
pub mod beacon;
pub mod canon;
pub mod dag;
pub mod error;
pub mod jws;
pub mod kel;
pub mod keys;
pub mod ots;
pub mod pdag;
pub mod policy;
pub mod resolve;
pub mod revoke;
pub mod session;
pub mod sshsig;
pub mod token;
pub mod totp;
pub mod util;
pub mod vault;
pub mod webauthn;

pub use error::{Error, Result};
