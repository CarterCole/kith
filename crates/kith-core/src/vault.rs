//! Crypto-enforced access, WNFS style.
//!
//! Cedar policies are *policy-enforced*: a server holds the data and decides. The
//! vault layer is *crypto-enforced*: data is encrypted, and access means holding a
//! key, so it works offline, peer-to-peer and on untrusted storage (IPFS, S3, …).
//!
//! * Every group (or any private node) has a [skip ratchet](https://github.com/fission-codes/skip-ratchet-paper).
//!   Revision `n` of the group's content is encrypted under `key(ratchet_n)`.
//! * A member who joins at revision `n` receives a [`TemporalKey`] (the ratchet
//!   state at `n`). They can derive keys for `n, n+1, …` – jumping ahead in
//!   O(log) – but never for `< n`. Forward access, no history.
//! * A [`snapshot`](GroupKeyring::snapshot_key) key grants exactly one revision.
//! * Removing a member re-keys: a fresh ratchet (new *lineage*) is sealed to the
//!   remaining members only. The removed member keeps what they already had.
//! * Keys are sealed to each member's **device exchange keys** (X25519, listed in
//!   their KEL), so revoking a device automatically excludes it from future shares.
//!
//! Who *should* get keys is still decided by Cedar group membership – including
//! dynamic, proposition-based groups – by a "key steward" (the hub or a group
//! admin's device) that re-evaluates membership and re-seals on change.

use serde::{Deserialize, Serialize};
use skip_ratchet::Ratchet;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::kel::KeyState;
use crate::util::{b64u, b64u_decode};
use crate::{Error, Result};

const X25519_CODEC: [u8; 2] = [0xec, 0x01];

/// A device's X25519 key-agreement key.
#[derive(Clone)]
pub struct ExchangeKey(x25519_dalek::StaticSecret);

impl ExchangeKey {
    pub fn generate() -> Self {
        ExchangeKey(x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng))
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        ExchangeKey(x25519_dalek::StaticSecret::from(b))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn public_did_key(&self) -> String {
        encode_xkey(x25519_dalek::PublicKey::from(&self.0).as_bytes())
    }
}

fn encode_xkey(pk: &[u8; 32]) -> String {
    let mut buf = X25519_CODEC.to_vec();
    buf.extend_from_slice(pk);
    format!("did:key:z{}", bs58::encode(buf).into_string())
}

pub fn decode_xkey(did: &str) -> Result<[u8; 32]> {
    let raw = bs58::decode(did.strip_prefix("did:key:z").ok_or_else(|| Error::Encoding("xkey must be did:key".into()))?)
        .into_vec()
        .map_err(|e| Error::Encoding(e.to_string()))?;
    raw.strip_prefix(&X25519_CODEC)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::Encoding("not an x25519 did:key".into()))
}

/// X25519 + HKDF-SHA256 + ChaCha20-Poly1305 sealed box (an HPKE-base-mode shape;
/// production should switch to RFC 9180 HPKE proper).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBox {
    pub to: String,
    pub epk: String,
    pub nonce: String,
    pub ct: String,
}

fn seal_key(shared: &[u8], epk: &[u8], rpk: &[u8]) -> [u8; 32] {
    let mut salt = epk.to_vec();
    salt.extend_from_slice(rpk);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared).expand(b"kith-seal-v1", &mut out).expect("32 bytes");
    out
}

fn nonce_of(b: &[u8]) -> Result<Nonce> {
    let arr: [u8; 12] = b.try_into().map_err(|_| Error::Encoding("nonce must be 12 bytes".into()))?;
    Ok(Nonce::from(arr))
}

fn random_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut n = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

pub fn seal(to_xkey: &str, aad: &[u8], plaintext: &[u8]) -> Result<SealedBox> {
    let rpk = decode_xkey(to_xkey)?;
    let eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let epk = x25519_dalek::PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(rpk));
    let key = seal_key(shared.as_bytes(), epk.as_bytes(), &rpk);
    let nonce = random_nonce();
    let ct = ChaCha20Poly1305::new(&key.into())
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Encoding("seal failed".into()))?;
    Ok(SealedBox { to: to_xkey.into(), epk: b64u(epk.as_bytes()), nonce: b64u(nonce), ct: b64u(ct) })
}

pub fn open(key: &ExchangeKey, aad: &[u8], sealed: &SealedBox) -> Result<Vec<u8>> {
    let epk: [u8; 32] = b64u_decode(&sealed.epk)?.try_into().map_err(|_| Error::Encoding("epk".into()))?;
    let rpk = *x25519_dalek::PublicKey::from(&key.0).as_bytes();
    let shared = key.0.diffie_hellman(&x25519_dalek::PublicKey::from(epk));
    let k = seal_key(shared.as_bytes(), &epk, &rpk);
    ChaCha20Poly1305::new(&k.into())
        .decrypt(&nonce_of(&b64u_decode(&sealed.nonce)?)?, Payload { msg: &b64u_decode(&sealed.ct)?, aad })
        .map_err(|_| Error::Signature("cannot open sealed box".into()))
}

fn dsi(group: &str, lineage: u32) -> String {
    format!("kith group content key v1 {group} {lineage}")
}

/// The steward's view of a group's key schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupKeyring {
    pub group: String,
    /// Increments on every re-key (member removal / compromise).
    pub lineage: u32,
    pub revision: u64,
    ratchet: Ratchet,
}

/// Access to one lineage of a group from `revision` onward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalKey {
    pub group: String,
    pub lineage: u32,
    pub revision: u64,
    ratchet: Ratchet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub group: String,
    pub lineage: u32,
    pub revision: u64,
    pub nonce: String,
    pub ct: String,
}

fn aad(group: &str, lineage: u32, revision: u64) -> Vec<u8> {
    format!("{group}|{lineage}|{revision}").into_bytes()
}

impl GroupKeyring {
    pub fn new(group: impl Into<String>) -> Self {
        GroupKeyring { group: group.into(), lineage: 0, revision: 0, ratchet: Ratchet::from_rng(&mut rand::rngs::OsRng) }
    }

    /// Advance to a new revision (e.g. each write to the group's content).
    pub fn advance(&mut self) -> u64 {
        self.ratchet.inc();
        self.revision += 1;
        self.revision
    }

    pub fn snapshot_key(&self) -> [u8; 32] {
        self.ratchet.derive_key(&dsi(&self.group, self.lineage)).finalize().into()
    }

    pub fn temporal_key(&self) -> TemporalKey {
        TemporalKey { group: self.group.clone(), lineage: self.lineage, revision: self.revision, ratchet: self.ratchet.clone() }
    }

    /// Start a new lineage that previously shared temporal keys cannot reach.
    pub fn rekey(&mut self) {
        self.lineage += 1;
        self.revision = 0;
        self.ratchet = Ratchet::from_rng(&mut rand::rngs::OsRng);
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Envelope> {
        let nonce = random_nonce();
        let ct = ChaCha20Poly1305::new(&self.snapshot_key().into())
            .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad: &aad(&self.group, self.lineage, self.revision) })
            .map_err(|_| Error::Encoding("encrypt failed".into()))?;
        Ok(Envelope { group: self.group.clone(), lineage: self.lineage, revision: self.revision, nonce: b64u(nonce), ct: b64u(ct) })
    }

    /// Seal the current temporal key to every active device of `member` that has
    /// an exchange key.
    pub fn share_with(&self, member: &KeyState) -> Result<Vec<SealedBox>> {
        let tk = serde_json::to_vec(&self.temporal_key())?;
        member
            .devices
            .values()
            .filter_map(|d| d.xkey.as_deref())
            .map(|x| seal(x, format!("kith-share|{}|{}", self.group, member.did).as_bytes(), &tk))
            .collect()
    }
}

impl TemporalKey {
    /// Key for `revision` of this lineage, or `None` if it is before our access began.
    pub fn key_at(&self, revision: u64) -> Option<[u8; 32]> {
        if revision < self.revision {
            return None;
        }
        let mut r = self.ratchet.clone();
        r.inc_by((revision - self.revision) as usize);
        Some(r.derive_key(&dsi(&self.group, self.lineage)).finalize().into())
    }

    pub fn decrypt(&self, env: &Envelope) -> Result<Vec<u8>> {
        if env.group != self.group || env.lineage != self.lineage {
            return Err(Error::Authz("envelope is from a lineage this key cannot read".into()));
        }
        let key = self.key_at(env.revision).ok_or_else(|| Error::Authz("revision predates access".into()))?;
        ChaCha20Poly1305::new(&key.into())
            .decrypt(&nonce_of(&b64u_decode(&env.nonce)?)?, Payload { msg: &b64u_decode(&env.ct)?, aad: &aad(&env.group, env.lineage, env.revision) })
            .map_err(|_| Error::Signature("decryption failed".into()))
    }

    pub fn open_share(key: &ExchangeKey, group: &str, member_did: &str, sealed: &SealedBox) -> Result<Self> {
        Ok(serde_json::from_slice(&open(key, format!("kith-share|{group}|{member_did}").as_bytes(), sealed)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kel::{tests::fixture, verify_log, EventBody};
    use crate::keys::VerifyOptions;

    #[test]
    fn join_later_sees_future_not_past() {
        let mut ring = GroupKeyring::new("finance");
        let early = ring.encrypt(b"Q1 numbers").unwrap();
        for _ in 0..4 {
            ring.advance();
        }
        let bob = ring.temporal_key(); // Bob joins at revision 4
        let now = ring.encrypt(b"Q2 numbers").unwrap();
        for _ in 0..1000 {
            ring.advance();
        }
        let later = ring.encrypt(b"Q3 numbers").unwrap();
        assert_eq!(bob.decrypt(&now).unwrap(), b"Q2 numbers");
        assert_eq!(bob.decrypt(&later).unwrap(), b"Q3 numbers"); // skips 1000 revisions cheaply
        assert!(bob.decrypt(&early).is_err());
    }

    #[test]
    fn rekey_excludes_removed_member() {
        let mut ring = GroupKeyring::new("finance");
        let mallory = ring.temporal_key();
        ring.rekey();
        let after = ring.encrypt(b"new secrets").unwrap();
        assert!(mallory.decrypt(&after).is_err());
        assert_eq!(ring.temporal_key().decrypt(&after).unwrap(), b"new secrets");
    }

    #[test]
    fn share_to_devices_listed_in_kel() {
        let mut f = fixture();
        let xk = ExchangeKey::generate();
        if let EventBody::Inception { devices, .. } = &mut f.log[0].body {
            devices[0].xkey = Some(xk.public_did_key());
        }
        f.log[0].sigs.clear();
        f.log[0].sign(&f.root).unwrap();
        f.log[0].sign(&f.device).unwrap();
        let member = verify_log(&f.log, &VerifyOptions::default()).unwrap();

        let ring = GroupKeyring::new("finance");
        let boxes = ring.share_with(&member).unwrap();
        assert_eq!(boxes.len(), 1);
        let tk = TemporalKey::open_share(&xk, "finance", &member.did, &boxes[0]).unwrap();
        let env = ring.encrypt(b"hello").unwrap();
        assert_eq!(tk.decrypt(&env).unwrap(), b"hello");
        assert!(TemporalKey::open_share(&ExchangeKey::generate(), "finance", &member.did, &boxes[0]).is_err());
    }
}
