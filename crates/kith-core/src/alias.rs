//! Private aliases: unlinkable public identities you can prove are yours, whenever
//! you choose, to whomever you choose.
//!
//! 1. Generate an alias key pair (`did:key`). Use the alias anywhere (it can hold
//!    its own sessions, sign in to sites, etc.) – nothing public links it to you.
//! 2. Commit `H("kith-alias-v1", root, alias, salt)` into your KEL (`alias_commit`).
//!    The KEL shows *that* you committed to something at a point in time, not what.
//! 3. To prove the link, reveal `(alias, salt)` and sign a fresh, audience-bound
//!    statement with the alias key. The verifier recomputes the commitment and
//!    finds it in the root's KEL. Both sides have now consented to the link.
//!
//! Public aliases (email, domain, GitHub, ENS…) use `alias_link` events instead,
//! with a back-link on the alias side (Keybase / Keyoxide style).

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::kel::KeyState;
use crate::keys::{verify_sig, KeyType, LocalSigner, Sig, VerifyOptions};
use crate::util::{b64u, now, random_id, sha256};
use crate::{Error, Result};

pub fn commitment(root: &str, alias: &str, salt: &str) -> String {
    let v = json!({"t": "kith-alias-v1", "root": root, "alias": alias, "salt": salt});
    b64u(sha256(crate::canon::to_canonical(&v).expect("canonical")))
}

#[derive(Clone)]
pub struct PrivateAlias {
    pub label: String,
    pub signer: LocalSigner,
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasProof {
    pub v: u32,
    pub root: String,
    pub alias: String,
    pub salt: String,
    /// KEL sequence number of the `alias_commit` event.
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub iat: i64,
    pub sig: Sig,
}

fn proof_message(root: &str, alias: &str, aud: Option<&str>, nonce: Option<&str>, iat: i64) -> Vec<u8> {
    format!(
        "kith alias link v1\nroot: {root}\nalias: {alias}\naud: {}\nnonce: {}\niat: {iat}",
        aud.unwrap_or("*"),
        nonce.unwrap_or("-")
    )
    .into_bytes()
}

impl PrivateAlias {
    pub fn generate(label: impl Into<String>) -> Self {
        PrivateAlias { label: label.into(), signer: LocalSigner::generate(KeyType::Ed25519), salt: random_id() }
    }

    pub fn id(&self) -> &str {
        &self.signer.id
    }

    pub fn commitment(&self, root: &str) -> String {
        commitment(root, self.id(), &self.salt)
    }

    pub fn prove(&self, root: &str, seq: u64, aud: Option<String>, nonce: Option<String>) -> Result<AliasProof> {
        let iat = now();
        let sig = self.signer.sign(&proof_message(root, self.id(), aud.as_deref(), nonce.as_deref(), iat))?;
        Ok(AliasProof { v: 1, root: root.into(), alias: self.id().into(), salt: self.salt.clone(), seq, aud, nonce, iat, sig })
    }
}

/// Verify an alias proof against the root identity's current key state.
pub fn verify_alias_proof(proof: &AliasProof, root: &KeyState, aud: Option<&str>, nonce: Option<&str>) -> Result<()> {
    if proof.root != root.did {
        return Err(Error::Signature("proof is for a different root".into()));
    }
    if aud.is_some() && proof.aud.as_deref() != aud {
        return Err(Error::Signature("alias proof audience mismatch".into()));
    }
    if nonce.is_some() && proof.nonce.as_deref() != nonce {
        return Err(Error::Signature("alias proof nonce mismatch".into()));
    }
    let c = commitment(&proof.root, &proof.alias, &proof.salt);
    if !root.alias_commitments.iter().any(|a| a.seq == proof.seq && a.commitment == c) {
        return Err(Error::NotFound("alias commitment not in root KEL".into()));
    }
    if proof.sig.signer != proof.alias {
        return Err(Error::Signature("proof must be signed by the alias key".into()));
    }
    verify_sig(&proof.sig, &proof_message(&proof.root, &proof.alias, proof.aud.as_deref(), proof.nonce.as_deref(), proof.iat), &VerifyOptions::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kel::{next_event, tests::fixture, verify_log, EventBody};

    #[test]
    fn prove_private_alias() {
        let mut f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let alias = PrivateAlias::generate("gaming");
        let mut ev = next_event(&st, EventBody::AliasCommit { commitment: alias.commitment(&st.did) });
        ev.sign(&f.device).unwrap(); // a device with the `alias` cap may commit
        f.log.push(ev);
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let proof = alias.prove(&st.did, 1, Some("https://shop.example".into()), Some("n1".into())).unwrap();
        verify_alias_proof(&proof, &st, Some("https://shop.example"), Some("n1")).unwrap();
        assert!(verify_alias_proof(&proof, &st, Some("https://other.example"), None).is_err());
        let mut forged = proof.clone();
        forged.salt = "guess".into();
        assert!(verify_alias_proof(&forged, &st, None, None).is_err());
    }
}
