//! Signer policies: who must sign for an action to count.
//!
//! ```json
//! "did:key:z6Mk…"                                     // one signer
//! {"threshold": 2, "of": ["did:key:…", "did:key:…", "eip155:1:0x…"]}
//! {"threshold": 1, "of": [{"threshold": 2, "of": [...]}, "did:key:…"]}   // nested
//! ```
//!
//! Policies nest, so "my Ledger, OR any 2 of my 3 passkeys" is expressible. This is
//! the same shape as Bitcoin miniscript `thresh()` or a Safe multisig.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::util::{b64u, sha256};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignerPolicy {
    Signer(String),
    Threshold { threshold: usize, of: Vec<SignerPolicy> },
}

impl SignerPolicy {
    pub fn single(id: impl Into<String>) -> Self {
        SignerPolicy::Signer(id.into())
    }

    pub fn threshold(k: usize, of: Vec<SignerPolicy>) -> Self {
        SignerPolicy::Threshold { threshold: k, of }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            SignerPolicy::Signer(id) => crate::keys::SignerRef::parse(id).map(|_| ()),
            SignerPolicy::Threshold { threshold, of } => {
                if *threshold == 0 || *threshold > of.len() {
                    return Err(Error::Kel(format!("threshold {threshold} of {} is unsatisfiable", of.len())));
                }
                of.iter().try_for_each(|p| p.validate())
            }
        }
    }

    /// Every signer id mentioned anywhere in the policy.
    pub fn signers(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.collect(&mut out);
        out
    }

    fn collect(&self, out: &mut BTreeSet<String>) {
        match self {
            SignerPolicy::Signer(id) => {
                out.insert(id.clone());
            }
            SignerPolicy::Threshold { of, .. } => of.iter().for_each(|p| p.collect(out)),
        }
    }

    pub fn is_satisfied_by(&self, signed: &BTreeSet<String>) -> bool {
        match self {
            SignerPolicy::Signer(id) => signed.contains(id),
            SignerPolicy::Threshold { threshold, of } => {
                of.iter().filter(|p| p.is_satisfied_by(signed)).count() >= *threshold
            }
        }
    }

    /// Commitment used for pre-rotation: `base64url(SHA-256(canonical JSON))`.
    pub fn digest(&self) -> String {
        b64u(sha256(crate::canon::canonical_of(self).expect("policy is canonicalizable")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyType, LocalSigner};

    #[test]
    fn nested_thresholds() {
        let a = LocalSigner::generate(KeyType::Ed25519).id;
        let b = LocalSigner::generate(KeyType::Ed25519).id;
        let c = LocalSigner::generate(KeyType::P256).id;
        let ledger = LocalSigner::generate_eth_wallet(1).id;
        // ledger OR 2-of-{a,b,c}
        let p = SignerPolicy::threshold(
            1,
            vec![
                SignerPolicy::single(&ledger),
                SignerPolicy::threshold(2, vec![SignerPolicy::single(&a), SignerPolicy::single(&b), SignerPolicy::single(&c)]),
            ],
        );
        p.validate().unwrap();
        let set = |ids: &[&String]| ids.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        assert!(p.is_satisfied_by(&set(&[&ledger])));
        assert!(p.is_satisfied_by(&set(&[&a, &c])));
        assert!(!p.is_satisfied_by(&set(&[&b])));
        assert_eq!(p.signers().len(), 4);
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<SignerPolicy>(&json).unwrap(), p);
    }

    #[test]
    fn rejects_bad_threshold() {
        let a = LocalSigner::generate(KeyType::Ed25519).id;
        assert!(SignerPolicy::threshold(2, vec![SignerPolicy::single(a)]).validate().is_err());
    }
}
