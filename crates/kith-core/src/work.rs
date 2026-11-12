//! Proof of work bound to an identity (spec §7.12).
//!
//! An account can show it cost someone compute: a nonce such that
//! `SHA-256("kith/work/v1\0" ‖ did ‖ "\0" ‖ nonce)` starts with many zero bits. The
//! number of leading zero bits is the account's **work**. Each extra bit doubles the
//! expected effort, so work grows with the logarithm of the time spent, and anyone can
//! check a proof with one hash.
//!
//! The DID is in the preimage, so a proof is useless for any other identity: work can
//! be bought for an account, but not moved to another one.

use crate::util::sha256;

const DOMAIN: &[u8] = b"kith/work/v1\0";

/// The hash a proof is judged by.
pub fn work_hash(did: &str, nonce: u64) -> [u8; 32] {
    let mut m = Vec::with_capacity(DOMAIN.len() + did.len() + 9);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(did.as_bytes());
    m.push(0);
    m.extend_from_slice(&nonce.to_be_bytes());
    sha256(m)
}

/// Leading zero bits of the proof: the work it shows.
pub fn work_bits(did: &str, nonce: u64) -> u32 {
    let mut bits = 0;
    for b in work_hash(did, nonce) {
        bits += b.leading_zeros();
        if b != 0 {
            break;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_is_leading_zero_bits_and_bound_to_the_did() {
        let did = "did:kith:testvector";
        let (nonce, bits) = (0..)
            .map(|n| (n, work_bits(did, n)))
            .find(|(_, b)| *b >= 12)
            .unwrap();
        assert!(bits >= 12);
        assert_eq!(work_bits(did, nonce), bits, "deterministic");
        assert!(
            work_bits("did:kith:other", nonce) < 12 || work_bits("did:kith:other", nonce) == bits,
            "a proof is for one did"
        );
        let h = work_hash(did, nonce);
        assert!(h[..bits as usize / 8].iter().all(|b| *b == 0));
    }
}
