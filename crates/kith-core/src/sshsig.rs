//! OpenSSH `SSHSIG` signatures (spec §1.3.1): an SSH key, including one held by
//! `ssh-agent`, as a Kith signer.
//!
//! The format is OpenSSH's `PROTOCOL.sshsig`, as written by `ssh-keygen -Y sign`.
//! Kith fixes the namespace to `kith` and accepts `ssh-ed25519` and
//! `ecdsa-sha2-nistp256` keys. The signer id is the key's `did:key`; the certificate
//! and key comment play no part.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256, Sha512};

use crate::keys::{KeyType, PublicKey};
use crate::{Error, Result};

/// The only namespace Kith accepts (`ssh-keygen -Y sign -n kith`).
pub const NAMESPACE: &str = "kith";
const MAGIC: &[u8] = b"SSHSIG";
const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----";

fn enc(msg: &str) -> Error {
    Error::Encoding(format!("SSHSIG: {msg}"))
}

/// Reads the SSH wire format (RFC 4251 §5).
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(enc("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn utf8(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.string()?).map_err(|_| enc("string is not UTF-8"))
    }

    fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(enc("trailing data"))
        }
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// A parsed `SSHSIG` blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSig {
    pub public_key: PublicKey,
    pub namespace: String,
    pub hash_algorithm: String,
    reserved: Vec<u8>,
    /// `ssh-ed25519`: 64 bytes. `ecdsa-sha2-nistp256`: fixed-size `r||s`.
    signature: Vec<u8>,
}

impl SshSig {
    /// Parse the binary blob (the contents of the armor, not the armored text).
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let mut r = Reader(blob);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(enc("missing SSHSIG preamble"));
        }
        let version = r.u32()?;
        if version != 1 {
            return Err(Error::Unsupported(format!("SSHSIG version {version}")));
        }
        let public_key = parse_public_key(r.string()?)?;
        let namespace = r.utf8()?.to_string();
        let reserved = r.string()?.to_vec();
        let hash_algorithm = r.utf8()?.to_string();
        let signature = parse_signature(r.string()?, public_key.kty)?;
        r.finish()?;
        Ok(SshSig { public_key, namespace, hash_algorithm, reserved, signature })
    }

    /// Check the signature over `message`, with the Kith namespace.
    pub fn verify(&self, message: &[u8]) -> Result<()> {
        if self.namespace != NAMESPACE {
            return Err(Error::Signature(format!("SSHSIG namespace {:?}, expected {NAMESPACE:?}", self.namespace)));
        }
        if !self.reserved.is_empty() {
            return Err(Error::Signature("SSHSIG reserved field is not empty".into()));
        }
        let data = signed_data(&self.namespace, &self.reserved, &self.hash_algorithm, message)?;
        self.public_key.verify(&data, &self.signature)
    }
}

/// Verify an `SSHSIG` blob over `message` for the signer key `pk` (alg `SSHSIG`).
pub fn verify(pk: &PublicKey, message: &[u8], blob: &[u8]) -> Result<()> {
    let sig = SshSig::parse(blob)?;
    if &sig.public_key != pk {
        return Err(Error::Signature("SSHSIG public key is not the signer's key".into()));
    }
    sig.verify(message)
}

/// The bytes the SSH key signs: the preamble, namespace, reserved field, hash
/// algorithm and the hash of the message.
fn signed_data(namespace: &str, reserved: &[u8], hash_algorithm: &str, message: &[u8]) -> Result<Vec<u8>> {
    let hash = match hash_algorithm {
        "sha256" => Sha256::digest(message).to_vec(),
        "sha512" => Sha512::digest(message).to_vec(),
        other => return Err(Error::Unsupported(format!("SSHSIG hash algorithm {other}"))),
    };
    let mut out = MAGIC.to_vec();
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, reserved);
    put_string(&mut out, hash_algorithm.as_bytes());
    put_string(&mut out, &hash);
    Ok(out)
}

/// Parse an SSH public key blob. P-256 points are stored compressed, like `did:key`.
fn parse_public_key(blob: &[u8]) -> Result<PublicKey> {
    let mut r = Reader(blob);
    let pk = match r.utf8()? {
        "ssh-ed25519" => PublicKey { kty: KeyType::Ed25519, bytes: r.string()?.to_vec() },
        "ecdsa-sha2-nistp256" => {
            if r.string()? != b"nistp256" {
                return Err(enc("curve name does not match the key type"));
            }
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(r.string()?).map_err(|e| enc(&e.to_string()))?;
            PublicKey { kty: KeyType::P256, bytes: vk.to_encoded_point(true).as_bytes().to_vec() }
        }
        other => return Err(Error::Unsupported(format!("SSH key type {other}"))),
    };
    r.finish()?;
    pk.validate()?;
    Ok(pk)
}

/// Parse an SSH signature blob into the raw form [`PublicKey::verify`] takes.
fn parse_signature(blob: &[u8], kty: KeyType) -> Result<Vec<u8>> {
    let mut r = Reader(blob);
    let sig = match (kty, r.utf8()?) {
        (KeyType::Ed25519, "ssh-ed25519") => {
            let s = r.string()?;
            if s.len() != 64 {
                return Err(enc("ed25519 signature length"));
            }
            s.to_vec()
        }
        (KeyType::P256, "ecdsa-sha2-nistp256") => {
            let mut inner = Reader(r.string()?);
            let mut rs = Vec::with_capacity(64);
            rs.extend(mpint32(inner.string()?)?);
            rs.extend(mpint32(inner.string()?)?);
            inner.finish()?;
            rs
        }
        (_, other) => return Err(Error::Signature(format!("SSH signature type {other} does not match the key"))),
    };
    r.finish()?;
    Ok(sig)
}

/// A non-negative SSH `mpint` as 32 big-endian bytes.
fn mpint32(b: &[u8]) -> Result<[u8; 32]> {
    if b.first().is_some_and(|x| x & 0x80 != 0) {
        return Err(enc("negative mpint"));
    }
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    let b = &b[start..];
    if b.len() > 32 {
        return Err(enc("mpint too large"));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

/// The `did:key` of an OpenSSH public key line (`ssh-ed25519 AAAA… comment`).
pub fn did_key_from_openssh(line: &str) -> Result<String> {
    let mut parts = line.split_whitespace();
    let (Some(kind), Some(b64)) = (parts.next(), parts.next()) else {
        return Err(enc("expected `<type> <base64> [comment]`"));
    };
    let blob = STANDARD.decode(b64).map_err(|e| enc(&format!("base64: {e}")))?;
    if Reader(&blob).utf8()? != kind {
        return Err(enc("key type does not match the key blob"));
    }
    Ok(parse_public_key(&blob)?.to_did_key())
}

/// The binary blob inside an armored `-----BEGIN SSH SIGNATURE-----` block.
pub fn dearmor(text: &str) -> Result<Vec<u8>> {
    let body = text
        .trim()
        .strip_prefix(ARMOR_BEGIN)
        .and_then(|s| s.strip_suffix(ARMOR_END))
        .ok_or_else(|| enc("not an armored SSH signature"))?;
    let b64: String = body.split_whitespace().collect();
    STANDARD.decode(b64).map_err(|e| enc(&format!("base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{verify_sig, Sig, VerifyOptions};
    use crate::util::{b64u, b64u_decode};
    use serde_json::Value;

    fn cases() -> Vec<Value> {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/sshsig.json")).unwrap();
        v["cases"].as_array().unwrap().clone()
    }

    fn sig_of(c: &Value) -> Sig {
        Sig {
            signer: c["signer"].as_str().unwrap().into(),
            alg: "SSHSIG".into(),
            sig: c["sig"].as_str().unwrap().into(),
            webauthn: None,
        }
    }

    #[test]
    fn vectors() {
        let cases = cases();
        assert!(cases.iter().filter(|c| c["valid"] == true).count() >= 4);
        for c in &cases {
            let name = c["name"].as_str().unwrap();
            let got = verify_sig(&sig_of(c), c["message"].as_str().unwrap().as_bytes(), &VerifyOptions::default());
            assert_eq!(got.is_ok(), c["valid"].as_bool().unwrap(), "{name}: {got:?}");
            // `sig` is exactly what ssh-keygen armored.
            assert_eq!(b64u(dearmor(c["armored"].as_str().unwrap()).unwrap()), c["sig"].as_str().unwrap(), "{name}");
        }
    }

    /// ssh-keygen checks structure and the signature, not who signed or which key
    /// types Kith allows. Kith must reject those cases for its own reasons.
    #[test]
    fn rejects_what_ssh_keygen_accepts() {
        let disagreements: Vec<Value> = cases().into_iter().filter(|c| c["ssh_keygen"] == true && c["valid"] == false).collect();
        assert_eq!(disagreements.len(), 2);
        for c in &disagreements {
            let err = verify_sig(&sig_of(c), c["message"].as_str().unwrap().as_bytes(), &VerifyOptions::default()).unwrap_err();
            match c["name"].as_str().unwrap() {
                "wrong-signer" => assert!(err.to_string().contains("not the signer's key"), "{err}"),
                "p384-unsupported" => assert!(matches!(err, Error::Unsupported(_)), "{err}"),
                other => panic!("unexpected disagreement with ssh-keygen: {other}"),
            }
        }
    }

    #[test]
    fn openssh_public_keys_give_the_signer_did_key() {
        for c in cases().iter().filter(|c| c["valid"] == true) {
            let did = did_key_from_openssh(c["public_key"].as_str().unwrap()).unwrap();
            assert_eq!(did, c["signer"].as_str().unwrap(), "{}", c["name"]);
        }
    }

    #[test]
    fn truncated_blobs_are_errors_not_panics() {
        for c in cases().iter().filter(|c| c["valid"] == true) {
            let blob = b64u_decode(c["sig"].as_str().unwrap()).unwrap();
            SshSig::parse(&blob).unwrap();
            for n in 0..blob.len() {
                assert!(SshSig::parse(&blob[..n]).is_err(), "{} cut at {n}", c["name"]);
            }
        }
    }

    #[test]
    fn other_algs_do_not_accept_sshsig_blobs() {
        let c = cases().into_iter().find(|c| c["valid"] == true).unwrap();
        let mut sig = sig_of(&c);
        sig.alg = "Ed25519".into();
        assert!(verify_sig(&sig, c["message"].as_str().unwrap().as_bytes(), &VerifyOptions::default()).is_err());
    }
}
