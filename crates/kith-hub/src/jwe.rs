//! JWE compact serialization (RFC 7516), enough to encrypt an ID token to a client:
//! `RSA-OAEP-256` or `ECDH-ES` (P-256) key management with `A256GCM` content
//! encryption.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand::RngCore;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Oaep, RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use kith_core::util::{b64u, b64u_decode};

pub const ALGS: [&str; 2] = ["RSA-OAEP-256", "ECDH-ES"];
pub const ENCS: [&str; 1] = ["A256GCM"];
const MIN_RSA_BITS: usize = 2048;

/// A client's public encryption key, with its `kid`.
#[derive(Debug)]
pub enum Recipient {
    Rsa(RsaPublicKey, Option<String>),
    P256(p256::PublicKey, Option<String>),
}

/// The private half, for a client decrypting what [`encrypt`] made.
pub enum Secret {
    Rsa(Box<RsaPrivateKey>),
    P256(p256::SecretKey),
}

fn bytes(k: &Value, name: &str) -> anyhow::Result<Vec<u8>> {
    let s = k[name].as_str().ok_or_else(|| anyhow::anyhow!("JWK has no {name}"))?;
    Ok(b64u_decode(s)?)
}

/// The key in `jwks` to encrypt to for `alg`: the first of the right type that is
/// not marked for signing or for another algorithm.
pub fn recipient_key(jwks: &Value, alg: &str, enc: &str) -> anyhow::Result<Recipient> {
    if !ENCS.contains(&enc) {
        anyhow::bail!("id_token_encrypted_response_enc must be A256GCM");
    }
    let (kty, crv) = match alg {
        "RSA-OAEP-256" => ("RSA", Value::Null),
        "ECDH-ES" => ("EC", json!("P-256")),
        _ => anyhow::bail!("id_token_encrypted_response_alg must be RSA-OAEP-256 or ECDH-ES"),
    };
    let fits = |k: &&Value| k["kty"] == kty && (crv.is_null() || k["crv"] == crv) && k["use"] != "sig" && (k["alg"].is_null() || k["alg"] == alg);
    let k = jwks["keys"].as_array().and_then(|keys| keys.iter().find(fits)).ok_or_else(|| anyhow::anyhow!("jwks has no {kty} key to encrypt ID tokens to with {alg}"))?;
    let kid = k["kid"].as_str().map(String::from);
    if kty == "RSA" {
        let key = RsaPublicKey::new(BigUint::from_bytes_be(&bytes(k, "n")?), BigUint::from_bytes_be(&bytes(k, "e")?))?;
        if key.n().bits() < MIN_RSA_BITS {
            anyhow::bail!("RSA encryption keys must be at least {MIN_RSA_BITS} bits");
        }
        return Ok(Recipient::Rsa(key, kid));
    }
    let (x, y) = (bytes(k, "x")?, bytes(k, "y")?);
    if x.len() != 32 || y.len() != 32 {
        anyhow::bail!("malformed P-256 key");
    }
    let point = p256::EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
    let key = Option::<p256::PublicKey>::from(p256::PublicKey::from_encoded_point(&point)).ok_or_else(|| anyhow::anyhow!("P-256 key is not on the curve"))?;
    Ok(Recipient::P256(key, kid))
}

/// Concat KDF (NIST SP 800-56A, as RFC 7518 §4.6.2 uses it) for a 256-bit key with
/// empty `apu` and `apv`. One round of SHA-256 is exactly the key.
fn concat_kdf(z: &[u8], enc: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(1u32.to_be_bytes());
    h.update(z);
    h.update((enc.len() as u32).to_be_bytes());
    h.update(enc.as_bytes());
    h.update(0u32.to_be_bytes()); // apu
    h.update(0u32.to_be_bytes()); // apv
    h.update(256u32.to_be_bytes());
    h.finalize().into()
}

/// Encrypt `plaintext` (a signed JWT) to `to`.
pub fn encrypt(to: &Recipient, plaintext: &[u8]) -> anyhow::Result<String> {
    let mut rng = rand::rngs::OsRng;
    let mut header = json!({"enc": "A256GCM", "cty": "JWT"});
    let (cek, encrypted_key) = match to {
        Recipient::Rsa(key, kid) => {
            header["alg"] = json!("RSA-OAEP-256");
            header["kid"] = json!(kid);
            let mut cek = [0u8; 32];
            rng.fill_bytes(&mut cek);
            (cek, key.encrypt(&mut rng, Oaep::new::<Sha256>(), &cek)?)
        }
        Recipient::P256(key, kid) => {
            header["alg"] = json!("ECDH-ES");
            header["kid"] = json!(kid);
            let eph = p256::ecdh::EphemeralSecret::random(&mut rng);
            let point = eph.public_key().to_encoded_point(false);
            let (x, y) = point.x().zip(point.y()).ok_or_else(|| anyhow::anyhow!("ephemeral key has no coordinates"))?;
            header["epk"] = json!({"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y)});
            // Direct agreement: the derived key is the content key, and no key is sent.
            (concat_kdf(eph.diffie_hellman(key).raw_secret_bytes(), "A256GCM"), vec![])
        }
    };
    if header["kid"].is_null() {
        header.as_object_mut().expect("object").remove("kid");
    }
    let protected = b64u(serde_json::to_vec(&header)?);
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);
    let sealed = Aes256Gcm::new(&cek.into())
        .encrypt(&Nonce::from(iv), Payload { msg: plaintext, aad: protected.as_bytes() })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    Ok(format!("{protected}.{}.{}.{}.{}", b64u(encrypted_key), b64u(iv), b64u(ciphertext), b64u(tag)))
}

/// Decrypt a compact JWE made by [`encrypt`] (or by any client using the same
/// algorithms). The hub itself never needs this; relying parties and tests do.
pub fn decrypt(jwe: &str, key: &Secret) -> anyhow::Result<Vec<u8>> {
    let parts: Vec<&str> = jwe.split('.').collect();
    let [protected, encrypted_key, iv, ciphertext, tag] = parts[..] else {
        anyhow::bail!("a compact JWE has five parts");
    };
    let header: Value = serde_json::from_slice(&b64u_decode(protected)?)?;
    if header["enc"] != "A256GCM" {
        anyhow::bail!("unsupported enc");
    }
    let cek: [u8; 32] = match (header["alg"].as_str(), key) {
        (Some("RSA-OAEP-256"), Secret::Rsa(k)) => {
            k.decrypt(Oaep::new::<Sha256>(), &b64u_decode(encrypted_key)?)?.try_into().map_err(|_| anyhow::anyhow!("content key has the wrong length"))?
        }
        (Some("ECDH-ES"), Secret::P256(k)) => {
            let (x, y) = (bytes(&header["epk"], "x")?, bytes(&header["epk"], "y")?);
            if x.len() != 32 || y.len() != 32 {
                anyhow::bail!("malformed epk");
            }
            let point = p256::EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
            let epk = Option::<p256::PublicKey>::from(p256::PublicKey::from_encoded_point(&point)).ok_or_else(|| anyhow::anyhow!("epk is not on the curve"))?;
            concat_kdf(p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), epk.as_affine()).raw_secret_bytes(), "A256GCM")
        }
        _ => anyhow::bail!("alg does not match the key"),
    };
    let mut sealed = b64u_decode(ciphertext)?;
    sealed.extend(b64u_decode(tag)?);
    let iv: [u8; 12] = b64u_decode(iv)?.try_into().map_err(|_| anyhow::anyhow!("malformed iv"))?;
    Aes256Gcm::new(&cek.into())
        .decrypt(&Nonce::from(iv), Payload { msg: &sealed, aad: protected.as_bytes() })
        .map_err(|_| anyhow::anyhow!("decryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p256_jwk(sk: &p256::SecretKey) -> Value {
        let p = sk.public_key().to_encoded_point(false);
        json!({"kty": "EC", "crv": "P-256", "x": b64u(p.x().unwrap()), "y": b64u(p.y().unwrap()), "kid": "ec-1", "use": "enc"})
    }

    #[test]
    fn round_trips() {
        let rsa = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let ec = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let sig_only = json!({"kty": "RSA", "n": b64u(rsa.n().to_bytes_be()), "e": b64u(rsa.e().to_bytes_be()), "use": "sig"});
        let rsa_jwk = json!({"kty": "RSA", "n": b64u(rsa.n().to_bytes_be()), "e": b64u(rsa.e().to_bytes_be()), "kid": "rsa-1"});
        let jwks = json!({"keys": [sig_only, rsa_jwk, p256_jwk(&ec)]});

        for (alg, secret) in [("RSA-OAEP-256", Secret::Rsa(Box::new(rsa.clone()))), ("ECDH-ES", Secret::P256(ec.clone()))] {
            let to = recipient_key(&jwks, alg, "A256GCM").unwrap();
            let jwe = encrypt(&to, b"a.signed.jwt").unwrap();
            let header: Value = serde_json::from_slice(&b64u_decode(jwe.split('.').next().unwrap()).unwrap()).unwrap();
            assert_eq!((header["alg"].as_str(), header["enc"].as_str(), header["cty"].as_str()), (Some(alg), Some("A256GCM"), Some("JWT")));
            assert_eq!(header["kid"], if alg == "ECDH-ES" { "ec-1" } else { "rsa-1" });
            assert_eq!(decrypt(&jwe, &secret).unwrap(), b"a.signed.jwt");

            // The header is authenticated, and so is the ciphertext.
            let mut parts: Vec<String> = jwe.split('.').map(String::from).collect();
            parts[3] = b64u(b"tampered....");
            assert!(decrypt(&parts.join("."), &secret).is_err());
        }
        let other = Secret::P256(p256::SecretKey::random(&mut rand::rngs::OsRng));
        assert!(decrypt(&encrypt(&recipient_key(&jwks, "ECDH-ES", "A256GCM").unwrap(), b"x").unwrap(), &other).is_err());
    }

    #[test]
    fn key_selection() {
        let ec = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let jwks = json!({"keys": [p256_jwk(&ec)]});
        assert!(recipient_key(&jwks, "RSA-OAEP-256", "A256GCM").is_err());
        assert!(recipient_key(&jwks, "ECDH-ES", "A128CBC-HS256").is_err());
        assert!(recipient_key(&jwks, "RSA1_5", "A256GCM").is_err());
        assert!(recipient_key(&Value::Null, "ECDH-ES", "A256GCM").is_err());
        let small = RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let weak = json!({"keys": [{"kty": "RSA", "n": b64u(small.n().to_bytes_be()), "e": b64u(small.e().to_bytes_be())}]});
        assert!(recipient_key(&weak, "RSA-OAEP-256", "A256GCM").is_err());
    }
}
