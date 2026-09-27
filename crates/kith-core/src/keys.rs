//! Keys and signers.
//!
//! A *signer* is anything that can produce a signature Kith can check. Signers are
//! named by a string identifier:
//!
//! * `did:key:z…` – a raw public key (Ed25519, P-256, secp256k1). P-256 keys may be
//!   passkeys (alg `WebAuthn`).
//! * `eip155:<chain>:0x<address>` – an Ethereum account (CAIP-10). EOAs sign with
//!   EIP-191; contract wallets (Safe, Coinbase Smart Wallet) verify through EIP-1271
//!   via a [`ChainVerifier`].
//! * `bip122:<genesis>:<address>` – a Bitcoin address (CAIP-10), BIP-322 (not yet implemented).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest as _, Keccak256};

use crate::util::{b64u, b64u_decode, sha256};
use crate::webauthn::{self, AssertionCheck, WebAuthnSigData};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    P256,
    Secp256k1,
}

impl KeyType {
    pub fn jws_alg(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "EdDSA",
            KeyType::P256 => "ES256",
            KeyType::Secp256k1 => "ES256K",
        }
    }
    fn multicodec(self) -> &'static [u8] {
        match self {
            KeyType::Ed25519 => &[0xed, 0x01],
            KeyType::P256 => &[0x80, 0x24],
            KeyType::Secp256k1 => &[0xe7, 0x01],
        }
    }
}

/// A public key. EC keys are stored SEC1-compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub kty: KeyType,
    pub bytes: Vec<u8>,
}

impl PublicKey {
    pub fn to_did_key(&self) -> String {
        let mut buf = self.kty.multicodec().to_vec();
        buf.extend_from_slice(&self.bytes);
        format!("did:key:z{}", bs58::encode(buf).into_string())
    }

    pub fn from_did_key(did: &str) -> Result<Self> {
        let rest = did
            .strip_prefix("did:key:z")
            .ok_or_else(|| Error::Encoding(format!("not a base58 did:key: {did}")))?;
        let rest = rest.split('#').next().unwrap_or(rest);
        let raw = bs58::decode(rest)
            .into_vec()
            .map_err(|e| Error::Encoding(format!("did:key base58: {e}")))?;
        for kty in [KeyType::Ed25519, KeyType::P256, KeyType::Secp256k1] {
            if let Some(bytes) = raw.strip_prefix(kty.multicodec()) {
                let pk = PublicKey { kty, bytes: bytes.to_vec() };
                pk.validate()?;
                return Ok(pk);
            }
        }
        Err(Error::Unsupported(format!("did:key multicodec in {did}")))
    }

    fn validate(&self) -> Result<()> {
        match self.kty {
            KeyType::Ed25519 => {
                let arr: [u8; 32] = self.bytes.as_slice().try_into().map_err(|_| Error::Encoding("ed25519 key length".into()))?;
                ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| Error::Encoding(e.to_string()))?;
            }
            KeyType::P256 => {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes).map_err(|e| Error::Encoding(e.to_string()))?;
            }
            KeyType::Secp256k1 => {
                k256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes).map_err(|e| Error::Encoding(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Parse a P-256 key from SubjectPublicKeyInfo DER (what the browser's
    /// `AuthenticatorAttestationResponse.getPublicKey()` returns for a passkey).
    pub fn p256_from_spki_der(der: &[u8]) -> Result<Self> {
        use p256::pkcs8::DecodePublicKey;
        let vk = p256::PublicKey::from_public_key_der(der).map_err(|e| Error::Encoding(format!("spki: {e}")))?;
        let point = p256::EncodedPoint::from(vk).compress();
        Ok(PublicKey { kty: KeyType::P256, bytes: point.as_bytes().to_vec() })
    }

    pub fn to_jwk(&self) -> Value {
        match self.kty {
            KeyType::Ed25519 => json!({"kty": "OKP", "crv": "Ed25519", "x": b64u(&self.bytes)}),
            KeyType::P256 => {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes).expect("validated");
                let p = vk.to_encoded_point(false);
                json!({"kty": "EC", "crv": "P-256", "x": b64u(p.x().unwrap()), "y": b64u(p.y().unwrap())})
            }
            KeyType::Secp256k1 => {
                let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes).expect("validated");
                let p = vk.to_encoded_point(false);
                json!({"kty": "EC", "crv": "secp256k1", "x": b64u(p.x().unwrap()), "y": b64u(p.y().unwrap())})
            }
        }
    }

    pub fn from_jwk(jwk: &Value) -> Result<Self> {
        let s = |k: &str| -> Result<Vec<u8>> {
            b64u_decode(jwk.get(k).and_then(Value::as_str).ok_or_else(|| Error::Encoding(format!("jwk missing {k}")))?)
        };
        let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or_default();
        let pk = match crv {
            "Ed25519" => PublicKey { kty: KeyType::Ed25519, bytes: s("x")? },
            "P-256" | "secp256k1" => {
                let mut sec1 = vec![0x04];
                sec1.extend(s("x")?);
                sec1.extend(s("y")?);
                if crv == "P-256" {
                    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| Error::Encoding(e.to_string()))?;
                    PublicKey { kty: KeyType::P256, bytes: vk.to_encoded_point(true).as_bytes().to_vec() }
                } else {
                    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| Error::Encoding(e.to_string()))?;
                    PublicKey { kty: KeyType::Secp256k1, bytes: vk.to_encoded_point(true).as_bytes().to_vec() }
                }
            }
            other => return Err(Error::Unsupported(format!("jwk crv {other}"))),
        };
        pk.validate()?;
        Ok(pk)
    }

    /// RFC 7638 JWK thumbprint (SHA-256, base64url).
    pub fn jwk_thumbprint(&self) -> String {
        let jwk = self.to_jwk();
        let members: &[&str] = match self.kty {
            KeyType::Ed25519 => &["crv", "kty", "x"],
            _ => &["crv", "kty", "x", "y"],
        };
        let obj: serde_json::Map<String, Value> =
            members.iter().map(|m| (m.to_string(), jwk[*m].clone())).collect();
        b64u(sha256(crate::canon::to_canonical(&Value::Object(obj)).expect("jwk is canonicalizable")))
    }

    /// Verify a raw signature. EC signatures may be fixed-size `r||s` or DER.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let bad = |e: String| Error::Signature(e);
        match self.kty {
            KeyType::Ed25519 => {
                let vk = ed25519_dalek::VerifyingKey::from_bytes(self.bytes.as_slice().try_into().map_err(|_| bad("len".into()))?)
                    .map_err(|e| bad(e.to_string()))?;
                let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|e| bad(e.to_string()))?;
                vk.verify_strict(msg, &sig).map_err(|e| bad(e.to_string()))
            }
            KeyType::P256 => {
                use p256::ecdsa::signature::Verifier;
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes).map_err(|e| bad(e.to_string()))?;
                let sig = p256::ecdsa::Signature::from_slice(sig)
                    .or_else(|_| p256::ecdsa::Signature::from_der(sig))
                    .map_err(|e| bad(e.to_string()))?;
                vk.verify(msg, &sig).map_err(|e| bad(e.to_string()))
            }
            KeyType::Secp256k1 => {
                use k256::ecdsa::signature::Verifier;
                let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes).map_err(|e| bad(e.to_string()))?;
                let sig = k256::ecdsa::Signature::from_slice(sig)
                    .or_else(|_| k256::ecdsa::Signature::from_der(sig))
                    .map_err(|e| bad(e.to_string()))?;
                vk.verify(msg, &sig).map_err(|e| bad(e.to_string()))
            }
        }
    }
}

/// A private key held locally.
#[derive(Clone)]
pub enum SecretKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    Secp256k1(k256::ecdsa::SigningKey),
}

impl SecretKey {
    pub fn generate(kty: KeyType) -> Self {
        let mut rng = rand::rngs::OsRng;
        match kty {
            KeyType::Ed25519 => SecretKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng)),
            KeyType::P256 => SecretKey::P256(p256::ecdsa::SigningKey::random(&mut rng)),
            KeyType::Secp256k1 => SecretKey::Secp256k1(k256::ecdsa::SigningKey::random(&mut rng)),
        }
    }

    pub fn kty(&self) -> KeyType {
        match self {
            SecretKey::Ed25519(_) => KeyType::Ed25519,
            SecretKey::P256(_) => KeyType::P256,
            SecretKey::Secp256k1(_) => KeyType::Secp256k1,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SecretKey::Ed25519(k) => k.to_bytes().to_vec(),
            SecretKey::P256(k) => k.to_bytes().to_vec(),
            SecretKey::Secp256k1(k) => k.to_bytes().to_vec(),
        }
    }

    pub fn from_bytes(kty: KeyType, bytes: &[u8]) -> Result<Self> {
        let err = |e: String| Error::Encoding(format!("secret key: {e}"));
        Ok(match kty {
            KeyType::Ed25519 => SecretKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                bytes.try_into().map_err(|_| err("length".into()))?,
            )),
            KeyType::P256 => SecretKey::P256(p256::ecdsa::SigningKey::from_slice(bytes).map_err(|e| err(e.to_string()))?),
            KeyType::Secp256k1 => {
                SecretKey::Secp256k1(k256::ecdsa::SigningKey::from_slice(bytes).map_err(|e| err(e.to_string()))?)
            }
        })
    }

    pub fn public(&self) -> PublicKey {
        match self {
            SecretKey::Ed25519(k) => PublicKey { kty: KeyType::Ed25519, bytes: k.verifying_key().to_bytes().to_vec() },
            SecretKey::P256(k) => PublicKey {
                kty: KeyType::P256,
                bytes: k.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
            },
            SecretKey::Secp256k1(k) => PublicKey {
                kty: KeyType::Secp256k1,
                bytes: k.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
            },
        }
    }

    /// Raw signature: 64 bytes (Ed25519 or ECDSA `r||s`, SHA-256 prehash).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer as _;
        match self {
            SecretKey::Ed25519(k) => k.sign(msg).to_bytes().to_vec(),
            SecretKey::P256(k) => {
                let s: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(k, msg);
                s.to_bytes().to_vec()
            }
            SecretKey::Secp256k1(k) => {
                let s: k256::ecdsa::Signature = k256::ecdsa::signature::Signer::sign(k, msg);
                s.to_bytes().to_vec()
            }
        }
    }

    /// EIP-191 `personal_sign`, returning the 65-byte `r||s||v` signature.
    pub fn sign_eip191(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let SecretKey::Secp256k1(k) = self else {
            return Err(Error::Unsupported("EIP-191 requires a secp256k1 key".into()));
        };
        let hash = eip191_hash(msg);
        let (sig, recid) = k.sign_prehash_recoverable(&hash).map_err(|e| Error::Signature(e.to_string()))?;
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + recid.to_byte());
        Ok(out)
    }
}

pub fn eip191_hash(msg: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(format!("\x19Ethereum Signed Message:\n{}", msg.len()).as_bytes());
    h.update(msg);
    h.finalize().into()
}

/// The Ethereum address (lowercase hex, 0x-prefixed) of a secp256k1 key.
pub fn eth_address(pk: &PublicKey) -> Result<String> {
    if pk.kty != KeyType::Secp256k1 {
        return Err(Error::Unsupported("eth address requires secp256k1".into()));
    }
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk.bytes).map_err(|e| Error::Encoding(e.to_string()))?;
    let uncompressed = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    Ok(format!("0x{}", hex(&hash[12..])))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A parsed signer identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerRef {
    Key(PublicKey),
    Eip155 { chain_id: String, address: String },
    Bip122 { chain: String, address: String },
}

impl SignerRef {
    pub fn parse(id: &str) -> Result<Self> {
        if id.starts_with("did:key:") {
            return Ok(SignerRef::Key(PublicKey::from_did_key(id)?));
        }
        let parts: Vec<&str> = id.splitn(3, ':').collect();
        match parts.as_slice() {
            ["eip155", chain, addr] if addr.len() == 42 && addr.starts_with("0x") => {
                Ok(SignerRef::Eip155 { chain_id: chain.to_string(), address: addr.to_ascii_lowercase() })
            }
            ["bip122", chain, addr] => Ok(SignerRef::Bip122 { chain: chain.to_string(), address: addr.to_string() }),
            _ => Err(Error::Unsupported(format!("signer id {id}"))),
        }
    }
}

/// A detached signature by a named signer, as carried in key events and proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sig {
    pub signer: String,
    /// `Ed25519`, `ES256`, `ES256K`, `WebAuthn`, `EIP191`, `EIP1271`, `BIP322`.
    pub alg: String,
    /// base64url signature bytes.
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebAuthnSigData>,
}

/// Verifies EIP-1271 contract signatures (Safe, Coinbase Smart Wallet, …) by
/// calling `isValidSignature(hash, sig)` on chain. Implementations should pin the
/// block they checked against, since contract signers can change over time.
pub trait ChainVerifier: Send + Sync {
    fn is_valid_signature(&self, chain_id: &str, contract: &str, hash: [u8; 32], sig: &[u8]) -> Result<bool>;
}

#[derive(Default, Clone, Copy)]
pub struct VerifyOptions<'a> {
    pub chain: Option<&'a dyn ChainVerifier>,
}

/// Verify `sig` over `message` for the signer it names.
pub fn verify_sig(sig: &Sig, message: &[u8], opts: &VerifyOptions) -> Result<()> {
    let raw = b64u_decode(&sig.sig)?;
    match (SignerRef::parse(&sig.signer)?, sig.alg.as_str()) {
        (SignerRef::Key(pk), "WebAuthn") => {
            let data = sig.webauthn.as_ref().ok_or_else(|| Error::Signature("WebAuthn sig missing data".into()))?;
            webauthn::verify_assertion(&pk, data, &raw, &AssertionCheck::for_message(message)).map(|_| ())
        }
        (SignerRef::Key(pk), alg) if alg == key_sig_alg(pk.kty) => pk.verify(message, &raw),
        (SignerRef::Eip155 { chain_id, address }, "EIP191" | "EIP1271") => {
            let hash = eip191_hash(message);
            if sig.alg == "EIP191" {
                let recovered = recover_eip191(&hash, &raw)?;
                if recovered == address {
                    return Ok(());
                }
                return Err(Error::Signature(format!("EIP-191 signer mismatch: {recovered} != {address}")));
            }
            let chain = opts
                .chain
                .ok_or_else(|| Error::Unsupported("EIP-1271 verification needs a ChainVerifier (RPC)".into()))?;
            if chain.is_valid_signature(&chain_id, &address, hash, &raw)? {
                Ok(())
            } else {
                Err(Error::Signature("EIP-1271 isValidSignature returned false".into()))
            }
        }
        (SignerRef::Bip122 { .. }, "BIP322") => Err(Error::Unsupported("BIP-322 verification not implemented yet".into())),
        (_, alg) => Err(Error::Signature(format!("alg {alg} does not match signer {}", sig.signer))),
    }
}

pub fn key_sig_alg(kty: KeyType) -> &'static str {
    match kty {
        KeyType::Ed25519 => "Ed25519",
        KeyType::P256 => "ES256",
        KeyType::Secp256k1 => "ES256K",
    }
}

fn recover_eip191(hash: &[u8; 32], sig: &[u8]) -> Result<String> {
    if sig.len() != 65 {
        return Err(Error::Signature("EIP-191 signature must be 65 bytes".into()));
    }
    let v = sig[64];
    let recid = k256::ecdsa::RecoveryId::from_byte(if v >= 27 { v - 27 } else { v })
        .ok_or_else(|| Error::Signature("bad recovery id".into()))?;
    let s = k256::ecdsa::Signature::from_slice(&sig[..64]).map_err(|e| Error::Signature(e.to_string()))?;
    let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(hash, &s, recid).map_err(|e| Error::Signature(e.to_string()))?;
    let pk = PublicKey { kty: KeyType::Secp256k1, bytes: vk.to_encoded_point(true).as_bytes().to_vec() };
    eth_address(&pk)
}

/// How a local signer produces signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// Sign the message bytes directly (identified as `did:key`).
    Raw,
    /// Ethereum `personal_sign` (identified as `eip155:<chain>:<address>`).
    Eip191,
}

/// A signer whose private key is held by this process.
#[derive(Clone)]
pub struct LocalSigner {
    pub id: String,
    pub scheme: Scheme,
    pub secret: SecretKey,
}

impl LocalSigner {
    pub fn generate(kty: KeyType) -> Self {
        let secret = SecretKey::generate(kty);
        LocalSigner { id: secret.public().to_did_key(), scheme: Scheme::Raw, secret }
    }

    /// A simulated Ethereum EOA wallet (secp256k1 + EIP-191) on `chain_id`.
    pub fn generate_eth_wallet(chain_id: u64) -> Self {
        let secret = SecretKey::generate(KeyType::Secp256k1);
        let addr = eth_address(&secret.public()).expect("secp256k1");
        LocalSigner { id: format!("eip155:{chain_id}:{addr}"), scheme: Scheme::Eip191, secret }
    }

    pub fn from_secret(secret: SecretKey, scheme: Scheme, id: Option<String>) -> Result<Self> {
        let id = match (scheme, id) {
            (_, Some(id)) => id,
            (Scheme::Raw, None) => secret.public().to_did_key(),
            (Scheme::Eip191, None) => format!("eip155:1:{}", eth_address(&secret.public())?),
        };
        Ok(LocalSigner { id, scheme, secret })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Sig> {
        let (alg, raw) = match self.scheme {
            Scheme::Raw => (key_sig_alg(self.secret.kty()).to_string(), self.secret.sign(message)),
            Scheme::Eip191 => ("EIP191".to_string(), self.secret.sign_eip191(message)?),
        };
        Ok(Sig { signer: self.id.clone(), alg, sig: b64u(raw), webauthn: None })
    }

    /// Serialized form for a local keystore. **Plaintext** – production keys belong in
    /// the OS keychain, a Secure Enclave/TPM, a hardware key or a wallet.
    pub fn to_json(&self) -> Value {
        json!({"id": self.id, "scheme": self.scheme, "kty": self.secret.kty(), "secret": b64u(self.secret.to_bytes())})
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let kty: KeyType = serde_json::from_value(v["kty"].clone())?;
        let scheme: Scheme = serde_json::from_value(v["scheme"].clone())?;
        let secret = SecretKey::from_bytes(kty, &b64u_decode(v["secret"].as_str().unwrap_or_default())?)?;
        Self::from_secret(secret, scheme, v["id"].as_str().map(String::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_roundtrip_all_types() {
        for kty in [KeyType::Ed25519, KeyType::P256, KeyType::Secp256k1] {
            let s = LocalSigner::generate(kty);
            let pk = PublicKey::from_did_key(&s.id).unwrap();
            assert_eq!(pk, s.secret.public());
            assert_eq!(PublicKey::from_jwk(&pk.to_jwk()).unwrap(), pk);
            let sig = s.sign(b"hello").unwrap();
            verify_sig(&sig, b"hello", &VerifyOptions::default()).unwrap();
            assert!(verify_sig(&sig, b"other", &VerifyOptions::default()).is_err());
        }
    }

    #[test]
    fn ed25519_did_key_prefix() {
        let s = LocalSigner::generate(KeyType::Ed25519);
        assert!(s.id.starts_with("did:key:z6Mk"), "{}", s.id);
        let p = LocalSigner::generate(KeyType::P256);
        assert!(p.id.starts_with("did:key:zDn"), "{}", p.id);
    }

    #[test]
    fn eip191_wallet_signature() {
        let w = LocalSigner::generate_eth_wallet(1);
        assert!(w.id.starts_with("eip155:1:0x"));
        let sig = w.sign(b"sign in").unwrap();
        assert_eq!(sig.alg, "EIP191");
        verify_sig(&sig, b"sign in", &VerifyOptions::default()).unwrap();
        assert!(verify_sig(&sig, b"sign out", &VerifyOptions::default()).is_err());
    }

    #[test]
    fn known_eth_address() {
        // Private key 0x…01 has a well known address.
        let mut sk = [0u8; 32];
        sk[31] = 1;
        let key = SecretKey::from_bytes(KeyType::Secp256k1, &sk).unwrap();
        assert_eq!(eth_address(&key.public()).unwrap(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn eip1271_requires_chain_verifier() {
        let w = LocalSigner::generate_eth_wallet(1);
        let mut sig = w.sign(b"x").unwrap();
        sig.alg = "EIP1271".into();
        assert!(matches!(verify_sig(&sig, b"x", &VerifyOptions::default()), Err(Error::Unsupported(_))));
    }
}
