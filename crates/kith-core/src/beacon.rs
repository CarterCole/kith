//! Public randomness beacons as proof of freshness (spec §8.8).
//!
//! A beacon value is unpredictable until it is published, so a heartbeat that
//! embeds one was signed *after* that moment, even if the signer's clock lies.
//! Verifiers turn a beacon value into the time it was published.
//!
//! * **drand** (League of Entropy): BLS12-381 threshold signatures. Quicknet is
//!   unchained, signs `SHA-256(round as u64 big-endian)` on G1, one round per 3 s.
//! * **NIST 2.0 format** (NIST, Inmetro/Brazil): RSA PKCS#1 v1.5 / SHA-512 over a
//!   length-prefixed serialization of the pulse, one pulse per 60 s. The signing
//!   certificate is named by `certificateId = SHA-512(DER)` and fetched from the
//!   beacon's own origin; only origins on an allowlist are accepted.

use std::collections::BTreeMap;

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

use crate::{Error, Result};

/// drand quicknet: unchained BLS on G1, a round every 3 s.
pub const QUICKNET_CHAIN: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
pub const QUICKNET_PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
pub const QUICKNET_GENESIS: i64 = 1692803367;
pub const QUICKNET_PERIOD: i64 = 3;
/// RFC 9380 hash-to-G1 domain separation tag used by quicknet.
pub const DRAND_G1_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Beacons in the NIST 2.0 format whose pulses are accepted, by `uri` prefix.
pub const NIST2_ORIGINS: &[&str] = &["https://beacon.nist.gov/beacon/2.0", "https://beacon.inmetro.gov.br/beacon/2.1", "https://beacon.inmetro.gov.br/beacon/2.0"];

/// Inmetro serves no certificates (its endpoint answers 400); this is the one its
/// open-source beacon hard-codes. SHA-512(DER) = its certificateId `04c5dc3b…`.
const INMETRO_CERT: &str = include_str!("../certs/inmetro-04c5dc3b.pem");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BeaconValue {
    /// A drand round (League of Entropy), e.g. quicknet: a new round every 3 s.
    Drand {
        /// Chain hash (hex).
        chain: String,
        round: u64,
        /// BLS signature for the round (hex).
        signature: String,
    },
    /// A pulse in the NIST Interoperable Randomness Beacon 2.0 format, as published
    /// by NIST and by the Brazilian beacon. A new pulse every 60 s.
    Nist2 { pulse: Value },
}

/// Turns a beacon value into the Unix time it was published, or fails.
pub trait BeaconVerifier {
    fn verify(&self, value: &BeaconValue) -> Result<i64>;
}

/// Accepts no beacons: heartbeats only count through their signed timestamp, and
/// only when the freshness policy doesn't require a beacon.
pub struct NoBeacons;

impl BeaconVerifier for NoBeacons {
    fn verify(&self, _: &BeaconValue) -> Result<i64> {
        Err(Error::Unsupported("no beacon verifier configured".into()))
    }
}

#[derive(Debug, Clone)]
pub struct DrandChain {
    pub public_key: G2Affine,
    pub genesis: i64,
    pub period: i64,
}

impl DrandChain {
    pub fn new(public_key_hex: &str, genesis: i64, period: i64) -> Result<Self> {
        let pk: [u8; 96] = hex(public_key_hex)?.try_into().map_err(|_| Error::Encoding("drand public key must be 96 bytes".into()))?;
        let public_key = Option::from(G2Affine::from_compressed(&pk)).ok_or_else(|| Error::Encoding("drand public key is not a G2 point".into()))?;
        Ok(DrandChain { public_key, genesis, period })
    }

    pub fn quicknet() -> Self {
        Self::new(QUICKNET_PUBLIC_KEY, QUICKNET_GENESIS, QUICKNET_PERIOD).expect("quicknet key is valid")
    }

    /// Verify an unchained G1 signature for `round`; returns the round's time.
    pub fn verify(&self, round: u64, signature_hex: &str) -> Result<i64> {
        let sig: [u8; 48] = hex(signature_hex)?.try_into().map_err(|_| Error::Signature("drand signature must be 48 bytes".into()))?;
        let sig = Option::<G1Affine>::from(G1Affine::from_compressed(&sig)).ok_or_else(|| Error::Signature("drand signature is not a G1 point".into()))?;
        let msg: [u8; 32] = Sha256::digest(round.to_be_bytes()).into();
        let h = G1Affine::from(<G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], DRAND_G1_DST));
        if round == 0 || pairing(&sig, &G2Affine::generator()) != pairing(&h, &self.public_key) {
            return Err(Error::Signature(format!("drand round {round}: bad signature")));
        }
        Ok(self.genesis + (round as i64 - 1) * self.period)
    }
}

/// The standard verifiers: drand chains by hash, and NIST 2.0-format beacons by
/// origin with certificates pinned by id.
#[derive(Debug, Clone)]
pub struct Verifiers {
    pub drand: BTreeMap<String, DrandChain>,
    pub nist_origins: Vec<String>,
    /// certificateId (lower-case hex) → key.
    nist_keys: BTreeMap<String, RsaPublicKey>,
}

impl Default for Verifiers {
    fn default() -> Self {
        let mut v = Verifiers {
            drand: [(QUICKNET_CHAIN.to_string(), DrandChain::quicknet())].into_iter().collect(),
            nist_origins: NIST2_ORIGINS.iter().map(|s| s.to_string()).collect(),
            nist_keys: BTreeMap::new(),
        };
        v.add_nist_certificate(INMETRO_CERT).expect("pinned Inmetro certificate parses");
        v
    }
}

impl Verifiers {
    /// Where to fetch the certificate a pulse names: `{base}/certificate/{id}`.
    /// Errors if the pulse is not from an allowed origin.
    pub fn nist_certificate_url(&self, pulse: &Value) -> Result<(String, String)> {
        let uri = pulse["uri"].as_str().unwrap_or_default();
        let base = self.nist_origins.iter().find(|o| uri.starts_with(&format!("{o}/"))).ok_or_else(|| Error::Unsupported(format!("beacon origin of {uri:?}")))?;
        Ok((base.clone(), pulse["certificateId"].as_str().unwrap_or_default().to_ascii_lowercase()))
    }

    /// Add a certificate (PEM, as beacons serve it; leniently parsed). Its id is
    /// SHA-512 of its DER, so a certificate can't be substituted for another.
    pub fn add_nist_certificate(&mut self, pem: &str) -> Result<String> {
        let der = pem_to_der(pem)?;
        let id = to_hex(&Sha512::digest(&der));
        let spki = spki_of_certificate(&der)?;
        let key = RsaPublicKey::from_public_key_der(spki).map_err(|e| Error::Encoding(format!("certificate key: {e}")))?;
        self.nist_keys.insert(id.clone(), key);
        Ok(id)
    }

    pub fn has_nist_certificate(&self, id: &str) -> bool {
        self.nist_keys.contains_key(&id.to_ascii_lowercase())
    }

    fn verify_nist2(&self, p: &Value) -> Result<i64> {
        self.nist_certificate_url(p)?;
        if p["cipherSuite"].as_u64() != Some(0) {
            return Err(Error::Unsupported(format!("NIST beacon cipher suite {}", p["cipherSuite"])));
        }
        let id = p["certificateId"].as_str().unwrap_or_default().to_ascii_lowercase();
        let key = self.nist_keys.get(&id).ok_or_else(|| Error::NotFound(format!("beacon certificate {id}")))?;
        let msg = nist2_serialize(p)?;
        let sig = hex(p["signatureValue"].as_str().unwrap_or_default())?;
        let s = RsaSignature::try_from(sig.as_slice()).map_err(|e| Error::Signature(e.to_string()))?;
        VerifyingKey::<Sha512>::new(key.clone()).verify(&msg, &s).map_err(|_| Error::Signature(format!("beacon pulse {}: bad signature", p["uri"])))?;
        // outputValue: NIST hashes the raw signature, Inmetro a length-prefixed one.
        let out = hex(p["outputValue"].as_str().unwrap_or_default())?;
        let raw = Sha512::digest([msg.as_slice(), &sig].concat());
        let prefixed = Sha512::digest([msg.as_slice(), &(sig.len() as u32).to_be_bytes(), &sig].concat());
        if out[..] != raw[..] && out[..] != prefixed[..] {
            return Err(Error::Signature("beacon pulse: outputValue does not match".into()));
        }
        parse_utc(p["timeStamp"].as_str().unwrap_or_default())
    }
}

impl BeaconVerifier for Verifiers {
    fn verify(&self, value: &BeaconValue) -> Result<i64> {
        match value {
            BeaconValue::Drand { chain, round, signature } => {
                let c = self.drand.get(chain).ok_or_else(|| Error::Unsupported(format!("drand chain {chain}")))?;
                c.verify(*round, signature)
            }
            BeaconValue::Nist2 { pulse } => self.verify_nist2(pulse),
        }
    }
}

/// The byte string a NIST 2.0 pulse is signed over, as deployed: every length
/// prefix is a 4-byte big-endian byte count (NISTIR 8213's draft says 8), hex
/// fields are decoded first, and integers are fixed width.
pub fn nist2_serialize(p: &Value) -> Result<Vec<u8>> {
    let mut out = vec![];
    let s = |out: &mut Vec<u8>, v: &Value| -> Result<()> {
        let b = v.as_str().ok_or_else(|| Error::Encoding("beacon pulse: missing string field".into()))?.as_bytes();
        out.extend((b.len() as u32).to_be_bytes());
        out.extend(b);
        Ok(())
    };
    let h = |out: &mut Vec<u8>, v: &Value| -> Result<()> {
        let b = hex(v.as_str().ok_or_else(|| Error::Encoding("beacon pulse: missing hex field".into()))?)?;
        out.extend((b.len() as u32).to_be_bytes());
        out.extend(b);
        Ok(())
    };
    let u32f = |out: &mut Vec<u8>, v: &Value| -> Result<()> {
        out.extend((v.as_u64().ok_or_else(|| Error::Encoding("beacon pulse: missing integer".into()))? as u32).to_be_bytes());
        Ok(())
    };
    let u64f = |out: &mut Vec<u8>, v: &Value| -> Result<()> {
        out.extend(v.as_u64().ok_or_else(|| Error::Encoding("beacon pulse: missing integer".into()))?.to_be_bytes());
        Ok(())
    };
    s(&mut out, &p["uri"])?;
    s(&mut out, &p["version"])?;
    u32f(&mut out, &p["cipherSuite"])?;
    u32f(&mut out, &p["period"])?;
    h(&mut out, &p["certificateId"])?;
    u64f(&mut out, &p["chainIndex"])?;
    u64f(&mut out, &p["pulseIndex"])?;
    s(&mut out, &p["timeStamp"])?;
    h(&mut out, &p["localRandomValue"])?;
    let ext = &p["external"];
    if !ext.is_object() {
        return Err(Error::Unsupported("beacon pulse: `external` must be one object (multi-source pulses are not supported)".into()));
    }
    h(&mut out, &ext["sourceId"])?;
    u32f(&mut out, &ext["statusCode"])?;
    h(&mut out, &ext["value"])?;
    let list = p["listValues"].as_array().cloned().unwrap_or_default();
    for t in ["previous", "hour", "day", "month", "year"] {
        let v = list.iter().find(|x| x["type"] == t).ok_or_else(|| Error::Encoding(format!("beacon pulse: no {t} value")))?;
        h(&mut out, &v["value"])?;
    }
    h(&mut out, &p["precommitmentValue"])?;
    u32f(&mut out, &p["statusCode"])?;
    Ok(out)
}

/// `YYYY-MM-DDTHH:MM:SS(.fff)Z` → Unix seconds.
pub fn parse_utc(s: &str) -> Result<i64> {
    let bad = || Error::Encoding(format!("timestamp {s:?}"));
    let n = |a: usize, b: usize| s.get(a..b).and_then(|x| x.parse::<i64>().ok()).ok_or_else(bad);
    if s.len() < 20 || !s.ends_with('Z') || &s[4..5] != "-" || &s[10..11] != "T" {
        return Err(bad());
    }
    let (y, m, d, hh, mm, ss) = (n(0, 4)?, n(5, 7)?, n(8, 10)?, n(11, 13)?, n(14, 16)?, n(17, 19)?);
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss)
}

fn hex(s: &str) -> Result<Vec<u8>> {
    crate::ots::hex_decode(&s.to_ascii_lowercase())
}

fn to_hex(b: &[u8]) -> String {
    crate::ots::hex(b)
}

/// PEM → DER, tolerating the quirks beacons serve (CRLF, trailing spaces).
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let body: String = pem.lines().map(str::trim).filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(body).map_err(|e| Error::Encoding(format!("certificate PEM: {e}")))
}

/// One DER TLV: (tag, whole element, contents).
fn tlv(b: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let bad = || Error::Encoding("certificate DER".into());
    let tag = *b.first().ok_or_else(bad)?;
    let first = *b.get(1).ok_or_else(bad)?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(bad());
        }
        let len = b.get(2..2 + n).ok_or_else(bad)?.iter().fold(0usize, |a, x| (a << 8) | *x as usize);
        (len, 2 + n)
    };
    let all = b.get(..hdr + len).ok_or_else(bad)?;
    Ok((tag, all, &all[hdr..]))
}

/// The SubjectPublicKeyInfo of an X.509 certificate.
fn spki_of_certificate(der: &[u8]) -> Result<&[u8]> {
    let (_, _, cert) = tlv(der)?;
    let (_, _, mut tbs) = tlv(cert)?;
    let mut fields = vec![];
    while !tbs.is_empty() {
        let (tag, all, _) = tlv(tbs)?;
        fields.push((tag, all));
        tbs = &tbs[all.len()..];
    }
    // [0] version (optional), serial, signature alg, issuer, validity, subject, spki
    let skip = usize::from(fields.first().is_some_and(|(t, _)| *t == 0xa0));
    fields.get(skip + 5).map(|(_, all)| *all).ok_or_else(|| Error::Encoding("certificate has no public key".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../../spec/test-vectors/beacons.json")).unwrap()
    }

    #[test]
    fn drand_vectors() {
        let v = vectors();
        let d = &v["drand"];
        let chain = DrandChain::new(d["public_key"].as_str().unwrap(), d["genesis_time"].as_i64().unwrap(), d["period"].as_i64().unwrap()).unwrap();
        let verifiers = Verifiers::default();
        for c in d["cases"].as_array().unwrap() {
            let value = BeaconValue::Drand { chain: d["chain"].as_str().unwrap().into(), round: c["round"].as_u64().unwrap(), signature: c["signature"].as_str().unwrap().into() };
            let got = verifiers.verify(&value);
            assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{}: {got:?}", c["name"]);
            if let Some(t) = c["time"].as_i64() {
                assert_eq!(got.unwrap(), t);
                assert_eq!(chain.verify(c["round"].as_u64().unwrap(), c["signature"].as_str().unwrap()).unwrap(), t);
            }
        }
        let unknown = BeaconValue::Drand { chain: "00".into(), round: 1, signature: "00".into() };
        assert!(verifiers.verify(&unknown).is_err());
    }

    #[test]
    fn nist2_vectors() {
        let v = vectors();
        let mut verifiers = Verifiers::default();
        for pem in v["nist2"]["certificates"].as_object().unwrap().values() {
            verifiers.add_nist_certificate(pem.as_str().unwrap()).unwrap();
        }
        for c in v["nist2"]["cases"].as_array().unwrap() {
            let got = verifiers.verify(&BeaconValue::Nist2 { pulse: c["pulse"].clone() });
            assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{}: {got:?}", c["name"]);
            if let Some(t) = c["time"].as_i64() {
                assert_eq!(got.unwrap(), t, "{}", c["name"]);
            }
        }
        // Pulses from origins outside the allowlist are refused before any crypto.
        let mut p = v["nist2"]["cases"][0]["pulse"].clone();
        p["uri"] = "https://evil.example/beacon/2.0/chain/2/pulse/1".into();
        assert!(matches!(verifiers.verify(&BeaconValue::Nist2 { pulse: p }), Err(Error::Unsupported(_))));
    }

    #[test]
    fn utc_parsing() {
        assert_eq!(parse_utc("1970-01-01T00:00:00.000Z").unwrap(), 0);
        assert_eq!(parse_utc("2026-09-27T19:49:00.000Z").unwrap(), 1790538540);
        assert_eq!(parse_utc("2000-02-29T12:00:00Z").unwrap(), 951825600);
    }
}
