//! Keys inside a TPM 2.0 (spec §1.3.3), on Linux with the `tpm` feature.
//!
//! A key is a P-256 ECDSA signing key, a child of the owner hierarchy's storage key. The
//! TPM makes it and never lets the private half out: `create` returns the public area
//! and the private area encrypted under the storage key, and that pair is the blob
//! Kith keeps, as the Secure Enclave backend keeps its blob. The storage key is not
//! stored anywhere. It is derived again from the TPM's owner seed and a fixed template
//! each time, so a blob opens only in the TPM that made it, and only until that TPM is
//! cleared (which, on an AMD fTPM, some firmware updates do).
//!
//! A key may have a PIN, its `authValue`. The TPM then signs only when the PIN is
//! given, and counts wrong PINs against its dictionary-attack lockout, so a thief who
//! can run code on the machine still can't guess it quickly. The PIN goes to the TPM
//! over an HMAC session, not in the clear. A key without a PIN is `noDA`.
//!
//! Which TPM: `KITH_TPM_TCTI` (a TCTI string such as `device:/dev/tpmrm0` or
//! `swtpm:port=2321`), default `device:/dev/tpmrm0`. The device needs read and write
//! access: the `tss` group, with the udev rule from Debian's `tpm-udev` package.

use std::str::FromStr;

use anyhow::{anyhow, bail, Context as _, Result};
use serde_json::{json, Value};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Auth, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyDerivationFunctionScheme,
    Private, Public, PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::{Context, TctiNameConf};

use kith_core::keys::{KeyType, PublicKey};
use kith_core::util::{b64u, b64u_decode, sha256};

/// Where the PIN comes from when the CLI is not asked interactively: scripts and tests.
pub const PIN_ENV: &str = "KITH_TPM_PIN";

pub struct TpmKey {
    public: Public,
    private: Private,
    /// Whether the key has a PIN; asked for on each signature.
    pub has_pin: bool,
    /// The `did:key` of the public half.
    pub id: String,
}

fn context() -> Result<Context> {
    let tcti = std::env::var("KITH_TPM_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".into());
    let conf = TctiNameConf::from_str(&tcti).map_err(|e| anyhow!("tpm: bad KITH_TPM_TCTI {tcti:?}: {e}"))?;
    Context::new(conf).map_err(|e| {
        anyhow!("tpm: cannot open {tcti}: {e}. Is there a TPM, and is this user in the `tss` group (Debian: `sudo apt install tpm-udev && sudo usermod -aG tss $USER`, then log in again)?")
    })
}

/// The owner hierarchy's storage key, made again from the TPM's seed. The same template
/// gives the same key every time, so nothing about it is stored.
fn storage_key(ctx: &mut Context) -> Result<KeyHandle> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let params = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()?;
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?;
    Ok(ctx
        .create_primary(Hierarchy::Owner, public, None, None, None, None)
        .context("tpm: making the storage key")?
        .key_handle)
}

fn signing_template(has_pin: bool) -> Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        // Wrong PINs count towards the lockout; a key with no PIN has nothing to guess.
        .with_no_da(!has_pin)
        .build()?;
    let params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

fn auth(pin: &str) -> Result<Auth> {
    Auth::try_from(pin.as_bytes().to_vec()).map_err(|e| anyhow!("tpm: the PIN is too long: {e}"))
}

/// A big-endian integer from the TPM as exactly 32 bytes.
fn coord(b: &[u8]) -> Result<[u8; 32]> {
    let b = &b[b.len().saturating_sub(32)..];
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

fn did_key(public: &Public) -> Result<String> {
    let Public::Ecc { unique, .. } = public else {
        bail!("tpm: the key is not an ECC key");
    };
    let mut point = vec![0x04];
    point.extend_from_slice(&coord(unique.x().value())?);
    point.extend_from_slice(&coord(unique.y().value())?);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
        .map_err(|e| anyhow!("tpm: public key: {e}"))?;
    Ok(PublicKey {
        kty: KeyType::P256,
        bytes: vk.to_encoded_point(true).as_bytes().to_vec(),
    }
    .to_did_key())
}

impl TpmKey {
    /// Make a new key in the TPM, with `pin` as its PIN if one is given.
    pub fn generate(pin: Option<&str>) -> Result<Self> {
        let mut ctx = context()?;
        let has_pin = pin.is_some();
        let template = signing_template(has_pin)?;
        let key_auth = pin.map(auth).transpose()?;
        let created = ctx.execute_with_nullauth_session(|ctx| -> Result<_> {
            let parent = storage_key(ctx)?;
            let r = ctx.create(parent, template, key_auth, None, None, None);
            ctx.flush_context(parent.into())?;
            r.context("tpm: making the key")
        })?;
        let id = did_key(&created.out_public)?;
        Ok(TpmKey {
            public: created.out_public,
            private: created.out_private,
            has_pin,
            id,
        })
    }

    /// Re-open a key from the blob [`TpmKey::blob`] returned. Nothing touches the TPM
    /// until it signs.
    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        let v: Value = serde_json::from_slice(blob).context("tpm: the key blob is not JSON")?;
        let field = |k: &str| -> Result<Vec<u8>> {
            Ok(b64u_decode(v[k].as_str().ok_or_else(|| anyhow!("tpm: the key blob has no {k}"))?)?)
        };
        let public = Public::unmarshall(&field("public")?).map_err(|e| anyhow!("tpm: public area: {e}"))?;
        let private = Private::try_from(field("private")?).map_err(|e| anyhow!("tpm: private area: {e}"))?;
        let id = did_key(&public)?;
        Ok(TpmKey {
            public,
            private,
            has_pin: v["pin"].as_bool().unwrap_or(false),
            id,
        })
    }

    /// The public area and the encrypted private area. Useless without this TPM.
    pub fn blob(&self) -> Result<Vec<u8>> {
        let public = self.public.marshall().map_err(|e| anyhow!("tpm: public area: {e}"))?;
        Ok(serde_json::to_vec(&json!({
            "v": 1,
            "public": b64u(public),
            "private": b64u(self.private.value()),
            "pin": self.has_pin,
        }))?)
    }

    /// ECDSA P-256 over SHA-256(msg), as the raw 64-byte `r||s` Kith uses. A key with a
    /// PIN asks for it ([`PIN_ENV`], or the terminal).
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let pin = if self.has_pin { Some(read_pin(&format!("PIN for TPM key {}: ", short(&self.id)))?) } else { None };
        self.sign_with(msg, pin.as_deref())
    }

    pub fn sign_with(&self, msg: &[u8], pin: Option<&str>) -> Result<Vec<u8>> {
        let mut ctx = context()?;
        let digest = Digest::try_from(sha256(msg).to_vec())?;
        let ticket = HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        })?;
        let sig = ctx.execute_with_nullauth_session(|ctx| -> Result<_> {
            let parent = storage_key(ctx)?;
            let key = ctx.load(parent, self.private.clone(), self.public.clone());
            ctx.flush_context(parent.into())?;
            let key = key.context("tpm: this key was made by another TPM, or this one was cleared")?;
            if let Some(p) = pin {
                ctx.tr_set_auth(key.into(), auth(p)?)?;
            }
            let r = ctx.sign(key, digest, SignatureScheme::Null, ticket);
            ctx.flush_context(key.into())?;
            r.map_err(|e| match pin {
                Some(_) => anyhow!("tpm: signing failed (a wrong PIN counts towards the TPM's lockout): {e}"),
                None => anyhow!("tpm: signing failed: {e}"),
            })
        })?;
        let Signature::EcDsa(e) = sig else {
            bail!("tpm: not an ECDSA signature");
        };
        let mut out = coord(e.signature_r().value())?.to_vec();
        out.extend_from_slice(&coord(e.signature_s().value())?);
        // Low-s, as verifiers expect; the TPM may return either.
        let s = p256::ecdsa::Signature::from_slice(&out).map_err(|e| anyhow!("tpm: signature: {e}"))?;
        Ok(s.normalize_s().unwrap_or(s).to_bytes().to_vec())
    }
}

fn short(id: &str) -> &str {
    &id[id.len().saturating_sub(8)..]
}

/// A PIN from [`PIN_ENV`], or typed at the terminal without echo.
pub fn read_pin(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var(PIN_ENV) {
        return Ok(p);
    }
    rpassword::prompt_password(prompt).context("reading the PIN")
}

/// A new PIN, typed twice.
pub fn new_pin() -> Result<String> {
    if let Ok(p) = std::env::var(PIN_ENV) {
        return Ok(p);
    }
    let a = rpassword::prompt_password("New PIN for the TPM key (at least 6 characters): ")?;
    if a.chars().count() < 6 {
        bail!("use at least 6 characters");
    }
    if rpassword::prompt_password("The same PIN again: ")? != a {
        bail!("the PINs differ");
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_core::keys::{verify_sig, Sig, VerifyOptions};

    /// Talks to a real TPM, so it runs only when asked: `KITH_TPM_TESTS=1 cargo test
    /// -p kith-cli --features tpm tpm::`. It makes transient keys and stores nothing in
    /// the TPM. It never sends a wrong PIN, which would count towards the lockout.
    #[test]
    fn a_tpm_key_signs_and_reopens_from_its_blob() {
        if std::env::var("KITH_TPM_TESTS").is_err() {
            eprintln!("skipped: set KITH_TPM_TESTS=1 to use the TPM");
            return;
        }
        for pin in [None, Some("correct horse")] {
            let k = TpmKey::generate(pin).unwrap();
            assert!(k.id.starts_with("did:key:zDn"), "{}", k.id);
            let again = TpmKey::from_blob(&k.blob().unwrap()).unwrap();
            assert_eq!(again.id, k.id);
            assert_eq!(again.has_pin, pin.is_some());
            let msg = b"kith tpm test";
            let raw = again.sign_with(msg, pin).unwrap();
            assert_eq!(raw.len(), 64);
            let sig = Sig {
                signer: k.id.clone(),
                alg: kith_core::keys::key_sig_alg(KeyType::P256).into(),
                sig: b64u(&raw),
                webauthn: None,
            };
            verify_sig(&sig, msg, &VerifyOptions::default()).unwrap();
        }
    }
}
