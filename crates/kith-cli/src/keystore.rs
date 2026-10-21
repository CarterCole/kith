//! Where the CLI keeps private keys (roadmap milestone 2, spec §1.3.3).
//!
//! Two backends:
//!
//! * `file`: secret bytes sit inline in `identity.json` (mode 0600). Plaintext; the
//!   only backend on Linux today.
//! * `keychain` (macOS): every secret is a generic password item in the login
//!   keychain, service [`SERVICE`], account `<did>/<key id>`. `identity.json` keeps
//!   the public half and the id to look the item up by. This device's signing key is
//!   created in the Secure Enclave when there is one ([`enclave`]): the keychain then
//!   holds the opaque, device-bound blob the Enclave hands back, and every signature
//!   is made inside the chip.
//!
//! Keychain items carry an access control list naming the binary that created them.
//! A rebuilt or upgraded `kith` is a different binary, so macOS asks once per item
//! ("Always Allow" remembers the answer).

use anyhow::{bail, Result};

/// Keychain service name for every item the CLI stores.
#[cfg(target_os = "macos")]
pub const SERVICE: &str = "kith";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    File,
    Keychain,
}

impl Backend {
    pub fn parse(s: &str) -> Result<Backend> {
        match s {
            "file" => Ok(Backend::File),
            "keychain" => Ok(Backend::Keychain),
            other => bail!("unknown keystore {other}; use `keychain` or `file`"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Backend::File => "file",
            Backend::Keychain => "keychain",
        }
    }

    /// The keychain on macOS, the file elsewhere.
    pub fn platform_default() -> Backend {
        if cfg!(target_os = "macos") {
            Backend::Keychain
        } else {
            Backend::File
        }
    }

    /// What this backend resolves to on this platform. Without a keychain backend
    /// (Linux) `keychain` falls back to `file`, with a one-line warning.
    pub fn resolve(self) -> Backend {
        if self == Backend::Keychain && !cfg!(target_os = "macos") {
            eprintln!("warning: no OS keychain backend on this platform; keys go to identity.json (mode 0600)");
            return Backend::File;
        }
        self
    }
}

#[cfg(target_os = "macos")]
fn account(did: &str, slot: &str) -> String {
    format!("{did}/{slot}")
}

/// Store `secret` for `did`'s key `slot` (a signer id, or `session/<device id>`,
/// `xkey/<device id>`). Replaces an existing item.
#[cfg(target_os = "macos")]
pub fn put(did: &str, slot: &str, secret: &[u8]) -> Result<()> {
    use anyhow::anyhow;
    use security_framework::passwords::set_generic_password_options;
    use security_framework::passwords_options::PasswordOptions;
    let mut opts = PasswordOptions::new_generic_password(SERVICE, &account(did, slot));
    opts.set_label(&format!("kith {slot}"));
    set_generic_password_options(secret, opts).map_err(|e| anyhow!("keychain: storing {slot}: {e}"))
}

#[cfg(target_os = "macos")]
pub fn get(did: &str, slot: &str) -> Result<Vec<u8>> {
    use anyhow::anyhow;
    use security_framework::passwords::get_generic_password;
    use security_framework_sys::base::errSecItemNotFound;
    get_generic_password(SERVICE, &account(did, slot)).map_err(|e| {
        if e.code() == errSecItemNotFound {
            anyhow!("key {slot} is not in this user's keychain (was it created on another machine, or forgotten with `kith keys forget`?)")
        } else {
            anyhow!("keychain: reading {slot}: {e}")
        }
    })
}

/// Remove `slot`. `Ok(false)` when there was nothing to remove.
#[cfg(target_os = "macos")]
pub fn delete(did: &str, slot: &str) -> Result<bool> {
    use anyhow::anyhow;
    use security_framework::passwords::delete_generic_password;
    use security_framework_sys::base::errSecItemNotFound;
    match delete_generic_password(SERVICE, &account(did, slot)) {
        Ok(()) => Ok(true),
        Err(e) if e.code() == errSecItemNotFound => Ok(false),
        Err(e) => Err(anyhow!("keychain: deleting {slot}: {e}")),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn put(_did: &str, slot: &str, _secret: &[u8]) -> Result<()> {
    bail!("no OS keychain backend on this platform (cannot store {slot})")
}

#[cfg(not(target_os = "macos"))]
pub fn get(_did: &str, slot: &str) -> Result<Vec<u8>> {
    bail!("key {slot} lives in a keychain, and this platform has no keychain backend")
}

#[cfg(not(target_os = "macos"))]
pub fn delete(_did: &str, _slot: &str) -> Result<bool> {
    Ok(false)
}

/// P-256 keys that live in the Secure Enclave. The private key never leaves the chip:
/// what we hold is the key's *token object id* (`kSecAttrTokenOID`), an opaque blob
/// holding the chip-wrapped key, its public half and its access rules, which only this
/// device's Enclave can use. CryptoKit calls the same blob `dataRepresentation`.
/// Signing is a call into the chip. The key is never added to a keychain item of its
/// own (that would need the data protection keychain and a signed binary); the blob
/// goes into our generic password item instead.
#[cfg(target_os = "macos")]
pub mod enclave {
    use anyhow::{anyhow, bail, Result};
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::error::CFError;
    use core_foundation::string::CFString;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType as SecKeyType, SecKey, Token};
    use security_framework_sys::access_control::{kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence};
    use security_framework_sys::item::{
        kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave,
    };
    use security_framework_sys::key::SecKeyCreateWithData;

    use kith_core::keys::{KeyType, PublicKey};

    /// `kSecAttrTokenOID`, which `security-framework-sys` does not bind.
    const TOKEN_OID: &str = "toid";

    pub struct EnclaveKey {
        key: SecKey,
        /// The `did:key` of the public half.
        pub id: String,
    }

    impl EnclaveKey {
        /// Create a new P-256 key inside the Secure Enclave. With `require_presence`
        /// every signature asks for Touch ID or the login password. Fails on Macs
        /// without a Secure Enclave (and in most virtual machines).
        pub fn generate(require_presence: bool) -> Result<Self> {
            let mut flags = kSecAccessControlPrivateKeyUsage;
            if require_presence {
                flags |= kSecAccessControlUserPresence;
            }
            let acl = SecAccessControl::create_with_protection(Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly), flags)
                .map_err(|e| anyhow!("secure enclave: access control: {e}"))?;
            let mut opts = GenerateKeyOptions::default();
            // No location: the key is not a keychain item. We keep its blob ourselves.
            opts.set_key_type(SecKeyType::ec_sec_prime_random()).set_size_in_bits(256).set_token(Token::SecureEnclave).set_access_control(acl).set_label("kith device key");
            let key = SecKey::new(&opts).map_err(|e| anyhow!("secure enclave: {}", describe(&e)))?;
            Self::wrap(key)
        }

        /// Re-open a key from the blob [`EnclaveKey::blob`] returned.
        ///
        /// The blob must go in as the `kSecAttrTokenOID` attribute. The Secure Enclave
        /// token ignores `SecKeyCreateWithData`'s data argument and, without the
        /// attribute, quietly mints a *new* key.
        pub fn from_blob(blob: &[u8]) -> Result<Self> {
            let data = CFData::from_buffer(blob);
            let attrs = unsafe {
                CFDictionary::from_CFType_pairs(&[
                    (CFString::wrap_under_get_rule(kSecAttrKeyType), CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType()),
                    (CFString::wrap_under_get_rule(kSecAttrKeyClass), CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFType()),
                    (CFString::wrap_under_get_rule(kSecAttrTokenID), CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType()),
                    (CFString::from_static_string(TOKEN_OID), data.as_CFType()),
                ])
            };
            let mut err: core_foundation::error::CFErrorRef = std::ptr::null_mut();
            let raw = unsafe { SecKeyCreateWithData(data.as_concrete_TypeRef(), attrs.as_concrete_TypeRef(), &mut err) };
            if raw.is_null() {
                let e = if err.is_null() { "unknown error".to_string() } else { describe(&unsafe { CFError::wrap_under_create_rule(err) }) };
                bail!("secure enclave: cannot open the device key on this machine: {e}");
            }
            Self::wrap(unsafe { SecKey::wrap_under_create_rule(raw) })
        }

        fn wrap(key: SecKey) -> Result<Self> {
            let pub_key = key.public_key().ok_or_else(|| anyhow!("secure enclave: key has no public half"))?;
            let point = pub_key.external_representation().ok_or_else(|| anyhow!("secure enclave: cannot export the public key"))?;
            // ANSI X9.63 uncompressed point `04 || X || Y`; Kith stores SEC1 compressed.
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point.bytes()).map_err(|e| anyhow!("secure enclave: public key: {e}"))?;
            let public = PublicKey { kty: KeyType::P256, bytes: vk.to_encoded_point(true).as_bytes().to_vec() };
            Ok(EnclaveKey { key, id: public.to_did_key() })
        }

        /// The opaque blob that stands for this key. Useless on any other machine;
        /// stored in the keychain all the same.
        pub fn blob(&self) -> Result<Vec<u8>> {
            let attrs = self.key.attributes();
            let oid = attrs
                .find(CFString::from_static_string(TOKEN_OID).as_CFTypeRef())
                .ok_or_else(|| anyhow!("secure enclave: key has no token object id"))?;
            Ok(unsafe { CFData::wrap_under_get_rule(*oid as _) }.to_vec())
        }

        /// ECDSA P-256 over SHA-256(msg), as the raw 64-byte `r||s` Kith uses.
        pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
            let der = self.key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg).map_err(|e| anyhow!("secure enclave: signing: {}", describe(&e)))?;
            let sig = p256::ecdsa::Signature::from_der(&der).map_err(|e| anyhow!("secure enclave: signature encoding: {e}"))?;
            Ok(sig.to_bytes().to_vec())
        }
    }

    fn describe(e: &CFError) -> String {
        format!("{} (code {})", e.description(), e.code())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use kith_core::keys::{verify_sig, Sig, VerifyOptions};
        use kith_core::util::b64u;

        #[test]
        fn key_round_trips_through_its_blob_and_signs() {
            let k = match EnclaveKey::generate(false) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("skipping: no Secure Enclave here ({e})");
                    return;
                }
            };
            assert!(k.id.starts_with("did:key:zDn"), "{}", k.id);
            let blob = k.blob().unwrap();
            let again = EnclaveKey::from_blob(&blob).unwrap();
            assert_eq!(again.id, k.id);
            let raw = again.sign(b"kith identity event v1").unwrap();
            assert_eq!(raw.len(), 64);
            let sig = Sig { signer: k.id.clone(), alg: "ES256".into(), sig: b64u(&raw), webauthn: None };
            verify_sig(&sig, b"kith identity event v1", &VerifyOptions::default()).unwrap();
            assert!(verify_sig(&sig, b"tampered", &VerifyOptions::default()).is_err());
            // Another key's blob opens as that key, never as this one.
            let other = EnclaveKey::generate(false).unwrap();
            let reopened = EnclaveKey::from_blob(&other.blob().unwrap()).unwrap();
            assert_eq!(reopened.id, other.id);
            assert_ne!(reopened.id, k.id);
            // Garbage is refused, not turned into a fresh key.
            assert!(EnclaveKey::from_blob(b"not a token object id").is_err());
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn keychain_round_trip() {
        let did = format!("did:kith:test{}", kith_core::util::random_id());
        let slot = "did:key:z6MkTestKey";
        put(&did, slot, b"secret bytes").unwrap();
        // Replacing is allowed.
        put(&did, slot, b"newer secret").unwrap();
        assert_eq!(get(&did, slot).unwrap(), b"newer secret");
        assert!(delete(&did, slot).unwrap());
        assert!(!delete(&did, slot).unwrap());
        let err = get(&did, slot).unwrap_err().to_string();
        assert!(err.contains("not in this user's keychain"), "{err}");
    }
}
