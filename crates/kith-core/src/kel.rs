//! The key event log (KEL): an append-only, hash-chained, signed history that *is*
//! a `did:kith` identity. Modeled on KERI (pre-rotation) and did:plc (self-certifying
//! id derived from the genesis operation).
//!
//! Authority levels:
//!
//! | level | who                     | may                                                   |
//! |-------|-------------------------|-------------------------------------------------------|
//! | L0    | `next` rotation policy  | rotate (replace `manage`), revoke all devices         |
//! |       | (pre-committed, cold)   |                                                       |
//! | L1    | `manage` policy         | add/revoke devices, link/unlink public aliases        |
//! | L2    | devices                 | sign session grants, commit private aliases, revoke   |
//! |       |                         | themselves                                            |
//! | L3    | session keys            | sign requests / tokens (never appear in the KEL)      |

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::keys::{verify_sig, LocalSigner, Sig, SignerRef, VerifyOptions};
use crate::policy::SignerPolicy;
use crate::util::{b64u, now, sha256};
use crate::{Error, Result};

pub const DID_PREFIX: &str = "did:kith:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// Key in a file or OS keychain.
    Software,
    /// WebAuthn passkey (platform authenticator or security key).
    Passkey,
    /// Non-exportable hardware key (Secure Enclave, TPM, YubiKey PIV, HSM).
    Hardware,
    /// A crypto wallet acting as a device.
    Wallet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    /// Signer id of the device key (a `did:key`).
    pub key: String,
    pub name: String,
    pub kind: DeviceKind,
    /// Highest NIST 800-63 authenticator assurance level this device can assert (1-3).
    pub aal: u8,
    /// Capabilities: `session` (sign session grants), `alias` (commit private aliases).
    #[serde(default)]
    pub caps: Vec<String>,
    /// For passkeys: the WebAuthn relying party id the credential is scoped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    /// X25519 exchange key (`did:key:z6LS…`) so others can seal keys to this device
    /// (see [`crate::vault`]). Revoking the device stops new shares reaching it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xkey: Option<String>,
}

impl Device {
    pub fn has_cap(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventBody {
    Inception {
        manage: SignerPolicy,
        /// Digest of the next rotation policy (pre-rotation commitment).
        next: String,
        #[serde(default)]
        devices: Vec<Device>,
    },
    Rotate {
        /// The rotation policy being revealed; its digest must equal the current `next`.
        rotation: SignerPolicy,
        manage: SignerPolicy,
        next: String,
        #[serde(default)]
        revoke_devices: bool,
    },
    AddDevice {
        device: Device,
    },
    RevokeDevice {
        device_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Hiding commitment to a private alias (see [`crate::alias`]).
    AliasCommit {
        commitment: String,
    },
    /// Public alias: `did:web:…`, `mailto:…`, `https://github.com/…`, `eip155:1:0x…`.
    AliasLink {
        alias: String,
    },
    AliasUnlink {
        alias: String,
    },
}

impl EventBody {
    pub fn kind(&self) -> &'static str {
        match self {
            EventBody::Inception { .. } => "inception",
            EventBody::Rotate { .. } => "rotate",
            EventBody::AddDevice { .. } => "add_device",
            EventBody::RevokeDevice { .. } => "revoke_device",
            EventBody::AliasCommit { .. } => "alias_commit",
            EventBody::AliasLink { .. } => "alias_link",
            EventBody::AliasUnlink { .. } => "alias_unlink",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    pub ts: i64,
    #[serde(flatten)]
    pub body: EventBody,
    #[serde(default)]
    pub sigs: Vec<Sig>,
}

impl Event {
    /// The signed payload: the event without `sigs`.
    pub fn payload(&self) -> Result<Value> {
        let mut v = serde_json::to_value(self)?;
        v.as_object_mut().expect("event is an object").remove("sigs");
        Ok(v)
    }

    pub fn digest(&self) -> Result<String> {
        Ok(b64u(sha256(crate::canon::to_canonical(&self.payload()?)?)))
    }

    /// Human-readable text that signers sign. Readable so wallets and hardware keys
    /// can display it, domain-separated so it can't be replayed as anything else.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        Ok(format!(
            "kith identity event v1\ndid: {}\nseq: {}\nkind: {}\ndigest: {}",
            self.did.as_deref().unwrap_or("new"),
            self.seq,
            self.body.kind(),
            self.digest()?
        )
        .into_bytes())
    }

    pub fn sign(&mut self, signer: &LocalSigner) -> Result<()> {
        let sig = signer.sign(&self.signing_message()?)?;
        self.sigs.push(sig);
        Ok(())
    }

    pub fn add_sig(&mut self, sig: Sig) {
        self.sigs.push(sig);
    }
}

pub fn did_for_inception(ev: &Event) -> Result<String> {
    let hash = sha256(crate::canon::to_canonical(&ev.payload()?)?);
    Ok(format!("{DID_PREFIX}{}", data_encoding::BASE32_NOPAD.encode(&hash).to_lowercase()))
}

pub fn new_inception(manage: SignerPolicy, next_rotation: &SignerPolicy, devices: Vec<Device>) -> Event {
    Event {
        v: 1,
        did: None,
        seq: 0,
        prev: None,
        ts: now(),
        body: EventBody::Inception { manage, next: next_rotation.digest(), devices },
        sigs: vec![],
    }
}

pub fn next_event(state: &KeyState, body: EventBody) -> Event {
    Event { v: 1, did: Some(state.did.clone()), seq: state.seq + 1, prev: Some(state.digest.clone()), ts: now().max(state.updated), body, sigs: vec![] }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasCommitment {
    pub seq: u64,
    pub ts: i64,
    pub commitment: String,
}

/// The current state of an identity, derived by replaying its KEL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyState {
    pub did: String,
    pub seq: u64,
    pub digest: String,
    pub manage: SignerPolicy,
    pub next: String,
    pub devices: BTreeMap<String, Device>,
    pub revoked: BTreeSet<String>,
    pub aliases: BTreeSet<String>,
    pub alias_commitments: Vec<AliasCommitment>,
    pub created: i64,
    pub updated: i64,
}

impl KeyState {
    pub fn device(&self, id: &str) -> Option<&Device> {
        self.devices.get(id)
    }

    /// Every signer that may authenticate as this identity (device keys and the
    /// manage policy's signers). The rotation keys are deliberately excluded: they
    /// stay cold until a rotation.
    pub fn is_authentication_signer(&self, signer: &str) -> bool {
        self.devices.values().any(|d| d.key == signer) || self.manage.signers().contains(signer)
    }

    /// A W3C DID Core document for this identity.
    pub fn did_document(&self, hub: Option<&str>) -> Value {
        let vm: Vec<Value> = self
            .devices
            .values()
            .map(|d| {
                json!({
                    "id": format!("{}#{}", self.did, d.id),
                    "type": "Multikey",
                    "controller": self.did,
                    "publicKeyMultibase": d.key.trim_start_matches("did:key:"),
                })
            })
            .collect();
        let ids: Vec<String> = self.devices.keys().map(|id| format!("{}#{}", self.did, id)).collect();
        let mut doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": self.did,
            "alsoKnownAs": self.aliases,
            "verificationMethod": vm,
            "authentication": ids,
            "assertionMethod": ids,
            "capabilityInvocation": ids,
            "kith": {"seq": self.seq, "manage": self.manage, "next": self.next},
        });
        if let Some(hub) = hub {
            doc["service"] = json!([{"id": "#hub", "type": "KithHub", "serviceEndpoint": hub}]);
        }
        doc
    }
}

fn valid_signers(ev: &Event, opts: &VerifyOptions) -> Result<BTreeSet<String>> {
    let msg = ev.signing_message()?;
    let mut out = BTreeSet::new();
    for sig in &ev.sigs {
        verify_sig(sig, &msg, opts).map_err(|e| Error::Kel(format!("seq {}: signature by {}: {e}", ev.seq, sig.signer)))?;
        out.insert(sig.signer.clone());
    }
    Ok(out)
}

fn validate_device(d: &Device) -> Result<()> {
    if d.id.is_empty() || d.id.contains('#') {
        return Err(Error::Kel(format!("bad device id {:?}", d.id)));
    }
    if !d.key.starts_with("did:key:") {
        return Err(Error::Kel("device keys must be did:key".into()));
    }
    SignerRef::parse(&d.key)?;
    if !(1..=3).contains(&d.aal) {
        return Err(Error::Kel("device aal must be 1-3".into()));
    }
    Ok(())
}

/// Replay and verify a KEL, returning the resulting state.
pub fn verify_log(events: &[Event], opts: &VerifyOptions) -> Result<KeyState> {
    let first = events.first().ok_or_else(|| Error::Kel("empty log".into()))?;
    let EventBody::Inception { manage, next, devices } = &first.body else {
        return Err(Error::Kel("first event must be inception".into()));
    };
    if first.v != 1 || first.seq != 0 || first.prev.is_some() || first.did.is_some() {
        return Err(Error::Kel("malformed inception".into()));
    }
    manage.validate()?;
    let signed = valid_signers(first, opts)?;
    if !manage.is_satisfied_by(&signed) {
        return Err(Error::Kel("inception not signed by its manage policy".into()));
    }
    let mut dev_map = BTreeMap::new();
    for d in devices {
        validate_device(d)?;
        if !signed.contains(&d.key) {
            return Err(Error::Kel(format!("device {} did not sign inception (proof of possession)", d.id)));
        }
        if dev_map.insert(d.id.clone(), d.clone()).is_some() {
            return Err(Error::Kel(format!("duplicate device id {}", d.id)));
        }
    }
    let mut st = KeyState {
        did: did_for_inception(first)?,
        seq: 0,
        digest: first.digest()?,
        manage: manage.clone(),
        next: next.clone(),
        devices: dev_map,
        revoked: BTreeSet::new(),
        aliases: BTreeSet::new(),
        alias_commitments: vec![],
        created: first.ts,
        updated: first.ts,
    };

    for ev in &events[1..] {
        if ev.v != 1 || ev.did.as_deref() != Some(st.did.as_str()) {
            return Err(Error::Kel(format!("seq {}: wrong did or version", ev.seq)));
        }
        if ev.seq != st.seq + 1 || ev.prev.as_deref() != Some(st.digest.as_str()) {
            return Err(Error::Kel(format!("seq {}: broken hash chain", ev.seq)));
        }
        if ev.ts < st.updated {
            return Err(Error::Kel(format!("seq {}: timestamp went backwards", ev.seq)));
        }
        let signed = valid_signers(ev, opts)?;
        let by_manage = st.manage.is_satisfied_by(&signed);
        match &ev.body {
            EventBody::Inception { .. } => return Err(Error::Kel("duplicate inception".into())),
            EventBody::Rotate { rotation, manage, next, revoke_devices } => {
                if rotation.digest() != st.next {
                    return Err(Error::Kel("rotation policy does not match pre-rotation commitment".into()));
                }
                rotation.validate()?;
                if !rotation.is_satisfied_by(&signed) {
                    return Err(Error::Kel("rotation not signed by the committed rotation keys".into()));
                }
                manage.validate()?;
                st.manage = manage.clone();
                st.next = next.clone();
                if *revoke_devices {
                    let ids: Vec<String> = st.devices.keys().cloned().collect();
                    st.revoked.extend(ids);
                    st.devices.clear();
                }
            }
            EventBody::AddDevice { device } => {
                validate_device(device)?;
                if !by_manage {
                    return Err(Error::Kel("add_device requires the manage policy".into()));
                }
                if !signed.contains(&device.key) {
                    return Err(Error::Kel("new device must co-sign (proof of possession)".into()));
                }
                if st.devices.contains_key(&device.id) || st.revoked.contains(&device.id) {
                    return Err(Error::Kel(format!("device id {} already used", device.id)));
                }
                if st.devices.values().any(|d| d.key == device.key) {
                    return Err(Error::Kel("device key already registered".into()));
                }
                st.devices.insert(device.id.clone(), device.clone());
            }
            EventBody::RevokeDevice { device_id, .. } => {
                let dev = st.devices.get(device_id).ok_or_else(|| Error::Kel(format!("unknown device {device_id}")))?;
                if !by_manage && !signed.contains(&dev.key) {
                    return Err(Error::Kel("revoke_device requires manage policy or the device itself".into()));
                }
                st.devices.remove(device_id);
                st.revoked.insert(device_id.clone());
            }
            EventBody::AliasCommit { commitment } => {
                let by_device = st.devices.values().any(|d| d.has_cap("alias") && signed.contains(&d.key));
                if !by_manage && !by_device {
                    return Err(Error::Kel("alias_commit requires manage policy or an alias-capable device".into()));
                }
                st.alias_commitments.push(AliasCommitment { seq: ev.seq, ts: ev.ts, commitment: commitment.clone() });
            }
            EventBody::AliasLink { alias } => {
                if !by_manage {
                    return Err(Error::Kel("alias_link requires the manage policy".into()));
                }
                st.aliases.insert(alias.clone());
            }
            EventBody::AliasUnlink { alias } => {
                if !by_manage {
                    return Err(Error::Kel("alias_unlink requires the manage policy".into()));
                }
                st.aliases.remove(alias);
            }
        }
        st.seq = ev.seq;
        st.digest = ev.digest()?;
        st.updated = ev.ts;
    }
    Ok(st)
}

/// True if `new` is `old` plus zero or more appended events (no fork).
pub fn extends(old: &[Event], new: &[Event]) -> Result<bool> {
    if new.len() < old.len() {
        return Ok(false);
    }
    for (a, b) in old.iter().zip(new) {
        if a.digest()? != b.digest()? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::KeyType;

    pub struct Fixture {
        pub root: LocalSigner,
        pub recovery: Vec<LocalSigner>,
        pub device: LocalSigner,
        pub device_id: String,
        pub log: Vec<Event>,
    }

    pub fn fixture() -> Fixture {
        let root = LocalSigner::generate(KeyType::Ed25519);
        let recovery = vec![
            LocalSigner::generate(KeyType::Ed25519),
            LocalSigner::generate(KeyType::Ed25519),
            LocalSigner::generate_eth_wallet(1),
        ];
        let rotation = SignerPolicy::threshold(2, recovery.iter().map(|s| SignerPolicy::single(&s.id)).collect());
        let device = LocalSigner::generate(KeyType::Ed25519);
        let dev = Device {
            id: "laptop".into(),
            key: device.id.clone(),
            name: "laptop".into(),
            kind: DeviceKind::Software,
            aal: 2,
            caps: vec!["session".into(), "alias".into()],
            rp_id: None,
            xkey: None,
        };
        let mut inc = new_inception(SignerPolicy::single(&root.id), &rotation, vec![dev]);
        inc.sign(&root).unwrap();
        inc.sign(&device).unwrap();
        Fixture { root, recovery, device, device_id: "laptop".into(), log: vec![inc] }
    }

    #[test]
    fn inception_derives_did() {
        let f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        assert!(st.did.starts_with("did:kith:"));
        assert_eq!(st.devices.len(), 1);
        let doc = st.did_document(Some("http://hub"));
        assert_eq!(doc["id"], st.did);
    }

    #[test]
    fn tampering_changes_did_or_breaks_sigs() {
        let mut f = fixture();
        if let EventBody::Inception { devices, .. } = &mut f.log[0].body {
            devices[0].aal = 3;
        }
        assert!(verify_log(&f.log, &VerifyOptions::default()).is_err());
    }

    #[test]
    fn add_passkey_device_and_revoke() {
        let mut f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let passkey = LocalSigner::generate(KeyType::P256);
        let dev = Device {
            id: "phone".into(),
            key: passkey.id.clone(),
            name: "phone passkey".into(),
            kind: DeviceKind::Passkey,
            aal: 3,
            caps: vec!["session".into()],
            rp_id: Some("example.com".into()),
            xkey: None,
        };
        let mut ev = next_event(&st, EventBody::AddDevice { device: dev });
        ev.sign(&f.root).unwrap();
        // Without the passkey's proof of possession this must fail.
        let mut missing = f.log.clone();
        missing.push(ev.clone());
        assert!(verify_log(&missing, &VerifyOptions::default()).is_err());
        let msg = ev.signing_message().unwrap();
        ev.add_sig(crate::webauthn::soft_sign_message(&passkey, "example.com", "https://example.com", &msg).unwrap());
        f.log.push(ev);
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        assert_eq!(st.devices.len(), 2);

        // A device may revoke itself.
        let mut rev = next_event(&st, EventBody::RevokeDevice { device_id: "phone".into(), reason: Some("lost".into()) });
        let msg = rev.signing_message().unwrap();
        rev.add_sig(crate::webauthn::soft_sign_message(&passkey, "example.com", "https://example.com", &msg).unwrap());
        f.log.push(rev);
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        assert!(st.device("phone").is_none());
        assert!(st.revoked.contains("phone"));
    }

    #[test]
    fn device_cannot_add_device() {
        let mut f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let other = LocalSigner::generate(KeyType::Ed25519);
        let dev = Device { id: "x".into(), key: other.id.clone(), name: "x".into(), kind: DeviceKind::Software, aal: 1, caps: vec![], rp_id: None, xkey: None };
        let mut ev = next_event(&st, EventBody::AddDevice { device: dev });
        ev.sign(&f.device).unwrap();
        ev.sign(&other).unwrap();
        f.log.push(ev);
        assert!(verify_log(&f.log, &VerifyOptions::default()).is_err());
    }

    #[test]
    fn pre_rotation_recovers_from_compromised_root() {
        let mut f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let rotation = SignerPolicy::threshold(2, f.recovery.iter().map(|s| SignerPolicy::single(&s.id)).collect());
        let new_root = LocalSigner::generate(KeyType::Ed25519);
        let new_next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);

        // The (compromised) root key alone cannot rotate.
        let mut bad = next_event(&st, EventBody::Rotate { rotation: rotation.clone(), manage: SignerPolicy::single(&new_root.id), next: new_next.digest(), revoke_devices: true });
        bad.sign(&f.root).unwrap();
        let mut attempt = f.log.clone();
        attempt.push(bad);
        assert!(verify_log(&attempt, &VerifyOptions::default()).is_err());

        // Two of the three recovery signers (one is an Ethereum wallet) can.
        let mut ev = next_event(&st, EventBody::Rotate { rotation, manage: SignerPolicy::single(&new_root.id), next: new_next.digest(), revoke_devices: true });
        ev.sign(&f.recovery[0]).unwrap();
        ev.sign(&f.recovery[2]).unwrap();
        f.log.push(ev);
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        assert_eq!(st.manage, SignerPolicy::single(&new_root.id));
        assert!(st.devices.is_empty());
        assert!(!st.is_authentication_signer(&f.root.id));
    }

    #[test]
    fn fork_detection() {
        let f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        let mut a = next_event(&st, EventBody::AliasLink { alias: "mailto:a@example.com".into() });
        a.sign(&f.root).unwrap();
        let mut b = next_event(&st, EventBody::AliasLink { alias: "mailto:b@example.com".into() });
        b.sign(&f.root).unwrap();
        let log_a = [f.log.clone(), vec![a]].concat();
        let log_b = [f.log.clone(), vec![b]].concat();
        assert!(extends(&f.log, &log_a).unwrap());
        assert!(!extends(&log_a, &log_b).unwrap());
    }

    #[test]
    fn serde_roundtrip_is_stable() {
        let f = fixture();
        let json = serde_json::to_string(&f.log).unwrap();
        let back: Vec<Event> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f.log);
        assert_eq!(back[0].digest().unwrap(), f.log[0].digest().unwrap());
        let _ = f.device_id;
    }
}
