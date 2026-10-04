//! Revocations and heartbeats (spec §8.6–8.9).
//!
//! Grants reach verifiers slowly, through the policy DAG. Revocations are pushed:
//! an org signs a hash-chained list of revocation entries, and a heartbeat every
//! few seconds that names the newest entry and embeds a public beacon value. A
//! verifier that is missing an entry can tell (the chain has a gap, or a heartbeat
//! names a later entry), and a verifier that stops hearing heartbeats can tell (the
//! newest one ages). Either way it fails closed, after a staleness budget the
//! verifier chooses.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::authz::{AuthzDecision, Principal, Resource};
use crate::beacon::{BeaconValue, BeaconVerifier};
use crate::kel::KeyState;
use crate::keys::{verify_sig, LocalSigner, Sig, VerifyOptions};
use crate::pdag::Slice;
use crate::util::{b64u, now, sha256};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Revocation {
    /// All access for a principal.
    Principal { id: String },
    /// One explicit or dynamic membership: `set` is `Group::x` or `Role::x`.
    Member { id: String, set: String },
    /// A device of some identity, ahead of its own KEL catching up.
    Device { did: String, device: String },
    /// A permit policy, by id. Forbids can't be revoked: revocation only removes access.
    Policy { id: String },
    /// One token or session, by `jti`.
    Token { jti: String },
}

/// One link of an org's revocation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub v: u32,
    pub org: String,
    /// Starts at 1.
    pub seq: u64,
    /// Digest of entry `seq - 1`. Absent for entry 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    pub ts: i64,
    pub revoke: Vec<Revocation>,
    #[serde(default)]
    pub sigs: Vec<Sig>,
}

/// A signed statement "the newest revocation is `seq`/`head`", made after `beacon`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub v: u32,
    pub org: String,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    pub ts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon: Option<BeaconValue>,
    #[serde(default)]
    pub sigs: Vec<Sig>,
}

fn digest_of<T: Serialize>(v: &T) -> Result<String> {
    let mut v = serde_json::to_value(v)?;
    v.as_object_mut().ok_or_else(|| Error::Encoding("expected an object".into()))?.remove("sigs");
    Ok(b64u(sha256(crate::canon::to_canonical(&v)?)))
}

fn signed_by(sigs: &[Sig], msg: &[u8]) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for s in sigs {
        verify_sig(s, msg, &VerifyOptions::default())?;
        out.insert(s.signer.clone());
    }
    Ok(out)
}

impl Entry {
    pub fn new(org: &str, prev: Option<&Entry>, revoke: Vec<Revocation>) -> Result<Self> {
        Ok(Entry {
            v: 1,
            org: org.into(),
            seq: prev.map_or(1, |p| p.seq + 1),
            prev: prev.map(Entry::digest).transpose()?,
            ts: now(),
            revoke,
            sigs: vec![],
        })
    }
    pub fn digest(&self) -> Result<String> {
        digest_of(self)
    }
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        Ok(format!("kith revocation v1\norg: {}\nseq: {}\ndigest: {}", self.org, self.seq, self.digest()?).into_bytes())
    }
    pub fn sign(&mut self, s: &LocalSigner) -> Result<()> {
        let sig = s.sign(&self.signing_message()?)?;
        self.sigs.push(sig);
        Ok(())
    }
    /// Check the signatures against the org's key state.
    pub fn verify(&self, org: &KeyState) -> Result<()> {
        if self.v != 1 || self.org != org.did || self.seq == 0 || (self.seq == 1) != self.prev.is_none() {
            return Err(Error::Token(format!("malformed revocation entry {}", self.seq)));
        }
        if !org.may_revoke(&signed_by(&self.sigs, &self.signing_message()?)?) {
            return Err(Error::Signature(format!("revocation {} is not signed by a revoker of {}", self.seq, org.did)));
        }
        Ok(())
    }
}

impl Heartbeat {
    pub fn new(org: &str, latest: Option<&Entry>, beacon: Option<BeaconValue>) -> Result<Self> {
        Ok(Heartbeat { v: 1, org: org.into(), seq: latest.map_or(0, |e| e.seq), head: latest.map(Entry::digest).transpose()?, ts: now(), beacon, sigs: vec![] })
    }
    pub fn digest(&self) -> Result<String> {
        digest_of(self)
    }
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        Ok(format!("kith revocation heartbeat v1\norg: {}\nseq: {}\ndigest: {}", self.org, self.seq, self.digest()?).into_bytes())
    }
    pub fn sign(&mut self, s: &LocalSigner) -> Result<()> {
        let sig = s.sign(&self.signing_message()?)?;
        self.sigs.push(sig);
        Ok(())
    }
    pub fn verify(&self, org: &KeyState) -> Result<()> {
        if self.v != 1 || self.org != org.did || (self.seq == 0) != self.head.is_none() {
            return Err(Error::Token("malformed heartbeat".into()));
        }
        if !org.may_revoke(&signed_by(&self.sigs, &self.signing_message()?)?) {
            return Err(Error::Signature(format!("heartbeat is not signed by a revoker of {}", org.did)));
        }
        Ok(())
    }
}

/// How stale a verifier lets its view of revocations get. This is the "how long
/// can I go between syncs" knob; each verifier picks its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessPolicy {
    /// Up to this age (seconds) the view counts as fresh.
    pub fresh_for: i64,
    /// Past `fresh_for` and up to this age the verifier runs *degraded*: decisions
    /// still happen, with `context.kith.degraded = true` so policies can refuse
    /// sensitive actions. Past it, everything is denied.
    pub max_staleness: i64,
    /// Only beacon-backed heartbeats move freshness forward. Without a beacon a
    /// heartbeat's own timestamp is used, which a signer could forge ahead of time.
    pub require_beacon: bool,
}

impl Default for FreshnessPolicy {
    fn default() -> Self {
        FreshnessPolicy { fresh_for: 120, max_staleness: 900, require_beacon: true }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Fresh,
    Degraded,
    /// Too long since the last heartbeat, or never heard one.
    Stale,
    /// A heartbeat names revocations this verifier hasn't got yet.
    Behind,
    /// The org signed two different entries for one sequence number.
    Forked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Freshness {
    pub level: Level,
    /// Seconds since the newest heartbeat's proven time; `None` if there is none.
    pub age: Option<i64>,
    /// Newest revocation entry held.
    pub seq: u64,
    /// Newest revocation entry any heartbeat has named.
    pub head_seq: u64,
}

impl Freshness {
    pub fn allows_decisions(&self) -> bool {
        matches!(self.level, Level::Fresh | Level::Degraded)
    }

    /// What policies see as `context.kith`.
    pub fn cedar_context(&self) -> Value {
        json!({ "sync_age": self.age.unwrap_or(i64::MAX / 2), "degraded": self.level != Level::Fresh, "revocation_seq": self.seq as i64 })
    }
}

/// A verifier's view of one org's revocations.
#[derive(Debug, Clone)]
pub struct Follower {
    pub org: String,
    pub policy: FreshnessPolicy,
    /// Entries up to here are already reflected in the policy root (compacted away).
    base: u64,
    entries: BTreeMap<u64, Entry>,
    digests: BTreeMap<u64, String>,
    proven: Option<i64>,
    head_seq: u64,
    clock: i64,
    forked: bool,
}

impl Follower {
    pub fn new(org: impl Into<String>, base: u64, policy: FreshnessPolicy) -> Self {
        Follower { org: org.into(), policy, base, entries: BTreeMap::new(), digests: BTreeMap::new(), proven: None, head_seq: base, clock: 0, forked: false }
    }

    /// A new policy root arrived: drop the entries it already reflects.
    pub fn set_base(&mut self, base: u64) {
        if base > self.base {
            self.base = base;
            self.entries.retain(|s, _| *s > base);
            self.head_seq = self.head_seq.max(base);
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    /// Newest contiguous entry held (or the base).
    pub fn seq(&self) -> u64 {
        let mut s = self.base;
        while self.entries.contains_key(&(s + 1)) {
            s += 1;
        }
        s
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// Add a revocation entry. Out-of-order entries are kept; a gap shows up as
    /// [`Level::Behind`] until it is filled.
    pub fn apply_entry(&mut self, org: &KeyState, e: &Entry) -> Result<()> {
        if org.did != self.org {
            return Err(Error::Token("entry for another org".into()));
        }
        e.verify(org)?;
        let d = e.digest()?;
        if let Some(known) = self.digests.get(&e.seq) {
            if *known != d {
                self.forked = true;
                return Err(Error::Token(format!("duplicity: two revocation entries at seq {}", e.seq)));
            }
            return Ok(());
        }
        // Chain links: to the entry before, and from the entry after, when held.
        if let (Some(prev), Some(want)) = (e.prev.as_ref(), self.digests.get(&(e.seq - 1))) {
            if prev != want {
                self.forked = true;
                return Err(Error::Token(format!("revocation {} does not chain to {}", e.seq, e.seq - 1)));
            }
        }
        if let Some(next) = self.entries.get(&(e.seq + 1)) {
            if next.prev.as_deref() != Some(d.as_str()) {
                self.forked = true;
                return Err(Error::Token(format!("revocation {} does not chain to {}", e.seq + 1, e.seq)));
            }
        }
        self.digests.insert(e.seq, d);
        if e.seq > self.base {
            self.entries.insert(e.seq, e.clone());
        }
        self.head_seq = self.head_seq.max(e.seq);
        Ok(())
    }

    /// Add a heartbeat. Its proven time is the beacon's publication time (or its
    /// own timestamp, if the policy allows unbeaconed heartbeats).
    pub fn apply_heartbeat(&mut self, org: &KeyState, h: &Heartbeat, beacons: &dyn BeaconVerifier, now: i64) -> Result<()> {
        if org.did != self.org {
            return Err(Error::Token("heartbeat for another org".into()));
        }
        h.verify(org)?;
        if let (Some(head), Some(known)) = (&h.head, self.digests.get(&h.seq)) {
            if head != known {
                self.forked = true;
                return Err(Error::Token(format!("duplicity: heartbeat names another entry {}", h.seq)));
            }
        }
        let proven = match &h.beacon {
            Some(b) => Some(beacons.verify(b)?),
            None if !self.policy.require_beacon => Some(h.ts.min(now)),
            None => None,
        };
        if let Some(t) = proven {
            if t > now.max(self.clock) + 60 {
                return Err(Error::Token("heartbeat proves a time in the future".into()));
            }
            self.proven = Some(self.proven.map_or(t, |p| p.max(t)));
        }
        self.head_seq = self.head_seq.max(h.seq);
        Ok(())
    }

    /// Freshness as of `now`. The clock never goes backwards, so rolling the system
    /// clock back can't make a stale view look fresh.
    pub fn freshness(&mut self, now: i64) -> Freshness {
        self.clock = self.clock.max(now);
        let seq = self.seq();
        let age = self.proven.map(|p| (self.clock - p).max(0));
        let level = if self.forked {
            Level::Forked
        } else if self.head_seq > seq {
            Level::Behind
        } else {
            match age {
                Some(a) if a <= self.policy.fresh_for => Level::Fresh,
                Some(a) if a <= self.policy.max_staleness => Level::Degraded,
                _ => Level::Stale,
            }
        };
        Freshness { level, age, seq, head_seq: self.head_seq }
    }

    fn revocations(&self) -> impl Iterator<Item = &Revocation> {
        self.entries.values().flat_map(|e| e.revoke.iter())
    }

    pub fn is_principal_revoked(&self, id: &str) -> bool {
        self.revocations().any(|r| matches!(r, Revocation::Principal { id: x } if x == id))
    }

    pub fn is_token_revoked(&self, jti: &str) -> bool {
        self.revocations().any(|r| matches!(r, Revocation::Token { jti: x } if x == jti))
    }

    pub fn is_device_revoked(&self, did: &str, device: &str) -> bool {
        self.revocations().any(|r| matches!(r, Revocation::Device { did: d, device: x } if d == did && x == device))
    }

    /// Sets a principal has been removed from.
    pub fn excluded_sets(&self, id: &str) -> BTreeSet<String> {
        self.revocations()
            .filter_map(|r| match r {
                Revocation::Member { id: x, set } if x == id => Some(set.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn revoked_policies(&self) -> BTreeSet<String> {
        self.revocations()
            .filter_map(|r| match r {
                Revocation::Policy { id } => Some(id.clone()),
                _ => None,
            })
            .collect()
    }
}

/// One authorization question.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub principal: &'a Principal,
    /// The token's `jti`, if the principal came from a token.
    pub jti: Option<&'a str>,
    pub action: &'a str,
    pub resource: &'a Resource,
    pub context: &'a Value,
}

/// Decide with revocations and freshness applied (spec §8.9):
///
/// 1. a stale, behind or forked view denies everything;
/// 2. a revoked principal or token is denied;
/// 3. memberships are recomputed from the slice with revoked memberships excluded
///    (so anything that came through them goes too), whatever the token claimed;
/// 4. revoked permit policies are dropped;
/// 5. policies see `context.kith = {sync_age, degraded, revocation_seq}`.
pub fn authorize(slice: &Slice, follower: &mut Follower, req: &Request, now: i64) -> Result<AuthzDecision> {
    let Request { principal, jti, action, resource, context } = *req;
    let deny = |why: &str| Ok(AuthzDecision { allowed: false, reasons: vec![why.to_string()], errors: vec![] });
    let f = follower.freshness(now);
    if !f.allows_decisions() {
        return deny(&format!("freshness:{}", serde_json::to_value(f.level)?.as_str().unwrap_or("stale")));
    }
    if follower.is_principal_revoked(&principal.id) {
        return deny("revoked:principal");
    }
    if jti.is_some_and(|j| follower.is_token_revoked(j)) {
        return deny("revoked:token");
    }
    let engine = slice.engine_without(&follower.revoked_policies())?;
    let attrs = engine.attributes(&principal.id, &principal.attrs);
    let m = engine.memberships_excluding(&principal.id, &attrs, &follower.excluded_sets(&principal.id))?;
    let p = Principal { attrs, groups: m.groups, roles: m.roles, ..principal.clone() };
    let mut ctx = match context {
        Value::Object(o) => o.clone(),
        _ => Map::new(),
    };
    ctx.insert("kith".into(), f.cedar_context());
    engine.authorize(&p, action, resource, &Value::Object(ctx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::Bundle;
    use crate::dag::MemStore;
    use crate::kel::{new_inception, verify_log, Device, DeviceKind};
    use crate::keys::KeyType;
    use crate::pdag::{build, load, Query};
    use crate::policy::SignerPolicy;

    /// A test beacon whose "signature" is the publication time.
    struct ClockBeacon;
    impl BeaconVerifier for ClockBeacon {
        fn verify(&self, v: &BeaconValue) -> Result<i64> {
            match v {
                BeaconValue::Drand { round, signature, .. } if signature == "ok" => Ok(*round as i64),
                _ => Err(Error::Signature("bad beacon".into())),
            }
        }
    }
    fn beacon(t: i64) -> Option<BeaconValue> {
        Some(BeaconValue::Drand { chain: "test".into(), round: t as u64, signature: "ok".into() })
    }

    struct Org {
        admin: LocalSigner,
        revoker: LocalSigner,
        state: KeyState,
    }

    fn org() -> Org {
        let admin = LocalSigner::generate(KeyType::Ed25519);
        let revoker = LocalSigner::generate(KeyType::Ed25519);
        let dev = Device { id: "hub".into(), key: revoker.id.clone(), name: "hub revoker".into(), kind: DeviceKind::Software, aal: 1, caps: vec!["revoke".into()], rp_id: None, xkey: None };
        let next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);
        let mut inc = new_inception(SignerPolicy::single(&admin.id), &next, vec![dev]);
        inc.sign(&admin).unwrap();
        inc.sign(&revoker).unwrap();
        let state = verify_log(&[inc], &VerifyOptions::default()).unwrap();
        Org { admin, revoker, state }
    }

    fn entry(o: &Org, prev: Option<&Entry>, r: Vec<Revocation>) -> Entry {
        let mut e = Entry::new(&o.state.did, prev, r).unwrap();
        e.sign(&o.admin).unwrap();
        e
    }

    fn heartbeat(o: &Org, latest: Option<&Entry>, t: i64) -> Heartbeat {
        let mut h = Heartbeat::new(&o.state.did, latest, beacon(t)).unwrap();
        h.sign(&o.revoker).unwrap();
        h
    }

    #[test]
    fn freshness_degrades_then_fails_closed() {
        let o = org();
        let mut f = Follower::new(&o.state.did, 0, FreshnessPolicy { fresh_for: 60, max_staleness: 600, require_beacon: true });
        assert_eq!(f.freshness(1000).level, Level::Stale, "no heartbeat yet");
        f.apply_heartbeat(&o.state, &heartbeat(&o, None, 1000), &ClockBeacon, 1000).unwrap();
        assert_eq!(f.freshness(1030).level, Level::Fresh);
        assert_eq!(f.freshness(1300).level, Level::Degraded);
        assert_eq!(f.freshness(1700).level, Level::Stale);
        // Rolling the clock back doesn't help.
        assert_eq!(f.freshness(1010).level, Level::Stale);
        // Unbeaconed heartbeats don't count when a beacon is required.
        let mut h = Heartbeat::new(&o.state.did, None, None).unwrap();
        h.ts = 1700;
        h.sign(&o.revoker).unwrap();
        f.apply_heartbeat(&o.state, &h, &ClockBeacon, 1700).unwrap();
        assert_eq!(f.freshness(1700).level, Level::Stale);
        // A beacon claiming the future is rejected.
        assert!(f.apply_heartbeat(&o.state, &heartbeat(&o, None, 99_999), &ClockBeacon, 1700).is_err());
        // Someone else's key can't sign heartbeats.
        let mut forged = heartbeat(&o, None, 1700);
        forged.sigs.clear();
        forged.sign(&LocalSigner::generate(KeyType::Ed25519)).unwrap();
        assert!(f.apply_heartbeat(&o.state, &forged, &ClockBeacon, 1700).is_err());
    }

    #[test]
    fn gaps_and_forks_are_detected() {
        let o = org();
        let e1 = entry(&o, None, vec![Revocation::Token { jti: "a".into() }]);
        let e2 = entry(&o, Some(&e1), vec![Revocation::Token { jti: "b".into() }]);
        let e3 = entry(&o, Some(&e2), vec![Revocation::Token { jti: "c".into() }]);
        let mut f = Follower::new(&o.state.did, 0, FreshnessPolicy::default());
        f.apply_entry(&o.state, &e1).unwrap();
        f.apply_heartbeat(&o.state, &heartbeat(&o, Some(&e3), 100), &ClockBeacon, 100).unwrap();
        assert_eq!(f.freshness(100).level, Level::Behind, "a heartbeat named entry 3");
        f.apply_entry(&o.state, &e3).unwrap();
        assert_eq!(f.freshness(100).level, Level::Behind, "entry 2 still missing");
        f.apply_entry(&o.state, &e2).unwrap();
        assert_eq!(f.freshness(100).level, Level::Fresh);
        assert!(f.is_token_revoked("b"));

        let other = entry(&o, Some(&e2), vec![]);
        assert!(f.apply_entry(&o.state, &other).is_err());
        assert_eq!(f.freshness(100).level, Level::Forked);
    }

    #[test]
    fn compaction_drops_entries_the_root_reflects() {
        let o = org();
        let e1 = entry(&o, None, vec![Revocation::Principal { id: "did:kith:bob".into() }]);
        let e2 = entry(&o, Some(&e1), vec![Revocation::Principal { id: "did:kith:eve".into() }]);
        let mut f = Follower::new(&o.state.did, 0, FreshnessPolicy::default());
        f.apply_entry(&o.state, &e1).unwrap();
        f.apply_entry(&o.state, &e2).unwrap();
        f.set_base(1);
        assert!(!f.is_principal_revoked("did:kith:bob"), "now reflected in the policy root itself");
        assert!(f.is_principal_revoked("did:kith:eve"));
        assert_eq!(f.seq(), 2);
    }

    fn setup() -> (Org, Slice, Follower) {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/authz.json")).unwrap();
        let mut bundle: Bundle = serde_json::from_value(v["bundle"].clone()).unwrap();
        bundle.policies.push_str(
            "\n@id(\"pay-needs-fresh\")\nforbid(principal, action == Action::\"Mutation.payInvoice\", resource) unless { context has kith && context.kith.sync_age < 60 };",
        );
        let store = MemStore::new();
        let root = build(&store, &bundle).unwrap();
        let q = Query::Actions { actions: vec!["Query.invoices".into(), "Mutation.payInvoice".into()], principals: vec!["did:kith:ada".into()] };
        let slice = load(&store, &root, &q).unwrap();
        let o = org();
        let f = Follower::new(&o.state.did, 0, FreshnessPolicy { fresh_for: 30, max_staleness: 3600, require_beacon: true });
        (o, slice, f)
    }

    fn ada() -> Principal {
        let mut attrs = Map::new();
        attrs.insert("aal".into(), json!(2));
        Principal { id: "did:kith:ada".into(), attrs, groups: vec!["finance".into()], roles: vec!["billing-reader".into()], actor: None, caps: None }
    }

    #[test]
    fn member_revocation_cascades_and_ignores_token_claims() {
        let (o, slice, mut f) = setup();
        f.apply_heartbeat(&o.state, &heartbeat(&o, None, 1000), &ClockBeacon, 1000).unwrap();
        let op = Resource::new("Operation", "Query.invoices");
        assert!(authorize(&slice, &mut f, &Request { principal: &ada(), jti: None, action: "Query.invoices", resource: &op, context: &json!({}) }, 1000).unwrap().allowed);

        // Removing ada from finance also removes billing-reader (via group:finance),
        // even though her token still says billing-reader.
        let e1 = entry(&o, None, vec![Revocation::Member { id: "did:kith:ada".into(), set: "Group::finance".into() }]);
        f.apply_entry(&o.state, &e1).unwrap();
        let d = authorize(&slice, &mut f, &Request { principal: &ada(), jti: None, action: "Query.invoices", resource: &op, context: &json!({}) }, 1001).unwrap();
        assert!(!d.allowed, "{d:?}");
    }

    #[test]
    fn policy_revocation_removes_permits_only() {
        let (o, slice, mut f) = setup();
        f.apply_heartbeat(&o.state, &heartbeat(&o, None, 1000), &ClockBeacon, 1000).unwrap();
        let e1 = entry(&o, None, vec![Revocation::Policy { id: "read-invoices".into() }, Revocation::Policy { id: "no-delegated-pay".into() }]);
        f.apply_entry(&o.state, &e1).unwrap();
        let op = Resource::new("Operation", "Query.invoices");
        assert!(!authorize(&slice, &mut f, &Request { principal: &ada(), jti: None, action: "Query.invoices", resource: &op, context: &json!({}) }, 1000).unwrap().allowed);
        // The forbid on delegated payments survives its "revocation".
        let mut delegated = ada();
        delegated.actor = Some("did:kith:assistant".into());
        let pay = Resource::new("Operation", "Mutation.payInvoice");
        assert!(!authorize(&slice, &mut f, &Request { principal: &delegated, jti: None, action: "Mutation.payInvoice", resource: &pay, context: &json!({"amount": 5}) }, 1000).unwrap().allowed);
        assert!(authorize(&slice, &mut f, &Request { principal: &ada(), jti: None, action: "Mutation.payInvoice", resource: &pay, context: &json!({"amount": 5}) }, 1000).unwrap().allowed);
    }

    #[test]
    fn policies_can_demand_fresher_views_than_the_verifier() {
        let (o, slice, mut f) = setup();
        f.apply_heartbeat(&o.state, &heartbeat(&o, None, 1000), &ClockBeacon, 1000).unwrap();
        let pay = Resource::new("Operation", "Mutation.payInvoice");
        let read = Resource::new("Operation", "Query.invoices");
        assert!(authorize(&slice, &mut f, &Request { principal: &ada(), jti: None, action: "Mutation.payInvoice", resource: &pay, context: &json!({"amount": 5}) }, 1010).unwrap().allowed);
        // 10 minutes without a heartbeat: degraded. Reads still work; the payment
        // policy wants a view younger than 60 s.
        assert_eq!(f.freshness(1600).level, Level::Degraded);
        assert!(authorize(&slice, &mut f, &Request { principal: &ada(), jti: None, action: "Query.invoices", resource: &read, context: &json!({}) }, 1600).unwrap().allowed);
        assert!(!authorize(&slice, &mut f, &Request { principal: &ada(), jti: None, action: "Mutation.payInvoice", resource: &pay, context: &json!({"amount": 5}) }, 1600).unwrap().allowed);
        // Past the verifier's own budget: nothing.
        let d = authorize(&slice, &mut f, &Request { principal: &ada(), jti: None, action: "Query.invoices", resource: &read, context: &json!({}) }, 5000).unwrap();
        assert_eq!(d.reasons, vec!["freshness:stale"]);
        // Principal and token revocations.
        f.apply_heartbeat(&o.state, &heartbeat(&o, None, 5000), &ClockBeacon, 5000).unwrap();
        let e1 = entry(&o, None, vec![Revocation::Token { jti: "t1".into() }]);
        f.apply_entry(&o.state, &e1).unwrap();
        assert_eq!(authorize(&slice, &mut f, &Request { principal: &ada(), jti: Some("t1"), action: "Query.invoices", resource: &read, context: &json!({}) }, 5000).unwrap().reasons, vec!["revoked:token"]);
    }
}
