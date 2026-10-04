//! `kith policy …`, `kith revoke …`, `kith revocations` and `kith anchor …`:
//! policy DAGs, revocations, freshness and timestamps (spec §8).

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use serde_json::json;

use kith_core::authz::Bundle;
use kith_core::beacon::{BeaconValue, Verifiers};
use kith_core::dag::{blocks_from_json, blocks_to_json, MemStore};
use kith_core::kel::{next_event, Device, DeviceKind, EventBody, KeyState};
use kith_core::pdag::{self, Query};
use kith_core::revoke::{Entry, FreshnessPolicy, Follower, Heartbeat, Revocation};
use kith_core::util::now;

use super::{check, fetch_state, http, print, publish, Home};

#[derive(Subcommand)]
pub enum PolicyCmd {
    /// Build a policy bundle into a DAG, upload its blocks, and commit its root in
    /// this identity's KEL (this identity is the org).
    Publish {
        bundle: PathBuf,
        /// Also write every block to this directory (for IPFS: `ipfs dag import`).
        #[arg(long)]
        blocks_dir: Option<PathBuf>,
    },
    /// Fetch a slice, check it against the org's committed root, and summarize it.
    Slice {
        /// The org (default: this identity).
        #[arg(long)]
        org: Option<String>,
        /// Actions to decide (repeatable).
        #[arg(long = "action")]
        actions: Vec<String>,
        /// Principals whose directory entries to include (repeatable).
        #[arg(long = "principal")]
        principals: Vec<String>,
        /// Print the proof blocks too.
        #[arg(long)]
        blocks: bool,
    },
    /// Everything that can apply to one principal: memberships and policies, with
    /// the org's revocations applied.
    Grants {
        #[arg(long)]
        org: Option<String>,
        /// Default: this identity.
        #[arg(long)]
        principal: Option<String>,
        /// Assurance level to evaluate dynamic groups at.
        #[arg(long, default_value_t = 1)]
        aal: u8,
    },
    /// Let the hub sign this org's heartbeats: add its revoker key as a device
    /// that can only revoke.
    AddRevoker,
}

#[derive(Subcommand)]
pub enum RevokeCmd {
    /// All access for a principal.
    Principal { id: String },
    /// One membership, e.g. `kith revoke member did:kith:… Group::finance`.
    Member { id: String, set: String },
    /// A device of some identity.
    Device { did: String, device: String },
    /// A permit policy by id.
    Policy { id: String },
    /// A token or session by `jti`.
    Token { jti: String },
}

#[derive(Subcommand)]
pub enum AnchorCmd {
    /// Timestamp a digest with OpenTimestamps calendars. Default: this identity's
    /// latest `policy_root` event.
    Stamp {
        /// A 32-byte digest (hex or base64url) instead.
        #[arg(long)]
        digest: Option<String>,
        /// Anchor revocation entry N of this org instead.
        #[arg(long)]
        revocation: Option<u64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Ask the calendars whether Bitcoin has confirmed a stamp yet.
    Upgrade { file: PathBuf },
    /// Check a stamp against Bitcoin block headers (from an Esplora API).
    Verify {
        file: PathBuf,
        #[arg(long, default_value = "https://blockstream.info/api")]
        esplora: String,
    },
}

fn digest32(s: &str) -> Result<[u8; 32]> {
    let b = kith_core::ots::hex_decode(s).or_else(|_| kith_core::util::b64u_decode(s)).map_err(|_| anyhow!("digest must be hex or base64url"))?;
    b.try_into().map_err(|_| anyhow!("digest must be 32 bytes"))
}

fn ots_http() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(20)).user_agent("kith-cli").build()?)
}

pub fn anchor(home: &Home, cmd: AnchorCmd) -> Result<()> {
    use kith_core::ots::{self, DetachedFile, Timestamp};
    match cmd {
        AnchorCmd::Stamp { digest, revocation, out } => {
            let (digest, what) = match (digest, revocation) {
                (Some(d), _) => (digest32(&d)?, "digest".to_string()),
                (None, Some(n)) => {
                    let did = home.did()?;
                    let r = check(http().get(format!("{}/v1/revocations/{did}?after={}", home.hub()?, n.saturating_sub(1))).send()?)?;
                    let e: Entry = serde_json::from_value(r["entries"].get(0).cloned().ok_or_else(|| anyhow!("no revocation {n}"))?)?;
                    (digest32(&e.digest()?)?, format!("revocation {n}"))
                }
                (None, None) => {
                    let st = home.state()?;
                    let seq = st.policy.as_ref().ok_or_else(|| anyhow!("no policy_root yet"))?.seq;
                    let ev = &home.kel()?[seq as usize];
                    (digest32(&ev.digest()?)?, format!("policy_root at kel seq {seq}"))
                }
            };
            let mut nonce = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
            let (mut file, msg) = ots::stamp_request(digest, nonce);
            let client = ots_http()?;
            let mut ok = 0;
            for cal in ots::CALENDARS {
                let resp = client
                    .post(format!("{cal}/digest"))
                    .header("accept", "application/vnd.opentimestamps.v1")
                    .body(msg.clone())
                    .send()
                    .and_then(|r| r.error_for_status())
                    .and_then(|r| r.bytes());
                match resp {
                    Ok(body) => match ots::add_calendar_response(&mut file, &msg, &body) {
                        Ok(()) => ok += 1,
                        Err(e) => eprintln!("{cal}: bad response ({e})"),
                    },
                    Err(e) => eprintln!("{cal}: {e}"),
                }
            }
            if ok == 0 {
                bail!("no calendar accepted the digest");
            }
            std::fs::write(&out, file.to_bytes())?;
            println!("{}", ots::hex(&digest));
            eprintln!("stamped {what} with {ok} calendars; Bitcoin confirms in a few hours (`kith anchor upgrade {}`)", out.display());
        }
        AnchorCmd::Upgrade { file } => {
            let mut f = DetachedFile::parse(&std::fs::read(&file)?)?;
            let client = ots_http()?;
            let digest = f.digest;
            let mut changed = false;
            for (uri, commitment) in f.pending()? {
                if !ots::may_follow(&uri) {
                    eprintln!("skipping calendar not on the allowlist: {uri}");
                    continue;
                }
                let r = client.get(format!("{uri}/timestamp/{}", ots::hex(&commitment))).header("accept", "application/vnd.opentimestamps.v1").send()?;
                if r.status().is_success() {
                    let ts = Timestamp::parse(&r.bytes()?)?;
                    changed |= f.timestamp.merge_at(&digest, &commitment, &ts)?;
                } else {
                    eprintln!("{uri}: {}", r.text().unwrap_or_default().trim());
                }
            }
            if changed {
                std::fs::write(&file, f.to_bytes())?;
            }
            let atts: Vec<String> = f.attestations()?.into_iter().map(|r| format!("{:?}", r.attestation)).collect();
            print(&json!({"upgraded": changed, "attestations": atts}));
        }
        AnchorCmd::Verify { file, esplora } => {
            let f = DetachedFile::parse(&std::fs::read(&file)?)?;
            let client = ots_http()?;
            let header = |height: u64| -> kith_core::Result<Vec<u8>> {
                let io = |e: reqwest::Error| kith_core::Error::NotFound(format!("block {height}: {e}"));
                let get = |url: String| client.get(url).send().and_then(|r| r.error_for_status()).and_then(|r| r.text()).map_err(io);
                let hash = get(format!("{esplora}/block-height/{height}"))?;
                let h = ots::hex_decode(get(format!("{esplora}/block/{}/header", hash.trim()))?.trim())?;
                // The header must hash to the block hash we asked about.
                let mut id = kith_core::util::sha256(kith_core::util::sha256(&h)).to_vec();
                id.reverse();
                if ots::hex(&id) != hash.trim() {
                    return Err(kith_core::Error::Signature(format!("block {height}: header does not hash to {}", hash.trim())));
                }
                Ok(h)
            };
            match f.verify_bitcoin(&header)? {
                Some((height, time)) => print(&json!({"digest": ots::hex(&f.digest), "bitcoin_block": height, "existed_by": time})),
                None => bail!("no Bitcoin attestation yet (pending at {:?}); try `kith anchor upgrade`", f.pending()?.keys().collect::<Vec<_>>()),
            }
        }
    }
    Ok(())
}

fn org_or_self(home: &Home, org: Option<String>) -> Result<String> {
    org.map(Ok).unwrap_or_else(|| home.did())
}

fn policy_root(st: &KeyState) -> Result<(String, u64)> {
    let p = st.policy.as_ref().ok_or_else(|| anyhow!("{} has not published a policy root", st.did))?;
    Ok((p.root.clone(), p.revocations_through))
}

/// Beacon verifiers, with the NIST-format certificate the heartbeat names fetched
/// from the beacon's own origin (only origins on the built-in allowlist).
pub fn verifiers_for(h: Option<&Heartbeat>) -> Result<Verifiers> {
    let mut v = Verifiers::default();
    if let Some(BeaconValue::Nist2 { pulse }) = h.and_then(|h| h.beacon.as_ref()) {
        let (base, id) = v.nist_certificate_url(pulse)?;
        let pem = http().get(format!("{base}/certificate/{id}")).send()?.error_for_status()?.text()?;
        v.add_nist_certificate(&pem)?;
    }
    Ok(v)
}

fn follow(hub: &str, st: &KeyState, policy: FreshnessPolicy) -> Result<(Follower, Option<Heartbeat>)> {
    let (_, through) = policy_root(st).unwrap_or_default();
    let r = check(http().get(format!("{hub}/v1/revocations/{}?after={through}", st.did)).send()?)?;
    let mut f = Follower::new(&st.did, through, policy);
    for e in r["entries"].as_array().cloned().unwrap_or_default() {
        f.apply_entry(st, &serde_json::from_value(e)?)?;
    }
    let hb: Option<Heartbeat> = serde_json::from_value(r["heartbeat"].clone()).ok();
    if let Some(h) = &hb {
        f.apply_heartbeat(st, h, &verifiers_for(Some(h))?, now())?;
    }
    Ok((f, hb))
}

pub fn policy(home: &mut Home, cmd: PolicyCmd) -> Result<()> {
    let hub = home.hub()?;
    match cmd {
        PolicyCmd::Publish { bundle, blocks_dir } => {
            let b: Bundle = serde_json::from_str(&std::fs::read_to_string(&bundle).with_context(|| format!("reading {}", bundle.display()))?)?;
            let store = MemStore::new();
            let root = pdag::build(&store, &b)?;
            let blocks = store.blocks();
            if let Some(dir) = blocks_dir {
                std::fs::create_dir_all(&dir)?;
                for (cid, bytes) in &blocks {
                    std::fs::write(dir.join(cid), bytes)?;
                }
            }
            check(http().put(format!("{hub}/v1/blocks")).json(&blocks_to_json(&blocks)).send()?)?;
            let st = home.state()?;
            // Revocations up to now are presumed folded into the new bundle.
            let r = check(http().get(format!("{hub}/v1/revocations/{}", st.did)).send()?)?;
            let through = r["entries"].as_array().and_then(|a| a.last()).and_then(|e| e["seq"].as_u64()).unwrap_or(0);
            let mut ev = next_event(&st, EventBody::PolicyRoot { root: root.clone(), revocations_through: through });
            for m in home.signers("manage")? {
                ev.sign(&m)?;
            }
            home.append(ev)?;
            publish(home)?;
            println!("{root}");
            eprintln!("published {} blocks; policy root committed at kel seq {} (revocations through {through})", blocks.len(), home.state()?.seq);
        }
        PolicyCmd::Slice { org, actions, principals, blocks } => {
            let org = org_or_self(home, org)?;
            let st = fetch_state(&hub, &org)?;
            let (root, _) = policy_root(&st)?;
            let q = if actions.is_empty() && principals.len() == 1 {
                Query::Principal { id: principals[0].clone() }
            } else {
                Query::Actions { actions, principals }
            };
            let r = check(http().post(format!("{hub}/v1/policy/{org}/slice")).json(&q).send()?)?;
            // The hub is just a block source: everything is checked against the KEL's root.
            let proof = blocks_from_json(&r["blocks"])?;
            let bytes: usize = proof.values().map(Vec::len).sum();
            let slice = pdag::load(&MemStore::from_blocks(proof.clone()), &root, &q)?;
            let mut out = json!({
                "org": org, "root": root, "query": q,
                "policies": slice.policies.iter().map(|p| json!({"id": p.id, "effect": p.effect})).collect::<Vec<_>>(),
                "sets": slice.sets.keys().collect::<Vec<_>>(),
                "directory": slice.directory.keys().collect::<Vec<_>>(),
                "proof": {"blocks": proof.len(), "bytes": bytes},
            });
            if blocks {
                out["blocks"] = r["blocks"].clone();
            }
            print(&out);
        }
        PolicyCmd::Grants { org, principal, aal } => {
            let org = org_or_self(home, org)?;
            let id = principal.map(Ok).unwrap_or_else(|| home.did())?;
            let st = fetch_state(&hub, &org)?;
            let (root, _) = policy_root(&st)?;
            let q = Query::Principal { id: id.clone() };
            let r = check(http().post(format!("{hub}/v1/policy/{org}/slice")).json(&q).send()?)?;
            let slice = pdag::load(&MemStore::from_blocks(blocks_from_json(&r["blocks"])?), &root, &q)?;
            let (f, _) = follow(&hub, &st, FreshnessPolicy { require_beacon: false, ..Default::default() })?;
            let engine = slice.engine_without(&f.revoked_policies())?;
            let mut attrs = serde_json::Map::new();
            attrs.insert("aal".into(), json!(aal));
            let attrs = engine.attributes(&id, &attrs);
            let m = engine.memberships_excluding(&id, &attrs, &f.excluded_sets(&id))?;
            let revoked = f.revoked_policies();
            print(&json!({
                "principal": id, "org": org, "root": root,
                "revoked": f.is_principal_revoked(&id),
                "groups": m.groups, "roles": m.roles,
                "policies": slice.policies.iter().map(|p| json!({
                    "id": p.id, "effect": p.effect,
                    "revoked": p.effect == "permit" && revoked.contains(&p.id),
                    "text": p.text,
                })).collect::<Vec<_>>(),
            }));
        }
        PolicyCmd::AddRevoker => {
            let info = check(http().get(format!("{hub}/v1/hub")).send()?)?;
            let key = info["revoker"].as_str().ok_or_else(|| anyhow!("hub has no revoker key"))?.to_string();
            let st = home.state()?;
            if st.devices.values().any(|d| d.key == key) {
                bail!("the hub's revoker is already a device of {}", st.did);
            }
            let dev = Device {
                id: "hub-revoker".into(),
                key,
                name: format!("revoker at {hub}"),
                kind: DeviceKind::Software,
                aal: 1,
                caps: vec!["revoke".into()],
                rp_id: None,
                xkey: None,
            };
            let mut ev = next_event(&st, EventBody::AddDevice { device: dev });
            for m in home.signers("manage")? {
                ev.sign(&m)?;
            }
            let pop = check(http().post(format!("{hub}/v1/hub/revoker")).json(&ev).send()?)?;
            ev.add_sig(serde_json::from_value(pop)?);
            home.append(ev)?;
            publish(home)?;
            eprintln!("the hub can now sign revocations and heartbeats for {} (and nothing else)", st.did);
        }
    }
    Ok(())
}

pub fn revoke(home: &mut Home, cmd: RevokeCmd) -> Result<()> {
    let hub = home.hub()?;
    let st = home.state()?;
    let r = match cmd {
        RevokeCmd::Principal { id } => Revocation::Principal { id },
        RevokeCmd::Member { id, set } => {
            if !(set.starts_with("Group::") || set.starts_with("Role::")) {
                bail!("set must be Group::<name> or Role::<name>");
            }
            Revocation::Member { id, set }
        }
        RevokeCmd::Device { did, device } => Revocation::Device { did, device },
        RevokeCmd::Policy { id } => Revocation::Policy { id },
        RevokeCmd::Token { jti } => Revocation::Token { jti },
    };
    let chain = check(http().get(format!("{hub}/v1/revocations/{}", st.did)).send()?)?;
    let prev: Option<Entry> = chain["entries"].as_array().and_then(|a| a.last()).map(|e| serde_json::from_value(e.clone())).transpose()?;
    let mut e = Entry::new(&st.did, prev.as_ref(), vec![r])?;
    for m in home.signers("manage")? {
        e.sign(&m)?;
    }
    check(http().post(format!("{hub}/v1/revocations/{}", st.did)).json(&e).send()?)?;
    println!("{}", e.seq);
    eprintln!("revocation {} pushed", e.seq);
    Ok(())
}

pub fn status(home: &Home, org: Option<String>, policy: FreshnessPolicy, watch: Option<u64>) -> Result<()> {
    let hub = home.hub()?;
    let org = org_or_self(home, org)?;
    loop {
        let st = fetch_state(&hub, &org)?;
        let (mut f, hb) = follow(&hub, &st, policy)?;
        let fr = f.freshness(now());
        print(&json!({
            "org": org, "freshness": fr,
            "revocations": f.entries().flat_map(|e| e.revoke.clone()).collect::<Vec<_>>(),
            "heartbeat": hb.map(|h| json!({"seq": h.seq, "ts": h.ts, "beacon": h.beacon.map(|b| match b {
                BeaconValue::Drand { round, chain, .. } => json!({"drand": {"round": round, "chain": chain}}),
                BeaconValue::Nist2 { pulse } => json!({"nist2": {"uri": pulse["uri"], "timeStamp": pulse["timeStamp"]}}),
            })})),
        }));
        match watch {
            Some(secs) => std::thread::sleep(std::time::Duration::from_secs(secs)),
            None => return Ok(()),
        }
    }
}
