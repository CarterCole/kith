//! Organizations: policy DAG blocks, slices, revocation chains and heartbeats
//! (spec §8).
//!
//! Nothing here needs trusting. Blocks are content-addressed, the policy root is
//! a `policy_root` event in the org's own KEL, and revocations and heartbeats are
//! signed by the org's revokers. The hub stores and relays them, and signs
//! heartbeats itself when the org has added the hub's revoker key as a device with
//! the `revoke` capability.
//!
//! | endpoint                                   | purpose                                        |
//! |--------------------------------------------|------------------------------------------------|
//! | `GET  /v1/hub`                             | hub info, including its revoker key            |
//! | `POST /v1/hub/revoker`                     | co-sign an org's `add_device` for that key     |
//! | `PUT  /v1/blocks`                          | upload blocks (`{cid: block}`); CIDs checked   |
//! | `GET  /v1/blocks/{cid}`, `/ipfs/{cid}`     | one raw block (IPFS trustless-gateway shape)   |
//! | `GET  /v1/policy/{org}`                    | the org's current policy root                  |
//! | `POST /v1/policy/{org}/slice`              | a slice plus its proof blocks                  |
//! | `GET/POST /v1/revocations/{org}`           | entries after `?after=N` / append one          |
//! | `GET  /v1/revocations/{org}/heartbeat`     | the newest heartbeat                           |
//! | `GET  /v1/revocations/{org}/events`        | server-sent events: `entry`, `heartbeat`       |

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, Query as QueryParams, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use kith_core::beacon::BeaconValue;
use kith_core::dag::{blocks_from_json, cid_of, BlockGet, BlockPut, FsStore};
use kith_core::kel::KeyState;
use kith_core::keys::{KeyType, LocalSigner};
use kith_core::pdag::{self, Query, Slice};
use kith_core::revoke::{Entry, Heartbeat, Revocation};
use kith_core::session::KelResolver;

use crate::{read_json, write_json, ApiError, ApiResult, Hub};

/// Largest block the hub accepts.
pub const MAX_BLOCK: usize = 256 * 1024;

/// Where heartbeats get their beacon value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BeaconSource {
    None,
    /// `{base}/{chain}/public/latest`, e.g. `https://api.drand.sh` + quicknet.
    Drand { base: String, chain: String },
    /// A NIST 2.0-format beacon, e.g. `https://beacon.nist.gov/beacon/2.0`.
    Nist2 { base: String },
}

impl BeaconSource {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "none" => BeaconSource::None,
            "drand" => BeaconSource::Drand { base: "https://api.drand.sh".into(), chain: kith_core::beacon::QUICKNET_CHAIN.into() },
            "nist" => BeaconSource::Nist2 { base: "https://beacon.nist.gov/beacon/2.0".into() },
            other => anyhow::bail!("unknown beacon {other:?} (none, drand, nist)"),
        })
    }

    async fn fetch(&self, http: &reqwest::Client) -> anyhow::Result<Option<BeaconValue>> {
        Ok(match self {
            BeaconSource::None => None,
            BeaconSource::Drand { base, chain } => {
                let v: Value = http.get(format!("{base}/{chain}/public/latest")).send().await?.error_for_status()?.json().await?;
                Some(BeaconValue::Drand {
                    chain: chain.clone(),
                    round: v["round"].as_u64().ok_or_else(|| anyhow::anyhow!("drand: no round"))?,
                    signature: v["signature"].as_str().unwrap_or_default().into(),
                })
            }
            BeaconSource::Nist2 { base } => {
                let v: Value = http.get(format!("{base}/pulse/last")).send().await?.error_for_status()?.json().await?;
                Some(BeaconValue::Nist2 { pulse: v["pulse"].clone() })
            }
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Push {
    Entry(Entry),
    Heartbeat(Heartbeat),
}

pub struct Orgs {
    pub blocks: FsStore,
    /// The hub's revoker key. An org opts in by adding it as a `revoke` device.
    pub revoker: LocalSigner,
    chains: Mutex<HashMap<String, Vec<Entry>>>,
    heartbeats: Mutex<HashMap<String, Heartbeat>>,
    push: broadcast::Sender<(String, Push)>,
    dir: std::path::PathBuf,
}

impl Orgs {
    pub fn open(data_dir: &std::path::Path) -> anyhow::Result<Self> {
        let key_path = data_dir.join("hub-revoker.json");
        let revoker = match read_json(&key_path) {
            Some(v) => LocalSigner::from_json(&v)?,
            None => {
                let s = LocalSigner::generate(KeyType::Ed25519);
                write_json(&key_path, &s.to_json())?;
                s
            }
        };
        let dir = data_dir.join("revocations");
        std::fs::create_dir_all(&dir)?;
        let mut chains = HashMap::new();
        for f in std::fs::read_dir(&dir)? {
            if let Some(v) = read_json(&f?.path()) {
                let entries: Vec<Entry> = serde_json::from_value(v)?;
                if let Some(e) = entries.first() {
                    chains.insert(e.org.clone(), entries);
                }
            }
        }
        Ok(Orgs {
            blocks: FsStore(data_dir.join("blocks")),
            revoker,
            chains: Mutex::new(chains),
            heartbeats: Mutex::new(HashMap::new()),
            push: broadcast::channel(256).0,
            dir,
        })
    }

    pub fn entries(&self, org: &str, after: u64) -> Vec<Entry> {
        self.chains.lock().unwrap().get(org).map(|c| c.iter().filter(|e| e.seq > after).cloned().collect()).unwrap_or_default()
    }

    pub fn latest(&self, org: &str) -> Option<Entry> {
        self.chains.lock().unwrap().get(org).and_then(|c| c.last().cloned())
    }

    /// Append the next entry of an org's chain (checked against its KEL).
    pub fn append(&self, st: &KeyState, e: Entry) -> ApiResult<()> {
        e.verify(st)?;
        let mut chains = self.chains.lock().unwrap();
        let chain = chains.entry(st.did.clone()).or_default();
        let want_prev = chain.last().map(Entry::digest).transpose()?;
        if e.seq != chain.len() as u64 + 1 || e.prev != want_prev {
            let msg = format!("expected seq {} after {:?}", chain.len() + 1, want_prev);
            return Err(ApiError(StatusCode::CONFLICT, "not_next".into(), msg, None));
        }
        chain.push(e.clone());
        let file = self.dir.join(format!("{}.json", st.did.replace(':', "_")));
        write_json(&file, &serde_json::to_value(&*chain).map_err(kith_core::Error::from)?)?;
        drop(chains);
        let _ = self.push.send((st.did.clone(), Push::Entry(e)));
        Ok(())
    }

    pub fn heartbeat(&self, org: &str) -> Option<Heartbeat> {
        self.heartbeats.lock().unwrap().get(org).cloned()
    }

    /// Sign and publish a heartbeat for `org`.
    pub fn beat(&self, org: &str, beacon: Option<BeaconValue>) -> kith_core::Result<Heartbeat> {
        let mut h = Heartbeat::new(org, self.latest(org).as_ref(), beacon)?;
        h.sign(&self.revoker)?;
        self.heartbeats.lock().unwrap().insert(org.into(), h.clone());
        let _ = self.push.send((org.into(), Push::Heartbeat(h.clone())));
        Ok(h)
    }

    /// Everything revoked for `org` since its policy root's `revocations_through`.
    pub fn active_revocations(&self, org: &str, through: u64) -> Vec<Revocation> {
        self.entries(org, through).into_iter().flat_map(|e| e.revoke).collect()
    }
}

impl Hub {
    /// Orgs whose KEL lists this hub's revoker as a `revoke` device.
    pub fn served_orgs(&self) -> Vec<String> {
        let me = &self.orgs.revoker.id;
        self.kel_dids()
            .into_iter()
            .filter(|did| self.resolve(did).is_ok_and(|st| st.devices.values().any(|d| &d.key == me && d.has_cap("revoke"))))
            .collect()
    }

    fn policy_head(&self, org: &str) -> ApiResult<(KeyState, kith_core::kel::PolicyHead)> {
        let st = self.resolve(org).map_err(|e| ApiError(StatusCode::NOT_FOUND, "not_found".into(), e.to_string(), None))?;
        let head = st.policy.clone().ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), format!("{org} has no policy root"), None))?;
        Ok((st, head))
    }

    /// A slice of an org's current policy DAG.
    pub fn slice(&self, org: &str, q: &Query) -> ApiResult<(Slice, BTreeMap<String, Vec<u8>>, u64)> {
        let (_, head) = self.policy_head(org)?;
        let (slice, blocks) = pdag::prove(&self.orgs.blocks, &head.root, q)?;
        Ok((slice, blocks, head.revocations_through))
    }

    /// Groups, roles and a revocation verdict for `did` from the configured policy
    /// org, if there is one. `Ok(None)`: no org configured, use the bundle file.
    pub(crate) fn org_memberships(&self, did: &str, attrs: &serde_json::Map<String, Value>) -> ApiResult<Option<(kith_core::authz::Memberships, serde_json::Map<String, Value>)>> {
        let Some(org) = &self.cfg.policy_org else { return Ok(None) };
        let (slice, _, through) = self.slice(org, &Query::Principal { id: did.into() })?;
        let revoked = self.orgs.active_revocations(org, through);
        if revoked.iter().any(|r| matches!(r, Revocation::Principal { id } if id == did)) {
            return Err(ApiError::unauthorized("principal revoked by the organization"));
        }
        let skip: BTreeSet<String> = revoked.iter().filter_map(|r| if let Revocation::Policy { id } = r { Some(id.clone()) } else { None }).collect();
        let excluded: BTreeSet<String> =
            revoked.iter().filter_map(|r| if let Revocation::Member { id, set } = r { (id == did).then(|| set.clone()) } else { None }).collect();
        let engine = slice.engine_without(&skip)?;
        let attrs = engine.attributes(did, attrs);
        Ok(Some((engine.memberships_excluding(did, &attrs, &excluded)?, attrs)))
    }
}

/// Sign heartbeats for every served org, forever.
pub async fn heartbeat_loop(hub: Arc<Hub>) {
    let http = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().expect("http client");
    let mut tick = tokio::time::interval(Duration::from_secs(hub.cfg.heartbeat_secs.max(1)));
    loop {
        tick.tick().await;
        let orgs = hub.served_orgs();
        if orgs.is_empty() {
            continue;
        }
        let beacon = match hub.cfg.beacon.fetch(&http).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("heartbeat: beacon unavailable ({e}); signing without one");
                None
            }
        };
        for org in orgs {
            if let Err(e) = hub.orgs.beat(&org, beacon.clone()) {
                eprintln!("heartbeat for {org}: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------- handlers

pub async fn info(State(h): State<Arc<Hub>>) -> Json<Value> {
    Json(json!({
        "issuer": h.cfg.issuer,
        "revoker": h.orgs.revoker.id,
        "beacon": h.cfg.beacon,
        "heartbeat_secs": h.cfg.heartbeat_secs,
        "policy_org": h.cfg.policy_org,
        "orgs": h.served_orgs(),
    }))
}

/// Proof of possession for the hub's revoker key: sign an org's `add_device` event
/// that adds exactly that key with exactly the `revoke` capability, nothing else.
pub async fn sign_revoker(State(h): State<Arc<Hub>>, Json(ev): Json<kith_core::kel::Event>) -> ApiResult<Json<Value>> {
    let ok = matches!(&ev.body, kith_core::kel::EventBody::AddDevice { device } if device.key == h.orgs.revoker.id && device.caps == ["revoke"]);
    if !ok {
        return Err(ApiError::bad("invalid_request", "only an add_device event for this hub's revoker key with caps [\"revoke\"]"));
    }
    Ok(Json(json!(h.orgs.revoker.sign(&ev.signing_message()?)?)))
}

pub async fn put_blocks(State(h): State<Arc<Hub>>, Json(v): Json<Value>) -> ApiResult<Json<Value>> {
    let blocks = blocks_from_json(&v)?;
    for (cid, bytes) in &blocks {
        if bytes.len() > MAX_BLOCK || cid_of(bytes) != *cid {
            return Err(ApiError::bad("invalid_request", format!("block {cid} is too big or does not match its CID")));
        }
    }
    for (cid, bytes) in blocks.iter() {
        h.orgs.blocks.put(cid, bytes.clone())?;
    }
    Ok(Json(json!({ "stored": blocks.len() })))
}

pub async fn get_block(State(h): State<Arc<Hub>>, Path(cid): Path<String>) -> ApiResult<Response> {
    let cid = cid.trim_end_matches(".json").to_string();
    let bytes = h.orgs.blocks.get(&cid)?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), cid.clone(), None))?;
    Ok((
        [(header::CONTENT_TYPE, "application/vnd.ipld.raw"), (header::CACHE_CONTROL, "public, max-age=31536000, immutable")],
        bytes,
    )
        .into_response())
}

pub async fn policy(State(h): State<Arc<Hub>>, Path(org): Path<String>) -> ApiResult<Json<Value>> {
    let (st, head) = h.policy_head(&org)?;
    Ok(Json(json!({ "org": st.did, "kel_seq": st.seq, "root": head.root, "revocations_through": head.revocations_through, "ts": head.ts })))
}

pub async fn slice(State(h): State<Arc<Hub>>, Path(org): Path<String>, Json(q): Json<Query>) -> ApiResult<Json<Value>> {
    let (slice, blocks, through) = h.slice(&org, &q)?;
    let mut v = pdag::slice_response(&slice.root, &q, &blocks);
    v["revocations_through"] = json!(through);
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct After {
    #[serde(default)]
    after: u64,
}

pub async fn get_revocations(State(h): State<Arc<Hub>>, Path(org): Path<String>, QueryParams(q): QueryParams<After>) -> Json<Value> {
    Json(json!({ "entries": h.orgs.entries(&org, q.after), "heartbeat": h.orgs.heartbeat(&org) }))
}

pub async fn post_revocation(State(h): State<Arc<Hub>>, Path(org): Path<String>, Json(e): Json<Entry>) -> ApiResult<Json<Value>> {
    let st = h.resolve(&org).map_err(|e| ApiError(StatusCode::NOT_FOUND, "not_found".into(), e.to_string(), None))?;
    let seq = e.seq;
    h.orgs.append(&st, e)?;
    // Push a heartbeat right away so followers learn the new head without waiting.
    if h.served_orgs().contains(&org) {
        let last = h.orgs.heartbeat(&org).and_then(|b| b.beacon);
        h.orgs.beat(&org, last)?;
    }
    Ok(Json(json!({ "org": org, "seq": seq })))
}

pub async fn get_heartbeat(State(h): State<Arc<Hub>>, Path(org): Path<String>) -> ApiResult<Json<Value>> {
    let hb = h.orgs.heartbeat(&org).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), "no heartbeat yet".into(), None))?;
    Ok(Json(json!(hb)))
}

pub async fn events(State(h): State<Arc<Hub>>, Path(org): Path<String>) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = BroadcastStream::new(h.orgs.push.subscribe());
    let stream = rx.filter_map(move |m| {
        let (o, push) = m.ok()?;
        if o != org {
            return None;
        }
        let (name, data) = match push {
            Push::Entry(e) => ("entry", json!(e)),
            Push::Heartbeat(b) => ("heartbeat", json!(b)),
        };
        Some(Ok(SseEvent::default().event(name).data(data.to_string())))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
