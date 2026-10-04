//! Content-addressed blocks and a deterministic Merkle map (spec §8.1–8.2).
//!
//! A block is canonical JSON in which a link is `{"/": "<cid>"}`, so every block is
//! also valid DAG-JSON and can be pinned on IPFS and fetched through any trustless
//! gateway. A CID is CIDv1 / dag-json (0x0129) / sha2-256, multibase base32 (`bagu…`).
//!
//! The Merkle map is a hash-array-mapped trie whose shape depends only on its
//! contents, never on insertion order, so two builders of the same map always get
//! the same root. A lookup touches one block per level and proves both presence
//! and absence of a key.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::util::sha256;
use crate::{Error, Result};

/// Multicodec for DAG-JSON.
pub const DAG_JSON: u64 = 0x0129;
/// Entries per leaf before it splits into 16 children.
pub const LEAF_MAX: usize = 8;

fn varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// The CID of a DAG-JSON block.
pub fn cid_of(bytes: &[u8]) -> String {
    let mut raw = vec![0x01];
    varint(DAG_JSON, &mut raw);
    raw.extend([0x12, 0x20]);
    raw.extend(sha256(bytes));
    format!("b{}", data_encoding::BASE32_NOPAD.encode(&raw).to_lowercase())
}

/// Encode a value as a block: canonical JSON bytes and their CID.
pub fn encode(v: &Value) -> Result<(String, Vec<u8>)> {
    let bytes = crate::canon::to_canonical(v)?.into_bytes();
    Ok((cid_of(&bytes), bytes))
}

pub fn link(cid: &str) -> Value {
    json!({ "/": cid })
}

/// The CID a `{"/": cid}` link points to.
pub fn as_link(v: &Value) -> Option<&str> {
    match v.as_object() {
        Some(o) if o.len() == 1 => o.get("/").and_then(Value::as_str),
        _ => None,
    }
}

/// Somewhere blocks come from. Stores are untrusted: [`get_verified`] checks the hash.
pub trait BlockGet {
    fn get(&self, cid: &str) -> Result<Option<Vec<u8>>>;
}

pub trait BlockPut: BlockGet {
    fn put(&self, cid: &str, bytes: Vec<u8>) -> Result<()>;
}

/// Fetch a block and check it hashes to its CID.
pub fn get_verified(store: &dyn BlockGet, cid: &str) -> Result<Value> {
    let bytes = store.get(cid)?.ok_or_else(|| Error::NotFound(format!("block {cid}")))?;
    if cid_of(&bytes) != cid {
        return Err(Error::Encoding(format!("block {cid} does not match its hash")));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn put_value(store: &dyn BlockPut, v: &Value) -> Result<String> {
    let (cid, bytes) = encode(v)?;
    store.put(&cid, bytes)?;
    Ok(cid)
}

/// An in-memory block store.
#[derive(Default)]
pub struct MemStore(pub Mutex<BTreeMap<String, Vec<u8>>>);

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn blocks(&self) -> BTreeMap<String, Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
    pub fn from_blocks(blocks: BTreeMap<String, Vec<u8>>) -> Self {
        MemStore(Mutex::new(blocks))
    }
}

impl BlockGet for MemStore {
    fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(cid).cloned())
    }
}

impl BlockPut for MemStore {
    fn put(&self, cid: &str, bytes: Vec<u8>) -> Result<()> {
        self.0.lock().unwrap().insert(cid.to_string(), bytes);
        Ok(())
    }
}

/// A directory of `<cid>` files.
pub struct FsStore(pub std::path::PathBuf);

impl BlockGet for FsStore {
    fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        if !cid.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::Encoding(format!("bad cid {cid:?}")));
        }
        match std::fs::read(self.0.join(cid)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Encoding(e.to_string())),
        }
    }
}

impl BlockPut for FsStore {
    fn put(&self, cid: &str, bytes: Vec<u8>) -> Result<()> {
        std::fs::create_dir_all(&self.0).map_err(|e| Error::Encoding(e.to_string()))?;
        std::fs::write(self.0.join(cid), bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// Wraps a store and remembers every block read through it: the proof for a lookup.
pub struct Recording<'a> {
    inner: &'a dyn BlockGet,
    pub seen: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl<'a> Recording<'a> {
    pub fn new(inner: &'a dyn BlockGet) -> Self {
        Recording { inner, seen: Mutex::new(BTreeMap::new()) }
    }
    pub fn into_blocks(self) -> BTreeMap<String, Vec<u8>> {
        self.seen.into_inner().unwrap()
    }
}

impl BlockGet for Recording<'_> {
    fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        let b = self.inner.get(cid)?;
        if let Some(b) = &b {
            self.seen.lock().unwrap().insert(cid.to_string(), b.clone());
        }
        Ok(b)
    }
}

/// Nibble `depth` of SHA-256(key): which child a key lives under at that depth.
fn nibble(key: &str, depth: usize) -> usize {
    let h = sha256(key.as_bytes());
    let b = h[depth / 2];
    (if depth.is_multiple_of(2) { b >> 4 } else { b & 0x0f }) as usize
}

/// Build a Merkle map. Returns the root CID; every node is written to `store`.
///
/// A node holding at most [`LEAF_MAX`] entries is a leaf `{"e": [[key, value], …]}`
/// sorted by key. Otherwise it is a branch `{"c": [link | null; 16]}` that splits
/// its entries by the next nibble of SHA-256(key).
pub fn map_build(store: &dyn BlockPut, entries: &BTreeMap<String, Value>) -> Result<String> {
    let all: Vec<(&String, &Value)> = entries.iter().collect();
    build_node(store, &all, 0)
}

fn build_node(store: &dyn BlockPut, entries: &[(&String, &Value)], depth: usize) -> Result<String> {
    if entries.len() <= LEAF_MAX {
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
        let e: Vec<Value> = sorted.iter().map(|(k, v)| json!([k, v])).collect();
        return put_value(store, &json!({ "e": e }));
    }
    if depth >= 64 {
        return Err(Error::Encoding("merkle map: hash collision".into()));
    }
    let mut buckets: Vec<Vec<(&String, &Value)>> = vec![vec![]; 16];
    for (k, v) in entries {
        buckets[nibble(k, depth)].push((k, v));
    }
    let mut c = vec![];
    for b in buckets {
        c.push(if b.is_empty() { Value::Null } else { link(&build_node(store, &b, depth + 1)?) });
    }
    put_value(store, &json!({ "c": c }))
}

/// Look `key` up in the map rooted at `root`. `Ok(None)` is a proof of absence:
/// every block on the path was hash-checked.
pub fn map_get(store: &dyn BlockGet, root: &str, key: &str) -> Result<Option<Value>> {
    let mut cid = root.to_string();
    for depth in 0..=64 {
        let node = get_verified(store, &cid)?;
        if let Some(e) = node.get("e").and_then(Value::as_array) {
            for pair in e {
                if pair.get(0).and_then(Value::as_str) == Some(key) {
                    return Ok(pair.get(1).cloned());
                }
            }
            return Ok(None);
        }
        let c = node.get("c").and_then(Value::as_array).filter(|c| c.len() == 16);
        let Some(c) = c else {
            return Err(Error::Encoding(format!("merkle map node {cid} is malformed")));
        };
        match &c[nibble(key, depth)] {
            Value::Null => return Ok(None),
            v => cid = as_link(v).ok_or_else(|| Error::Encoding("merkle map child is not a link".into()))?.to_string(),
        }
    }
    Err(Error::Encoding("merkle map too deep".into()))
}

/// Every entry of a map (walks the whole tree).
pub fn map_entries(store: &dyn BlockGet, root: &str) -> Result<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_string()];
    while let Some(cid) = stack.pop() {
        let node = get_verified(store, &cid)?;
        if let Some(e) = node.get("e").and_then(Value::as_array) {
            for pair in e {
                if let (Some(k), Some(v)) = (pair.get(0).and_then(Value::as_str), pair.get(1)) {
                    out.insert(k.to_string(), v.clone());
                }
            }
        } else if let Some(c) = node.get("c").and_then(Value::as_array) {
            stack.extend(c.iter().filter_map(as_link).map(String::from));
        }
    }
    Ok(out)
}

/// Blocks as a JSON object `{cid: block text}` (the test-vector and HTTP bundle form).
pub fn blocks_to_json(blocks: &BTreeMap<String, Vec<u8>>) -> Value {
    Value::Object(blocks.iter().map(|(k, v)| (k.clone(), Value::String(String::from_utf8_lossy(v).into_owned()))).collect::<Map<_, _>>())
}

pub fn blocks_from_json(v: &Value) -> Result<BTreeMap<String, Vec<u8>>> {
    let o = v.as_object().ok_or_else(|| Error::Encoding("blocks must be an object".into()))?;
    Ok(o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().as_bytes().to_vec())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_is_dag_json_cidv1() {
        let (cid, bytes) = encode(&json!({"hello": "world"})).unwrap();
        assert_eq!(bytes, br#"{"hello":"world"}"#);
        // Same CID as @ipld/dag-json + multiformats produce for this value.
        assert_eq!(cid, "baguqeerasords4njcts6vs7qvdjfcvgnume4hqohf65zsfguprqphs3icwea");
    }

    #[test]
    fn map_shape_is_order_independent_and_proves_absence() {
        let entries: BTreeMap<String, Value> = (0..100).map(|i| (format!("k{i}"), json!(i))).collect();
        let a = MemStore::new();
        let root = map_build(&a, &entries).unwrap();
        let b = MemStore::new();
        let mut rev: Vec<_> = entries.clone().into_iter().collect();
        rev.reverse();
        assert_eq!(map_build(&b, &rev.into_iter().collect()).unwrap(), root);

        let rec = Recording::new(&a);
        assert_eq!(map_get(&rec, &root, "k42").unwrap(), Some(json!(42)));
        let proof = rec.into_blocks();
        assert!(proof.len() < a.len() / 3, "a lookup touches a path, not the tree");
        // The proof alone is enough to repeat the lookup.
        assert_eq!(map_get(&MemStore::from_blocks(proof), &root, "k42").unwrap(), Some(json!(42)));
        assert_eq!(map_get(&a, &root, "nope").unwrap(), None);
        assert_eq!(map_entries(&a, &root).unwrap(), entries);
    }

    #[test]
    fn tampered_blocks_are_rejected() {
        let s = MemStore::new();
        let root = map_build(&s, &[("a".to_string(), json!(1))].into_iter().collect()).unwrap();
        s.0.lock().unwrap().insert(root.clone(), br#"{"e":[["a",2]]}"#.to_vec());
        assert!(map_get(&s, &root, "a").is_err());
    }
}
