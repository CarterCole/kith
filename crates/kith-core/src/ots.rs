//! OpenTimestamps proofs (spec §8.10): "this digest existed no later than Bitcoin
//! block N".
//!
//! Parses and writes standard `.ots` files, replays their operations, and reports
//! the attestations they reach. Checking a Bitcoin attestation needs the block's
//! Merkle root, which the caller supplies (from a node, or an explorer API).

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
pub const PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
pub const BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
pub const LITECOIN: [u8; 8] = [0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45];
const OP_SHA256: u8 = 0x08;

/// Calendars whose pending attestations may be followed when upgrading. Pending
/// URIs come from untrusted proof files, so only these are contacted.
pub const UPGRADE_ALLOWLIST: &[&str] = &[".calendar.opentimestamps.org", ".calendar.eternitywall.com", ".calendar.catallaxy.com"];

pub fn may_follow(uri: &str) -> bool {
    uri.strip_prefix("https://").is_some_and(|host| {
        let host = host.split('/').next().unwrap_or_default();
        UPGRADE_ALLOWLIST.iter().any(|suffix| host.ends_with(suffix) && host.len() > suffix.len())
    })
}

/// Default public calendars.
pub const CALENDARS: &[&str] = &["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    Sha1,
    Ripemd160,
    Sha256,
    Keccak256,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Reverse,
    Hexlify,
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::Sha1 => 0x02,
            Op::Ripemd160 => 0x03,
            Op::Sha256 => OP_SHA256,
            Op::Keccak256 => 0x67,
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1,
            Op::Reverse => 0xf2,
            Op::Hexlify => 0xf3,
        }
    }

    pub fn apply(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Op::Sha256 => Sha256::digest(msg).to_vec(),
            Op::Sha1 => {
                use sha1::Digest as _;
                sha1::Sha1::digest(msg).to_vec()
            }
            Op::Keccak256 => {
                use sha3::Digest as _;
                sha3::Keccak256::digest(msg).to_vec()
            }
            Op::Ripemd160 => {
                use ripemd::Digest as _;
                ripemd::Ripemd160::digest(msg).to_vec()
            }
            Op::Append(b) => [msg, b].concat(),
            Op::Prepend(b) => [b.as_slice(), msg].concat(),
            Op::Reverse => msg.iter().rev().copied().collect(),
            Op::Hexlify => msg.iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attestation {
    // Variant order follows the tags, so sorting matches the reference serializer.
    /// `msg` is the Merkle root of the Bitcoin block at `height`.
    Bitcoin { height: u64 },
    Litecoin { height: u64 },
    /// Submitted to a calendar; upgrade later from `{uri}/timestamp/{hex(msg)}`.
    Pending { uri: String },
    Unknown { tag: [u8; 8], payload: Vec<u8> },
}

/// A timestamp tree: attestations on this message, and operations leading on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Timestamp {
    pub attestations: Vec<Attestation>,
    pub ops: Vec<(Op, Timestamp)>,
}

/// A detached `.ots` file: the digest of the stamped data and its timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedFile {
    pub digest: [u8; 32],
    pub timestamp: Timestamp,
}

/// An attestation reached by replaying the proof, with the message it attests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reached {
    pub attestation: Attestation,
    pub msg: Vec<u8>,
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8> {
        let v = *self.b.get(self.i).ok_or_else(|| Error::Encoding("ots: truncated".into()))?;
        self.i += 1;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&[u8]> {
        if self.i + n > self.b.len() {
            return Err(Error::Encoding("ots: truncated".into()));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn varuint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::Encoding("ots: varuint too long".into()))
    }
    fn varbytes(&mut self, max: usize) -> Result<Vec<u8>> {
        let n = self.varuint()? as usize;
        if n > max {
            return Err(Error::Encoding("ots: field too long".into()));
        }
        Ok(self.bytes(n)?.to_vec())
    }
}

fn put_varuint(mut n: u64, out: &mut Vec<u8>) {
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

fn put_varbytes(b: &[u8], out: &mut Vec<u8>) {
    put_varuint(b.len() as u64, out);
    out.extend(b);
}

fn read_op(r: &mut Reader, tag: u8) -> Result<Op> {
    Ok(match tag {
        0x02 => Op::Sha1,
        0x03 => Op::Ripemd160,
        OP_SHA256 => Op::Sha256,
        0x67 => Op::Keccak256,
        0xf0 => Op::Append(r.varbytes(4096)?),
        0xf1 => Op::Prepend(r.varbytes(4096)?),
        0xf2 => Op::Reverse,
        0xf3 => Op::Hexlify,
        t => return Err(Error::Encoding(format!("ots: unknown op 0x{t:02x}"))),
    })
}

fn read_attestation(r: &mut Reader) -> Result<Attestation> {
    let tag: [u8; 8] = r.bytes(8)?.try_into().expect("8 bytes");
    let payload = r.varbytes(8192)?;
    let mut p = Reader { b: &payload, i: 0 };
    Ok(match tag {
        PENDING => {
            let uri = String::from_utf8(p.varbytes(1000)?).map_err(|_| Error::Encoding("ots: calendar uri".into()))?;
            if !uri.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._/:".contains(&c)) {
                return Err(Error::Encoding(format!("ots: suspicious calendar uri {uri:?}")));
            }
            Attestation::Pending { uri }
        }
        BITCOIN => Attestation::Bitcoin { height: p.varuint()? },
        LITECOIN => Attestation::Litecoin { height: p.varuint()? },
        _ => Attestation::Unknown { tag, payload },
    })
}

fn read_timestamp(r: &mut Reader, depth: usize) -> Result<Timestamp> {
    if depth > 256 {
        return Err(Error::Encoding("ots: proof too deep".into()));
    }
    let mut ts = Timestamp::default();
    let item = |r: &mut Reader, tag: u8, ts: &mut Timestamp| -> Result<()> {
        if tag == 0x00 {
            ts.attestations.push(read_attestation(r)?);
        } else {
            let op = read_op(r, tag)?;
            let child = read_timestamp(r, depth + 1)?;
            ts.ops.push((op, child));
        }
        Ok(())
    };
    let mut tag = r.byte()?;
    while tag == 0xff {
        let t = r.byte()?;
        item(r, t, &mut ts)?;
        tag = r.byte()?;
    }
    item(r, tag, &mut ts)?;
    Ok(ts)
}

fn write_attestation(a: &Attestation, out: &mut Vec<u8>) {
    let (tag, payload) = match a {
        Attestation::Pending { uri } => {
            let mut p = vec![];
            put_varbytes(uri.as_bytes(), &mut p);
            (PENDING, p)
        }
        Attestation::Bitcoin { height } | Attestation::Litecoin { height } => {
            let mut p = vec![];
            put_varuint(*height, &mut p);
            (if matches!(a, Attestation::Bitcoin { .. }) { BITCOIN } else { LITECOIN }, p)
        }
        Attestation::Unknown { tag, payload } => (*tag, payload.clone()),
    };
    out.extend(tag);
    put_varbytes(&payload, out);
}

fn write_op(op: &Op, out: &mut Vec<u8>) {
    out.push(op.tag());
    if let Op::Append(b) | Op::Prepend(b) = op {
        put_varbytes(b, out);
    }
}

impl Timestamp {
    /// Parse a bare timestamp, as calendars return it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader { b: bytes, i: 0 };
        let ts = read_timestamp(&mut r, 0)?;
        if r.i != bytes.len() {
            return Err(Error::Encoding("ots: trailing bytes".into()));
        }
        Ok(ts)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        let mut atts = self.attestations.clone();
        atts.sort();
        let mut ops: Vec<&(Op, Timestamp)> = self.ops.iter().collect();
        ops.sort_by(|a, b| a.0.cmp(&b.0));
        let n = atts.len() + ops.len();
        let mut i = 0;
        for a in &atts {
            i += 1;
            if i < n {
                out.push(0xff);
            }
            out.push(0x00);
            write_attestation(a, out);
        }
        for (op, child) in ops {
            i += 1;
            if i < n {
                out.push(0xff);
            }
            write_op(op, out);
            child.write(out);
        }
    }

    /// Replay every path from `msg` and collect the attestations reached.
    pub fn attestations_from(&self, msg: &[u8]) -> Result<Vec<Reached>> {
        let mut out = vec![];
        self.walk(msg, &mut out)?;
        Ok(out)
    }

    fn walk(&self, msg: &[u8], out: &mut Vec<Reached>) -> Result<()> {
        for a in &self.attestations {
            out.push(Reached { attestation: a.clone(), msg: msg.to_vec() });
        }
        for (op, child) in &self.ops {
            let next = op.apply(msg)?;
            if next.len() > 4096 {
                return Err(Error::Encoding("ots: message too long".into()));
            }
            child.walk(&next, out)?;
        }
        Ok(())
    }

    /// Graft `other` (a calendar response for the message this node attests) in
    /// place of the pending attestation at `msg`. Returns true if anything changed.
    pub fn merge_at(&mut self, cur: &[u8], target: &[u8], other: &Timestamp) -> Result<bool> {
        if cur == target {
            let before = self.clone();
            for a in &other.attestations {
                if !self.attestations.contains(a) {
                    self.attestations.push(a.clone());
                }
            }
            for (op, child) in &other.ops {
                match self.ops.iter_mut().find(|(o, _)| o == op) {
                    Some((_, mine)) => {
                        let next = op.apply(cur)?;
                        mine.merge_at(&next, &next, child)?;
                    }
                    None => self.ops.push((op.clone(), child.clone())),
                }
            }
            return Ok(*self != before);
        }
        let mut changed = false;
        for (op, child) in &mut self.ops {
            let next = op.apply(cur)?;
            changed |= child.merge_at(&next, target, other)?;
        }
        Ok(changed)
    }
}

impl DetachedFile {
    pub fn new(digest: [u8; 32], timestamp: Timestamp) -> Self {
        DetachedFile { digest, timestamp }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader { b: bytes, i: 0 };
        if r.bytes(MAGIC.len())? != MAGIC {
            return Err(Error::Encoding("not an OpenTimestamps proof".into()));
        }
        if r.varuint()? != 1 {
            return Err(Error::Unsupported("OpenTimestamps proof version".into()));
        }
        if r.byte()? != OP_SHA256 {
            return Err(Error::Unsupported("OpenTimestamps proofs of non-SHA-256 digests".into()));
        }
        let digest: [u8; 32] = r.bytes(32)?.try_into().expect("32 bytes");
        let timestamp = read_timestamp(&mut r, 0)?;
        if r.i != bytes.len() {
            return Err(Error::Encoding("ots: trailing bytes".into()));
        }
        Ok(DetachedFile { digest, timestamp })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        put_varuint(1, &mut out);
        out.push(OP_SHA256);
        out.extend(self.digest);
        self.timestamp.write(&mut out);
        out
    }

    pub fn attestations(&self) -> Result<Vec<Reached>> {
        self.timestamp.attestations_from(&self.digest)
    }

    /// The earliest Bitcoin block this proof reaches, as `(height, block time)`.
    /// `header(height)` returns that block's raw 80-byte header; its Merkle root
    /// (bytes 36..68, raw order) must equal the attested message.
    pub fn verify_bitcoin(&self, header: &dyn Fn(u64) -> Result<Vec<u8>>) -> Result<Option<(u64, i64)>> {
        let mut best: Option<(u64, i64)> = None;
        for r in self.attestations()? {
            if let Attestation::Bitcoin { height } = r.attestation {
                let h = header(height)?;
                if h.len() != 80 || r.msg.len() != 32 || h[36..68] != r.msg[..] {
                    return Err(Error::Signature(format!("ots: block {height} merkle root does not match")));
                }
                let time = i64::from(u32::from_le_bytes(h[68..72].try_into().expect("4 bytes")));
                if best.is_none_or(|(b, _)| height < b) {
                    best = Some((height, time));
                }
            }
        }
        Ok(best)
    }

    /// Pending calendar attestations, with the commitment to ask each about.
    pub fn pending(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        Ok(self
            .attestations()?
            .into_iter()
            .filter_map(|r| match r.attestation {
                Attestation::Pending { uri } => Some((uri, r.msg)),
                _ => None,
            })
            .collect())
    }
}

/// Build the stamp request for `digest`: a random nonce is appended and hashed
/// first (as the reference client does) so calendars learn nothing about it.
/// Returns the file skeleton and the message to submit to calendars.
pub fn stamp_request(digest: [u8; 32], nonce: [u8; 16]) -> (DetachedFile, Vec<u8>) {
    let appended = Op::Append(nonce.to_vec());
    let msg = Op::Sha256.apply(&appended.apply(&digest).expect("append")).expect("sha256");
    let ts = Timestamp { attestations: vec![], ops: vec![(appended, Timestamp { attestations: vec![], ops: vec![(Op::Sha256, Timestamp::default())] })] };
    (DetachedFile::new(digest, ts), msg)
}

/// Add a calendar's response (a bare timestamp for `msg`) to a stamp request.
pub fn add_calendar_response(file: &mut DetachedFile, msg: &[u8], response: &[u8]) -> Result<()> {
    let ts = Timestamp::parse(response)?;
    let digest = file.digest;
    file.timestamp.merge_at(&digest, msg, &ts)?;
    Ok(())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Encoding("odd hex".into()));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::Encoding("bad hex".into()))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_replay() {
        let digest = crate::util::sha256(b"kith");
        let (mut file, msg) = stamp_request(digest, [7; 16]);
        // A calendar answers: prepend its own bytes, hash, then "pending at me".
        let resp = Timestamp {
            attestations: vec![],
            ops: vec![(Op::Prepend(vec![1, 2, 3]), Timestamp { attestations: vec![], ops: vec![(Op::Sha256, Timestamp { attestations: vec![Attestation::Pending { uri: "https://a.pool.opentimestamps.org".into() }], ops: vec![] })] })],
        };
        add_calendar_response(&mut file, &msg, &resp.to_bytes()).unwrap();
        let bytes = file.to_bytes();
        let back = DetachedFile::parse(&bytes).unwrap();
        assert_eq!(back, file);
        let pending = back.pending().unwrap();
        let commitment = &pending["https://a.pool.opentimestamps.org"];
        assert_eq!(*commitment, Op::Sha256.apply(&[vec![1, 2, 3], msg.clone()].concat()).unwrap());
        // After Bitcoin confirms: the calendar's upgrade maps that commitment to a block.
        let upgrade = Timestamp { attestations: vec![Attestation::Bitcoin { height: 800_000 }], ops: vec![] };
        let mut up = back.clone();
        up.timestamp.merge_at(&digest, commitment, &upgrade).unwrap();
        let header = |root: &[u8]| {
            let mut h = vec![0u8; 80];
            h[36..68].copy_from_slice(root);
            h[68..72].copy_from_slice(&1_700_000_000u32.to_le_bytes());
            h
        };
        let good = header(commitment);
        assert_eq!(up.verify_bitcoin(&|h| { assert_eq!(h, 800_000); Ok(good.clone()) }).unwrap(), Some((800_000, 1_700_000_000)));
        assert!(up.verify_bitcoin(&|_| Ok(header(&[0; 32]))).is_err());
    }
}

#[cfg(test)]
mod vector_tests {
    use super::*;
    use base64::Engine;
    use serde_json::Value;

    #[test]
    fn opentimestamps_client_examples() {
        let v: Value = serde_json::from_str(include_str!("../../../spec/test-vectors/ots.json")).unwrap();
        let b64 = |s: &Value| base64::engine::general_purpose::STANDARD.decode(s.as_str().unwrap()).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let bytes = b64(&c["ots"]);
            let f = DetachedFile::parse(&bytes).unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
            // Our writer reproduces the reference client's bytes exactly.
            assert_eq!(f.to_bytes(), bytes, "{}", c["name"]);
            if !c["data"].is_null() {
                assert_eq!(f.digest, crate::util::sha256(b64(&c["data"])), "{}", c["name"]);
            }
            match c["bitcoin"].as_object() {
                Some(b) => {
                    let header = hex_decode(b["header"].as_str().unwrap()).unwrap();
                    let got = f.verify_bitcoin(&|h| { assert_eq!(h, b["height"].as_u64().unwrap()); Ok(header.clone()) }).unwrap();
                    assert_eq!(got, Some((b["height"].as_u64().unwrap(), b["time"].as_i64().unwrap())));
                }
                None => {
                    assert_eq!(f.verify_bitcoin(&|_| panic!("no bitcoin attestation expected")).unwrap(), None);
                    let pending = f.pending().unwrap();
                    assert!(!pending.is_empty());
                    assert!(pending.keys().all(|u| may_follow(u)), "{pending:?}");
                }
            }
        }
        assert!(!may_follow("https://evil.example/calendar.opentimestamps.org"));
        assert!(!may_follow("http://alice.btc.calendar.opentimestamps.org"));
    }
}
