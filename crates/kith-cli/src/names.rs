//! `kith name …` and `kith resolve`: local names (petnames) for roots, and public
//! aliases resolved through the alias side's back-link (spec §5.1.1 and §5.1.2).
//!
//! `names.json` in the home directory pins each name to a root. A name added from
//! an alias also records the alias, how it resolved and when, so a pinned root can
//! be told from whatever the alias side would hand out today.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use serde_json::{json, Map, Value};

use kith_core::resolve::{self, Candidate, Lookup};
use kith_core::util::now;

use super::{fetch_state, http, print, Home};

#[derive(Subcommand)]
pub enum NameCmd {
    /// Give a root a local name. `who` is its DID, or a public alias (`mailto:`,
    /// `https://`, `did:web:`) resolved through its back-link and checked against
    /// the root's KEL. The name then works wherever a DID does.
    Add {
        name: String,
        who: String,
        /// Move a name that already points at a different root.
        #[arg(long)]
        replace: bool,
    },
    /// Every name and the root it pins.
    List,
    /// Forget a name.
    Rm { name: String },
    /// Re-resolve names that were added from an alias and report any that moved, no
    /// longer resolve or became ambiguous. Exits non-zero if any did. A name never
    /// moves by itself; fix one with `kith name add NAME ALIAS --replace`.
    Check {
        /// Only these names (default: all).
        names: Vec<String>,
    },
}

/// A public alias resolved in both directions.
pub struct Resolved {
    pub alias: String,
    pub did: String,
    pub via: &'static str,
    pub hub: Option<String>,
}

impl Resolved {
    pub fn json(&self) -> Value {
        json!({"alias": self.alias, "did": self.did, "via": self.via, "hub": self.hub})
    }
}

fn valid_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'));
    if !ok {
        bail!("a name is 1-64 of a-z, 0-9, '-', '_' and '.', starting with a letter (got {name:?})");
    }
    Ok(())
}

fn book_path(home: &Home) -> PathBuf {
    home.dir.join("names.json")
}

fn load_book(home: &Home) -> Result<Map<String, Value>> {
    let p = book_path(home);
    if !p.exists() {
        return Ok(Map::new());
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).with_context(|| p.display().to_string())?)?;
    Ok(v["names"].as_object().cloned().unwrap_or_default())
}

fn save_book(home: &Home, names: Map<String, Value>) -> Result<()> {
    std::fs::create_dir_all(&home.dir)?;
    std::fs::write(book_path(home), serde_json::to_vec_pretty(&json!({"v": 1, "names": names}))?)?;
    Ok(())
}

/// The DID for a principal argument: a DID as given, a public alias resolved on the
/// spot (and said so on stderr), or a name from the book.
pub fn principal(home: &Home, s: &str) -> Result<String> {
    if resolve::lookups(s).is_ok() {
        let r = resolve(home, s)?;
        eprintln!("{s} is {} (via {})", r.did, r.via);
        return Ok(r.did);
    }
    if s.contains(':') {
        return Ok(s.to_string());
    }
    let names = load_book(home)?;
    names
        .get(s)
        .and_then(|e| e["did"].as_str())
        .map(String::from)
        .ok_or_else(|| anyhow!("no name {s:?}; add one with `kith name add {s} <did or alias>`"))
}

/// Resolves a public alias: fetch its back-links, then check every root they name
/// against its KEL. Exactly one root must link the alias back; two or more is an
/// error (spec §5.1.1), not a choice.
pub fn resolve(home: &Home, alias: &str) -> Result<Resolved> {
    let mut notes = Vec::new();
    let mut found: Vec<Candidate> = Vec::new();
    for l in resolve::lookups(alias)? {
        match fetch(&l) {
            Ok(c) if c.is_empty() => notes.push(format!("{} names no root", l.describe())),
            Ok(c) => found.extend(c),
            Err(e) => notes.push(format!("{}: {e}", l.describe())),
        }
    }
    let candidates = resolve::merge(found);
    if candidates.is_empty() {
        bail!("no back-link found for {alias} ({})", notes.join("; "));
    }
    let mut passed = Vec::new();
    for c in candidates {
        let Some(hub) = c.hub.clone().or_else(|| home.hub().ok()) else {
            notes.push(format!("{}: no hub to fetch its KEL from", c.did));
            continue;
        };
        match fetch_state(&hub, &c.did) {
            Ok(st) if resolve::links_back(&st, alias) => passed.push(Candidate { hub: Some(hub), ..c }),
            Ok(_) => notes.push(format!("{} (via {}) does not link {alias} back", c.did, c.via)),
            Err(e) => notes.push(format!("{} (via {}): {e:#}", c.did, c.via)),
        }
    }
    match resolve::unique(alias, passed)? {
        Some(c) => Ok(Resolved { alias: alias.to_string(), did: c.did, via: c.via, hub: c.hub }),
        None => bail!("{alias} does not resolve: {}", notes.join("; ")),
    }
}

fn fetch(l: &Lookup) -> Result<Vec<Candidate>> {
    Ok(match l {
        Lookup::WebFinger { url } => resolve::from_jrd(&get_json(url, "application/jrd+json, application/json")?),
        Lookup::DidWeb { url } => resolve::from_did_document(&get_json(url, "application/did+json, application/json")?),
        Lookup::Dns { name } => resolve::from_txt(&txt(name)?),
    })
}

fn get_json(url: &str, accept: &str) -> Result<Value> {
    let resp = http().get(url).header("accept", accept).send()?;
    let status = resp.status();
    if !status.is_success() {
        bail!("HTTP {status}");
    }
    Ok(resp.json()?)
}

/// The TXT records at `name`, through the system resolver. Each record's strings
/// are concatenated, as RFC 7208 reads them.
fn txt(name: &str) -> Result<Vec<String>> {
    use hickory_resolver::Resolver;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let resolver = Resolver::builder_tokio()?.build()?;
        let lookup = match resolver.txt_lookup(format!("{name}.")).await {
            Ok(l) => l,
            Err(e) if e.to_string().contains("no records found") => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                hickory_resolver::proto::rr::RData::TXT(t) => Some(t.txt_data.iter().map(|s| String::from_utf8_lossy(s)).collect::<String>()),
                _ => None,
            })
            .collect())
    })
}

/// What re-resolving one pinned name found.
fn check_one(home: &Home, name: &str, entry: &Value) -> (Value, bool) {
    let did = entry["did"].as_str().unwrap_or_default();
    let mut row = json!({"name": name, "did": did});
    let Some(alias) = entry["alias"].as_str() else {
        // Added from a DID: nothing to compare against.
        row["status"] = json!("pinned");
        return (row, true);
    };
    row["alias"] = json!(alias);
    match resolve(home, alias) {
        Ok(r) if r.did == did => {
            row["status"] = json!("ok");
            row["via"] = json!(r.via);
            (row, true)
        }
        Ok(r) => {
            row["status"] = json!("moved");
            row["now"] = json!(r.did);
            row["via"] = json!(r.via);
            (row, false)
        }
        Err(e) => {
            row["status"] = json!(match e.downcast_ref::<kith_core::Error>() {
                Some(kith_core::Error::Ambiguous(_)) => "ambiguous",
                _ => "unresolved",
            });
            row["reason"] = json!(format!("{e}"));
            (row, false)
        }
    }
}

pub fn run(home: &Home, cmd: NameCmd) -> Result<()> {
    match cmd {
        NameCmd::Add { name, who, replace } => {
            valid_name(&name)?;
            let mut names = load_book(home)?;
            let mut entry = if resolve::lookups(&who).is_ok() {
                let r = resolve(home, &who)?;
                json!({"did": r.did, "alias": r.alias, "via": r.via, "hub": r.hub, "verified": now(), "added": now()})
            } else if who.starts_with("did:") {
                json!({"did": who, "added": now()})
            } else {
                bail!("{who:?} is neither a DID nor an alias with a back-link (mailto:, https://, did:web:)");
            };
            if let Some(old) = names.get(&name) {
                if old["did"] != entry["did"] {
                    if !replace {
                        bail!("{name} is already {}; pass --replace to move it", old["did"].as_str().unwrap_or("?"));
                    }
                    eprintln!("warning: {name} moves from {} to {}", old["did"].as_str().unwrap_or("?"), entry["did"].as_str().unwrap_or("?"));
                } else if let Some(added) = old.get("added") {
                    entry["added"] = added.clone();
                }
            }
            let mut shown = entry.as_object().cloned().unwrap_or_default();
            shown.insert("name".into(), json!(name));
            names.insert(name, entry);
            save_book(home, names)?;
            print(&Value::Object(shown));
        }
        NameCmd::List => {
            let names = load_book(home)?;
            let mut rows: Vec<Value> = names
                .iter()
                .map(|(n, e)| {
                    let mut o = e.as_object().cloned().unwrap_or_default();
                    o.insert("name".into(), json!(n));
                    Value::Object(o)
                })
                .collect();
            rows.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            print(&Value::Array(rows));
        }
        NameCmd::Check { names: wanted } => {
            let mut book = load_book(home)?;
            for w in &wanted {
                if !book.contains_key(w) {
                    bail!("no name {w:?}");
                }
            }
            let mut rows = Vec::new();
            let mut bad = 0;
            for (name, entry) in book.clone() {
                if !wanted.is_empty() && !wanted.contains(&name) {
                    continue;
                }
                let (row, ok) = check_one(home, &name, &entry);
                if ok && row["status"] == "ok" {
                    book[&name]["verified"] = json!(now());
                }
                if !ok {
                    bad += 1;
                }
                rows.push(row);
            }
            save_book(home, book)?;
            let total = rows.len();
            print(&Value::Array(rows));
            if bad > 0 {
                bail!("{bad} of {total} names need attention; nothing was changed (use `kith name add NAME ALIAS --replace` to follow a move)");
            }
        }
        NameCmd::Rm { name } => {
            let mut names = load_book(home)?;
            names.remove(&name).ok_or_else(|| anyhow!("no name {name:?}"))?;
            save_book(home, names)?;
            eprintln!("forgot {name}");
        }
    }
    Ok(())
}
