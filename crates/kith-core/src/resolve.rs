//! Resolving a public alias to its root (spec §5.1.1).
//!
//! A public alias names a root in two places, and both must agree: the alias side
//! carries a **back-link** (a WebFinger JRD, a DNS TXT record, or a did:web
//! document) that names the root, and the root's KEL carries an `alias_link` that
//! names the alias. Either alone proves nothing.
//!
//! This module is network-free. [`lookups`] says what to fetch for an alias, the
//! `from_*` functions read what came back into root [`Candidate`]s, [`merge`] makes
//! them one per root, [`links_back`] is the other direction, and [`unique`] refuses to
//! pick between roots that all pass. `kith resolve` and `kith name add` do the fetching.

use serde_json::Value;

use crate::kel::KeyState;
use crate::{Error, Result};

/// WebFinger link relation whose `href` is a root the subject claims to be.
pub const REL_ROOT: &str = "urn:kith:root";
/// Property on that link, or key in a TXT record: a hub that serves the root's KEL.
pub const PROP_HUB: &str = "urn:kith:hub";
/// DNS label under the alias's host that carries TXT back-links.
pub const DNS_LABEL: &str = "_kith";

/// One thing to fetch on the alias side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// `GET url`, expecting a JRD (RFC 7033). Read it with [`from_jrd`].
    WebFinger { url: String },
    /// The TXT records at `name`. Read them with [`from_txt`].
    Dns { name: String },
    /// `GET url`, expecting a DID document. Read it with [`from_did_document`].
    DidWeb { url: String },
}

impl Lookup {
    pub fn describe(&self) -> String {
        match self {
            Lookup::WebFinger { url } => format!("WebFinger {url}"),
            Lookup::Dns { name } => format!("DNS TXT {name}"),
            Lookup::DidWeb { url } => format!("did:web {url}"),
        }
    }
}

/// A root the alias side named, and where its KEL may be fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub did: String,
    pub hub: Option<String>,
    /// `webfinger`, `dns` or `did:web`.
    pub via: &'static str,
}

/// Splits an alias into the host that must vouch for it and the WebFinger resource
/// to ask for. `mailto:` becomes `acct:` (RFC 7565).
fn host_and_resource(alias: &str) -> Result<(String, String)> {
    let unsupported = || Error::Unsupported(format!("no back-link method for alias {alias}"));
    if let Some(addr) = alias.strip_prefix("mailto:").or_else(|| alias.strip_prefix("acct:")) {
        let (_, host) = addr.rsplit_once('@').ok_or_else(unsupported)?;
        if host.is_empty() || addr.starts_with('@') {
            return Err(unsupported());
        }
        return Ok((host.to_ascii_lowercase(), format!("acct:{addr}")));
    }
    if let Some(rest) = alias.strip_prefix("https://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if host.is_empty() {
            return Err(unsupported());
        }
        return Ok((host.to_ascii_lowercase(), alias.to_string()));
    }
    if let Some(rest) = alias.strip_prefix("did:web:") {
        let host = rest.split(':').next().unwrap_or_default().replace("%3A", ":").replace("%3a", ":");
        if host.is_empty() {
            return Err(unsupported());
        }
        return Ok((host.to_ascii_lowercase(), alias.to_string()));
    }
    Err(unsupported())
}

/// `http://` for loopback hosts (tests), `https://` for everything else.
pub fn origin(host: &str) -> String {
    let bare = host.rsplit_once(':').filter(|(h, p)| !h.is_empty() && p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host);
    let local = matches!(bare, "localhost" | "127.0.0.1" | "[::1]") || bare.ends_with(".localhost");
    format!("{}://{host}", if local { "http" } else { "https" })
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Where a did:web DID's document lives (DID Core did:web method).
pub fn did_web_url(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:web:")?;
    let mut parts = rest.split(':');
    let host = parts.next()?.replace("%3A", ":").replace("%3a", ":");
    if host.is_empty() {
        return None;
    }
    let path: Vec<&str> = parts.collect();
    Some(if path.is_empty() { format!("{}/.well-known/did.json", origin(&host)) } else { format!("{}/{}/did.json", origin(&host), path.join("/")) })
}

/// What to fetch for `alias`, in the order to try. Errors for alias kinds that have
/// no resolvable back-link yet (wallets, ENS, `at://`, OpenID Connect accounts).
pub fn lookups(alias: &str) -> Result<Vec<Lookup>> {
    let (host, resource) = host_and_resource(alias)?;
    let webfinger = Lookup::WebFinger { url: format!("{}/.well-known/webfinger?resource={}", origin(&host), percent_encode(&resource)) };
    let dns = Lookup::Dns { name: format!("{DNS_LABEL}.{}", host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host)) };
    let mut out = Vec::new();
    if let Some(rest) = alias.strip_prefix("https://") {
        // A bare origin is the host's own alias: DNS can vouch for it.
        if rest.trim_end_matches('/') == host {
            out.push(dns);
        }
        out.push(webfinger);
    } else if let Some(rest) = alias.strip_prefix("did:web:") {
        if let Some(url) = did_web_url(alias) {
            out.push(Lookup::DidWeb { url });
        }
        // Only the host form of did:web is the host's own alias.
        if rest.replace("%3A", ":").eq_ignore_ascii_case(&host) {
            out.push(dns);
        }
        out.push(webfinger);
    } else {
        out.push(webfinger);
    }
    Ok(out)
}

/// Roots named by a JRD: every link with `rel` [`REL_ROOT`] whose `href` is a
/// `did:kith`. The link's [`PROP_HUB`] property, if any, is the hub.
pub fn from_jrd(jrd: &Value) -> Vec<Candidate> {
    jrd["links"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|l| l["rel"] == REL_ROOT)
        .filter_map(|l| {
            let did = l["href"].as_str()?;
            did.starts_with("did:kith:").then(|| Candidate { did: did.to_string(), hub: l["properties"][PROP_HUB].as_str().map(String::from), via: "webfinger" })
        })
        .collect()
}

/// Roots named by TXT records: each is `did=did:kith:…`, optionally followed by
/// `;hub=https://…`. Other records at the name are ignored.
pub fn from_txt<S: AsRef<str>>(records: &[S]) -> Vec<Candidate> {
    records
        .iter()
        .filter_map(|r| {
            let mut did = None;
            let mut hub = None;
            for field in r.as_ref().split(';') {
                match field.trim().split_once('=') {
                    Some(("did", v)) if v.starts_with("did:kith:") => did = Some(v.to_string()),
                    Some(("hub", v)) => hub = Some(v.to_string()),
                    _ => {}
                }
            }
            did.map(|did| Candidate { did, hub, via: "dns" })
        })
        .collect()
}

/// Roots a DID document names in `alsoKnownAs`.
pub fn from_did_document(doc: &Value) -> Vec<Candidate> {
    doc["alsoKnownAs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .filter(|s| s.starts_with("did:kith:"))
        .map(|did| Candidate { did: did.to_string(), hub: None, via: "did:web" })
        .collect()
}

/// One candidate per root. A root named by several back-links keeps its first entry
/// and takes the hub of a later one if it had none.
pub fn merge(found: impl IntoIterator<Item = Candidate>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for c in found {
        match out.iter_mut().find(|o| o.did == c.did) {
            Some(o) => {
                if o.hub.is_none() {
                    o.hub = c.hub;
                }
            }
            None => out.push(c),
        }
    }
    out
}

/// The root of an alias, from the candidates whose KEL linked it back (`passed`, one
/// per root, see [`merge`]). `None` if none did. If more than one did, the alias is
/// ambiguous and this is an error: a resolver must not choose, because which root
/// "wins" would depend on the order of the lookups.
pub fn unique(alias: &str, mut passed: Vec<Candidate>) -> Result<Option<Candidate>> {
    match passed.len() {
        0 | 1 => Ok(passed.pop()),
        _ => {
            let roots: Vec<String> = passed.iter().map(|c| format!("{} (via {})", c.did, c.via)).collect();
            Err(Error::Ambiguous(format!("{alias} is linked back by {} roots: {}", passed.len(), roots.join(", "))))
        }
    }
}

/// Whether two alias strings name the same alias: equal, `acct:` and `mailto:`
/// for the same address, or the same `https://` origin with or without a trailing
/// slash. Nothing else is normalized.
pub fn same_alias(a: &str, b: &str) -> bool {
    fn canon(s: &str) -> String {
        if let Some(addr) = s.strip_prefix("acct:") {
            return format!("mailto:{addr}");
        }
        if let Some(rest) = s.strip_prefix("https://") {
            if !rest.trim_end_matches('/').contains('/') {
                return format!("https://{}", rest.trim_end_matches('/'));
            }
        }
        s.to_string()
    }
    a == b || canon(a) == canon(b)
}

/// The second direction: the root's current state links `alias`.
pub fn links_back(st: &KeyState, alias: &str) -> bool {
    st.aliases.iter().any(|a| same_alias(a, alias))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kel::{next_event, tests::fixture, verify_log, EventBody};
    use crate::keys::VerifyOptions;
    use serde_json::json;

    #[test]
    fn mailto_is_webfinger_as_acct() {
        let l = lookups("mailto:ada@acme.test").unwrap();
        assert_eq!(l, vec![Lookup::WebFinger { url: "https://acme.test/.well-known/webfinger?resource=acct%3Aada%40acme.test".into() }]);
        assert_eq!(lookups("acct:ada@acme.test").unwrap(), l);
    }

    #[test]
    fn origin_gets_dns_then_webfinger() {
        let l = lookups("https://acme.test/").unwrap();
        assert_eq!(
            l,
            vec![
                Lookup::Dns { name: "_kith.acme.test".into() },
                Lookup::WebFinger { url: "https://acme.test/.well-known/webfinger?resource=https%3A%2F%2Facme.test%2F".into() },
            ]
        );
        // A URL with a path is an account at that host, which DNS cannot vouch for.
        let l = lookups("https://github.com/ada").unwrap();
        assert_eq!(l.len(), 1);
        assert!(matches!(&l[0], Lookup::WebFinger { url } if url.starts_with("https://github.com/.well-known/webfinger?resource=")));
    }

    #[test]
    fn did_web_document_then_dns_then_webfinger() {
        let l = lookups("did:web:acme.test").unwrap();
        assert_eq!(l[0], Lookup::DidWeb { url: "https://acme.test/.well-known/did.json".into() });
        assert_eq!(l[1], Lookup::Dns { name: "_kith.acme.test".into() });
        assert!(matches!(&l[2], Lookup::WebFinger { .. }));
        let l = lookups("did:web:acme.test:users:ada").unwrap();
        assert_eq!(l[0], Lookup::DidWeb { url: "https://acme.test/users/ada/did.json".into() });
        assert!(!l.iter().any(|x| matches!(x, Lookup::Dns { .. })));
        assert_eq!(did_web_url("did:web:localhost%3A8080:u"), Some("http://localhost:8080/u/did.json".into()));
    }

    #[test]
    fn loopback_is_plain_http() {
        let l = lookups("mailto:ada@localhost:7789").unwrap();
        assert_eq!(l, vec![Lookup::WebFinger { url: "http://localhost:7789/.well-known/webfinger?resource=acct%3Aada%40localhost%3A7789".into() }]);
        assert_eq!(origin("acme.test:8443"), "https://acme.test:8443");
        assert_eq!(origin("app.localhost"), "http://app.localhost");
        let Lookup::Dns { name } = &lookups("https://localhost:7789").unwrap()[0] else { panic!() };
        assert_eq!(name, "_kith.localhost");
    }

    #[test]
    fn unsupported_aliases_are_errors() {
        for a in ["eip155:1:0xabc", "at://ada.bsky.social", "https://oauth.telegram.org#424242", "mailto:nobody", "https://", "did:web:", "ada"] {
            assert!(lookups(a).is_err() || a.starts_with("https://oauth"), "{a}");
        }
        assert!(lookups("eip155:1:0xabc").is_err());
    }

    #[test]
    fn jrd_links() {
        let jrd = json!({
            "subject": "acct:ada@acme.test",
            "links": [
                {"rel": "self", "href": "https://acme.test/users/ada"},
                {"rel": REL_ROOT, "href": "did:plc:notkith"},
                {"rel": REL_ROOT, "href": "did:kith:aaa", "properties": {PROP_HUB: "https://hub.example"}},
                {"rel": REL_ROOT, "href": "did:kith:bbb"}
            ]
        });
        let c = from_jrd(&jrd);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], Candidate { did: "did:kith:aaa".into(), hub: Some("https://hub.example".into()), via: "webfinger" });
        assert_eq!(c[1].hub, None);
        assert!(from_jrd(&json!({})).is_empty());
    }

    #[test]
    fn txt_records() {
        let c = from_txt(&["v=spf1 -all", "did=did:kith:aaa; hub=https://hub.example", "did=did:plc:x", "did=did:kith:bbb"]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], Candidate { did: "did:kith:aaa".into(), hub: Some("https://hub.example".into()), via: "dns" });
        assert_eq!(c[1].did, "did:kith:bbb");
    }

    #[test]
    fn did_document_also_known_as() {
        let c = from_did_document(&json!({"id": "did:web:acme.test", "alsoKnownAs": ["https://acme.test", "did:kith:aaa"]}));
        assert_eq!(c, vec![Candidate { did: "did:kith:aaa".into(), hub: None, via: "did:web" }]);
    }

    fn cand(did: &str, hub: Option<&str>, via: &'static str) -> Candidate {
        Candidate { did: did.into(), hub: hub.map(String::from), via }
    }

    #[test]
    fn merge_keeps_one_entry_per_root() {
        let m = merge([cand("did:kith:a", None, "dns"), cand("did:kith:b", None, "webfinger"), cand("did:kith:a", Some("https://hub.example"), "webfinger")]);
        assert_eq!(m, vec![cand("did:kith:a", Some("https://hub.example"), "dns"), cand("did:kith:b", None, "webfinger")]);
        // The first hub wins; a later one does not replace it.
        let m = merge([cand("did:kith:a", Some("https://one.example"), "dns"), cand("did:kith:a", Some("https://two.example"), "webfinger")]);
        assert_eq!(m, vec![cand("did:kith:a", Some("https://one.example"), "dns")]);
        assert!(merge(Vec::new()).is_empty());
    }

    #[test]
    fn two_roots_that_pass_are_ambiguous() {
        let a = cand("did:kith:a", None, "dns");
        let b = cand("did:kith:b", None, "webfinger");
        assert_eq!(unique("mailto:ada@acme.test", vec![]).unwrap(), None);
        assert_eq!(unique("mailto:ada@acme.test", vec![a.clone()]).unwrap(), Some(a.clone()));
        let err = unique("mailto:ada@acme.test", vec![a, b]).unwrap_err();
        assert!(matches!(err, Error::Ambiguous(_)));
        let msg = err.to_string();
        assert!(msg.contains("did:kith:a (via dns)") && msg.contains("did:kith:b (via webfinger)") && msg.contains("2 roots"), "{msg}");
    }

    #[test]
    fn root_must_link_back() {
        let mut f = fixture();
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        assert!(!links_back(&st, "mailto:ada@acme.test"));
        let mut ev = next_event(&st, EventBody::AliasLink { alias: "mailto:ada@acme.test".into() });
        ev.sign(&f.root).unwrap();
        f.log.push(ev);
        let mut ev = next_event(&verify_log(&f.log, &VerifyOptions::default()).unwrap(), EventBody::AliasLink { alias: "https://acme.test".into() });
        ev.sign(&f.root).unwrap();
        f.log.push(ev);
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        assert!(links_back(&st, "mailto:ada@acme.test"));
        assert!(links_back(&st, "acct:ada@acme.test"));
        assert!(links_back(&st, "https://acme.test/"));
        assert!(!links_back(&st, "https://acme.test/ada"));
        assert!(!links_back(&st, "mailto:bob@acme.test"));
        let mut ev = next_event(&st, EventBody::AliasUnlink { alias: "mailto:ada@acme.test".into() });
        ev.sign(&f.root).unwrap();
        f.log.push(ev);
        let st = verify_log(&f.log, &VerifyOptions::default()).unwrap();
        assert!(!links_back(&st, "mailto:ada@acme.test"));
    }
}
