//! Proving that an identity controls a domain (spec §7.8.3).
//!
//! The proof is published where only the domain's owner can write, and it **names the
//! identity**: `kith-domain-verification=<did>`. Because the record carries the DID, no
//! hub has to remember a challenge: any party that can read the domain can check the claim
//! for itself, and any number of them can sign what they saw. An org's DID is proved the
//! same way as a person's.
//!
//! Three ways to publish it, the same three Google and Bing offer:
//!
//! | method | where | what |
//! |--------|-------|------|
//! | `txt`   | TXT at `_kith-challenge.<domain>` | the value `kith-domain-verification=<did>` |
//! | `cname` | CNAME at `_kith-<h16>.<domain>`   | pointing at `<h32>.dv.kith.invalid` |
//! | `html`  | `https://<domain>/kith-<h16>.html` | a file containing `kith-domain-verification=<did>` |
//!
//! `h16` and `h32` are the first 16 and 32 hex digits of SHA-256 of the DID: a DNS label
//! cannot hold a DID, and a CNAME has only its name and target to carry one. The HTML
//! file name carries `h16` only, so a site that echoes the request path into a page cannot
//! be made to print the whole proof.
//!
//! This module is network-free. [`records`] says what to publish, the `check_*` functions
//! read what came back, and the hub and the CLI do the fetching.

use crate::util::sha256;
use crate::{Error, Result};

/// The value, or the prefix of the value, that names the identity.
pub const VALUE_KEY: &str = "kith-domain-verification";
/// DNS label under the domain that carries the TXT proof.
pub const TXT_LABEL: &str = "_kith-challenge";
/// Suffix of the CNAME target. `.invalid` (RFC 6761) is never delegated, so the target
/// names no real host and belongs to no hub: every verifier reads the same record.
pub const CNAME_SUFFIX: &str = "dv.kith.invalid";
/// Contacts and attestations name a domain as `dns:<domain>`.
pub const SCHEME: &str = "dns:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Txt,
    Cname,
    Html,
}

impl Method {
    pub const ALL: [Method; 3] = [Method::Txt, Method::Cname, Method::Html];

    pub fn name(self) -> &'static str {
        match self {
            Method::Txt => "txt",
            Method::Cname => "cname",
            Method::Html => "html",
        }
    }

    pub fn parse(s: &str) -> Result<Method> {
        Method::ALL.into_iter().find(|m| m.name() == s.to_ascii_lowercase()).ok_or_else(|| Error::Invalid(format!("unknown domain verification method {s:?} (txt, cname or html)")))
    }
}

/// Names under which no one can prove ownership, or that point inside a network.
const RESERVED: [&str; 7] = ["localhost", "local", "internal", "invalid", "lan", "home.arpa", "onion"];

/// The domain a user typed, as a bare lower-case ASCII name: `Example.COM.` and
/// `dns:example.com` both give `example.com`. Refuses IP addresses, single labels,
/// reserved names, and anything that is not letters, digits and hyphens (an
/// internationalised name is written in its `xn--` form).
pub fn normalize(input: &str) -> Result<String> {
    let bad = |why: &str| Err(Error::Invalid(format!("{why}: {input:?}")));
    let s = input.trim();
    let s = s.strip_prefix(SCHEME).unwrap_or(s).to_ascii_lowercase();
    let s = s.strip_suffix('.').unwrap_or(&s);
    if s.is_empty() || s.len() > 253 {
        return bad("not a domain name");
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return bad("a domain needs at least two labels");
    }
    for l in &labels {
        let ok = (1..=63).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !l.starts_with('-') && !l.ends_with('-');
        if !ok {
            return bad("not a domain name (letters, digits and hyphens; write international names as xn--)");
        }
    }
    // `1.2.3.4` and `0x7f.1` are addresses, not names.
    if labels.last().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()) || tld.starts_with("0x")) {
        return bad("an IP address is not a domain");
    }
    if RESERVED.iter().any(|r| s == *r || s.ends_with(&format!(".{r}"))) {
        return bad("a reserved name cannot be verified");
    }
    Ok(s.to_string())
}

/// Whether `did` can be put in a record and a URL path without surprises.
pub fn valid_did(did: &str) -> bool {
    did.starts_with("did:") && did.len() <= 200 && did.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'-' | b'%'))
}

fn digest(did: &str) -> String {
    sha256(did.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// The text that proves `did`, in a TXT record or an HTML file.
pub fn value(did: &str) -> String {
    format!("{VALUE_KEY}={did}")
}

/// What to publish to prove `did` controls `domain` (already [`normalize`]d).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Records {
    pub txt_name: String,
    pub txt_value: String,
    pub cname_name: String,
    pub cname_target: String,
    /// Where the file must be served, over HTTPS, with no redirect.
    pub html_url: String,
    pub html_body: String,
}

pub fn records(domain: &str, did: &str) -> Records {
    let h = digest(did);
    Records {
        txt_name: format!("{TXT_LABEL}.{domain}"),
        txt_value: value(did),
        cname_name: format!("_kith-{}.{domain}", &h[..16]),
        cname_target: format!("{}.{CNAME_SUFFIX}", &h[..32]),
        html_url: format!("https://{domain}{}", html_path(did)),
        html_body: value(did),
    }
}

/// The path of the HTML file for `did`.
pub fn html_path(did: &str) -> String {
    format!("/kith-{}.html", &digest(did)[..16])
}

/// A TXT record set proves `did` if one record is exactly [`value`]. A record that
/// merely starts with it (a longer DID) does not.
pub fn check_txt(records: &[String], did: &str) -> bool {
    let want = value(did);
    records.iter().any(|r| r.trim() == want)
}

/// A CNAME proves `did` if it points at the expected target (case and a trailing dot
/// are ignored, as DNS ignores them).
pub fn check_cname(targets: &[String], did: &str) -> bool {
    let want = format!("{}.{CNAME_SUFFIX}", &digest(did)[..32]);
    targets.iter().any(|t| t.trim().trim_end_matches('.').eq_ignore_ascii_case(&want))
}

/// A page proves `did` if some whitespace- or markup-delimited word of it is [`value`].
/// Matching whole words keeps `did:kith:abc` from being proved by `did:kith:abcd`.
pub fn check_html(body: &str, did: &str) -> bool {
    let want = value(did);
    body.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '`' | ',')).any(|w| w == want)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADA: &str = "did:kith:ada";

    #[test]
    fn domains_are_normalised() {
        for (input, want) in [("Example.COM", "example.com"), ("dns:example.com", "example.com"), (" example.com. ", "example.com"), ("a-b.sub.example.co.uk", "a-b.sub.example.co.uk"), ("xn--bcher-kva.example", "xn--bcher-kva.example")] {
            assert_eq!(normalize(input).as_deref().ok(), Some(want), "{input}");
        }
        for bad in [
            "", "com", "localhost", "foo.localhost", "printer.local", "db.internal", "1.2.3.4", "0x7f.1", "[::1]", "exa_mple.com", "-a.example.com", "a-.example.com", "a..example.com", ".example.com",
            "bücher.example", "example.com/path", "user@example.com", "example.com:8080", "exa mple.com", "http://example.com", "xn--a.onion",
        ] {
            assert!(normalize(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(normalize(&format!("{}.com", "a".repeat(64))).is_err(), "label too long");
        assert!(normalize(&format!("{}.com", vec!["a".repeat(60); 5].join("."))).is_err(), "name too long");
    }

    #[test]
    fn records_name_the_identity() {
        let r = records("example.com", ADA);
        assert_eq!(r.txt_name, "_kith-challenge.example.com");
        assert_eq!(r.txt_value, "kith-domain-verification=did:kith:ada");
        assert_eq!(r.html_body, r.txt_value);
        let h = digest(ADA);
        assert_eq!(h.len(), 64);
        assert_eq!(r.cname_name, format!("_kith-{}.example.com", &h[..16]));
        assert_eq!(r.cname_target, format!("{}.dv.kith.invalid", &h[..32]));
        assert_eq!(r.html_url, format!("https://example.com/kith-{}.html", &h[..16]));
        assert_ne!(records("example.com", "did:kith:bob").cname_name, r.cname_name, "one name per identity");
        // A label is at most 63 characters.
        assert!(r.cname_name.split('.').all(|l| l.len() <= 63) && r.cname_target.split('.').all(|l| l.len() <= 63));
    }

    #[test]
    fn txt_needs_the_exact_value() {
        let v = |s: &str| vec![s.to_string()];
        assert!(check_txt(&v("kith-domain-verification=did:kith:ada"), ADA));
        assert!(check_txt(&["v=spf1 -all".into(), " kith-domain-verification=did:kith:ada ".into()], ADA));
        assert!(!check_txt(&v("kith-domain-verification=did:kith:adam"), ADA), "a longer DID is not this one");
        assert!(!check_txt(&v("kith-domain-verification=did:kith:ad"), ADA));
        assert!(!check_txt(&v("x kith-domain-verification=did:kith:ada"), ADA), "must be the whole record");
        assert!(!check_txt(&[], ADA));
    }

    #[test]
    fn cname_ignores_case_and_the_trailing_dot() {
        let t = records("example.com", ADA).cname_target;
        assert!(check_cname(std::slice::from_ref(&t), ADA));
        assert!(check_cname(&[format!("{}.", t.to_ascii_uppercase())], ADA));
        assert!(!check_cname(&[t], "did:kith:bob"));
        assert!(!check_cname(&["other.example.net.".into()], ADA));
    }

    #[test]
    fn html_needs_the_whole_word() {
        assert!(check_html("kith-domain-verification=did:kith:ada", ADA));
        assert!(check_html("<html><body>kith-domain-verification=did:kith:ada</body></html>", ADA));
        assert!(check_html("<meta name=\"x\" content=\"kith-domain-verification=did:kith:ada\">", ADA));
        assert!(!check_html("kith-domain-verification=did:kith:adam", ADA));
        assert!(!check_html("kith-domain-verification=did:kith:ad", ADA));
        assert!(!check_html("not found: /kith-0123456789abcdef.html", ADA), "an echoed path proves nothing");
        assert!(!check_html("", ADA));
    }

    #[test]
    fn dids_are_safe_to_publish() {
        assert!(valid_did("did:kith:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
        for bad in ["", "ada", "did:kith:a b", "did:kith:a\"b", "did:kith:a<b>", "did:kith:a/b", "did:kith:a\nb", &format!("did:kith:{}", "a".repeat(200))] {
            assert!(!valid_did(bad), "{bad:?}");
        }
    }

    #[test]
    fn methods_parse() {
        assert_eq!(Method::parse("TXT").unwrap(), Method::Txt);
        assert_eq!(Method::parse("html").unwrap(), Method::Html);
        assert!(Method::parse("whois").is_err());
    }
}
