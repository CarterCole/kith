//! Verified domains (spec 7.8.3): an identity proves it controls a domain by publishing
//! a record that names its DID (`kith_core::domain`), and the hub attests what it saw.
//!
//! Three ways to publish the proof (a TXT record, a CNAME, or an HTML file), as Google and
//! Bing offer. The record carries the DID, so the hub keeps no challenge: anyone can read
//! it, and any hub can **witness** it for any DID, signing what it saw with its own key.
//! The person who proves a domain, or an org, ends up as a contact whose address is
//! `dns:<domain>`, so listing, publishing, forgetting, staleness, takeover and the public
//! lookup are the verified-contact ones (spec 7.8.2).
//!
//! | endpoint                    | purpose                                                     |
//! |-----------------------------|-------------------------------------------------------------|
//! | `POST /v1/domains`          | what to publish to prove the caller's DID (bearer)          |
//! | `POST /v1/domains/verify`   | look for it; on success the caller holds the domain (bearer) |
//! | `GET  /v1/domains/attest`   | look for any DID's proof and sign what was seen (no token)  |
//!
//! DNS and HTTP go through a [`DomainProbe`] so tests need no network. The real one
//! ([`SystemProbe`]) fetches the page over HTTPS only, from an address it resolved and
//! checked is public, with no redirects, a short timeout and a small body limit: the
//! domain is the caller's input, so this is a server-side request the caller steers.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use kith_core::domain::{self, Method};
use kith_core::token::AccountAttestation;
use kith_core::util::{now, random_id};

use crate::contacts::{view, PUBLIC_AUDIENCE};
use crate::{ApiError, ApiResult, ClientIp, Hub, RateLimit, TOKEN_TTL};

/// How long a witness statement lasts. Short on purpose: it says what this hub saw just
/// now, so a relying party that wants a later answer asks again.
pub const WITNESS_TTL: i64 = 600;
/// The most of a page the hub reads.
const BODY_LIMIT: usize = 16 * 1024;
/// How long one DNS lookup or page fetch may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub type Probe<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

/// What the hub asks of the outside world. An answer of no records is `Ok(vec![])`; a
/// failure to ask is an `Err` that the caller is shown.
pub trait DomainProbe: Send + Sync + std::fmt::Debug {
    /// The TXT records at `name`, each record's strings joined.
    fn txt<'a>(&'a self, name: &'a str) -> Probe<'a, Vec<String>>;
    /// The CNAME targets at `name` (not followed).
    fn cname<'a>(&'a self, name: &'a str) -> Probe<'a, Vec<String>>;
    /// `GET https://{host}{path}`: the body of a `200` and nothing else.
    fn fetch<'a>(&'a self, host: &'a str, path: &'a str) -> Probe<'a, String>;
}

#[derive(Debug, Clone)]
pub struct DomainConfig {
    pub probe: Arc<dyn DomainProbe>,
    /// The methods this hub accepts. An operator who thinks a file on a shared host is
    /// too weak a proof can leave `Html` out.
    pub methods: Vec<Method>,
    /// Seconds a verification stays good. Domains change hands, so it is shorter than
    /// an email address's year.
    pub max_age: i64,
    /// Checks per identity and per client address (verify), and per client address
    /// (witness). Each one asks the network something.
    pub verify_limit: RateLimit,
}

impl Default for DomainConfig {
    fn default() -> Self {
        DomainConfig { probe: Arc::new(SystemProbe), methods: Method::ALL.to_vec(), max_age: 90 * 86_400, verify_limit: RateLimit { max: 10, window_secs: 3600 } }
    }
}

impl DomainConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.max_age <= 0 {
            anyhow::bail!("domain max age must be positive");
        }
        if self.methods.is_empty() {
            anyhow::bail!("at least one domain verification method must be allowed");
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ the real network

/// DNS through the system resolver, and pages over HTTPS.
#[derive(Debug, Default)]
pub struct SystemProbe;

fn resolver() -> anyhow::Result<hickory_resolver::TokioResolver> {
    Ok(hickory_resolver::Resolver::builder_tokio()?.build()?)
}

fn no_records(e: &hickory_resolver::net::NetError) -> bool {
    e.is_no_records_found()
}

/// Whether `ip` is an address a stranger's page may be fetched from. Everything that
/// points inside a network is refused: loopback, private ranges, link-local (cloud
/// metadata lives at 169.254.169.254), carrier-grade NAT, unique-local, multicast, and
/// IPv4 inside IPv6.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (18..20).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64: an IPv4 address in disguise
                || s[0] == 0x2002) // 6to4
        }
    }
}

impl DomainProbe for SystemProbe {
    fn txt<'a>(&'a self, name: &'a str) -> Probe<'a, Vec<String>> {
        Box::pin(async move {
            let lookup = match resolver()?.txt_lookup(format!("{name}.")).await {
                Ok(l) => l,
                Err(e) if no_records(&e) => return Ok(Vec::new()),
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

    fn cname<'a>(&'a self, name: &'a str) -> Probe<'a, Vec<String>> {
        Box::pin(async move {
            use hickory_resolver::proto::rr::RecordType;
            let lookup = match resolver()?.lookup(format!("{name}."), RecordType::CNAME).await {
                Ok(l) => l,
                Err(e) if no_records(&e) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    hickory_resolver::proto::rr::RData::CNAME(c) => Some(c.0.to_string()),
                    _ => None,
                })
                .collect())
        })
    }

    fn fetch<'a>(&'a self, host: &'a str, path: &'a str) -> Probe<'a, String> {
        Box::pin(async move {
            // Resolve first and refuse anything non-public, then connect to exactly the
            // address that was checked, so a second answer cannot send us elsewhere.
            let ips: Vec<IpAddr> = resolver()?.lookup_ip(format!("{host}.")).await?.iter().collect();
            if ips.is_empty() {
                anyhow::bail!("{host} has no address");
            }
            if let Some(bad) = ips.iter().find(|ip| !is_public(**ip)) {
                anyhow::bail!("{host} resolves to {bad}, which is not a public address");
            }
            let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(PROBE_TIMEOUT).resolve_to_addrs(host, &ips.iter().map(|ip| SocketAddr::new(*ip, 443)).collect::<Vec<_>>()).build()?;
            let mut resp = client.get(format!("https://{host}{path}")).header("accept", "text/html, text/plain").send().await?;
            if resp.status() != reqwest::StatusCode::OK {
                anyhow::bail!("HTTP {} (redirects are not followed)", resp.status());
            }
            let mut body = Vec::new();
            while let Some(chunk) = resp.chunk().await? {
                body.extend_from_slice(&chunk);
                if body.len() > BODY_LIMIT {
                    body.truncate(BODY_LIMIT);
                    break;
                }
            }
            Ok(String::from_utf8_lossy(&body).into_owned())
        })
    }
}

// ------------------------------------------------------------------ checking

struct Outcome {
    found: Option<Method>,
    checked: Vec<Value>,
}

async fn timed<T>(f: Probe<'_, T>) -> anyhow::Result<T> {
    tokio::time::timeout(PROBE_TIMEOUT + Duration::from_secs(5), f).await.map_err(|_| anyhow::anyhow!("timed out"))?
}

/// Looks for `did`'s proof at `domain` by each allowed method (or only `only`), in the
/// order txt, cname, html, stopping at the first that holds.
async fn look(h: &Hub, domain: &str, did: &str, only: Option<Method>) -> Outcome {
    let probe = &h.cfg.domains.probe;
    let want = domain::records(domain, did);
    let mut checked = Vec::new();
    for m in Method::ALL.into_iter().filter(|m| h.cfg.domains.methods.contains(m) && only.is_none_or(|o| o == *m)) {
        let result: anyhow::Result<(bool, String)> = match m {
            Method::Txt => timed(probe.txt(&want.txt_name)).await.map(|r| (domain::check_txt(&r, did), format!("{} TXT record(s) at {}, none is {}", r.len(), want.txt_name, want.txt_value))),
            Method::Cname => timed(probe.cname(&want.cname_name)).await.map(|r| (domain::check_cname(&r, did), format!("{} CNAME record(s) at {}, none points at {}", r.len(), want.cname_name, want.cname_target))),
            Method::Html => timed(probe.fetch(domain, &domain::html_path(did))).await.map(|b| (domain::check_html(&b, did), format!("{} does not contain {}", want.html_url, want.html_body))),
        };
        match result {
            Ok((true, _)) => {
                checked.push(json!({"method": m.name(), "ok": true}));
                return Outcome { found: Some(m), checked };
            }
            Ok((false, why)) => checked.push(json!({"method": m.name(), "ok": false, "why": why})),
            Err(e) => checked.push(json!({"method": m.name(), "ok": false, "why": e.to_string()})),
        }
    }
    Outcome { found: None, checked }
}

fn failed(domain: &str, did: &str, checked: Vec<Value>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, "verification_failed".into(), format!("found no proof that {did} controls {domain}"), Some(json!({"checked": checked})))
}

fn too_many(retry: i64) -> ApiError {
    ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited".into(), format!("too many checks; try again in {retry}s"), Some(json!({"retry_after": retry})))
}

fn parse_domain(input: &str) -> ApiResult<String> {
    domain::normalize(input).map_err(|e| ApiError::bad("invalid_request", e))
}

fn parse_method(h: &Hub, m: Option<&str>) -> ApiResult<Option<Method>> {
    let Some(m) = m else { return Ok(None) };
    let m = Method::parse(m).map_err(|e| ApiError::bad("invalid_request", e))?;
    if !h.cfg.domains.methods.contains(&m) {
        return Err(ApiError::bad("invalid_request", format!("this hub does not accept the {} method", m.name())));
    }
    Ok(Some(m))
}

// ------------------------------------------------------------------ handlers

#[derive(Deserialize)]
pub struct DomainReq {
    domain: String,
    #[serde(default)]
    method: Option<String>,
}

/// `POST /v1/domains`: what to publish. Nothing is stored and nothing is looked up.
pub async fn records(State(h): State<Arc<Hub>>, headers: HeaderMap, Json(req): Json<DomainReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let domain = parse_domain(&req.domain)?;
    let r = domain::records(&domain, &c.sub);
    let mut methods = serde_json::Map::new();
    for m in Method::ALL.into_iter().filter(|m| h.cfg.domains.methods.contains(m)) {
        methods.insert(
            m.name().into(),
            match m {
                Method::Txt => json!({"type": "TXT", "name": r.txt_name, "value": r.txt_value}),
                Method::Cname => json!({"type": "CNAME", "name": r.cname_name, "value": r.cname_target}),
                Method::Html => json!({"url": r.html_url, "body": r.html_body}),
            },
        );
    }
    Ok(Json(json!({"domain": format!("{}{domain}", domain::SCHEME), "did": c.sub, "methods": methods})))
}

/// `POST /v1/domains/verify`: look for the caller's proof. If it is there the caller
/// holds the domain (taking it from whoever held it before) and may publish it.
pub async fn verify(State(h): State<Arc<Hub>>, ip: ClientIp, headers: HeaderMap, Json(req): Json<DomainReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let domain = parse_domain(&req.domain)?;
    let only = parse_method(&h, req.method.as_deref())?;
    let t = now();
    for bucket in [format!("domain-did|{}", c.sub), format!("domain-ip|{}", ip.0)] {
        if let Some(retry) = h.store.hit(&bucket, h.cfg.domains.verify_limit, t)? {
            return Err(too_many(retry));
        }
    }
    let out = look(&h, &domain, &c.sub, only).await;
    let Some(method) = out.found else { return Err(failed(&domain, &c.sub, out.checked)) };
    let rec = h.store.hold_contact(&c.sub, &format!("{}{domain}", domain::SCHEME), now())?;
    let mut v = view(&h, &rec);
    v["method"] = json!(method.name());
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct AttestQuery {
    domain: String,
    did: String,
}

/// `GET /v1/domains/attest?domain=…&did=…`: look for `did`'s proof at `domain` and, if it
/// is there, sign that this hub saw it. No token: the proof is public, so anyone may ask,
/// and the DID need not have an account here (an org's DID usually does not). Nothing is
/// stored. A relying party that trusts several hubs collects one statement from each.
pub async fn attest(State(h): State<Arc<Hub>>, ip: ClientIp, Query(q): Query<AttestQuery>) -> ApiResult<Json<Value>> {
    let domain = parse_domain(&q.domain)?;
    if !domain::valid_did(&q.did) {
        return Err(ApiError::bad("invalid_request", "did is not a DID"));
    }
    if let Some(retry) = h.store.hit(&format!("domain-witness-ip|{}", ip.0), h.cfg.domains.verify_limit, now())? {
        return Err(too_many(retry));
    }
    let out = look(&h, &domain, &q.did, None).await;
    let Some(method) = out.found else { return Err(failed(&domain, &q.did, out.checked)) };
    let iat = now();
    let account = format!("{}{domain}", domain::SCHEME);
    let claims = AccountAttestation {
        iss: h.cfg.issuer.clone(),
        sub: q.did.clone(),
        aud: PUBLIC_AUDIENCE.into(),
        iat,
        exp: iat + WITNESS_TTL.min(TOKEN_TTL),
        jti: random_id(),
        provider: "domain".into(),
        provider_iss: h.cfg.issuer.clone(),
        account: account.clone(),
        verified_at: iat,
    };
    let attestation = h.signer.issue_attestation(&claims)?;
    Ok(Json(json!({"domain": account, "did": q.did, "method": method.name(), "verified_at": iat, "attestation": attestation})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_may_be_fetched_from() {
        for ok in ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2a00:1450:4001::1"] {
            assert!(is_public(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "127.0.0.1", "127.8.8.8", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "100.127.255.255", "224.0.0.1", "255.255.255.255", "240.0.0.1", "192.0.2.1",
            "198.51.100.1", "203.0.113.1", "198.18.0.1", "192.0.0.8", "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::7f00:1", "2001:db8::1", "2002:7f00:1::1",
        ] {
            assert!(!is_public(bad.parse().unwrap()), "{bad}");
        }
    }

    /// Against the real network: `cargo test -p kith-hub --lib -- --ignored`.
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn the_system_probe_reads_real_dns_and_refuses_private_hosts() {
        let p = SystemProbe;
        let cnames = p.cname("docs.python.org").await.unwrap();
        assert!(cnames.iter().any(|c| c.contains("fastly")), "{cnames:?}");
        assert!(p.cname("google.com").await.unwrap().is_empty(), "no CNAME at an apex is not an error");
        assert!(p.txt("google.com").await.unwrap().iter().any(|t| t.starts_with("v=spf1")));
        assert!(p.txt("no-such-name.kith-test.example.com").await.unwrap().is_empty());
        let page = p.fetch("example.com", "/").await.unwrap();
        assert!(page.contains("Example Domain"), "{page}");
        // Redirects are not followed, and a 404 is an error.
        assert!(p.fetch("example.com", "/kith-0000000000000000.html").await.is_err());
        let e = p.fetch("localhost", "/").await.unwrap_err().to_string();
        assert!(e.contains("not a public address"), "{e}");
    }
}
