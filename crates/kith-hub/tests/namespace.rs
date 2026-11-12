//! Names in a verified domain's namespace (spec 7.8.4): whoever holds `dns:example.com`
//! gives out `ada@example.com`, and the hub answers WebFinger for it. The name resolves
//! only when both sides agree: the domain's holder names the root, and the root's own KEL
//! links the alias (spec 5.1.1). A name is served only while the holder who gave it still
//! holds the domain.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kith_core::domain;
use kith_core::kel::{new_inception, next_event, verify_log, Device, DeviceKind, Event, EventBody, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::resolve;
use kith_core::session::{DeviceSigner, SessionKey};
use kith_core::util::random_id;
use kith_hub::domains::{DomainProbe, Probe};
use kith_hub::{Hub, HubConfig, TT_SESSION};

const ISSUER: &str = "http://localhost:7777";
const ALIAS: &str = "acct:ada@example.com";

/// The DNS of the test: only what a test published exists.
#[derive(Debug, Default)]
struct Net {
    txt: Mutex<HashMap<String, Vec<String>>>,
}

impl DomainProbe for Net {
    fn txt<'a>(&'a self, name: &'a str) -> Probe<'a, Vec<String>> {
        let out = self.txt.lock().unwrap().get(name).cloned().unwrap_or_default();
        Box::pin(async move { Ok(out) })
    }
    fn cname<'a>(&'a self, _: &'a str) -> Probe<'a, Vec<String>> {
        Box::pin(async { Ok(vec![]) })
    }
    fn fetch<'a>(&'a self, _: &'a str, _: &'a str) -> Probe<'a, String> {
        Box::pin(async { Err(anyhow::anyhow!("HTTP 404")) })
    }
}

struct Person {
    st: KeyState,
    log: Vec<Event>,
    root: LocalSigner,
    laptop: LocalSigner,
}

struct World {
    app: Router,
    hub: Arc<Hub>,
    net: Arc<Net>,
}

fn person(hub: &Hub) -> Person {
    let root = LocalSigner::generate(KeyType::Ed25519);
    let laptop = LocalSigner::generate(KeyType::Ed25519);
    let next = SignerPolicy::single(LocalSigner::generate(KeyType::Ed25519).id);
    let dev = Device { id: "laptop".into(), key: laptop.id.clone(), name: "laptop".into(), kind: DeviceKind::Software, aal: 1, caps: vec!["session".into()], rp_id: None, xkey: None };
    let mut inc = new_inception(SignerPolicy::single(&root.id), &next, vec![dev]);
    inc.sign(&root).unwrap();
    inc.sign(&laptop).unwrap();
    let log = vec![inc];
    let st = verify_log(&log, &VerifyOptions::default()).unwrap();
    hub.put_kel(&st.did, log.clone()).unwrap();
    Person { st, log, root, laptop }
}

/// The person links `alias` in their own log, as `kith alias link` does.
fn link_alias(hub: &Hub, p: &mut Person, alias: &str) {
    let mut ev = next_event(&p.st, EventBody::AliasLink { alias: alias.into() });
    ev.sign(&p.root).unwrap();
    p.log.push(ev);
    p.st = verify_log(&p.log, &VerifyOptions::default()).unwrap();
    hub.put_kel(&p.st.did, p.log.clone()).unwrap();
}

fn world_with(configure: impl FnOnce(&mut HubConfig)) -> World {
    let dir = std::env::temp_dir().join(format!("kith-namespace-{}", random_id()));
    let net = Arc::new(Net::default());
    let mut cfg = HubConfig::new(ISSUER, dir.join("data"));
    cfg.domains.probe = net.clone();
    configure(&mut cfg);
    let hub = Hub::open(cfg).unwrap();
    World { app: kith_hub::router(hub.clone()), hub, net }
}

fn world() -> World {
    world_with(|_| {})
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn header(&self, name: &str) -> &str {
        self.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default()
    }
}

async fn call(app: &Router, method: &str, uri: &str, auth: Option<&str>, body: Option<Value>) -> Resp {
    let mut b = Request::builder().method(method).uri(uri).extension(ConnectInfo(SocketAddr::new("10.0.0.1".parse().unwrap(), 4000)));
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let r = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let (status, headers) = (r.status(), r.headers().clone());
    Resp { status, headers, body: r.into_body().collect().await.unwrap().to_bytes().to_vec() }
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// A hub token from the person's laptop key, as the CLI gets one.
async fn bearer(w: &World, p: &Person) -> String {
    let dev = p.st.device("laptop").unwrap().clone();
    let sk = SessionKey::create(&p.st.did, &dev, DeviceSigner::Key(&p.laptop.secret), 3600).unwrap();
    let st_tok = sk.session_token(ISSUER, json!({})).unwrap();
    let body = format!("grant_type={}&subject_token={}&subject_token_type={}", enc("urn:ietf:params:oauth:grant-type:token-exchange"), enc(&st_tok), enc(TT_SESSION));
    let req = Request::post("/oauth/token").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(Body::from(body)).unwrap();
    let r = w.app.clone().oneshot(req).await.unwrap();
    let tok: Value = serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    format!("Bearer {}", tok["access_token"].as_str().expect("access token"))
}

/// `who` proves `domain` the way a person does: publish the record, ask the hub to look.
async fn hold(w: &World, who: &Person, auth: &str, domain: &str) {
    let r = domain::records(domain, &who.st.did);
    w.net.txt.lock().unwrap().entry(r.txt_name).or_default().push(r.txt_value);
    let r = call(&w.app, "POST", "/v1/domains/verify", Some(auth), Some(json!({"domain": domain}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

async fn give(w: &World, auth: &str, domain: &str, local: &str, did: &str) -> Resp {
    call(&w.app, "PUT", &format!("/v1/namespaces/{domain}/{local}"), Some(auth), Some(json!({"did": did}))).await
}

async fn finger(w: &World, resource: &str) -> Resp {
    call(&w.app, "GET", &format!("/.well-known/webfinger?resource={}", enc(resource)), None, None).await
}

#[tokio::test]
async fn a_domain_holder_gives_out_a_name_and_the_hub_answers_webfinger_for_it() {
    let w = world();
    let mut ada = person(&w.hub);
    let acme = person(&w.hub);
    let a = bearer(&w, &acme).await;
    hold(&w, &acme, &a, "example.com").await;

    let r = give(&w, &a, "example.com", "ada", &ada.st.did).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let j = r.json();
    assert_eq!((j["alias"].as_str(), j["did"].as_str(), j["held_by"].as_str(), j["linked"].as_bool()), (Some(ALIAS), Some(ada.st.did.as_str()), Some(acme.st.did.as_str()), Some(false)));

    // Anyone can finger it; no token. mailto: is acct: (RFC 7565), and the host is case-blind.
    for resource in [ALIAS, "mailto:ada@example.com", "acct:ada@EXAMPLE.com"] {
        let r = finger(&w, resource).await;
        assert_eq!(r.status, StatusCode::OK, "{resource}: {}", r.text());
        assert_eq!(r.header("content-type"), "application/jrd+json");
        assert_eq!(r.header("access-control-allow-origin"), "*", "RFC 7033: browsers may ask");
        let jrd = r.json();
        assert_eq!(jrd["subject"], ALIAS);
        // The very JRD `kith resolve` reads: a root, and the hub that serves its log.
        let c = resolve::from_jrd(&jrd);
        assert_eq!(c.len(), 1, "{jrd}");
        assert_eq!((c[0].did.as_str(), c[0].hub.as_deref(), c[0].via), (ada.st.did.as_str(), Some(ISSUER), "webfinger"));
    }
    let jrd = finger(&w, ALIAS).await.json();
    let profile = jrd["links"].as_array().unwrap().iter().find(|l| l["rel"] == "http://webfinger.net/rel/profile-page").expect("a profile link");
    assert_eq!(profile["href"], format!("{ISSUER}/v1/profile/{}", ada.st.did));

    // rel narrows the links (RFC 7033 4.3); the subject stays.
    let only = finger_rel(&w, ALIAS, "http://webfinger.net/rel/profile-page").await.json();
    assert_eq!(only["subject"], ALIAS);
    assert_eq!(only["links"].as_array().unwrap().len(), 1);

    // The domain's word alone proves nothing: Ada's log has to link the name too.
    assert!(!resolve::links_back(&ada.st, ALIAS), "she has not linked it yet");
    link_alias(&w.hub, &mut ada, "mailto:ada@example.com");
    assert!(resolve::links_back(&ada.st, ALIAS), "acct: and mailto: are one alias");
}

async fn finger_rel(w: &World, resource: &str, rel: &str) -> Resp {
    call(&w.app, "GET", &format!("/.well-known/webfinger?resource={}&rel={}", enc(resource), enc(rel)), None, None).await
}

#[tokio::test]
async fn only_the_current_holder_of_a_domain_gives_out_its_names() {
    let w = world();
    let (ada, acme, eve) = (person(&w.hub), person(&w.hub), person(&w.hub));
    let (a, e) = (bearer(&w, &acme).await, bearer(&w, &eve).await);

    // Nobody holds example.com yet.
    assert_eq!(give(&w, &a, "example.com", "ada", &ada.st.did).await.status, StatusCode::FORBIDDEN);
    hold(&w, &acme, &a, "example.com").await;
    let put = |auth: Option<&str>, local: &str, did: &str| {
        let (app, auth, did) = (w.app.clone(), auth.map(String::from), did.to_string());
        let uri = format!("/v1/namespaces/example.com/{local}");
        async move { call(&app, "PUT", &uri, auth.as_deref(), Some(json!({"did": did}))).await }
    };
    assert_eq!(put(None, "ada", &ada.st.did).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(put(Some(&e), "ada", &ada.st.did).await.status, StatusCode::FORBIDDEN, "Eve holds nothing");
    assert_eq!(finger(&w, ALIAS).await.status, StatusCode::NOT_FOUND, "and nothing was given");

    // A name is a short, plain local part; the target is a DID this hub has a log for.
    for bad in ["", "Ada", "a%20b", "a%2Fb", "-", &"x".repeat(65)] {
        let r = put(Some(&a), bad, &ada.st.did).await;
        assert!(matches!(r.status, StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND), "{bad:?}: {} {}", r.status, r.text());
        assert_ne!(r.status, StatusCode::OK, "{bad:?}");
    }
    assert_eq!(put(Some(&a), "ada", "did:kith:nobody").await.status, StatusCode::BAD_REQUEST, "no log for it here");
    assert_eq!(put(Some(&a), "ada", "mailto:x@example.com").await.status, StatusCode::BAD_REQUEST, "not a DID");
    assert_eq!(put(Some(&a), "ada", &ada.st.did).await.status, StatusCode::OK);
}

#[tokio::test]
async fn names_are_served_only_while_the_holder_who_gave_them_holds_the_domain() {
    let w = world();
    let (ada, acme, eve) = (person(&w.hub), person(&w.hub), person(&w.hub));
    let (a, e) = (bearer(&w, &acme).await, bearer(&w, &eve).await);
    hold(&w, &acme, &a, "example.com").await;
    assert_eq!(give(&w, &a, "example.com", "ada", &ada.st.did).await.status, StatusCode::OK);
    assert_eq!(finger(&w, ALIAS).await.status, StatusCode::OK);

    // The domain changes hands. What Acme gave out is not Eve's to vouch for, and not Acme's any more.
    hold(&w, &eve, &e, "example.com").await;
    assert_eq!(finger(&w, ALIAS).await.status, StatusCode::NOT_FOUND);
    assert_eq!(give(&w, &a, "example.com", "ada", &ada.st.did).await.status, StatusCode::FORBIDDEN);
    assert_eq!(call(&w.app, "GET", "/v1/namespaces/example.com", Some(&e), None).await.json(), json!([]), "Eve starts with none");

    // If Acme proves the domain again its names come back: they were never deleted.
    hold(&w, &acme, &a, "example.com").await;
    assert_eq!(finger(&w, ALIAS).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_stale_domain_stops_answering_until_it_is_checked_again() {
    let w = world_with(|c| c.domains.max_age = 1);
    let (ada, acme) = (person(&w.hub), person(&w.hub));
    let a = bearer(&w, &acme).await;
    hold(&w, &acme, &a, "example.com").await;
    give(&w, &a, "example.com", "ada", &ada.st.did).await;
    assert_eq!(finger(&w, ALIAS).await.status, StatusCode::OK);

    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert_eq!(finger(&w, ALIAS).await.status, StatusCode::NOT_FOUND, "an unchecked domain vouches for nothing");
    assert_eq!(give(&w, &a, "example.com", "bob", &ada.st.did).await.status, StatusCode::FORBIDDEN);

    // The record is still published, so checking again brings the names back.
    let r = call(&w.app, "POST", "/v1/domains/verify", Some(&a), Some(json!({"domain": "example.com"}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(finger(&w, ALIAS).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_holder_lists_replaces_and_removes_names() {
    let w = world();
    let (ada, bob, acme, eve) = (person(&w.hub), person(&w.hub), person(&w.hub), person(&w.hub));
    let (a, e) = (bearer(&w, &acme).await, bearer(&w, &eve).await);
    hold(&w, &acme, &a, "example.com").await;
    give(&w, &a, "example.com", "ada", &ada.st.did).await;
    give(&w, &a, "example.com", "bob", &bob.st.did).await;

    let listed = call(&w.app, "GET", "/v1/namespaces/example.com", Some(&a), None).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text());
    let names: Vec<(String, String, bool)> = listed.json().as_array().unwrap().iter().map(|n| (n["alias"].as_str().unwrap().into(), n["did"].as_str().unwrap().into(), n["linked"].as_bool().unwrap())).collect();
    assert_eq!(names, [("acct:ada@example.com".into(), ada.st.did.clone(), false), ("acct:bob@example.com".into(), bob.st.did.clone(), false)]);
    assert_eq!(call(&w.app, "GET", "/v1/namespaces/example.com", Some(&e), None).await.status, StatusCode::FORBIDDEN, "a list of people is not public");
    assert_eq!(call(&w.app, "GET", "/v1/namespaces/example.com", None, None).await.status, StatusCode::UNAUTHORIZED);

    // One name names one root: giving it again replaces.
    give(&w, &a, "example.com", "ada", &bob.st.did).await;
    assert_eq!(resolve::from_jrd(&finger(&w, ALIAS).await.json())[0].did, bob.st.did);

    let gone = call(&w.app, "DELETE", "/v1/namespaces/example.com/ada", Some(&a), None).await;
    assert_eq!(gone.status, StatusCode::OK, "{}", gone.text());
    assert_eq!(finger(&w, ALIAS).await.status, StatusCode::NOT_FOUND);
    assert_eq!(call(&w.app, "DELETE", "/v1/namespaces/example.com/ada", Some(&a), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(call(&w.app, "DELETE", "/v1/namespaces/example.com/bob", Some(&e), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(finger(&w, "acct:bob@example.com").await.status, StatusCode::OK, "Eve could not remove Bob's");
}

#[tokio::test]
async fn webfinger_has_nothing_to_say_about_names_it_does_not_hold() {
    let w = world();
    let (ada, acme) = (person(&w.hub), person(&w.hub));
    let a = bearer(&w, &acme).await;
    hold(&w, &acme, &a, "example.com").await;
    give(&w, &a, "example.com", "ada", &ada.st.did).await;
    for resource in ["acct:bob@example.com", "acct:ada@other.example", "https://example.com/ada", "acct:ada@localhost:7777"] {
        let r = finger(&w, resource).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{resource:?}: {}", r.text());
    }
    // RFC 7033 4.2: a resource that is absent or malformed is a bad request, not a miss.
    for resource in ["", "acct:ada", "ada@example.com"] {
        let r = finger(&w, resource).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{resource:?}: {}", r.text());
    }
    assert_eq!(call(&w.app, "GET", "/.well-known/webfinger", None, None).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_name_both_sides_agree_on_shows_on_the_profile_and_finds_it() {
    let w = world();
    let (mut ada, acme) = (person(&w.hub), person(&w.hub));
    let (a, auth) = (bearer(&w, &acme).await, bearer(&w, &ada).await);
    hold(&w, &acme, &a, "example.com").await;
    give(&w, &a, "example.com", "ada", &ada.st.did).await;
    let profile = |who: String| {
        let app = w.app.clone();
        async move { call(&app, "GET", &format!("/v1/profile/{who}"), None, None).await }
    };

    // Offered, not yet linked: Ada sees the offer, the public sees nothing, the name finds no profile.
    let mine = call(&w.app, "GET", "/v1/whoami", Some(&auth), None).await.json();
    assert_eq!(mine["namespaces"], json!([{"alias": ALIAS, "domain": "example.com", "held_by": acme.st.did, "linked": false}]));
    assert_eq!(profile(ada.st.did.clone()).await.json()["namespaces"], json!([]));
    assert_eq!(profile("ada@example.com".into()).await.status, StatusCode::NOT_FOUND);

    // Ada links it in her own log; now both directions hold.
    link_alias(&w.hub, &mut ada, "mailto:ada@example.com");
    let public = profile(ada.st.did.clone()).await.json();
    assert_eq!(public["namespaces"], json!([{"alias": ALIAS, "domain": "example.com", "held_by": acme.st.did, "linked": true}]));
    assert_eq!(call(&w.app, "GET", "/v1/whoami", Some(&auth), None).await.json()["namespaces"], public["namespaces"]);

    // And the name is a way to the profile, in any spelling.
    for who in ["ada@example.com", "acct:ada@example.com", "mailto:ada@example.com", "ada@EXAMPLE.com"] {
        let r = profile(enc(who)).await;
        assert_eq!(r.status, StatusCode::OK, "{who}: {}", r.text());
        assert_eq!(r.json()["did"], ada.st.did);
    }

    // Take the domain away from Acme and the proof is gone from the profile.
    call(&w.app, "DELETE", "/v1/contacts", Some(&a), Some(json!({"address": "dns:example.com"}))).await;
    assert_eq!(profile(ada.st.did.clone()).await.json()["namespaces"], json!([]));
    assert_eq!(profile("ada@example.com".into()).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_domain_can_only_give_out_so_many_names() {
    let w = world();
    let (ada, acme) = (person(&w.hub), person(&w.hub));
    let a = bearer(&w, &acme).await;
    hold(&w, &acme, &a, "example.com").await;
    for i in 0..1000 {
        let r = give(&w, &a, "example.com", &format!("u{i}"), &ada.st.did).await;
        assert_eq!(r.status, StatusCode::OK, "{i}: {}", r.text());
    }
    let over = give(&w, &a, "example.com", "one-more", &ada.st.did).await;
    assert_eq!(over.status, StatusCode::CONFLICT, "{}", over.text());
    assert_eq!(give(&w, &a, "example.com", "u7", &ada.st.did).await.status, StatusCode::OK, "replacing is not adding");
}
