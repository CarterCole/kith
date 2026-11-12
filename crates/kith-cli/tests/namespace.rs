//! `kith namespace` and `kith finger` against a real hub on a real port (spec 7.8.4).
//!
//! The binary is the one Cargo built. The hub is in this process, with a fake DNS, because
//! a domain can only be verified by a record the hub can see, and `scripts/cli-flows.sh`
//! has no domain to publish one for.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use kith_core::domain;
use kith_hub::domains::{DomainProbe, Probe};
use kith_hub::HubConfig;

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

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {:?}\n{}", self.stdout, self.stderr))
    }
}

fn kith(home: &Path, args: &[&str]) -> Out {
    let o = Command::new(env!("CARGO_BIN_EXE_kith")).arg("--home").arg(home).args(args).env_remove("KITH_HUB").output().expect("run kith");
    Out { ok: o.status.success(), stdout: String::from_utf8_lossy(&o.stdout).trim().into(), stderr: String::from_utf8_lossy(&o.stderr).into() }
}

fn temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kith-cli-ns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_domain_holder_names_a_root_and_finger_finds_it_only_once_the_root_links_it() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let hub = format!("http://localhost:{port}");
    let net = Arc::new(Net::default());
    let mut cfg = HubConfig::new(&hub, temp("hub").join("data"));
    cfg.domains.probe = net.clone();
    std::thread::spawn(move || {
        let _ = tokio::runtime::Runtime::new().unwrap().block_on(kith_hub::serve(cfg, &format!("127.0.0.1:{port}")));
    });
    let client = reqwest::blocking::Client::new();
    for _ in 0..100 {
        if client.get(format!("{hub}/.well-known/jwks.json")).send().is_ok_and(|r| r.status().is_success()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let (acme, ada) = (temp("acme"), temp("ada"));
    let init = |home: &Path| -> String {
        let o = kith(home, &["init", "--keystore", "file", "--no-secure-enclave", "--hub", &hub]);
        assert!(o.ok, "init: {}", o.stderr);
        o.stdout
    };
    let (acme_did, ada_did) = (init(&acme), init(&ada));

    // Acme proves example.com; with no record, it holds nothing and may name no one.
    let early = kith(&acme, &["namespace", "add", "ada@example.com", "--to", &ada_did]);
    assert!(!early.ok && early.stderr.contains("example.com"), "{}", early.stderr);
    let r = domain::records("example.com", &acme_did);
    net.txt.lock().unwrap().entry(r.txt_name).or_default().push(r.txt_value);
    let v = kith(&acme, &["domain", "verify", "example.com"]);
    assert!(v.ok, "verify: {}", v.stderr);

    // Acme names Ada. Ada has not linked it, so it does not resolve.
    let added = kith(&acme, &["namespace", "add", "ada@example.com", "--to", &ada_did]);
    assert!(added.ok, "add: {}", added.stderr);
    assert!(added.stderr.contains("kith alias link mailto:ada@example.com"), "says what Ada must do: {}", added.stderr);
    let j = added.json();
    assert_eq!((j["alias"].as_str(), j["did"].as_str(), j["linked"].as_bool()), (Some("acct:ada@example.com"), Some(ada_did.as_str()), Some(false)));
    let early = kith(&acme, &["finger", "ada@example.com", "--hub", &hub]);
    assert!(!early.ok && early.stderr.contains("does not link"), "the domain's word alone proves nothing: {}", early.stderr);

    // Ada links it in her own log; now both directions hold, and anyone can finger it.
    let linked = kith(&ada, &["alias", "link", "mailto:ada@example.com"]);
    assert!(linked.ok, "alias link: {}", linked.stderr);
    let stranger = temp("stranger");
    let found = kith(&stranger, &["finger", "ada@example.com", "--hub", &hub]);
    assert!(found.ok, "finger: {}", found.stderr);
    let j = found.json();
    assert_eq!((j["did"].as_str(), j["via"].as_str(), j["hub"].as_str()), (Some(ada_did.as_str()), Some("webfinger"), Some(hub.as_str())));

    let listed = kith(&acme, &["namespace", "list", "example.com"]).json();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!((listed[0]["alias"].as_str(), listed[0]["linked"].as_bool()), (Some("acct:ada@example.com"), Some(true)));

    // The public profile now carries the name, and the name finds the profile.
    let by_name: Value = client.get(format!("{hub}/v1/profile/ada@example.com")).send().unwrap().json().unwrap();
    assert_eq!(by_name["did"], ada_did.as_str());
    assert_eq!(by_name["namespaces"][0]["held_by"], acme_did.as_str());

    // Taking it back ends it.
    assert!(kith(&acme, &["namespace", "remove", "ada@example.com"]).ok);
    assert!(!kith(&stranger, &["finger", "ada@example.com", "--hub", &hub]).ok);
}
