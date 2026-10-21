//! `kith` – the Kith command line.
//!
//! State lives in `$KITH_HOME` (default `~/.kith`). **Keys are stored in plaintext
//! JSON in this reference CLI**; real deployments keep the manage key on hardware or
//! in a wallet, recovery keys offline, and device keys in the OS keychain / Secure
//! Enclave / TPM.

mod names;
mod org;

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use kith_core::alias::{verify_alias_proof, AliasProof, PrivateAlias};
use kith_core::kel::{new_inception, next_event, verify_log, Device, DeviceKind, Event, EventBody, KeyState};
use kith_core::keys::{KeyType, LocalSigner, VerifyOptions};
use kith_core::policy::SignerPolicy;
use kith_core::session::{Capability, DeviceSigner, SessionKey};
use kith_core::util::{b64u, b64u_decode, now, random_id};
use kith_core::vault::ExchangeKey;
use kith_core::{jws, totp};

#[derive(Parser)]
#[command(name = "kith", version, about = "Universal identity: one root, many devices, sessions, aliases and delegation")]
struct Cli {
    /// State directory.
    #[arg(long, env = "KITH_HOME", global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new root identity with a device, a manage key and 2-of-3 recovery keys.
    Init {
        #[arg(long, env = "KITH_HUB")]
        hub: Option<String>,
        #[arg(long, default_value = "this-device")]
        device_name: String,
        /// Use a (simulated) Ethereum wallet as one of the recovery signers.
        #[arg(long)]
        wallet: bool,
    },
    /// Show this identity.
    Status,
    /// Print the key event log.
    Kel,
    /// Print the DID document.
    DidDoc,
    /// Push the KEL to the hub.
    Publish,
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Rotate the manage key using the pre-committed recovery keys.
    Rotate {
        /// Also revoke every device (use after a compromise).
        #[arg(long)]
        revoke_devices: bool,
        /// Make the hub's TOTP-gated co-signer one of the next recovery signers.
        #[arg(long)]
        add_cosigner: bool,
        /// TOTP code, when the current recovery policy includes the hub co-signer.
        #[arg(long)]
        totp: Option<String>,
    },
    #[command(subcommand)]
    Alias(AliasCmd),
    /// Local names for roots: `kith name add ada mailto:ada@acme.test`, then
    /// `--to ada` anywhere a DID is expected.
    #[command(subcommand)]
    Name(names::NameCmd),
    /// Resolve a public alias to its root: the alias side's back-link (WebFinger,
    /// DNS TXT or did:web) must name the root, and the root's KEL must link the alias.
    Resolve { alias: String },
    /// Authenticate to the hub and get an access token for an audience.
    Login {
        #[arg(long)]
        aud: Option<String>,
        /// `session` (device → session key chain) or `challenge` (sign a hub challenge).
        #[arg(long, default_value = "session")]
        method: String,
        /// TOTP code for step-up.
        #[arg(long)]
        totp: Option<String>,
        /// Redeem a delegation token (you are the actor).
        #[arg(long)]
        delegation: Option<String>,
        /// Print the access token.
        #[arg(long)]
        print: bool,
    },
    /// Print a valid access token for an audience (logging in if needed).
    Token {
        #[arg(long)]
        aud: Option<String>,
    },
    /// Show the claims of the stored access token.
    Whoami {
        #[arg(long)]
        aud: Option<String>,
    },
    /// Delegate capabilities to another identity.
    Delegate {
        #[arg(long)]
        to: String,
        /// Action or glob, e.g. `Query.invoices` or `Query.*` (repeatable).
        #[arg(long = "action", required = true)]
        actions: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        ttl: i64,
    },
    #[command(subcommand)]
    Totp(TotpCmd),
    #[command(subcommand)]
    Passkey(PasskeyCmd),
    /// Get the hub's TOTP-gated co-signer id for your identity.
    Cosigner,
    /// Decode a JWT (no verification).
    Inspect { token: String },
    #[command(subcommand)]
    Hub(HubCmd),
    /// Policy DAGs: publish a bundle, fetch provable slices, list grants.
    #[command(subcommand)]
    Policy(org::PolicyCmd),
    /// Push a signed revocation for this org.
    #[command(subcommand)]
    Revoke(org::RevokeCmd),
    /// OpenTimestamps: prove a policy root or revocation existed by a Bitcoin block.
    #[command(subcommand)]
    Anchor(org::AnchorCmd),
    /// Follow an org's revocations and report how fresh this view is.
    Revocations {
        #[arg(long)]
        org: Option<String>,
        /// Seconds a view counts as fresh.
        #[arg(long, default_value_t = 120)]
        fresh_for: i64,
        /// Seconds between syncs you can tolerate before everything is denied.
        #[arg(long, default_value_t = 900)]
        max_staleness: i64,
        /// Accept heartbeats without a beacon (trusting the signer's clock).
        #[arg(long)]
        no_beacon: bool,
        /// Keep watching, re-checking every N seconds.
        #[arg(long)]
        watch: Option<u64>,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    List,
    /// Enroll a new device. Writes a file to import on that device, or, with
    /// `--key`, enrolls an external key (a browser passkey) in two steps.
    Add {
        #[arg(long)]
        name: String,
        /// External device key (did:key). Prints the event message the device must sign;
        /// finish with `kith device complete --sig '<Sig JSON>'`.
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        device_id: Option<String>,
        /// software | passkey (simulated WebAuthn authenticator)
        #[arg(long, default_value = "software")]
        kind: String,
        /// Defaults: software 1, passkey 2, hardware 3.
        #[arg(long)]
        aal: Option<u8>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Finish enrolling an external device with its proof-of-possession signature.
    Complete {
        #[arg(long)]
        sig: String,
    },
    /// Use an exported device on this machine.
    Import { file: PathBuf },
    Revoke { id: String },
}

#[derive(Subcommand)]
enum AliasCmd {
    List,
    /// Create a private alias and commit to it in the KEL.
    New { label: String },
    /// Prove a private alias is yours.
    Prove {
        label: String,
        #[arg(long)]
        aud: Option<String>,
        #[arg(long)]
        nonce: Option<String>,
    },
    /// Verify someone's alias proof (file) against their KEL on the hub.
    Verify {
        file: PathBuf,
        #[arg(long)]
        aud: Option<String>,
    },
    /// Publicly link an alias (mailto:, https:, did:web:, eip155:…).
    Link { alias: String },
}

#[derive(Subcommand)]
enum TotpCmd {
    /// Enroll TOTP at the hub; prints the otpauth URI for your authenticator app.
    Enroll,
    Confirm { code: String },
    /// Compute the current code for a base32 secret (acts as an authenticator app).
    Code { secret: String },
}

#[derive(Subcommand)]
enum PasskeyCmd {
    /// Create a passkey in your browser (on the hub's origin) and add it as a device.
    /// It can then sign in to any app that uses the hub for OpenID Connect.
    Enroll {
        #[arg(long, default_value = "passkey")]
        name: String,
        /// Don't try to open the browser; just print the link.
        #[arg(long)]
        no_open: bool,
    },
}

#[derive(Subcommand)]
enum HubCmd {
    Serve {
        #[arg(long, default_value = "127.0.0.1:7777")]
        addr: String,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long, default_value = ".kith-hub")]
        data: PathBuf,
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// WebAuthn relying party id (default: the issuer's host).
        #[arg(long)]
        rp_id: Option<String>,
        #[arg(long = "origin")]
        origins: Vec<String>,
        /// JSON file with an array of OpenID Connect clients.
        #[arg(long)]
        clients: Option<PathBuf>,
        /// Take groups and roles from this org's policy DAG instead of --bundle.
        #[arg(long)]
        policy_org: Option<String>,
        /// Beacon for heartbeats: drand, nist or none.
        #[arg(long, default_value = "drand")]
        beacon: String,
        /// Seconds between heartbeats.
        #[arg(long, default_value_t = 15)]
        heartbeat: u64,
    },
}

// ------------------------------------------------------------------ state

struct Home {
    dir: PathBuf,
    v: Value,
}

impl Home {
    fn load(dir: PathBuf) -> Result<Self> {
        let p = dir.join("identity.json");
        let v = if p.exists() { serde_json::from_str(&std::fs::read_to_string(&p)?)? } else { json!({}) };
        Ok(Home { dir, v })
    }

    fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let p = self.dir.join("identity.json");
        std::fs::write(&p, serde_json::to_vec_pretty(&self.v)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn did(&self) -> Result<String> {
        self.v["did"].as_str().map(String::from).ok_or_else(|| anyhow!("no identity here; run `kith init`"))
    }

    fn hub(&self) -> Result<String> {
        self.v["hub"].as_str().map(|s| s.trim_end_matches('/').to_string()).ok_or_else(|| anyhow!("no hub configured"))
    }

    fn kel(&self) -> Result<Vec<Event>> {
        Ok(serde_json::from_value(self.v["kel"].clone())?)
    }

    fn state(&self) -> Result<KeyState> {
        Ok(verify_log(&self.kel()?, &VerifyOptions::default())?)
    }

    fn signers(&self, key: &str) -> Result<Vec<LocalSigner>> {
        self.v[key].as_array().map(|a| a.iter().map(LocalSigner::from_json).collect::<Result<Vec<_>, _>>()).transpose()?.ok_or_else(|| anyhow!("no {key} keys on this machine"))
    }

    fn device(&self) -> Result<(String, LocalSigner)> {
        let d = &self.v["device"];
        Ok((d["id"].as_str().ok_or_else(|| anyhow!("no device on this machine"))?.into(), LocalSigner::from_json(&d["signer"])?))
    }

    fn append(&mut self, ev: Event) -> Result<KeyState> {
        let mut kel = self.kel()?;
        kel.push(ev);
        let st = verify_log(&kel, &VerifyOptions::default())?;
        self.v["kel"] = serde_json::to_value(&kel)?;
        self.save()?;
        Ok(st)
    }
}

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::new()
}

fn check(resp: reqwest::blocking::Response) -> Result<Value> {
    let status = resp.status();
    let body: Value = resp.json().unwrap_or(json!({}));
    if !status.is_success() {
        bail!("hub returned {status}: {}", body["error_description"].as_str().unwrap_or(&body.to_string()));
    }
    Ok(body)
}

fn publish(home: &Home) -> Result<()> {
    let Ok(hub) = home.hub() else { return Ok(()) };
    let did = home.did()?;
    check(http().put(format!("{hub}/v1/kel/{did}")).json(&home.v["kel"]).send()?)?;
    Ok(())
}

fn fetch_state(hub: &str, did: &str) -> Result<KeyState> {
    let events: Vec<Event> = serde_json::from_value(check(http().get(format!("{hub}/v1/kel/{did}")).send()?)?)?;
    let st = verify_log(&events, &VerifyOptions::default())?;
    if st.did != did {
        bail!("hub returned a log for a different DID");
    }
    Ok(st)
}

fn new_device(name: &str, kind: DeviceKind, aal: u8) -> (Device, LocalSigner, ExchangeKey) {
    let signer = LocalSigner::generate(if kind == DeviceKind::Passkey { KeyType::P256 } else { KeyType::Ed25519 });
    let xkey = ExchangeKey::generate();
    let dev = Device {
        id: format!("dev_{}", &random_id()[..8]),
        key: signer.id.clone(),
        name: name.into(),
        kind,
        aal,
        caps: vec!["session".into(), "alias".into()],
        rp_id: (kind == DeviceKind::Passkey).then(|| "localhost".to_string()),
        xkey: Some(xkey.public_did_key()),
    };
    (dev, signer, xkey)
}

/// Sign as a device: plain signature, or a WebAuthn assertion for passkeys.
fn device_sign(ev: &mut Event, signer: &LocalSigner, kind: DeviceKind) -> Result<()> {
    if kind == DeviceKind::Passkey {
        let msg = ev.signing_message()?;
        ev.add_sig(kith_core::webauthn::soft_sign_message(signer, "localhost", "http://localhost", &msg)?);
    } else {
        ev.sign(signer)?;
    }
    Ok(())
}

fn session(home: &mut Home) -> Result<SessionKey> {
    let did = home.did()?;
    let s = &home.v["session"];
    if s["exp"].as_i64().unwrap_or(0) > now() + 300 {
        let secret = kith_core::keys::SecretKey::from_bytes(KeyType::Ed25519, &b64u_decode(s["secret"].as_str().unwrap_or_default())?)?;
        return Ok(SessionKey { did, secret, grant: s["grant"].as_str().unwrap_or_default().into() });
    }
    let (dev_id, signer) = home.device()?;
    let st = home.state()?;
    let dev = st.device(&dev_id).ok_or_else(|| anyhow!("this device ({dev_id}) is not active in the KEL"))?.clone();
    let ttl = 12 * 3600;
    let sk = match dev.kind {
        DeviceKind::Passkey => SessionKey::create(&did, &dev, DeviceSigner::Passkey { key: &signer.secret, rp_id: "localhost", origin: "http://localhost" }, ttl)?,
        _ => SessionKey::create(&did, &dev, DeviceSigner::Key(&signer.secret), ttl)?,
    };
    home.v["session"] = json!({"secret": b64u(sk.secret.to_bytes()), "grant": sk.grant, "exp": now() + ttl});
    home.save()?;
    Ok(sk)
}

fn store_token(home: &mut Home, aud: &str, resp: &Value) -> Result<String> {
    let tok = resp["access_token"].as_str().ok_or_else(|| anyhow!("no access_token in response"))?.to_string();
    home.v["tokens"][aud] = json!({"access_token": tok, "exp": now() + resp["expires_in"].as_i64().unwrap_or(0)});
    home.save()?;
    Ok(tok)
}

fn login(home: &mut Home, aud: Option<String>, method: &str, totp_code: Option<String>, delegation: Option<String>) -> Result<(String, String)> {
    let hub = home.hub()?;
    let aud = aud.unwrap_or_else(|| hub.clone());
    let resp = if let Some(dtok) = delegation {
        let sk = session(home)?;
        let actor = sk.session_token(&hub, json!({}))?;
        check(http().post(format!("{hub}/v1/oauth/token")).form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", dtok.as_str()),
            ("subject_token_type", kith_hub::TT_DELEGATION),
            ("actor_token", actor.as_str()),
            ("actor_token_type", kith_hub::TT_SESSION),
            ("audience", aud.as_str()),
        ]).send()?)?
    } else if method == "challenge" {
        let did = home.did()?;
        let ch = check(http().post(format!("{hub}/v1/auth/challenge")).json(&json!({"did": did})).send()?)?;
        let msg = ch["message"].as_str().unwrap_or_default();
        let (dev_id, signer) = home.device()?;
        let dev = home.state()?.device(&dev_id).cloned().ok_or_else(|| anyhow!("device not active"))?;
        let mut factors = vec![];
        if dev.kind == DeviceKind::Passkey {
            let (data, sig) = kith_core::webauthn::soft_assert(&signer.secret, "localhost", "http://localhost", &kith_core::util::sha256(msg.as_bytes()), true, 1)?;
            factors.push(json!({"type": "webauthn", "device_id": dev_id, "authenticator_data": data.authenticator_data, "client_data_json": data.client_data_json, "signature": b64u(sig)}));
        } else {
            factors.push(json!({"type": "signature", "sig": signer.sign(msg.as_bytes())?}));
        }
        if let Some(code) = totp_code {
            factors.push(json!({"type": "totp", "code": code}));
        }
        check(http().post(format!("{hub}/v1/auth/verify")).json(&json!({"challenge_id": ch["challenge_id"], "audience": aud, "factors": factors})).send()?)?
    } else {
        let sk = session(home)?;
        let st = sk.session_token(&hub, json!({}))?;
        let mut form = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange".to_string()),
            ("subject_token", st),
            ("subject_token_type", kith_hub::TT_SESSION.to_string()),
            ("audience", aud.clone()),
        ];
        if let Some(code) = totp_code {
            form.push(("totp", code));
        }
        check(http().post(format!("{hub}/v1/oauth/token")).form(&form).send()?)?
    };
    let tok = store_token(home, &aud, &resp)?;
    Ok((aud, tok))
}

fn cached_token(home: &mut Home, aud: Option<String>) -> Result<String> {
    let hub = home.hub()?;
    let aud = aud.unwrap_or(hub);
    let t = &home.v["tokens"][&aud];
    if t["exp"].as_i64().unwrap_or(0) > now() + 30 {
        return Ok(t["access_token"].as_str().unwrap_or_default().into());
    }
    Ok(login(home, Some(aud), "session", None, None)?.1)
}

fn bearer(home: &mut Home) -> Result<String> {
    Ok(format!("Bearer {}", cached_token(home, None)?))
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = cli.home.clone().unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".kith"));

    if let Cmd::Hub(HubCmd::Serve { addr, issuer, data, bundle, rp_id, origins, clients, policy_org, beacon, heartbeat }) = cli.cmd {
        // Browsers only allow passkeys on "localhost", not "127.0.0.1", so default to it.
        let port = addr.rsplit(':').next().unwrap_or("7777");
        let local = ["127.0.0.1", "0.0.0.0", "localhost", "[::1]"].iter().any(|h| addr.starts_with(h));
        let issuer = issuer.unwrap_or_else(|| if local { format!("http://localhost:{port}") } else { format!("http://{addr}") });
        let mut cfg = kith_hub::HubConfig::new(issuer, data);
        cfg.bundle_path = bundle;
        cfg.policy_org = policy_org;
        cfg.beacon = kith_hub::org::BeaconSource::parse(&beacon)?;
        cfg.heartbeat_secs = heartbeat;
        if let Some(rp) = rp_id {
            cfg.rp_id = rp;
        }
        if origins.is_empty() {
            // Soft passkeys created by `kith device add --kind passkey` use this origin.
            cfg.origins.push("http://localhost".into());
        } else {
            cfg.origins = origins;
        }
        if let Some(path) = clients {
            cfg.clients = serde_json::from_str(&std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?)?;
        }
        return tokio::runtime::Runtime::new()?.block_on(kith_hub::serve(cfg, &addr));
    }

    let mut home = Home::load(dir)?;
    match cli.cmd {
        Cmd::Init { hub, device_name, wallet } => {
            if home.v.get("did").is_some() {
                bail!("{} already holds an identity", home.dir.display());
            }
            let root = LocalSigner::generate(KeyType::Ed25519);
            let mut recovery = vec![LocalSigner::generate(KeyType::Ed25519), LocalSigner::generate(KeyType::Ed25519)];
            recovery.push(if wallet { LocalSigner::generate_eth_wallet(1) } else { LocalSigner::generate(KeyType::Ed25519) });
            let rotation = SignerPolicy::threshold(2, recovery.iter().map(|s| SignerPolicy::single(&s.id)).collect());
            // A software key alone is AAL1 (NIST 800-63B); step up with TOTP or a passkey.
            let (dev, dsigner, xkey) = new_device(&device_name, DeviceKind::Software, 1);
            let mut inc = new_inception(SignerPolicy::single(&root.id), &rotation, vec![dev.clone()]);
            inc.sign(&root)?;
            inc.sign(&dsigner)?;
            let st = verify_log(std::slice::from_ref(&inc), &VerifyOptions::default())?;
            home.v = json!({
                "did": st.did,
                "hub": hub,
                "kel": [inc],
                "manage": [root.to_json()],
                "recovery": recovery.iter().map(|s| s.to_json()).collect::<Vec<_>>(),
                "rotation_policy": rotation,
                "device": {"id": dev.id, "signer": dsigner.to_json(), "xkey": b64u(xkey.to_bytes())},
                "aliases": [],
            });
            home.save()?;
            if let Err(e) = publish(&home) {
                eprintln!("warning: could not publish to hub ({e}); run `kith publish` later");
            }
            println!("{}", st.did);
            eprintln!("created identity with device {} ({}) and 2-of-3 recovery keys{}", dev.id, device_name, if wallet { " (one is an Ethereum wallet)" } else { "" });
            eprintln!("warning: this reference CLI stores keys in plaintext at {}", home.dir.join("identity.json").display());
        }
        Cmd::Status => {
            let st = home.state()?;
            print(&json!({
                "did": st.did, "hub": home.v["hub"], "seq": st.seq,
                "this_device": home.v["device"]["id"],
                "devices": st.devices.values().map(|d| json!({"id": d.id, "name": d.name, "kind": d.kind, "aal": d.aal})).collect::<Vec<_>>(),
                "revoked": st.revoked, "public_aliases": st.aliases,
                "private_aliases": home.v["aliases"].as_array().map(|a| a.iter().map(|x| x["label"].clone()).collect::<Vec<_>>()),
                "manage": st.manage,
            }));
        }
        Cmd::Kel => print(&home.v["kel"]),
        Cmd::DidDoc => print(&home.state()?.did_document(home.v["hub"].as_str())),
        Cmd::Publish => {
            publish(&home)?;
            eprintln!("published");
        }
        Cmd::Device(DeviceCmd::List) => print(&json!(home.state()?.devices)),
        Cmd::Device(DeviceCmd::Add { name, key: Some(key), device_id, kind, aal, .. }) => {
            let kind = if kind == "passkey" { DeviceKind::Passkey } else { DeviceKind::Hardware };
            let st = home.state()?;
            let dev = Device {
                id: device_id.unwrap_or_else(|| format!("dev_{}", &random_id()[..8])),
                key,
                name,
                kind,
                aal: aal.unwrap_or(2),
                caps: vec!["session".into()],
                rp_id: (kind == DeviceKind::Passkey).then(|| "localhost".to_string()),
                xkey: None,
            };
            let mut ev = next_event(&st, EventBody::AddDevice { device: dev.clone() });
            for m in home.signers("manage")? {
                ev.sign(&m)?;
            }
            let msg = String::from_utf8(ev.signing_message()?)?;
            home.v["pending"] = serde_json::to_value(&ev)?;
            home.save()?;
            print(&json!({"device_id": dev.id, "signer": dev.key, "message": msg}));
        }
        Cmd::Device(DeviceCmd::Complete { sig }) => {
            let mut ev: Event = serde_json::from_value(home.v["pending"].take()).context("no pending device enrollment")?;
            ev.add_sig(serde_json::from_str(&sig)?);
            home.append(ev)?;
            home.v.as_object_mut().unwrap().remove("pending");
            home.save()?;
            publish(&home)?;
            eprintln!("device enrolled");
        }
        Cmd::Device(DeviceCmd::Add { name, kind, aal, out, .. }) => {
            let out = out.ok_or_else(|| anyhow!("--out is required when kith generates the device key"))?;
            let kind = match kind.as_str() {
                "software" => DeviceKind::Software,
                "passkey" => DeviceKind::Passkey,
                "hardware" => DeviceKind::Hardware,
                other => bail!("unknown device kind {other}"),
            };
            let aal = aal.unwrap_or(match kind {
                DeviceKind::Software | DeviceKind::Wallet => 1,
                DeviceKind::Passkey => 2,
                DeviceKind::Hardware => 3,
            });
            let st = home.state()?;
            let (dev, signer, xkey) = new_device(&name, kind, aal);
            let mut ev = next_event(&st, EventBody::AddDevice { device: dev.clone() });
            for m in home.signers("manage")? {
                ev.sign(&m)?;
            }
            device_sign(&mut ev, &signer, kind)?;
            home.append(ev)?;
            publish(&home)?;
            let export = json!({"did": st.did, "hub": home.v["hub"], "kel": home.v["kel"], "device": {"id": dev.id, "signer": signer.to_json(), "xkey": b64u(xkey.to_bytes())}});
            std::fs::write(&out, serde_json::to_vec_pretty(&export)?)?;
            println!("{}", dev.id);
            eprintln!("added {} device {}; import it elsewhere with `kith device import {}`", kind_str(kind), dev.id, out.display());
        }
        Cmd::Device(DeviceCmd::Import { file }) => {
            if home.v.get("did").is_some() {
                bail!("{} already holds an identity", home.dir.display());
            }
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&file)?)?;
            home.v = json!({"did": v["did"], "hub": v["hub"], "kel": v["kel"], "device": v["device"], "aliases": []});
            home.state()?;
            home.save()?;
            eprintln!("imported device {} for {}", v["device"]["id"].as_str().unwrap_or("?"), v["did"].as_str().unwrap_or("?"));
        }
        Cmd::Device(DeviceCmd::Revoke { id }) => {
            let st = home.state()?;
            let mut ev = next_event(&st, EventBody::RevokeDevice { device_id: id.clone(), reason: None });
            for m in home.signers("manage")? {
                ev.sign(&m)?;
            }
            home.append(ev)?;
            publish(&home)?;
            eprintln!("revoked {id}");
        }
        Cmd::Rotate { revoke_devices, add_cosigner, totp } => {
            let st = home.state()?;
            let rotation: SignerPolicy = serde_json::from_value(home.v["rotation_policy"].clone()).context("no rotation policy stored here")?;
            let new_root = LocalSigner::generate(KeyType::Ed25519);
            let mut new_recovery = vec![LocalSigner::generate(KeyType::Ed25519), LocalSigner::generate(KeyType::Ed25519)];
            let mut next_ids: Vec<String> = new_recovery.iter().map(|s| s.id.clone()).collect();
            if add_cosigner {
                let hub = home.hub()?;
                let auth = bearer(&mut home)?;
                let c = check(http().post(format!("{hub}/v1/cosigner")).header("authorization", auth).send()?)?;
                next_ids.push(c["signer"].as_str().unwrap_or_default().into());
            } else {
                new_recovery.push(LocalSigner::generate(KeyType::Ed25519));
                next_ids.push(new_recovery[2].id.clone());
            }
            let next = SignerPolicy::threshold(2, next_ids.into_iter().map(SignerPolicy::Signer).collect());
            let mut ev = next_event(&st, EventBody::Rotate { rotation: rotation.clone(), manage: SignerPolicy::single(&new_root.id), next: next.digest(), revoke_devices });
            // Sign with local recovery keys that the rotation policy names…
            let local = home.signers("recovery")?;
            let names = rotation.signers();
            for s in local.iter().filter(|s| names.contains(&s.id)) {
                ev.sign(s)?;
                let signed: std::collections::BTreeSet<String> = ev.sigs.iter().map(|s| s.signer.clone()).collect();
                if rotation.is_satisfied_by(&signed) {
                    break;
                }
            }
            // …and, if needed, ask the hub co-signer (gated by TOTP).
            let signed: std::collections::BTreeSet<String> = ev.sigs.iter().map(|s| s.signer.clone()).collect();
            if !rotation.is_satisfied_by(&signed) {
                let code = totp.ok_or_else(|| anyhow!("recovery keys alone don't satisfy the rotation policy; pass --totp for the hub co-signer"))?;
                let hub = home.hub()?;
                let sig = check(http().post(format!("{hub}/v1/cosign")).json(&json!({"did": st.did, "code": code, "event": ev})).send()?)?;
                ev.add_sig(serde_json::from_value(sig)?);
            }
            let st = home.append(ev)?;
            home.v["manage"] = json!([new_root.to_json()]);
            home.v["recovery"] = json!(new_recovery.iter().map(|s| s.to_json()).collect::<Vec<_>>());
            home.v["rotation_policy"] = serde_json::to_value(&next)?;
            if revoke_devices {
                home.v["session"] = json!(null);
                home.v["tokens"] = json!({});
            }
            home.save()?;
            publish(&home)?;
            eprintln!("rotated to seq {}; new manage key {}{}", st.seq, new_root.id, if add_cosigner { "; hub co-signer is now a recovery signer" } else { "" });
        }
        Cmd::Alias(AliasCmd::List) => print(&json!(home.v["aliases"].as_array().map(|a| a.iter().map(|x| json!({"label": x["label"], "alias": x["signer"]["id"], "seq": x["seq"]})).collect::<Vec<_>>()))),
        Cmd::Alias(AliasCmd::New { label }) => {
            // `prove` finds an alias by label, so a second one would never be reachable.
            // Refuse before anything is committed to the KEL.
            if home.v["aliases"].as_array().is_some_and(|a| a.iter().any(|x| x["label"] == label.as_str())) {
                bail!("you already have a private alias labelled {label:?}; labels are how `kith alias prove` finds one, so pick another");
            }
            let st = home.state()?;
            let alias = PrivateAlias::generate(&label);
            let mut ev = next_event(&st, EventBody::AliasCommit { commitment: alias.commitment(&st.did) });
            let (_, dsigner) = home.device()?;
            ev.sign(&dsigner)?;
            let st = home.append(ev)?;
            home.v["aliases"].as_array_mut().ok_or_else(|| anyhow!("bad state"))?.push(json!({"label": label, "signer": alias.signer.to_json(), "salt": alias.salt, "seq": st.seq}));
            home.save()?;
            publish(&home)?;
            println!("{}", alias.id());
        }
        Cmd::Alias(AliasCmd::Prove { label, aud, nonce }) => {
            let did = home.did()?;
            let a = home.v["aliases"].as_array().and_then(|a| a.iter().find(|x| x["label"] == label.as_str())).ok_or_else(|| anyhow!("no alias {label}"))?;
            let alias = PrivateAlias { label: label.clone(), signer: LocalSigner::from_json(&a["signer"])?, salt: a["salt"].as_str().unwrap_or_default().into() };
            print(&serde_json::to_value(alias.prove(&did, a["seq"].as_u64().unwrap_or(0), aud, nonce)?)?);
        }
        Cmd::Alias(AliasCmd::Verify { file, aud }) => {
            let proof: AliasProof = serde_json::from_str(&std::fs::read_to_string(file)?)?;
            let st = fetch_state(&home.hub()?, &proof.root)?;
            verify_alias_proof(&proof, &st, aud.as_deref(), None)?;
            println!("valid: {} is an alias of {}", proof.alias, proof.root);
        }
        Cmd::Alias(AliasCmd::Link { alias }) => {
            let st = home.state()?;
            let mut ev = next_event(&st, EventBody::AliasLink { alias: alias.clone() });
            for m in home.signers("manage")? {
                ev.sign(&m)?;
            }
            home.append(ev)?;
            publish(&home)?;
            eprintln!("linked {alias} (add a back-link on the alias side so others can check both directions)");
        }
        Cmd::Name(cmd) => names::run(&home, cmd)?,
        Cmd::Resolve { alias } => print(&names::resolve(&home, &alias)?.json()),
        Cmd::Login { aud, method, totp, delegation, print: show } => {
            let (aud, tok) = login(&mut home, aud, &method, totp, delegation)?;
            let c = jws::decode(&tok)?.claims;
            eprintln!("logged in as {} for {aud} (aal {}, amr {}, groups {}, roles {})", c["sub"].as_str().unwrap_or("?"), c["aal"], c["amr"], c["groups"], c["roles"]);
            if show {
                println!("{tok}");
            }
        }
        Cmd::Token { aud } => println!("{}", cached_token(&mut home, aud)?),
        Cmd::Whoami { aud } => {
            let tok = cached_token(&mut home, aud)?;
            print(&jws::decode(&tok)?.claims);
        }
        Cmd::Delegate { to, actions, ttl } => {
            let to = names::principal(&home, &to)?;
            let hub = home.hub()?;
            let sk = session(&mut home)?;
            println!("{}", sk.delegate(&to, &hub, actions.into_iter().map(Capability::new).collect(), ttl)?);
        }
        Cmd::Totp(TotpCmd::Enroll) => {
            let hub = home.hub()?;
            let auth = bearer(&mut home)?;
            print(&check(http().post(format!("{hub}/v1/totp/enroll")).header("authorization", auth).send()?)?);
        }
        Cmd::Totp(TotpCmd::Confirm { code }) => {
            let hub = home.hub()?;
            let auth = bearer(&mut home)?;
            print(&check(http().post(format!("{hub}/v1/totp/confirm")).header("authorization", auth).json(&json!({"code": code})).send()?)?);
        }
        Cmd::Passkey(PasskeyCmd::Enroll { name, no_open }) => {
            let hub = home.hub()?;
            let auth = bearer(&mut home)?;
            let e = check(http().post(format!("{hub}/v1/enroll")).header("authorization", &auth).json(&json!({"name": name})).send()?)?;
            let id = e["id"].as_str().unwrap_or_default().to_string();
            let url = e["url"].as_str().unwrap_or_default().to_string();
            println!("{url}");
            eprintln!("open {url} in a browser to create the passkey (link valid for 10 minutes)");
            if !no_open {
                let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
                let _ = std::process::Command::new(opener).arg(&url).status();
            }
            let poll = |want: &str| -> Result<Value> {
                let deadline = now() + 600;
                loop {
                    let s = check(http().get(format!("{hub}/v1/enroll/{id}")).send()?)?;
                    if !s[want].is_null() {
                        return Ok(s);
                    }
                    if now() > deadline {
                        bail!("timed out waiting for the browser");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(400));
                }
            };
            let s = poll("key")?;
            let key = s["key"].as_str().unwrap_or_default().to_string();
            eprintln!("browser created passkey {key}; approving with your manage key");
            let st = home.state()?;
            let dev = Device {
                id: format!("dev_{}", &random_id()[..8]),
                key,
                name: name.clone(),
                kind: DeviceKind::Passkey,
                aal: 2,
                caps: vec!["session".into()],
                rp_id: e["rp_id"].as_str().map(String::from),
                xkey: None,
            };
            let mut ev = next_event(&st, EventBody::AddDevice { device: dev.clone() });
            for m in home.signers("manage")? {
                ev.sign(&m)?;
            }
            let message = String::from_utf8(ev.signing_message()?)?;
            check(http().post(format!("{hub}/v1/enroll/{id}/event")).header("authorization", &auth).json(&json!({"device_id": dev.id, "message": message})).send()?)?;
            let s = poll("sig")?;
            ev.add_sig(serde_json::from_value(s["sig"].clone())?);
            home.append(ev)?;
            publish(&home)?;
            eprintln!("enrolled passkey as device {} ({name})", dev.id);
        }
        Cmd::Totp(TotpCmd::Code { secret }) => println!("{}", totp::code_at(&totp::from_base32(&secret)?, now())),
        Cmd::Cosigner => {
            let hub = home.hub()?;
            let auth = bearer(&mut home)?;
            print(&check(http().post(format!("{hub}/v1/cosigner")).header("authorization", auth).send()?)?);
        }
        Cmd::Inspect { token } => {
            let t = jws::decode(&token)?;
            let mut header = t.header.clone();
            if let Some(g) = header.get("kith_grant").and_then(Value::as_str) {
                header["kith_grant"] = jws::decode(g)?.claims;
            }
            print(&json!({"header": header, "claims": t.claims}));
        }
        Cmd::Hub(_) => unreachable!(),
        Cmd::Policy(cmd) => org::policy(&mut home, cmd)?,
        Cmd::Revoke(cmd) => org::revoke(&mut home, cmd)?,
        Cmd::Anchor(cmd) => org::anchor(&home, cmd)?,
        Cmd::Revocations { org, fresh_for, max_staleness, no_beacon, watch } => {
            org::status(&home, org, kith_core::revoke::FreshnessPolicy { fresh_for, max_staleness, require_beacon: !no_beacon }, watch)?
        }
    }
    Ok(())
}

fn kind_str(k: DeviceKind) -> &'static str {
    match k {
        DeviceKind::Software => "software",
        DeviceKind::Passkey => "passkey",
        DeviceKind::Hardware => "hardware",
        DeviceKind::Wallet => "wallet",
    }
}
