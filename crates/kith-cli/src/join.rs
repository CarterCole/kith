//! Joining this machine to an identity, approving a device that is joining, and changing
//! who approves (spec §7.13).
//!
//! The hub holds each join request and assembles its signatures; this side makes the
//! device key, checks the event the hub built before signing it, and keeps the log.

use std::io::IsTerminal;

use kith_core::kel::extends;
use kith_core::keys::PublicKey;
use kith_core::recovery;
use kith_core::util::key_fingerprint;

use super::*;

pub(super) struct JoinOpts {
    pub hub: String,
    pub did: Option<String>,
    pub name: Option<String>,
    pub keystore: Option<String>,
    pub no_secure_enclave: bool,
    pub touch_id: bool,
    pub no_open: bool,
    pub yes: bool,
}

pub(super) struct ManageSet {
    pub threshold: usize,
    pub signers: Vec<String>,
    pub recovery_key: Option<PathBuf>,
    pub recovery_words: bool,
    pub next: Option<String>,
    pub next_out: Option<PathBuf>,
    pub yes: bool,
}

/// How long a request lives on the hub (spec §7.13).
const JOIN_TTL: i64 = 900;

fn open_in_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener).arg(url).status();
}

/// The link, and a QR code of it for a phone, on stderr.
fn show_link(url: &str) {
    eprintln!("\n  {url}\n");
    if let Some(q) = kith_hub::qr::text(url) {
        if std::io::stderr().is_terminal() {
            eprint!("{}", kith_hub::qr::terminal_colors(&q));
        } else {
            eprint!("{q}");
        }
        eprintln!();
    }
}

/// Poll a join request until `done` says to stop.
fn poll(hub: &str, id: &str, done: impl Fn(&Value) -> bool) -> Result<Value> {
    let deadline = now() + JOIN_TTL;
    loop {
        let r = http().get(format!("{hub}/v1/join/{id}")).send()?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            bail!("the join request expired; start again");
        }
        let s = check(r)?;
        if done(&s) || s["state"] == "failed" {
            return Ok(s);
        }
        if now() > deadline {
            bail!("timed out waiting for the browser");
        }
        std::thread::sleep(std::time::Duration::from_millis(700));
    }
}

fn failed(s: &Value) -> Result<()> {
    if s["state"] == "failed" {
        bail!(
            "the hub couldn't add the device: {}",
            s["error"].as_str().unwrap_or("unknown error")
        );
    }
    Ok(())
}

fn fetch_kel(hub: &str, did: &str) -> Result<Vec<Event>> {
    let events: Vec<Event> =
        serde_json::from_value(check(http().get(format!("{hub}/v1/kel/{did}")).send()?)?)?;
    let st = verify_log(&events, &VerifyOptions::default())?;
    if st.did != did {
        bail!("hub returned a log for a different DID");
    }
    Ok(events)
}

/// Bring this home's log up to the hub's, which must extend it, and save it.
fn sync_kel(home: &mut Home) -> Result<KeyState> {
    let Ok(hub) = home.hub() else {
        return home.state();
    };
    let remote = fetch_kel(&hub, &home.did()?)?;
    let local = home.kel()?;
    if !extends(&local, &remote)? {
        bail!("the hub's log for this identity does not extend the one here; refusing to go on");
    }
    home.v["kel"] = serde_json::to_value(&remote)?;
    home.save()?;
    Ok(verify_log(&remote, &VerifyOptions::default())?)
}

/// The event the hub built must be the next one on `st`'s log, unsigned, and add a
/// device with exactly this key.
fn check_event(ev: &Event, st: &KeyState, key: &str) -> Result<Device> {
    if ev.did.as_deref() != Some(st.did.as_str())
        || ev.seq != st.seq + 1
        || ev.prev.as_deref() != Some(st.digest.as_str())
        || !ev.sigs.is_empty()
    {
        bail!("the hub's event is not the next one on {}'s log", st.did);
    }
    let EventBody::AddDevice { device } = &ev.body else {
        bail!("the hub's event does not add a device");
    };
    if device.key != key {
        bail!("the hub's event adds a different key");
    }
    Ok(device.clone())
}

fn message_of(ev: &Event, s: &Value) -> Result<Vec<u8>> {
    let message = ev.signing_message()?;
    if s["message"].as_str().map(str::as_bytes) != Some(&message[..]) {
        bail!("the hub's message does not match its event");
    }
    Ok(message)
}

/// `kith device join`: make this machine's key, have a browser claim and approve it,
/// prove possession, and keep the log as a device-only home.
pub(super) fn join(home: &mut Home, o: JoinOpts) -> Result<()> {
    if let Some(did) = home.v.get("did") {
        bail!(
            "{} already holds an identity ({}); join from another home with --home or KITH_HOME",
            home.dir.display(),
            did.as_str().unwrap_or("?")
        );
    }
    let hub = o.hub.trim_end_matches('/').to_string();
    let backend = o
        .keystore
        .as_deref()
        .map(Backend::parse)
        .transpose()?
        .unwrap_or_else(Backend::platform_default)
        .resolve();
    let dkey = new_device_key(backend, o.no_secure_enclave, o.touch_id);
    let xkey = ExchangeKey::generate();
    let (kind, aal) = if dkey.is_hardware() {
        (DeviceKind::Hardware, if o.touch_id { 3 } else { 1 })
    } else {
        (DeviceKind::Software, 1)
    };
    let name = o.name.unwrap_or_else(|| {
        if cfg!(target_os = "macos") {
            "mac".into()
        } else {
            "computer".into()
        }
    });
    let r = check(
        http()
            .post(format!("{hub}/v1/join"))
            .json(&json!({"device": {"key": dkey.id(), "xkey": xkey.public_did_key(), "name": name, "kind": kind, "aal": aal}}))
            .send()?,
    )?;
    let id = r["id"]
        .as_str()
        .ok_or_else(|| anyhow!("the hub returned no join request"))?
        .to_string();
    let url = r["url"].as_str().unwrap_or_default().to_string();

    eprintln!(
        "Open this link in a browser signed in to your identity, or scan it with your phone:"
    );
    show_link(&url);
    eprintln!(
        "This device's code is {}. The page shows the same code.",
        key_fingerprint(dkey.id())
    );
    if !o.no_open {
        open_in_browser(&url);
    }
    eprintln!("Waiting for a browser to add it (the link works for 15 minutes)…");

    let s = poll(&hub, &id, |s| s["state"] != "waiting_for_identity")?;
    failed(&s)?;
    let did = s["did"]
        .as_str()
        .ok_or_else(|| anyhow!("the hub did not say which identity claimed this device"))?
        .to_string();
    if let Some(want) = &o.did {
        if *want != did {
            bail!("{did} claimed this device, not {want}; nothing was signed");
        }
    }
    // Look before signing: the event must be the next one on that identity's log, as the
    // hub publishes it, and add exactly this device.
    let st = fetch_state(&hub, &did)?;
    let ev: Event = serde_json::from_value(s["event"].clone())?;
    let dev = check_event(&ev, &st, dkey.id())?;
    let caps: Vec<String> = vec!["session".into(), "alias".into()];
    if dev.xkey.as_deref() != Some(xkey.public_did_key().as_str())
        || dev.name != name
        || dev.kind != kind
        || dev.aal != aal
        || dev.caps != caps
        || dev.rp_id.is_some()
    {
        bail!(
            "the hub's event describes this device differently than it asked; nothing was signed"
        );
    }
    let message = message_of(&ev, &s)?;
    eprintln!(
        "{did} claimed this device. It has {} device{} now.",
        st.devices.len(),
        if st.devices.len() == 1 { "" } else { "s" }
    );
    if !confirm(
        &format!("Join {did} as \"{name}\"?"),
        o.yes,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr(),
    )? {
        bail!("not joined; nothing was signed (pass --yes to skip the question)");
    }
    let sig = dkey.sign(&message)?;
    check(
        http()
            .post(format!("{hub}/v1/join/{id}/pop"))
            .json(&json!({"sig": sig}))
            .send()?,
    )?;
    eprintln!("Signed. Waiting for approval in the browser…");
    let s = poll(&hub, &id, |s| s["state"] == "done")?;
    failed(&s)?;

    let kel = fetch_kel(&hub, &did)?;
    let st = verify_log(&kel, &VerifyOptions::default())?;
    if st.device(&dev.id).map(|d| d.key.as_str()) != Some(dkey.id()) {
        bail!("the hub says the device was added, but its log does not have it");
    }
    home.v = json!({"did": did, "hub": hub, "keystore": backend.name(), "kel": kel, "aliases": []});
    home.v["device"] = home.device_json(&dev.id, &dkey, Some(&xkey.to_bytes()))?;
    home.save()?;
    println!("{did}");
    eprintln!(
        "Joined as device {} ({name}, {} key, aal {aal}). `kith login` signs in with it.",
        dev.id,
        kind_str(kind)
    );
    Ok(())
}

/// `kith device approve`: add this device's approval to a request, when its key is one
/// of the identity's manage signers.
pub(super) fn approve(home: &mut Home, request: &str, yes: bool) -> Result<()> {
    let hub = home.hub()?;
    let did = home.did()?;
    let request = request.trim().trim_end_matches('/');
    if request.contains("://") && !request.starts_with(&format!("{hub}/join/")) {
        bail!("that link is not on this identity's hub ({hub})");
    }
    let id = request.rsplit('/').next().unwrap_or(request);
    let s = check(http().get(format!("{hub}/v1/join/{id}")).send()?)?;
    failed(&s)?;
    match s["state"].as_str() {
        Some("waiting_for_approval") => {}
        Some("done") => bail!("that device has already been added"),
        Some(other) => bail!("the request is not ready to approve ({other})"),
        None => bail!("the hub returned no state"),
    }
    if s["did"] != json!(did) {
        bail!(
            "that request is for {}, not this identity",
            s["did"].as_str().unwrap_or("another identity")
        );
    }
    let st = sync_kel(home)?;
    let (dev_id, dkey) = home.device()?;
    if st
        .device(&dev_id)
        .is_some_and(|d| d.kind == DeviceKind::Passkey)
    {
        bail!("this device is a passkey; approve in the browser instead");
    }
    if !st.manage.signers().contains(dkey.id()) {
        bail!("this device ({dev_id}) does not manage {did}, so it can't approve devices; `kith manage show` lists who does");
    }
    let ev: Event = serde_json::from_value(s["event"].clone())?;
    let key = s["device"]["key"].as_str().unwrap_or_default();
    let dev = check_event(&ev, &st, key)?;
    let message = message_of(&ev, &s)?;
    eprintln!(
        "{} ({}, aal {}) wants to join {did}. Its code is {}; check that the new device shows the same.",
        dev.name,
        kind_str(dev.kind),
        dev.aal,
        key_fingerprint(&dev.key)
    );
    if !confirm(
        "Approve it?",
        yes,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr(),
    )? {
        bail!("not approved (pass --yes to skip the question)");
    }
    let r = check(
        http()
            .post(format!("{hub}/v1/join/{id}/approve"))
            .json(&json!({"sig": dkey.sign(&message)?}))
            .send()?,
    )?;
    failed(&r)?;
    if r["state"] == "done" {
        sync_kel(home)?;
        eprintln!("Approved. {} is now a device of {did}.", dev.name);
    } else if r["approved"] == true {
        eprintln!("Approved. Waiting for the new device to confirm.");
    } else {
        eprintln!("Approved. It needs more approvals from other manage signers.");
    }
    Ok(())
}

/// The manage policy with device names where its signers are devices.
fn describe(p: &SignerPolicy, st: &KeyState) -> String {
    match p {
        SignerPolicy::Signer(id) => st
            .devices
            .values()
            .find(|d| d.key == *id)
            .map(|d| d.name.clone())
            .unwrap_or_else(|| id.clone()),
        SignerPolicy::Threshold { threshold, of } => format!(
            "{threshold} of [{}]",
            of.iter()
                .map(|q| describe(q, st))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub(super) fn manage_show(home: &mut Home) -> Result<()> {
    let st = sync_kel(home)?;
    let mine = home.device().ok().map(|(_, k)| k.id().to_string());
    let signers: Vec<Value> = st
        .manage
        .signers()
        .into_iter()
        .map(|id| {
            let dev = st.devices.values().find(|d| d.key == id);
            json!({"signer": id, "device": dev.map(|d| &d.id), "name": dev.map(|d| &d.name), "this_device": mine.as_deref() == Some(id.as_str())})
        })
        .collect();
    print(
        &json!({"did": st.did, "manage": describe(&st.manage, &st), "policy": st.manage, "signers": signers}),
    );
    Ok(())
}

/// A date as RFC 3339, for the recovery key file.
fn rfc3339(ts: i64) -> String {
    // Days to civil date (Howard Hinnant's algorithm).
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn write_private(path: &std::path::Path, v: &Value) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;
    f.sync_all()?;
    Ok(())
}

/// `kith manage set`: a `rotate` signed with the recovery key that replaces the manage
/// policy and commits a new recovery key.
pub(super) fn manage_set(home: &mut Home, o: ManageSet) -> Result<()> {
    let did = home.did()?;
    let st = sync_kel(home)?;

    let mut ids: Vec<String> = vec![];
    for s in &o.signers {
        let id = if s.starts_with("did:key:") {
            PublicKey::from_did_key(s).with_context(|| format!("{s} is not a valid did:key"))?;
            s.clone()
        } else {
            let found: Vec<&Device> = st
                .devices
                .values()
                .filter(|d| d.id == *s || d.name == *s)
                .collect();
            match found[..] {
                [d] => d.key.clone(),
                [] => bail!("{did} has no device called {s}; `kith device list` shows them"),
                _ => bail!("more than one device is called {s}; use its device id"),
            }
        };
        if ids.contains(&id) {
            bail!("{s} is listed twice");
        }
        ids.push(id);
    }
    if o.threshold == 0 || o.threshold > ids.len() {
        bail!("the threshold must be from 1 to {}", ids.len());
    }
    let manage = if ids.len() == 1 {
        SignerPolicy::single(&ids[0])
    } else {
        SignerPolicy::threshold(o.threshold, ids.iter().map(SignerPolicy::single).collect())
    };
    manage.validate()?;

    let recovery = match (&o.recovery_key, o.recovery_words) {
        (Some(path), _) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("could not read {}", path.display()))?;
            recovery::from_file(&serde_json::from_str(&text)?)?
        }
        (None, true) => {
            if std::io::stdin().is_terminal() {
                eprint!("Recovery phrase: ");
            }
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            eprintln!("Deriving the key (a few seconds)…");
            recovery::from_words(&line)?
        }
        (None, false) => bail!("pass --recovery-key FILE, or --recovery-words to type the phrase"),
    };
    let rotation = SignerPolicy::single(&recovery.id);
    if rotation.digest() != st.next {
        bail!("that is not the recovery key {did} committed to, so it can't change who manages it");
    }

    let (next, new_key) = match &o.next {
        Some(k) => {
            PublicKey::from_did_key(k).with_context(|| format!("{k} is not a valid did:key"))?;
            if *k == recovery.id {
                bail!("the next recovery key must be a new one: this rotation reveals the current one");
            }
            (k.clone(), None)
        }
        None => {
            let path = o
                .next_out
                .clone()
                .unwrap_or_else(|| PathBuf::from(format!("kith-recovery-key-{}.json", st.seq + 1)));
            if path.exists() {
                bail!(
                    "{} already exists; choose another --next-out",
                    path.display()
                );
            }
            let k = LocalSigner::generate(KeyType::P256);
            (k.id.clone(), Some((path, k)))
        }
    };

    let mut ev = next_event(
        &st,
        EventBody::Rotate {
            rotation,
            manage: manage.clone(),
            next: SignerPolicy::single(&next).digest(),
            revoke_devices: false,
        },
    );
    ev.sign(&recovery)?;
    let mut kel = home.kel()?;
    kel.push(ev.clone());
    let after = verify_log(&kel, &VerifyOptions::default())?;

    eprintln!("{did}");
    eprintln!("  approves changes now: {}", describe(&st.manage, &st));
    eprintln!(
        "  will approve them:    {}",
        describe(&after.manage, &after)
    );
    match &new_key {
        Some((path, _)) => eprintln!("  new recovery key:     saved to {}", path.display()),
        None => eprintln!("  new recovery key:     {next}"),
    }
    eprintln!("Each device still signs in on its own. The current recovery key stops working.");
    if !confirm(
        "Sign this with the recovery key?",
        o.yes,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr(),
    )? {
        bail!("nothing was changed (pass --yes to skip the question)");
    }
    // The new key is saved before the rotation goes anywhere: once the rotation is
    // published, it is the only key that can rotate again.
    if let Some((path, k)) = &new_key {
        let hub = home.hub().ok();
        write_private(
            path,
            &recovery::to_file(k, hub.as_deref(), &rfc3339(now()))?,
        )?;
    }
    home.append(ev)?;
    publish(home)?;
    eprintln!(
        "Done: {} now approves changes to {did}.",
        describe(&after.manage, &after)
    );
    if let Some((path, _)) = new_key {
        eprintln!(
            "Keep {} offline, like the old one; the old recovery key can be deleted.",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_793_754_113), "2026-11-04T01:01:53Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}
