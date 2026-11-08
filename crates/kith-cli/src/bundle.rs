//! `kith bundle`: check a policy bundle file before it is deployed, and edit one in the
//! browser.
//!
//! The editor is for a bundle kept in git, nhost-console style: it runs on this
//! machine, writes the file in your checkout, and you review the diff, commit and
//! deploy. The running hub never takes writes. It listens on loopback only, and every
//! API call must carry the random token in the address it prints, so other pages open
//! in the same browser cannot read or change the file.

// Handlers return the refusal itself as the error; boxing it buys nothing here.
#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use clap::Subcommand;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use kith_core::authz::{Engine, Memberships};
use kith_core::bundle::{check, Report};
use kith_core::util::{b64u, random_id, sha256};

const PAGE: &str = include_str!("bundle_editor.html");

#[derive(Subcommand)]
pub enum BundleCmd {
    /// Check a bundle file. Errors stop a deploy (exit status 1); warnings are printed.
    Check {
        file: PathBuf,
        /// Fail on warnings too.
        #[arg(long)]
        strict: bool,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Edit a bundle file in your browser. It runs on this machine and writes the file;
    /// you commit and deploy it.
    Edit {
        file: PathBuf,
        /// Loopback address to listen on.
        #[arg(long, default_value = "127.0.0.1:7801")]
        addr: String,
        /// People to choose from: the JSON the hub's `GET /v1/admin/identities` returns.
        #[arg(long)]
        people: Option<PathBuf>,
        /// Or fetch them from this hub, with --admin-token.
        #[arg(long)]
        hub: Option<String>,
        #[arg(long, env = "KITH_ADMIN_TOKEN", hide_env_values = true)]
        admin_token: Option<String>,
        /// Print the address instead of opening a browser.
        #[arg(long)]
        no_open: bool,
    },
}

pub fn run(cmd: BundleCmd) -> Result<()> {
    match cmd {
        BundleCmd::Check { file, strict, json } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let r = check(&text);
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                for e in &r.errors {
                    eprintln!("error: {e}");
                }
                for w in &r.warnings {
                    eprintln!("warning: {w}");
                }
                if r.errors.is_empty() && r.warnings.is_empty() {
                    eprintln!("{}: ok", file.display());
                }
            }
            if !r.ok() || (strict && !r.warnings.is_empty()) {
                std::process::exit(1);
            }
            Ok(())
        }
        BundleCmd::Edit {
            file,
            addr,
            people,
            hub,
            admin_token,
            no_open,
        } => tokio::runtime::Runtime::new()?.block_on(edit(
            file,
            &addr,
            people,
            hub,
            admin_token,
            no_open,
        )),
    }
}

/// Where the editor's list of people came from, and what went wrong getting it.
#[derive(Clone, Default)]
pub struct People {
    pub list: Vec<Value>,
    pub source: String,
    pub error: Option<String>,
}

pub struct Editor {
    pub file: PathBuf,
    pub token: String,
    /// `Host` values a request may carry: this listener under its loopback names.
    pub hosts: Vec<String>,
    pub people: People,
}

impl Editor {
    pub fn new(file: PathBuf, port: u16, people: People) -> Self {
        Editor {
            file,
            token: random_id(),
            hosts: ["127.0.0.1", "localhost", "[::1]"]
                .iter()
                .map(|h| format!("{h}:{port}"))
                .collect(),
            people,
        }
    }

    /// Requests must name this listener: a page on another site that rebinds its
    /// DNS name to 127.0.0.1 still sends its own name.
    fn check_host(&self, headers: &HeaderMap) -> Result<String, Response> {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if self.hosts.iter().any(|h| h == host) {
            Ok(host.to_string())
        } else {
            Err(refuse(StatusCode::FORBIDDEN, "wrong Host for this editor"))
        }
    }

    fn guard(&self, headers: &HeaderMap) -> Result<(), Response> {
        let host = self.check_host(headers)?;
        let given = headers
            .get("x-kith-editor")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !ct_eq(given, &self.token) {
            return Err(refuse(
                StatusCode::FORBIDDEN,
                "the editor's token is missing or wrong: open the address `kith bundle edit` printed",
            ));
        }
        if let Some(origin) = headers.get(header::ORIGIN) {
            if origin.to_str().ok() != Some(format!("http://{host}").as_str()) {
                return Err(refuse(StatusCode::FORBIDDEN, "cross-origin request"));
            }
        }
        Ok(())
    }

    fn read(&self) -> Result<String, Response> {
        std::fs::read_to_string(&self.file).map_err(|e| {
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("reading {}: {e}", self.file.display()),
            )
        })
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn refuse(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"error": msg}))).into_response()
}

fn digest(text: &str) -> String {
    b64u(sha256(text.as_bytes()))
}

pub fn router(editor: Arc<Editor>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/api/state", get(state))
        .route("/api/check", post(check_draft))
        .route("/api/bundle", put(save))
        .with_state(editor)
}

async fn page(State(e): State<Arc<Editor>>, headers: HeaderMap) -> Response {
    if let Err(r) = e.check_host(&headers) {
        return r;
    }
    let nonce = random_id();
    let mut r = Html(PAGE.replace("{{NONCE}}", &nonce)).into_response();
    let h = r.headers_mut();
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; img-src data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&csp).expect("ascii"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

async fn state(State(e): State<Arc<Editor>>, headers: HeaderMap) -> Response {
    if let Err(r) = e.guard(&headers) {
        return r;
    }
    let text = match e.read() {
        Ok(t) => t,
        Err(r) => return r,
    };
    let report = check(&text);
    Json(json!({
        "file": e.file.display().to_string(),
        "text": text,
        "sha": digest(&text),
        "report": report,
        "analysis": analyze(&text, &e.people.list),
        "people": e.people.list,
        "people_source": e.people.source,
        "people_error": e.people.error,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct Draft {
    text: String,
    /// The digest of the file as the page loaded it (save only).
    #[serde(default)]
    sha: Option<String>,
}

async fn check_draft(
    State(e): State<Arc<Editor>>,
    headers: HeaderMap,
    Json(d): Json<Draft>,
) -> Response {
    if let Err(r) = e.guard(&headers) {
        return r;
    }
    Json(json!({"report": check(&d.text), "analysis": analyze(&d.text, &e.people.list)}))
        .into_response()
}

async fn save(State(e): State<Arc<Editor>>, headers: HeaderMap, Json(d): Json<Draft>) -> Response {
    if let Err(r) = e.guard(&headers) {
        return r;
    }
    let report = check(&d.text);
    if !report.ok() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "the bundle has errors; nothing was written", "report": report})),
        )
            .into_response();
    }
    let current = match e.read() {
        Ok(t) => t,
        Err(r) => return r,
    };
    if d.sha.as_deref() != Some(digest(&current).as_str()) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "the file changed on disk since this page loaded it; reload to see it"})),
        )
            .into_response();
    }
    if let Err(err) = write_atomically(&e.file, &d.text) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("writing {}: {err:#}", e.file.display()),
        );
    }
    Json(json!({"sha": digest(&d.text), "report": report})).into_response()
}

/// Write `text` next to `path` and rename it into place, so a reader (the hub, git)
/// sees the old file or the new one, never half of one.
pub fn write_atomically(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .context("not a file")?
        .to_string_lossy()
        .to_string();
    let tmp = dir.join(format!(".{name}.{}.tmp", random_id()));
    let result = (|| -> Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        if let Ok(meta) = std::fs::metadata(path) {
            f.set_permissions(meta.permissions())?;
        }
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Each person's groups and roles under `text`: standing ones (the directory's
/// attributes alone, as the hub's admin API reports them) and with a passkey sign-in
/// (AAL 2), which rules such as `principal.aal >= 2` need. People are the given list
/// plus every DID the bundle names.
pub fn analyze(text: &str, people: &[Value]) -> Value {
    let Ok(engine) = Engine::from_json(text) else {
        return json!({});
    };
    let mut dids: BTreeSet<String> = people
        .iter()
        .filter_map(|p| p["did"].as_str().map(str::to_owned))
        .collect();
    for set in engine
        .bundle
        .groups
        .values()
        .chain(engine.bundle.roles.values())
    {
        dids.extend(
            set.members
                .iter()
                .filter(|m| m.starts_with("did:"))
                .cloned(),
        );
    }
    dids.extend(engine.bundle.directory.keys().cloned());
    let empty = Memberships::default();
    let mut out = Map::new();
    for did in dids {
        let person = people.iter().find(|p| p["did"] == did.as_str());
        let mut kel = Map::new();
        if let Some(p) = person {
            kel.insert("aliases".into(), p["aliases"].clone());
            kel.insert("work".into(), p["work"].clone());
        }
        let standing = engine.attributes(&did, &kel);
        let mut strong = standing.clone();
        strong.insert("aal".into(), json!(2));
        let standing = engine.memberships(&did, &standing).unwrap_or(empty.clone());
        let strong = engine.memberships(&did, &strong).unwrap_or(empty.clone());
        out.insert(did, json!({"standing": standing, "strong": strong}));
    }
    Value::Object(out)
}

async fn load_people(
    people: Option<PathBuf>,
    hub: Option<String>,
    token: Option<String>,
) -> Result<People> {
    if let Some(path) = people {
        let list: Vec<Value> = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("{} is not a list of identities", path.display()))?;
        return Ok(People {
            list,
            source: path.display().to_string(),
            error: None,
        });
    }
    let Some(hub) = hub else {
        return Ok(People {
            source: "the bundle".into(),
            error: Some("No people list: pass --people FILE or --hub URL. Only DIDs already in the bundle are shown.".into()),
            ..Default::default()
        });
    };
    let url = format!("{}/v1/admin/identities", hub.trim_end_matches('/'));
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        return Ok(People {
            source: url,
            error: Some("--hub needs --admin-token (or KITH_ADMIN_TOKEN) to list people.".into()),
            ..Default::default()
        });
    };
    let fetched = async {
        let r = reqwest::Client::new()
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?;
        let status = r.status();
        if !status.is_success() {
            bail!("{url} answered {status}");
        }
        Ok::<Vec<Value>, anyhow::Error>(r.json().await?)
    }
    .await;
    Ok(match fetched {
        Ok(list) => People {
            list,
            source: url,
            error: None,
        },
        Err(e) => People {
            source: url,
            error: Some(format!("{e:#}")),
            ..Default::default()
        },
    })
}

async fn edit(
    file: PathBuf,
    addr: &str,
    people: Option<PathBuf>,
    hub: Option<String>,
    admin_token: Option<String>,
    no_open: bool,
) -> Result<()> {
    let sock: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("{addr} is not an address like 127.0.0.1:7801"))?;
    if !sock.ip().is_loopback() {
        bail!("the editor listens on loopback only (127.0.0.1 or [::1]), not {addr}");
    }
    let text =
        std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
    let report: Report = check(&text);
    for e in &report.errors {
        eprintln!("error: {e}");
    }
    let people = load_people(people, hub, admin_token).await?;
    if let Some(e) = &people.error {
        eprintln!("people: {e}");
    }
    let listener = tokio::net::TcpListener::bind(sock).await?;
    let port = listener.local_addr()?.port();
    let editor = Arc::new(Editor::new(file.clone(), port, people));
    let url = format!("http://localhost:{port}/#{}", editor.token);
    eprintln!("editing {} at {url}", file.display());
    eprintln!(
        "Ctrl-C stops it. Saving writes the file; review it with git diff, then commit and deploy."
    );
    if !no_open {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(opener).arg(&url).spawn();
    }
    axum::serve(listener, router(editor)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ADA: &str = "did:kith:ada";

    fn setup() -> (Arc<Editor>, Router, PathBuf) {
        let dir = std::env::temp_dir().join(format!("kith-editor-{}", random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("bundle.json");
        std::fs::write(&file, bundle("carterbox:admin")).unwrap();
        let people = People {
            list: vec![json!({"did": ADA, "aliases": [], "work": 0})],
            source: "test".into(),
            error: None,
        };
        let e = Arc::new(Editor::new(file.clone(), 7801, people));
        (e.clone(), router(e), file)
    }

    fn bundle(role: &str) -> String {
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "groups": {"org:acme": {"members": [ADA]}, "strong": {"rule": "principal.aal >= 2"}},
            "roles": {
                (role): {"members": ["group:org:acme"]},
                "carterbox:owner": {"rule": "principal in Group::\"org:acme\" && principal in Group::\"strong\""}
            },
            "policies": ""
        }))
        .unwrap()
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let body = match body {
            Some(v) => {
                b = b.header("content-type", "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let r = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
        let status = r.status();
        let bytes = r.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[tokio::test]
    async fn the_api_needs_the_token_the_right_host_and_no_other_origin() {
        let (e, app, _) = setup();
        let host = ("host", "localhost:7801");
        let token = ("x-kith-editor", e.token.as_str());
        assert_eq!(
            call(&app, "GET", "/api/state", &[host], None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "GET",
                "/api/state",
                &[host, ("x-kith-editor", "guess")],
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        // A rebound DNS name sends its own Host.
        assert_eq!(
            call(
                &app,
                "GET",
                "/api/state",
                &[("host", "evil.example:7801"), token],
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "GET",
                "/api/state",
                &[host, token, ("origin", "https://evil.example")],
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let (status, s) = call(
            &app,
            "GET",
            "/api/state",
            &[host, token, ("origin", "http://localhost:7801")],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{s}");
        assert_eq!(s["report"]["errors"], json!([]), "{s}");
        assert_eq!(s["sha"], json!(digest(&bundle("carterbox:admin"))));
    }

    #[tokio::test]
    async fn a_draft_is_checked_and_each_person_analyzed() {
        let (e, app, _) = setup();
        let h = [
            ("host", "127.0.0.1:7801"),
            ("x-kith-editor", e.token.as_str()),
        ];
        let (_, r) = call(
            &app,
            "POST",
            "/api/check",
            &h,
            Some(json!({"text": bundle("carterbox:admin")})),
        )
        .await;
        let ada = &r["analysis"][ADA];
        assert_eq!(ada["standing"]["roles"], json!(["carterbox:admin"]), "{r}");
        assert_eq!(
            ada["strong"]["roles"],
            json!(["carterbox:admin", "carterbox:owner"]),
            "{r}"
        );

        let mut bad: Value = serde_json::from_str(&bundle("x")).unwrap();
        bad["roles"]["x"]["members"] = json!(["group:org:acm"]);
        let (_, r) = call(
            &app,
            "POST",
            "/api/check",
            &h,
            Some(json!({"text": bad.to_string()})),
        )
        .await;
        assert!(
            r["report"]["errors"][0]
                .as_str()
                .unwrap()
                .contains("group:org:acm"),
            "{r}"
        );
    }

    #[tokio::test]
    async fn save_refuses_errors_and_stale_pages_then_writes_the_file() {
        let (e, app, file) = setup();
        let h = [
            ("host", "localhost:7801"),
            ("x-kith-editor", e.token.as_str()),
        ];
        let sha = digest(&std::fs::read_to_string(&file).unwrap());
        let before = std::fs::read_to_string(&file).unwrap();

        let (status, r) = call(
            &app,
            "PUT",
            "/api/bundle",
            &h,
            Some(json!({"text": "{\"version\": 1, \"rols\": {}}", "sha": sha})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{r}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            before,
            "nothing was written"
        );

        let next = bundle("carterbox:viewer");
        let (status, r) = call(
            &app,
            "PUT",
            "/api/bundle",
            &h,
            Some(json!({"text": next, "sha": "stale"})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{r}");

        let (status, r) = call(
            &app,
            "PUT",
            "/api/bundle",
            &h,
            Some(json!({"text": next, "sha": sha})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{r}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), next);
        assert_eq!(r["sha"], json!(digest(&next)));
        let leftovers: Vec<_> = std::fs::read_dir(file.parent().unwrap())
            .unwrap()
            .filter_map(|d| d.ok())
            .filter(|d| d.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no temporary files are left behind");
    }

    #[tokio::test]
    async fn the_page_is_served_with_a_strict_policy() {
        let (_, app, _) = setup();
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "localhost:7801")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let csp = r.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"),
            "{csp}"
        );
        let html =
            String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(!html.contains("{{NONCE}}"));
    }
}
