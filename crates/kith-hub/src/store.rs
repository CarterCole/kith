//! Durable hub state: one SQLite file, `hub.sqlite`, in the data directory.
//!
//! Everything a restart used to lose lives here: OpenID Connect sessions, codes,
//! refresh tokens and pending sign-in requests, remembered consent, dynamically
//! registered clients, TOTP enrollments with their lockouts, co-signer keys, the
//! token replay cache and rate-limit counters. Bearer secrets (session cookies,
//! codes, refresh tokens, request ids) are stored as their SHA-256, so a copy of the
//! file does not let anyone replay them. KELs stay as files under `kels/` (anyone
//! can mirror them; they are self-verifying), and so do the hub's own keys.
//!
//! Records are JSON in a `data` column, next to the columns the hub queries by
//! (expiry, session id, DID, client id). One connection behind a mutex is plenty for
//! a reference hub; SQLite serialises writers anyway.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Params};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use kith_core::keys::{KeyType, LocalSigner};
use kith_core::util::{b64u, b64u_decode, now, sha256};

use crate::oidc::{AuthRequest, Client, CodeGrant, RefreshGrant, SsoSession};
use crate::{read_json, RateLimit};

pub const FILE: &str = "hub.sqlite";
/// How long a sign-in request may sit on the login or consent page.
pub const REQUEST_TTL: i64 = 900;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_requests (key TEXT PRIMARY KEY, created INTEGER NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_codes (key TEXT PRIMARY KEY, sid TEXT, expires INTEGER NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_sessions (key TEXT PRIMARY KEY, sid TEXT NOT NULL UNIQUE, did TEXT NOT NULL, expires INTEGER NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS oidc_sessions_did ON oidc_sessions (did);
CREATE TABLE IF NOT EXISTS oidc_refresh (key TEXT PRIMARY KEY, client_id TEXT NOT NULL, did TEXT NOT NULL, sid TEXT, expires INTEGER NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS oidc_refresh_did ON oidc_refresh (did);
CREATE TABLE IF NOT EXISTS oidc_grants (did TEXT NOT NULL, client_id TEXT NOT NULL, scope TEXT NOT NULL, granted INTEGER NOT NULL, PRIMARY KEY (did, client_id, scope));
CREATE TABLE IF NOT EXISTS oidc_clients (client_id TEXT PRIMARY KEY, created INTEGER NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS totp (did TEXT PRIMARY KEY, secret TEXT NOT NULL, confirmed INTEGER NOT NULL, last_step INTEGER NOT NULL, failures INTEGER NOT NULL, locked_until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cosigners (did TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS seen_jti (jti TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rate_limits (bucket TEXT PRIMARY KEY, window_start INTEGER NOT NULL, window_secs INTEGER NOT NULL, count INTEGER NOT NULL);
INSERT OR IGNORE INTO meta (key, value) VALUES ('schema', '1');
";

pub struct Store {
    conn: Mutex<Connection>,
}

/// A TOTP enrollment, with its replay and lockout state.
#[derive(Debug, Clone)]
pub(crate) struct TotpRecord {
    pub secret: Vec<u8>,
    pub confirmed: bool,
    /// The last time step a code was accepted for; a code is good once.
    pub last_step: i64,
    pub failures: u32,
    /// Wrong codes are refused until this time (0 when not locked).
    pub locked_until: i64,
}

/// Secrets are looked up by hash, never stored. Records that must refer to a bearer
/// secret (a request waiting on consent names its session) keep this instead.
pub(crate) fn hash(secret: &str) -> String {
    b64u(sha256(secret.as_bytes()))
}

fn key(secret: &str) -> String {
    hash(secret)
}

fn one<T: DeserializeOwned>(c: &Connection, sql: &str, p: impl Params) -> anyhow::Result<Option<T>> {
    let data: Option<String> = c.query_row(sql, p, |r| r.get(0)).optional()?;
    Ok(data.map(|d| serde_json::from_str(&d)).transpose()?)
}

fn many<T: DeserializeOwned>(c: &Connection, sql: &str, p: impl Params) -> anyhow::Result<Vec<T>> {
    let mut stmt = c.prepare(sql)?;
    let rows = stmt.query_map(p, |r| r.get::<_, String>(0))?;
    rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
}

fn json<T: Serialize>(v: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string(v)?)
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Store> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn)
    }

    /// Move state that earlier hubs kept in JSON files into the database, once. Each
    /// file is renamed `*.imported` afterwards.
    pub fn import_json_files(&self, dir: &Path) -> anyhow::Result<()> {
        let done = |p: std::path::PathBuf| std::fs::rename(&p, p.with_extension("json.imported"));
        let totp = dir.join("totp.json");
        if let Some(Value::Object(m)) = read_json(&totp) {
            for (did, r) in m {
                if self.totp(&did)?.is_none() {
                    let secret = b64u_decode(r["secret"].as_str().unwrap_or_default())?;
                    self.put_totp(&did, &TotpRecord { secret, confirmed: r["confirmed"].as_bool().unwrap_or(false), last_step: r["last_step"].as_i64().unwrap_or(0), failures: 0, locked_until: 0 })?;
                }
            }
            done(totp)?;
        }
        let cosigners = dir.join("cosigners.json");
        if let Some(Value::Object(m)) = read_json(&cosigners) {
            for (did, s) in m {
                LocalSigner::from_json(&s)?;
                self.with(|c| Ok(c.execute("INSERT OR IGNORE INTO cosigners (did, data) VALUES (?1, ?2)", params![did, s.to_string()])?))?;
            }
            done(cosigners)?;
        }
        let clients = dir.join("clients.json");
        if let Some(v) = read_json(&clients) {
            for c in serde_json::from_value::<Vec<Client>>(v)? {
                if self.client(&c.client_id)?.is_none() {
                    self.put_client(&c)?;
                }
            }
            done(clients)?;
        }
        Ok(())
    }

    /// Drop what has expired.
    pub fn sweep(&self, t: i64) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM oidc_requests WHERE created + ?1 <= ?2", params![REQUEST_TTL, t])?;
            c.execute("DELETE FROM oidc_codes WHERE expires <= ?1", params![t])?;
            c.execute("DELETE FROM oidc_sessions WHERE expires <= ?1", params![t])?;
            c.execute("DELETE FROM oidc_refresh WHERE expires <= ?1", params![t])?;
            c.execute("DELETE FROM seen_jti WHERE expires <= ?1", params![t])?;
            c.execute("DELETE FROM rate_limits WHERE window_start + window_secs <= ?1", params![t])?;
            Ok(())
        })
    }

    /// Row counts, for the admin API.
    pub fn counts(&self) -> anyhow::Result<Value> {
        self.with(|c| {
            let count = |table: &str| -> anyhow::Result<i64> { Ok(c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?) };
            Ok(json!({
                "sessions": count("oidc_sessions")?,
                "refresh_tokens": count("oidc_refresh")?,
                "codes": count("oidc_codes")?,
                "requests": count("oidc_requests")?,
                "grants": count("oidc_grants")?,
                "registered_clients": count("oidc_clients")?,
                "totp_enrollments": count("totp")?,
                "cosigners": count("cosigners")?,
            }))
        })
    }

    // ------------------------------------------------------------ sign-in requests

    pub(crate) fn put_request(&self, id: &str, r: &AuthRequest) -> anyhow::Result<()> {
        self.with(|c| Ok(c.execute("INSERT OR REPLACE INTO oidc_requests (key, created, data) VALUES (?1, ?2, ?3)", params![key(id), r.created, json(r)?]).map(drop)?))
    }

    pub(crate) fn request(&self, id: &str) -> anyhow::Result<Option<AuthRequest>> {
        self.with(|c| one(c, "SELECT data FROM oidc_requests WHERE key = ?1 AND created + ?2 > ?3", params![key(id), REQUEST_TTL, now()]))
    }

    /// Change a stored request in place; `false` when there is none.
    pub(crate) fn update_request(&self, id: &str, f: impl FnOnce(&mut AuthRequest)) -> anyhow::Result<bool> {
        self.with(|c| {
            let Some(mut r) = one::<AuthRequest>(c, "SELECT data FROM oidc_requests WHERE key = ?1 AND created + ?2 > ?3", params![key(id), REQUEST_TTL, now()])? else {
                return Ok(false);
            };
            f(&mut r);
            c.execute("UPDATE oidc_requests SET data = ?2 WHERE key = ?1", params![key(id), json(&r)?])?;
            Ok(true)
        })
    }

    /// Remove and return a request: exactly one caller gets it.
    pub(crate) fn take_request(&self, id: &str) -> anyhow::Result<Option<AuthRequest>> {
        self.with(|c| one(c, "DELETE FROM oidc_requests WHERE key = ?1 RETURNING data", params![key(id)]))
    }

    // ------------------------------------------------------------ codes

    pub(crate) fn put_code(&self, code: &str, g: &CodeGrant) -> anyhow::Result<()> {
        self.with(|c| Ok(c.execute("INSERT INTO oidc_codes (key, sid, expires, data) VALUES (?1, ?2, ?3, ?4)", params![key(code), g.sid, g.expires, json(g)?]).map(drop)?))
    }

    pub(crate) fn take_code(&self, code: &str) -> anyhow::Result<Option<CodeGrant>> {
        self.with(|c| one(c, "DELETE FROM oidc_codes WHERE key = ?1 RETURNING data", params![key(code)]))
    }

    /// Unredeemed codes of a hub session (by its public `sid`) die with it.
    pub(crate) fn delete_codes_of_session(&self, sid: &str) -> anyhow::Result<usize> {
        self.with(|c| Ok(c.execute("DELETE FROM oidc_codes WHERE sid = ?1", params![sid])?))
    }

    // ------------------------------------------------------------ hub sessions

    pub(crate) fn put_session(&self, cookie: &str, s: &SsoSession) -> anyhow::Result<()> {
        self.with(|c| Ok(c.execute("INSERT INTO oidc_sessions (key, sid, did, expires, data) VALUES (?1, ?2, ?3, ?4, ?5)", params![key(cookie), s.id, s.authn.st.did, s.expires, json(s)?]).map(drop)?))
    }

    /// The live session behind a cookie.
    pub(crate) fn session(&self, cookie: &str) -> anyhow::Result<Option<SsoSession>> {
        self.with(|c| one(c, "SELECT data FROM oidc_sessions WHERE key = ?1 AND expires > ?2", params![key(cookie), now()]))
    }

    /// Note that `client_id` got tokens in the session behind `cookie`, and return
    /// the session's public id.
    pub(crate) fn session_add_client(&self, cookie: &str, client_id: &str) -> anyhow::Result<Option<String>> {
        self.with(|c| {
            let Some(mut s) = one::<SsoSession>(c, "SELECT data FROM oidc_sessions WHERE key = ?1 AND expires > ?2", params![key(cookie), now()])? else {
                return Ok(None);
            };
            s.clients.insert(client_id.to_string());
            c.execute("UPDATE oidc_sessions SET data = ?2 WHERE key = ?1", params![key(cookie), json(&s)?])?;
            Ok(Some(s.id))
        })
    }

    pub(crate) fn take_session(&self, cookie: &str) -> anyhow::Result<Option<SsoSession>> {
        self.with(|c| one(c, "DELETE FROM oidc_sessions WHERE key = ?1 RETURNING data", params![key(cookie)]))
    }

    pub(crate) fn take_session_by_sid(&self, sid: &str) -> anyhow::Result<Option<SsoSession>> {
        self.with(|c| one(c, "DELETE FROM oidc_sessions WHERE sid = ?1 RETURNING data", params![sid]))
    }

    pub(crate) fn take_sessions_of(&self, did: &str) -> anyhow::Result<Vec<SsoSession>> {
        self.with(|c| many(c, "DELETE FROM oidc_sessions WHERE did = ?1 RETURNING data", params![did]))
    }

    /// Live sessions, the ones ending last first; all of them, or one identity's.
    pub(crate) fn sessions(&self, did: Option<&str>) -> anyhow::Result<Vec<SsoSession>> {
        self.with(|c| many(c, "SELECT data FROM oidc_sessions WHERE expires > ?1 AND (?2 IS NULL OR did = ?2) ORDER BY expires DESC", params![now(), did]))
    }

    // ------------------------------------------------------------ refresh tokens

    pub(crate) fn put_refresh(&self, token: &str, g: &RefreshGrant) -> anyhow::Result<()> {
        self.with(|c| {
            Ok(c.execute("INSERT INTO oidc_refresh (key, client_id, did, sid, expires, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![key(token), g.client_id, g.authn.st.did, g.sid, g.expires, json(g)?]).map(drop)?)
        })
    }

    pub(crate) fn take_refresh(&self, token: &str) -> anyhow::Result<Option<RefreshGrant>> {
        self.with(|c| one(c, "DELETE FROM oidc_refresh WHERE key = ?1 RETURNING data", params![key(token)]))
    }

    /// Revoke refresh tokens by identity, client, hub session, or any combination
    /// of those. With no filter, none.
    pub(crate) fn revoke_refresh(&self, did: Option<&str>, client_id: Option<&str>, sid: Option<&str>) -> anyhow::Result<usize> {
        if did.is_none() && client_id.is_none() && sid.is_none() {
            return Ok(0);
        }
        self.with(|c| Ok(c.execute("DELETE FROM oidc_refresh WHERE (?1 IS NULL OR did = ?1) AND (?2 IS NULL OR client_id = ?2) AND (?3 IS NULL OR sid = ?3)", params![did, client_id, sid])?))
    }

    // ------------------------------------------------------------ consent

    pub(crate) fn grant<'a>(&self, did: &str, client_id: &str, scopes: impl IntoIterator<Item = &'a str>) -> anyhow::Result<()> {
        self.with(|c| {
            let t = now();
            for s in scopes {
                c.execute("INSERT OR IGNORE INTO oidc_grants (did, client_id, scope, granted) VALUES (?1, ?2, ?3, ?4)", params![did, client_id, s, t])?;
            }
            Ok(())
        })
    }

    pub(crate) fn granted_scopes(&self, did: &str, client_id: &str) -> anyhow::Result<BTreeSet<String>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT scope FROM oidc_grants WHERE did = ?1 AND client_id = ?2")?;
            let rows = stmt.query_map(params![did, client_id], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        })
    }

    /// Every client an identity agreed to share with: (client id, scopes, first granted).
    pub(crate) fn grants_of(&self, did: &str) -> anyhow::Result<Vec<(String, BTreeSet<String>, i64)>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT client_id, scope, granted FROM oidc_grants WHERE did = ?1 ORDER BY client_id, scope")?;
            let mut out: Vec<(String, BTreeSet<String>, i64)> = vec![];
            for row in stmt.query_map(params![did], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))? {
                let (client, scope, granted) = row?;
                match out.last_mut() {
                    Some(last) if last.0 == client => {
                        last.1.insert(scope);
                        last.2 = last.2.min(granted);
                    }
                    _ => out.push((client, BTreeSet::from([scope]), granted)),
                }
            }
            Ok(out)
        })
    }

    pub(crate) fn revoke_grant(&self, did: &str, client_id: &str) -> anyhow::Result<usize> {
        self.with(|c| Ok(c.execute("DELETE FROM oidc_grants WHERE did = ?1 AND client_id = ?2", params![did, client_id])?))
    }

    // ------------------------------------------------------------ registered clients

    pub(crate) fn put_client(&self, client: &Client) -> anyhow::Result<()> {
        self.with(|c| {
            Ok(c.execute("INSERT INTO oidc_clients (client_id, created, data) VALUES (?1, ?2, ?3) ON CONFLICT(client_id) DO UPDATE SET data = excluded.data", params![client.client_id, now(), json(client)?]).map(drop)?)
        })
    }

    pub(crate) fn client(&self, id: &str) -> anyhow::Result<Option<Client>> {
        self.with(|c| one(c, "SELECT data FROM oidc_clients WHERE client_id = ?1", params![id]))
    }

    pub(crate) fn clients(&self) -> anyhow::Result<Vec<Client>> {
        self.with(|c| many(c, "SELECT data FROM oidc_clients ORDER BY created, client_id", []))
    }

    /// Delete a registered client with everything that referred to it: consent,
    /// refresh tokens, codes.
    pub(crate) fn delete_client(&self, id: &str) -> anyhow::Result<bool> {
        self.with(|c| {
            let n = c.execute("DELETE FROM oidc_clients WHERE client_id = ?1", params![id])?;
            c.execute("DELETE FROM oidc_grants WHERE client_id = ?1", params![id])?;
            c.execute("DELETE FROM oidc_refresh WHERE client_id = ?1", params![id])?;
            Ok(n == 1)
        })
    }

    // ------------------------------------------------------------ TOTP, co-signers

    pub(crate) fn totp(&self, did: &str) -> anyhow::Result<Option<TotpRecord>> {
        self.with(|c| {
            let row: Option<(String, bool, i64, u32, i64)> = c
                .query_row("SELECT secret, confirmed, last_step, failures, locked_until FROM totp WHERE did = ?1", params![did], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
                .optional()?;
            Ok(match row {
                Some((secret, confirmed, last_step, failures, locked_until)) => Some(TotpRecord { secret: b64u_decode(&secret)?, confirmed, last_step, failures, locked_until }),
                None => None,
            })
        })
    }

    pub(crate) fn put_totp(&self, did: &str, r: &TotpRecord) -> anyhow::Result<()> {
        self.with(|c| {
            Ok(c.execute(
                "INSERT INTO totp (did, secret, confirmed, last_step, failures, locked_until) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(did) DO UPDATE SET secret = excluded.secret, confirmed = excluded.confirmed, last_step = excluded.last_step, failures = excluded.failures, locked_until = excluded.locked_until",
                params![did, b64u(&r.secret), r.confirmed, r.last_step, r.failures, r.locked_until],
            )
            .map(drop)?)
        })
    }

    pub(crate) fn cosigner(&self, did: &str) -> anyhow::Result<Option<LocalSigner>> {
        self.with(|c| Ok(one::<Value>(c, "SELECT data FROM cosigners WHERE did = ?1", params![did])?.map(|v| LocalSigner::from_json(&v)).transpose()?))
    }

    /// The hub-held co-signer key for `did`, created on first use.
    pub(crate) fn cosigner_or_create(&self, did: &str) -> anyhow::Result<LocalSigner> {
        self.with(|c| {
            if let Some(v) = one::<Value>(c, "SELECT data FROM cosigners WHERE did = ?1", params![did])? {
                return Ok(LocalSigner::from_json(&v)?);
            }
            let s = LocalSigner::generate(KeyType::Ed25519);
            c.execute("INSERT INTO cosigners (did, data) VALUES (?1, ?2)", params![did, s.to_json().to_string()])?;
            Ok(s)
        })
    }

    // ------------------------------------------------------------ replay cache, rate limits

    /// `true` the first time `jti` is presented; it is remembered until `expires`.
    pub(crate) fn first_use(&self, jti: &str, expires: i64, t: i64) -> anyhow::Result<bool> {
        self.with(|c| {
            c.execute("DELETE FROM seen_jti WHERE expires <= ?1", params![t])?;
            Ok(c.execute("INSERT OR IGNORE INTO seen_jti (jti, expires) VALUES (?1, ?2)", params![jti, expires])? == 1)
        })
    }

    /// Count one attempt in `bucket`. `Some(seconds)` when `limit` is exceeded: how
    /// long until the window resets. A limit with `max == 0` never trips.
    pub(crate) fn hit(&self, bucket: &str, limit: RateLimit, t: i64) -> anyhow::Result<Option<i64>> {
        if limit.max == 0 {
            return Ok(None);
        }
        self.with(|c| {
            c.execute("DELETE FROM rate_limits WHERE window_start + window_secs <= ?1", params![t])?;
            let (count, start): (i64, i64) = c.query_row(
                "INSERT INTO rate_limits (bucket, window_start, window_secs, count) VALUES (?1, ?2, ?3, 1)
                 ON CONFLICT(bucket) DO UPDATE SET count = count + 1
                 RETURNING count, window_start",
                params![bucket, t, limit.window_secs],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok((count > i64::from(limit.max)).then(|| (start + limit.window_secs - t).max(1)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        let dir = std::env::temp_dir().join(format!("kith-store-{}", kith_core::util::random_id()));
        Store::open(&dir.join(FILE)).unwrap()
    }

    #[test]
    fn rate_limit_windows() {
        let s = store();
        let limit = RateLimit { max: 2, window_secs: 60 };
        assert_eq!(s.hit("login|1.2.3.4", limit, 1000).unwrap(), None);
        assert_eq!(s.hit("login|1.2.3.4", limit, 1001).unwrap(), None);
        assert_eq!(s.hit("login|1.2.3.4", limit, 1002).unwrap(), Some(58), "third try in the window is refused");
        assert_eq!(s.hit("login|9.9.9.9", limit, 1002).unwrap(), None, "other callers are not affected");
        assert_eq!(s.hit("login|1.2.3.4", limit, 1060).unwrap(), None, "the window has passed");
        // Buckets with longer windows are not swept by shorter ones.
        let hour = RateLimit { max: 1, window_secs: 3600 };
        assert_eq!(s.hit("register|1.2.3.4", hour, 2000).unwrap(), None);
        assert_eq!(s.hit("login|1.2.3.4", limit, 2100).unwrap(), None);
        assert_eq!(s.hit("register|1.2.3.4", hour, 2100).unwrap(), Some(3500));
        assert_eq!(s.hit("anything", RateLimit { max: 0, window_secs: 1 }, 0).unwrap(), None, "max 0 disables");
    }

    #[test]
    fn replay_cache_and_totp() {
        let s = store();
        assert!(s.first_use("j1", 100, 50).unwrap());
        assert!(!s.first_use("j1", 100, 60).unwrap(), "seen before");
        assert!(s.first_use("j1", 100, 100).unwrap(), "forgotten once expired");

        assert!(s.totp("did:kith:a").unwrap().is_none());
        let rec = TotpRecord { secret: vec![1, 2, 3], confirmed: false, last_step: 7, failures: 4, locked_until: 0 };
        s.put_totp("did:kith:a", &rec).unwrap();
        let back = s.totp("did:kith:a").unwrap().unwrap();
        assert_eq!((back.secret, back.confirmed, back.last_step, back.failures), (vec![1, 2, 3], false, 7, 4));
        s.put_totp("did:kith:a", &TotpRecord { locked_until: 99, ..rec }).unwrap();
        assert_eq!(s.totp("did:kith:a").unwrap().unwrap().locked_until, 99);

        let a = s.cosigner_or_create("did:kith:a").unwrap();
        assert_eq!(s.cosigner_or_create("did:kith:a").unwrap().id, a.id, "created once");
        assert_eq!(s.cosigner("did:kith:a").unwrap().unwrap().id, a.id);
        assert!(s.cosigner("did:kith:b").unwrap().is_none());
    }

    #[test]
    fn grants_group_by_client() {
        let s = store();
        s.grant("did:kith:a", "app", ["openid", "email"]).unwrap();
        s.grant("did:kith:a", "app", ["openid", "groups"]).unwrap();
        s.grant("did:kith:a", "other", ["openid"]).unwrap();
        assert_eq!(s.granted_scopes("did:kith:a", "app").unwrap(), BTreeSet::from(["email".to_string(), "groups".into(), "openid".into()]));
        let all = s.grants_of("did:kith:a").unwrap();
        assert_eq!(all.iter().map(|g| (g.0.as_str(), g.1.len())).collect::<Vec<_>>(), vec![("app", 3), ("other", 1)]);
        assert_eq!(s.revoke_grant("did:kith:a", "app").unwrap(), 3);
        assert!(s.granted_scopes("did:kith:a", "app").unwrap().is_empty());
        assert_eq!(s.grants_of("did:kith:b").unwrap(), vec![]);
    }
}
