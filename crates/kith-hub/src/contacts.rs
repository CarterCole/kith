//! Verified contacts: email addresses and phone numbers an identity has proved it
//! receives messages at (spec 7.8.2).
//!
//! The hub sends a six-digit code, the identity sends it back, and from then on the
//! hub can attest the contact with the same `kith-account+jwt` it uses for upstream
//! accounts (spec 7.8.1), naming itself as the provider. Contacts are private by
//! default: an app gets one only with the user's agreement to its `email` or `phone`
//! scope. The user can publish one, and the hub then answers
//! `GET /v1/contacts/lookup` for it. A verification goes stale after
//! [`ContactConfig::email_max_age`] or [`ContactConfig::phone_max_age`], and whoever
//! proves control of an address last holds it.
//!
//! | endpoint                          | purpose                                      |
//! |-----------------------------------|----------------------------------------------|
//! | `POST /v1/contacts`               | send a code to an address (bearer)           |
//! | `POST /v1/contacts/confirm`       | confirm it with the code (bearer)            |
//! | `GET  /v1/contacts`               | the caller's contacts (bearer)               |
//! | `PUT  /v1/contacts/public`        | publish or withdraw one (bearer, `alias` cap) |
//! | `DELETE /v1/contacts`             | forget one (bearer)                          |
//! | `GET  /v1/contacts/lookup`        | a published contact's holder, signed (no token) |

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use kith_core::session::KelResolver;
use kith_core::token::{AccessClaims, AccountAttestation};
use kith_core::util::{now, random_id};

use crate::{ApiError, ApiResult, ClientIp, Hub, RateLimit, TOKEN_TTL};

/// The `aud` of an attestation anyone may check: the answer to a public lookup.
pub const PUBLIC_AUDIENCE: &str = "urn:kith:public";
/// How long a code is good for, and how many wrong tries it survives.
pub const CODE_TTL: i64 = 600;
pub const CODE_TRIES: u32 = 5;
const DAY: i64 = 86_400;

/// How the hub sends codes.
#[derive(Debug, Clone, Default)]
pub enum Delivery {
    /// Contacts are turned off: the endpoints answer `501`.
    #[default]
    None,
    /// Append each message to this file as a JSON line (`to`, `subject`, `body`, `at`).
    /// For tests and development.
    Outbox(PathBuf),
    /// Amazon SES for email and AWS End User Messaging SMS for texts. Needs the `aws`
    /// feature.
    Aws(AwsDelivery),
}

#[derive(Debug, Clone, Default)]
pub struct AwsDelivery {
    /// The AWS region; otherwise the usual environment and profile settings decide.
    pub region: Option<String>,
    /// A verified SES identity to send mail from, e.g. `Kith <no-reply@example.com>`.
    /// Email is turned off without it.
    pub email_from: Option<String>,
    /// An origination identity for texts: a phone number, sender id, or pool, by id or
    /// ARN. Texts are turned off without it.
    pub sms_from: Option<String>,
    /// An End User Messaging configuration set, for its protect settings and events.
    pub sms_configuration_set: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ContactConfig {
    pub delivery: Delivery,
    /// Seconds a verification stays good. Carriers give numbers to new subscribers
    /// after a few months, so phone numbers go stale sooner.
    pub email_max_age: i64,
    pub phone_max_age: i64,
    /// Codes sent per identity, per address and per client address.
    pub send_limit: RateLimit,
    /// E.164 prefixes phone numbers must start with (`+1`); empty allows any.
    pub phone_prefixes: Vec<String>,
}

impl Default for ContactConfig {
    fn default() -> Self {
        ContactConfig { delivery: Delivery::None, email_max_age: 365 * DAY, phone_max_age: 90 * DAY, send_limit: RateLimit { max: 5, window_secs: 3600 }, phone_prefixes: vec![] }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Email,
    Phone,
    /// A domain the identity proved it controls (spec 7.8.3); the address is `dns:<domain>`.
    Domain,
}

impl Kind {
    pub fn of(address: &str) -> Kind {
        if address.starts_with("tel:") {
            Kind::Phone
        } else if address.starts_with(kith_core::domain::SCHEME) {
            Kind::Domain
        } else {
            Kind::Email
        }
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Email => "email",
            Kind::Phone => "phone",
            Kind::Domain => "domain",
        }
    }
}

/// The contact URI for what a user typed: `mailto:` in lower case, or `tel:` in E.164.
pub fn normalize(input: &str) -> Result<String, String> {
    let s = input.trim();
    let bad = |why: &str| Err(format!("{why}: {input:?}"));
    if let Some(d) = s.strip_prefix(kith_core::domain::SCHEME) {
        return kith_core::domain::normalize(d).map(|d| format!("{}{d}", kith_core::domain::SCHEME)).map_err(|e| e.to_string());
    }
    if let Some(rest) = s.strip_prefix("tel:").or_else(|| s.strip_prefix('+').map(|_| s)) {
        let Some(number) = rest.strip_prefix('+') else {
            return bad("a phone number needs its + country code");
        };
        let mut digits = String::new();
        for c in number.chars() {
            match c {
                '0'..='9' => digits.push(c),
                ' ' | '-' | '.' | '(' | ')' => {}
                _ => return bad("not a phone number"),
            }
        }
        if !(8..=15).contains(&digits.len()) || digits.starts_with('0') {
            return bad("a phone number has 8 to 15 digits after the +");
        }
        return Ok(format!("tel:+{digits}"));
    }
    let addr = s.strip_prefix("mailto:").unwrap_or(s).to_ascii_lowercase();
    let Some((local, domain)) = addr.split_once('@') else {
        return bad("not an email address or phone number");
    };
    if local.is_empty() || domain.contains('@') || !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return bad("not an email address");
    }
    if addr.len() > 254 || addr.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';' | '"' | '\\')) {
        return bad("not an email address");
    }
    Ok(format!("mailto:{addr}"))
}

/// One verified contact, as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactRecord {
    pub address: String,
    pub did: String,
    pub verified_at: i64,
    pub public: bool,
}

/// What the claims and attestations call a contact: the address without its scheme.
fn bare(address: &str) -> &str {
    address.split_once(':').map(|(_, a)| a).unwrap_or(address)
}

impl Hub {
    fn max_age(&self, kind: Kind) -> i64 {
        match kind {
            Kind::Email => self.cfg.contacts.email_max_age,
            Kind::Phone => self.cfg.contacts.phone_max_age,
            Kind::Domain => self.cfg.domains.max_age,
        }
    }

    pub(crate) fn fresh_until(&self, c: &ContactRecord) -> i64 {
        c.verified_at.saturating_add(self.max_age(Kind::of(&c.address)))
    }

    /// `did`'s contacts that are still fresh, most recently verified first.
    pub(crate) fn fresh_contacts(&self, did: &str) -> ApiResult<Vec<ContactRecord>> {
        let t = now();
        let mut out: Vec<_> = self.store.contacts_of(did)?.into_iter().filter(|c| t < self.fresh_until(c)).collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.verified_at));
        Ok(out)
    }

    /// The kinds of contact the `email` and `phone` scopes release.
    fn granted(scope: &str) -> Vec<Kind> {
        let has = |s: &str| scope.split_whitespace().any(|x| x == s);
        [(has("email"), Kind::Email), (has("phone"), Kind::Phone), (has("domain"), Kind::Domain)].into_iter().filter(|(on, _)| *on).map(|(_, k)| k).collect()
    }

    /// Claims from verified contacts, for the scopes granted: `email` and
    /// `phone_number`, each with its `_verified`. They only fill gaps in `claims`.
    pub(crate) fn add_contact_claims(&self, did: &str, scope: &str, claims: &mut Map<String, Value>) -> ApiResult<()> {
        let kinds = Self::granted(scope);
        if kinds.is_empty() {
            return Ok(());
        }
        let fresh = self.fresh_contacts(did)?;
        for kind in kinds {
            let (claim, verified) = match kind {
                Kind::Email => ("email", "email_verified"),
                Kind::Phone => ("phone_number", "phone_number_verified"),
                // Domains are released as attestations only, never as a claim.
                Kind::Domain => continue,
            };
            if claims.contains_key(claim) {
                continue;
            }
            if let Some(c) = fresh.iter().find(|c| Kind::of(&c.address) == kind) {
                claims.insert(claim.into(), json!(bare(&c.address)));
                claims.insert(verified.into(), json!(true));
            }
        }
        Ok(())
    }

    /// The fresh contacts the scopes would attest, for the consent page.
    pub(crate) fn attested_contacts(&self, did: &str, scope: &str) -> ApiResult<Vec<ContactRecord>> {
        let kinds = Self::granted(scope);
        Ok(self.fresh_contacts(did)?.into_iter().filter(|c| kinds.contains(&Kind::of(&c.address))).collect())
    }

    fn contact_attestation(&self, aud: &str, sub: &str, c: &ContactRecord) -> ApiResult<String> {
        let iat = now();
        let claims = AccountAttestation {
            iss: self.cfg.issuer.clone(),
            sub: sub.into(),
            aud: aud.into(),
            iat,
            exp: iat + TOKEN_TTL,
            jti: random_id(),
            provider: Kind::of(&c.address).name().into(),
            provider_iss: self.cfg.issuer.clone(),
            account: c.address.clone(),
            verified_at: c.verified_at,
        };
        Ok(self.signer.issue_attestation(&claims)?)
    }

    /// One attestation per fresh contact the scopes release, for `client_id`.
    pub(crate) fn contact_attestations(&self, client_id: &str, sub: &str, did: &str, scope: &str) -> ApiResult<Vec<String>> {
        self.attested_contacts(did, scope)?.iter().map(|c| self.contact_attestation(client_id, sub, c)).collect()
    }

    async fn deliver(&self, address: &str, code: &str) -> anyhow::Result<()> {
        let rp = &self.cfg.rp_id;
        let mins = CODE_TTL / 60;
        let (subject, body) = match Kind::of(address) {
            Kind::Email => (
                format!("Your {rp} verification code"),
                format!(
                    "{code} is your code to confirm this address with {rp} ({}).\n\nIt expires in {mins} minutes. If you did not ask for it, ignore this message: nothing changes unless the code is used.\n",
                    self.cfg.issuer
                ),
            ),
            // The last line is an origin-bound one-time code, so a phone offers it only
            // on the hub's own site.
            Kind::Phone => (String::new(), format!("{code} is your {rp} verification code. It expires in {mins} minutes.\n\n@{rp} #{code}")),
            Kind::Domain => anyhow::bail!("domains are proved with a published record, not a code"),
        };
        match &self.cfg.contacts.delivery {
            Delivery::None => anyhow::bail!("no delivery method"),
            Delivery::Outbox(path) => {
                use std::io::Write;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let line = json!({"to": address, "subject": subject, "body": body, "at": now()});
                let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
                writeln!(f, "{line}")?;
                Ok(())
            }
            #[cfg(feature = "aws")]
            Delivery::Aws(cfg) => aws::send(&self.aws, cfg, address, &subject, &body).await,
            #[cfg(not(feature = "aws"))]
            Delivery::Aws(_) => anyhow::bail!("this hub was built without the aws feature"),
        }
    }

    /// The DID behind an OpenID Connect access token's `sub`, which is pairwise for
    /// some clients.
    pub(crate) fn did_for(&self, c: &AccessClaims) -> Option<String> {
        let client = self.client(c.client_id.as_deref()?)?;
        if c.sub.starts_with("did:") && self.subject_for(&client, &c.sub) == c.sub {
            return Some(c.sub.clone());
        }
        self.kel_dids().into_iter().find(|d| self.subject_for(&client, d) == c.sub)
    }
}

impl ContactConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.email_max_age <= 0 || self.phone_max_age <= 0 {
            anyhow::bail!("contact max ages must be positive");
        }
        for p in &self.phone_prefixes {
            if !p.starts_with('+') || p.len() < 2 || !p[1..].chars().all(|c| c.is_ascii_digit()) {
                anyhow::bail!("phone prefix {p:?} must be + and digits");
            }
        }
        if let Delivery::Aws(a) = &self.delivery {
            if !cfg!(feature = "aws") {
                anyhow::bail!("AWS delivery needs a hub built with the aws feature");
            }
            if a.email_from.is_none() && a.sms_from.is_none() {
                anyhow::bail!("AWS delivery needs an email sender, an SMS origination identity, or both");
            }
        }
        Ok(())
    }

    /// Whether this hub can send to `kind` at all.
    fn sends(&self, kind: Kind) -> bool {
        match &self.delivery {
            Delivery::None => false,
            Delivery::Outbox(_) => true,
            Delivery::Aws(a) => match kind {
                Kind::Email => a.email_from.is_some(),
                Kind::Phone => a.sms_from.is_some(),
                Kind::Domain => false,
            },
        }
    }
}

// ---------------------------------------------------------------- handlers

fn off(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_IMPLEMENTED, "unsupported".into(), format!("this hub does not send {what}"), None)
}

fn too_many(retry: i64) -> ApiError {
    ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited".into(), format!("too many codes requested; try again in {retry}s"), Some(json!({"retry_after": retry})))
}

pub(crate) fn view(h: &Hub, c: &ContactRecord) -> Value {
    let until = h.fresh_until(c);
    json!({"address": c.address, "kind": Kind::of(&c.address), "verified_at": c.verified_at, "fresh_until": until, "fresh": now() < until, "public": c.public})
}

#[derive(Deserialize)]
pub struct AddressReq {
    address: String,
}

/// `POST /v1/contacts`: send a code to an address.
pub async fn request_code(State(h): State<Arc<Hub>>, ip: ClientIp, headers: HeaderMap, Json(req): Json<AddressReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let address = normalize(&req.address).map_err(|e| ApiError::bad("invalid_request", e))?;
    let kind = Kind::of(&address);
    if kind == Kind::Domain {
        return Err(ApiError::bad("invalid_request", "a domain is proved with a published record: POST /v1/domains, then POST /v1/domains/verify"));
    }
    if !h.cfg.contacts.sends(kind) {
        return Err(off(if kind == Kind::Email { "email" } else { "text messages" }));
    }
    let prefixes = &h.cfg.contacts.phone_prefixes;
    if kind == Kind::Phone && !prefixes.is_empty() && !prefixes.iter().any(|p| address["tel:".len()..].starts_with(p.as_str())) {
        return Err(ApiError::bad("invalid_request", format!("this hub only sends texts to numbers starting {}", prefixes.join(", "))));
    }
    let t = now();
    let limit = h.cfg.contacts.send_limit;
    for bucket in [format!("contact-did|{}", c.sub), format!("contact-addr|{address}"), format!("contact-ip|{}", ip.0)] {
        if let Some(retry) = h.store.hit(&bucket, limit, t)? {
            return Err(too_many(retry));
        }
    }
    let code = format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32));
    h.store.put_contact_code(&c.sub, &address, &code, t + CODE_TTL)?;
    if let Err(e) = h.deliver(&address, &code).await {
        h.store.drop_contact_code(&c.sub, &address)?;
        return Err(ApiError(StatusCode::BAD_GATEWAY, "delivery_failed".into(), format!("could not send the code: {e}"), None));
    }
    Ok(Json(json!({"address": address, "kind": kind, "expires_at": t + CODE_TTL})))
}

#[derive(Deserialize)]
pub struct ConfirmReq {
    address: String,
    code: String,
}

/// `POST /v1/contacts/confirm`: the code that was sent proves control.
pub async fn confirm(State(h): State<Arc<Hub>>, headers: HeaderMap, Json(req): Json<ConfirmReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let address = normalize(&req.address).map_err(|e| ApiError::bad("invalid_request", e))?;
    let rec = h.store.confirm_contact(&c.sub, &address, req.code.trim(), now())?.ok_or_else(|| ApiError::unauthorized("wrong, expired or used code; ask for a new one"))?;
    Ok(Json(view(&h, &rec)))
}

/// `GET /v1/contacts`: the caller's contacts, fresh or not.
pub async fn list(State(h): State<Arc<Hub>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let contacts: Vec<Value> = h.store.contacts_of(&c.sub)?.iter().map(|r| view(&h, r)).collect();
    Ok(Json(json!({"contacts": contacts})))
}

#[derive(Deserialize)]
pub struct PublicReq {
    address: String,
    public: bool,
}

/// `PUT /v1/contacts/public`: publish or withdraw. Publishing links the identity to
/// the address for everyone, so it takes what linking an alias takes: a device with
/// the `alias` cap, or a manage key.
pub async fn set_public(State(h): State<Arc<Hub>>, headers: HeaderMap, Json(req): Json<PublicReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let address = normalize(&req.address).map_err(|e| ApiError::bad("invalid_request", e))?;
    let rec = h.store.contacts_of(&c.sub)?.into_iter().find(|r| r.address == address).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found".into(), "no such verified contact".into(), None))?;
    if req.public {
        let st = h.resolve(&c.sub)?;
        let may = match &c.dev {
            Some(dev) => st.device(dev).is_some_and(|d| d.has_cap("alias")),
            // No device: a manage key or wallet signed in, not an authenticator code.
            None => c.amr.iter().any(|m| matches!(m.as_str(), "swk" | "hwk" | "wallet")),
        };
        if !may {
            return Err(ApiError(StatusCode::FORBIDDEN, "forbidden".into(), "publishing a contact needs a device with the alias cap".into(), None));
        }
        if now() >= h.fresh_until(&rec) {
            return Err(ApiError::bad("stale", "this contact must be checked again before it is published"));
        }
    }
    h.store.set_contact_public(&c.sub, &address, req.public)?;
    Ok(Json(view(&h, &ContactRecord { public: req.public, ..rec })))
}

/// `DELETE /v1/contacts`: forget a contact.
pub async fn remove(State(h): State<Arc<Hub>>, headers: HeaderMap, Json(req): Json<AddressReq>) -> ApiResult<Json<Value>> {
    let c = h.bearer(&headers)?;
    let address = normalize(&req.address).map_err(|e| ApiError::bad("invalid_request", e))?;
    Ok(Json(json!({"removed": h.store.delete_contact(&c.sub, &address)?})))
}

/// `GET /v1/contacts/lookup?address=…`: who holds a published contact, signed. A
/// private contact gets the same `404` as one nobody holds.
pub async fn lookup(State(h): State<Arc<Hub>>, Query(q): Query<std::collections::HashMap<String, String>>) -> ApiResult<Json<Value>> {
    let not_found = || ApiError(StatusCode::NOT_FOUND, "not_found".into(), "no published contact".into(), None);
    let address = normalize(q.get("address").map(String::as_str).unwrap_or_default()).map_err(|_| not_found())?;
    let rec = h.store.contact(&address)?.filter(|r| r.public && now() < h.fresh_until(r)).ok_or_else(not_found)?;
    let attestation = h.contact_attestation(PUBLIC_AUDIENCE, &rec.did, &rec)?;
    Ok(Json(json!({"address": rec.address, "did": rec.did, "verified_at": rec.verified_at, "attestation": attestation})))
}

#[cfg(feature = "aws")]
pub(crate) mod aws {
    //! Amazon SES (email) and AWS End User Messaging SMS (texts). Credentials come
    //! from the default chain: environment, shared profile, SSO, instance role.

    use super::{AwsDelivery, Kind};
    use aws_sdk_pinpointsmsvoicev2 as sms;
    use aws_sdk_sesv2 as ses;
    use tokio::sync::OnceCell;

    #[derive(Default)]
    pub(crate) struct Clients(OnceCell<(ses::Client, sms::Client)>);

    async fn clients<'a>(c: &'a Clients, cfg: &AwsDelivery) -> &'a (ses::Client, sms::Client) {
        c.0.get_or_init(|| async {
            let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
            if let Some(r) = &cfg.region {
                loader = loader.region(aws_config::Region::new(r.clone()));
            }
            let conf = loader.load().await;
            (ses::Client::new(&conf), sms::Client::new(&conf))
        })
        .await
    }

    pub(crate) async fn send(c: &Clients, cfg: &AwsDelivery, address: &str, subject: &str, body: &str) -> anyhow::Result<()> {
        let (mail, text) = clients(c, cfg).await;
        match Kind::of(address) {
            Kind::Email => {
                use ses::types::{Body, Content, Destination, EmailContent, Message};
                let from = cfg.email_from.as_deref().ok_or_else(|| anyhow::anyhow!("no email sender configured"))?;
                let utf8 = |s: &str| Content::builder().data(s).charset("UTF-8").build();
                let message = Message::builder().subject(utf8(subject)?).body(Body::builder().text(utf8(body)?).build()).build();
                mail.send_email()
                    .from_email_address(from)
                    .destination(Destination::builder().to_addresses(super::bare(address)).build())
                    .content(EmailContent::builder().simple(message).build())
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("SES: {}", ses::error::DisplayErrorContext(e)))?;
            }
            Kind::Phone => {
                let from = cfg.sms_from.as_deref().ok_or_else(|| anyhow::anyhow!("no SMS origination identity configured"))?;
                let mut req = text
                    .send_text_message()
                    .destination_phone_number(super::bare(address))
                    .origination_identity(from)
                    .message_body(body)
                    .message_type(sms::types::MessageType::Transactional);
                if let Some(set) = &cfg.sms_configuration_set {
                    req = req.configuration_set_name(set);
                }
                req.send().await.map_err(|e| anyhow::anyhow!("End User Messaging: {}", sms::error::DisplayErrorContext(e)))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_normalised() {
        for (input, want) in [
            ("Ada@Example.COM", "mailto:ada@example.com"),
            (" mailto:ada@example.com ", "mailto:ada@example.com"),
            ("ada+tag@mail.example.co.uk", "mailto:ada+tag@mail.example.co.uk"),
            ("+1 (555) 555-0100", "tel:+15555550100"),
            ("+44 20.7946.0000", "tel:+442079460000"),
            ("tel:+15555550100", "tel:+15555550100"),
        ] {
            assert_eq!(normalize(input).as_deref(), Ok(want), "{input}");
        }
        for bad in ["", "555-0100", "15555550100", "tel:15555550100", "+1 555", "+1234567890123456", "+0 555 555 0100", "+1 555 555 0100 x2", "ada@", "@example.com", "ada@localhost", "ada@@example.com", "ada@example..com", "ada example@example.com", "<ada@example.com>", "ada@.example.com"] {
            assert!(normalize(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(normalize(&format!("{}@example.com", "a".repeat(250))).is_err(), "too long");
    }
}
