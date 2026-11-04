//! Outgoing mail. The hub only ever sends short plain-text codes, so this is a thin
//! client for the Amazon SES v2 `SendEmail` call, signed with SigV4 by hand to avoid
//! pulling in the AWS SDK.

use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub enum Mailer {
    /// Amazon SES. The key needs only `ses:SendEmail`.
    Ses {
        region: String,
        key: String,
        secret: String,
        from: String,
    },
    /// Keeps what would have been sent; for tests.
    Capture(Arc<Mutex<Vec<Mail>>>),
}

#[derive(Debug, Clone)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mailer::Ses { region, from, .. } => write!(f, "Ses({region}, {from})"),
            Mailer::Capture(_) => write!(f, "Capture"),
        }
    }
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac takes any key length");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` for a Unix time.
fn amz_time(t: i64) -> (String, String) {
    let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let date = format!("{y:04}{m:02}{d:02}");
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    );
    (date, stamp)
}

/// The `Authorization` header value for a POST to `host` + `path` with `body`.
fn sign(
    region: &str,
    key: &str,
    secret: &str,
    host: &str,
    path: &str,
    body: &str,
    t: i64,
) -> (String, String) {
    let (date, stamp) = amz_time(t);
    let scope = format!("{date}/{region}/ses/aws4_request");
    let canonical = format!(
        "POST\n{path}\n\ncontent-type:application/json\nhost:{host}\nx-amz-date:{stamp}\n\ncontent-type;host;x-amz-date\n{}",
        hex(&Sha256::digest(body.as_bytes()))
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let k = hmac(format!("AWS4{secret}").as_bytes(), &date);
    let k = hmac(&k, region);
    let k = hmac(&k, "ses");
    let k = hmac(&k, "aws4_request");
    let sig = hex(&hmac(&k, &to_sign));
    (
        format!(
            "AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders=content-type;host;x-amz-date, Signature={sig}"
        ),
        stamp,
    )
}

impl Mailer {
    pub async fn send(&self, to: &str, subject: &str, body: &str) -> anyhow::Result<()> {
        match self {
            Mailer::Capture(v) => {
                v.lock().unwrap().push(Mail {
                    to: to.into(),
                    subject: subject.into(),
                    body: body.into(),
                });
                Ok(())
            }
            Mailer::Ses {
                region,
                key,
                secret,
                from,
            } => {
                let host = format!("email.{region}.amazonaws.com");
                let path = "/v2/email/outbound-emails";
                let payload = json!({
                    "FromEmailAddress": from,
                    "Destination": {"ToAddresses": [to]},
                    "Content": {"Simple": {
                        "Subject": {"Data": subject, "Charset": "UTF-8"},
                        "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
                    }},
                })
                .to_string();
                let (auth, stamp) = sign(
                    region,
                    key,
                    secret,
                    &host,
                    path,
                    &payload,
                    kith_core::util::now(),
                );
                let res = reqwest::Client::new()
                    .post(format!("https://{host}{path}"))
                    .header("content-type", "application/json")
                    .header("x-amz-date", stamp)
                    .header("authorization", auth)
                    .body(payload)
                    .timeout(std::time::Duration::from_secs(15))
                    .send()
                    .await?;
                if !res.status().is_success() {
                    let status = res.status();
                    let text = res.text().await.unwrap_or_default();
                    anyhow::bail!(
                        "SES answered {status}: {}",
                        text.chars().take(300).collect::<String>()
                    );
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_times_like_amz() {
        assert_eq!(amz_time(0).1, "19700101T000000Z");
        assert_eq!(amz_time(1_440_938_160).1, "20150830T123600Z");
        assert_eq!(amz_time(1_782_000_000).0, "20260621");
    }

    #[test]
    fn matches_the_documented_signing_key_example() {
        // From the AWS SigV4 documentation: derived key for this secret/date/region/service.
        let k = hmac(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830");
        let k = hmac(&k, "us-east-1");
        let k = hmac(&k, "iam");
        let k = hmac(&k, "aws4_request");
        assert_eq!(
            hex(&k),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }
}
