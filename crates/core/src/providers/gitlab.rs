use async_trait::async_trait;
use serde::Deserialize;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// GitLab personal-access-token rotation via the REST API.
///
/// GitLab's `POST /personal_access_tokens/:id/rotate` mints a new token AND
/// revokes the old one in a single call, so this is an `AtomicRotate` provider:
/// there is no overlap window and no rollback to the old token. The engine
/// handles that by updating consumers and verifying immediately, and shouting
/// if verification fails.
///
/// Auth: a PAT with `api` scope (the connecting token), sent in the
/// `PRIVATE-TOKEN` header. Note: rotating the *same* token you authenticate
/// with will invalidate the connecting token — rotate other tokens by id, or
/// re-store the returned value as your new admin token.
pub struct GitlabConnector {
    client: reqwest::Client,
    base_url: String,
    token: String,
    /// If set, request this expiry (days from now) for rotated tokens.
    default_expiry_days: Option<u32>,
}

impl GitlabConnector {
    pub fn new(base_url: Option<String>, token: String, default_expiry_days: Option<u32>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.unwrap_or_else(|| "https://gitlab.com".into()),
            token,
            default_expiry_days,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v4{}", self.base_url.trim_end_matches('/'), path)
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }
}

#[async_trait]
impl Connector for GitlabConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Gitlab
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::AtomicRotate
    }

    async fn connect(&self) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(self.url("/user"))
            .header("PRIVATE-TOKEN", self.token.as_str())
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(RotationError::NotAuthorized(
                Self::err_body(resp).await.to_string(),
            ))
        }
    }

    async fn list_keys(&self) -> Result<Vec<Secret>, RotationError> {
        let resp = self
            .client
            .get(self.url("/personal_access_tokens"))
            .header("PRIVATE-TOKEN", self.token.as_str())
            .query(&[("state", "active")])
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let tokens: Vec<GlToken> = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse tokens: {e}")))?;
        Ok(tokens
            .into_iter()
            .map(|t| {
                Secret::new(
                    ProviderKind::Gitlab,
                    t.id.to_string(),
                    t.name,
                    t.id.to_string(),
                )
            })
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        // This rotate both mints the new token and revokes the old one.
        let mut req = self
            .client
            .post(self.url(&format!(
                "/personal_access_tokens/{}/rotate",
                secret.external_id
            )))
            .header("PRIVATE-TOKEN", self.token.as_str());

        if let Some(days) = self.default_expiry_days {
            let expires = expiry_date(days);
            req = req.query(&[("expires_at", expires.as_str())]);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let rotated: GlRotated = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse rotate: {e}")))?;
        Ok(NewCredential::new(rotated.id.to_string(), rotated.token))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(self.url("/user"))
            .header("PRIVATE-TOKEN", cred.secret_value.as_str())
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(RotationError::VerificationFailed(
                Self::err_body(resp).await.to_string(),
            ))
        }
    }

    async fn current_key_id(&self) -> Option<String> {
        let resp = self
            .client
            .get(self.url("/personal_access_tokens/self"))
            .header("PRIVATE-TOKEN", self.token.as_str())
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let t: GlToken = resp.json().await.ok()?;
        Some(t.id.to_string())
    }

    // No deactivate_old / delete_old: GitLab already revoked the old token
    // during `create`.
}

/// Compute an RFC3339 date (YYYY-MM-DD) `days` from now, without pulling in a
/// date crate: days since Unix epoch → civil date (Howard Hinnant's algorithm).
fn expiry_date(days: u32) -> String {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let total_days = (now_secs / 86_400) as i64 + days as i64;
    let (y, m, d) = civil_from_days(total_days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[derive(Deserialize)]
struct GlToken {
    id: u64,
    name: String,
}

#[derive(Deserialize)]
struct GlRotated {
    id: u64,
    token: String,
}
