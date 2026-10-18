use async_trait::async_trait;
use serde::Deserialize;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// Cloudflare user API tokens.
///
/// Cloudflare's roll endpoint (`PUT /user/tokens/{id}/value`) regenerates a
/// token's secret in place: same id, new value, old value dead immediately —
/// an `AtomicRotate` provider. Auth is a Bearer admin token with the
/// "API Tokens Write" permission.
pub struct CloudflareConnector {
    client: reqwest::Client,
    token: String,
}

impl CloudflareConnector {
    pub fn new(token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://api.cloudflare.com/client/v4{path}")
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }
}

#[async_trait]
impl Connector for CloudflareConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Cloudflare
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::AtomicRotate
    }

    async fn connect(&self) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(self.url("/user/tokens/verify"))
            .bearer_auth(&self.token)
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
            .get(self.url("/user/tokens"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let parsed: CfList = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse tokens: {e}")))?;
        Ok(parsed
            .result
            .into_iter()
            .map(|t| Secret::new(ProviderKind::Cloudflare, t.id.clone(), t.name, t.id))
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        // Roll regenerates the value for this token id and revokes the old one.
        let resp = self
            .client
            .put(self.url(&format!("/user/tokens/{}/value", secret.external_id)))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let rolled: CfRoll = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse roll: {e}")))?;
        // The id is unchanged; the result is the new secret value.
        Ok(NewCredential::new(
            secret.external_id.clone(),
            rolled.result,
        ))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(self.url("/user/tokens/verify"))
            .bearer_auth(&cred.secret_value)
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

    // deactivate_old / delete_old: default no-ops — roll already killed the old value.
}

#[derive(Deserialize)]
struct CfList {
    result: Vec<CfToken>,
}

#[derive(Deserialize)]
struct CfToken {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct CfRoll {
    /// On a successful roll this is the new token value (a string).
    result: String,
}
