use async_trait::async_trait;
use serde::Deserialize;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// SendGrid API keys.
///
/// Overlap: create a new key (carrying the old key's scopes), verify, delete
/// the old one. Auth is a Bearer key that itself holds `api_keys.create` /
/// `.read` / `.delete` scopes.
pub struct SendGridConnector {
    client: reqwest::Client,
    token: String,
}

impl SendGridConnector {
    pub fn new(token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://api.sendgrid.com{path}")
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }

    /// Fetch the scopes of an existing key so the replacement matches it.
    async fn scopes_of(&self, id: &str) -> Result<Vec<String>, RotationError> {
        let resp = self
            .client
            .get(self.url(&format!("/v3/api_keys/{id}")))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let detail: SgKeyDetail = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse key detail: {e}")))?;
        Ok(detail.scopes.unwrap_or_default())
    }
}

#[async_trait]
impl Connector for SendGridConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::SendGrid
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Overlap
    }

    async fn connect(&self) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(self.url("/v3/scopes"))
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
            .get(self.url("/v3/api_keys"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let parsed: SgList = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse api_keys: {e}")))?;
        Ok(parsed
            .result
            .into_iter()
            .map(|k| {
                Secret::new(
                    ProviderKind::SendGrid,
                    k.api_key_id.clone(),
                    k.name,
                    k.api_key_id,
                )
            })
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        let scopes = self
            .scopes_of(&secret.external_id)
            .await
            .unwrap_or_default();
        let body = serde_json::json!({ "name": secret.label, "scopes": scopes });
        let resp = self
            .client
            .post(self.url("/v3/api_keys"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let created: SgCreate = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse create: {e}")))?;
        Ok(NewCredential::new(created.api_key_id, created.api_key))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(self.url("/v3/scopes"))
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

    async fn delete_old(&self, external_id: &str) -> Result<(), RotationError> {
        let resp = self
            .client
            .delete(self.url(&format!("/v3/api_keys/{external_id}")))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::err_body(resp).await)
        }
    }
}

#[derive(Deserialize)]
struct SgList {
    result: Vec<SgKeyMeta>,
}

#[derive(Deserialize)]
struct SgKeyMeta {
    api_key_id: String,
    name: String,
}

#[derive(Deserialize)]
struct SgKeyDetail {
    scopes: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct SgCreate {
    api_key_id: String,
    /// Full key, present only in the create response.
    api_key: String,
}
