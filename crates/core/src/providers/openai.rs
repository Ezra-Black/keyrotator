use async_trait::async_trait;
use serde::Deserialize;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// OpenAI organization **admin** API keys.
///
/// Overlap: create a new admin key (value returned only on create), verify,
/// delete the old one. Auth is a Bearer admin key.
///
/// Note: this rotates *admin* keys. The `sk-...` project keys applications use
/// are best rotated by creating a project service account key — a separate
/// endpoint — which can be added as its own connector variant.
pub struct OpenAiConnector {
    client: reqwest::Client,
    admin_key: String,
}

impl OpenAiConnector {
    pub fn new(admin_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            admin_key,
        }
    }

    fn url(path: &str) -> String {
        format!("https://api.openai.com/v1{path}")
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }
}

#[async_trait]
impl Connector for OpenAiConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::OpenAI
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Overlap
    }

    async fn connect(&self) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(Self::url("/organization/admin_api_keys"))
            .bearer_auth(&self.admin_key)
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
            .get(Self::url("/organization/admin_api_keys"))
            .bearer_auth(&self.admin_key)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let parsed: OaList = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse admin keys: {e}")))?;
        Ok(parsed
            .data
            .into_iter()
            .map(|k| {
                Secret::new(
                    ProviderKind::OpenAI,
                    k.id.clone(),
                    k.name.unwrap_or_default(),
                    k.id,
                )
            })
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        let body = serde_json::json!({ "name": secret.label });
        let resp = self
            .client
            .post(Self::url("/organization/admin_api_keys"))
            .bearer_auth(&self.admin_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let created: OaCreated = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse create: {e}")))?;
        let value = created
            .value
            .ok_or_else(|| RotationError::Http("create response had no key value".into()))?;
        Ok(NewCredential::new(created.id, value))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(Self::url("/organization/admin_api_keys"))
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
            .delete(Self::url(&format!(
                "/organization/admin_api_keys/{external_id}"
            )))
            .bearer_auth(&self.admin_key)
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
struct OaList {
    data: Vec<OaKeyMeta>,
}

#[derive(Deserialize)]
struct OaKeyMeta {
    id: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct OaCreated {
    id: String,
    /// Full secret, present only on create.
    value: Option<String>,
}
