use async_trait::async_trait;
use serde::Deserialize;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// Datadog API keys (the `DD-API-KEY` kind, not application keys).
///
/// Overlap: create a new API key, verify it, delete the old one. Management
/// calls authenticate with BOTH an existing API key and an application key
/// (the admin creds). `site` selects the region (default datadoghq.com).
pub struct DatadogConnector {
    client: reqwest::Client,
    base: String,
    api_key: String,
    app_key: String,
}

impl DatadogConnector {
    pub fn new(site: Option<String>, api_key: String, app_key: String) -> Self {
        let site = site.unwrap_or_else(|| "datadoghq.com".into());
        Self {
            client: reqwest::Client::new(),
            base: format!("https://api.{site}"),
            api_key,
            app_key,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn admin(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.header("DD-API-KEY", self.api_key.as_str())
            .header("DD-APPLICATION-KEY", self.app_key.as_str())
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }
}

#[async_trait]
impl Connector for DatadogConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Datadog
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Overlap
    }

    async fn connect(&self) -> Result<(), RotationError> {
        let resp = self
            .admin(self.client.get(self.url("/api/v2/api_keys")))
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
            .admin(self.client.get(self.url("/api/v2/api_keys")))
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let parsed: DdList = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse api_keys: {e}")))?;
        Ok(parsed
            .data
            .into_iter()
            .map(|k| {
                let name = k.attributes.name.unwrap_or_default();
                Secret::new(ProviderKind::Datadog, k.id.clone(), name, k.id)
            })
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        let body = serde_json::json!({
            "data": { "type": "api_keys", "attributes": { "name": secret.label } }
        });
        let resp = self
            .admin(self.client.post(self.url("/api/v2/api_keys")))
            .json(&body)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let created: DdCreate = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse create: {e}")))?;
        let key = created
            .data
            .attributes
            .key
            .ok_or_else(|| RotationError::Http("create response had no key value".into()))?;
        Ok(NewCredential::new(created.data.id, key))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        // /api/v1/validate checks that an API key is valid.
        let resp = self
            .client
            .get(self.url("/api/v1/validate"))
            .header("DD-API-KEY", cred.secret_value.as_str())
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

    async fn deactivate_old(&self, _external_id: &str) -> Result<(), RotationError> {
        // Datadog has no "disable" state for API keys — deletion is the revoke.
        Ok(())
    }

    async fn delete_old(&self, external_id: &str) -> Result<(), RotationError> {
        let resp = self
            .admin(
                self.client
                    .delete(self.url(&format!("/api/v2/api_keys/{external_id}"))),
            )
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
struct DdList {
    data: Vec<DdKeyMeta>,
}

#[derive(Deserialize)]
struct DdKeyMeta {
    id: String,
    attributes: DdNameAttr,
}

#[derive(Deserialize)]
struct DdNameAttr {
    name: Option<String>,
}

#[derive(Deserialize)]
struct DdCreate {
    data: DdCreatedKey,
}

#[derive(Deserialize)]
struct DdCreatedKey {
    id: String,
    attributes: DdSecretAttr,
}

#[derive(Deserialize)]
struct DdSecretAttr {
    /// The full secret, present only in the create response.
    key: Option<String>,
}
