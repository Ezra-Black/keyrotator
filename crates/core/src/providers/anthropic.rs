use async_trait::async_trait;
use serde::Deserialize;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// Anthropic Admin API keys.
///
/// `Manual` style: the Admin API can list and **deactivate** keys but offers no
/// endpoint to create one (keys are minted in the Console), so the tool can't
/// fully auto-rotate. `list_keys` and `deactivate_old` work against the Admin
/// API; `create` is intentionally unsupported and the engine surfaces the
/// manual step via `manual_rotation_hint`.
///
/// Auth is an Admin API key in the `x-api-key` header.
pub struct AnthropicConnector {
    client: reqwest::Client,
    admin_key: String,
}

impl AnthropicConnector {
    pub fn new(admin_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            admin_key,
        }
    }

    fn url(path: &str) -> String {
        format!("https://api.anthropic.com/v1{path}")
    }

    fn admin(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.header("x-api-key", self.admin_key.as_str())
            .header("anthropic-version", "2023-06-01")
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }
}

#[async_trait]
impl Connector for AnthropicConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Anthropic
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Manual
    }

    fn manual_rotation_hint(&self) -> Option<String> {
        Some(
            "Anthropic keys can't be created via the Admin API. Create a new key at \
             https://console.anthropic.com/settings/keys, point your consumers at it, \
             then revoke the old one (the tool can deactivate it by id)."
                .to_string(),
        )
    }

    async fn connect(&self) -> Result<(), RotationError> {
        let resp = self
            .admin(self.client.get(Self::url("/organizations/api_keys")))
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
            .admin(self.client.get(Self::url("/organizations/api_keys")))
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let parsed: AnList = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse api_keys: {e}")))?;
        Ok(parsed
            .data
            .into_iter()
            .map(|k| {
                Secret::new(
                    ProviderKind::Anthropic,
                    k.id.clone(),
                    k.name.unwrap_or_default(),
                    k.id,
                )
            })
            .collect())
    }

    async fn create(&self, _secret: &Secret) -> Result<NewCredential, RotationError> {
        Err(RotationError::ManualActionRequired(
            self.manual_rotation_hint().unwrap_or_default(),
        ))
    }

    async fn verify(&self, _cred: &NewCredential) -> Result<(), RotationError> {
        Ok(())
    }

    fn supports_deactivate(&self) -> bool {
        true
    }

    async fn deactivate_old(&self, external_id: &str) -> Result<(), RotationError> {
        // Admin API updates a key's status; "inactive" revokes it.
        let body = serde_json::json!({ "status": "inactive" });
        let resp = self
            .admin(
                self.client
                    .post(Self::url(&format!("/organizations/api_keys/{external_id}"))),
            )
            .json(&body)
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
struct AnList {
    data: Vec<AnKeyMeta>,
}

#[derive(Deserialize)]
struct AnKeyMeta {
    id: String,
    name: Option<String>,
}
