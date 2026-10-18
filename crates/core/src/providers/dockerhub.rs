use async_trait::async_trait;
use serde::Deserialize;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// Docker Hub personal access tokens.
///
/// Overlap: create a new PAT (value shown once), verify, delete the old one by
/// uuid. All management calls use a short-lived JWT obtained by logging in with
/// the username and a password (or an existing PAT) — we fetch a fresh JWT per
/// operation rather than hold state.
pub struct DockerHubConnector {
    client: reqwest::Client,
    username: String,
    password: String,
}

impl DockerHubConnector {
    pub fn new(username: String, password: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            username,
            password,
        }
    }

    fn url(path: &str) -> String {
        format!("https://hub.docker.com{path}")
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }

    /// Log in and return a JWT for subsequent authenticated calls.
    async fn jwt(&self, username: &str, password: &str) -> Result<String, RotationError> {
        let resp = self
            .client
            .post(Self::url("/v2/users/login"))
            .json(&serde_json::json!({ "username": username, "password": password }))
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(RotationError::NotAuthorized(
                Self::err_body(resp).await.to_string(),
            ));
        }
        let login: DhLogin = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse login: {e}")))?;
        Ok(login.token)
    }
}

#[async_trait]
impl Connector for DockerHubConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::DockerHub
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Overlap
    }

    async fn connect(&self) -> Result<(), RotationError> {
        self.jwt(&self.username, &self.password).await.map(|_| ())
    }

    async fn list_keys(&self) -> Result<Vec<Secret>, RotationError> {
        let jwt = self.jwt(&self.username, &self.password).await?;
        let resp = self
            .client
            .get(Self::url("/v2/access-tokens"))
            .bearer_auth(&jwt)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let parsed: DhList = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse tokens: {e}")))?;
        Ok(parsed
            .results
            .into_iter()
            .map(|t| {
                let label = t.token_label.unwrap_or_default();
                Secret::new(
                    ProviderKind::DockerHub,
                    t.uuid.clone(),
                    label,
                    self.username.clone(),
                )
            })
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        let jwt = self.jwt(&self.username, &self.password).await?;
        let label = if secret.label.is_empty() {
            "keyrotator".to_string()
        } else {
            secret.label.clone()
        };
        let body =
            serde_json::json!({ "token_label": label, "scopes": ["repo:read", "repo:write"] });
        let resp = self
            .client
            .post(Self::url("/v2/access-tokens"))
            .bearer_auth(&jwt)
            .json(&body)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let created: DhCreate = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse create: {e}")))?;
        Ok(NewCredential::new(created.uuid, created.token))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        // A PAT works as the login password; success means the new token is live.
        self.jwt(&self.username, &cred.secret_value)
            .await
            .map(|_| ())
    }

    async fn delete_old(&self, external_id: &str) -> Result<(), RotationError> {
        let jwt = self.jwt(&self.username, &self.password).await?;
        let resp = self
            .client
            .delete(Self::url(&format!("/v2/access-tokens/{external_id}")))
            .bearer_auth(&jwt)
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
struct DhLogin {
    token: String,
}

#[derive(Deserialize)]
struct DhList {
    results: Vec<DhTokenMeta>,
}

#[derive(Deserialize)]
struct DhTokenMeta {
    uuid: String,
    token_label: Option<String>,
}

#[derive(Deserialize)]
struct DhCreate {
    uuid: String,
    /// The secret token, returned only on creation.
    token: String,
}
