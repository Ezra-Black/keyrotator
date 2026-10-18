use async_trait::async_trait;
use serde::Deserialize;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// Twilio API keys (Standard keys under an account).
///
/// Overlap: create a new key (returns sid + secret, secret shown once), verify,
/// delete the old one. Auth is HTTP Basic with the Account SID and Auth Token
/// (or an existing API key sid/secret).
pub struct TwilioConnector {
    client: reqwest::Client,
    account_sid: String,
    auth_user: String,
    auth_pass: String,
}

impl TwilioConnector {
    /// `auth_user`/`auth_pass` are the Account SID + Auth Token, or an API key
    /// SID + secret with permission to manage keys.
    pub fn new(account_sid: String, auth_user: String, auth_pass: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            account_sid,
            auth_user,
            auth_pass,
        }
    }

    fn url(&self, path: &str) -> String {
        format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}{path}",
            self.account_sid
        )
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }
}

#[async_trait]
impl Connector for TwilioConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Twilio
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Overlap
    }

    async fn connect(&self) -> Result<(), RotationError> {
        let resp = self
            .client
            .get(self.url(".json"))
            .basic_auth(&self.auth_user, Some(&self.auth_pass))
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
            .get(self.url("/Keys.json"))
            .basic_auth(&self.auth_user, Some(&self.auth_pass))
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let parsed: TwList = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse keys: {e}")))?;
        Ok(parsed
            .keys
            .into_iter()
            .map(|k| {
                let name = k.friendly_name.unwrap_or_default();
                Secret::new(ProviderKind::Twilio, k.sid.clone(), name, k.sid)
            })
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        let resp = self
            .client
            .post(self.url("/Keys.json"))
            .basic_auth(&self.auth_user, Some(&self.auth_pass))
            .form(&[("FriendlyName", secret.label.as_str())])
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let created: TwCreate = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse create: {e}")))?;
        let secret_val = created
            .secret
            .ok_or_else(|| RotationError::Http("create response had no secret".into()))?;
        Ok(NewCredential::new(created.sid, secret_val))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        // Use the new key (sid + secret) as Basic auth against the account.
        let resp = self
            .client
            .get(self.url(".json"))
            .basic_auth(&cred.external_id, Some(&cred.secret_value))
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
            .delete(self.url(&format!("/Keys/{external_id}.json")))
            .basic_auth(&self.auth_user, Some(&self.auth_pass))
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
struct TwList {
    keys: Vec<TwKeyMeta>,
}

#[derive(Deserialize)]
struct TwKeyMeta {
    sid: String,
    friendly_name: Option<String>,
}

#[derive(Deserialize)]
struct TwCreate {
    sid: String,
    /// Secret is only returned when the key is created.
    secret: Option<String>,
}
