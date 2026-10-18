use async_trait::async_trait;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// GitHub App installation tokens.
///
/// `Ephemeral` style: instead of a long-lived PAT, the tool holds the App's
/// private key and mints a fresh **installation access token** (~1 hour) on
/// demand. "Rotation" is just minting a new one; the previous token expires by
/// itself, so there is nothing to revoke and no rollback.
///
/// The only long-lived secret is the App private key, which you rotate rarely
/// (and can hold two of) in the App's settings. This turns GitHub from the
/// provider that *can't* be automated (PATs) into the best-behaved one.
pub struct GithubAppConnector {
    client: reqwest::Client,
    app_id: String,
    private_key_pem: String,
}

impl GithubAppConnector {
    pub fn new(app_id: String, private_key_pem: String) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("keyrotator")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            app_id,
            private_key_pem,
        }
    }

    fn url(path: &str) -> String {
        format!("https://api.github.com{path}")
    }

    /// A GitHub App JWT (RS256), valid ~9 minutes, signed with the App key.
    fn app_jwt(&self) -> Result<String, RotationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let claims = Claims {
            // Backdate iat 60s to tolerate clock skew; GitHub caps exp at 10 min.
            iat: now.saturating_sub(60),
            exp: now + 9 * 60,
            iss: self.app_id.clone(),
        };
        let key = EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes())
            .map_err(|e| RotationError::NotAuthorized(format!("bad App private key: {e}")))?;
        encode(&Header::new(Algorithm::RS256), &claims, &key)
            .map_err(|e| RotationError::NotAuthorized(format!("JWT sign failed: {e}")))
    }

    fn gh(&self, rb: reqwest::RequestBuilder, bearer: &str) -> reqwest::RequestBuilder {
        rb.bearer_auth(bearer)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    async fn err_body(resp: reqwest::Response) -> RotationError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        RotationError::Http(format!("{status}: {body}"))
    }
}

#[async_trait]
impl Connector for GithubAppConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::GithubApp
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Ephemeral
    }

    async fn connect(&self) -> Result<(), RotationError> {
        let jwt = self.app_jwt()?;
        let resp = self
            .gh(self.client.get(Self::url("/app/installations")), &jwt)
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
        let jwt = self.app_jwt()?;
        let resp = self
            .gh(self.client.get(Self::url("/app/installations")), &jwt)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let installs: Vec<GhInstallation> = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse installations: {e}")))?;
        Ok(installs
            .into_iter()
            .map(|i| {
                let login = i.account.map(|a| a.login).unwrap_or_default();
                let id = i.id.to_string();
                Secret::new(
                    ProviderKind::GithubApp,
                    id.clone(),
                    format!("installation for {login}"),
                    id,
                )
            })
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        let jwt = self.app_jwt()?;
        let path = format!("/app/installations/{}/access_tokens", secret.external_id);
        let resp = self
            .gh(self.client.post(Self::url(&path)), &jwt)
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Self::err_body(resp).await);
        }
        let minted: GhToken = resp
            .json()
            .await
            .map_err(|e| RotationError::Http(format!("parse token: {e}")))?;
        // The installation id is stable; the secret is the fresh token.
        Ok(NewCredential::new(secret.external_id.clone(), minted.token))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        // An installation token can list the installation's repositories.
        let resp = self
            .gh(
                self.client
                    .get(Self::url("/installation/repositories?per_page=1")),
                &cred.secret_value,
            )
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

    // No deactivate_old / delete_old: installation tokens expire on their own.
}

#[derive(Serialize)]
struct Claims {
    iat: u64,
    exp: u64,
    iss: String,
}

#[derive(Deserialize)]
struct GhInstallation {
    id: u64,
    account: Option<GhAccount>,
}

#[derive(Deserialize)]
struct GhAccount {
    login: String,
}

#[derive(Deserialize)]
struct GhToken {
    token: String,
}
