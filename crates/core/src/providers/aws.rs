use async_trait::async_trait;
use serde::Deserialize;
use tokio::process::Command;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// AWS IAM access-key rotation via the `aws` CLI.
///
/// IAM allows up to 2 access keys per user — exactly what overlap rotation
/// needs. Auth reuses whatever the `aws` CLI already has (SSO session, named
/// profile, or assumed role); we never handle the user's password.
pub struct AwsConnector {
    profile: Option<String>,
}

impl AwsConnector {
    pub fn new(profile: Option<String>) -> Self {
        Self { profile }
    }

    fn base_args(&self) -> Vec<String> {
        match &self.profile {
            Some(p) => vec!["--profile".into(), p.clone()],
            None => vec![],
        }
    }

    async fn aws(&self, args: &[&str]) -> Result<String, RotationError> {
        let mut cmd = Command::new("aws");
        cmd.args(args).args(self.base_args());
        Self::run(cmd, args).await
    }

    async fn run(mut cmd: Command, args: &[&str]) -> Result<String, RotationError> {
        let out = cmd.output().await?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(RotationError::CliFailure {
                command: format!("aws {}", args.join(" ")),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            })
        }
    }

    async fn raw_keys(&self, user_name: &str) -> Result<Vec<AccessKeyMetadata>, RotationError> {
        let stdout = self
            .aws(&[
                "iam",
                "list-access-keys",
                "--user-name",
                user_name,
                "--output",
                "json",
            ])
            .await?;
        let parsed: ListAccessKeys = serde_json::from_str(&stdout)
            .map_err(|e| RotationError::Http(format!("parse list-access-keys: {e}")))?;
        Ok(parsed.access_key_metadata)
    }
}

#[async_trait]
impl Connector for AwsConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Aws
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Overlap
    }

    async fn connect(&self) -> Result<(), RotationError> {
        self.aws(&["sts", "get-caller-identity", "--output", "json"])
            .await
            .map(|_| ())
            .map_err(|e| RotationError::NotAuthorized(e.to_string()))
    }

    async fn list_keys(&self) -> Result<Vec<Secret>, RotationError> {
        let stdout = self
            .aws(&["iam", "list-access-keys", "--output", "json"])
            .await?;
        let parsed: ListAccessKeys = serde_json::from_str(&stdout)
            .map_err(|e| RotationError::Http(format!("parse list-access-keys: {e}")))?;
        Ok(parsed
            .access_key_metadata
            .into_iter()
            .map(|m| {
                Secret::new(
                    ProviderKind::Aws,
                    m.access_key_id,
                    format!("IAM key for {}", m.user_name),
                    m.user_name,
                )
            })
            .collect())
    }

    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError> {
        // Overlap precondition: room for a second key.
        if self.raw_keys(&secret.principal).await?.len() >= 2 {
            return Err(RotationError::ProviderLimit(format!(
                "IAM user {} already has 2 access keys; retire the unused one first",
                secret.principal
            )));
        }
        let stdout = self
            .aws(&[
                "iam",
                "create-access-key",
                "--user-name",
                &secret.principal,
                "--output",
                "json",
            ])
            .await?;
        let created: CreateAccessKey = serde_json::from_str(&stdout)
            .map_err(|e| RotationError::Http(format!("parse create-access-key: {e}")))?;
        Ok(NewCredential::new(
            created.access_key.access_key_id,
            created.access_key.secret_access_key,
        ))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        // Call STS with ONLY the new key, retrying for propagation. No
        // `--profile` here, and every other credential source is cleared: a
        // profile would win over the env vars and we'd be verifying the old
        // key instead of the new one.
        let args = ["sts", "get-caller-identity", "--output", "json"];
        for attempt in 1..=6 {
            let mut cmd = Command::new("aws");
            cmd.args(args)
                .env("AWS_ACCESS_KEY_ID", &cred.external_id)
                .env("AWS_SECRET_ACCESS_KEY", &cred.secret_value);
            for var in [
                "AWS_PROFILE",
                "AWS_DEFAULT_PROFILE",
                "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN",
            ] {
                cmd.env_remove(var);
            }
            match Self::run(cmd, &args).await {
                Ok(_) => return Ok(()),
                Err(e) if attempt == 6 => {
                    return Err(RotationError::VerificationFailed(format!(
                        "new key never became usable: {e}"
                    )))
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        unreachable!()
    }

    fn supports_deactivate(&self) -> bool {
        true
    }

    async fn current_key_id(&self) -> Option<String> {
        if self.profile.is_none() {
            if let Some(id) = std::env::var("AWS_ACCESS_KEY_ID")
                .ok()
                .filter(|s| !s.is_empty())
            {
                return Some(id);
            }
        }
        // Static-key profiles; SSO / role sessions have no long-lived key id.
        self.aws(&["configure", "get", "aws_access_key_id"])
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    async fn deactivate_old(&self, external_id: &str) -> Result<(), RotationError> {
        self.aws(&[
            "iam",
            "update-access-key",
            "--access-key-id",
            external_id,
            "--status",
            "Inactive",
        ])
        .await
        .map(|_| ())
    }

    async fn delete_old(&self, external_id: &str) -> Result<(), RotationError> {
        self.aws(&["iam", "delete-access-key", "--access-key-id", external_id])
            .await
            .map(|_| ())
    }
}

// AWS CLI JSON shapes (only the fields we use).

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAccessKeys {
    access_key_metadata: Vec<AccessKeyMetadata>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AccessKeyMetadata {
    access_key_id: String,
    user_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateAccessKey {
    access_key: AccessKeyBody,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AccessKeyBody {
    access_key_id: String,
    secret_access_key: String,
}
