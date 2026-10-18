use std::fs;
use std::path::Path;
use tokio::process::Command;

use crate::models::{Consumer, NewCredential, RotationError};

/// Pushes a freshly minted secret value to every place that consumes it.
/// A new key is useless until `.env` files, CI secrets, SSM params, etc. carry
/// it — this is the half of rotation that keeps the user's apps from breaking.
#[derive(Default)]
pub struct ConsumerUpdater;

impl ConsumerUpdater {
    pub async fn update(
        &self,
        consumer: &Consumer,
        cred: &NewCredential,
    ) -> Result<(), RotationError> {
        match consumer {
            Consumer::DotEnvFile { path, variable } => {
                update_dotenv(path, variable, &cred.secret_value)
            }
            Consumer::GithubActionsSecret { repo, secret_name } => {
                let out = Command::new("gh")
                    .args([
                        "secret",
                        "set",
                        secret_name,
                        "--repo",
                        repo,
                        "--body",
                        &cred.secret_value,
                    ])
                    .output()
                    .await?;
                if out.status.success() {
                    Ok(())
                } else {
                    Err(RotationError::ConsumerUpdate(format!(
                        "gh secret set {secret_name}: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )))
                }
            }
            Consumer::AwsSsmParameter { name, region } => {
                let out = Command::new("aws")
                    .args([
                        "ssm",
                        "put-parameter",
                        "--name",
                        name,
                        "--type",
                        "SecureString",
                        "--overwrite",
                        "--region",
                        region,
                        "--value",
                        &cred.secret_value,
                    ])
                    .output()
                    .await?;
                if out.status.success() {
                    Ok(())
                } else {
                    Err(RotationError::ConsumerUpdate(format!(
                        "ssm put-parameter {name}: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )))
                }
            }
        }
    }
}

/// In-place edit of a single VAR=value line, preserving the rest of the file.
fn update_dotenv(path: &str, variable: &str, value: &str) -> Result<(), RotationError> {
    let p = Path::new(path);
    let original = fs::read_to_string(p).unwrap_or_default();
    let prefix = format!("{variable}=");
    let new_line = format!("{variable}={value}");

    let mut lines: Vec<String> = if original.is_empty() {
        Vec::new()
    } else {
        original.lines().map(|s| s.to_string()).collect()
    };

    if let Some(idx) = lines.iter().position(|l| l.starts_with(&prefix)) {
        lines[idx] = new_line;
    } else {
        lines.push(new_line);
    }
    fs::write(p, lines.join("\n"))?;
    Ok(())
}
