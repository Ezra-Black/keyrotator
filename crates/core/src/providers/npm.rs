use async_trait::async_trait;
use std::io::Write;
use tokio::process::Command;

use crate::connector::Connector;
use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// npm classic automation tokens, via the `npm` CLI.
///
/// Overlap: `npm token create` mints a new token, we verify with `npm whoami`,
/// then `npm token revoke <id>` kills the old one. Auth reuses the logged-in
/// npm session (`npm login` / an `~/.npmrc` authToken).
///
/// Best-effort: the CLI has no stable `--json` for `token`, so this parses
/// human output and targets classic tokens. Granular/fine-grained tokens are
/// web-only and not handled here.
pub struct NpmConnector {
    registry: String,
}

impl NpmConnector {
    pub fn new(registry: Option<String>) -> Self {
        Self {
            registry: registry.unwrap_or_else(|| "https://registry.npmjs.org/".into()),
        }
    }

    async fn npm(
        &self,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Result<String, RotationError> {
        let mut cmd = Command::new("npm");
        cmd.args(args).args(["--registry", self.registry.as_str()]);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let out = cmd.output().await?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(RotationError::CliFailure {
                command: format!("npm {}", args.join(" ")),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            })
        }
    }

    /// Pull a token value out of `npm token create` output (npm_… or a UUID).
    fn extract_token(out: &str) -> Option<String> {
        out.split(|c: char| c.is_whitespace() || c == '│' || c == '|')
            .map(|s| s.trim())
            .find(|s| {
                s.starts_with("npm_")
                    || (s.len() == 36 && s.chars().filter(|&c| c == '-').count() == 4)
            })
            .map(|s| s.to_string())
    }

    /// Pull token ids out of `npm token list` rows (short hex identifiers).
    fn extract_ids(out: &str) -> Vec<String> {
        out.lines()
            .flat_map(|line| line.split(|c: char| c.is_whitespace() || c == '│' || c == '|'))
            .map(|s| s.trim())
            .filter(|s| s.len() >= 6 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .map(|s| s.to_string())
            .collect()
    }
}

#[async_trait]
impl Connector for NpmConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Npm
    }

    fn rotation_style(&self) -> RotationStyle {
        RotationStyle::Overlap
    }

    async fn connect(&self) -> Result<(), RotationError> {
        self.npm(&["whoami"], &[])
            .await
            .map(|_| ())
            .map_err(|e| RotationError::NotAuthorized(e.to_string()))
    }

    async fn list_keys(&self) -> Result<Vec<Secret>, RotationError> {
        let out = self.npm(&["token", "list"], &[]).await?;
        Ok(Self::extract_ids(&out)
            .into_iter()
            .map(|id| Secret::new(ProviderKind::Npm, id.clone(), "npm token".to_string(), id))
            .collect())
    }

    async fn create(&self, _secret: &Secret) -> Result<NewCredential, RotationError> {
        let out = self.npm(&["token", "create"], &[]).await?;
        let token = Self::extract_token(&out).ok_or_else(|| {
            RotationError::Http("could not parse a new token from `npm token create` output".into())
        })?;
        // `npm token create` doesn't reliably print the new token's id, and
        // deriving one from the token value would leak part of the secret.
        Ok(NewCredential::new(
            "(new npm token — see `npm token list`)",
            token,
        ))
    }

    async fn verify(&self, cred: &NewCredential) -> Result<(), RotationError> {
        // Write a throwaway .npmrc so the token never lands in argv, then whoami.
        let mut file = tempfile_npmrc(&self.registry, &cred.secret_value)?;
        let path = file.1.clone();
        file.0.flush().ok();
        let res = self
            .npm(&["whoami"], &[("NPM_CONFIG_USERCONFIG", path.as_str())])
            .await
            .map(|_| ())
            .map_err(|e| RotationError::VerificationFailed(e.to_string()));
        let _ = std::fs::remove_file(&path);
        res
    }

    // No deactivate_old: npm tokens have no disabled state; revoke is delete.

    async fn delete_old(&self, external_id: &str) -> Result<(), RotationError> {
        self.npm(&["token", "revoke", external_id], &[])
            .await
            .map(|_| ())
    }
}

/// Create a temp .npmrc containing the auth token; returns (handle, path).
fn tempfile_npmrc(registry: &str, token: &str) -> Result<(std::fs::File, String), RotationError> {
    let host = registry
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let path = std::env::temp_dir().join(format!(
        "rekey-npmrc-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path)?;
    writeln!(f, "//{host}:_authToken={token}")?;
    Ok((f, path.to_string_lossy().into_owned()))
}
