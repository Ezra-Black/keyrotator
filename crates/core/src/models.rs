use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A provider we know how to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Aws,
    Gitlab,
    Cloudflare,
    Datadog,
    Npm,
    DockerHub,
    OpenAI,
    Anthropic,
    Twilio,
    SendGrid,
    GithubApp,
}

impl ProviderKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            ProviderKind::Aws => "AWS IAM",
            ProviderKind::Gitlab => "GitLab",
            ProviderKind::Cloudflare => "Cloudflare",
            ProviderKind::Datadog => "Datadog",
            ProviderKind::Npm => "npm",
            ProviderKind::DockerHub => "Docker Hub",
            ProviderKind::OpenAI => "OpenAI",
            ProviderKind::Anthropic => "Anthropic",
            ProviderKind::Twilio => "Twilio",
            ProviderKind::SendGrid => "SendGrid",
            ProviderKind::GithubApp => "GitHub App",
        }
    }
}

impl std::str::FromStr for ProviderKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "aws" | "aws-iam" | "iam" => Ok(ProviderKind::Aws),
            "gitlab" | "gl" => Ok(ProviderKind::Gitlab),
            "cloudflare" | "cf" => Ok(ProviderKind::Cloudflare),
            "datadog" | "dd" => Ok(ProviderKind::Datadog),
            "npm" => Ok(ProviderKind::Npm),
            "dockerhub" | "docker" | "docker-hub" => Ok(ProviderKind::DockerHub),
            "openai" => Ok(ProviderKind::OpenAI),
            "anthropic" => Ok(ProviderKind::Anthropic),
            "twilio" => Ok(ProviderKind::Twilio),
            "sendgrid" | "sg" => Ok(ProviderKind::SendGrid),
            "github-app" | "githubapp" | "gha" => Ok(ProviderKind::GithubApp),
            other => Err(format!("unknown provider '{other}'")),
        }
    }
}

/// How a provider performs rotation — this is the crux that the engine branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStyle {
    /// We control timing: create the new key while the old one still works,
    /// cut over, verify, then deactivate/delete the old one. Clean rollback.
    /// (AWS IAM: 2 keys per user give us the overlap window.)
    Overlap,
    /// The provider's rotate call mints the new secret AND revokes the old one
    /// atomically. There is no window where both are valid and no rollback to
    /// the old secret. (GitLab personal/project/group access tokens; Cloudflare
    /// roll-token endpoint.)
    AtomicRotate,
    /// The provider offers no API to mint a new secret — creation is console-only
    /// — so the tool can revoke the old one but the user must create the new one
    /// by hand. (Anthropic Admin API keys; classic GitHub PATs.) The engine does
    /// nothing destructive and returns the provider's manual instructions.
    Manual,
    /// The credential is short-lived and minted fresh each time from a long-lived
    /// secret the tool holds (e.g. a GitHub App private key). "Rotation" is just
    /// minting a new token; the old one expires on its own, so there is nothing
    /// to revoke and no rollback. (GitHub App installation tokens.)
    Ephemeral,
}

/// A place that consumes a key and must be updated when it rotates.
///
/// Every rotation needs at least one consumer: a freshly minted secret that
/// isn't delivered anywhere is a secret you've lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Consumer {
    /// Rewrite a single `VAR=value` line in a `.env` file. `id_variable`
    /// optionally also records the new key's id (e.g. `AWS_ACCESS_KEY_ID`).
    DotEnvFile {
        path: String,
        variable: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_variable: Option<String>,
    },
    /// Set a GitHub Actions repository secret via `gh secret set`.
    GithubActionsSecret { repo: String, secret_name: String },
    /// Write an AWS SSM Parameter Store `SecureString`.
    AwsSsmParameter { name: String, region: String },
    /// Write the raw secret to a file readable only by you (mode 0600).
    File { path: String },
    /// Store the secret in the OS keychain (needs the `os-keyring` feature).
    Keychain { service: String, account: String },
    /// Hand the secret back to the caller in `RotationOutcome::revealed_secret`.
    /// Never loaded from config, and never offered over MCP.
    #[serde(skip)]
    Reveal,
}

impl Consumer {
    /// A human description that never includes the secret.
    pub fn describe(&self) -> String {
        match self {
            Consumer::DotEnvFile {
                path,
                variable,
                id_variable,
            } => match id_variable {
                Some(idv) => format!("{variable} + {idv} in {path}"),
                None => format!("{variable} in {path}"),
            },
            Consumer::GithubActionsSecret { repo, secret_name } => {
                format!("GitHub secret {secret_name} in {repo}")
            }
            Consumer::AwsSsmParameter { name, region } => format!("SSM {name} ({region})"),
            Consumer::File { path } => format!("file {path}"),
            Consumer::Keychain { service, account } => {
                format!("keychain {service}/{account}")
            }
            Consumer::Reveal => "printed output".into(),
        }
    }
}

/// A single managed secret for an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub provider: ProviderKind,
    /// Provider-native identifier (AWS access key id, or GitLab token id).
    pub external_id: String,
    pub label: String,
    /// The account/principal this belongs to (IAM user name, or GitLab token id).
    pub principal: String,
    #[serde(default)]
    pub consumers: Vec<Consumer>,
}

impl Secret {
    pub fn new(
        provider: ProviderKind,
        external_id: impl Into<String>,
        label: impl Into<String>,
        principal: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            provider,
            external_id: external_id.into(),
            label: label.into(),
            principal: principal.into(),
            consumers: Vec::new(),
        }
    }
}

/// The freshly minted credential a connector hands back.
///
/// `secret_value` is sensitive — never log it or put it in an error message.
#[derive(Clone)]
pub struct NewCredential {
    pub external_id: String,
    pub secret_value: String,
}

impl NewCredential {
    pub fn new(external_id: impl Into<String>, secret_value: impl Into<String>) -> Self {
        Self {
            external_id: external_id.into(),
            secret_value: secret_value.into(),
        }
    }
}

// Keep the secret out of any accidental debug print.
impl std::fmt::Debug for NewCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewCredential")
            .field("external_id", &self.external_id)
            .field("secret_value", &"<redacted>")
            .finish()
    }
}

/// Lifecycle stages, emitted as progress so a front-end can show live status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStage {
    Creating,
    UpdatingConsumers,
    Verifying,
    DeactivatingOld,
    DeletingOld,
    RolledBack,
    Done,
    Failed,
}

/// What happened to the old key at the end of a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OldKeyState {
    /// The provider revoked it as part of the rotate call (Atomic).
    Revoked,
    /// Disabled but recoverable; run `retire` to delete it.
    Deactivated,
    /// Permanently deleted.
    Deleted,
    /// Still fully working — this provider has no disabled state, or we
    /// deliberately left it alone. Run `retire` once nothing uses it.
    StillActive,
    /// Nothing to retire (Ephemeral tokens expire on their own).
    NotApplicable,
}

/// The result of a rotation that changed something.
///
/// The engine's contract: `Err` means nothing changed (or everything was
/// rolled back). `Ok` means the provider's state changed, and `problems`
/// lists anything that still needs your attention.
#[derive(Debug, Clone)]
pub struct RotationOutcome {
    pub new_external_id: String,
    pub old_key: OldKeyState,
    pub updated_consumers: Vec<Consumer>,
    pub failed_consumers: Vec<(Consumer, String)>,
    /// Set only when a `Consumer::Reveal` was requested.
    pub revealed_secret: Option<String>,
    /// Where the secret was written if every consumer failed on a rotation
    /// that couldn't be undone.
    pub rescue_file: Option<std::path::PathBuf>,
    pub problems: Vec<String>,
}

impl RotationOutcome {
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty() && self.failed_consumers.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("not authorized: {0}")]
    NotAuthorized(String),
    #[error("provider limit reached: {0}")]
    ProviderLimit(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("consumer update failed: {0}")]
    ConsumerUpdate(String),
    #[error("command `{command}` failed: {stderr}")]
    CliFailure { command: String, stderr: String },
    #[error("http error: {0}")]
    Http(String),
    #[error("not supported: {0}")]
    NotImplemented(String),
    #[error("manual action required: {0}")]
    ManualActionRequired(String),
    #[error(
        "nowhere to put the new secret for {0} — refusing to rotate. \
         Add a consumer (e.g. --dotenv, --secret-file, --print-secret, or a keyrotator.toml entry)."
    )]
    NoDestination(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
