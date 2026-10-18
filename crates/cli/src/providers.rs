use std::sync::Arc;

use anyhow::{Context, Result};
use clap::ValueEnum;
use keyrotator_core::providers::{
    AnthropicConnector, AwsConnector, CloudflareConnector, DatadogConnector, DockerHubConnector,
    GithubAppConnector, GitlabConnector, NpmConnector, OpenAiConnector, SendGridConnector,
    TwilioConnector,
};
use keyrotator_core::{Connector, ProviderKind};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Provider {
    Aws,
    Gitlab,
    Cloudflare,
    Datadog,
    Npm,
    Dockerhub,
    Openai,
    Anthropic,
    Twilio,
    Sendgrid,
    GithubApp,
}

impl From<Provider> for ProviderKind {
    fn from(p: Provider) -> Self {
        match p {
            Provider::Aws => ProviderKind::Aws,
            Provider::Gitlab => ProviderKind::Gitlab,
            Provider::Cloudflare => ProviderKind::Cloudflare,
            Provider::Datadog => ProviderKind::Datadog,
            Provider::Npm => ProviderKind::Npm,
            Provider::Dockerhub => ProviderKind::DockerHub,
            Provider::Openai => ProviderKind::OpenAI,
            Provider::Anthropic => ProviderKind::Anthropic,
            Provider::Twilio => ProviderKind::Twilio,
            Provider::Sendgrid => ProviderKind::SendGrid,
            Provider::GithubApp => ProviderKind::GithubApp,
        }
    }
}

/// One credential a provider needs, with enough context to tell a first-time
/// user where to get it.
struct Cred {
    var: &'static str,
    what: &'static str,
    where_: &'static str,
    /// Known prefixes for this value; anything else gets a gentle warning.
    prefixes: &'static [&'static str],
    secret: bool,
}

/// Reads credentials from the environment, and in a terminal asks for any
/// that are missing (hidden input for secrets) instead of failing.
struct Creds {
    ask: bool,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|s| !s.trim().is_empty())
}

impl Creds {
    fn get(&self, c: &Cred) -> Result<String> {
        if let Some(v) = env(c.var) {
            warn_shape(c, &v);
            return Ok(v.trim().to_string());
        }
        if !self.ask {
            anyhow::bail!(
                "{var} isn't set — keyrotator needs {what}.\n  \
                 Get one: {where_}\n  \
                 Then run: export {var}=...\n  \
                 (Use `export`; a plain `{var}=...` line isn't visible to programs you run.)",
                var = c.var,
                what = c.what,
                where_ = c.where_,
            );
        }
        eprintln!("{} isn't set. keyrotator needs {}.", c.var, c.what);
        eprintln!("  Get one: {}", c.where_);
        let v = if c.secret {
            dialoguer::Password::new()
                .with_prompt("Paste it here (hidden; used for this run only)")
                .interact()?
        } else {
            dialoguer::Input::<String>::new()
                .with_prompt(c.var)
                .interact_text()?
        };
        let v = v.trim().to_string();
        warn_shape(c, &v);
        eprintln!(
            "  Tip: to skip this question next time, run `export {}=...` in your shell first.\n",
            c.var
        );
        Ok(v)
    }
}

/// Warn (never fail) when a value looks like it belongs to another service —
/// e.g. a GitHub token in GITLAB_TOKEN.
fn warn_shape(c: &Cred, value: &str) {
    if c.prefixes.is_empty() || c.prefixes.iter().any(|p| value.starts_with(p)) {
        return;
    }
    let known: &[(&str, &str)] = &[
        ("ghp_", "a GitHub personal access token"),
        ("github_pat_", "a GitHub personal access token"),
        ("glpat-", "a GitLab token"),
        ("sk-ant-admin", "an Anthropic admin key"),
        ("sk-ant-", "an Anthropic API key"),
        ("sk-admin-", "an OpenAI admin key"),
        ("sk-", "an OpenAI API key"),
        ("SG.", "a SendGrid key"),
        ("AKIA", "an AWS access key id"),
    ];
    let looks = known
        .iter()
        .find(|(p, _)| value.starts_with(p))
        .map(|(_, name)| format!(" It looks like {name}."))
        .unwrap_or_default();
    eprintln!(
        "Warning: {} doesn't look right — expected it to start with {}.{looks}",
        c.var,
        c.prefixes.join(" or ")
    );
}

/// Build the connector for a provider from environment configuration.
///
/// Each provider reads its own admin credential(s) from the environment so no
/// secret is passed on the command line. AWS and npm reuse their CLI sessions.
/// With `ask`, missing credentials are prompted for (never over MCP, whose
/// stdin is the protocol).
pub fn build_connector(p: Provider, ask: bool) -> Result<Arc<dyn Connector>> {
    let creds = Creds { ask };
    let need = |c: Cred| creds.get(&c);

    match p {
        Provider::Aws => Ok(Arc::new(AwsConnector::new(env("AWS_PROFILE")))),

        Provider::Gitlab => {
            let token = need(Cred {
                var: "GITLAB_TOKEN",
                what: "a GitLab personal access token with the `api` scope",
                where_: "https://gitlab.com/-/user_settings/personal_access_tokens \
                         (self-hosted GitLab: also set GITLAB_URL)",
                prefixes: &["glpat-"],
                secret: true,
            })?;
            let expiry = env("GITLAB_TOKEN_EXPIRY_DAYS").and_then(|s| s.parse().ok());
            Ok(Arc::new(GitlabConnector::new(
                env("GITLAB_URL"),
                token,
                expiry,
            )))
        }

        Provider::Cloudflare => {
            let token = need(Cred {
                var: "CLOUDFLARE_API_TOKEN",
                what: "a Cloudflare API token with the \"API Tokens: Edit\" permission",
                where_: "https://dash.cloudflare.com/profile/api-tokens",
                prefixes: &[],
                secret: true,
            })?;
            Ok(Arc::new(CloudflareConnector::new(token)))
        }

        Provider::Datadog => {
            let api = need(Cred {
                var: "DD_API_KEY",
                what: "a Datadog API key",
                where_: "https://app.datadoghq.com/organization-settings/api-keys",
                prefixes: &[],
                secret: true,
            })?;
            let app = need(Cred {
                var: "DD_APP_KEY",
                what: "a Datadog application key that can manage API keys",
                where_: "https://app.datadoghq.com/organization-settings/application-keys",
                prefixes: &[],
                secret: true,
            })?;
            Ok(Arc::new(DatadogConnector::new(env("DD_SITE"), api, app)))
        }

        Provider::Npm => Ok(Arc::new(NpmConnector::new(env("NPM_REGISTRY")))),

        Provider::Dockerhub => {
            let user = need(Cred {
                var: "DOCKERHUB_USERNAME",
                what: "your Docker Hub username",
                where_: "https://app.docker.com/settings",
                prefixes: &[],
                secret: false,
            })?;
            let pass = need(Cred {
                var: "DOCKERHUB_PASSWORD",
                what: "your Docker Hub password or an existing access token",
                where_: "https://app.docker.com/settings/personal-access-tokens",
                prefixes: &[],
                secret: true,
            })?;
            Ok(Arc::new(DockerHubConnector::new(user, pass)))
        }

        Provider::Openai => {
            let key = need(Cred {
                var: "OPENAI_ADMIN_KEY",
                what: "an OpenAI organization admin key",
                where_: "https://platform.openai.com/settings/organization/admin-keys",
                prefixes: &["sk-admin-"],
                secret: true,
            })?;
            Ok(Arc::new(OpenAiConnector::new(key)))
        }

        Provider::Anthropic => {
            let key = need(Cred {
                var: "ANTHROPIC_ADMIN_KEY",
                what: "an Anthropic Admin API key",
                where_: "https://console.anthropic.com/settings/admin-keys",
                prefixes: &["sk-ant-admin"],
                secret: true,
            })?;
            Ok(Arc::new(AnthropicConnector::new(key)))
        }

        Provider::Twilio => {
            let sid = need(Cred {
                var: "TWILIO_ACCOUNT_SID",
                what: "your Twilio Account SID",
                where_: "https://console.twilio.com (Account Info)",
                prefixes: &["AC"],
                secret: false,
            })?;
            let user = env("TWILIO_API_USER").unwrap_or_else(|| sid.clone());
            let pass = need(Cred {
                var: "TWILIO_AUTH_TOKEN",
                what: "your Twilio Auth Token (or an API key secret)",
                where_: "https://console.twilio.com (Account Info)",
                prefixes: &[],
                secret: true,
            })?;
            Ok(Arc::new(TwilioConnector::new(sid, user, pass)))
        }

        Provider::Sendgrid => {
            let key = need(Cred {
                var: "SENDGRID_API_KEY",
                what: "a SendGrid API key with the api_keys scopes",
                where_: "https://app.sendgrid.com/settings/api_keys",
                prefixes: &["SG."],
                secret: true,
            })?;
            Ok(Arc::new(SendGridConnector::new(key)))
        }

        Provider::GithubApp => {
            let app_id = need(Cred {
                var: "GITHUB_APP_ID",
                what: "your GitHub App's numeric App ID",
                where_: "your App's settings page under https://github.com/settings/apps",
                prefixes: &[],
                secret: false,
            })?;
            // Accept the PEM inline, or a path to the .pem file.
            let pem = match env("GITHUB_APP_PRIVATE_KEY") {
                Some(p) => p,
                None => {
                    let path = need(Cred {
                        var: "GITHUB_APP_PRIVATE_KEY_PATH",
                        what: "the path to your App's private key (.pem)",
                        where_: "your App's settings page → Private keys → Generate",
                        prefixes: &[],
                        secret: false,
                    })?;
                    let path = shellexpand_home(&path);
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("reading App private key at {path}"))?
                }
            };
            Ok(Arc::new(GithubAppConnector::new(app_id, pem)))
        }
    }
}

/// `~/x` → `$HOME/x`, for paths typed at a prompt (the shell didn't expand them).
pub fn shellexpand_home(path: &str) -> String {
    match (path.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => path.to_string(),
    }
}

/// The environment variables a provider's credentials come from, for error
/// messages.
pub fn credential_vars(p: Provider) -> &'static str {
    match p {
        Provider::Aws => "your aws CLI session (AWS_PROFILE / `aws sso login`)",
        Provider::Gitlab => "GITLAB_TOKEN",
        Provider::Cloudflare => "CLOUDFLARE_API_TOKEN",
        Provider::Datadog => "DD_API_KEY / DD_APP_KEY",
        Provider::Npm => "your npm login (`npm login`)",
        Provider::Dockerhub => "DOCKERHUB_USERNAME / DOCKERHUB_PASSWORD",
        Provider::Openai => "OPENAI_ADMIN_KEY",
        Provider::Anthropic => "ANTHROPIC_ADMIN_KEY",
        Provider::Twilio => "TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN",
        Provider::Sendgrid => "SENDGRID_API_KEY",
        Provider::GithubApp => "GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY_PATH",
    }
}

impl Provider {
    /// The name used on the command line and in MCP tool arguments.
    pub fn cli_name(self) -> String {
        self.to_possible_value()
            .map(|v| v.get_name().to_string())
            .unwrap_or_default()
    }

    pub fn parse(s: &str) -> Result<Self> {
        <Self as ValueEnum>::from_str(s, true).map_err(|_| {
            let names: Vec<_> = Self::value_variants()
                .iter()
                .map(|p| p.cli_name())
                .collect();
            anyhow::anyhow!(
                "unknown provider '{s}' (expected one of: {})",
                names.join(", ")
            )
        })
    }
}
