use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use keyrotator_core::providers::{
    AnthropicConnector, AwsConnector, CloudflareConnector, DatadogConnector, DockerHubConnector,
    GithubAppConnector, GitlabConnector, NpmConnector, OpenAiConnector, SendGridConnector,
    TwilioConnector,
};
use keyrotator_core::{Connector, ProviderKind, RotationEngine, RotationStage};

/// Auto-rotate API keys across the accounts you administer.
#[derive(Parser)]
#[command(name = "keyrotator", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check that a provider's credentials work and you can manage its keys.
    Connect {
        #[arg(value_enum)]
        provider: Provider,
    },
    /// List the keys discovered for a provider.
    List {
        #[arg(value_enum)]
        provider: Provider,
    },
    /// Rotate a single key by its external id (AWS access key id / GitLab token id).
    Rotate {
        #[arg(value_enum)]
        provider: Provider,
        /// The key/token id to rotate.
        id: String,
        /// Delete the old credential immediately instead of after a grace period (AWS only).
        #[arg(long)]
        delete_old_now: bool,
    },
    /// Rotate every discovered key for a provider.
    RotateAll {
        #[arg(value_enum)]
        provider: Provider,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Provider {
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

/// Build the connector for a provider from environment configuration.
///
/// Each provider reads its own admin credential(s) from the environment so no
/// secret is passed on the command line. AWS and npm reuse their CLI sessions.
fn build_connector(p: Provider) -> Result<Arc<dyn Connector>> {
    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    let need = |k: &str, hint: &str| -> Result<String> {
        env(k).with_context(|| format!("set {k} ({hint})"))
    };

    match p {
        Provider::Aws => Ok(Arc::new(AwsConnector::new(env("AWS_PROFILE")))),

        Provider::Gitlab => {
            let token = need("GITLAB_TOKEN", "a PAT with `api` scope")?;
            let expiry = env("GITLAB_TOKEN_EXPIRY_DAYS").and_then(|s| s.parse().ok());
            Ok(Arc::new(GitlabConnector::new(
                env("GITLAB_URL"),
                token,
                expiry,
            )))
        }

        Provider::Cloudflare => {
            let token = need("CLOUDFLARE_API_TOKEN", "a token with API Tokens Write")?;
            Ok(Arc::new(CloudflareConnector::new(token)))
        }

        Provider::Datadog => {
            let api = need("DD_API_KEY", "a Datadog API key")?;
            let app = need("DD_APP_KEY", "a Datadog application key")?;
            Ok(Arc::new(DatadogConnector::new(env("DD_SITE"), api, app)))
        }

        Provider::Npm => Ok(Arc::new(NpmConnector::new(env("NPM_REGISTRY")))),

        Provider::Dockerhub => {
            let user = need("DOCKERHUB_USERNAME", "your Docker Hub username")?;
            let pass = need("DOCKERHUB_PASSWORD", "password or an existing PAT")?;
            Ok(Arc::new(DockerHubConnector::new(user, pass)))
        }

        Provider::Openai => {
            let key = need("OPENAI_ADMIN_KEY", "an organization admin key")?;
            Ok(Arc::new(OpenAiConnector::new(key)))
        }

        Provider::Anthropic => {
            let key = need("ANTHROPIC_ADMIN_KEY", "an Admin API key")?;
            Ok(Arc::new(AnthropicConnector::new(key)))
        }

        Provider::Twilio => {
            let sid = need("TWILIO_ACCOUNT_SID", "your Account SID")?;
            let user = env("TWILIO_API_USER").unwrap_or_else(|| sid.clone());
            let pass = need("TWILIO_AUTH_TOKEN", "Auth Token or API key secret")?;
            Ok(Arc::new(TwilioConnector::new(sid, user, pass)))
        }

        Provider::Sendgrid => {
            let key = need("SENDGRID_API_KEY", "a key with api_keys.* scopes")?;
            Ok(Arc::new(SendGridConnector::new(key)))
        }

        Provider::GithubApp => {
            let app_id = need("GITHUB_APP_ID", "your GitHub App's numeric ID")?;
            // Accept the PEM inline, or a path to the .pem file.
            let pem = match env("GITHUB_APP_PRIVATE_KEY") {
                Some(p) => p,
                None => {
                    let path = need(
                        "GITHUB_APP_PRIVATE_KEY_PATH",
                        "path to the App's .pem (or set GITHUB_APP_PRIVATE_KEY)",
                    )?;
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("reading App private key at {path}"))?
                }
            };
            Ok(Arc::new(GithubAppConnector::new(app_id, pem)))
        }
    }
}

fn progress() -> keyrotator_core::engine::ProgressFn {
    Arc::new(|_id, stage: RotationStage, msg: &str| {
        let tag = match stage {
            RotationStage::Done => "✓",
            RotationStage::Failed | RotationStage::RolledBack => "✗",
            _ => "·",
        };
        eprintln!("  {tag} {msg}");
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Connect { provider } => {
            let c = build_connector(provider)?;
            c.connect().await.map_err(|e| anyhow::anyhow!(e))?;
            println!(
                "Connected to {}.",
                ProviderKind::from(provider).display_name()
            );
        }

        Command::List { provider } => {
            let c = build_connector(provider)?;
            let keys = c.list_keys().await.map_err(|e| anyhow::anyhow!(e))?;
            if keys.is_empty() {
                println!("No keys found.");
            }
            for k in keys {
                println!("{}  {}  ({})", mask(&k.external_id), k.label, k.principal);
            }
        }

        Command::Rotate {
            provider,
            id,
            delete_old_now,
        } => {
            let c = build_connector(provider)?;
            let keys = c.list_keys().await.map_err(|e| anyhow::anyhow!(e))?;
            let secret = keys
                .into_iter()
                .find(|s| s.external_id == id)
                .with_context(|| format!("no key with id {id} for this account"))?;

            let engine = RotationEngine::new(vec![c]).on_progress(progress());
            println!("Rotating {}…", secret.label);
            let new_id = engine
                .rotate(&secret, delete_old_now)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            println!("Done. New id: {}", mask(&new_id));
        }

        Command::RotateAll { provider } => {
            let c = build_connector(provider)?;
            let keys = c.list_keys().await.map_err(|e| anyhow::anyhow!(e))?;
            let engine = RotationEngine::new(vec![c]).on_progress(progress());

            println!("Rotating {} key(s)…", keys.len());
            let results = engine.rotate_all(&keys).await;

            let mut failures = 0;
            for key in &keys {
                match results.get(&key.id) {
                    Some(Ok(new_id)) => println!("  ✓ {} → {}", key.label, mask(new_id)),
                    Some(Err(e)) => {
                        failures += 1;
                        println!("  ✗ {}: {e}", key.label);
                    }
                    None => {}
                }
            }
            if failures > 0 {
                anyhow::bail!("{failures} key(s) failed to rotate");
            }
        }
    }

    Ok(())
}

/// Never print a full key id.
fn mask(id: &str) -> String {
    if id.chars().count() <= 8 {
        "••••".into()
    } else {
        let chars: Vec<char> = id.chars().collect();
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}…{tail}")
    }
}
