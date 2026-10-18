use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::ValueEnum;
use keyrotator_core::credstore::{self, LOGIN_SERVICE};
use keyrotator_core::providers::{
    AnthropicConnector, AwsConnector, CloudflareConnector, DatadogConnector, DockerHubConnector,
    GithubAppConnector, GitlabConnector, NpmConnector, OpenAiConnector, SendGridConnector,
    TwilioConnector,
};
use keyrotator_core::{Connector, ProviderKind};

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
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
pub struct Cred {
    pub var: &'static str,
    pub what: &'static str,
    pub where_: &'static str,
    /// Known prefixes for this value; anything else gets a gentle warning.
    pub prefixes: &'static [&'static str],
    pub secret: bool,
    /// Another variable that satisfies this one when set instead.
    pub alt: Option<&'static str>,
}

/// A setting that has a sensible default, offered at `login`.
pub struct Setting {
    pub var: &'static str,
    pub prompt: &'static str,
    pub default: &'static str,
}

const fn cred(
    var: &'static str,
    what: &'static str,
    where_: &'static str,
    prefixes: &'static [&'static str],
    secret: bool,
) -> Cred {
    Cred {
        var,
        what,
        where_,
        prefixes,
        secret,
        alt: None,
    }
}

/// The credentials each provider needs.
pub fn required_creds(p: Provider) -> Vec<Cred> {
    match p {
        Provider::Aws | Provider::Npm => vec![],
        Provider::Gitlab => vec![cred(
            "GITLAB_TOKEN",
            "a GitLab personal access token with the `api` scope",
            "https://gitlab.com/-/user_settings/personal_access_tokens \
             (self-hosted GitLab: also set GITLAB_URL)",
            &["glpat-"],
            true,
        )],
        Provider::Cloudflare => vec![cred(
            "CLOUDFLARE_API_TOKEN",
            "a Cloudflare API token with the \"API Tokens: Edit\" permission",
            "https://dash.cloudflare.com/profile/api-tokens",
            &[],
            true,
        )],
        Provider::Datadog => vec![
            cred(
                "DD_API_KEY",
                "a Datadog API key",
                "https://app.datadoghq.com/organization-settings/api-keys",
                &[],
                true,
            ),
            cred(
                "DD_APP_KEY",
                "a Datadog application key that can manage API keys",
                "https://app.datadoghq.com/organization-settings/application-keys",
                &[],
                true,
            ),
        ],
        Provider::Dockerhub => vec![
            cred(
                "DOCKERHUB_USERNAME",
                "your Docker Hub username",
                "https://app.docker.com/settings",
                &[],
                false,
            ),
            cred(
                "DOCKERHUB_PASSWORD",
                "your Docker Hub password or an existing access token",
                "https://app.docker.com/settings/personal-access-tokens",
                &[],
                true,
            ),
        ],
        Provider::Openai => vec![cred(
            "OPENAI_ADMIN_KEY",
            "an OpenAI organization admin key",
            "https://platform.openai.com/settings/organization/admin-keys",
            &["sk-admin-"],
            true,
        )],
        Provider::Anthropic => vec![cred(
            "ANTHROPIC_ADMIN_KEY",
            "an Anthropic Admin API key",
            "https://console.anthropic.com/settings/admin-keys",
            &["sk-ant-admin"],
            true,
        )],
        Provider::Twilio => vec![
            cred(
                "TWILIO_ACCOUNT_SID",
                "your Twilio Account SID",
                "https://console.twilio.com (Account Info)",
                &["AC"],
                false,
            ),
            cred(
                "TWILIO_AUTH_TOKEN",
                "your Twilio Auth Token (or an API key secret)",
                "https://console.twilio.com (Account Info)",
                &[],
                true,
            ),
        ],
        Provider::Sendgrid => vec![cred(
            "SENDGRID_API_KEY",
            "a SendGrid API key with the api_keys scopes",
            "https://app.sendgrid.com/settings/api_keys",
            &["SG."],
            true,
        )],
        Provider::GithubApp => vec![
            cred(
                "GITHUB_APP_ID",
                "your GitHub App's numeric App ID",
                "your App's settings page under https://github.com/settings/apps",
                &[],
                false,
            ),
            Cred {
                alt: Some("GITHUB_APP_PRIVATE_KEY"),
                ..cred(
                    "GITHUB_APP_PRIVATE_KEY_PATH",
                    "the path to your App's private key (.pem)",
                    "your App's settings page → Private keys → Generate",
                    &[],
                    false,
                )
            },
        ],
    }
}

/// Optional settings read from the environment or a saved login.
fn optional_vars(p: Provider) -> &'static [&'static str] {
    match p {
        Provider::Aws => &["AWS_PROFILE"],
        Provider::Gitlab => &["GITLAB_URL", "GITLAB_TOKEN_EXPIRY_DAYS"],
        Provider::Datadog => &["DD_SITE"],
        Provider::Npm => &["NPM_REGISTRY"],
        Provider::Twilio => &["TWILIO_API_USER"],
        Provider::GithubApp => &["GITHUB_APP_PRIVATE_KEY"],
        _ => &[],
    }
}

/// Settings worth asking about at `login` (only saved when not the default).
pub fn login_settings(p: Provider) -> &'static [Setting] {
    match p {
        Provider::Gitlab => &[Setting {
            var: "GITLAB_URL",
            prompt: "GitLab URL (change it for self-hosted GitLab)",
            default: "https://gitlab.com",
        }],
        Provider::Datadog => &[Setting {
            var: "DD_SITE",
            prompt: "Datadog site",
            default: "datadoghq.com",
        }],
        _ => &[],
    }
}

/// Every variable a saved login for this provider may hold.
pub fn login_vars(p: Provider) -> Vec<&'static str> {
    let mut vars: Vec<_> = required_creds(p).iter().map(|c| c.var).collect();
    vars.extend(optional_vars(p));
    vars
}

/// The variable holding the token keyrotator signs in with, for providers
/// whose own login token can be rotated (so a saved login can follow it).
pub fn login_token_var(p: Provider) -> Option<&'static str> {
    match p {
        Provider::Gitlab => Some("GITLAB_TOKEN"),
        Provider::Cloudflare => Some("CLOUDFLARE_API_TOKEN"),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Env,
    Saved,
    Prompt,
}

/// Where each credential came from in this run, for error messages.
static SOURCES: Mutex<Vec<(&'static str, Source)>> = Mutex::new(Vec::new());

pub fn source_of(var: &str) -> Option<Source> {
    SOURCES
        .lock()
        .unwrap()
        .iter()
        .find(|(v, _)| *v == var)
        .map(|(_, s)| *s)
}

fn env(k: &str) -> Option<String> {
    std::env::var(k)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Environment first (so CI and one-off overrides win), then a saved login.
fn lookup(var: &str) -> Option<(String, Source)> {
    env(var)
        .map(|v| (v, Source::Env))
        .or_else(|| credstore::get(LOGIN_SERVICE, var).map(|v| (v, Source::Saved)))
}

/// Credential values for one provider, with where each came from.
#[derive(Default)]
pub struct Resolved {
    values: HashMap<&'static str, (String, Source)>,
}

impl Resolved {
    fn get(&self, var: &str) -> Option<String> {
        self.values.get(var).map(|(v, _)| v.clone())
    }

    fn need(&self, var: &str) -> Result<String> {
        self.get(var).with_context(|| format!("{var} is not set"))
    }

    pub fn insert(&mut self, var: &'static str, value: String, source: Source) {
        self.values.insert(var, (value, source));
    }

    fn prompted(&self) -> Vec<(&'static str, String)> {
        self.values
            .iter()
            .filter(|(_, (_, s))| *s == Source::Prompt)
            .map(|(k, (v, _))| (*k, v.clone()))
            .collect()
    }

    pub fn entries(&self) -> Vec<(&'static str, String)> {
        self.values
            .iter()
            .map(|(k, (v, _))| (*k, v.clone()))
            .collect()
    }
}

/// Ask for one credential: hidden input for secrets.
pub fn prompt_cred(c: &Cred) -> Result<String> {
    eprintln!("keyrotator needs {} ({}).", c.what, c.var);
    eprintln!("  Get one: {}", c.where_);
    let v = if c.secret {
        dialoguer::Password::new()
            .with_prompt("Paste it here (input is hidden)")
            .interact()?
    } else {
        dialoguer::Input::<String>::new()
            .with_prompt(c.var)
            .interact_text()?
    };
    let v = v.trim().to_string();
    warn_shape(c, &v);
    Ok(v)
}

fn missing(p: Provider, c: &Cred) -> anyhow::Error {
    anyhow::anyhow!(
        "{var} isn't set — keyrotator needs {what}.\n  \
         Get one: {where_}\n  \
         Then save it once with: keyrotator login {p}\n  \
         (or for this shell only: export {var}=...)",
        var = c.var,
        what = c.what,
        where_ = c.where_,
        p = p.cli_name(),
    )
}

/// Gather a provider's credentials: environment, then saved login, then (with
/// `ask`) a prompt.
pub fn resolve(p: Provider, ask: bool) -> Result<Resolved> {
    let mut r = Resolved::default();
    for var in optional_vars(p) {
        if let Some((v, s)) = lookup(var) {
            r.insert(var, v, s);
        }
    }
    for c in required_creds(p) {
        if c.alt.is_some_and(|alt| r.get(alt).is_some()) {
            continue;
        }
        match lookup(c.var) {
            Some((v, s)) => {
                warn_shape(&c, &v);
                r.insert(c.var, v, s);
            }
            None if ask => {
                eprintln!("You're not logged in to {} yet.", p.display_name());
                let v = prompt_cred(&c)?;
                r.insert(c.var, v, Source::Prompt);
            }
            None => return Err(missing(p, &c)),
        }
    }
    *SOURCES.lock().unwrap() = r.values.iter().map(|(k, (_, s))| (*k, *s)).collect();
    Ok(r)
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

/// Construct a connector from resolved credentials.
pub fn connector_from(p: Provider, r: &Resolved) -> Result<Arc<dyn Connector>> {
    Ok(match p {
        Provider::Aws => Arc::new(AwsConnector::new(r.get("AWS_PROFILE"))),
        Provider::Gitlab => Arc::new(GitlabConnector::new(
            r.get("GITLAB_URL"),
            r.need("GITLAB_TOKEN")?,
            r.get("GITLAB_TOKEN_EXPIRY_DAYS")
                .and_then(|s| s.parse().ok()),
        )),
        Provider::Cloudflare => Arc::new(CloudflareConnector::new(r.need("CLOUDFLARE_API_TOKEN")?)),
        Provider::Datadog => Arc::new(DatadogConnector::new(
            r.get("DD_SITE"),
            r.need("DD_API_KEY")?,
            r.need("DD_APP_KEY")?,
        )),
        Provider::Npm => Arc::new(NpmConnector::new(
            env("NPM_REGISTRY").or(r.get("NPM_REGISTRY")),
        )),
        Provider::Dockerhub => Arc::new(DockerHubConnector::new(
            r.need("DOCKERHUB_USERNAME")?,
            r.need("DOCKERHUB_PASSWORD")?,
        )),
        Provider::Openai => Arc::new(OpenAiConnector::new(r.need("OPENAI_ADMIN_KEY")?)),
        Provider::Anthropic => Arc::new(AnthropicConnector::new(r.need("ANTHROPIC_ADMIN_KEY")?)),
        Provider::Twilio => {
            let sid = r.need("TWILIO_ACCOUNT_SID")?;
            let user = r.get("TWILIO_API_USER").unwrap_or_else(|| sid.clone());
            Arc::new(TwilioConnector::new(
                sid,
                user,
                r.need("TWILIO_AUTH_TOKEN")?,
            ))
        }
        Provider::Sendgrid => Arc::new(SendGridConnector::new(r.need("SENDGRID_API_KEY")?)),
        Provider::GithubApp => {
            // Accept the PEM inline, or a path to the .pem file.
            let pem = match r.get("GITHUB_APP_PRIVATE_KEY") {
                Some(p) => p,
                None => {
                    let path = shellexpand_home(&r.need("GITHUB_APP_PRIVATE_KEY_PATH")?);
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("reading App private key at {path}"))?
                }
            };
            Arc::new(GithubAppConnector::new(r.need("GITHUB_APP_ID")?, pem))
        }
    })
}

/// Save every value to the OS credential store.
pub fn save_login(entries: &[(&'static str, String)]) -> Result<()> {
    for (var, value) in entries {
        credstore::set(LOGIN_SERVICE, var, value)
            .map_err(|e| anyhow::anyhow!("couldn't save {var}: {e}"))?;
    }
    Ok(())
}

/// Build the connector for a provider.
///
/// Credentials come from the environment, then a saved login (`keyrotator
/// login`), then — with `ask` — a prompt, after which the user is offered to
/// save what they typed. MCP passes `ask = false`: its stdin is the protocol.
pub async fn build_connector(p: Provider, ask: bool) -> Result<Arc<dyn Connector>> {
    let r = resolve(p, ask)?;
    let c = connector_from(p, &r)?;
    let typed = r.prompted();
    if ask && !typed.is_empty() && credstore::available() {
        let save = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Save this to {} so you don't have to enter it again?",
                credstore::place()
            ))
            .default(true)
            .interact()?;
        if save {
            match c.connect().await {
                Ok(()) => {
                    save_login(&typed)?;
                    eprintln!(
                        "  ✓ Saved. keyrotator will use it from any terminal. \
                         Remove it any time with: keyrotator logout {}\n",
                        p.cli_name()
                    );
                }
                Err(e) => eprintln!(
                    "  Not saved — {} didn't accept it ({e}).\n",
                    p.display_name()
                ),
            }
        } else {
            eprintln!(
                "  OK, using it for this run only. `keyrotator login {}` saves it later.\n",
                p.cli_name()
            );
        }
    }
    Ok(c)
}

/// `~/x` → `$HOME/x`, for paths typed at a prompt (the shell didn't expand them).
pub fn shellexpand_home(path: &str) -> String {
    match (path.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => path.to_string(),
    }
}

/// Where this run's credentials came from, for "rejected" error messages.
pub fn credential_source_note(p: Provider) -> String {
    match p {
        Provider::Aws => return "your aws CLI session (AWS_PROFILE / `aws sso login`)".into(),
        Provider::Npm => return "your npm login (`npm login`)".into(),
        _ => {}
    }
    let parts: Vec<String> = required_creds(p)
        .iter()
        .filter_map(|c| {
            source_of(c.var).map(|s| match s {
                Source::Env => format!("{} from your environment", c.var),
                Source::Saved => format!("{} from your saved login", c.var),
                Source::Prompt => format!("the {} you entered", c.var),
            })
        })
        .collect();
    if parts.is_empty() {
        required_creds(p)
            .iter()
            .map(|c| c.var)
            .collect::<Vec<_>>()
            .join(" / ")
    } else {
        parts.join(" and ")
    }
}

impl Provider {
    pub fn display_name(self) -> &'static str {
        ProviderKind::from(self).display_name()
    }

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
