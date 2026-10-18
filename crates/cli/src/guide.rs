//! Plain-language explanations: what a rotation is about to do, and what to
//! do afterwards. Everything here is text; nothing touches a provider.

use std::path::Path;
use std::process::{Command, Stdio};

use keyrotator_core::{Consumer, OldKeyState, RotationOutcome, RotationStyle, Secret};

use crate::providers::Provider;

/// What the provider calls its credential, for sentences like "a new token".
pub fn noun(p: Provider) -> &'static str {
    match p {
        Provider::Aws => "access key",
        Provider::Gitlab | Provider::Cloudflare | Provider::Npm | Provider::Dockerhub => "token",
        Provider::GithubApp => "installation token",
        _ => "API key",
    }
}

/// The variable a `.env` consumer writes by default: (secret var, id var).
pub fn default_env_vars(p: Provider) -> (&'static str, Option<&'static str>) {
    match p {
        Provider::Aws => ("AWS_SECRET_ACCESS_KEY", Some("AWS_ACCESS_KEY_ID")),
        Provider::Gitlab => ("GITLAB_TOKEN", None),
        Provider::Cloudflare => ("CLOUDFLARE_API_TOKEN", None),
        Provider::Datadog => ("DD_API_KEY", None),
        Provider::Npm => ("NPM_TOKEN", None),
        Provider::Dockerhub => ("DOCKERHUB_TOKEN", None),
        Provider::Openai => ("OPENAI_ADMIN_KEY", None),
        Provider::Anthropic => ("ANTHROPIC_API_KEY", None),
        Provider::Twilio => ("TWILIO_API_SECRET", None),
        Provider::Sendgrid => ("SENDGRID_API_KEY", None),
        Provider::GithubApp => ("GITHUB_TOKEN", None),
    }
}

/// Parse `--dotenv PATH[:VAR]`. Without a variable, use the provider's
/// default (and for AWS also write the new access key id).
pub fn parse_dotenv_flag(p: Provider, s: &str) -> Consumer {
    let is_var = |v: &str| {
        !v.is_empty()
            && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !v.starts_with(|c: char| c.is_ascii_digit())
    };
    match s.rsplit_once(':') {
        Some((path, var)) if !path.is_empty() && is_var(var) => Consumer::DotEnvFile {
            path: path.into(),
            variable: var.into(),
            id_variable: None,
        },
        _ => {
            let (var, id_var) = default_env_vars(p);
            Consumer::DotEnvFile {
                path: s.into(),
                variable: var.into(),
                id_variable: id_var.map(Into::into),
            }
        }
    }
}

/// The numbered plan shown before an interactive rotation.
pub fn plan(
    p: Provider,
    style: RotationStyle,
    supports_deactivate: bool,
    secret: &Secret,
    delete_old_now: bool,
) -> Vec<String> {
    let name = keyrotator_core::ProviderKind::from(p).display_name();
    let n = noun(p);
    let targets: Vec<String> = secret.consumers.iter().map(describe_target).collect();
    let deliver = format!("The new {n} is saved to {}.", join_and(&targets));
    let mut steps = Vec::new();
    match style {
        RotationStyle::Overlap => {
            steps.push(format!(
                "{name} creates a new {n} for \"{}\". The old one keeps working for now.",
                secret.label
            ));
            steps.push(format!("keyrotator checks that the new {n} works."));
            steps.push(deliver);
            steps.push(if delete_old_now {
                format!("The old {n} is permanently deleted.")
            } else if supports_deactivate {
                format!(
                    "The old {n} is switched off. You can switch it back on in {name} if \
                     something still needed it."
                )
            } else {
                format!(
                    "The old {n} keeps working until you retire it — {name} has no \
                     \"switched off\" state. keyrotator will tell you how."
                )
            });
            steps.push(
                "If anything fails before that, the new one is removed and nothing changes.".into(),
            );
        }
        RotationStyle::AtomicRotate => {
            steps.push(format!(
                "{name} replaces \"{}\" with a new {n} and immediately revokes the old one. \
                 This can't be undone.",
                secret.label
            ));
            steps.push(deliver);
            steps.push(format!("keyrotator checks that the new {n} works."));
        }
        RotationStyle::Ephemeral => {
            steps.push(format!("{name} issues a fresh short-lived {n}."));
            steps.push("keyrotator checks that it works.".into());
            steps.push(deliver);
            steps.push("The previous one expires on its own.".into());
        }
        RotationStyle::Manual => {}
    }
    steps
}

/// A path as a person would type it: relative to the cwd when inside it,
/// `~/…` when under the home directory.
pub fn pretty_path(path: &str) -> String {
    let p = Path::new(path);
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = p.strip_prefix(&cwd) {
            return rel.to_string_lossy().into_owned();
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if let Ok(rel) = p.strip_prefix(&home) {
            return format!("~/{}", rel.to_string_lossy());
        }
    }
    path.to_string()
}

/// Like `Consumer::describe`, with friendlier paths.
pub fn describe_target(c: &Consumer) -> String {
    match c {
        Consumer::DotEnvFile {
            path,
            variable,
            id_variable: Some(idv),
        } => format!("{variable} and {idv} in {}", pretty_path(path)),
        Consumer::DotEnvFile { path, variable, .. } => {
            format!("{variable} in {}", pretty_path(path))
        }
        Consumer::GithubActionsSecret { repo, secret_name } => {
            format!("the GitHub Actions secret {secret_name} in {repo}")
        }
        Consumer::AwsSsmParameter { name, region } => format!("SSM parameter {name} ({region})"),
        Consumer::File { path } => format!("{} (only you can read it)", pretty_path(path)),
        Consumer::Keychain { service, .. }
            if service == keyrotator_core::credstore::LOGIN_SERVICE =>
        {
            "your saved keyrotator login".into()
        }
        Consumer::Keychain { .. } => "your keychain".into(),
        Consumer::Reveal => "your screen (shown once, not stored)".into(),
    }
}

fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// Plain next steps after a rotation, in priority order.
pub fn next_steps(p: Provider, old: &Secret, outcome: &RotationOutcome) -> Vec<String> {
    let n = noun(p);
    let cli = p.cli_name();
    let mut steps = Vec::new();

    for c in &outcome.updated_consumers {
        match c {
            Consumer::DotEnvFile { path, .. } => {
                steps.push(format!(
                    "Restart anything that reads {} so it picks up the new {n}.",
                    pretty_path(path)
                ));
                if let Some(warning) = not_git_ignored(path) {
                    steps.push(warning);
                }
            }
            Consumer::File { path } => {
                steps.push(format!(
                    "{} now holds the live {n}. Keep it — it's the copy your tools \
                     should use. Don't commit or share it.",
                    pretty_path(path)
                ));
                if let Some(warning) = not_git_ignored(path) {
                    steps.push(warning);
                }
            }
            Consumer::Reveal => steps.push(format!(
                "The {n} above was shown once and isn't stored anywhere. Copy it to \
                 wherever it's used now."
            )),
            Consumer::GithubActionsSecret { repo, .. } => steps.push(format!(
                "Workflows in {repo} use the new {n} from their next run."
            )),
            _ => {}
        }
    }

    match outcome.old_key {
        OldKeyState::StillActive if outcome.failed_consumers.is_empty() => steps.push(format!(
            "The old {n} still works. Once everything uses the new one, revoke it:\n      \
             keyrotator retire {cli} {}",
            old.external_id
        )),
        OldKeyState::Deactivated => steps.push(format!(
            "The old {n} is switched off. When you're sure nothing broke, delete it:\n      \
             keyrotator retire {cli} {} --delete",
            old.external_id
        )),
        _ => {}
    }
    steps
}

/// A warning when `path` sits inside a git repo and isn't ignored.
fn not_git_ignored(path: &str) -> Option<String> {
    let p = Path::new(path);
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.is_dir() {
        return None;
    }
    let in_repo = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?
        .success();
    if !in_repo {
        return None;
    }
    let file = p.file_name()?;
    let ignored = Command::new("git")
        .args(["check-ignore", "-q"])
        .arg(file)
        .current_dir(dir)
        .status()
        .ok()?
        .success();
    (!ignored).then(|| {
        format!(
            "Careful: {} is inside a git repository and isn't git-ignored. Add it to \
             .gitignore so the secret isn't committed.",
            pretty_path(path)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_flag_with_and_without_variable() {
        assert_eq!(
            parse_dotenv_flag(Provider::Gitlab, ".env:MY_TOKEN"),
            Consumer::DotEnvFile {
                path: ".env".into(),
                variable: "MY_TOKEN".into(),
                id_variable: None
            }
        );
        assert_eq!(
            parse_dotenv_flag(Provider::Gitlab, ".env"),
            Consumer::DotEnvFile {
                path: ".env".into(),
                variable: "GITLAB_TOKEN".into(),
                id_variable: None
            }
        );
        // AWS writes both halves of the key pair by default.
        assert_eq!(
            parse_dotenv_flag(Provider::Aws, "app/.env"),
            Consumer::DotEnvFile {
                path: "app/.env".into(),
                variable: "AWS_SECRET_ACCESS_KEY".into(),
                id_variable: Some("AWS_ACCESS_KEY_ID".into())
            }
        );
        // A Windows drive letter isn't mistaken for a variable.
        assert_eq!(
            parse_dotenv_flag(Provider::Gitlab, r"C:\app\.env"),
            Consumer::DotEnvFile {
                path: r"C:\app\.env".into(),
                variable: "GITLAB_TOKEN".into(),
                id_variable: None
            }
        );
    }

    #[test]
    fn atomic_plan_warns_it_cannot_be_undone() {
        let mut s = Secret::new(keyrotator_core::ProviderKind::Gitlab, "1", "kr-test", "1");
        s.consumers
            .push(parse_dotenv_flag(Provider::Gitlab, ".env"));
        let plan = plan(
            Provider::Gitlab,
            RotationStyle::AtomicRotate,
            false,
            &s,
            false,
        );
        assert!(plan[0].contains("can't be undone"), "{plan:?}");
        assert_eq!(plan[1], "The new token is saved to GITLAB_TOKEN in .env.");
    }
}
