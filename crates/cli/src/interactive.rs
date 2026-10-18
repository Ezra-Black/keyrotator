//! Questions asked in a terminal when something wasn't given on the command
//! line. Never used when stdin/stderr aren't terminals or with --no-input, so
//! scripts and CI behave exactly as the flags say.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Select};
use keyrotator_core::{Consumer, Secret};
use serde::Serialize;

use crate::guide;
use crate::providers::{shellexpand_home, Provider};

pub fn available(no_input: bool) -> bool {
    !no_input && std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// Let the user pick a key from the provider's list.
pub fn pick_key(
    provider: Provider,
    keys: Vec<Secret>,
    current: Option<&str>,
    verb: &str,
) -> Result<Secret> {
    if keys.is_empty() {
        anyhow::bail!("no keys found for this {} account", provider.cli_name());
    }
    let items: Vec<String> = keys
        .iter()
        .map(|k| {
            let mut line = format!("{}  (id {})", k.label, k.external_id);
            if current == Some(k.external_id.as_str()) {
                line.push_str("  ← the key keyrotator is signed in with");
            }
            line
        })
        .collect();
    // Default to a key other than the one we're signed in with.
    let default = keys
        .iter()
        .position(|k| current != Some(k.external_id.as_str()))
        .unwrap_or(0);
    let i = Select::new()
        .with_prompt(format!(
            "Which {} do you want to {verb}?",
            guide::noun(provider)
        ))
        .items(&items)
        .default(default)
        .interact()?;
    let key = keys.into_iter().nth(i).expect("index from list");
    eprintln!(
        "  (Next time you can skip this: keyrotator {verb} {} {})\n",
        provider.cli_name(),
        key.external_id
    );
    Ok(key)
}

/// Ask where the new secret should go. Returns the consumers and whether
/// they're worth saving to the config file.
pub fn choose_destination(provider: Provider, secret: &Secret) -> Result<(Vec<Consumer>, bool)> {
    let n = guide::noun(provider);
    eprintln!("The new {n} needs somewhere to go — keyrotator won't create one it can't hand you.");
    let mut options = vec![
        "Update a .env file (recommended for local apps)",
        "Save it to a file only you can read",
        "Set a GitHub Actions secret (uses the gh CLI)",
    ];
    if keyrotator_core::credstore::available() {
        options.push("Store it in your OS keychain");
    }
    options.push("Just show it to me once (not saved anywhere)");

    let choice = Select::new()
        .with_prompt(format!("Where should the new {n} go?"))
        .items(&options)
        .default(0)
        .interact()?;

    let consumer = match options[choice] {
        o if o.starts_with("Update a .env") => {
            let path: String = Input::new()
                .with_prompt(".env file to update (created if missing)")
                .default(".env".into())
                .interact_text()?;
            let (default_var, id_var) = guide::default_env_vars(provider);
            let variable: String = Input::new()
                .with_prompt("Variable name")
                .default(default_var.into())
                .interact_text()?;
            let id_variable = match id_var {
                Some(idv) if variable == default_var => {
                    eprintln!("  AWS keys come in pairs, so {idv} will be updated too.");
                    Some(idv.to_string())
                }
                _ => None,
            };
            Consumer::DotEnvFile {
                path: absolute(&path),
                variable,
                id_variable,
            }
        }
        o if o.starts_with("Save it to a file") => {
            let suggested = format!("{}-{}.secret", provider.cli_name(), slug(&secret.label));
            let path: String = Input::new()
                .with_prompt("File to write")
                .default(suggested)
                .interact_text()?;
            Consumer::File {
                path: absolute(&path),
            }
        }
        o if o.starts_with("Set a GitHub") => {
            let repo: String = Input::new()
                .with_prompt("Repository (owner/name)")
                .interact_text()?;
            let (default_var, _) = guide::default_env_vars(provider);
            let secret_name: String = Input::new()
                .with_prompt("Secret name")
                .default(default_var.into())
                .interact_text()?;
            Consumer::GithubActionsSecret { repo, secret_name }
        }
        o if o.starts_with("Store it in your OS keychain") => {
            crate::ops::keychain_consumer(provider, secret)
        }
        _ => return Ok((vec![Consumer::Reveal], false)),
    };
    Ok((vec![consumer], true))
}

/// Offer to save the chosen consumers so the next rotation needs no questions.
pub fn offer_to_remember(
    provider: Provider,
    secret: &Secret,
    consumers: &[Consumer],
    config_path: Option<&Path>,
) -> Result<()> {
    let path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(keyrotator_core::config::FILE_NAME));
    eprintln!(
        "\nkeyrotator can save this choice in {} (no secrets, just where they go), so \
         next time it's simply: keyrotator rotate {} {}",
        crate::guide::pretty_path(&path.to_string_lossy()),
        provider.cli_name(),
        secret.external_id
    );
    let save = Confirm::new()
        .with_prompt("Remember this for next time?")
        .default(true)
        .interact()?;
    if !save {
        return Ok(());
    }
    let text = config_entry(provider, secret, consumers)?;
    let mut existing = std::fs::read_to_string(&path).unwrap_or_default();
    if !existing.is_empty() && !existing.ends_with("\n\n") {
        existing.push_str(if existing.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        });
    }
    existing.push_str(&text);
    std::fs::write(&path, existing).with_context(|| format!("writing {}", path.display()))?;
    eprintln!("  Saved.\n");
    Ok(())
}

#[derive(Serialize)]
struct Entry<'a> {
    provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<&'a str>,
    consumers: &'a [Consumer],
}

#[derive(Serialize)]
struct Doc<'a> {
    keys: [Entry<'a>; 1],
}

/// A `[[keys]]` entry that keeps matching after rotation: AWS by IAM user,
/// providers with stable ids by id, everything else by name.
pub fn config_entry(provider: Provider, secret: &Secret, consumers: &[Consumer]) -> Result<String> {
    let (id, name, principal) = match provider {
        Provider::Aws => (None, None, Some(secret.principal.as_str())),
        Provider::Cloudflare | Provider::Npm | Provider::GithubApp => {
            (Some(secret.external_id.as_str()), None, None)
        }
        _ => (None, Some(secret.label.as_str()), None),
    };
    let doc = Doc {
        keys: [Entry {
            provider: provider.cli_name(),
            id,
            name,
            principal,
            consumers,
        }],
    };
    Ok(toml::to_string(&doc)?)
}

fn absolute(path: &str) -> String {
    let p = PathBuf::from(shellexpand_home(path));
    if p.is_absolute() {
        return p.to_string_lossy().into_owned();
    }
    std::env::current_dir()
        .map(|d| d.join(&p))
        .unwrap_or(p)
        .to_string_lossy()
        .into_owned()
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrotator_core::{Config, ProviderKind};

    #[test]
    fn remembered_entry_round_trips_and_survives_new_ids() {
        let secret = Secret::new(ProviderKind::Gitlab, "4821", "kr-test", "4821");
        let consumers = vec![Consumer::DotEnvFile {
            path: "/proj/.env".into(),
            variable: "GITLAB_TOKEN".into(),
            id_variable: None,
        }];
        let text = config_entry(Provider::Gitlab, &secret, &consumers).unwrap();
        let cfg = Config::parse(&text, Path::new("/")).unwrap();
        // Matches the rotated token, which has a new id but the same name.
        let rotated = Secret::new(ProviderKind::Gitlab, "4822", "kr-test", "4822");
        assert_eq!(cfg.consumers_for(&rotated), consumers);
    }
}
