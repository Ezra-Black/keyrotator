//! `keyrotator login` / `logout`: keep provider credentials in the OS
//! keychain so keyrotator works from any terminal, with nothing exported and
//! nothing in a dotfile.

use anyhow::Result;
use clap::ValueEnum;
use dialoguer::{Confirm, Select};
use keyrotator_core::credstore::{self, LOGIN_SERVICE};

use crate::providers::{
    ask_for_cred, connector_from, login_setting, login_vars, masked, required_creds, save_login,
    shape_problem, shellexpand_home, Provider, Resolved, Source,
};

fn env(k: &str) -> Option<String> {
    std::env::var(k)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// How a provider is authenticated right now: "saved login", "environment",
/// "aws CLI session", or "not set".
pub fn status_word(p: Provider) -> &'static str {
    let creds = required_creds(p);
    if creds.is_empty() {
        return match p {
            Provider::Aws => "aws CLI session",
            _ => "npm login",
        };
    }
    let satisfied =
        |f: &dyn Fn(&str) -> bool| creds.iter().all(|c| f(c.var) || c.alt.is_some_and(f));
    if satisfied(&|v| env(v).is_some()) {
        "environment"
    } else if satisfied(&|v| credstore::get(LOGIN_SERVICE, v).is_some()) {
        "saved login"
    } else {
        "not set"
    }
}

fn print_status() {
    eprintln!("Provider logins:");
    for p in Provider::value_variants() {
        eprintln!("  {:<12} {}", p.cli_name(), status_word(*p));
    }
    eprintln!(
        "\n\"environment\" means an exported variable is set in this terminal; it takes \
         priority over a saved login.\n"
    );
}

fn ensure_store() -> Result<()> {
    if credstore::available() {
        return Ok(());
    }
    anyhow::bail!(
        "saving logins isn't available here — KEYROTATOR_DISABLE_KEYCHAIN is set, or this \
         build has no keychain support. Use environment variables instead."
    )
}

pub async fn login(provider: Option<Provider>, url: Option<String>, ask: bool) -> Result<()> {
    ensure_store()?;
    let p = match provider {
        Some(p) => p,
        None if ask => {
            print_status();
            let choices: Vec<Provider> = Provider::value_variants()
                .iter()
                .copied()
                .filter(|p| !required_creds(*p).is_empty())
                .collect();
            let names: Vec<String> = choices
                .iter()
                .map(|p| format!("{:<12} {}", p.cli_name(), status_word(*p)))
                .collect();
            let i = Select::new()
                .with_prompt("Log in to which provider?")
                .items(&names)
                .default(0)
                .interact()?;
            choices[i]
        }
        None => {
            print_status();
            return Ok(());
        }
    };

    let name = p.display_name();
    let creds = required_creds(p);
    if creds.is_empty() {
        let how = match p {
            Provider::Aws => "`aws sso login` (or a configured profile)",
            _ => "`npm login`",
        };
        eprintln!(
            "{name} uses its own CLI's login, so there's nothing for keyrotator to save. \
             Sign in with {how}."
        );
        return Ok(());
    }

    // GitLab URL / Datadog site: --url, else environment, else saved. Never asked.
    let setting_def = login_setting(p);
    if url.is_some() && setting_def.is_none() {
        anyhow::bail!("--url only applies to gitlab (self-hosted URL) and datadog (site)");
    }
    let setting: Option<String> = url
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .or_else(|| {
            setting_def.and_then(|(var, _)| env(var).or_else(|| credstore::get(LOGIN_SERVICE, var)))
        });
    match (&setting, setting_def) {
        (Some(s), Some((_, default))) if s != default => eprintln!("Logging in to {name} at {s}."),
        _ => eprintln!("Logging in to {name}."),
    }

    // Offer credentials already exported in this terminal — unless they look
    // like another provider's.
    let mut values: Vec<(&'static str, String)> = Vec::new();
    for c in &creds {
        if let Some(alt) = c.alt.filter(|a| env(a).is_some()) {
            values.push((alt, env(alt).unwrap()));
            continue;
        }
        let Some(v) = env(c.var) else { continue };
        if let Some(problem) = shape_problem(c, &v) {
            eprintln!("Ignoring {} from this terminal: {problem}", c.var);
            continue;
        }
        let use_it = !ask
            || Confirm::new()
                .with_prompt(format!(
                    "Found {} in this terminal ({}). Use it?",
                    c.var,
                    masked(&v)
                ))
                .default(true)
                .interact()?;
        if use_it {
            values.push((c.var, v));
        }
    }

    loop {
        for c in &creds {
            let have = |var: &str| values.iter().any(|(k, _)| *k == var);
            if have(c.var) || c.alt.is_some_and(have) {
                continue;
            }
            if !ask {
                anyhow::bail!(
                    "{} isn't set (or doesn't look like {}). Run `keyrotator login {}` in a \
                     terminal to be asked for it.",
                    c.var,
                    c.what,
                    p.cli_name()
                );
            }
            eprintln!();
            let v = ask_for_cred(c, setting.as_deref())?;
            let v = if c.var.ends_with("_PATH") {
                shellexpand_home(&v)
            } else {
                v
            };
            values.push((c.var, v));
        }

        let mut r = Resolved::default();
        for (k, v) in &values {
            r.insert(k, v.clone(), Source::Prompt);
        }
        if let (Some(s), Some((var, _))) = (&setting, setting_def) {
            r.insert(var, s.clone(), Source::Prompt);
        }

        eprintln!("Checking with {name}…");
        let connector = connector_from(p, &r)?;
        match connector.connect().await {
            Ok(()) => {
                let who = connector
                    .account_name()
                    .await
                    .map(|a| format!(" as {a}"))
                    .unwrap_or_default();
                save_login(&values)?;
                if let Some((var, default)) = setting_def {
                    match &setting {
                        Some(s) if s != default => save_login(&[(var, s.clone())])?,
                        _ => {
                            let _ = credstore::delete(LOGIN_SERVICE, var);
                        }
                    }
                }
                eprintln!(
                    "✓ Logged in to {name}{who}. Saved to {}.\n  keyrotator now works from any \
                     terminal — nothing to export.",
                    credstore::place()
                );
                for (var, saved) in &values {
                    if env(var).is_some_and(|e| e != *saved) {
                        eprintln!(
                            "  Note: a different {var} is still exported in this terminal and \
                             takes priority. Run `unset {var}` to use the saved login."
                        );
                    }
                }
                eprintln!("\nNext: keyrotator list {}", p.cli_name());
                return Ok(());
            }
            Err(e) => {
                let text = e.to_string();
                let why = if text.contains("401") {
                    "the token is invalid, expired, or revoked".to_string()
                } else if text.contains("403") {
                    "the token works but doesn't have permission to manage keys (check its \
                     scopes)"
                        .to_string()
                } else {
                    text
                };
                eprintln!("✗ {name} didn't accept it: {why}.");
                let retry = ask
                    && Confirm::new()
                        .with_prompt("Try a different one?")
                        .default(true)
                        .interact()?;
                if !retry {
                    anyhow::bail!("not logged in — nothing was saved");
                }
                values.clear();
            }
        }
    }
}

pub fn logout(provider: Option<Provider>, ask: bool) -> Result<()> {
    ensure_store()?;
    let p = match provider {
        Some(p) => p,
        None if ask => {
            let saved: Vec<Provider> = Provider::value_variants()
                .iter()
                .copied()
                .filter(|p| status_word(*p) == "saved login")
                .collect();
            if saved.is_empty() {
                eprintln!("No saved logins.");
                return Ok(());
            }
            let names: Vec<String> = saved.iter().map(|p| p.cli_name()).collect();
            let i = Select::new()
                .with_prompt("Log out of which provider?")
                .items(&names)
                .interact()?;
            saved[i]
        }
        None => anyhow::bail!("which provider? e.g. keyrotator logout gitlab"),
    };
    for var in login_vars(p) {
        credstore::delete(LOGIN_SERVICE, var)
            .map_err(|e| anyhow::anyhow!("removing {var}: {e}"))?;
    }
    eprintln!(
        "✓ Removed your saved {} login from {}.\n  The credential itself still works — revoke it \
         in {} if you're done with it.",
        p.display_name(),
        credstore::place(),
        p.display_name()
    );
    Ok(())
}
