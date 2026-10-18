//! `keyrotator login` / `logout`: keep provider credentials in the OS
//! keychain so keyrotator works from any terminal, with nothing exported and
//! nothing in a dotfile.

use anyhow::Result;
use clap::ValueEnum;
use dialoguer::{Confirm, Input, Select};
use keyrotator_core::credstore::{self, LOGIN_SERVICE};

use crate::providers::{
    connector_from, login_settings, login_vars, prompt_cred, required_creds, save_login,
    shellexpand_home, Provider, Resolved, Source,
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

pub async fn login(provider: Option<Provider>, ask: bool) -> Result<()> {
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
        eprintln!("{name} uses its own CLI's login, so there's nothing for keyrotator to save. Sign in with {how}.");
        return Ok(());
    }

    eprintln!(
        "Logging in to {name}. keyrotator saves this to {} so it works from any terminal.\n",
        credstore::place()
    );
    let mut r = Resolved::default();
    for c in &creds {
        if c.alt.is_some_and(|a| env(a).is_some()) {
            let alt = c.alt.unwrap();
            r.insert(alt, env(alt).unwrap(), Source::Prompt);
            continue;
        }
        let value = match (env(c.var), ask) {
            (Some(v), true)
                if Confirm::new()
                    .with_prompt(format!("Use the {} that's set in this terminal?", c.var))
                    .default(true)
                    .interact()? =>
            {
                v
            }
            (Some(v), false) => v,
            (_, true) => prompt_cred(c)?,
            (None, false) => anyhow::bail!(
                "{} isn't set. Run this in a terminal to be asked for it, or set it first: \
                 {}=... keyrotator login {}",
                c.var,
                c.var,
                p.cli_name()
            ),
        };
        let value = if c.var.ends_with("_PATH") {
            shellexpand_home(&value)
        } else {
            value
        };
        r.insert(c.var, value, Source::Prompt);
    }

    let mut clear = Vec::new();
    for s in login_settings(p) {
        let current = env(s.var)
            .or_else(|| credstore::get(LOGIN_SERVICE, s.var))
            .unwrap_or_else(|| s.default.to_string());
        let value = if ask {
            Input::<String>::new()
                .with_prompt(s.prompt)
                .default(current)
                .interact_text()?
        } else {
            current
        };
        if value.trim() == s.default {
            clear.push(s.var);
        } else {
            r.insert(s.var, value.trim().to_string(), Source::Prompt);
        }
    }

    eprintln!("Checking with {name}…");
    let connector = connector_from(p, &r)?;
    if let Err(e) = connector.connect().await {
        anyhow::bail!(
            "{name} didn't accept it: {e}\nNothing was saved. Check the value and its \
             permissions, then run `keyrotator login {}` again.",
            p.cli_name()
        );
    }
    save_login(&r.entries())?;
    for var in clear {
        let _ = credstore::delete(LOGIN_SERVICE, var);
    }
    let vars: Vec<&str> = creds.iter().map(|c| c.var).collect();
    eprintln!(
        "✓ Logged in to {name}. Saved to {}.\n\
         \n  keyrotator now works from any terminal — no export needed.\
         \n  (If {} is also set in your environment, that value wins.)\
         \n  Remove it with: keyrotator logout {p}\
         \n\nNext: keyrotator list {p}",
        credstore::place(),
        vars.join(" / "),
        p = p.cli_name()
    );
    Ok(())
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
