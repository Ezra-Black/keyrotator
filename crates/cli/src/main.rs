mod banner;
mod guide;
mod interactive;
mod login;
mod mcp;
mod ops;
mod providers;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use rekey_core::{
    Connector, Consumer, OldKeyState, RotationEngine, RotationError, RotationStage, RotationStyle,
    Secret,
};

use crate::providers::{
    build_connector, credential_source_note, login_token_var, Provider, Source,
};

const GETTING_STARTED: &str = "\
Getting started:
  1. rekey login gitlab       save your GitLab token once (works in every terminal)
  2. rekey rotate gitlab      pick a key, choose where the new one goes, done

In a terminal, rekey asks for anything you leave out. Flags can go in any
order. Use --no-input in scripts to get errors instead of questions.";

/// Rotate the API keys and tokens for accounts you administer.
///
/// Status messages go to stderr; stdout carries only `list` output and, with
/// --print-secret, the new secret — so it's safe to capture.
#[derive(Parser)]
#[command(name = "rekey", version, about)]
struct Cli {
    /// Config file with per-key consumers [default: ./rekey.toml, then
    /// ~/.config/rekey/config.toml]
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Never ask questions; fail with an explanation instead (for scripts/CI).
    #[arg(long, global = true)]
    no_input: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Save a provider's credentials in your OS keychain, so rekey works
    /// in any terminal without exporting anything. Run with no provider to
    /// see what's saved.
    Login {
        #[arg(value_enum)]
        provider: Option<Provider>,
        /// Self-hosted GitLab URL (e.g. https://gitlab.example.com), or the
        /// Datadog site (e.g. datadoghq.eu).
        #[arg(long)]
        url: Option<String>,
    },
    /// Remove a provider's saved credentials (doesn't revoke them).
    Logout {
        #[arg(value_enum)]
        provider: Option<Provider>,
    },
    /// Check that a provider's credentials work and you can manage its keys.
    Connect {
        #[arg(value_enum)]
        provider: Provider,
    },
    /// List the keys for a provider, with the ids `rotate` and `retire` take.
    List {
        #[arg(value_enum)]
        provider: Provider,
    },
    /// Rotate one key, delivering the new secret where it's used.
    ///
    /// The new secret must go somewhere: consumers from rekey.toml and/or
    /// the destination flags below. In a terminal, anything you leave out —
    /// which key, where it goes — is asked for, with the plan shown before
    /// anything changes.
    #[command(after_help = "\
Examples:
  rekey rotate gitlab                        asks which key and where it goes
  rekey rotate gitlab 4821 --dotenv .env     writes GITLAB_TOKEN in .env
  rekey rotate gitlab 4821 --dotenv .env:MY_TOKEN --gh-secret me/app:MY_TOKEN
  rekey rotate aws AKIA... --dotenv .env     writes both AWS_ACCESS_KEY_ID and
                                                  AWS_SECRET_ACCESS_KEY

Flags can go in any order.")]
    Rotate {
        #[arg(value_enum)]
        provider: Provider,
        /// The key's id, exactly as shown by `list`. Omit it to pick from a list.
        id: Option<String>,
        #[command(flatten)]
        dest: Destinations,
        /// Write the new secret to this file (created owner-only, mode 0600).
        #[arg(long, value_name = "PATH")]
        secret_file: Option<PathBuf>,
        /// Set a variable in a .env file; VAR defaults to the usual name for
        /// the provider (e.g. GITLAB_TOKEN). Repeatable.
        #[arg(long, value_name = "PATH[:VAR]")]
        dotenv: Vec<String>,
        /// Set a GitHub Actions secret via `gh`. Repeatable.
        #[arg(long, value_name = "OWNER/REPO:NAME")]
        gh_secret: Vec<String>,
        /// Write an AWS SSM SecureString parameter. Repeatable.
        #[arg(long, value_name = "NAME:REGION")]
        ssm: Vec<String>,
        /// Delete the old key right away instead of leaving it for `retire`.
        #[arg(long)]
        delete_old_now: bool,
        /// Skip the "go ahead?" question.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Rotate every key for a provider that has somewhere to deliver its new
    /// secret (configured consumers, or the flags below).
    ///
    /// Skips the key you're authenticated with, when the provider can tell.
    RotateAll {
        #[arg(value_enum)]
        provider: Provider,
        #[command(flatten)]
        dest: Destinations,
        /// Write each new secret to <DIR>/<provider>-<id>.secret (mode 0600).
        #[arg(long, value_name = "DIR")]
        secret_dir: Option<PathBuf>,
        /// Delete each old key right away instead of leaving it for `retire`.
        #[arg(long)]
        delete_old_now: bool,
        /// Don't ask for confirmation.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Revoke a key you no longer use: switch it off where the provider
    /// supports that, otherwise delete it.
    Retire {
        #[arg(value_enum)]
        provider: Provider,
        /// The key's id, exactly as shown by `list`. Omit it to pick from a list.
        id: Option<String>,
        /// Also permanently delete a key the provider can switch off.
        #[arg(long)]
        delete: bool,
        /// Don't ask for confirmation.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Run an MCP server on stdio so an AI assistant can list and rotate keys.
    ///
    /// Read-only unless --allow-rotate / --allow-retire are given. Rotation
    /// over MCP only delivers secrets to consumers in your config file; secret
    /// values are never returned to the assistant.
    Mcp {
        /// Expose the `rotate_key` tool.
        #[arg(long)]
        allow_rotate: bool,
        /// Expose the `retire_key` tool.
        #[arg(long)]
        allow_retire: bool,
    },
}

/// Destinations available to both `rotate` and `rotate-all`.
#[derive(Args)]
struct Destinations {
    /// Print the new secret to stdout.
    #[arg(long)]
    print_secret: bool,
    /// Store the new secret in the OS keychain (service "rekey").
    #[arg(long)]
    keychain: bool,
}

impl Destinations {
    fn consumers(&self, provider: Provider, secret: &Secret) -> Vec<Consumer> {
        let mut out = Vec::new();
        if self.print_secret {
            out.push(Consumer::Reveal);
        }
        if self.keychain {
            out.push(ops::keychain_consumer(provider, secret));
        }
        out
    }
}

fn split_last<'a>(s: &'a str, flag: &str, shape: &str) -> Result<(&'a str, &'a str)> {
    s.rsplit_once(':')
        .filter(|(a, b)| !a.is_empty() && !b.is_empty())
        .with_context(|| format!("--{flag} expects {shape}, got '{s}'"))
}

fn progress() -> rekey_core::engine::ProgressFn {
    Arc::new(|_id, stage: RotationStage, msg: &str| {
        let tag = match stage {
            RotationStage::Done => "✓",
            RotationStage::Failed | RotationStage::RolledBack => "✗",
            _ => "·",
        };
        eprintln!("  {tag} {msg}");
    })
}

/// Ask for confirmation in a terminal; without one, require --yes.
fn confirm(question: &str, yes: bool, ask: bool, default: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !ask {
        anyhow::bail!("{question} — refusing without confirmation; pass --yes to proceed");
    }
    if dialoguer::Confirm::new()
        .with_prompt(question)
        .default(default)
        .interact()?
    {
        Ok(())
    } else {
        anyhow::bail!("cancelled — nothing was changed")
    }
}

/// Turn "401 Unauthorized" into something a person can act on.
fn explain(provider: Provider, e: RotationError) -> anyhow::Error {
    let text = e.to_string();
    let auth = matches!(e, RotationError::NotAuthorized(_))
        || text.contains("401")
        || text.contains("403");
    if auth {
        let p = provider.cli_name();
        let shadowed = providers::env_shadows_saved_login(provider);
        let fix = if let Some(var) = shadowed {
            format!(
                "You also have a saved login, but {var} in this terminal overrides it. \
                 Run `unset {var}` to use the saved login."
            )
        } else if credential_source_note(provider).contains("saved login") {
            format!("Your saved login may be expired or revoked. Replace it with: rekey login {p}")
        } else {
            format!(
                "Check the value is current (not expired or revoked) and has permission to \
                 manage keys. `rekey connect {p}` tests just that."
            )
        };
        anyhow::anyhow!(
            "{text}\n\n{} rejected {}.\n{fix}",
            provider.display_name(),
            credential_source_note(provider),
        )
    } else {
        e.into()
    }
}

async fn list_keys(provider: Provider, c: &Arc<dyn Connector>) -> Result<Vec<Secret>> {
    c.list_keys().await.map_err(|e| explain(provider, e))
}

/// The key named by `id`, or one picked from a list in a terminal.
fn select_key(
    provider: Provider,
    keys: Vec<Secret>,
    id: Option<String>,
    current: Option<&str>,
    ask: bool,
    verb: &str,
) -> Result<Secret> {
    let p = provider.cli_name();
    match id {
        Some(id) => keys
            .into_iter()
            .find(|k| k.external_id == id)
            .with_context(|| {
                format!("no key with id {id} in this account. See the ids with: rekey list {p}")
            }),
        None if ask => interactive::pick_key(provider, keys, current, verb),
        None => {
            let listed: Vec<String> = keys
                .iter()
                .map(|k| format!("  {}  {}", k.external_id, k.label))
                .collect();
            let example = keys
                .iter()
                .find(|k| current != Some(k.external_id.as_str()))
                .or(keys.first())
                .map(|k| k.external_id.clone())
                .unwrap_or_else(|| "12345".into());
            anyhow::bail!(
                "which key? Your {p} keys are:\n{}\n\nPass the id, for example:\n  \
                 rekey {verb} {p} {example}",
                listed.join("\n")
            )
        }
    }
}

fn print_steps(title: &str, steps: &[String]) {
    if steps.is_empty() {
        return;
    }
    eprintln!("\n{title}");
    for (i, s) in steps.iter().enumerate() {
        eprintln!("  {}. {s}", i + 1);
    }
}

fn main() -> Result<()> {
    let help = format!("{GETTING_STARTED}\n\n{}", banner::plain());
    let matches = Cli::command().after_help(help).get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let config_path = cli.config.as_deref();
    let ask = interactive::available(cli.no_input);
    if !matches!(cli.command, Command::Mcp { .. }) {
        banner::show_once();
    }

    match cli.command {
        Command::Login { provider, url } => login::login(provider, url, ask).await?,

        Command::Logout { provider } => login::logout(provider, ask)?,

        Command::Connect { provider } => {
            let c = build_connector(provider, ask).await?;
            c.connect().await.map_err(|e| explain(provider, e))?;
            let p = provider.cli_name();
            let who = c
                .account_name()
                .await
                .map(|a| format!(" as {a}"))
                .unwrap_or_default();
            eprintln!("✓ Connected to {}{who}.", c.kind().display_name());
            eprintln!("  Next: `rekey list {p}` to see your keys, or `rekey rotate {p}`.");
        }

        Command::List { provider } => {
            let c = build_connector(provider, ask).await?;
            let config = ops::load_config(config_path)?;
            let mut keys = list_keys(provider, &c).await?;
            ops::attach_config(&mut keys, config.as_ref().map(|(_, c)| c));
            let current = c.current_key_id().await;
            if keys.is_empty() {
                eprintln!("No keys found.");
                return Ok(());
            }
            let notes = |k: &Secret| {
                let mut notes = Vec::new();
                if current.as_deref() == Some(k.external_id.as_str()) {
                    notes.push("signed in with this key".to_string());
                }
                if !k.consumers.is_empty() {
                    notes.push(format!("{} consumer(s) configured", k.consumers.len()));
                }
                notes
            };
            if std::io::stdout().is_terminal() {
                let w = keys
                    .iter()
                    .map(|k| k.external_id.len())
                    .max()
                    .unwrap_or(2)
                    .max(2);
                println!("{:<w$}  NAME", "ID");
                for k in &keys {
                    let n = notes(k);
                    let n = if n.is_empty() {
                        String::new()
                    } else {
                        format!("   ({})", n.join("; "))
                    };
                    println!("{:<w$}  {}{n}", k.external_id, k.label);
                }
                let example = keys
                    .iter()
                    .find(|k| current.as_deref() != Some(k.external_id.as_str()))
                    .unwrap_or(&keys[0]);
                eprintln!(
                    "\nRotate one with: rekey rotate {} {}   (or leave out the ID to pick from a list)",
                    provider.cli_name(),
                    example.external_id
                );
            } else {
                // Stable, tab-separated output for scripts.
                for k in &keys {
                    let n = notes(k);
                    let n = if n.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", n.join("; "))
                    };
                    println!("{}\t{}\t{}{n}", k.external_id, k.label, k.principal);
                }
            }
        }

        Command::Rotate {
            provider,
            id,
            dest,
            secret_file,
            dotenv,
            gh_secret,
            ssm,
            delete_old_now,
            yes,
        } => {
            let c = build_connector(provider, ask).await?;
            let config = ops::load_config(config_path)?;
            let keys = list_keys(provider, &c).await?;
            let current = c.current_key_id().await;
            let mut secret = select_key(provider, keys, id, current.as_deref(), ask, "rotate")?;
            ops::attach_config(
                std::slice::from_mut(&mut secret),
                config.as_ref().map(|(_, c)| c),
            );

            secret.consumers.extend(dest.consumers(provider, &secret));
            if let Some(path) = secret_file {
                secret.consumers.push(Consumer::File {
                    path: path.to_string_lossy().into_owned(),
                });
            }
            for d in &dotenv {
                secret.consumers.push(guide::parse_dotenv_flag(provider, d));
            }
            for g in &gh_secret {
                let (repo, name) = split_last(g, "gh-secret", "OWNER/REPO:NAME")?;
                secret.consumers.push(Consumer::GithubActionsSecret {
                    repo: repo.into(),
                    secret_name: name.into(),
                });
            }
            for s in &ssm {
                let (name, region) = split_last(s, "ssm", "NAME:REGION")?;
                secret.consumers.push(Consumer::AwsSsmParameter {
                    name: name.into(),
                    region: region.into(),
                });
            }

            // Rotating the token rekey itself signs in with: keep a saved
            // login pointing at the new token so you aren't locked out.
            if current.as_deref() == Some(secret.external_id.as_str()) {
                let n = guide::noun(provider);
                match login_token_var(provider).map(|v| (v, providers::source_of(v))) {
                    Some((var, Some(Source::Saved | Source::Prompt)))
                        if rekey_core::credstore::get(
                            rekey_core::credstore::LOGIN_SERVICE,
                            var,
                        )
                        .is_some() =>
                    {
                        eprintln!(
                            "This is the {n} rekey signs in with. Your saved login will be \
                             updated to the new {n} automatically."
                        );
                        secret.consumers.push(Consumer::Keychain {
                            service: rekey_core::credstore::LOGIN_SERVICE.into(),
                            account: var.into(),
                        });
                    }
                    Some((var, _)) => eprintln!(
                        "Heads up: this is the {n} rekey signs in with ({var}). After \
                         rotating, update {var} to the new value — or run `rekey login {}` \
                         so rekey keeps track of it for you.",
                        provider.cli_name()
                    ),
                    None => eprintln!(
                        "Heads up: this is the {n} rekey signs in with ({}). After \
                         rotating, update it to the new value.",
                        secret.label
                    ),
                }
            }

            let style = c.rotation_style();
            if secret.consumers.is_empty() && style != RotationStyle::Manual && ask {
                let (chosen, rememberable) = interactive::choose_destination(provider, &secret)?;
                if rememberable {
                    interactive::offer_to_remember(
                        provider,
                        &secret,
                        &chosen,
                        config.as_ref().map(|(p, _)| p.as_path()),
                    )?;
                }
                secret.consumers.extend(chosen);
            }

            if ask && style != RotationStyle::Manual && !secret.consumers.is_empty() {
                let plan = guide::plan(
                    provider,
                    style,
                    c.supports_deactivate(),
                    &secret,
                    delete_old_now,
                );
                print_steps("Here's what will happen:", &plan);
                eprintln!();
                confirm("Go ahead?", yes, ask, true)?;
            }

            let engine = RotationEngine::new(vec![c]).on_progress(progress());
            eprintln!("\nRotating {}…", secret.label);
            let outcome = engine
                .rotate(&secret, delete_old_now)
                .await
                .map_err(|e| match e {
                    RotationError::NoDestination(_) => anyhow::anyhow!(
                        "{e}\n\nFor example:\n  rekey rotate {p} {id} --dotenv .env\n  \
                         rekey rotate {p} {id} --secret-file ./{p}.secret\n\
                         Or run it in a terminal without --no-input and it'll ask.",
                        p = provider.cli_name(),
                        id = secret.external_id
                    ),
                    other => explain(provider, other),
                })?;

            // The secret goes out first so it's never lost to a later error.
            if let Some(value) = &outcome.revealed_secret {
                if std::io::stdout().is_terminal() {
                    eprintln!("\nNew {} (shown once, not stored):", guide::noun(provider));
                }
                println!("{value}");
            }
            eprintln!();
            for line in ops::outcome_lines(provider, &secret, &outcome) {
                eprintln!("{line}");
            }
            print_steps(
                "What to do now:",
                &guide::next_steps(provider, &secret, &outcome),
            );
            if !outcome.is_clean() {
                std::process::exit(1);
            }
        }

        Command::RotateAll {
            provider,
            dest,
            secret_dir,
            delete_old_now,
            yes,
        } => {
            let c = build_connector(provider, ask).await?;
            let config = ops::load_config(config_path)?;
            let mut keys = list_keys(provider, &c).await?;
            ops::attach_config(&mut keys, config.as_ref().map(|(_, c)| c));
            let current = c.current_key_id().await;
            let p = provider.cli_name();

            let mut todo = Vec::new();
            for mut k in keys {
                if current.as_deref() == Some(k.external_id.as_str()) {
                    eprintln!(
                        "Skipping {} ({}): it's the key rekey is signed in with. \
                         Rotate it on its own with `rekey rotate {p} {}`.",
                        k.label, k.external_id, k.external_id
                    );
                    continue;
                }
                let extra = dest.consumers(provider, &k);
                k.consumers.extend(extra);
                if let Some(dir) = &secret_dir {
                    let file = format!("{p}-{}.secret", k.external_id);
                    k.consumers.push(Consumer::File {
                        path: dir.join(file).to_string_lossy().into_owned(),
                    });
                }
                if k.consumers.is_empty() {
                    eprintln!(
                        "Skipping {} ({}): nowhere to deliver its new secret. Set it up once \
                         with `rekey rotate {p} {}` (it asks where it goes and can \
                         remember), or pass --secret-dir / --print-secret / --keychain.",
                        k.label, k.external_id, k.external_id
                    );
                    continue;
                }
                todo.push(k);
            }

            if todo.is_empty() {
                anyhow::bail!("nothing to rotate");
            }
            eprintln!("\nWill rotate {} key(s):", todo.len());
            for k in &todo {
                let to: Vec<_> = k.consumers.iter().map(Consumer::describe).collect();
                eprintln!("  {}  {}  → {}", k.external_id, k.label, to.join(", "));
            }
            confirm(&format!("Rotate {} key(s)?", todo.len()), yes, ask, false)?;

            let engine = RotationEngine::new(vec![c]).on_progress(progress());
            let mut failures = 0;
            // One at a time: readable output and no burst against rate limits.
            for k in &todo {
                eprintln!("\n{} ({})", k.label, k.external_id);
                match engine.rotate(k, delete_old_now).await {
                    Ok(outcome) => {
                        if let Some(value) = &outcome.revealed_secret {
                            println!("{}\t{}\t{value}", k.label, outcome.new_external_id);
                        }
                        for line in ops::outcome_lines(provider, k, &outcome) {
                            eprintln!("  {line}");
                        }
                        if !outcome.is_clean() {
                            failures += 1;
                        }
                    }
                    Err(e) => {
                        failures += 1;
                        eprintln!("  ✗ not rotated: {}", explain(provider, e));
                    }
                }
            }
            if failures > 0 {
                anyhow::bail!("{failures} key(s) need attention");
            }
        }

        Command::Retire {
            provider,
            id,
            delete,
            yes,
        } => {
            let c = build_connector(provider, ask).await?;
            let keys = list_keys(provider, &c).await?;
            let current = c.current_key_id().await;
            let secret = select_key(provider, keys, id, current.as_deref(), ask, "retire")?;
            let id = secret.external_id.clone();
            let action = if delete || !c.supports_deactivate() {
                "permanently delete"
            } else {
                "switch off"
            };
            let mut question = format!(
                "This will {action} {} ({id}). Anything still using it will stop working.",
                secret.label
            );
            if current.as_deref() == Some(id.as_str()) {
                question.push_str(" It's also the key rekey is signed in with!");
            }
            question.push_str(" Continue?");
            confirm(&question, yes, ask, false)?;
            let engine = RotationEngine::new(vec![c]);
            let state = engine
                .retire(provider.into(), &id, delete)
                .await
                .map_err(|e| explain(provider, e))?;
            match state {
                OldKeyState::Deactivated => eprintln!(
                    "✓ {} ({id}) is switched off. You can switch it back on in the provider's \
                     console, or delete it for good with: rekey retire {} {id} --delete",
                    secret.label,
                    provider.cli_name()
                ),
                OldKeyState::Deleted => eprintln!("✓ {} ({id}) deleted.", secret.label),
                _ => eprintln!("{} ({id}) unchanged.", secret.label),
            }
        }

        Command::Mcp {
            allow_rotate,
            allow_retire,
        } => {
            mcp::serve(mcp::Options {
                config: cli.config.clone(),
                allow_rotate,
                allow_retire,
            })
            .await?;
        }
    }

    Ok(())
}
