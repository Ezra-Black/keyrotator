//! Logic shared by the CLI commands and the MCP server.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rekey_core::{Config, Connector, Consumer, OldKeyState, RotationOutcome, Secret};

use crate::providers::Provider;

pub fn load_config(explicit: Option<&Path>) -> Result<Option<(PathBuf, Config)>> {
    Config::discover(explicit).map_err(|e| anyhow::anyhow!("config: {e}"))
}

/// Look up a key by its exact id as shown by `list`.
pub async fn find_key(connector: &Arc<dyn Connector>, id: &str) -> Result<Secret> {
    let keys = connector.list_keys().await?;
    keys.into_iter()
        .find(|s| s.external_id == id)
        .with_context(|| format!("no key with id {id} for this account (see `rekey list`)"))
}

/// Attach the consumers configured for each key.
pub fn attach_config(keys: &mut [Secret], config: Option<&Config>) {
    if let Some(cfg) = config {
        for k in keys {
            k.consumers.extend(cfg.consumers_for(k));
        }
    }
}

pub fn keychain_consumer(provider: Provider, secret: &Secret) -> Consumer {
    Consumer::Keychain {
        service: "rekey".into(),
        account: format!("{}:{}", provider.cli_name(), secret.label),
    }
}

/// Human summary of a rotation. Never includes the secret value.
pub fn outcome_lines(provider: Provider, old: &Secret, o: &RotationOutcome) -> Vec<String> {
    let p = provider.cli_name();
    let old_id = &old.external_id;
    let mut lines = vec![format!("New key id: {}", o.new_external_id)];
    if !o.updated_consumers.is_empty() {
        let names: Vec<_> = o
            .updated_consumers
            .iter()
            .map(crate::guide::describe_target)
            .collect();
        lines.push(format!("Updated: {}", names.join(", ")));
    }
    for (c, e) in &o.failed_consumers {
        lines.push(format!(
            "Failed to update {}: {e}",
            crate::guide::describe_target(c)
        ));
    }
    lines.push(match o.old_key {
        OldKeyState::Revoked => "Old token was revoked by the provider.".into(),
        OldKeyState::Deactivated => format!(
            "Old key {old_id} is deactivated (recoverable). Delete it with \
             `rekey retire {p} {old_id} --delete`."
        ),
        OldKeyState::Deleted => format!("Old key {old_id} deleted."),
        OldKeyState::StillActive => format!(
            "Old key {old_id} is STILL ACTIVE. Once nothing uses it, run \
             `rekey retire {p} {old_id}`."
        ),
        OldKeyState::NotApplicable => "The previous token expires on its own.".into(),
    });
    if let Some(path) = &o.rescue_file {
        lines.push(format!("Rescue copy of the new secret: {}", path.display()));
    }
    for problem in &o.problems {
        lines.push(format!("! {problem}"));
    }
    lines
}
