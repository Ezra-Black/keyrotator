//! A Model Context Protocol server over stdio (newline-delimited JSON-RPC).
//!
//! Safety model:
//! - Read-only by default. `rotate_key` / `retire_key` only exist when the
//!   user starts the server with `--allow-rotate` / `--allow-retire`.
//! - Rotation delivers secrets only to consumers from the user's config file.
//!   The assistant can't choose where a secret goes, so it can't route one
//!   somewhere it can read.
//! - Secret values are never included in any response.
//! - stdout carries protocol messages only; diagnostics go to stderr.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::ValueEnum;
use keyrotator_core::{Consumer, RotationEngine, RotationStyle};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::ops;
use crate::providers::{self, build_connector, Provider};

const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

pub struct Options {
    pub config: Option<PathBuf>,
    pub allow_rotate: bool,
    pub allow_retire: bool,
}

pub async fn serve(opts: Options) -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&opts, msg).await,
            Err(e) => Some(error_response(
                Value::Null,
                -32700,
                &format!("parse error: {e}"),
            )),
        };
        if let Some(resp) = response {
            let mut out = serde_json::to_vec(&resp)?;
            out.push(b'\n');
            stdout.write_all(&out).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Handle one message. Notifications (no `id`) never get a response.
async fn handle(opts: &Options, msg: Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    let id = id?;
    let result = match method {
        "initialize" => Ok(initialize(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools(opts) })),
        "tools/call" => Ok(call_tool(opts, &params).await),
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err((code, m)) => error_response(id, code, &m),
    })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn initialize(params: &Value) -> Value {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let version = PROTOCOL_VERSIONS
        .iter()
        .find(|v| **v == requested)
        .unwrap_or(&PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "keyrotator", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "Rotates API keys for accounts the user administers. Call list_keys to \
            get key ids. rotate_key only delivers new secrets to consumers configured in the \
            user's keyrotator.toml and never returns secret values. Confirm with the user \
            before rotating or retiring keys.",
    })
}

fn provider_prop() -> Value {
    let names: Vec<String> = Provider::value_variants()
        .iter()
        .map(|p| p.cli_name())
        .collect();
    json!({ "type": "string", "enum": names, "description": "Provider name." })
}

fn tools(opts: &Options) -> Vec<Value> {
    let read_only = json!({ "readOnlyHint": true, "openWorldHint": true });
    let mut tools = vec![
        json!({
            "name": "list_providers",
            "description": "List supported providers, their rotation style, and whether \
                credentials for them are set in the server's environment.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": read_only,
        }),
        json!({
            "name": "check_connection",
            "description": "Check that a provider's credentials work and can manage keys.",
            "inputSchema": {
                "type": "object",
                "properties": { "provider": provider_prop() },
                "required": ["provider"],
            },
            "annotations": read_only,
        }),
        json!({
            "name": "list_keys",
            "description": "List a provider's keys with their ids, names, principals, which \
                consumers are configured for each, and which one the server is signed in with.",
            "inputSchema": {
                "type": "object",
                "properties": { "provider": provider_prop() },
                "required": ["provider"],
            },
            "annotations": read_only,
        }),
    ];
    if opts.allow_rotate {
        tools.push(json!({
            "name": "rotate_key",
            "description": "Rotate one key: mint a new one, deliver it to the consumers \
                configured for this key in keyrotator.toml, verify it, then deactivate the old \
                key where possible. Refuses keys with no configured consumers. Never returns \
                the secret value.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "provider": provider_prop(),
                    "id": { "type": "string", "description": "Key id from list_keys." },
                    "delete_old": {
                        "type": "boolean",
                        "description": "Delete the old key immediately instead of leaving it \
                            for retire_key. Default false.",
                    },
                },
                "required": ["provider", "id"],
            },
            "annotations": { "destructiveHint": true, "idempotentHint": false, "openWorldHint": true },
        }));
    }
    if opts.allow_retire {
        tools.push(json!({
            "name": "retire_key",
            "description": "Revoke a key that is no longer used: deactivate it where the \
                provider supports that, otherwise delete it. Anything still using it breaks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "provider": provider_prop(),
                    "id": { "type": "string", "description": "Key id from list_keys." },
                    "delete": {
                        "type": "boolean",
                        "description": "Also permanently delete a key the provider can \
                            deactivate. Default false.",
                    },
                },
                "required": ["provider", "id"],
            },
            "annotations": { "destructiveHint": true, "idempotentHint": true, "openWorldHint": true },
        }));
    }
    tools
}

/// Tool failures are reported as `isError` results (visible to the model),
/// not protocol errors.
async fn call_tool(opts: &Options, params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let result = match name {
        "list_providers" => list_providers(),
        "check_connection" => check_connection(&args).await,
        "list_keys" => list_keys(opts, &args).await,
        "rotate_key" if opts.allow_rotate => rotate_key(opts, &args).await,
        "retire_key" if opts.allow_retire => retire_key(&args).await,
        "rotate_key" | "retire_key" => Err(anyhow::anyhow!(
            "{name} is disabled. The user must start the server with --allow-{}.",
            name.trim_end_matches("_key")
        )),
        other => Err(anyhow::anyhow!("unknown tool: {other}")),
    };
    match result {
        Ok(v) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }],
            "structuredContent": v,
            "isError": false,
        }),
        Err(e) => json!({
            "content": [{ "type": "text", "text": format!("Error: {e:#}") }],
            "isError": true,
        }),
    }
}

fn arg_provider(args: &Value) -> Result<Provider> {
    let s = args
        .get("provider")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing `provider`"))?;
    Provider::parse(s)
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing `{key}`"))
}

fn arg_bool(args: &Value, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn style_name(s: RotationStyle) -> &'static str {
    match s {
        RotationStyle::Overlap => "overlap",
        RotationStyle::AtomicRotate => "atomic",
        RotationStyle::Ephemeral => "ephemeral",
        RotationStyle::Manual => "manual",
    }
}

fn list_providers() -> Result<Value> {
    let rows: Vec<Value> = Provider::value_variants()
        .iter()
        .map(|p| {
            match providers::resolve(*p, false).and_then(|r| providers::connector_from(*p, &r)) {
                Ok(c) => json!({
                    "provider": p.cli_name(),
                    "style": style_name(c.rotation_style()),
                    "credentials": crate::login::status_word(*p),
                }),
                Err(e) => json!({
                    "provider": p.cli_name(),
                    "credentials": format!("missing: {e}"),
                }),
            }
        })
        .collect();
    Ok(json!({ "providers": rows }))
}

async fn check_connection(args: &Value) -> Result<Value> {
    let p = arg_provider(args)?;
    let c = build_connector(p, false).await?;
    c.connect().await?;
    Ok(json!({ "provider": p.cli_name(), "connected": true }))
}

async fn list_keys(opts: &Options, args: &Value) -> Result<Value> {
    let p = arg_provider(args)?;
    let c = build_connector(p, false).await?;
    let config = ops::load_config(opts.config.as_deref())?;
    let mut keys = c.list_keys().await?;
    ops::attach_config(&mut keys, config.as_ref().map(|(_, c)| c));
    let current = c.current_key_id().await;
    let rows: Vec<Value> = keys
        .iter()
        .map(|k| {
            json!({
                "id": k.external_id,
                "name": k.label,
                "principal": k.principal,
                "signed_in_with_this_key": current.as_deref() == Some(k.external_id.as_str()),
                "consumers": k.consumers.iter().map(Consumer::describe).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "provider": p.cli_name(),
        "style": style_name(c.rotation_style()),
        "config_file": config.map(|(path, _)| path.display().to_string()),
        "keys": rows,
    }))
}

async fn rotate_key(opts: &Options, args: &Value) -> Result<Value> {
    let p = arg_provider(args)?;
    let id = arg_str(args, "id")?;
    let delete_old = arg_bool(args, "delete_old");

    let c = build_connector(p, false).await?;
    let config = ops::load_config(opts.config.as_deref())?;
    let Some((config_path, config)) = config else {
        anyhow::bail!(
            "no keyrotator.toml found. Over MCP, new secrets can only be delivered to \
             consumers the user has configured; ask them to add this key to the config."
        );
    };
    let mut secret = ops::find_key(&c, id).await?;
    // Only config consumers: never Reveal, never a path chosen by the caller.
    secret.consumers = config
        .consumers_for(&secret)
        .into_iter()
        .filter(|c| *c != Consumer::Reveal)
        .collect();
    if secret.consumers.is_empty() {
        anyhow::bail!(
            "{} ({id}) has no consumers in {}; ask the user to configure where its new \
             secret should go.",
            secret.label,
            config_path.display()
        );
    }

    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = log.clone();
    let rescue_dir = config_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let engine = RotationEngine::new(vec![c])
        .rescue_dir(rescue_dir)
        .on_progress(Arc::new(move |_, _, msg: &str| {
            sink.lock().unwrap().push(msg.to_string());
        }));

    let outcome = engine.rotate(&secret, delete_old).await;
    let progress = log.lock().unwrap().clone();
    let outcome = outcome.map_err(|e| {
        anyhow::anyhow!(
            "not rotated (nothing changed): {e}\nprogress: {}",
            progress.join(" → ")
        )
    })?;
    Ok(json!({
        "rotated": true,
        "clean": outcome.is_clean(),
        "new_key_id": outcome.new_external_id,
        "old_key_state": outcome.old_key,
        "summary": ops::outcome_lines(p, &secret, &outcome),
        "progress": progress,
    }))
}

async fn retire_key(args: &Value) -> Result<Value> {
    let p = arg_provider(args)?;
    let id = arg_str(args, "id")?;
    let delete = arg_bool(args, "delete");
    let c = build_connector(p, false).await?;
    if c.current_key_id().await.as_deref() == Some(id) {
        anyhow::bail!(
            "{id} is the key this server is signed in with; retiring it over MCP is refused. \
             The user can run `keyrotator retire` themselves."
        );
    }
    ops::find_key(&c, id).await?;
    let engine = RotationEngine::new(vec![c]);
    let state = engine.retire(p.into(), id, delete).await?;
    Ok(json!({ "provider": p.cli_name(), "id": id, "state": state }))
}
