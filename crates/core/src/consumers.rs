use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::models::{Consumer, NewCredential, RotationError};

/// Pushes a freshly minted secret value to every place that consumes it.
/// A new key is useless until `.env` files, CI secrets, SSM params, etc. carry
/// it — this is the half of rotation that keeps the user's apps from breaking.
///
/// Secret values are never passed in a subprocess's argument list (visible in
/// `ps`): `gh` and `aws` read them from stdin instead.
#[derive(Default)]
pub struct ConsumerUpdater;

impl ConsumerUpdater {
    pub async fn update(
        &self,
        consumer: &Consumer,
        cred: &NewCredential,
    ) -> Result<(), RotationError> {
        match consumer {
            Consumer::DotEnvFile {
                path,
                variable,
                id_variable,
            } => {
                let mut vars = vec![(variable.as_str(), cred.secret_value.as_str())];
                if let Some(idv) = id_variable {
                    vars.push((idv.as_str(), cred.external_id.as_str()));
                }
                update_dotenv(Path::new(path), &vars)
            }
            Consumer::File { path } => write_private(
                Path::new(path),
                format!("{}\n", cred.secret_value).as_bytes(),
            ),
            // The engine hands the value back to the caller; nothing to do here.
            Consumer::Reveal => Ok(()),
            Consumer::GithubActionsSecret { repo, secret_name } => {
                // With no --body, `gh secret set` reads the value from stdin.
                let mut cmd = Command::new("gh");
                cmd.args(["secret", "set", secret_name, "--repo", repo]);
                run_with_stdin(
                    cmd,
                    &cred.secret_value,
                    &format!("gh secret set {secret_name}"),
                )
                .await
            }
            Consumer::AwsSsmParameter { name, region } => {
                update_ssm(name, region, &cred.secret_value).await
            }
            Consumer::Keychain { service, account } => {
                keychain_set(service, account, &cred.secret_value)
            }
        }
    }
}

#[cfg(unix)]
async fn update_ssm(name: &str, region: &str, value: &str) -> Result<(), RotationError> {
    // `--cli-input-json file:///dev/stdin` keeps the value out of argv.
    let input = serde_json::json!({
        "Name": name,
        "Value": value,
        "Type": "SecureString",
        "Overwrite": true,
    })
    .to_string();
    let mut cmd = Command::new("aws");
    cmd.args([
        "ssm",
        "put-parameter",
        "--region",
        region,
        "--cli-input-json",
        "file:///dev/stdin",
    ]);
    run_with_stdin(cmd, &input, &format!("ssm put-parameter {name}")).await
}

#[cfg(not(unix))]
async fn update_ssm(name: &str, _region: &str, _value: &str) -> Result<(), RotationError> {
    Err(RotationError::ConsumerUpdate(format!(
        "SSM parameter {name}: SSM consumers are only supported on macOS and Linux"
    )))
}

async fn run_with_stdin(mut cmd: Command, input: &str, what: &str) -> Result<(), RotationError> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).await?;
        // Dropping stdin closes it so the child sees EOF.
    }
    let out = child.wait_with_output().await?;
    if out.status.success() {
        Ok(())
    } else {
        Err(RotationError::ConsumerUpdate(format!(
            "{what}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn keychain_set(service: &str, account: &str, value: &str) -> Result<(), RotationError> {
    crate::credstore::set(service, account, value)
        .map_err(|e| RotationError::ConsumerUpdate(format!("keychain {service}/{account}: {e}")))
}

/// Set `variable` in a `.env` file, preserving every other line, the file's
/// line endings and trailing newline, and its permissions. The file is
/// replaced atomically, so a crash can't leave it half-written.
fn update_dotenv(path: &Path, vars: &[(&str, &str)]) -> Result<(), RotationError> {
    let original = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let updated = vars.iter().fold(original, |text, (var, value)| {
        rewrite_dotenv(&text, var, value)
    });
    write_private(path, updated.as_bytes())
}

/// Pure text transform behind `update_dotenv`.
pub fn rewrite_dotenv(original: &str, variable: &str, value: &str) -> String {
    let eol = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut lines: Vec<String> = original.lines().map(str::to_string).collect();
    let rendered = render_value(value);

    let mut found = false;
    for line in lines.iter_mut() {
        let indent_len = line.len() - line.trim_start().len();
        let (indent, rest) = line.split_at(indent_len);
        let (export, body) = match rest.strip_prefix("export ") {
            Some(b) => ("export ", b.trim_start()),
            None => ("", rest),
        };
        let Some((key, _)) = body.split_once('=') else {
            continue;
        };
        if key.trim() == variable {
            *line = format!("{indent}{export}{variable}={rendered}");
            found = true;
            break;
        }
    }
    if !found {
        lines.push(format!("{variable}={rendered}"));
    }

    let mut out = lines.join(eol);
    // Keep a trailing newline if the file had one (or is new).
    if original.is_empty() || original.ends_with('\n') {
        out.push_str(eol);
    }
    out
}

/// Quote a value only when a dotenv parser could misread it.
fn render_value(value: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_.+/=:@~,%".contains(c);
    if value.chars().all(safe) {
        value.to_string()
    } else if !value.contains('\'') {
        format!("'{value}'")
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Atomically replace `path` with `contents`. Keeps the existing file's
/// permissions; a new file is created readable only by the owner (0600).
/// Symlinks are followed so the link itself survives.
pub(crate) fn write_private(path: &Path, contents: &[u8]) -> Result<(), RotationError> {
    let target: PathBuf = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = match target.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "secret".into());
    let tmp = dir.join(format!(".{name}.keyrotator-{}.tmp", uuid::Uuid::new_v4()));

    let existing_perms = fs::metadata(&target).ok().map(|m| m.permissions());

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        if let Some(perms) = existing_perms {
            fs::set_permissions(&tmp, perms)?;
        }
        fs::rename(&tmp, &target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_in_place_and_keeps_trailing_newline() {
        let out = rewrite_dotenv("A=1\nKEY=old\nB=2\n", "KEY", "new");
        assert_eq!(out, "A=1\nKEY=new\nB=2\n");
    }

    #[test]
    fn keeps_export_prefix_and_indentation() {
        let out = rewrite_dotenv("  export KEY=old\n", "KEY", "new");
        assert_eq!(out, "  export KEY=new\n");
    }

    #[test]
    fn matches_spaces_around_equals() {
        let out = rewrite_dotenv("KEY = old\n", "KEY", "new");
        assert_eq!(out, "KEY=new\n");
    }

    #[test]
    fn does_not_match_prefix_of_other_variable() {
        let out = rewrite_dotenv("KEY_OLD=x\n", "KEY", "new");
        assert_eq!(out, "KEY_OLD=x\nKEY=new\n");
    }

    #[test]
    fn appends_to_empty_file_with_newline() {
        assert_eq!(rewrite_dotenv("", "KEY", "v"), "KEY=v\n");
    }

    #[test]
    fn no_trailing_newline_stays_that_way() {
        assert_eq!(rewrite_dotenv("A=1", "KEY", "v"), "A=1\nKEY=v");
    }

    #[test]
    fn preserves_crlf() {
        assert_eq!(
            rewrite_dotenv("A=1\r\nKEY=o\r\n", "KEY", "n"),
            "A=1\r\nKEY=n\r\n"
        );
    }

    #[test]
    fn quotes_values_that_need_it() {
        assert_eq!(render_value("abc+/=123"), "abc+/=123");
        assert_eq!(render_value("has space#x"), "'has space#x'");
        assert_eq!(render_value("it's \"q\""), "\"it's \\\"q\\\"\"");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_creates_0600_and_keeps_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kr-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let new = dir.join("new.secret");
        write_private(&new, b"x").unwrap();
        assert_eq!(
            fs::metadata(&new).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let existing = dir.join(".env");
        fs::write(&existing, "A=1\n").unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o640)).unwrap();
        update_dotenv(&existing, &[("KEY", "v"), ("KEY_ID", "id1")]).unwrap();
        assert_eq!(
            fs::read_to_string(&existing).unwrap(),
            "A=1\nKEY=v\nKEY_ID=id1\n"
        );
        assert_eq!(
            fs::metadata(&existing).unwrap().permissions().mode() & 0o777,
            0o640
        );

        // No temp files left behind.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }
}
