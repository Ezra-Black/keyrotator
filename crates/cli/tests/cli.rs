//! End-to-end tests: the real binary against a fake GitLab API.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

const ADMIN_TOKEN: &str = "glpat-admin";
const NEW_TOKEN: &str = "glpat-NEW-SECRET-VALUE";

/// A minimal GitLab: token 1 is the admin token we sign in with, 4821 is the
/// one we rotate. Records every request as "METHOD /path".
struct FakeGitlab {
    url: String,
    log: Arc<Mutex<Vec<String>>>,
}

impl FakeGitlab {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut token = String::new();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap();
                    match k.to_ascii_lowercase().as_str() {
                        "private-token" => token = v.trim().to_string(),
                        "content-length" => len = v.trim().parse().unwrap(),
                        _ => {}
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();

                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap().to_string();
                let target = parts.next().unwrap().to_string();
                let path = target.split('?').next().unwrap().to_string();
                log2.lock().unwrap().push(format!("{method} {path}"));

                let authed = token == ADMIN_TOKEN || token == NEW_TOKEN;
                let (status, body) = match (method.as_str(), path.as_str()) {
                    _ if !authed => (401, json!({"message": "401 Unauthorized"})),
                    ("GET", "/api/v4/user") => (200, json!({"id": 7, "username": "me"})),
                    ("GET", "/api/v4/personal_access_tokens/self") => {
                        (200, json!({"id": 1, "name": "admin"}))
                    }
                    ("GET", "/api/v4/personal_access_tokens") => (
                        200,
                        json!([{"id": 1, "name": "admin"}, {"id": 4821, "name": "ci-deploy"}]),
                    ),
                    ("POST", p)
                        if p.starts_with("/api/v4/personal_access_tokens/")
                            && p.ends_with("/rotate") =>
                    {
                        (200, json!({"id": 4822, "token": NEW_TOKEN}))
                    }
                    _ => (404, json!({"message": "404 Not Found"})),
                };
                let body = body.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Self { url, log }
    }

    fn rotate_calls(&self) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.ends_with("/rotate"))
            .count()
    }
}

fn tmpdir() -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("kr-cli-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn rekey(gl: &FakeGitlab, cwd: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rekey"));
    cmd.current_dir(cwd)
        .env("GITLAB_URL", &gl.url)
        .env("GITLAB_TOKEN", ADMIN_TOKEN)
        // Don't pick up a real user config or touch the real keychain.
        .env("XDG_CONFIG_HOME", cwd.join("no-xdg"))
        .env("REKEY_TEST_CREDSTORE", cwd.join("credstore.json"))
        .stdin(Stdio::null());
    cmd
}

fn run(cmd: &mut Command) -> (Output, String, String) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out, stdout, stderr)
}

#[test]
fn rotate_without_destination_refuses_before_touching_the_provider() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let (out, _, stderr) = run(rekey(&gl, &dir).args(["rotate", "gitlab", "4821"]));
    assert!(!out.status.success());
    assert!(stderr.contains("nowhere to put the new secret"), "{stderr}");
    assert_eq!(gl.rotate_calls(), 0);
}

#[test]
fn rotate_print_secret_puts_only_the_secret_on_stdout() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let (out, stdout, stderr) =
        run(rekey(&gl, &dir).args(["rotate", "gitlab", "4821", "--print-secret"]));
    assert!(out.status.success(), "{stderr}");
    assert_eq!(stdout, format!("{NEW_TOKEN}\n"));
    assert!(stderr.contains("New key id: 4822"), "{stderr}");
    assert!(stderr.contains("revoked by the provider"), "{stderr}");
    assert!(!stderr.contains(NEW_TOKEN));
}

#[test]
fn rotate_updates_dotenv_and_secret_file() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    std::fs::write(dir.join(".env"), "A=1\nGITLAB_TOKEN=old\n").unwrap();
    let (out, stdout, stderr) = run(rekey(&gl, &dir).args([
        "rotate",
        "gitlab",
        "4821",
        "--dotenv",
        ".env:GITLAB_TOKEN",
        "--secret-file",
        "new.secret",
    ]));
    assert!(out.status.success(), "{stderr}");
    assert!(stdout.is_empty());
    assert_eq!(
        std::fs::read_to_string(dir.join(".env")).unwrap(),
        format!("A=1\nGITLAB_TOKEN={NEW_TOKEN}\n")
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("new.secret")).unwrap(),
        format!("{NEW_TOKEN}\n")
    );
}

#[test]
fn rotate_uses_consumers_from_config_matched_by_name() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    std::fs::write(
        dir.join("rekey.toml"),
        r#"
[[keys]]
provider = "gitlab"
name = "ci-deploy"
consumers = [{ type = "dot_env_file", path = "app.env", variable = "TOKEN" }]
"#,
    )
    .unwrap();
    let (out, _, stderr) = run(rekey(&gl, &dir).args(["rotate", "gitlab", "4821"]));
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(dir.join("app.env")).unwrap(),
        format!("TOKEN={NEW_TOKEN}\n")
    );
}

#[test]
fn list_shows_full_ids_and_flags_the_signed_in_key() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let (out, stdout, stderr) = run(rekey(&gl, &dir).args(["list", "gitlab"]));
    assert!(out.status.success(), "{stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("1\tadmin") && lines[0].contains("signed in with this key"));
    assert!(lines[1].starts_with("4821\tci-deploy"));
}

#[test]
fn rotate_all_needs_confirmation_and_skips_the_signed_in_key() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let secrets = dir.join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    let secrets_arg = secrets.to_string_lossy().into_owned();

    // No terminal and no --yes: refuse without rotating anything.
    let (out, _, stderr) =
        run(rekey(&gl, &dir).args(["rotate-all", "gitlab", "--secret-dir", &secrets_arg]));
    assert!(!out.status.success());
    assert!(stderr.contains("--yes"), "{stderr}");
    assert_eq!(gl.rotate_calls(), 0);

    let (out, _, stderr) = run(rekey(&gl, &dir).args([
        "rotate-all",
        "gitlab",
        "--secret-dir",
        &secrets_arg,
        "--yes",
    ]));
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("Skipping admin (1)"), "{stderr}");
    assert_eq!(gl.rotate_calls(), 1);
    let file = secrets.join("gitlab-4821.secret");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("{NEW_TOKEN}\n")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn retire_is_refused_for_atomic_providers() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let (out, _, stderr) = run(rekey(&gl, &dir).args(["retire", "gitlab", "4821", "--yes"]));
    assert!(!out.status.success());
    assert!(stderr.contains("nothing to retire"), "{stderr}");
}

/// Drive `rekey mcp` with a batch of JSON-RPC messages.
fn mcp(gl: &FakeGitlab, dir: &Path, flags: &[&str], messages: &[Value]) -> Vec<Value> {
    let mut child = rekey(gl, dir)
        .arg("mcp")
        .args(flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for m in messages {
            writeln!(stdin, "{m}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("stdout is pure JSON-RPC"))
        .collect()
}

fn init() -> Value {
    json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}}})
}

fn call(id: u64, name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": args}})
}

#[test]
fn mcp_is_read_only_by_default() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let resp = mcp(
        &gl,
        &dir,
        &[],
        &[
            init(),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            call(2, "list_keys", json!({"provider": "gitlab"})),
            call(3, "rotate_key", json!({"provider": "gitlab", "id": "4821"})),
            json!({"jsonrpc": "2.0", "id": 4, "method": "bogus"}),
        ],
    );
    // The notification gets no response.
    assert_eq!(resp.len(), 5);
    assert_eq!(resp[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(resp[0]["result"]["serverInfo"]["name"], "rekey");

    let names: Vec<&str> = resp[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["list_providers", "check_connection", "list_keys"]);

    let keys = &resp[2]["result"]["structuredContent"]["keys"];
    assert_eq!(keys[0]["id"], "1");
    assert_eq!(keys[0]["signed_in_with_this_key"], true);
    assert_eq!(keys[1]["id"], "4821");

    assert_eq!(resp[3]["result"]["isError"], true);
    assert_eq!(resp[4]["error"]["code"], -32601);
    assert_eq!(gl.rotate_calls(), 0);
}

#[test]
fn mcp_rotates_only_to_configured_consumers_and_never_returns_the_secret() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let flags = ["--allow-rotate"];

    // No config: refuse without touching the provider.
    let resp = mcp(
        &gl,
        &dir,
        &flags,
        &[
            init(),
            call(1, "rotate_key", json!({"provider": "gitlab", "id": "4821"})),
        ],
    );
    assert_eq!(resp[1]["result"]["isError"], true);
    assert_eq!(gl.rotate_calls(), 0);

    std::fs::write(
        dir.join("rekey.toml"),
        r#"
[[keys]]
provider = "gitlab"
name = "ci-deploy"
consumers = [{ type = "dot_env_file", path = ".env", variable = "GITLAB_TOKEN" }]
"#,
    )
    .unwrap();
    let resp = mcp(
        &gl,
        &dir,
        &flags,
        &[
            init(),
            call(1, "rotate_key", json!({"provider": "gitlab", "id": "4821"})),
        ],
    );
    let result = &resp[1]["result"];
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(result["structuredContent"]["new_key_id"], "4822");
    assert_eq!(result["structuredContent"]["old_key_state"], "revoked");
    assert!(!resp[1].to_string().contains(NEW_TOKEN));
    assert_eq!(
        std::fs::read_to_string(dir.join(".env")).unwrap(),
        format!("GITLAB_TOKEN={NEW_TOKEN}\n")
    );
}

/// Fake `gh` / `aws` binaries record their argv and stdin, proving the secret
/// travels over stdin and never appears in a process's argument list.
#[cfg(unix)]
#[test]
fn ci_consumers_never_put_the_secret_in_argv() {
    use std::os::unix::fs::PermissionsExt;
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for tool in ["gh", "aws"] {
        let script = format!(
            "#!/bin/sh\necho \"$@\" > \"{d}/{tool}.argv\"\ncat > \"{d}/{tool}.stdin\"\n",
            d = dir.display()
        );
        let path = bin.join(tool);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let (out, _, stderr) = run(rekey(&gl, &dir).env("PATH", path).args([
        "rotate",
        "gitlab",
        "4821",
        "--gh-secret",
        "me/app:GITLAB_TOKEN",
        "--ssm",
        "/ci/gitlab:us-east-1",
    ]));
    assert!(out.status.success(), "{stderr}");

    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap();
    assert_eq!(
        read("gh.argv").trim(),
        "secret set GITLAB_TOKEN --repo me/app"
    );
    assert_eq!(read("gh.stdin"), NEW_TOKEN);
    assert!(!read("aws.argv").contains(NEW_TOKEN));
    let ssm: Value = serde_json::from_str(&read("aws.stdin")).unwrap();
    assert_eq!(ssm["Name"], "/ci/gitlab");
    assert_eq!(ssm["Value"], NEW_TOKEN);
    assert_eq!(ssm["Type"], "SecureString");
}

/// With AWS_PROFILE set, verification must use only the new key — a
/// `--profile` flag would silently verify the old key instead.
#[cfg(unix)]
#[test]
fn aws_verify_uses_only_the_new_key() {
    use std::os::unix::fs::PermissionsExt;
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = format!(
        r#"#!/bin/sh
case "$1 $2" in
  "iam list-access-keys") echo '{{"AccessKeyMetadata":[{{"AccessKeyId":"AKIAOLD000000000","UserName":"ci"}}]}}' ;;
  "iam create-access-key") echo '{{"AccessKey":{{"AccessKeyId":"AKIANEW000000000","SecretAccessKey":"sekret"}}}}' ;;
  "sts get-caller-identity") echo "args=$* key=$AWS_ACCESS_KEY_ID profile=${{AWS_PROFILE-unset}}" >> "{d}/verify.log"; echo '{{}}' ;;
  "configure get") exit 1 ;;
  *) echo "$*" >> "{d}/other.log" ;;
esac
"#,
        d = dir.display()
    );
    let aws = bin.join("aws");
    std::fs::write(&aws, script).unwrap();
    std::fs::set_permissions(&aws, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());

    std::fs::write(
        dir.join("rekey.toml"),
        r#"
[[keys]]
provider = "aws"
principal = "ci"
consumers = [{ type = "dot_env_file", path = ".env", variable = "AWS_SECRET_ACCESS_KEY", id_variable = "AWS_ACCESS_KEY_ID" }]
"#,
    )
    .unwrap();
    let (out, stdout, stderr) = run(rekey(&gl, &dir)
        .env("PATH", path)
        .env("AWS_PROFILE", "prod")
        .args(["rotate", "aws", "AKIAOLD000000000", "--print-secret"]));
    assert!(out.status.success(), "{stderr}");
    assert_eq!(stdout, "sekret\n");

    let verify = std::fs::read_to_string(dir.join("verify.log")).unwrap();
    assert_eq!(
        verify.trim(),
        "args=sts get-caller-identity --output json key=AKIANEW000000000 profile=unset"
    );
    let other = std::fs::read_to_string(dir.join("other.log")).unwrap();
    assert!(other.contains(
        "iam update-access-key --access-key-id AKIAOLD000000000 --status Inactive --profile prod"
    ));
    assert!(stderr.contains("is deactivated"), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(dir.join(".env")).unwrap(),
        "AWS_SECRET_ACCESS_KEY=sekret\nAWS_ACCESS_KEY_ID=AKIANEW000000000\n"
    );
}

fn saved(dir: &Path) -> Value {
    std::fs::read_to_string(dir.join("credstore.json"))
        .map(|s| serde_json::from_str(&s).unwrap())
        .unwrap_or(json!({}))
}

#[test]
fn login_saves_credentials_and_later_runs_need_no_export() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();

    // A rejected token is never saved.
    let (out, _, stderr) = run(rekey(&gl, &dir)
        .env("GITLAB_TOKEN", "glpat-wrong")
        .args(["login", "gitlab"]));
    assert!(!out.status.success());
    assert!(stderr.contains("nothing was saved"), "{stderr}");
    assert_eq!(saved(&dir), json!({}));

    let (out, _, stderr) = run(rekey(&gl, &dir).args(["login", "gitlab"]));
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("Logged in to GitLab as @me"), "{stderr}");
    assert_eq!(saved(&dir)["rekey-login/GITLAB_TOKEN"], ADMIN_TOKEN);

    // No GITLAB_TOKEN in the environment: the saved login is used.
    let (out, _, stderr) = run(rekey(&gl, &dir)
        .env_remove("GITLAB_TOKEN")
        .args(["connect", "gitlab"]));
    assert!(out.status.success(), "{stderr}");

    let (out, _, stderr) = run(rekey(&gl, &dir).env_remove("GITLAB_TOKEN").args(["login"]));
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("gitlab       saved login"), "{stderr}");

    let (out, _, stderr) = run(rekey(&gl, &dir).args(["logout", "gitlab"]));
    assert!(out.status.success(), "{stderr}");
    assert_eq!(saved(&dir), json!({}));

    let (out, _, stderr) = run(rekey(&gl, &dir)
        .env_remove("GITLAB_TOKEN")
        .args(["connect", "gitlab"]));
    assert!(!out.status.success());
    assert!(stderr.contains("rekey login gitlab"), "{stderr}");
}

#[test]
fn rejected_saved_login_says_how_to_fix_it() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    std::fs::write(
        dir.join("credstore.json"),
        json!({"rekey-login/GITLAB_TOKEN": "glpat-revoked"}).to_string(),
    )
    .unwrap();
    let (out, _, stderr) = run(rekey(&gl, &dir)
        .env_remove("GITLAB_TOKEN")
        .args(["connect", "gitlab"]));
    assert!(!out.status.success());
    assert!(
        stderr.contains("GITLAB_TOKEN from your saved login"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Replace it with: rekey login gitlab"),
        "{stderr}"
    );
}

#[test]
fn rotating_the_login_token_updates_the_saved_login() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let (out, _, stderr) = run(rekey(&gl, &dir).args(["login", "gitlab"]));
    assert!(out.status.success(), "{stderr}");

    // Token 1 is the one rekey signs in with. The saved login counts as a
    // destination, so no other flag is needed.
    let (out, _, stderr) = run(rekey(&gl, &dir)
        .env_remove("GITLAB_TOKEN")
        .args(["rotate", "gitlab", "1"]));
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("saved login will be updated"), "{stderr}");
    assert!(
        stderr.contains("Updated: your saved rekey login"),
        "{stderr}"
    );
    assert_eq!(saved(&dir)["rekey-login/GITLAB_TOKEN"], NEW_TOKEN);

    // And rekey keeps working with the new token.
    let (out, _, stderr) = run(rekey(&gl, &dir)
        .env_remove("GITLAB_TOKEN")
        .args(["connect", "gitlab"]));
    assert!(out.status.success(), "{stderr}");
}

#[test]
fn login_ignores_a_token_from_another_provider() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    let (out, _, stderr) = run(rekey(&gl, &dir)
        .env("GITLAB_TOKEN", "ghp_notagitlabtoken")
        .args(["login", "gitlab"]));
    assert!(!out.status.success());
    assert!(stderr.contains("Ignoring GITLAB_TOKEN"), "{stderr}");
    assert!(stderr.contains("looks like a GitHub token"), "{stderr}");
    // Only a prefix of the value is ever shown.
    assert!(
        stderr.contains("ghp_no…") && !stderr.contains("ghp_notagitlabtoken"),
        "{stderr}"
    );
    assert_eq!(saved(&dir), json!({}));
}

#[test]
fn login_url_is_saved_only_when_not_the_default() {
    let gl = FakeGitlab::start();
    let dir = tmpdir();
    // The fake server stands in for a self-hosted GitLab.
    let (out, _, stderr) = run(rekey(&gl, &dir).env_remove("GITLAB_URL").args([
        "login",
        "gitlab",
        "--url",
        &format!("{}/", gl.url),
    ]));
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("Logging in to GitLab at {}.", gl.url)),
        "{stderr}"
    );
    assert_eq!(saved(&dir)["rekey-login/GITLAB_URL"], gl.url.as_str());

    // With the saved URL, nothing else needs to be set.
    let (out, _, stderr) = run(rekey(&gl, &dir)
        .env_remove("GITLAB_URL")
        .env_remove("GITLAB_TOKEN")
        .args(["connect", "gitlab"]));
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("Connected to GitLab as @me"), "{stderr}");
}
