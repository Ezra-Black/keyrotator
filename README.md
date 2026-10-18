# keyrotator

A command-line tool that rotates the API keys and tokens you actually use —
AWS, GitLab, Cloudflare, Datadog, npm, Docker Hub, OpenAI, Twilio, SendGrid,
GitHub Apps — one command for all of them, or one key at a time.

It does the whole job, not half of it: it mints the new key, pushes it to every
place that uses it (`.env` files, GitHub Actions secrets, AWS SSM), checks the
new key actually works, and only then retires the old one. If anything goes
wrong mid-rotation, it rolls back so you're never left with a broken key.

> **It only touches accounts you administer.** Every provider connects with
> *your own* credential and acts as you. There is no magic that rotates a key
> you merely found — if you've got a leaked key, revoke it from the owning
> account and report it to the provider.

---

## Contents

- [Why this exists](#why-this-exists)
- [How rotation works](#how-rotation-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Providers](#providers)
  - [Per-provider setup](#per-provider-setup)
- [Keeping consumers in sync](#keeping-consumers-in-sync)
- [Using it from an AI assistant (MCP)](#using-it-from-an-ai-assistant-mcp)
- [Where secrets are stored](#where-secrets-are-stored)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists

Rotating keys by hand is tedious enough that most people just don't. You log
into five dashboards, generate new keys, paste them into CI and `.env` files,
hope you didn't miss one, and hope the old keys weren't still in use somewhere.

The hard part isn't generating a new key — it's the two things around it:

1. **Updating everywhere the key is used.** A fresh key is useless until every
   consumer has it. Miss one and you've taken down a service.
2. **Not killing the old key until the new one is proven.** Revoke too early
   and you've got an outage; too late and the leak stays open.

keyrotator handles both. You tell it where each key is consumed once, and from
then on rotation is a single command.

### Providers don't rotate the same way

This is the one design idea worth understanding. Different APIs behave
differently, and the tool adapts instead of pretending they're all the same:

| Style | What the provider does | Can we roll back? | Example |
|-------|------------------------|-------------------|---------|
| **Overlap** | lets you create a second key while the first still works | Yes | AWS, Datadog, Twilio |
| **Atomic** | one call swaps the secret and kills the old one instantly | No | GitLab, Cloudflare |
| **Ephemeral** | you mint a short-lived token on demand; it expires itself | N/A | GitHub App |
| **Manual** | no API to create a key (console only) | N/A | Anthropic |

For **Overlap** providers you get the full safety net. For **Atomic** ones the
old secret dies the moment you rotate, so the tool gets consumers onto the new
secret and verifies immediately — but there's nothing to roll back to, so a
failed verify is loud. For **Ephemeral** (GitHub App) there's no stored secret
to rotate at all; you mint a fresh token each time. For **Manual** ones the tool
can revoke the old key but you create the new one in the web console.

---

## How rotation works

For an **Overlap** provider, `keyrotator rotate` runs these steps in order:

```
1. create        mint the new key           (old key still works)
2. verify        confirm the new key authenticates
3. update        push it to every consumer  (.env, CI secrets, SSM, file…)
4. deactivate    disable the old key        (where the provider can)
5. delete        remove the old key         (with --delete-old-now, or later via `retire`)
```

If step 1–2 fails, or *every* consumer update fails, the new key is deleted and
the old one is left untouched — you end exactly where you started. If only
*some* consumers fail, both keys stay live (nothing is broken) and the tool
tells you which consumers to fix before you retire the old key.

**A new secret always has somewhere to go.** `rotate` refuses to start unless
the key has at least one consumer — a config entry, a destination flag such as
`--dotenv` or `--secret-file`, or `--print-secret`. A key minted and then
dropped on the floor is worse than no rotation at all.

**Atomic** providers can't overlap: rotate → update consumers → verify. Every
consumer is attempted; if all of them fail, the secret is written to an
owner-only `keyrotator-rescue-*.secret` file rather than lost.
**Ephemeral** providers mint → verify → update. **Manual** providers stop and
tell you what to do in the console.

---

## Install

You need the [Rust toolchain](https://rustup.rs) (stable). Then:

```bash
git clone https://github.com/Ezra-Black/keyrotator.git
cd keyrotator
cargo build --release
```

The binary lands at `target/release/keyrotator`. Put it on your `PATH`:

```bash
cp target/release/keyrotator /usr/local/bin/      # or ~/.local/bin
```

Or install straight from the repo:

```bash
cargo install --path crates/cli
```

That's it — OS keychain support (for `keyrotator login` and `--keychain`) is
built in on macOS, Windows and Linux. To leave it out, build with
`--no-default-features` on `keyrotator-core`.

### Tools some providers shell out to

- **AWS** uses the `aws` CLI — install it and sign in (`aws sso login` or a
  configured profile).
- **npm** uses the `npm` CLI — you need to be logged in (`npm login`).
- **GitHub Actions** consumers use the `gh` CLI (`gh auth login`).

Everything else talks to the provider's REST API directly and needs no extra
tooling.

---

## Quick start

Log in once — keyrotator checks the token works and saves it in your OS
keychain, so it works from every terminal with nothing to `export`:

```bash
keyrotator login gitlab
```

Then rotate:

```bash
keyrotator rotate gitlab
```

keyrotator walks you through it: it lets you pick which token to rotate, asks where the new one should go (a `.env`
file, a private file, a GitHub Actions secret, your keychain, or just shown
once), shows exactly what's about to happen, and waits for your OK. It can
remember where each key goes, so the next rotation is one command and one
"yes".

Everything it asks can also be given as flags, in any order — handy for
scripts and CI, where `--no-input` turns questions into clear errors:

```bash
export GITLAB_TOKEN=glpat-xxxxxxxxxxxx
keyrotator rotate gitlab 4821 --dotenv .env                    # writes GITLAB_TOKEN in .env
keyrotator rotate gitlab 4821 --dotenv .env:MY_TOKEN --yes     # pick the variable, skip the prompt
```

For anything you rotate more than once, describe its consumers in a
[`keyrotator.toml`](#keeping-consumers-in-sync) and then it's just:

```bash
keyrotator rotate-all gitlab
```

### Where credentials come from

keyrotator looks for each provider credential in this order:

1. **An environment variable** (e.g. `GITLAB_TOKEN`) — for CI and one-off
   overrides. Remember `export`; a plain `VAR=...` line isn't visible to
   programs you run.
2. **A saved login** from `keyrotator login <provider>`, kept in your OS
   keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service).
3. **Asking you**, in a terminal — and offering to save what you type.

Credentials are never taken as command-line flags, so nothing sensitive lands
in your shell history. `keyrotator login` with no provider shows what's set;
`keyrotator logout <provider>` removes a saved login. If you rotate the very
token keyrotator signs in with (GitLab, Cloudflare), a saved login is updated
to the new token automatically. The
[per-provider setup](#per-provider-setup) section lists each provider's
variables. Set `KEYROTATOR_DISABLE_KEYCHAIN=1` to keep keyrotator away from the
keychain entirely (e.g. in CI).

---

## Commands

```
keyrotator login       [provider]                 save credentials in your OS keychain
keyrotator logout      <provider>                 remove saved credentials
keyrotator connect     <provider>                 check credentials and access
keyrotator list        <provider>                 list keys and their ids
keyrotator rotate      <provider> <id> [dest...]  rotate one key
keyrotator rotate-all  <provider> [dest...]       rotate every key that has a destination
keyrotator retire      <provider> <id>            revoke a key you no longer use
keyrotator mcp                                    run as an MCP server (see below)
```

- `<provider>` is one of: `aws`, `gitlab`, `cloudflare`, `datadog`, `npm`,
  `dockerhub`, `openai`, `anthropic`, `twilio`, `sendgrid`, `github-app`.
- `<id>` is the key's native id, exactly as printed by `list` (first column).
- Leave out `<id>` (or anything else) in a terminal and keyrotator asks.
  `--no-input` makes it fail with an explanation instead; `--yes` skips the
  "go ahead?" question.
- `--config <path>` picks a config file; otherwise `./keyrotator.toml`, then
  `~/.config/keyrotator/config.toml`, is used if present.

Where the new secret goes (combine as many as you like; config consumers are
always included):

| Flag | Destination |
|------|-------------|
| `--print-secret` | stdout — the only thing written there, so `$(…)` captures it cleanly |
| `--secret-file <path>` | a file created owner-only (0600) |
| `--dotenv <path>[:<VAR>]` | sets `VAR` in a `.env` file; `VAR` defaults to the provider's usual name (e.g. `GITLAB_TOKEN`; for AWS both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`). Repeatable |
| `--gh-secret <owner/repo>:<NAME>` | a GitHub Actions secret via `gh` (repeatable) |
| `--ssm <name>:<region>` | an AWS SSM `SecureString` (repeatable) |
| `--keychain` | the OS keychain, service `keyrotator` |
| `--secret-dir <dir>` | `rotate-all` only: one 0600 file per key |

Other options:

- `--delete-old-now` deletes the old key as soon as the new one is delivered.
  Without it, the old key is deactivated where the provider supports that (AWS)
  and otherwise **left active** — the output says which, and gives you the
  `retire` command to run once nothing uses it.
- `rotate-all` lists what it's about to do and asks for confirmation (`--yes`
  to skip). It skips keys with nowhere to deliver a secret, and the key you're
  signed in with when the provider can tell (GitLab, Cloudflare, Twilio, AWS
  static keys).
- `retire` deactivates a key where the provider supports it, otherwise deletes
  it; `--delete` also deletes a deactivated key. It asks for confirmation
  (`--yes` to skip).

Status goes to stderr. A rotation that changed something but needs attention
(a consumer failed, the old key couldn't be deactivated) exits non-zero after
printing exactly what's left to do.

Run `connect` first whenever you set up a new provider — it's a cheap check that
your credentials are right before you try to rotate anything.

---

## Providers

| Provider | Style | What it rotates | Needs |
|----------|-------|-----------------|-------|
| AWS IAM | Overlap | IAM access keys | `aws` CLI session |
| GitLab | Atomic | personal access tokens | `GITLAB_TOKEN` |
| Cloudflare | Atomic | user API tokens | `CLOUDFLARE_API_TOKEN` |
| Datadog | Overlap | API keys | `DD_API_KEY` + `DD_APP_KEY` |
| npm | Overlap | classic automation tokens | `npm` CLI session |
| Docker Hub | Overlap | personal access tokens | username + password/PAT |
| OpenAI | Overlap | org **admin** keys | `OPENAI_ADMIN_KEY` |
| Anthropic | Manual | — (revoke only) | `ANTHROPIC_ADMIN_KEY` |
| Twilio | Overlap | Standard API keys | Account SID + Auth Token |
| GitHub App | Ephemeral | installation tokens | App ID + private key |
| SendGrid | Overlap | API keys | `SENDGRID_API_KEY` |

### Per-provider setup

Each provider below lists the credential you need, how to get it, the
environment variables to set, and anything that'll trip you up.

#### AWS IAM

Rotates IAM access keys. IAM allows two access keys per user, which is what
makes safe overlap possible.

- **Credential:** none to set — it reuses your `aws` CLI session. Sign in with
  `aws sso login`, a named profile, or an assumed role.
- **Env:** `AWS_PROFILE` (optional) to pin a profile.

```bash
aws sso login
keyrotator rotate aws AKIAEXAMPLE --dotenv .env:AWS_SECRET_ACCESS_KEY
```

AWS keys come as a pair: the new **access key id** is printed on stderr, and a
`.env` consumer in `keyrotator.toml` can write it too with
`id_variable = "AWS_ACCESS_KEY_ID"` (see
[Keeping consumers in sync](#keeping-consumers-in-sync)). Without
`--delete-old-now` the old key is set to Inactive, so you can flip it back on in
the IAM console if something was missed.

**Gotcha:** if the user already has two access keys, rotation refuses rather
than guessing which to destroy. Delete the unused one first.

#### GitLab

Rotates personal access tokens. GitLab's rotate endpoint mints the new token and
revokes the old one in a single call (Atomic).

- **Credential:** a PAT with the `api` scope.
- **Env:** `GITLAB_TOKEN` (required), `GITLAB_URL` (for self-hosted, e.g.
  `https://gitlab.example.com`), `GITLAB_TOKEN_EXPIRY_DAYS` (optional expiry for
  the rotated token).

```bash
export GITLAB_TOKEN=glpat-xxxxxxxxxxxx
keyrotator list gitlab
keyrotator rotate gitlab 4821 --dotenv .env:GITLAB_TOKEN   # 4821 = id from `list`
```

**Gotcha:** rotating the token you're authenticating with invalidates
`GITLAB_TOKEN`. `list` marks that token, `rotate-all` skips it, and if you
rotate it on purpose, give it a destination (e.g. `--print-secret`) and update
`GITLAB_TOKEN` afterwards.

#### Cloudflare

Rotates user API tokens via the roll endpoint (Atomic): the token keeps its id,
gets a new secret, and the old secret stops working immediately.

- **Credential:** an API token with the **API Tokens Write** permission.
- **Env:** `CLOUDFLARE_API_TOKEN`.

```bash
export CLOUDFLARE_API_TOKEN=xxxxxxxx
keyrotator rotate-all cloudflare
```

#### Datadog

Rotates API keys. Datadog's management endpoints need both an API key and an
application key.

- **Credential:** an existing API key plus an application key with the scopes to
  manage keys.
- **Env:** `DD_API_KEY`, `DD_APP_KEY`, `DD_SITE` (optional, e.g.
  `datadoghq.eu`; defaults to `datadoghq.com`).

```bash
export DD_API_KEY=xxxxxxxx DD_APP_KEY=yyyyyyyy
keyrotator rotate datadog <api-key-id> --dotenv .env:DD_API_KEY --delete-old-now
```

**Gotcha:** Datadog keys have no "disabled" state, so the old key keeps working
until it's deleted. Use `--delete-old-now`, or run `keyrotator retire datadog
<old-id>` once nothing uses it.

#### npm

Rotates classic automation tokens via the `npm` CLI.

- **Credential:** a logged-in npm session (`npm login`).
- **Env:** `NPM_REGISTRY` (optional, for a private registry).

```bash
npm login
keyrotator rotate-all npm --secret-dir ~/secrets
```

**Gotcha:** the `npm` CLI has no stable machine-readable output for tokens, so
this parses human output and targets *classic* tokens. Fine-grained/granular
tokens are web-only and aren't handled here.

#### Docker Hub

Rotates personal access tokens.

- **Credential:** your username plus a password or an existing PAT (used to get
  a short-lived session for the management calls).
- **Env:** `DOCKERHUB_USERNAME`, `DOCKERHUB_PASSWORD`.

```bash
export DOCKERHUB_USERNAME=you DOCKERHUB_PASSWORD=xxxxxxxx
keyrotator rotate dockerhub <token-uuid> --secret-file ~/secrets/dockerhub --delete-old-now
```

**Note:** the new token is created with `repo:read` + `repo:write` scopes,
whatever the old one had.

#### OpenAI

Rotates organization **admin** keys.

- **Credential:** an organization admin key.
- **Env:** `OPENAI_ADMIN_KEY`.

```bash
export OPENAI_ADMIN_KEY=sk-admin-xxxxxxxx
keyrotator rotate openai <key-id> --keychain --delete-old-now
```

**Note:** this rotates *admin* keys. The `sk-...` project keys your apps use are
best rotated by creating a project service account key — that's a natural next
connector to add (see [Contributing](#contributing)).

#### Anthropic

Manual style. The Admin API can list and deactivate keys but has **no endpoint
to create one** — keys are made in the Console. So the tool can't fully
auto-rotate here.

- **Credential:** an Admin API key.
- **Env:** `ANTHROPIC_ADMIN_KEY`.

```bash
export ANTHROPIC_ADMIN_KEY=sk-ant-admin-xxxxxxxx
keyrotator rotate anthropic <key-id>
# → prints the Console URL and steps. Once you've made the new key and
#   pointed your apps at it, revoke the old one:
keyrotator retire anthropic <key-id>
```

#### Twilio

Rotates Standard API keys.

- **Credential:** your Account SID and Auth Token (or an existing API key
  sid/secret with permission to manage keys).
- **Env:** `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_API_USER`
  (optional; defaults to the Account SID).

```bash
export TWILIO_ACCOUNT_SID=ACxxxxxxxx TWILIO_AUTH_TOKEN=xxxxxxxx
keyrotator rotate twilio <key-sid> --dotenv .env:TWILIO_API_SECRET --delete-old-now
```

#### SendGrid

Rotates API keys, carrying over the old key's scopes to the new one.

- **Credential:** an API key with the `api_keys.create`, `api_keys.read`, and
  `api_keys.delete` scopes.
- **Env:** `SENDGRID_API_KEY`.

```bash
export SENDGRID_API_KEY=SG.xxxxxxxx
keyrotator rotate-all sendgrid --keychain
```

#### GitHub App

The best-behaved provider, and the right way to automate GitHub. Instead of a
long-lived PAT, the tool holds your App's private key and mints a fresh
**installation token** (valid ~1 hour) on demand. "Rotation" is just minting a
new one — the old token expires by itself.

- **Credential:** your GitHub App's numeric ID and its private key (`.pem`).
- **Env:** `GITHUB_APP_ID`, and either `GITHUB_APP_PRIVATE_KEY` (the PEM
  contents) or `GITHUB_APP_PRIVATE_KEY_PATH` (a path to the `.pem`).

```bash
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY_PATH=~/secrets/my-app.private-key.pem
keyrotator list github-app                 # shows each installation
keyrotator rotate github-app <installation-id> --dotenv .env:GITHUB_TOKEN
```

The only long-lived secret is the App private key, which you rotate rarely (and
can hold two of) in the App's settings.

---

## Keeping consumers in sync

A "consumer" is any place that uses a key and must be updated when it rotates:

- **`.env` files** — rewrites one `VAR=...` line in place (keeping `export`,
  the rest of the file, its permissions and trailing newline), atomically.
- **GitHub Actions secrets** — via `gh secret set`.
- **AWS SSM Parameter Store** — as a `SecureString`.
- **A file** — the raw secret, owner-only.
- **The OS keychain**.

Describe them once in `keyrotator.toml` (in the current directory, or
`~/.config/keyrotator/config.toml`). See
[`keyrotator.toml.example`](keyrotator.toml.example) for every option.

```toml
[[keys]]
provider = "gitlab"
name = "ci-deploy"                  # match by name, id, and/or principal
consumers = [
  { type = "dot_env_file", path = ".env", variable = "GITLAB_TOKEN" },
  { type = "github_actions_secret", repo = "me/my-app", secret_name = "GITLAB_TOKEN" },
]

[[keys]]
provider = "aws"
principal = "ci-user"               # the IAM user — survives the new key id
consumers = [
  { type = "dot_env_file", path = ".env", variable = "AWS_SECRET_ACCESS_KEY", id_variable = "AWS_ACCESS_KEY_ID" },
  { type = "aws_ssm_parameter", name = "/ci/aws-secret", region = "us-east-1" },
]
```

Match on `name` or `principal` rather than `id` for providers that issue a new
id on every rotation (AWS, GitLab, Datadog, OpenAI, Twilio, SendGrid, Docker
Hub); otherwise the entry stops matching after the first rotation. Relative
paths are relative to the config file. `keyrotator list` shows how many
consumers each key has.

---

## Using it from an AI assistant (MCP)

`keyrotator mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io)
server on stdio, so Claude and other MCP clients can check, list and rotate
your keys.

Run `keyrotator login <provider>` first: the server reads saved logins from
your keychain, so no token has to go into your MCP client's config file.

```json
{
  "mcpServers": {
    "keyrotator": {
      "command": "keyrotator",
      "args": ["mcp", "--config", "/Users/me/.config/keyrotator/config.toml"]
    }
  }
}
```

With Claude Code:

```bash
claude mcp add keyrotator -- keyrotator mcp --config ~/.config/keyrotator/config.toml
```

(On macOS, the first time the server reads a saved login after you install or
update keyrotator, the Keychain may ask you to allow it — choose
**Always Allow**.)

| Tool | Available | What it does |
|------|-----------|--------------|
| `list_providers` | always | providers, rotation style, whether credentials are set |
| `check_connection` | always | runs `connect` for a provider |
| `list_keys` | always | key ids, names, configured consumers, which key the server signs in with |
| `rotate_key` | with `--allow-rotate` | rotates one key into its configured consumers |
| `retire_key` | with `--allow-retire` | deactivates/deletes an old key |

Guardrails, because the assistant is driving:

- **Read-only by default.** The write tools don't exist unless you start the
  server with `--allow-rotate` / `--allow-retire`, and they're marked
  destructive so your client asks before each call.
- **Secrets never reach the model.** `rotate_key` returns ids and a summary,
  never a secret value.
- **The assistant can't choose where secrets go.** `rotate_key` only delivers
  to consumers in *your* config file — it has no destination arguments, so it
  can't route a secret somewhere it could read. Keys with no configured
  consumers are refused.
- `retire_key` refuses to revoke the key the server itself is signed in with.

---

## Where secrets are stored

- New secret values go only to the consumers you configure or pass as flags.
  Nothing is cached by the tool between runs.
- Provider logins you save with `keyrotator login` live in your OS keychain
  under the service `keyrotator-login`, never in a file.
- Files the tool creates (`--secret-file`, `--secret-dir`, rescue files, new
  `.env` files) are owner-only (0600); existing `.env` files keep their
  permissions.
- Secrets handed to `gh` and `aws` go over **stdin**, never the argument list,
  so they don't show up in `ps`.
- Secret values are never printed unless you pass `--print-secret`, and are
  never returned over MCP. Key *ids* are printed in full — they're identifiers,
  not secrets, and you need them for `rotate` and `retire`.

---

## Troubleshooting

**`not authorized` on `connect`.**
Your credential is wrong, expired, or missing a scope. The error says whether it
came from your environment or your saved login; for a saved login, run
`keyrotator login <provider>` to replace it. For AWS, your CLI session may have
expired — run `aws sso login` again.

**It worked yesterday, today it says the token isn't set.**
An `export` only lasts for that terminal window. Run `keyrotator login
<provider>` once and it works everywhere.

**`provider limit reached` (AWS).**
The IAM user already has two access keys. Delete the one you're not using in the
IAM console (or with `aws iam delete-access-key`) and retry.

**The old key is still active after rotating.**
For Datadog, Twilio, SendGrid, OpenAI, and Docker Hub there's no "disabled"
state — the old key lives until it's deleted. Add `--delete-old-now`, or run
`keyrotator retire <provider> <old-id>` once nothing uses it.

**`nowhere to put the new secret … refusing to rotate`.**
Working as intended: nothing was changed. Give the key a destination — a
`keyrotator.toml` entry, or a flag such as `--dotenv`, `--secret-file` or
`--print-secret`.

**`Partially rotated; old key kept`.**
Some consumers got the new key and some didn't. Both keys still work, so
nothing is broken. Fix the failed consumer (the error says which), then
`retire` the old key.

**`verification failed`.**
The new key didn't authenticate. For AWS this is usually propagation delay (the
tool already retries for a few seconds), and the new key has already been
removed again. For an Atomic provider (GitLab, Cloudflare) the old secret is
already gone, so re-run `rotate` to mint another.

**My GitLab/OpenAI/Anthropic token stopped working right after rotating.**
You rotated the same credential you were authenticating with. Take the new value
from wherever you delivered it and update the env var. (`list` marks that key,
and `rotate-all` skips it where the provider can tell.)

**`could not parse a new token from npm token create` (npm).**
npm changed its CLI output format for your version. This connector is
best-effort; open an issue with your `npm --version` and a redacted sample of
`npm token create` output.

**GitHub App: `401` or `A JSON web token could not be decoded`.**
The App ID or private key is wrong, or the key isn't a valid RSA PEM. Make sure
`GITHUB_APP_PRIVATE_KEY_PATH` points at the `.pem` you downloaded from the App's
settings, unmodified.

**GitHub App: `404` on rotate.**
The installation id is wrong. Run `keyrotator list github-app` to see the real
installation ids for your App.

**A provider's API changed and a response won't parse.**
APIs drift. Each provider is a single self-contained file in
`crates/core/src/providers/` — the fix is usually a one-field change in that
file. PRs welcome.

---

## Security

- Report a vulnerability privately via GitHub's **Report a vulnerability** on the
  Security tab, not a public issue.
- This tool holds real admin credentials. Give each provider credential the
  **minimum scope** needed to manage keys, and prefer short-lived sessions
  (AWS SSO, GitHub App tokens) over long-lived ones.
- `.env` and `*.pem` are git-ignored here. Don't commit real credentials.
- Nothing is sent anywhere except the provider's own API (and the consumer
  targets you configure).

---

## Contributing

New providers are the most useful contribution and they're easy — one file
implementing one trait. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full
walkthrough, including which rotation style to pick and which existing connector
to copy.

Good first additions: GitHub Actions as a first-class provider, Google Cloud and
Azure service-account keys, OpenAI project keys via service accounts, and more
consumer types (Vault, Kubernetes secrets, Vercel/Netlify env vars).

## Credits

keyrotator is created by **Ezra Black**. If it saved you time, please consider
[contributing](https://github.com/Ezra-Black/keyrotator) and supporting the
creator at [ezrablack.dev](https://www.ezrablack.dev).

## License

[MIT](LICENSE) © 2026 Ezra Black
