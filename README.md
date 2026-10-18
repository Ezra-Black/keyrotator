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
2. update        push it to every consumer  (.env, CI secrets, SSM…)
3. verify        confirm the new key authenticates
4. deactivate    disable the old key        (recoverable)
5. delete        remove the old key         (after a grace period, or now)
```

If step 1–3 fails, the new key is deleted and the old one is left untouched.
You end exactly where you started, nothing broken.

**Atomic** providers skip the overlap: rotate → update consumers → verify.
**Ephemeral** providers mint → update → verify. **Manual** providers stop and
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

### Storing secrets in your OS keychain

By default the tool keeps rotated secrets in memory only (fine for one-shot
runs). To use the real OS keychain — macOS Keychain, Windows Credential
Manager, or Linux libsecret — build with the `os-keyring` feature:

```bash
cargo build --release --features keyrotator-core/os-keyring
```

On Linux this needs libsecret installed (`sudo apt install libsecret-1-dev`, or
your distro's equivalent).

### Tools some providers shell out to

- **AWS** uses the `aws` CLI — install it and sign in (`aws sso login` or a
  configured profile).
- **npm** uses the `npm` CLI — you need to be logged in (`npm login`).
- **GitHub Actions** consumers use the `gh` CLI (`gh auth login`).

Everything else talks to the provider's REST API directly and needs no extra
tooling.

---

## Quick start

Rotate a single AWS access key:

```bash
aws sso login                        # or your usual sign-in
keyrotator list aws                  # see your keys
keyrotator rotate aws AKIAEXAMPLE    # rotate one by id
```

Rotate every key for a provider at once:

```bash
export GITLAB_TOKEN=glpat-xxxxxxxxxxxx
keyrotator rotate-all gitlab
```

Each provider reads its credentials from environment variables (never from the
command line, so nothing sensitive lands in your shell history). The
[per-provider setup](#per-provider-setup) section lists exactly which ones.

---

## Commands

```
keyrotator connect     <provider>            check credentials and access
keyrotator list        <provider>            list the keys for an account
keyrotator rotate      <provider> <id>       rotate one key by its id
keyrotator rotate      <provider> <id> --delete-old-now
keyrotator rotate-all  <provider>            rotate every discovered key
```

- `<provider>` is one of: `aws`, `gitlab`, `cloudflare`, `datadog`, `npm`,
  `dockerhub`, `openai`, `anthropic`, `twilio`, `sendgrid`, `github-app`.
- `<id>` is the key's native id, exactly as shown by `list` (an AWS access key
  id, a GitLab token id, a Cloudflare token id, and so on).
- `--delete-old-now` deletes the old key immediately instead of leaving it
  disabled for the grace period. Use it for providers that have no "disabled"
  state (see the notes below).

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
keyrotator rotate aws AKIAEXAMPLE --delete-old-now
```

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
keyrotator rotate gitlab 4821          # 4821 = token id from `list`
```

**Gotcha:** don't rotate the same token you're authenticating with — it'll
invalidate `GITLAB_TOKEN` mid-run. Rotate *other* token ids, or grab the new
value from the output and update `GITLAB_TOKEN`.

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
keyrotator rotate datadog <api-key-id> --delete-old-now
```

**Gotcha:** Datadog keys have no "disabled" state, so the old key is only
revoked at the delete step. Use `--delete-old-now` (or the grace-period delete)
to actually retire it.

#### npm

Rotates classic automation tokens via the `npm` CLI.

- **Credential:** a logged-in npm session (`npm login`).
- **Env:** `NPM_REGISTRY` (optional, for a private registry).

```bash
npm login
keyrotator rotate-all npm
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
keyrotator rotate dockerhub <token-uuid> --delete-old-now
```

#### OpenAI

Rotates organization **admin** keys.

- **Credential:** an organization admin key.
- **Env:** `OPENAI_ADMIN_KEY`.

```bash
export OPENAI_ADMIN_KEY=sk-admin-xxxxxxxx
keyrotator rotate openai <key-id> --delete-old-now
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
# → prints the Console URL and steps; revoke the old key once you've made
#   the new one and pointed your apps at it.
```

#### Twilio

Rotates Standard API keys.

- **Credential:** your Account SID and Auth Token (or an existing API key
  sid/secret with permission to manage keys).
- **Env:** `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_API_USER`
  (optional; defaults to the Account SID).

```bash
export TWILIO_ACCOUNT_SID=ACxxxxxxxx TWILIO_AUTH_TOKEN=xxxxxxxx
keyrotator rotate twilio <key-sid> --delete-old-now
```

#### SendGrid

Rotates API keys, carrying over the old key's scopes to the new one.

- **Credential:** an API key with the `api_keys.create`, `api_keys.read`, and
  `api_keys.delete` scopes.
- **Env:** `SENDGRID_API_KEY`.

```bash
export SENDGRID_API_KEY=SG.xxxxxxxx
keyrotator rotate-all sendgrid
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
keyrotator rotate github-app <installation-id>
```

The only long-lived secret is the App private key, which you rotate rarely (and
can hold two of) in the App's settings.

---

## Keeping consumers in sync

A "consumer" is any place that uses a key and must be updated when it rotates.
The tool currently knows how to update:

- **`.env` files** — rewrites a single `VAR=...` line in place, leaving the rest
  of the file alone.
- **GitHub Actions secrets** — via `gh secret set`.
- **AWS SSM Parameter Store** — as a `SecureString`.

When you attach consumers to a key, rotation updates them automatically between
minting the new key and retiring the old one. In this first release consumers
are defined in code (see `Consumer` in `crates/core/src/models.rs`); wiring them
up through a config file is on the roadmap.

---

## Where secrets are stored

- With `--features os-keyring`, rotated secret values go into your OS keychain
  (macOS Keychain, Windows Credential Manager, or libsecret).
- Without it, they're kept in memory for the duration of the run only.
- Secrets passed to CLIs (`aws`, `npm`, `gh`) are passed through the environment,
  not the argument list, so they don't show up in `ps`.
- The tool never prints a full key id or secret — ids are masked in output.

---

## Troubleshooting

**`not authorized` on `connect`.**
Your credential is wrong, expired, or missing a scope. Re-check the env vars for
that provider in [Per-provider setup](#per-provider-setup). For AWS, your CLI
session may have expired — run `aws sso login` again.

**`provider limit reached` (AWS).**
The IAM user already has two access keys. Delete the one you're not using in the
IAM console (or with `aws iam delete-access-key`) and retry.

**The old key is still active after rotating.**
For Datadog, Twilio, SendGrid, OpenAI, and Docker Hub there's no "disabled"
state — the old key lives until it's deleted. Add `--delete-old-now`, or let the
grace-period delete run.

**`verification failed`.**
The new key didn't authenticate. For AWS this is usually propagation delay (the
tool already retries for a few seconds). For an Atomic provider (GitLab,
Cloudflare) the old secret is already gone, so re-run `rotate` to mint another.

**My GitLab/OpenAI/Anthropic token stopped working right after rotating.**
You rotated the same credential you were authenticating with. Rotate a
*different* key id, or take the new value from the output and update the env var.

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
Azure service-account keys, OpenAI project keys via service accounts, and a
config file for defining consumers.

## License

[MIT](LICENSE) © 2026 Ezra Black
