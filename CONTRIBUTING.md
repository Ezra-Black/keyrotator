# Contributing

Thanks for taking a look. This project is small and the architecture is
deliberately simple, so most contributions — especially new providers — are
self-contained and easy to review.

## Ground rules

- **Only accounts you control.** Every connector acts through the user's own
  authorized credential. Nothing here should ever try to act on a credential
  the user hasn't proven they administer. Keep it that way.
- **Secrets never hit disk in plaintext, logs, or `argv`.** Pass secret
  material to subprocesses via the environment, store it in the OS keychain,
  and keep it out of `Debug` output (see `NewCredential`'s manual `Debug` impl).
- **Verify against the real API.** Connector code should match the provider's
  current docs. Link the doc page in your PR description.

## Setting up

```bash
git clone https://github.com/Ezra-Black/keyrotator.git
cd keyrotator
cargo build
cargo test
cargo fmt --all
cargo clippy --all-targets
```

CI runs fmt, clippy, build, and test on every push and PR.

## Adding a provider

A provider is one file in `crates/core/src/providers/` implementing the
`Connector` trait. The whole contract is in `crates/core/src/connector.rs`.

1. **Pick a rotation style** (`crates/core/src/models.rs` → `RotationStyle`):
   - `Overlap` — the API lets you create a second key before killing the first.
     Implement `create`, `verify`, `deactivate_old`, `delete_old`.
   - `AtomicRotate` — one "roll" call swaps the secret and kills the old one.
     Implement `create` (the roll) and `verify`; leave the revoke methods as
     the no-op defaults.
   - `Ephemeral` — you mint a short-lived token from a long-lived secret you
     hold. Implement `create` (mint) and `verify`.
   - `Manual` — no create API. Implement `list_keys` and `deactivate_old`, add
     a `manual_rotation_hint`, and have `create` return
     `RotationError::ManualActionRequired`.
2. **Add the variant** to `ProviderKind` (plus `display_name` and `FromStr`).
3. **Register it** in `providers/mod.rs` and in the CLI's `build_connector`
   (read credentials from env vars — never a CLI flag).
4. **Copy the nearest existing connector** as a starting point: `gitlab.rs`
   (REST, atomic), `datadog.rs` / `sendgrid.rs` (REST, overlap), `aws.rs`
   (CLI, overlap), `github_app.rs` (ephemeral, JWT).
5. **Update the README** provider table and the per-provider setup section.

Keep the HTTP code boring and consistent with the other connectors: build a URL
helper, send the admin credential, check `status().is_success()`, and funnel
failures through `err_body`.

## Pull requests

- One provider (or one fix) per PR.
- Run `cargo fmt` and make sure `cargo test` passes.
- In the description, link the vendor doc pages your connector relies on so a
  reviewer can check the endpoints without guessing.
- If you changed behavior in the engine, add or update a test in
  `crates/core/tests/engine.rs`.

## Reporting issues

Open an issue with:
- the provider and command you ran,
- what you expected vs. what happened,
- the error text (redact any real token values).

Security-sensitive reports: please open a private advisory via GitHub's
"Report a vulnerability" rather than a public issue.
