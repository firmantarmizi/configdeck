# Contributing to ConfigDeck

Thank you for helping improve ConfigDeck. Changes should preserve its small, deployment-platform-neutral architecture and server-side security boundaries.

## Before opening a pull request

1. Read `docs/architecture.md`, `docs/security-model.md`, and the relevant operational document.
2. Keep authorization, masking, decryption, recent authentication, and workflow validation on the backend.
3. Never add real credentials, `.env` files, master keys, SQLite databases, backups, session tokens, or plaintext configuration values.
4. Add negative tests for changes involving authentication, authorization, encryption, import, restore, rotation, or proxy handling.
5. Use a new migration for schema changes; do not silently rewrite an existing released migration.

## Required checks

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked --release
cargo audit
docker build .
```

The declared minimum supported Rust version is 1.94.0. Keep `Cargo.lock` updated and committed when dependencies change.

## Pull request guidance

- Keep each pull request focused and explain user-visible behavior and security impact.
- Update the public architecture or security model when a change affects those contracts.
- Update runbooks when operational behavior changes.
- Avoid new runtimes, services, frameworks, or third-party browser assets unless the benefit and security tradeoff are clear.
- Do not include deployment credentials or organization-specific notification/webhook configuration.

Vulnerabilities must be reported privately according to `SECURITY.md`.
