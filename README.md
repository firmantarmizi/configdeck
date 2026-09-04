# ConfigDeck

**Configuration Management Platform**

[![CI](https://github.com/firmantarmizi/configdeck/actions/workflows/ci.yml/badge.svg)](https://github.com/firmantarmizi/configdeck/actions/workflows/ci.yml)

ConfigDeck is a lightweight, deployment-platform-neutral application for encrypted environment configuration and auditable change workflows. Administrators can manage accounts and Contributor service access; authorized users can submit atomic change sets, and Operators can review, fulfill, preview, and confirm externally deployed changes.

ConfigDeck is designed as a small self-hosted internal tool. It does not require a particular hosting provider, deployment platform, notification service, or external identity vendor.

Created and maintained by **Firman Tarmizi**.

## Development

Requirements: Rust 1.94 or newer and a 32-byte master key encoded with standard base64. The container build pins the Rust 1.98.0 stable toolchain on Debian Bookworm.

```bash
export CONFIGDECK_ENV=development
export CONFIGDECK_MASTER_KEY="$(openssl rand -base64 32)"
export CONFIGDECK_ADMIN_EMAIL=admin@example.com
export CONFIGDECK_ADMIN_PASSWORD='replace-with-a-long-random-password'
cargo run
```

On PowerShell, set the same values through `$env:NAME = 'value'`. The environment-key fallback is development/test only. Production reads `/run/secrets/configdeck_master_key`.

The first Administrator password login is deliberately restricted to TOTP enrollment. A new database then opens an authenticated organization setup page for the organization name and an optional PNG/WebP logo (maximum 256 KiB). Full application access starts after both steps. Existing databases are marked as already onboarded by migration. Remove `CONFIGDECK_ADMIN_PASSWORD` after bootstrap; it is ignored once a user exists, but should not remain in deployment configuration.

Administrators create additional accounts from `Users & Access`. There are no default Contributor or Operator credentials.

## Docker Compose

1. Copy `.env.example` to `.env` and provide a strong bootstrap password.
2. Create a host-private `secrets/` directory and `secrets/configdeck_master_key` containing standard-base64 encoding of exactly 32 random bytes. The file must be readable by the non-root container process.
3. Start the service:

```bash
docker compose up -d
```

The published port binds to loopback by default. Put it behind an HTTPS reverse proxy and private/identity-aware access layer before storing production credentials.

Run migrations without starting the server:

```bash
docker compose run --rm configdeck migrate
```

Data and backups use separate named volumes. The container is non-root, drops capabilities, uses `no-new-privileges`, and has a read-only root filesystem.

For a real deployment, follow [`docs/deployment.md`](docs/deployment.md). The supplied Compose baseline constrains the runtime to 0.5 CPU, 256 MiB memory, 128 processes, loopback-only publishing, bounded local logs, and separate data/backup volumes. Put ConfigDeck behind HTTPS plus a private or identity-aware access layer.

### Manual smoke test from WSL

From a Linux or WSL terminal, enter the cloned repository:

```bash
cd configdeck
cp .env.example .env
install -d -m 700 secrets
openssl rand -base64 32 > secrets/configdeck_master_key
chmod 644 secrets/configdeck_master_key
nano .env
```

Generate the master-key file only for a brand-new database. If the ConfigDeck data volume already exists, keep the existing `secrets/configdeck_master_key`; replacing it will make the application fail closed because the stored KEK fingerprint will no longer match.
The source file is readable inside the container but remains protected on the host by the mode-`0700` parent directory and is mounted read-only. On platforms with managed file secrets, prefer their equivalent read-only file mount.

Set `CONFIGDECK_ADMIN_PASSWORD` in `.env` to a unique password of at least 12 bytes. For HTTP localhost, include `docker-compose.local.yml` so ConfigDeck uses a non-Secure development session cookie:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.local.yml build --pull
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
docker compose -f docker-compose.yml -f docker-compose.local.yml ps
docker compose -f docker-compose.yml -f docker-compose.local.yml logs --tail=100 configdeck
curl -fsS http://127.0.0.1:3000/health
curl -fsS http://127.0.0.1:3000/ready
```

Both `curl` commands must succeed, and `docker compose ps` must eventually show the service as healthy. Open `http://127.0.0.1:3000` from Windows to complete the first login and TOTP enrollment. Never commit `.env` or the generated `secrets/` directory.

After login, open **Configurations**. Creating an App atomically provisions **Development**, **Staging**, and **Production** with independent encrypted environment keys; custom environments remain available for cases such as QA or preview. The App workspace provides a numbered cross-environment matrix with a view-only environment selector. Each expanded key lists selected environments vertically with directly editable fields: public values can be reviewed inline, restricted values remain masked, and every submit creates a traceable request instead of mutating current state. A key rename becomes one atomic delete-and-add change set so immutable history remains intact. Administrator can reversibly archive custom environments, Apps, and existing environment metadata; archived items remain restorable and do not erase history. Operator and Administrator can record a variable only after its exact value has already been applied in the target deployment platform. Recording a deletion means confirming that the key was already removed from that platform; it creates a tombstone and immutable encrypted history instead of erasing the record.

Accounts created from **Users & Access** must replace their initial password at first sign-in. Administrator role/status/password/TOTP changes require recent identity confirmation and cannot target the Administrator's own destructive identity controls. Password reset sets a temporary password, revokes all target sessions, and forces replacement at next sign-in. Removing a user safely deactivates the account and revokes every session and App grant while preserving audit/history; reactivation does not restore prior grants. The last active Administrator remains protected. Operator and Administrator can inspect the filtered **Audit log**; only explicitly allowlisted non-secret metadata is rendered.

Administrators use **Maintenance → Backup & recovery** to create verified SQLite snapshots and prepare offline restore intents. Both writes require recent identity confirmation. The application never replaces a live database; follow [`docs/operations.md`](docs/operations.md) after creating an intent.

**Maintenance → Key rotation** supports atomic KEK re-wrap/TOTP re-encryption and synchronous resumable per-environment DEK rotation. Both require high-impact identity confirmation. Follow [`docs/operations.md`](docs/operations.md); never replace the active master-key file without first preserving it as the temporary previous-key secret.

For initial migration, refresh privileged authentication and select **Record deployed configuration**. This Operator-only workflow is explicitly for values already active on the deployment platform. Its preview never repeats plaintext values and defaults every row to `restricted`; search/filter keys, review detected groups and descriptions, apply bulk visibility only to the currently visible rows, and review the suggested type before recording the state. Use `# [Database]` as a portable group heading and an ordinary comment immediately above a key as its description. **Preview .env** preserves those sections and comments, decrypts the complete current environment only after recent authentication, and supports Copy `.env`, Copy Selected, and download. Close the preview after use because it contains plaintext restricted values.

An Administrator opens **Manage Contributor access** on an App. Grant/revoke immediately invalidates the affected Contributor's sessions. An assigned Contributor adds one or more keys through the progressive builder, updates or deletes an existing key from its row, or pastes up to 50 `.env` entries as one request. Bulk paste detects ADD versus UPDATE, keeps values out of preview HTML, defaults visibility to `restricted`, and does not mutate current state. “I provide it” encrypts the submitted value immediately; a restricted value is write-only afterward. “Operator provides it” remains `NEEDS_INPUT` until fulfilled. Operator/Administrator approval, resulting `.env` preview, external deployment, and explicit Mark Applied preserve the difference between proposed and deployed state.

If the production Compose file was already started directly for local testing, no data reset is necessary. Recreate only the container while retaining the named volumes:

```bash
docker compose down
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

Do not add `-v` to `docker compose down`, because that would remove the local database and backup volumes.

## Verification

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
cargo +1.94.0 check --locked --all-targets --all-features
docker build .
```

Install `cargo-audit` with `cargo install cargo-audit`, then run `cargo audit` when available.

Pull requests and pushes are checked by [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Version tags matching `v*.*.*` publish a container image with an SBOM, provenance, and GitHub attestation to GitHub Container Registry through [`.github/workflows/release.yml`](.github/workflows/release.yml). The public workflow builds and publishes artifacts only; deployment credentials and environment-specific webhooks belong in a protected deployment repository or platform configuration. See [`docs/deployment.md`](docs/deployment.md).

## Contributing and security

- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.
- Report vulnerabilities privately according to [`SECURITY.md`](SECURITY.md); do not open a public issue containing exploit details or real configuration values.
- Planned improvements and explicitly deferred scope are listed in [`ROADMAP.md`](ROADMAP.md).
- Public technical documentation is intentionally concise: [Architecture](docs/architecture.md), [Security model](docs/security-model.md), [Deployment](docs/deployment.md), and [Operations](docs/operations.md).

## Security and production checklist

- Never commit `.env`, `secrets/`, SQLite data, backup snapshots, or restore markers.
- Keep the KEK backup separate from database backups and maintain at least two active Administrators.
- Remove bootstrap credentials after provisioning and scope trusted proxy CIDRs narrowly.
- Test backup restore and key rotation on disposable data before relying on them operationally.
- Treat Preview/Download `.env` and restricted reveal as sensitive browser surfaces; finish the task and close them.
- Review audit events and copy important backups off-host.
- Define audit and backup retention before production. Authentication housekeeping is bounded automatically, while audit/history/archive and verified snapshots are never deleted silently.

## Current limitations

- Deployment to the target platform remains manual; ConfigDeck does not call deployment-platform APIs.
- Restore is an explicit offline operator procedure. KEK/DEK rotation is synchronous-resumable and should use a maintenance window for large history.
- SQLite is designed for one ConfigDeck process and one persistent data volume, not horizontal replicas or a shared network filesystem.
- Local accounts/TOTP are implemented; SSO/OIDC/LDAP, service accounts, dynamic secrets, automatic rotation, and secret-plaintext comparison are non-goals for this MVP.
- English is the production copy baseline. Localization and comparison-workspace visual improvements are tracked in [`ROADMAP.md`](ROADMAP.md).
- ConfigDeck is an internal configuration workflow tool, not a replacement for Vault or another dynamic-secret system.

## License

ConfigDeck is available under the [MIT License](LICENSE). Copyright © 2026 Firman Tarmizi.
