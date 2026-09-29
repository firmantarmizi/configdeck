# Deployment

ConfigDeck runs as one container with a persistent SQLite data volume and a separate backup volume. Deploy it behind HTTPS and a private, VPN, or identity-aware access layer.

## Published images

Pushes and pull requests run `.github/workflows/ci.yml`. Version tags matching `v*.*.*` run `.github/workflows/release.yml`, which publishes:

```text
ghcr.io/<repository-owner>/<repository-name>:<version>
```

The release includes an SBOM, provenance, and GitHub attestation. Production deployments should pin the immutable image digest rather than a mutable tag. Environment-specific credentials, hosts, and webhooks belong in protected deployment configuration, not this repository.

## Prerequisites

- Docker Engine 24+ with Compose v2, or an equivalent container platform.
- Persistent writable storage mounted at `/data` and `/backup`.
- A DNS name and HTTPS reverse proxy.
- A private network path or identity-aware access layer.
- An off-host destination for verified backups.

Do not use a shared network filesystem for SQLite and do not run multiple ConfigDeck replicas against the same database.

## First deployment with Docker Compose

Copy the environment template and generate the master key once:

```bash
cp .env.example .env
install -d -m 700 secrets
openssl rand -base64 32 > secrets/configdeck_master_key
chmod 644 secrets/configdeck_master_key
```

Set a unique bootstrap Administrator email and password in `.env`, then start:

```bash
docker compose config --quiet
docker compose build --pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:3000/health
curl -fsS http://127.0.0.1:3000/ready
```

The master-key file must decode from standard base64 to exactly 32 bytes. Preserve it for the lifetime of the database and back it up separately. Replacing it on an existing database causes ConfigDeck to fail closed.
Mode `0644` allows the fixed non-root container UID to read the bind-mounted file; the mode-`0700` parent directory prevents other host users from reaching it, and the container mount is read-only. A managed secret-file mount with equivalent access is preferred when the platform provides one.

Complete TOTP enrollment, replace the initial password, finish organization setup, and create a second Administrator. Remove `CONFIGDECK_ADMIN_EMAIL` and `CONFIGDECK_ADMIN_PASSWORD` from the deployment after bootstrap, then recreate only the container. Never remove the data volume during a normal redeploy.

## Required production configuration

```env
CONFIGDECK_ENV=production
CONFIGDECK_BIND=0.0.0.0:3000
CONFIGDECK_DATABASE_URL=sqlite:///data/configdeck.db
CONFIGDECK_DB_MAX_CONNECTIONS=5
CONFIGDECK_TRUSTED_PROXIES=
```

Production reads the KEK from:

```text
/run/secrets/configdeck_master_key
```

Keep `CONFIGDECK_TRUSTED_PROXIES` empty unless ConfigDeck is behind a known proxy network. When used, set only the exact proxy CIDR ranges.

## Reverse proxy

- Terminate TLS at the proxy and forward to port `3000` on a private container network or loopback interface.
- Preserve the original `Host` and HTTPS scheme.
- Do not cache authenticated responses.
- Restrict access at the network or identity layer; ConfigDeck login is not a reason to expose the portal directly to the public Internet.

## Runtime baseline

The supplied Compose file provides:

- non-root UID/GID `10001`;
- a read-only root filesystem;
- all Linux capabilities dropped and `no-new-privileges`;
- separate `/data` and `/backup` volumes and a small `/tmp` tmpfs;
- limits of 0.5 CPU, 256 MiB memory, and 128 processes;
- loopback-only host publishing and bounded local container logs;
- `/health` and `/ready` probes.

Monitor health/readiness, restart count, CPU, memory, data/backup free space, backup age, failed authentication, administrative audit events, active restore intent, and nonterminal key rotation.

## Upgrades

The original version 0.1.1 release added multiline import and redacted environment preview without schema or encryption-format changes. Version 0.1.2 includes migration `0002_audit_cursor_indexes.sql`, which replaces audit filter indexes for cursor navigation. It preserves all records and encryption formats. Validate the upgrade against a disposable backup copy. The sidebar/account menu displays the version and build identity after deployment. Keep the existing database, data/backup volumes, and master key. Do not reset volumes or rerun bootstrap. Follow the backup and validation steps below.

1. Create a verified backup and copy it off-host.
2. Preserve the exact active master-key file.
3. Record the currently deployed image digest.
4. Test migrations against a disposable backup copy for major upgrades.
5. Deploy the new immutable image without deleting volumes.
6. Verify health, readiness, login/TOTP, App comparison, a restricted reveal, and audit activity.

Rollback to an older image only when schema compatibility is documented. Otherwise restore the pre-upgrade snapshot using the offline procedure in [Operations](operations.md).

## Production acceptance

Before storing real configuration, confirm:

- HTTPS and private/identity-aware access are active;
- trusted proxy ranges are exact;
- bootstrap variables have been removed;
- at least two Administrators can authenticate with TOTP;
- the master-key backup is protected separately from database backups;
- backup, offline restore, and key-rotation drills have been completed with synthetic data;
- data and backup free-space alerts are active;
- audit and backup retention are documented;
- the deployed image digest and operational owners are recorded outside ConfigDeck.

See [Operations](operations.md) for backup, restore, retention, and key rotation.
