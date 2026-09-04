# Deployment

ConfigDeck runs as one container with a persistent SQLite data volume and a separate backup volume. Deploy it behind HTTPS and a private, VPN, or identity-aware access layer.

## Published images

Pushes and pull requests run `.github/workflows/ci.yml`. Version tags matching `v*.*.*` run `.github/workflows/release.yml`, which publishes:

```text
ghcr.io/<repository-owner>/<repository-name>:<version>
```

The release includes an SBOM, provenance, and GitHub attestation. Production deployments should pin the immutable image digest rather than a mutable tag. Environment-specific credentials, hosts, and webhooks belong in protected deployment configuration, not this repository.

## Dokploy with a published image

For a small production host, publish the image in GitHub Actions and let Dokploy pull it instead of compiling Rust on the deployment server. Create a Docker Compose service in Dokploy and use the following baseline, replacing `<version>` with a published release such as `0.1.0`:

```yaml
services:
  configdeck:
    image: ghcr.io/firmantarmizi/configdeck:<version>
    restart: unless-stopped
    environment:
      CONFIGDECK_ENV: production
      CONFIGDECK_BIND: 0.0.0.0:3000
      CONFIGDECK_DATABASE_URL: sqlite:///data/configdeck.db
      CONFIGDECK_ADMIN_EMAIL: ${CONFIGDECK_ADMIN_EMAIL:-}
      CONFIGDECK_ADMIN_PASSWORD: ${CONFIGDECK_ADMIN_PASSWORD:-}
      CONFIGDECK_DB_MAX_CONNECTIONS: ${CONFIGDECK_DB_MAX_CONNECTIONS:-5}
      CONFIGDECK_TRUSTED_PROXIES: ${CONFIGDECK_TRUSTED_PROXIES:-}
      RUST_LOG: ${RUST_LOG:-configdeck=info,tower_http=info}
    expose:
      - "3000"
    volumes:
      - configdeck_data:/data
      - configdeck_backup:/backup
      - ../files/configdeck_master_key:/run/secrets/configdeck_master_key:ro
    read_only: true
    pids_limit: 128
    mem_limit: 256m
    cpus: 0.50
    stop_grace_period: 20s
    tmpfs:
      - /tmp:size=16m,mode=1777
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    healthcheck:
      test: ["CMD", "/usr/local/bin/configdeck", "healthcheck"]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  configdeck_data:
  configdeck_backup:
```

In Dokploy:

1. Create `../files/configdeck_master_key` through the Compose service file-mount facility. Its content must be one standard-base64 value that decodes to exactly 32 bytes. Never store it in Git or the Compose environment editor.
2. Add the bootstrap Administrator email and a unique temporary password in the Dokploy Environment tab. The Compose file references only the required variables; Dokploy environment values are not automatically injected unless referenced.
3. Deploy exactly one replica. SQLite must not be shared by multiple running ConfigDeck instances.
4. In the Domains tab, route the `configdeck` service to container port `3000`, enable HTTPS, and redeploy after domain changes. A host port does not need to be published.
5. Complete TOTP enrollment, change the bootstrap password, create a second Administrator, then remove both bootstrap variables and redeploy without deleting either named volume.
6. Verify `/health`, `/ready`, login, backup creation, and an off-host backup before storing real configuration.

Public GHCR container packages can be pulled anonymously. If the package remains private, configure a GHCR registry in Dokploy using a classic token limited to `read:packages`. Pin the resolved image digest after the first successful deployment, and create a verified backup before changing versions.

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
