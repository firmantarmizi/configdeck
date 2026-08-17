# ConfigDeck Production Runbook

This runbook is the deployment baseline for the single-container MVP. It is deployment-platform neutral and assumes an HTTPS reverse proxy or private access layer in front of ConfigDeck.

## Host prerequisites

- Docker Engine 24+ with Compose v2 and BuildKit.
- A dedicated host or protected internal network path; do not expose port 3000 publicly.
- Persistent storage for `configdeck_data` and a separate `configdeck_backup` volume.
- An off-host, access-controlled backup destination.
- A DNS name and trusted HTTPS reverse proxy.

## First deployment

1. Copy `.env.example` to `.env` and set a unique bootstrap Administrator email and a randomly generated password of at least 12 bytes.
2. Create the master key once:

   ```bash
   umask 077
   mkdir -p secrets
   openssl rand -base64 32 > secrets/configdeck_master_key
   chmod 600 secrets/configdeck_master_key
   ```

3. Keep the key outside source control and back it up separately from the SQLite database. Losing it makes encrypted data unrecoverable.
4. Validate and start:

   ```bash
   docker compose config --quiet
   docker compose build --pull
   docker compose up -d
   docker compose ps
   curl -fsS http://127.0.0.1:3000/health
   curl -fsS http://127.0.0.1:3000/ready
   ```

5. Complete TOTP enrollment, replace the initial password, and finish organization setup.
6. Remove both bootstrap variables from the deployed Compose environment after the first account exists, then recreate only the container. Never remove the data volume.

## Reverse proxy

- Terminate TLS at the proxy and forward to `127.0.0.1:3000` or a private container network.
- Preserve the original `Host` and HTTPS scheme.
- Only configure `CONFIGDECK_TRUSTED_PROXIES` with the exact proxy CIDR(s). If it is empty, forwarding headers are ignored.
- Do not cache authenticated responses. ConfigDeck already sends private/no-store headers on sensitive surfaces.
- Add an identity-aware access layer or VPN; ConfigDeck authentication is not a reason to expose the portal to the public Internet.

## Runtime baseline

The supplied Compose file limits ConfigDeck to 0.5 CPU, 256 MiB memory, and 128 processes. The root filesystem is read-only; only `/data`, `/backup`, and the 16 MiB `/tmp` tmpfs are writable. The process is UID/GID 10001, has all Linux capabilities dropped, uses `no-new-privileges`, and rotates local container logs.

Monitor:

- `/health` for liveness and `/ready` for database/key readiness.
- container restart count, memory, CPU, volume free space, and backup age;
- failed login/rate-limit events and administrative audit events;
- active restore intent or nonterminal key rotation before maintenance.

## Upgrades

1. Create and verify a backup; copy it off-host.
2. Preserve the exact active master-key file.
3. Read migration/release notes and build the new image.
4. Run the new binary's `migrate` command against a disposable backup copy first for major upgrades.
5. Recreate the container without `-v`, then verify health, readiness, login/TOTP, App comparison, one restricted reveal, and audit.
6. Rollback uses the previous image only when its schema compatibility is documented. Otherwise follow the offline restore runbook using the pre-upgrade snapshot.

## Backup, restore, and rotation

- Backup and offline restore: [`backup-restore-runbook.md`](backup-restore-runbook.md)
- KEK/DEK rotation and compromise response: [`key-rotation-runbook.md`](key-rotation-runbook.md)

Never use `docker compose down -v` in normal operations. Never replace the master key merely to fix a startup failure.

## Production acceptance

Before storing real configuration, complete every item in [`release-checklist.md`](release-checklist.md). Record the image digest, ConfigDeck version/commit, database backup identifier, master-key custody owner, and date of the restore drill in the organization's operational records.
