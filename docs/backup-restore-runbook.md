# ConfigDeck Backup and Offline Restore Runbook

This runbook covers the MVP single-container SQLite deployment. Restore is always offline. The ConfigDeck HTTP process never replaces its live database.

## Preconditions

- Use an Administrator account with TOTP and fresh identity confirmation.
- Confirm `/data` and `/backup` are separate persistent volumes.
- Keep the matching ConfigDeck master key available. Database backup and master-key backup must be stored separately.
- Keep an off-host copy of important snapshots. The `/backup` volume is not disaster recovery by itself.
- Never use `docker compose down -v` during backup or restore.

## Create and verify a backup

1. Open **Maintenance → Backup & recovery**.
2. Select **Create backup** and complete identity confirmation when requested.
3. Record the generated identifier, size, and SHA-256 shown in the UI.
4. Copy important snapshots off-host using an access-controlled operational process.

ConfigDeck generates the basename, runs SQLite `VACUUM INTO`, rejects collisions and symlinks, checks SQLite integrity/foreign keys/migration metadata, calculates SHA-256 and size, then commits `CREATE_BACKUP` to the audit log. Browser input never becomes a filesystem path.

## Prepare a restore

1. In **Maintenance**, select the snapshot and enter a non-secret reason.
2. Select **Create restore intent** and complete identity confirmation.
3. Confirm the page shows an active intent with the expected identifier, size, and SHA-256.
4. Do not restart ConfigDeck without completing or deliberately recovering this procedure. With an active marker, startup fails closed unless `/data/configdeck.db` exactly matches the selected snapshot.

The marker is `/data/restore-intent.json`. Do not edit it. It contains no configuration plaintext or key material.

## Offline replacement with Docker Compose

Set the two values from the Maintenance page, then stop ConfigDeck:

```bash
export BACKUP_ID='configdeck-YYYYMMDDTHHMMSSZ-xxxxxxxx.db'
export EXPECTED_SHA256='64-lowercase-hex-characters-from-the-UI'
docker compose stop configdeck
```

For localhost with the repository's override, add `-f docker-compose.yml -f docker-compose.local.yml` to every Compose command.

Run a one-off container with the same data and backup volumes. The command refuses a non-basename identifier, a non-empty WAL, a checksum mismatch, or a leftover temporary destination:

```bash
docker compose run --rm --no-deps \
  -e BACKUP_ID="$BACKUP_ID" \
  -e EXPECTED_SHA256="$EXPECTED_SHA256" \
  --entrypoint sh configdeck -ceu '
    case "$BACKUP_ID" in
      configdeck-*.db) ;;
      *) echo "invalid backup identifier" >&2; exit 1 ;;
    esac
    test "$(basename "$BACKUP_ID")" = "$BACKUP_ID"
    test -f "/backup/$BACKUP_ID"
    test -f /data/configdeck.db
    test ! -s /data/configdeck.db-wal
    test ! -e /data/.configdeck.db.restore
    printf "%s  %s\n" "$EXPECTED_SHA256" "/backup/$BACKUP_ID" | sha256sum -c -
    safety="/backup/safety-before-restore-$(date -u +%Y%m%dT%H%M%SZ).db"
    cp /data/configdeck.db "$safety"
    chmod 600 "$safety"
    cp "/backup/$BACKUP_ID" /data/.configdeck.db.restore
    printf "%s  %s\n" "$EXPECTED_SHA256" /data/.configdeck.db.restore | sha256sum -c -
    sync /data/.configdeck.db.restore "$safety"
    chmod 600 /data/.configdeck.db.restore
    mv /data/.configdeck.db.restore /data/configdeck.db
    sync /data
  '
```

Start ConfigDeck and verify it:

```bash
docker compose up -d configdeck
docker compose ps
docker compose logs --tail=100 configdeck
curl -fsS http://127.0.0.1:3000/health
curl -fsS http://127.0.0.1:3000/ready
```

Startup must pass checksum preflight, migrations, SQLite integrity and foreign-key checks, KEK fingerprint validation, and active DEK unwrap validation. It then commits `RESTORE_BACKUP`, checkpoints the audit write, and removes the marker. Sign in and confirm `RESTORE_BACKUP` is the newest relevant event in **Audit log**.

## Failure recovery

If startup fails, do not repeatedly modify files and do not delete the marker immediately. The retained marker is evidence that reconciliation did not complete.

1. Stop ConfigDeck.
2. Preserve container logs and a copy of `restore-intent.json` outside `/data`.
3. Check that the selected snapshot and mounted master key are the intended pair.
4. If correcting the restore, repeat the offline replacement with the exact selected snapshot.
5. If abandoning the restore and rolling back to the safety copy, preserve the failed marker externally, document the incident, deliberately remove `/data/restore-intent.json` while stopped, atomically replace `/data/configdeck.db` with the safety copy, and start ConfigDeck.
6. After recovery, create an administrative incident record outside ConfigDeck because an offline failure cannot be trusted to have written into either database.

Never use a safety copy or a different snapshot while leaving the original marker active: checksum preflight will correctly refuse startup.

