# Operations

This runbook covers backup, offline restore, retention, and key rotation for a single-container ConfigDeck deployment. Perform destructive or cryptographic maintenance with synthetic data first, then use an Administrator account with fresh identity confirmation during a maintenance window.

## Backup

1. Open **Maintenance → Backup & recovery**.
2. Select **Create backup** and confirm identity when requested.
3. Record the generated identifier, size, and SHA-256.
4. Copy important snapshots to access-controlled off-host storage.

ConfigDeck generates the filename, runs SQLite `VACUUM INTO`, rejects collisions and symlinks, validates SQLite integrity, foreign keys, and migration metadata, then records a metadata-only `CREATE_BACKUP` audit event. Browser input never becomes a filesystem path.

Keep database and master-key backups in separate protected locations. A backup is not reliable until a restore drill has succeeded.

## Offline restore

ConfigDeck never replaces its live database through HTTP. Creating a restore intent requires separate high-impact password/TOTP verification, valid for two minutes. Recent MFA sign-in alone does not authorize restore or key rotation. Use a new authenticator code if the previous code has already been consumed.

1. In **Maintenance**, select the snapshot and create a restore intent using a non-secret reason.
2. Record the identifier and expected SHA-256 displayed by ConfigDeck.
3. Stop the application.
4. Verify the selected file, preserve a safety copy, and atomically replace the database while stopped.
5. Start ConfigDeck and verify readiness and the `RESTORE_BACKUP` audit event.

Example for the supplied Compose deployment:

```bash
export BACKUP_ID='configdeck-YYYYMMDDTHHMMSSZ-xxxxxxxx.db'
export EXPECTED_SHA256='64-lowercase-hex-characters-from-the-UI'
docker compose stop configdeck

docker compose run --rm --no-deps \
  -e BACKUP_ID="$BACKUP_ID" \
  -e EXPECTED_SHA256="$EXPECTED_SHA256" \
  --entrypoint sh configdeck -ceu '
    case "$BACKUP_ID" in configdeck-*.db) ;; *) exit 1 ;; esac
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

docker compose up -d configdeck
curl -fsS http://127.0.0.1:3000/health
curl -fsS http://127.0.0.1:3000/ready
```

Startup validates the restore marker checksum, schema, integrity, foreign keys, KEK fingerprint, and active DEKs. It removes `/data/restore-intent.json` only after committing `RESTORE_BACKUP`.

If startup fails, stop the application and preserve logs plus a copy of the marker. Do not repeatedly edit the marker or try unrelated snapshots while it remains active. Either repeat the exact intended restore or deliberately abandon it: preserve evidence externally, remove the marker while stopped, restore the safety copy atomically, then document the incident outside ConfigDeck.

Never use `docker compose down -v` during normal operations, backup, upgrade, or restore.

## Master-key (KEK) rotation

KEK rotation re-wraps environment DEKs and re-encrypts TOTP seeds; it does not re-encrypt every environment value.

Before rotation, create and verify an off-host backup. Preserve the current key as the temporary previous key and generate a new primary key:

```bash
install -d -m 700 secrets
cp --preserve=mode,timestamps secrets/configdeck_master_key secrets/configdeck_master_key_previous
openssl rand -base64 32 > secrets/configdeck_master_key.new
chmod 644 secrets/configdeck_master_key.new secrets/configdeck_master_key_previous
mv secrets/configdeck_master_key.new secrets/configdeck_master_key
```

The `secrets/` directory remains host-private at mode `0700`; mode `0644` on the files is required only so the fixed non-root container UID can read each read-only bind mount.

Temporarily mount the previous key at:

```text
/run/secrets/configdeck_master_key_previous
```

and set:

```env
CONFIGDECK_PREVIOUS_MASTER_KEY_FILE=/run/secrets/configdeck_master_key_previous
```

Recreate the container with both keys. Startup succeeds only when the new primary key is valid and the previous key matches the active registry fingerprint. Open **Maintenance → Key rotation**, confirm identity, enter a non-secret reason, and rotate the KEK.

Before removing the previous key, verify `/ready`, a normal TOTP login, one authorized restricted reveal, and a successful `ROTATE_KEK` audit event. Then remove the previous-key mount and file, recreate the container with only the new key, and verify readiness again.

If prevalidation fails, restore the original primary key from the preserved previous key and investigate. If post-commit verification fails, keep both keys, stop writes, and recover from the verified backup. Never delete either key while the result is uncertain.

## Environment-key (DEK) rotation

DEK rotation creates a new environment key and re-encrypts current values, immutable history, and encrypted request proposals in resumable batches.

1. Create and verify an off-host backup.
2. Open **Maintenance → Key rotation**.
3. Select the exact App and environment, enter a non-secret reason, and confirm identity.
4. Start or resume the DEK rotation until its status is `COMPLETED`.
5. Verify readiness, the `ROTATE_DEK` audit event, a current reveal, a historical reveal, and any affected pending request preview.

ConfigDeck does not guess completion after a timeout or disconnect. Re-submit the same environment to resume. Finalization occurs only after every ciphertext reference uses the new version and passes authenticated-decryption checks; old wrapped key material is then destroyed.

## Compromise response

- Suspected KEK exposure: isolate the cause, rotate the KEK, assess process-memory exposure, and rotate affected DEKs and external credentials when warranted.
- Suspected DEK exposure: rotate that environment DEK and rotate the actual database/API/password credentials in their source systems.
- Lost KEK: recover the separately protected matching key backup. The encrypted database cannot be recovered without it.
- Host compromise: isolate and rebuild the host first. Assume any value decryptable by the running process may have been exposed.

## Retention and storage

- Container stdout/stderr is bounded by the supplied Compose configuration to three 10 MiB files.
- Login-attempt rows are retained for 24 hours; session rows are removed 30 days after absolute expiry. Cleanup runs opportunistically at most once per day.
- Audit events, change requests, configuration history, and archived records are not silently deleted. Define retention from legal, contractual, recovery, and incident-response needs.
- Local snapshots are not deleted automatically. Keep enough recent snapshots for recovery, copy important snapshots off-host, and remove a local snapshot only after verifying the off-host copy and confirming no active restore intent references it.
- Monitor both data and backup free space. Do not schedule blind `VACUUM` against the live database; use verified backups and a documented maintenance window for any future compaction.

## Audit retention and resource use

The online audit retention policy is 180 days. An Administrator can run **Maintenance → Archive older audit events** after recent authentication. Each action processes at most 1,000 expired events. Repeat until the result reports zero; this is an explicit maintenance action, not an automatic scheduler. Ordinary audit updates/deletes remain prohibited.

Each batch writes a private `audit-<timestamp>-<uuid>.jsonl` file in the configured backup directory. The first line describes the archive format, cutoff, and record count; subsequent lines retain the complete original audit columns plus actor/App/environment display names. The application synchronizes the file, verifies its SHA-256 by reading it back, then removes exactly those rows and records an `ARCHIVE_AUDIT` receipt in one database transaction. Failure leaves the database records intact; a verified file left by a failed transaction is recoverable duplicate evidence and must not be treated as proof of deletion. Never edit the archive manually.

Include JSONL archives in protected off-host backups. They contain audit identities and request metadata, although configuration plaintext is never included. Archives are not SQLite restore snapshots and do not appear in the snapshot restore selector. Archive files and database snapshots are not deleted automatically: moving evidence out of SQLite reduces active database growth, but total backup storage still requires an off-host lifecycle. Keep archives alongside the matching backups when restoring an older database; duplicate audit IDs across restored databases must be interpreted with their archive context.

SQLite reuses freed pages; archival does not necessarily shrink the database file immediately. Do not run an automatic full VACUUM on each archive action. If physical compaction is required, take a verified backup, stop application writes, and perform SQLite maintenance during an operational window with sufficient free space.

Audit pages use cursor navigation (25 records), without total-history counts or deep offsets. Version history also loads bounded pages. Successful health/readiness/static requests log at debug, while application activity and unsuccessful requests remain at info. Existing authentication housekeeping retains login attempts for 24 hours and cleans session rows 30 days after absolute expiry. Configuration versions, requests, and archived Apps/environments remain preserved.
