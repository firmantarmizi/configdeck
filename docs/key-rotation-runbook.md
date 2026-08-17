# ConfigDeck Key Rotation Runbook

This runbook is deployment-platform neutral. Run it only as an Administrator during a maintenance window, after creating and verifying a current backup. Keep database and master-key backups in separate protected locations.

## Before every rotation

1. Confirm `/health` and `/ready` succeed and no restore intent is active.
2. Create a fresh backup from **Maintenance**, copy it off-host, and verify its SHA-256.
3. Confirm no change request is being applied. Rotation pauses other writes while its operation is nonterminal.
4. Record a non-secret operational reason. Never put credentials, configuration values, KEK, DEK, TOTP seed, or key-file content in the reason.

## KEK / master-key rotation

KEK rotation does not re-encrypt environment values. It atomically re-wraps every active environment DEK and re-encrypts every stored TOTP seed with the new purpose-derived key.

Run the commands from the repository root:

```bash
umask 077
cp --preserve=mode,timestamps secrets/configdeck_master_key secrets/configdeck_master_key_previous
openssl rand -base64 32 > secrets/configdeck_master_key.new
chmod 600 secrets/configdeck_master_key.new secrets/configdeck_master_key_previous
mv secrets/configdeck_master_key.new secrets/configdeck_master_key
```

Create a temporary `docker-compose.rotation.yml` locally; do not commit key files:

```yaml
services:
  configdeck:
    environment:
      CONFIGDECK_PREVIOUS_MASTER_KEY_FILE: /run/secrets/configdeck_master_key_previous
    secrets:
      - configdeck_master_key_previous

secrets:
  configdeck_master_key_previous:
    file: ./secrets/configdeck_master_key_previous
```

Recreate the container with both secret files:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.local.yml \
  -f docker-compose.rotation.yml \
  up -d --force-recreate
```

Startup succeeds only when the primary file is a different valid key and the previous file matches the currently active registry fingerprint. Normal configuration writes remain paused. Sign in, open **Maintenance → Key rotation**, confirm identity, enter the reason, and select **Rotate KEK**.

Verify before removing the previous key:

```bash
curl -fsS http://127.0.0.1:3000/ready
docker compose \
  -f docker-compose.yml \
  -f docker-compose.local.yml \
  -f docker-compose.rotation.yml \
  logs --tail=100 configdeck
```

Confirm the Audit log contains one successful `ROTATE_KEK` with versions/count only. Confirm a normal TOTP login and one authorized restricted reveal still work. Then remove the temporary override and previous key, and recreate the container using only the new primary key:

```bash
rm docker-compose.rotation.yml
rm secrets/configdeck_master_key_previous
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --force-recreate
curl -fsS http://127.0.0.1:3000/ready
```

If prevalidation fails, the registry, wrapped DEKs, TOTP ciphertext, and values remain unchanged. Restore the original primary file from `configdeck_master_key_previous`, remove the override, recreate the container, and investigate before retrying. If post-commit readiness fails, keep both keys, stop writes, preserve the database, and recover using the verified backup; do not repeatedly rotate or delete either key.

## DEK rotation

Open **Maintenance → Key rotation**, select the exact App/environment, enter the reason, confirm identity, and select **Rotate DEK**. ConfigDeck creates a pending DEK and migrates current values, immutable history, and encrypted request proposals in small committed batches. A disconnect or timeout does not guess completion: reopen Maintenance and submit the same environment again to resume the nonterminal operation.

Completion requires all ciphertext references to use the new version and pass AEAD verification. The final transaction activates the new DEK, retires the old metadata row, nulls the old wrapped key and nonce, and writes `ROTATE_DEK`. Do not treat a pending or verifying operation as completed.

For a large history, keep the maintenance window open until status is `COMPLETED`. Afterward confirm readiness, the audit event, an authorized current reveal, a historical reveal, and preview of any affected pending request.

## Compromise response

- Suspected KEK exposure: rotate KEK immediately, then assess whether process memory/plaintext was exposed. Re-wrap alone cannot undo stolen plaintext; rotate affected DEKs and real external credentials when warranted.
- Suspected DEK exposure: rotate that environment DEK, then rotate the actual database/API/password credentials in their source systems and update the deployment platform and ConfigDeck through the normal workflow.
- Lost KEK: recover the separately protected KEK backup. Encrypted data is cryptographically unrecoverable without a matching key.
- Active host compromise: isolate and rebuild the host first. Assume every value decryptable by the running process may be exposed; application key rotation on an untrusted host is insufficient.
