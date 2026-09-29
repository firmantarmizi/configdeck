# Security Model

ConfigDeck stores operationally sensitive configuration. It must run behind HTTPS and a private, VPN, or identity-aware access layer. Host and container administrators remain privileged; encryption at rest protects a copied database or backup when the master key is not also compromised.

## Data protection

- Every environment value is encrypted with ChaCha20-Poly1305, including values marked `public`.
- Each environment has an independently generated 256-bit data-encryption key (DEK).
- The master key (KEK) wraps DEKs and encrypts purpose-separated TOTP material. It is mounted from `/run/secrets/configdeck_master_key` and is never stored in SQLite.
- Random 96-bit nonces are generated for each encryption operation.
- Canonical authenticated data binds ciphertext to its purpose, entity identifiers, version, and key version.
- Database records contain ciphertext, nonce, and key metadata only. Restricted plaintext is decrypted only after backend authorization and recent authentication.

Back up the database and the matching master key separately. Losing the master key makes encrypted data unrecoverable; stealing both defeats encryption-at-rest protection.

## Identity and sessions

- Passwords use Argon2id.
- Operator and Administrator accounts require TOTP. Organizations may require TOTP for every account.
- Sessions are server-side. Browsers receive a random `Secure`, `HttpOnly`, `SameSite=Strict` token; SQLite stores only its hash.
- Sessions have idle and absolute expiry and are revoked after password, role, account, TOTP, or App-access changes.
- Account and client throttling uses exponential backoff without a permanent count-based lockout.
- CSRF tokens are bound to the session and required for unsafe requests.

Login verifies email and password before asking enrolled users for a TOTP code. The intermediate session expires after five minutes, has no application access, and retains no password. Completing TOTP rotates the session and CSRF token. Enrollment and accounts requiring a password change do not receive recent-auth assurance.

A completed enrolled MFA login grants standard recent authentication for five minutes, so ordinary protected actions such as reveal, export, and backup do not immediately ask again. This is a fixed window, not extended by activity. Restore intent and key rotation require separate high-impact password/TOTP verification with a two-minute window. Every operation still checks role and scope. TOTP timesteps cannot be reused, including between login and high-impact verification; a new authenticator code may be required. Failed second-factor and recent-auth attempts are throttled.

## Authorization

| Capability | Contributor | Operator | Administrator |
|---|:---:|:---:|:---:|
| View assigned Apps and public values | Yes | All Apps | All Apps |
| View restricted plaintext | No | Recent auth | Recent auth |
| Create change requests | Assigned Apps | Yes | Yes |
| Review, fulfill, reject, and record applied changes | No | Yes | Yes |
| Preview/export a resolved environment | No | Recent auth | Recent auth |
| Manage Apps, environments, users, and grants | No | No | Yes |
| Backup | No | No | Recent auth |
| Restore intent and key rotation | No | No | High-impact recent auth |
| View audit log | No | Yes | Yes |

Inactive users are always denied. Contributor access is App-scoped. The backend performs the same checks regardless of whether a request originated from the HTML interface or a direct HTTP call.

## Browser and HTTP controls

- Askama escaping, a restrictive Content Security Policy, frame denial, MIME sniffing protection, and a strict referrer policy reduce browser attack surface.
- Sensitive pages use `Cache-Control: no-store` and `Pragma: no-cache`.
- Public static asset URLs include a build fingerprint, allowing browsers to refresh styles and scripts after deployment while caching each build.
- Plaintext values are never placed in URLs, browser storage, global JavaScript state, logs, or audit metadata.
- Reveal and export are explicit actions. Restricted values remain masked on ordinary pages.
- The comparison workspace only decrypts a logical key when its visibility is consistently public. Any restricted current value or proposal makes the complete key fail closed and masked across environments until the metadata is normalized.
- Forwarded client headers are ignored unless the immediate proxy is in `CONFIGDECK_TRUSTED_PROXIES`.

## Primary threats and controls

| Threat | Primary controls | Remaining responsibility |
|---|---|---|
| Stolen database or backup | AEAD, per-environment DEKs, KEK outside SQLite | Keep key backups separate and rotate affected external credentials if both are exposed |
| Unauthorized restricted-value access | Backend role/scope checks, no decrypt before authorization, recent auth | Review grants and privileged audit events |
| Session theft | Hashed session tokens, secure cookies, expiry, rotation, revocation | Protect endpoints, browsers, and TLS termination |
| CSRF/XSS/cache leakage | Session-bound CSRF, output escaping, CSP, no-store, no plaintext URLs/storage | Patch promptly and restrict network access |
| Malicious `.env` input | Data-only parser, size/count/metadata limits, duplicate rejection, explicit dotted-key validation, no shell expansion, and purpose-bound encrypted preview tokens | Review detected action, group, visibility, and type; ordinary comments are ignored, contributor paste creates a proposal, and recording deployed state remains recent-authenticated and Operator-only |
| Log leakage | Request-body exclusion and metadata allowlists | Restrict log access and define retention |
| Storage exhaustion | Bounded logs/auth state, pagination, free-space monitoring | Define audit/archive/backup lifecycle and alerts |
| Host compromise | Non-root container, read-only filesystem, dropped capabilities | Isolate and rebuild the host; rotate real credentials afterward |

## Audit and retention

Audit events contain allowlisted metadata, never configuration plaintext or authentication secrets. Configuration history and audit records are durable by design. Login-attempt rows older than 24 hours and sessions older than 30 days past absolute expiry are pruned opportunistically. Audit older than 180 days can be moved to verified archives through Administrator maintenance. Archive files and backups require an off-host lifecycle suitable for recovery and incident response.

## Reporting vulnerabilities

Follow the private reporting process in [`SECURITY.md`](../SECURITY.md). Never include real configuration values, credentials, session material, databases, backups, or production host details in a report.

### Redacted environment preview

The read-only `/environments/{id}/preview` page uses the same backend-authorized projection as the normal variable list. It decrypts public values only; restricted values are fixed masks, including for their original requester. Every request checks the session and service scope. It needs no recent authentication because it reveals no additional information, uses no-store/no-cache headers, and grants no full-export, download, or request-apply capability.

Deployed-import metadata matching is scoped to the authorized App and selects no ciphertext or plaintext. Known visibility is locked in review and enforced again inside the write transaction. Conflicting visibility, incompatible pending changes, manipulated selections, and stale encrypted preview snapshots reject the batch without partial writes. Archiving an environment is reversible and transactionally blocked for the last active environment or an environment with open requests.

Audit archival is an Administrator-only, recent-authenticated, CSRF-protected maintenance action with a fixed 180-day cutoff and bounded batches. A durable verified archive precedes deletion. The delete guard is suspended only inside the exclusive writer transaction and reinstated before commit; rollback restores both rows and guard. No general audit-delete API exists. Archive files are private operational evidence and must be protected with backups.
