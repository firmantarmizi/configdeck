# Architecture

ConfigDeck is a modular monolith for managing encrypted environment configuration and auditable change workflows. It is intentionally small: one Rust process, one SQLite database, one data volume, and one separate backup volume.

## Runtime

- Rust, Axum, Tokio, SQLx, SQLite, Askama, and small vanilla JavaScript enhancements.
- Server-rendered HTML; no SPA framework or Node.js runtime in production.
- A single non-root container behind an HTTPS reverse proxy or private access layer.
- Local assets only. Authenticated and sensitive responses are not intended for shared caches.

## Modules

| Module | Responsibility |
|---|---|
| `auth` | Password authentication, TOTP, sessions, CSRF, rate limiting, and recent authentication |
| `crypto` | KEK/DEK handling, authenticated encryption, and key metadata validation |
| `organization` | First-run organization setup and branding |
| `users` | Accounts, roles, lifecycle, and App grants |
| `services` | App catalog and metadata |
| `environments` | Standard/custom environments and comparison views |
| `variables` | Current encrypted configuration and immutable history |
| `requests` | Multi-item change workflow, review, fulfillment, preview, and apply state |
| `audit` | Append-only privileged and configuration activity |
| `operations` / `rotations` | Backup, restore intent, KEK rotation, and resumable DEK rotation |
| `web` | Routes, middleware, templates, security headers, and request tracing |

Modules call domain functions directly. ConfigDeck does not require Redis, a message broker, a background worker, or an internal network API between components.

## Data model

```text
Organization
└── App
    ├── Contributor grants
    └── Environment
        ├── Environment key versions
        ├── Current variables
        ├── Immutable variable history
        └── Change requests and items
```

SQLite migrations in `migrations/` are the schema source of truth. Foreign keys, strict tables, checks, unique constraints, and append-only triggers enforce invariants alongside backend validation.

All configuration values are encrypted at rest. `visibility` controls authorization to plaintext; it does not change storage encryption. There is no plaintext value column and no parallel `is_secret` flag.

Variable grouping is presentation metadata, not an authorization boundary. Each variable version may carry an optional group name and stable display order. Import and export use portable `.env` comments (`# [Group]` plus optional key descriptions), while restricted-value access continues to depend only on `visibility` and backend authorization.

## Request path

A typical authenticated request passes through:

```text
request ID
→ trusted proxy/client identity
→ safe tracing metadata
→ security headers and body limits
→ session lookup
→ CSRF validation for unsafe methods
→ role and App-scope authorization
→ recent-authentication check when required
→ handler and transaction
```

Authorization, masking, decryption, and workflow-state validation are backend responsibilities. Restricted values are not decrypted for unauthorized users and are never sent to the browser as hidden plaintext.

## Change workflow

Contributors add keys through a progressive request builder, update or delete existing keys from their configuration row, or paste up to 50 `.env` entries into one encrypted request preview. The comparison row edits a logical key, visibility, and type once across every active environment where that key exists; the expanded detail edits only each environment's value and value source. A missing cell offers an inline ADD request locked to that logical key and inherited metadata, while a cell with an active proposal links to the pending request instead of offering a duplicate ADD. Fulfilled public proposals are visible in context, restricted proposals are always masked, Operator-supplied values remain `Awaiting operator input`, and deletion requests are identified explicitly. If a logical key has restricted visibility in any active environment or proposal, the backend does not decrypt any current or proposed value for that key until its metadata is normalized. The server validates the complete target set and inserts the environment-scoped requests and audit records in one SQLite transaction, so a collision cannot leave a partial cross-environment request set. Bulk request paste detects additions versus updates and never changes current state directly. An Operator or Administrator can fulfill missing values, review the request, preview the resulting environment, apply the values through the organization's deployment system, and explicitly confirm the request as applied. A separate recent-authenticated workflow records configuration that is already deployed.

```text
REQUESTED / NEEDS_INPUT
→ READY_TO_APPLY
→ external deployment
→ APPLIED
```

Saving a request in ConfigDeck never implies that a deployment happened. Current configuration changes only after an authorized user explicitly records the external action.

## Operational boundaries

- SQLite is intended for one ConfigDeck process and one persistent local volume, not horizontal replicas or a shared network filesystem.
- Backup uses SQLite `VACUUM INTO`; restore is an offline operator procedure.
- KEK rotation re-wraps environment DEKs and re-encrypts TOTP seeds.
- DEK rotation re-encrypts current values, history, and pending proposals in resumable batches.
- Container logs and disposable authentication state are bounded. Audit, history, and archived domain records require an explicit organizational retention policy.
- Deployment-platform integration, dynamic secrets, SSO, and background workers are outside the current scope.

See [Security model](security-model.md), [Deployment](deployment.md), and [Operations](operations.md) for the corresponding controls and procedures.
