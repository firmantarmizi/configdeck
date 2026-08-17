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

Contributors propose one or more additions, updates, or deletions. An Operator or Administrator can fulfill missing values, review the request, preview the resulting environment, apply the values through the organization's deployment system, and explicitly confirm the request as applied.

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
