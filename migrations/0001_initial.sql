-- ConfigDeck migration 0001: baseline schema
-- Target: SQLite >= 3.37 (STRICT tables), foreign_keys=ON.
-- IDs are canonical lowercase UUID strings; timestamps are RFC 3339 UTC strings.
-- This document is the reviewed baseline. Implementation migrations may split it
-- into numbered files but must preserve these invariants.

CREATE TABLE organizations (
    id                  TEXT PRIMARY KEY,
    singleton           INTEGER NOT NULL DEFAULT 1 UNIQUE CHECK (singleton = 1),
    name                TEXT NOT NULL,
    require_totp_all    INTEGER NOT NULL DEFAULT 0 CHECK (require_totp_all IN (0, 1)),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
) STRICT;

CREATE TABLE users (
    id                          TEXT PRIMARY KEY,
    organization_id             TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    email                       TEXT NOT NULL,
    email_normalized            TEXT NOT NULL UNIQUE,
    password_hash               TEXT NOT NULL,
    role                        TEXT NOT NULL CHECK (role IN ('CONTRIBUTOR', 'OPERATOR', 'ADMINISTRATOR')),
    active                      INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    auth_version                INTEGER NOT NULL DEFAULT 1 CHECK (auth_version >= 1),
    totp_secret_ciphertext      BLOB,
    totp_secret_nonce           BLOB,
    totp_crypto_version         INTEGER,
    totp_kek_version            INTEGER REFERENCES kek_registry(kek_version) ON DELETE RESTRICT,
    totp_enabled_at             TEXT,
    totp_last_used_step         INTEGER,
    password_changed_at         TEXT NOT NULL,
    last_login_at               TEXT,
    created_at                  TEXT NOT NULL,
    updated_at                  TEXT NOT NULL,
    created_by                  TEXT REFERENCES users(id) ON DELETE SET NULL,
    CHECK (
        (totp_secret_ciphertext IS NULL AND totp_secret_nonce IS NULL AND totp_crypto_version IS NULL AND totp_kek_version IS NULL AND totp_enabled_at IS NULL)
        OR
        (totp_secret_ciphertext IS NOT NULL AND totp_secret_nonce IS NOT NULL AND totp_crypto_version IS NOT NULL AND totp_kek_version IS NOT NULL)
    ),
    CHECK (totp_secret_nonce IS NULL OR length(totp_secret_nonce) = 12),
    CHECK (totp_secret_ciphertext IS NULL OR length(totp_secret_ciphertext) >= 16)
) STRICT;

CREATE TABLE services (
    id                  TEXT PRIMARY KEY,
    organization_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    name                TEXT NOT NULL,
    name_normalized     TEXT NOT NULL,
    description         TEXT,
    archived_at         TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    created_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    UNIQUE (organization_id, name_normalized)
) STRICT;

CREATE TABLE environments (
    id                  TEXT PRIMARY KEY,
    service_id          TEXT NOT NULL REFERENCES services(id) ON DELETE RESTRICT,
    name                TEXT NOT NULL,
    name_normalized     TEXT NOT NULL,
    description         TEXT,
    archived_at         TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    created_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    UNIQUE (service_id, name_normalized),
    UNIQUE (id, service_id)
) STRICT;

CREATE TABLE kek_registry (
    kek_version         INTEGER PRIMARY KEY CHECK (kek_version >= 1),
    fingerprint         BLOB NOT NULL UNIQUE,
    status              TEXT NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED')),
    activated_at        TEXT NOT NULL,
    retired_at          TEXT,
    CHECK (
        (status = 'ACTIVE' AND retired_at IS NULL)
        OR (status = 'RETIRED' AND retired_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX ux_kek_registry_one_active
    ON kek_registry ((1)) WHERE status = 'ACTIVE';

CREATE TABLE environment_keys (
    id                  TEXT PRIMARY KEY,
    environment_id      TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    dek_version         INTEGER NOT NULL CHECK (dek_version >= 1),
    wrapped_dek         BLOB,
    wrapped_dek_nonce   BLOB,
    crypto_version      INTEGER NOT NULL DEFAULT 1 CHECK (crypto_version >= 1),
    kek_version         INTEGER NOT NULL REFERENCES kek_registry(kek_version) ON DELETE RESTRICT,
    status              TEXT NOT NULL CHECK (status IN ('ACTIVE', 'PENDING', 'RETIRED')),
    created_at          TEXT NOT NULL,
    retired_at          TEXT,
    UNIQUE (environment_id, dek_version),
    CHECK (
        (status IN ('ACTIVE', 'PENDING') AND wrapped_dek IS NOT NULL AND wrapped_dek_nonce IS NOT NULL AND retired_at IS NULL)
        OR
        (status = 'RETIRED' AND wrapped_dek IS NULL AND wrapped_dek_nonce IS NULL AND retired_at IS NOT NULL)
    ),
    CHECK (wrapped_dek_nonce IS NULL OR length(wrapped_dek_nonce) = 12),
    CHECK (wrapped_dek IS NULL OR length(wrapped_dek) = 48)
) STRICT;

CREATE UNIQUE INDEX ux_environment_keys_one_active
    ON environment_keys (environment_id) WHERE status = 'ACTIVE';
CREATE UNIQUE INDEX ux_environment_keys_one_pending
    ON environment_keys (environment_id) WHERE status = 'PENDING';

CREATE TABLE user_service_access (
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_id          TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    access_level        TEXT NOT NULL DEFAULT 'READ_REQUEST' CHECK (access_level IN ('READ_REQUEST')),
    granted_at          TEXT NOT NULL,
    granted_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    PRIMARY KEY (user_id, service_id)
) STRICT;

CREATE TABLE variables (
    id                  TEXT PRIMARY KEY,
    environment_id      TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    key                 TEXT NOT NULL,
    encrypted_value     BLOB NOT NULL,
    value_nonce         BLOB NOT NULL,
    crypto_version      INTEGER NOT NULL DEFAULT 1 CHECK (crypto_version >= 1),
    dek_version         INTEGER NOT NULL,
    visibility          TEXT NOT NULL CHECK (visibility IN ('public', 'restricted')),
    value_type          TEXT NOT NULL CHECK (value_type IN ('string', 'boolean', 'integer', 'url', 'multiline')),
    description         TEXT,
    version             INTEGER NOT NULL CHECK (version >= 1),
    lifecycle_status    TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle_status IN ('ACTIVE', 'DELETED')),
    deployment_status   TEXT NOT NULL DEFAULT 'APPLIED' CHECK (deployment_status IN ('NOT_APPLIED', 'APPLIED')),
    created_at          TEXT NOT NULL,
    created_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at          TEXT NOT NULL,
    updated_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    deleted_at          TEXT,
    last_applied_at     TEXT,
    last_applied_by     TEXT REFERENCES users(id) ON DELETE RESTRICT,
    UNIQUE (environment_id, key),
    FOREIGN KEY (environment_id, dek_version)
        REFERENCES environment_keys(environment_id, dek_version) ON DELETE RESTRICT,
    CHECK (length(key) BETWEEN 1 AND 255),
    CHECK (substr(key, 1, 1) GLOB '[A-Za-z_]'),
    CHECK (key NOT GLOB '*[^A-Za-z0-9_]*'),
    CHECK (
        (lifecycle_status = 'ACTIVE' AND deleted_at IS NULL)
        OR (lifecycle_status = 'DELETED' AND deleted_at IS NOT NULL)
    ),
    CHECK (
        (last_applied_at IS NULL AND last_applied_by IS NULL)
        OR (last_applied_at IS NOT NULL AND last_applied_by IS NOT NULL)
    ),
    CHECK (length(value_nonce) = 12),
    CHECK (length(encrypted_value) >= 16)
) STRICT;

CREATE TABLE change_requests (
    id                  TEXT PRIMARY KEY,
    service_id          TEXT NOT NULL REFERENCES services(id) ON DELETE RESTRICT,
    environment_id      TEXT NOT NULL,
    title               TEXT,
    reason              TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('REQUESTED', 'NEEDS_INPUT', 'READY_TO_APPLY', 'APPLIED', 'REJECTED')),
    requested_by        TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    requested_at        TEXT NOT NULL,
    approved_by         TEXT REFERENCES users(id) ON DELETE RESTRICT,
    approved_at         TEXT,
    rejected_by         TEXT REFERENCES users(id) ON DELETE RESTRICT,
    rejected_at         TEXT,
    rejection_reason    TEXT,
    applied_by          TEXT REFERENCES users(id) ON DELETE RESTRICT,
    applied_at          TEXT,
    preview_fingerprint BLOB,
    revision            INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    FOREIGN KEY (environment_id, service_id)
        REFERENCES environments(id, service_id) ON DELETE RESTRICT,
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CHECK ((rejected_by IS NULL) = (rejected_at IS NULL)),
    CHECK ((applied_by IS NULL) = (applied_at IS NULL)),
    CHECK (
        (status = 'REJECTED' AND rejected_at IS NOT NULL AND rejection_reason IS NOT NULL AND applied_at IS NULL)
        OR (status = 'APPLIED' AND applied_at IS NOT NULL AND approved_at IS NOT NULL AND rejected_at IS NULL)
        OR (status IN ('REQUESTED', 'NEEDS_INPUT', 'READY_TO_APPLY') AND applied_at IS NULL AND rejected_at IS NULL)
    ),
    CHECK (status <> 'READY_TO_APPLY' OR approved_at IS NOT NULL)
) STRICT;

CREATE TABLE change_request_items (
    id                          TEXT PRIMARY KEY,
    change_request_id           TEXT NOT NULL REFERENCES change_requests(id) ON DELETE CASCADE,
    variable_id                 TEXT REFERENCES variables(id) ON DELETE RESTRICT,
    action                      TEXT NOT NULL CHECK (action IN ('ADD', 'UPDATE', 'DELETE')),
    key                         TEXT NOT NULL,
    base_variable_version       INTEGER,
    encrypted_proposed_value    BLOB,
    proposed_value_nonce        BLOB,
    proposed_crypto_version     INTEGER,
    proposed_dek_version        INTEGER,
    proposed_visibility         TEXT NOT NULL CHECK (proposed_visibility IN ('public', 'restricted')),
    proposed_value_type         TEXT NOT NULL CHECK (proposed_value_type IN ('string', 'boolean', 'integer', 'url', 'multiline')),
    proposed_description        TEXT,
    value_source                TEXT CHECK (value_source IN ('REQUESTER_PROVIDED', 'OPERATOR_PROVIDED')),
    value_fulfilled_by          TEXT REFERENCES users(id) ON DELETE RESTRICT,
    value_fulfilled_at          TEXT,
    item_revision               INTEGER NOT NULL DEFAULT 1 CHECK (item_revision >= 1),
    created_at                  TEXT NOT NULL,
    UNIQUE (change_request_id, key),
    CHECK (length(key) BETWEEN 1 AND 255),
    CHECK (substr(key, 1, 1) GLOB '[A-Za-z_]'),
    CHECK (key NOT GLOB '*[^A-Za-z0-9_]*'),
    CHECK ((value_fulfilled_by IS NULL) = (value_fulfilled_at IS NULL)),
    CHECK (
        (encrypted_proposed_value IS NULL AND proposed_value_nonce IS NULL AND proposed_crypto_version IS NULL AND proposed_dek_version IS NULL)
        OR
        (encrypted_proposed_value IS NOT NULL AND proposed_value_nonce IS NOT NULL AND proposed_crypto_version IS NOT NULL AND proposed_dek_version IS NOT NULL)
    ),
    CHECK (
        (action = 'ADD' AND variable_id IS NULL AND base_variable_version IS NULL AND value_source IS NOT NULL)
        OR
        (action IN ('UPDATE', 'DELETE') AND variable_id IS NOT NULL AND base_variable_version IS NOT NULL)
    ),
    CHECK (
        (action = 'DELETE' AND encrypted_proposed_value IS NULL AND value_source IS NULL)
        OR
        (action IN ('ADD', 'UPDATE') AND value_source IS NOT NULL)
    ),
    CHECK (
        value_source <> 'REQUESTER_PROVIDED'
        OR encrypted_proposed_value IS NOT NULL
    ),
    CHECK (proposed_value_nonce IS NULL OR length(proposed_value_nonce) = 12),
    CHECK (encrypted_proposed_value IS NULL OR length(encrypted_proposed_value) >= 16)
) STRICT;

CREATE TABLE variable_versions (
    id                  TEXT PRIMARY KEY,
    variable_id         TEXT NOT NULL REFERENCES variables(id) ON DELETE RESTRICT,
    environment_id      TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    version             INTEGER NOT NULL CHECK (version >= 1),
    operation           TEXT NOT NULL CHECK (operation IN ('ADD', 'UPDATE', 'DELETE', 'IMPORT')),
    encrypted_value     BLOB NOT NULL,
    value_nonce         BLOB NOT NULL,
    crypto_version      INTEGER NOT NULL DEFAULT 1 CHECK (crypto_version >= 1),
    dek_version         INTEGER NOT NULL,
    visibility          TEXT NOT NULL CHECK (visibility IN ('public', 'restricted')),
    value_type          TEXT NOT NULL CHECK (value_type IN ('string', 'boolean', 'integer', 'url', 'multiline')),
    description         TEXT,
    lifecycle_status    TEXT NOT NULL CHECK (lifecycle_status IN ('ACTIVE', 'DELETED')),
    changed_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    changed_at          TEXT NOT NULL,
    change_request_id   TEXT REFERENCES change_requests(id) ON DELETE RESTRICT,
    change_request_item_id TEXT REFERENCES change_request_items(id) ON DELETE RESTRICT,
    UNIQUE (variable_id, version),
    FOREIGN KEY (environment_id, dek_version)
        REFERENCES environment_keys(environment_id, dek_version) ON DELETE RESTRICT,
    CHECK (
        (change_request_id IS NULL AND change_request_item_id IS NULL)
        OR (change_request_id IS NOT NULL AND change_request_item_id IS NOT NULL)
    ),
    CHECK (length(value_nonce) = 12),
    CHECK (length(encrypted_value) >= 16)
) STRICT;

CREATE TABLE sessions (
    id                  TEXT PRIMARY KEY,
    token_hash          BLOB NOT NULL UNIQUE,
    csrf_token_hash     BLOB NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_version        INTEGER NOT NULL CHECK (auth_version >= 1),
    authentication_state TEXT NOT NULL DEFAULT 'FULL' CHECK (authentication_state IN ('PASSWORD_ONLY', 'FULL')),
    created_at          TEXT NOT NULL,
    last_seen_at        TEXT NOT NULL,
    idle_expires_at     TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    privileged_authenticated_at TEXT,
    privileged_auth_level TEXT CHECK (privileged_auth_level IN ('STANDARD', 'HIGH_IMPACT')),
    client_ip           TEXT,
    user_agent_hash     BLOB,
    revoked_at          TEXT,
    revoke_reason       TEXT,
    CHECK (
        (privileged_authenticated_at IS NULL AND privileged_auth_level IS NULL)
        OR (privileged_authenticated_at IS NOT NULL AND privileged_auth_level IS NOT NULL)
    ),
    CHECK (length(token_hash) = 32),
    CHECK (length(csrf_token_hash) = 32)
) STRICT;

CREATE TABLE login_attempts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_key_hash    BLOB NOT NULL,
    client_identity_hash BLOB NOT NULL,
    attempted_at        TEXT NOT NULL,
    succeeded           INTEGER NOT NULL CHECK (succeeded IN (0, 1))
) STRICT;

CREATE TABLE audit_logs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at         TEXT NOT NULL,
    actor_user_id       TEXT REFERENCES users(id) ON DELETE SET NULL,
    action              TEXT NOT NULL,
    outcome             TEXT NOT NULL DEFAULT 'SUCCESS' CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILED')),
    service_id          TEXT REFERENCES services(id) ON DELETE SET NULL,
    environment_id      TEXT REFERENCES environments(id) ON DELETE SET NULL,
    variable_id         TEXT REFERENCES variables(id) ON DELETE SET NULL,
    variable_key        TEXT,
    change_request_id   TEXT REFERENCES change_requests(id) ON DELETE SET NULL,
    request_id          TEXT,
    client_ip           TEXT,
    user_agent          TEXT,
    metadata_json       TEXT NOT NULL DEFAULT '{}',
    CHECK (length(metadata_json) <= 16384)
) STRICT;

CREATE TRIGGER audit_logs_no_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs are append-only');
END;

CREATE TRIGGER audit_logs_no_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs are append-only');
END;

CREATE TRIGGER change_request_items_validate_scope_insert
BEFORE INSERT ON change_request_items
BEGIN
    SELECT CASE WHEN NEW.variable_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM variables v
        JOIN change_requests r ON r.id = NEW.change_request_id
        WHERE v.id = NEW.variable_id AND v.environment_id = r.environment_id
    ) THEN RAISE(ABORT, 'change request variable scope mismatch') END;
    SELECT CASE WHEN NEW.proposed_dek_version IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM environment_keys k
        JOIN change_requests r ON r.id = NEW.change_request_id
        WHERE k.environment_id = r.environment_id AND k.dek_version = NEW.proposed_dek_version
    ) THEN RAISE(ABORT, 'change request DEK scope mismatch') END;
END;

CREATE TRIGGER change_request_items_validate_scope_update
BEFORE UPDATE ON change_request_items
BEGIN
    SELECT CASE WHEN NEW.variable_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM variables v
        JOIN change_requests r ON r.id = NEW.change_request_id
        WHERE v.id = NEW.variable_id AND v.environment_id = r.environment_id
    ) THEN RAISE(ABORT, 'change request variable scope mismatch') END;
    SELECT CASE WHEN NEW.proposed_dek_version IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM environment_keys k
        JOIN change_requests r ON r.id = NEW.change_request_id
        WHERE k.environment_id = r.environment_id AND k.dek_version = NEW.proposed_dek_version
    ) THEN RAISE(ABORT, 'change request DEK scope mismatch') END;
END;

CREATE TRIGGER change_requests_validate_ready
BEFORE UPDATE OF status, approved_at ON change_requests
WHEN NEW.status = 'READY_TO_APPLY'
BEGIN
    SELECT CASE WHEN NEW.approved_at IS NULL
        THEN RAISE(ABORT, 'ready change request must be approved') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM change_request_items i WHERE i.change_request_id = NEW.id
    ) THEN RAISE(ABORT, 'ready change request must contain items') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM change_request_items i
        WHERE i.change_request_id = NEW.id
          AND i.action IN ('ADD', 'UPDATE')
          AND i.encrypted_proposed_value IS NULL
    ) THEN RAISE(ABORT, 'ready change request contains missing value') END;
END;

CREATE TRIGGER change_requests_validate_apply_transition
BEFORE UPDATE OF status ON change_requests
WHEN NEW.status = 'APPLIED' AND OLD.status <> 'READY_TO_APPLY'
BEGIN
    SELECT RAISE(ABORT, 'only ready change requests can be applied');
END;

CREATE TABLE key_rotation_operations (
    id                  TEXT PRIMARY KEY,
    rotation_type       TEXT NOT NULL CHECK (rotation_type IN ('KEK', 'DEK')),
    environment_id      TEXT REFERENCES environments(id) ON DELETE RESTRICT,
    source_kek_version  INTEGER,
    target_kek_version  INTEGER,
    source_dek_version  INTEGER,
    target_dek_version  INTEGER,
    status              TEXT NOT NULL CHECK (status IN ('VALIDATING', 'PREPARING', 'MIGRATING', 'VERIFYING', 'COMMITTING', 'COMPLETED', 'FAILED')),
    total_records       INTEGER NOT NULL DEFAULT 0 CHECK (total_records >= 0),
    processed_records   INTEGER NOT NULL DEFAULT 0 CHECK (processed_records >= 0 AND processed_records <= total_records),
    requested_by        TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    requested_at        TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    completed_at        TEXT,
    failure_code        TEXT,
    CHECK (
        (rotation_type = 'KEK' AND environment_id IS NULL AND source_dek_version IS NULL AND target_dek_version IS NULL)
        OR
        (rotation_type = 'DEK' AND environment_id IS NOT NULL AND source_dek_version IS NOT NULL AND target_dek_version IS NOT NULL)
    ),
    CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX ux_one_active_dek_rotation_per_environment
    ON key_rotation_operations (environment_id)
    WHERE rotation_type = 'DEK' AND status NOT IN ('COMPLETED', 'FAILED');
CREATE UNIQUE INDEX ux_one_active_kek_rotation
    ON key_rotation_operations ((1))
    WHERE rotation_type = 'KEK' AND status NOT IN ('COMPLETED', 'FAILED');

CREATE TABLE backups (
    id                  TEXT PRIMARY KEY,
    backup_identifier   TEXT NOT NULL UNIQUE,
    size_bytes          INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    checksum_sha256     BLOB,
    status              TEXT NOT NULL CHECK (status IN ('CREATING', 'AVAILABLE', 'FAILED')),
    created_by          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TEXT NOT NULL,
    completed_at        TEXT,
    failure_code        TEXT,
    CHECK (backup_identifier NOT LIKE '%/%' AND backup_identifier NOT LIKE '%\%'),
    CHECK (
        (status = 'AVAILABLE' AND completed_at IS NOT NULL AND checksum_sha256 IS NOT NULL AND size_bytes IS NOT NULL)
        OR status IN ('CREATING', 'FAILED')
    )
) STRICT;

CREATE TABLE restore_intents (
    id                  TEXT PRIMARY KEY,
    backup_identifier   TEXT NOT NULL,
    reason              TEXT NOT NULL,
    requested_by        TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    requested_at        TEXT NOT NULL,
    marker_written_at   TEXT NOT NULL,
    cancelled_at        TEXT,
    FOREIGN KEY (backup_identifier) REFERENCES backups(backup_identifier) ON DELETE RESTRICT,
    CHECK (backup_identifier NOT LIKE '%/%' AND backup_identifier NOT LIKE '%\%')
) STRICT;

CREATE INDEX ix_environments_service ON environments (service_id, archived_at);
CREATE INDEX ix_access_service ON user_service_access (service_id, user_id);
CREATE INDEX ix_variables_environment_active ON variables (environment_id, key) WHERE lifecycle_status = 'ACTIVE';
CREATE INDEX ix_variable_versions_variable ON variable_versions (variable_id, version DESC);
CREATE INDEX ix_change_requests_environment_status ON change_requests (environment_id, status, requested_at);
CREATE INDEX ix_change_requests_requester ON change_requests (requested_by, requested_at DESC);
CREATE INDEX ix_change_request_items_request ON change_request_items (change_request_id);
CREATE INDEX ix_sessions_user ON sessions (user_id, revoked_at, absolute_expires_at);
CREATE INDEX ix_sessions_expiry ON sessions (absolute_expires_at, idle_expires_at);
CREATE INDEX ix_login_attempts_account_time ON login_attempts (account_key_hash, attempted_at);
CREATE INDEX ix_login_attempts_client_time ON login_attempts (client_identity_hash, attempted_at);
CREATE INDEX ix_audit_time ON audit_logs (occurred_at DESC);
CREATE INDEX ix_audit_actor_time ON audit_logs (actor_user_id, occurred_at DESC);
CREATE INDEX ix_audit_environment_time ON audit_logs (environment_id, occurred_at DESC);

