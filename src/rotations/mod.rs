use std::sync::atomic::{AtomicBool, Ordering};

use sqlx::{FromRow, Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use crate::{
    auth::{AuthenticatedSession, PrivilegedAuthLevel, SessionManager},
    crypto::{CryptoManager, CurrentValueContext, ProposedValueContext},
    db::{now_rfc3339, validate_active_environment_keys},
    error::AppError,
    users::Capability,
};

const BATCH_SIZE: i64 = 64;
const MAX_REASON_BYTES: usize = 1_000;

#[derive(Debug)]
pub struct RotationOverview {
    pub active_kek_version: i64,
    pub kek_rotation_ready: bool,
    pub previous_key_mounted: bool,
    pub environments: Vec<RotationEnvironment>,
    pub operations: Vec<RotationOperation>,
}

#[derive(Debug, FromRow)]
pub struct RotationEnvironment {
    pub id: String,
    pub app_name: String,
    pub environment_name: String,
    pub active_dek_version: i64,
}

#[derive(Debug, FromRow)]
pub struct RotationOperation {
    pub rotation_type: String,
    pub target_name: Option<String>,
    pub status: String,
    pub processed_records: i64,
    pub total_records: i64,
    pub updated_display: String,
    pub failure_code: Option<String>,
}

#[derive(FromRow)]
struct RotationOperationRow {
    rotation_type: String,
    target_name: Option<String>,
    status: String,
    processed_records: i64,
    total_records: i64,
    updated_at: String,
    failure_code: Option<String>,
}

#[derive(FromRow)]
struct WrappedDekRow {
    environment_id: String,
    dek_version: i64,
    kek_version: i64,
    wrapped_dek: Vec<u8>,
    wrapped_dek_nonce: Vec<u8>,
}

#[derive(FromRow)]
struct TotpRow {
    id: String,
    crypto_version: i64,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    kek_version: i64,
}

struct PreparedDek {
    row: WrappedDekRow,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

struct PreparedTotp {
    row: TotpRow,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(FromRow)]
struct ActiveDekRotation {
    id: String,
    environment_id: String,
    source_dek_version: i64,
    target_dek_version: i64,
    total_records: i64,
}

#[derive(FromRow)]
struct CurrentCipherRow {
    id: String,
    service_id: String,
    environment_id: String,
    version: i64,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(FromRow)]
struct HistoryCipherRow {
    id: String,
    service_id: String,
    environment_id: String,
    variable_id: String,
    version: i64,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(FromRow)]
struct ProposalCipherRow {
    id: String,
    service_id: String,
    environment_id: String,
    change_request_id: String,
    item_revision: i64,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    legacy_variable_id: Option<String>,
    legacy_variable_version: Option<i64>,
    legacy_direct_apply: i64,
}

pub async fn overview(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
) -> Result<RotationOverview, AppError> {
    require_administrator(session)?;
    let active =
        sqlx::query("SELECT kek_version, fingerprint FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;
    let active_kek_version: i64 = active.try_get("kek_version")?;
    let active_fingerprint: Vec<u8> = active.try_get("fingerprint")?;
    let kek_rotation_ready = crypto
        .previous_fingerprint()
        .is_some_and(|fingerprint| fingerprint == active_fingerprint)
        && crypto.fingerprint() != active_fingerprint;
    let environments = sqlx::query_as::<_, RotationEnvironment>(
        "SELECT e.id, s.name AS app_name, e.name AS environment_name, k.dek_version AS active_dek_version \
         FROM environments e JOIN services s ON s.id = e.service_id \
         JOIN environment_keys k ON k.environment_id = e.id AND k.status = 'ACTIVE' \
         WHERE s.organization_id = ? ORDER BY s.name_normalized, e.name_normalized",
    )
    .bind(&session.user.organization_id)
    .fetch_all(pool)
    .await?;
    let operation_rows = sqlx::query_as::<_, RotationOperationRow>(
        "SELECT o.rotation_type, CASE WHEN o.rotation_type = 'DEK' THEN s.name || ' / ' || e.name ELSE NULL END AS target_name, \
                o.status, o.processed_records, o.total_records, o.updated_at, o.failure_code \
         FROM key_rotation_operations o LEFT JOIN environments e ON e.id = o.environment_id \
         LEFT JOIN services s ON s.id = e.service_id ORDER BY o.requested_at DESC LIMIT 12",
    )
    .fetch_all(pool)
    .await?;
    let operations = operation_rows
        .into_iter()
        .map(|row| RotationOperation {
            rotation_type: row.rotation_type,
            target_name: row.target_name,
            status: row.status,
            processed_records: row.processed_records,
            total_records: row.total_records,
            updated_display: display_timestamp(&row.updated_at),
            failure_code: row.failure_code,
        })
        .collect();
    Ok(RotationOverview {
        active_kek_version,
        kek_rotation_ready,
        previous_key_mounted: crypto.has_previous_key(),
        environments,
        operations,
    })
}

pub async fn write_blocked(pool: &SqlitePool, crypto: &CryptoManager) -> Result<bool, AppError> {
    let operation_active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM key_rotation_operations WHERE status NOT IN ('COMPLETED', 'FAILED'))",
    )
    .fetch_one(pool)
    .await?;
    if operation_active {
        return Ok(true);
    }
    let active_fingerprint: Vec<u8> =
        sqlx::query_scalar("SELECT fingerprint FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;
    Ok(active_fingerprint != crypto.fingerprint())
}

#[allow(clippy::too_many_lines)] // Keeps prevalidation, atomic mutation, and post-commit verification visibly ordered.
pub async fn rotate_kek(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    readiness: &AtomicBool,
    reason: &str,
) -> Result<(), AppError> {
    require_recent_administrator(sessions, session)?;
    validate_reason(reason)?;
    let active =
        sqlx::query("SELECT kek_version, fingerprint FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;
    let source_version: i64 = active.try_get("kek_version")?;
    let active_fingerprint: Vec<u8> = active.try_get("fingerprint")?;
    let previous_fingerprint = crypto.previous_fingerprint().ok_or(AppError::Conflict)?;
    let target_fingerprint = crypto.fingerprint();
    if previous_fingerprint != active_fingerprint || target_fingerprint == active_fingerprint {
        return Err(AppError::Conflict);
    }
    let fingerprint_conflict: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kek_registry WHERE fingerprint = ?)")
            .bind(&target_fingerprint)
            .fetch_one(pool)
            .await?;
    let concurrent: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM key_rotation_operations WHERE status NOT IN ('COMPLETED', 'FAILED'))",
    )
    .fetch_one(pool)
    .await?;
    if fingerprint_conflict || concurrent {
        return Err(AppError::Conflict);
    }
    let target_version: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(kek_version), 0) + 1 FROM kek_registry")
            .fetch_one(pool)
            .await?;

    let dek_rows = sqlx::query_as::<_, WrappedDekRow>(
        "SELECT environment_id, dek_version, kek_version, wrapped_dek, wrapped_dek_nonce \
         FROM environment_keys WHERE status = 'ACTIVE' ORDER BY environment_id",
    )
    .fetch_all(pool)
    .await?;
    let mut prepared_deks = Vec::with_capacity(dek_rows.len());
    for row in dek_rows {
        if row.kek_version != source_version {
            return Err(AppError::Conflict);
        }
        let dek = crypto
            .unwrap_dek_with_previous(
                &row.environment_id,
                to_u64(row.dek_version)?,
                to_u64(row.kek_version)?,
                &row.wrapped_dek,
                &row.wrapped_dek_nonce,
            )
            .map_err(|_| AppError::Crypto)?;
        let wrapped = crypto
            .wrap_dek(
                &row.environment_id,
                to_u64(row.dek_version)?,
                to_u64(target_version)?,
                &dek,
            )
            .map_err(|_| AppError::Crypto)?;
        prepared_deks.push(PreparedDek {
            row,
            ciphertext: wrapped.ciphertext,
            nonce: wrapped.nonce.to_vec(),
        });
    }

    let totp_rows = sqlx::query_as::<_, TotpRow>(
        "SELECT id, totp_crypto_version AS crypto_version, totp_secret_ciphertext AS ciphertext, \
                totp_secret_nonce AS nonce, totp_kek_version AS kek_version \
         FROM users WHERE totp_secret_ciphertext IS NOT NULL ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut prepared_totp = Vec::with_capacity(totp_rows.len());
    for row in totp_rows {
        if row.kek_version != source_version {
            return Err(AppError::Conflict);
        }
        let seed = crypto
            .decrypt_totp_seed_with_previous(
                &row.id,
                to_u64(row.crypto_version)?,
                &row.ciphertext,
                &row.nonce,
            )
            .map_err(|_| AppError::Crypto)?;
        let encrypted = crypto
            .encrypt_totp_seed(&row.id, to_u64(row.crypto_version)?, &seed)
            .map_err(|_| AppError::Crypto)?;
        prepared_totp.push(PreparedTotp {
            row,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce.to_vec(),
        });
    }

    let now = now_rfc3339()?;
    let operation_id = Uuid::new_v4().to_string();
    let total = i64::try_from(prepared_deks.len() + prepared_totp.len())
        .map_err(|_| AppError::InvalidRequest)?;
    let mut transaction = pool.begin().await?;
    revalidate_kek_source(&mut transaction, source_version, &active_fingerprint).await?;
    sqlx::query(
        "INSERT INTO key_rotation_operations(id, rotation_type, source_kek_version, target_kek_version, status, total_records, processed_records, requested_by, requested_at, updated_at) \
         VALUES(?, 'KEK', ?, ?, 'VALIDATING', ?, 0, ?, ?, ?)",
    )
    .bind(&operation_id)
    .bind(source_version)
    .bind(target_version)
    .bind(total)
    .bind(&session.user.id)
    .bind(&now)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE kek_registry SET status = 'RETIRED', retired_at = ? WHERE kek_version = ? AND status = 'ACTIVE'")
        .bind(&now)
        .bind(source_version)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("INSERT INTO kek_registry(kek_version, fingerprint, status, activated_at) VALUES(?, ?, 'ACTIVE', ?)")
        .bind(target_version)
        .bind(&target_fingerprint)
        .bind(&now)
        .execute(&mut *transaction)
        .await?;
    for prepared in &prepared_deks {
        let result = sqlx::query(
            "UPDATE environment_keys SET wrapped_dek = ?, wrapped_dek_nonce = ?, kek_version = ? \
             WHERE environment_id = ? AND dek_version = ? AND status = 'ACTIVE' AND kek_version = ?",
        )
        .bind(&prepared.ciphertext)
        .bind(&prepared.nonce)
        .bind(target_version)
        .bind(&prepared.row.environment_id)
        .bind(prepared.row.dek_version)
        .bind(source_version)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AppError::Conflict);
        }
    }
    for prepared in &prepared_totp {
        let result = sqlx::query(
            "UPDATE users SET totp_secret_ciphertext = ?, totp_secret_nonce = ?, totp_kek_version = ?, updated_at = ? \
             WHERE id = ? AND totp_kek_version = ?",
        )
        .bind(&prepared.ciphertext)
        .bind(&prepared.nonce)
        .bind(target_version)
        .bind(&now)
        .bind(&prepared.row.id)
        .bind(source_version)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AppError::Conflict);
        }
    }
    complete_operation(
        &mut transaction,
        &operation_id,
        &now,
        total,
        &session.user.id,
        "ROTATE_KEK",
        None,
        serde_json::json!({
            "rotation_type": "KEK",
            "source_kek_version": source_version,
            "target_kek_version": target_version,
            "record_count": total,
            "reason_length": reason.trim().len(),
        }),
    )
    .await?;
    transaction.commit().await?;

    if validate_environment_keys_with_primary(pool, crypto)
        .await
        .is_err()
        || validate_totp_with_primary(pool, crypto).await.is_err()
    {
        readiness.store(false, Ordering::Release);
        return Err(AppError::Crypto);
    }
    Ok(())
}

pub async fn rotate_dek(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    readiness: &AtomicBool,
    environment_id: &str,
    reason: &str,
) -> Result<(), AppError> {
    require_recent_administrator(sessions, session)?;
    validate_reason(reason)?;
    authorize_environment(pool, session, environment_id).await?;
    ensure_primary_kek_active(pool, crypto).await?;
    let operation =
        load_or_prepare_dek_operation(pool, crypto, session, environment_id, reason.trim().len())
            .await?;
    migrate_dek_batches(pool, crypto, &operation).await?;
    verify_and_finalize_dek(
        pool,
        crypto,
        session,
        readiness,
        &operation,
        reason.trim().len(),
    )
    .await
}

async fn load_or_prepare_dek_operation(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    environment_id: &str,
    _reason_length: usize,
) -> Result<ActiveDekRotation, AppError> {
    if let Some(operation) = sqlx::query_as::<_, ActiveDekRotation>(
        "SELECT id, environment_id, source_dek_version, target_dek_version, total_records \
         FROM key_rotation_operations WHERE rotation_type = 'DEK' AND environment_id = ? \
         AND status NOT IN ('COMPLETED', 'FAILED')",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?
    {
        return Ok(operation);
    }
    let other_rotation: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM key_rotation_operations WHERE status NOT IN ('COMPLETED', 'FAILED'))",
    )
    .fetch_one(pool)
    .await?;
    if other_rotation {
        return Err(AppError::Conflict);
    }
    let active = sqlx::query_as::<_, WrappedDekRow>(
        "SELECT environment_id, dek_version, kek_version, wrapped_dek, wrapped_dek_nonce \
         FROM environment_keys WHERE environment_id = ? AND status = 'ACTIVE'",
    )
    .bind(environment_id)
    .fetch_one(pool)
    .await?;
    crypto
        .unwrap_dek(
            environment_id,
            to_u64(active.dek_version)?,
            to_u64(active.kek_version)?,
            &active.wrapped_dek,
            &active.wrapped_dek_nonce,
        )
        .map_err(|_| AppError::Crypto)?;
    let target_version: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(dek_version), 0) + 1 FROM environment_keys WHERE environment_id = ?",
    )
    .bind(environment_id)
    .fetch_one(pool)
    .await?;
    let new_dek = crypto.generate_dek().map_err(|_| AppError::Crypto)?;
    let wrapped = crypto
        .wrap_dek(
            environment_id,
            to_u64(target_version)?,
            to_u64(active.kek_version)?,
            &new_dek,
        )
        .map_err(|_| AppError::Crypto)?;
    let total_records = count_dek_references(pool, environment_id, active.dek_version).await?;
    let now = now_rfc3339()?;
    let operation_id = Uuid::new_v4().to_string();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO environment_keys(id, environment_id, dek_version, wrapped_dek, wrapped_dek_nonce, crypto_version, kek_version, status, created_at) \
         VALUES(?, ?, ?, ?, ?, 1, ?, 'PENDING', ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(environment_id)
    .bind(target_version)
    .bind(&wrapped.ciphertext)
    .bind(wrapped.nonce.as_slice())
    .bind(active.kek_version)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO key_rotation_operations(id, rotation_type, environment_id, source_kek_version, target_kek_version, source_dek_version, target_dek_version, status, total_records, processed_records, requested_by, requested_at, updated_at) \
         VALUES(?, 'DEK', ?, ?, ?, ?, ?, 'MIGRATING', ?, 0, ?, ?, ?)",
    )
    .bind(&operation_id)
    .bind(environment_id)
    .bind(active.kek_version)
    .bind(active.kek_version)
    .bind(active.dek_version)
    .bind(target_version)
    .bind(total_records)
    .bind(&session.user.id)
    .bind(&now)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(ActiveDekRotation {
        id: operation_id,
        environment_id: environment_id.to_owned(),
        source_dek_version: active.dek_version,
        target_dek_version: target_version,
        total_records,
    })
}

async fn migrate_dek_batches(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    operation: &ActiveDekRotation,
) -> Result<(), AppError> {
    let old_dek = load_dek(
        pool,
        crypto,
        &operation.environment_id,
        operation.source_dek_version,
    )
    .await?;
    let new_dek = load_dek(
        pool,
        crypto,
        &operation.environment_id,
        operation.target_dek_version,
    )
    .await?;
    loop {
        let migrated =
            match migrate_current_batch(pool, crypto, operation, &old_dek, &new_dek).await {
                Ok(migrated) => migrated,
                Err(error) => {
                    record_rotation_issue(pool, operation, "DEK_CURRENT_MIGRATION").await;
                    return Err(error);
                }
            };
        if migrated > 0 {
            continue;
        }
        let migrated =
            match migrate_history_batch(pool, crypto, operation, &old_dek, &new_dek).await {
                Ok(migrated) => migrated,
                Err(error) => {
                    record_rotation_issue(pool, operation, "DEK_HISTORY_MIGRATION").await;
                    return Err(error);
                }
            };
        if migrated > 0 {
            continue;
        }
        let migrated =
            match migrate_proposal_batch(pool, crypto, operation, &old_dek, &new_dek).await {
                Ok(migrated) => migrated,
                Err(error) => {
                    record_rotation_issue(pool, operation, "DEK_PROPOSAL_MIGRATION").await;
                    return Err(error);
                }
            };
        if migrated == 0 {
            break;
        }
    }
    sqlx::query("UPDATE key_rotation_operations SET status = 'VERIFYING', failure_code = NULL, updated_at = ? WHERE id = ? AND status = 'MIGRATING'")
        .bind(now_rfc3339()?)
        .bind(&operation.id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn record_rotation_issue(
    pool: &SqlitePool,
    operation: &ActiveDekRotation,
    failure_code: &'static str,
) {
    let updated_at = match now_rfc3339() {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(rotation_type = "DEK", stage = failure_code, error = %error, "unable to timestamp resumable rotation issue");
            return;
        }
    };
    let result = sqlx::query(
        "UPDATE key_rotation_operations SET failure_code = ?, updated_at = ? WHERE id = ? AND status = 'MIGRATING'",
    )
    .bind(failure_code)
    .bind(updated_at)
    .bind(&operation.id)
    .execute(pool)
    .await;
    match result {
        Ok(_) => tracing::error!(
            rotation_type = "DEK",
            stage = failure_code,
            total_records = operation.total_records,
            "resumable key rotation batch failed"
        ),
        Err(error) => tracing::error!(
            rotation_type = "DEK",
            stage = failure_code,
            total_records = operation.total_records,
            database_error = %error,
            "key rotation batch failed and diagnostic checkpoint could not be stored"
        ),
    }
}

fn display_timestamp(value: &str) -> String {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).map_or_else(
        |_| value.to_owned(),
        |timestamp| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                timestamp.year(),
                timestamp.month() as u8,
                timestamp.day(),
                timestamp.hour(),
                timestamp.minute()
            )
        },
    )
}

async fn migrate_current_batch(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    operation: &ActiveDekRotation,
    old_dek: &[u8; 32],
    new_dek: &[u8; 32],
) -> Result<usize, AppError> {
    let rows = sqlx::query_as::<_, CurrentCipherRow>(
        "SELECT v.id, e.service_id, v.environment_id, v.version, v.encrypted_value AS ciphertext, v.value_nonce AS nonce \
         FROM variables v JOIN environments e ON e.id = v.environment_id \
         WHERE v.environment_id = ? AND v.dek_version = ? ORDER BY v.id LIMIT ?",
    )
    .bind(&operation.environment_id)
    .bind(operation.source_dek_version)
    .bind(BATCH_SIZE)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let mut prepared = Vec::with_capacity(rows.len());
    for row in &rows {
        let old_context = CurrentValueContext {
            service_id: &row.service_id,
            environment_id: &row.environment_id,
            variable_id: &row.id,
            version: to_u64(row.version)?,
            dek_version: to_u64(operation.source_dek_version)?,
        };
        let plaintext = crypto
            .decrypt_current_value(old_dek, &old_context, &row.ciphertext, &row.nonce)
            .map_err(|_| AppError::Crypto)?;
        let new_context = CurrentValueContext {
            dek_version: to_u64(operation.target_dek_version)?,
            ..old_context
        };
        prepared.push(
            crypto
                .encrypt_current_value(new_dek, &new_context, &plaintext)
                .map_err(|_| AppError::Crypto)?,
        );
    }
    let mut transaction = pool.begin().await?;
    for (row, encrypted) in rows.iter().zip(&prepared) {
        update_cipher_row(
            &mut transaction,
            "variables",
            &row.id,
            operation.source_dek_version,
            operation.target_dek_version,
            &encrypted.ciphertext,
            &encrypted.nonce,
        )
        .await?;
    }
    checkpoint(&mut transaction, operation, rows.len()).await?;
    transaction.commit().await?;
    Ok(rows.len())
}

async fn migrate_history_batch(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    operation: &ActiveDekRotation,
    old_dek: &[u8; 32],
    new_dek: &[u8; 32],
) -> Result<usize, AppError> {
    let rows = sqlx::query_as::<_, HistoryCipherRow>(
        "SELECT vv.id, e.service_id, vv.environment_id, vv.variable_id, vv.version, vv.encrypted_value AS ciphertext, vv.value_nonce AS nonce \
         FROM variable_versions vv JOIN environments e ON e.id = vv.environment_id \
         WHERE vv.environment_id = ? AND vv.dek_version = ? ORDER BY vv.id LIMIT ?",
    )
    .bind(&operation.environment_id)
    .bind(operation.source_dek_version)
    .bind(BATCH_SIZE)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let mut prepared = Vec::with_capacity(rows.len());
    for row in &rows {
        let old_context = CurrentValueContext {
            service_id: &row.service_id,
            environment_id: &row.environment_id,
            variable_id: &row.variable_id,
            version: to_u64(row.version)?,
            dek_version: to_u64(operation.source_dek_version)?,
        };
        let plaintext = crypto
            .decrypt_current_value(old_dek, &old_context, &row.ciphertext, &row.nonce)
            .map_err(|_| AppError::Crypto)?;
        let new_context = CurrentValueContext {
            dek_version: to_u64(operation.target_dek_version)?,
            ..old_context
        };
        prepared.push(
            crypto
                .encrypt_current_value(new_dek, &new_context, &plaintext)
                .map_err(|_| AppError::Crypto)?,
        );
    }
    let mut transaction = pool.begin().await?;
    for (row, encrypted) in rows.iter().zip(&prepared) {
        update_cipher_row(
            &mut transaction,
            "variable_versions",
            &row.id,
            operation.source_dek_version,
            operation.target_dek_version,
            &encrypted.ciphertext,
            &encrypted.nonce,
        )
        .await?;
    }
    checkpoint(&mut transaction, operation, rows.len()).await?;
    transaction.commit().await?;
    Ok(rows.len())
}

async fn migrate_proposal_batch(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    operation: &ActiveDekRotation,
    old_dek: &[u8; 32],
    new_dek: &[u8; 32],
) -> Result<usize, AppError> {
    let rows = sqlx::query_as::<_, ProposalCipherRow>(
        "SELECT i.id, r.service_id, r.environment_id, i.change_request_id, i.item_revision, \
                i.encrypted_proposed_value AS ciphertext, i.proposed_value_nonce AS nonce, \
                vv.variable_id AS legacy_variable_id, vv.version AS legacy_variable_version, \
                CASE WHEN r.status = 'APPLIED' AND r.title = 'Direct registry apply' \
                          AND i.value_source = 'OPERATOR_PROVIDED' AND vv.id IS NOT NULL THEN 1 ELSE 0 END AS legacy_direct_apply \
         FROM change_request_items i JOIN change_requests r ON r.id = i.change_request_id \
         LEFT JOIN variable_versions vv ON vv.id = (SELECT vv2.id FROM variable_versions vv2 \
             WHERE vv2.change_request_item_id = i.id ORDER BY vv2.changed_at DESC, vv2.id LIMIT 1) \
         WHERE r.environment_id = ? AND i.proposed_dek_version = ? ORDER BY i.id LIMIT ?",
    )
    .bind(&operation.environment_id)
    .bind(operation.source_dek_version)
    .bind(BATCH_SIZE)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let mut prepared = Vec::with_capacity(rows.len());
    for row in &rows {
        let old_context = ProposedValueContext {
            service_id: &row.service_id,
            environment_id: &row.environment_id,
            change_request_id: &row.change_request_id,
            item_id: &row.id,
            item_revision: to_u64(row.item_revision)?,
            dek_version: to_u64(operation.source_dek_version)?,
        };
        let plaintext =
            match crypto.decrypt_proposed_value(old_dek, &old_context, &row.ciphertext, &row.nonce)
            {
                Ok(plaintext) => plaintext,
                Err(_) if row.legacy_direct_apply == 1 => {
                    let variable_id = row.legacy_variable_id.as_deref().ok_or(AppError::Crypto)?;
                    let variable_version = row
                        .legacy_variable_version
                        .ok_or(AppError::Crypto)
                        .and_then(to_u64)?;
                    crypto
                        .decrypt_current_value(
                            old_dek,
                            &CurrentValueContext {
                                service_id: &row.service_id,
                                environment_id: &row.environment_id,
                                variable_id,
                                version: variable_version,
                                dek_version: to_u64(operation.source_dek_version)?,
                            },
                            &row.ciphertext,
                            &row.nonce,
                        )
                        .map_err(|_| AppError::Crypto)?
                }
                Err(_) => return Err(AppError::Crypto),
            };
        let new_context = ProposedValueContext {
            dek_version: to_u64(operation.target_dek_version)?,
            ..old_context
        };
        prepared.push(
            crypto
                .encrypt_proposed_value(new_dek, &new_context, &plaintext)
                .map_err(|_| AppError::Crypto)?,
        );
    }
    let mut transaction = pool.begin().await?;
    for (row, encrypted) in rows.iter().zip(&prepared) {
        let result = sqlx::query(
            "UPDATE change_request_items SET encrypted_proposed_value = ?, proposed_value_nonce = ?, proposed_dek_version = ? \
             WHERE id = ? AND proposed_dek_version = ?",
        )
        .bind(&encrypted.ciphertext)
        .bind(encrypted.nonce.as_slice())
        .bind(operation.target_dek_version)
        .bind(&row.id)
        .bind(operation.source_dek_version)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AppError::Conflict);
        }
    }
    checkpoint(&mut transaction, operation, rows.len()).await?;
    transaction.commit().await?;
    Ok(rows.len())
}

async fn verify_and_finalize_dek(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    readiness: &AtomicBool,
    operation: &ActiveDekRotation,
    reason_length: usize,
) -> Result<(), AppError> {
    let old_references = count_dek_references(
        pool,
        &operation.environment_id,
        operation.source_dek_version,
    )
    .await?;
    let new_references = count_dek_references(
        pool,
        &operation.environment_id,
        operation.target_dek_version,
    )
    .await?;
    if old_references != 0 || new_references != operation.total_records {
        return Err(AppError::Conflict);
    }
    verify_dek_ciphertexts(pool, crypto, operation).await?;
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    sqlx::query("UPDATE key_rotation_operations SET status = 'COMMITTING', updated_at = ? WHERE id = ? AND status = 'VERIFYING'")
        .bind(&now)
        .bind(&operation.id)
        .execute(&mut *transaction)
        .await?;
    let retired = sqlx::query(
        "UPDATE environment_keys SET status = 'RETIRED', wrapped_dek = NULL, wrapped_dek_nonce = NULL, retired_at = ? \
         WHERE environment_id = ? AND dek_version = ? AND status = 'ACTIVE'",
    )
    .bind(&now)
    .bind(&operation.environment_id)
    .bind(operation.source_dek_version)
    .execute(&mut *transaction)
    .await?;
    let activated = sqlx::query(
        "UPDATE environment_keys SET status = 'ACTIVE' WHERE environment_id = ? AND dek_version = ? AND status = 'PENDING'",
    )
    .bind(&operation.environment_id)
    .bind(operation.target_dek_version)
    .execute(&mut *transaction)
    .await?;
    if retired.rows_affected() != 1 || activated.rows_affected() != 1 {
        return Err(AppError::Conflict);
    }
    complete_operation(
        &mut transaction,
        &operation.id,
        &now,
        operation.total_records,
        &session.user.id,
        "ROTATE_DEK",
        Some(&operation.environment_id),
        serde_json::json!({
            "rotation_type": "DEK",
            "source_dek_version": operation.source_dek_version,
            "target_dek_version": operation.target_dek_version,
            "record_count": operation.total_records,
            "reason_length": reason_length,
        }),
    )
    .await?;
    transaction.commit().await?;
    if validate_active_environment_keys(pool, crypto)
        .await
        .is_err()
    {
        readiness.store(false, Ordering::Release);
        return Err(AppError::Crypto);
    }
    Ok(())
}

async fn verify_dek_ciphertexts(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    operation: &ActiveDekRotation,
) -> Result<(), AppError> {
    let new_dek = load_dek(
        pool,
        crypto,
        &operation.environment_id,
        operation.target_dek_version,
    )
    .await?;
    let current = sqlx::query_as::<_, CurrentCipherRow>(
        "SELECT v.id, e.service_id, v.environment_id, v.version, v.encrypted_value AS ciphertext, v.value_nonce AS nonce \
         FROM variables v JOIN environments e ON e.id = v.environment_id WHERE v.environment_id = ? AND v.dek_version = ?",
    )
    .bind(&operation.environment_id)
    .bind(operation.target_dek_version)
    .fetch_all(pool)
    .await?;
    for row in current {
        crypto
            .decrypt_current_value(
                &new_dek,
                &CurrentValueContext {
                    service_id: &row.service_id,
                    environment_id: &row.environment_id,
                    variable_id: &row.id,
                    version: to_u64(row.version)?,
                    dek_version: to_u64(operation.target_dek_version)?,
                },
                &row.ciphertext,
                &row.nonce,
            )
            .map_err(|_| AppError::Crypto)?;
    }
    let history = sqlx::query_as::<_, HistoryCipherRow>(
        "SELECT vv.id, e.service_id, vv.environment_id, vv.variable_id, vv.version, vv.encrypted_value AS ciphertext, vv.value_nonce AS nonce \
         FROM variable_versions vv JOIN environments e ON e.id = vv.environment_id WHERE vv.environment_id = ? AND vv.dek_version = ?",
    )
    .bind(&operation.environment_id)
    .bind(operation.target_dek_version)
    .fetch_all(pool)
    .await?;
    for row in history {
        crypto
            .decrypt_current_value(
                &new_dek,
                &CurrentValueContext {
                    service_id: &row.service_id,
                    environment_id: &row.environment_id,
                    variable_id: &row.variable_id,
                    version: to_u64(row.version)?,
                    dek_version: to_u64(operation.target_dek_version)?,
                },
                &row.ciphertext,
                &row.nonce,
            )
            .map_err(|_| AppError::Crypto)?;
    }
    let proposals = sqlx::query_as::<_, ProposalCipherRow>(
        "SELECT i.id, r.service_id, r.environment_id, i.change_request_id, i.item_revision, \
                 i.encrypted_proposed_value AS ciphertext, i.proposed_value_nonce AS nonce, \
                 NULL AS legacy_variable_id, NULL AS legacy_variable_version, 0 AS legacy_direct_apply \
         FROM change_request_items i JOIN change_requests r ON r.id = i.change_request_id \
         WHERE r.environment_id = ? AND i.proposed_dek_version = ?",
    )
    .bind(&operation.environment_id)
    .bind(operation.target_dek_version)
    .fetch_all(pool)
    .await?;
    for row in proposals {
        crypto
            .decrypt_proposed_value(
                &new_dek,
                &ProposedValueContext {
                    service_id: &row.service_id,
                    environment_id: &row.environment_id,
                    change_request_id: &row.change_request_id,
                    item_id: &row.id,
                    item_revision: to_u64(row.item_revision)?,
                    dek_version: to_u64(operation.target_dek_version)?,
                },
                &row.ciphertext,
                &row.nonce,
            )
            .map_err(|_| AppError::Crypto)?;
    }
    Ok(())
}

async fn update_cipher_row(
    transaction: &mut Transaction<'_, Sqlite>,
    table: &str,
    id: &str,
    source_version: i64,
    target_version: i64,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<(), AppError> {
    let sql = match table {
        "variables" => {
            "UPDATE variables SET encrypted_value = ?, value_nonce = ?, dek_version = ? WHERE id = ? AND dek_version = ?"
        }
        "variable_versions" => {
            "UPDATE variable_versions SET encrypted_value = ?, value_nonce = ?, dek_version = ? WHERE id = ? AND dek_version = ?"
        }
        _ => return Err(AppError::InvalidRequest),
    };
    let result = sqlx::query(sql)
        .bind(ciphertext)
        .bind(nonce)
        .bind(target_version)
        .bind(id)
        .bind(source_version)
        .execute(&mut **transaction)
        .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AppError::Conflict)
    }
}

async fn checkpoint(
    transaction: &mut Transaction<'_, Sqlite>,
    operation: &ActiveDekRotation,
    count: usize,
) -> Result<(), AppError> {
    let count = i64::try_from(count).map_err(|_| AppError::InvalidRequest)?;
    let result = sqlx::query(
        "UPDATE key_rotation_operations SET processed_records = processed_records + ?, updated_at = ? \
         WHERE id = ? AND status = 'MIGRATING' AND processed_records + ? <= total_records",
    )
    .bind(count)
    .bind(now_rfc3339()?)
    .bind(&operation.id)
    .bind(count)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AppError::Conflict)
    }
}

#[allow(clippy::too_many_arguments)] // Transactional audit completion needs the full immutable operation context.
async fn complete_operation(
    transaction: &mut Transaction<'_, Sqlite>,
    operation_id: &str,
    now: &str,
    total: i64,
    actor_id: &str,
    audit_action: &str,
    environment_id: Option<&str>,
    metadata: serde_json::Value,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE key_rotation_operations SET status = 'COMPLETED', processed_records = ?, updated_at = ?, completed_at = ? WHERE id = ?",
    )
    .bind(total)
    .bind(now)
    .bind(now)
    .bind(operation_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, environment_id, metadata_json) VALUES(?, ?, ?, ?, ?)",
    )
    .bind(now)
    .bind(actor_id)
    .bind(audit_action)
    .bind(environment_id)
    .bind(metadata.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn count_dek_references(
    pool: &SqlitePool,
    environment_id: &str,
    dek_version: i64,
) -> Result<i64, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT \
           (SELECT COUNT(*) FROM variables WHERE environment_id = ? AND dek_version = ?) + \
           (SELECT COUNT(*) FROM variable_versions WHERE environment_id = ? AND dek_version = ?) + \
           (SELECT COUNT(*) FROM change_request_items i JOIN change_requests r ON r.id = i.change_request_id \
             WHERE r.environment_id = ? AND i.proposed_dek_version = ?)",
    )
    .bind(environment_id)
    .bind(dek_version)
    .bind(environment_id)
    .bind(dek_version)
    .bind(environment_id)
    .bind(dek_version)
    .fetch_one(pool)
    .await?)
}

async fn load_dek(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment_id: &str,
    dek_version: i64,
) -> Result<zeroize::Zeroizing<[u8; 32]>, AppError> {
    let row = sqlx::query(
        "SELECT kek_version, wrapped_dek, wrapped_dek_nonce FROM environment_keys \
         WHERE environment_id = ? AND dek_version = ? AND wrapped_dek IS NOT NULL",
    )
    .bind(environment_id)
    .bind(dek_version)
    .fetch_one(pool)
    .await?;
    crypto
        .unwrap_dek(
            environment_id,
            to_u64(dek_version)?,
            to_u64(row.try_get("kek_version")?)?,
            &row.try_get::<Vec<u8>, _>("wrapped_dek")?,
            &row.try_get::<Vec<u8>, _>("wrapped_dek_nonce")?,
        )
        .map_err(|_| AppError::Crypto)
}

async fn revalidate_kek_source(
    transaction: &mut Transaction<'_, Sqlite>,
    source_version: i64,
    fingerprint: &[u8],
) -> Result<(), AppError> {
    let matches: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kek_registry WHERE kek_version = ? AND fingerprint = ? AND status = 'ACTIVE')",
    )
    .bind(source_version)
    .bind(fingerprint)
    .fetch_one(&mut **transaction)
    .await?;
    if matches {
        Ok(())
    } else {
        Err(AppError::Conflict)
    }
}

async fn validate_totp_with_primary(
    pool: &SqlitePool,
    crypto: &CryptoManager,
) -> Result<(), AppError> {
    let rows = sqlx::query_as::<_, TotpRow>(
        "SELECT id, totp_crypto_version AS crypto_version, totp_secret_ciphertext AS ciphertext, \
                totp_secret_nonce AS nonce, totp_kek_version AS kek_version \
         FROM users WHERE totp_secret_ciphertext IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    let active_version: i64 =
        sqlx::query_scalar("SELECT kek_version FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;
    for row in rows {
        if row.kek_version != active_version {
            return Err(AppError::Conflict);
        }
        crypto
            .decrypt_totp_seed_with_primary(
                &row.id,
                to_u64(row.crypto_version)?,
                &row.ciphertext,
                &row.nonce,
            )
            .map_err(|_| AppError::Crypto)?;
    }
    Ok(())
}

async fn validate_environment_keys_with_primary(
    pool: &SqlitePool,
    crypto: &CryptoManager,
) -> Result<(), AppError> {
    let rows = sqlx::query_as::<_, WrappedDekRow>(
        "SELECT environment_id, dek_version, kek_version, wrapped_dek, wrapped_dek_nonce \
         FROM environment_keys WHERE status = 'ACTIVE'",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        crypto
            .unwrap_dek_with_primary(
                &row.environment_id,
                to_u64(row.dek_version)?,
                to_u64(row.kek_version)?,
                &row.wrapped_dek,
                &row.wrapped_dek_nonce,
            )
            .map_err(|_| AppError::Crypto)?;
    }
    Ok(())
}

async fn ensure_primary_kek_active(
    pool: &SqlitePool,
    crypto: &CryptoManager,
) -> Result<(), AppError> {
    let fingerprint: Vec<u8> =
        sqlx::query_scalar("SELECT fingerprint FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;
    if fingerprint == crypto.fingerprint() {
        Ok(())
    } else {
        Err(AppError::Conflict)
    }
}

async fn authorize_environment(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    environment_id: &str,
) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM environments e JOIN services s ON s.id = e.service_id \
         WHERE e.id = ? AND s.organization_id = ?)",
    )
    .bind(environment_id)
    .bind(&session.user.organization_id)
    .fetch_one(pool)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

fn require_administrator(session: &AuthenticatedSession) -> Result<(), AppError> {
    session.require_full()?;
    if session.user.role.allows(Capability::RotateKeys) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn require_recent_administrator(
    sessions: &SessionManager,
    session: &AuthenticatedSession,
) -> Result<(), AppError> {
    require_administrator(session)?;
    if sessions.has_recent_auth(session, PrivilegedAuthLevel::HighImpact) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn validate_reason(reason: &str) -> Result<(), AppError> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
        Err(AppError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn to_u64(value: i64) -> Result<u64, AppError> {
    u64::try_from(value).map_err(|_| AppError::Crypto)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use sqlx::{Row, SqlitePool};
    use time::{Duration, OffsetDateTime};
    use zeroize::Zeroizing;

    use crate::{
        auth::{
            AuthenticatedSession, AuthenticationState, PrivilegedAuthLevel, SessionManager,
            SessionUser,
        },
        config::SessionSettings,
        crypto::{CryptoManager, CurrentValueContext, ProposedValueContext},
        db::{initialize_and_validate_key_registry, test_pool},
        users::Role,
    };

    use super::{
        load_or_prepare_dek_operation, migrate_current_batch, migrate_dek_batches, rotate_dek,
        rotate_kek, verify_and_finalize_dek, write_blocked,
    };

    const NOW: &str = "2026-08-17T00:00:00Z";

    struct Fixture {
        pool: SqlitePool,
        crypto: CryptoManager,
        session: AuthenticatedSession,
        sessions: SessionManager,
        current_ciphertext: Vec<u8>,
    }

    #[allow(clippy::too_many_lines)] // The fixture intentionally seeds every encrypted DEK scope in one place.
    async fn fixture(key: u8) -> Fixture {
        let pool = test_pool().await;
        let crypto = CryptoManager::new(Zeroizing::new([key; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        sqlx::query("INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org', 'Test', ?, ?)")
            .bind(NOW)
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES('admin', 'org', 'admin@example.test', 'admin@example.test', 'hash', 'ADMINISTRATOR', ?, ?, ?)")
            .bind(NOW)
            .bind(NOW)
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO services(id, organization_id, name, name_normalized, created_at, updated_at, created_by, updated_by) VALUES('service', 'org', 'App', 'app', ?, ?, 'admin', 'admin')")
            .bind(NOW)
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO environments(id, service_id, name, name_normalized, created_at, updated_at, created_by, updated_by) VALUES('env', 'service', 'Production', 'production', ?, ?, 'admin', 'admin')")
            .bind(NOW)
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        let dek = crypto.generate_dek().unwrap();
        let wrapped = crypto.wrap_dek("env", 1, 1, &dek).unwrap();
        sqlx::query("INSERT INTO environment_keys(id, environment_id, dek_version, wrapped_dek, wrapped_dek_nonce, crypto_version, kek_version, status, created_at) VALUES('key-1', 'env', 1, ?, ?, 1, 1, 'ACTIVE', ?)")
            .bind(&wrapped.ciphertext)
            .bind(wrapped.nonce.as_slice())
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        let current_context = CurrentValueContext {
            service_id: "service",
            environment_id: "env",
            variable_id: "variable",
            version: 1,
            dek_version: 1,
        };
        let current = crypto
            .encrypt_current_value(&dek, &current_context, b"current-secret")
            .unwrap();
        sqlx::query("INSERT INTO variables(id, environment_id, key, encrypted_value, value_nonce, crypto_version, dek_version, visibility, value_type, version, created_at, created_by, updated_at, updated_by) VALUES('variable', 'env', 'SECRET', ?, ?, 1, 1, 'restricted', 'string', 1, ?, 'admin', ?, 'admin')")
            .bind(&current.ciphertext)
            .bind(current.nonce.as_slice())
            .bind(NOW)
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        let history = crypto
            .encrypt_current_value(&dek, &current_context, b"history-secret")
            .unwrap();
        sqlx::query("INSERT INTO variable_versions(id, variable_id, environment_id, version, operation, encrypted_value, value_nonce, crypto_version, dek_version, visibility, value_type, lifecycle_status, changed_by, changed_at) VALUES('history', 'variable', 'env', 1, 'ADD', ?, ?, 1, 1, 'restricted', 'string', 'ACTIVE', 'admin', ?)")
            .bind(&history.ciphertext)
            .bind(history.nonce.as_slice())
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO change_requests(id, service_id, environment_id, reason, status, requested_by, requested_at) VALUES('request', 'service', 'env', 'test', 'REQUESTED', 'admin', ?)")
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        let proposal_context = ProposedValueContext {
            service_id: "service",
            environment_id: "env",
            change_request_id: "request",
            item_id: "item",
            item_revision: 1,
            dek_version: 1,
        };
        let proposal = crypto
            .encrypt_proposed_value(&dek, &proposal_context, b"proposal-secret")
            .unwrap();
        sqlx::query("INSERT INTO change_request_items(id, change_request_id, variable_id, action, key, base_variable_version, encrypted_proposed_value, proposed_value_nonce, proposed_crypto_version, proposed_dek_version, proposed_visibility, proposed_value_type, value_source, item_revision, created_at) VALUES('item', 'request', 'variable', 'UPDATE', 'SECRET', 1, ?, ?, 1, 1, 'restricted', 'string', 'REQUESTER_PROVIDED', 1, ?)")
            .bind(&proposal.ciphertext)
            .bind(proposal.nonce.as_slice())
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
        let session = admin_session(true);
        let sessions = SessionManager::new(
            pool.clone(),
            crypto.clone(),
            SessionSettings {
                cookie_name: "test".into(),
                secure_cookie: false,
                idle_timeout: Duration::minutes(30),
                absolute_timeout: Duration::hours(12),
                recent_auth_timeout: Duration::minutes(5),
            },
        );
        Fixture {
            pool,
            crypto,
            session,
            sessions,
            current_ciphertext: current.ciphertext,
        }
    }

    fn admin_session(recent: bool) -> AuthenticatedSession {
        AuthenticatedSession {
            id: "session".into(),
            token_hash: vec![1; 32],
            csrf_token_hash: vec![2; 32],
            user: SessionUser {
                id: "admin".into(),
                organization_id: "org".into(),
                email: "admin@example.test".into(),
                role: Role::Administrator,
                auth_version: 1,
                totp_enabled: true,
                must_change_password: false,
            },
            authentication_state: AuthenticationState::Full,
            privileged_authenticated_at: recent.then(OffsetDateTime::now_utc),
            privileged_auth_level: recent.then_some(PrivilegedAuthLevel::HighImpact),
        }
    }

    #[tokio::test]
    async fn kek_rotation_rewraps_deks_and_totp_without_touching_value_ciphertext() {
        let fixture = fixture(41).await;
        let old = fixture.crypto.clone();
        let seed = old
            .encrypt_totp_seed("admin", 1, b"01234567890123456789")
            .unwrap();
        sqlx::query("UPDATE users SET totp_secret_ciphertext = ?, totp_secret_nonce = ?, totp_crypto_version = 1, totp_kek_version = 1, totp_enabled_at = ? WHERE id = 'admin'")
            .bind(&seed.ciphertext)
            .bind(seed.nonce.as_slice())
            .bind(NOW)
            .execute(&fixture.pool)
            .await
            .unwrap();
        let rotating =
            CryptoManager::with_previous(Zeroizing::new([42; 32]), Zeroizing::new([41; 32]));
        let sessions = SessionManager::new(
            fixture.pool.clone(),
            rotating.clone(),
            SessionSettings {
                cookie_name: "test".into(),
                secure_cookie: false,
                idle_timeout: Duration::minutes(30),
                absolute_timeout: Duration::hours(12),
                recent_auth_timeout: Duration::minutes(5),
            },
        );
        let readiness = AtomicBool::new(true);
        rotate_kek(
            &fixture.pool,
            &rotating,
            &sessions,
            &fixture.session,
            &readiness,
            "scheduled rotation",
        )
        .await
        .unwrap();
        assert!(readiness.load(Ordering::Acquire));
        let active_version: i64 =
            sqlx::query_scalar("SELECT kek_version FROM kek_registry WHERE status = 'ACTIVE'")
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        assert_eq!(active_version, 2);
        let current: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_value FROM variables WHERE id = 'variable'")
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        assert_eq!(current, fixture.current_ciphertext);
        let totp = sqlx::query(
            "SELECT totp_secret_ciphertext, totp_secret_nonce FROM users WHERE id = 'admin'",
        )
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        let opened = rotating
            .decrypt_totp_seed(
                "admin",
                1,
                &totp
                    .try_get::<Vec<u8>, _>("totp_secret_ciphertext")
                    .unwrap(),
                &totp.try_get::<Vec<u8>, _>("totp_secret_nonce").unwrap(),
            )
            .unwrap();
        assert_eq!(opened.as_slice(), b"01234567890123456789");
    }

    #[tokio::test]
    async fn kek_prevalidation_failure_has_zero_registry_mutation() {
        let fixture = fixture(43).await;
        let wrong_previous =
            CryptoManager::with_previous(Zeroizing::new([44; 32]), Zeroizing::new([45; 32]));
        let sessions = SessionManager::new(
            fixture.pool.clone(),
            wrong_previous.clone(),
            SessionSettings {
                cookie_name: "test".into(),
                secure_cookie: false,
                idle_timeout: Duration::minutes(30),
                absolute_timeout: Duration::hours(12),
                recent_auth_timeout: Duration::minutes(5),
            },
        );
        assert!(
            rotate_kek(
                &fixture.pool,
                &wrong_previous,
                &sessions,
                &fixture.session,
                &AtomicBool::new(true),
                "test failure",
            )
            .await
            .is_err()
        );
        let versions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kek_registry")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        let operations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM key_rotation_operations")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_eq!((versions, operations), (1, 0));
    }

    #[tokio::test]
    async fn dek_rotation_covers_current_history_and_proposals_then_destroys_old_material() {
        let fixture = fixture(46).await;
        rotate_dek(
            &fixture.pool,
            &fixture.crypto,
            &fixture.sessions,
            &fixture.session,
            &AtomicBool::new(true),
            "env",
            "suspected environment key exposure",
        )
        .await
        .unwrap();
        let versions: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT dek_version FROM variables WHERE id = 'variable'), \
                    (SELECT dek_version FROM variable_versions WHERE id = 'history'), \
                    (SELECT proposed_dek_version FROM change_request_items WHERE id = 'item')",
        )
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(versions, (2, 2, 2));
        let old = sqlx::query("SELECT status, wrapped_dek, wrapped_dek_nonce FROM environment_keys WHERE environment_id = 'env' AND dek_version = 1")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_eq!(old.try_get::<String, _>("status").unwrap(), "RETIRED");
        assert!(
            old.try_get::<Option<Vec<u8>>, _>("wrapped_dek")
                .unwrap()
                .is_none()
        );
        assert!(
            old.try_get::<Option<Vec<u8>>, _>("wrapped_dek_nonce")
                .unwrap()
                .is_none()
        );
        let audit_metadata: String =
            sqlx::query_scalar("SELECT metadata_json FROM audit_logs WHERE action = 'ROTATE_DEK'")
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        assert!(!audit_metadata.contains("secret"));
    }

    #[tokio::test]
    async fn dek_rotation_normalizes_legacy_direct_apply_proposal_aad() {
        let fixture = fixture(52).await;
        sqlx::query("DELETE FROM change_request_items WHERE id = 'item'")
            .execute(&fixture.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM change_requests WHERE id = 'request'")
            .execute(&fixture.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO change_requests(id, service_id, environment_id, title, reason, status, requested_by, requested_at, approved_by, approved_at, applied_by, applied_at) VALUES('legacy-request', 'service', 'env', 'Direct registry apply', 'legacy', 'APPLIED', 'admin', ?, 'admin', ?, 'admin', ?)")
            .bind(NOW)
            .bind(NOW)
            .bind(NOW)
            .execute(&fixture.pool)
            .await
            .unwrap();
        let current: (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT encrypted_value, value_nonce FROM variables WHERE id = 'variable'",
        )
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO change_request_items(id, change_request_id, variable_id, action, key, base_variable_version, encrypted_proposed_value, proposed_value_nonce, proposed_crypto_version, proposed_dek_version, proposed_visibility, proposed_value_type, value_source, value_fulfilled_by, value_fulfilled_at, item_revision, created_at) VALUES('legacy-item', 'legacy-request', 'variable', 'UPDATE', 'SECRET', 1, ?, ?, 1, 1, 'restricted', 'string', 'OPERATOR_PROVIDED', 'admin', ?, 1, ?)")
            .bind(&current.0)
            .bind(&current.1)
            .bind(NOW)
            .bind(NOW)
            .execute(&fixture.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE variable_versions SET change_request_id = 'legacy-request', change_request_item_id = 'legacy-item' WHERE id = 'history'")
            .execute(&fixture.pool)
            .await
            .unwrap();

        rotate_dek(
            &fixture.pool,
            &fixture.crypto,
            &fixture.sessions,
            &fixture.session,
            &AtomicBool::new(true),
            "env",
            "normalize legacy direct apply proposal",
        )
        .await
        .unwrap();
        let proposal: (Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
            "SELECT encrypted_proposed_value, proposed_value_nonce, proposed_dek_version FROM change_request_items WHERE id = 'legacy-item'",
        )
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        let dek = super::load_dek(&fixture.pool, &fixture.crypto, "env", 2)
            .await
            .unwrap();
        let plaintext = fixture
            .crypto
            .decrypt_proposed_value(
                &dek,
                &ProposedValueContext {
                    service_id: "service",
                    environment_id: "env",
                    change_request_id: "legacy-request",
                    item_id: "legacy-item",
                    item_revision: 1,
                    dek_version: 2,
                },
                &proposal.0,
                &proposal.1,
            )
            .unwrap();
        assert_eq!(proposal.2, 2);
        assert_eq!(plaintext.as_slice(), b"current-secret");
    }

    #[tokio::test]
    async fn interrupted_dek_batch_resumes_from_persisted_versions() {
        let fixture = fixture(47).await;
        let operation = load_or_prepare_dek_operation(
            &fixture.pool,
            &fixture.crypto,
            &fixture.session,
            "env",
            4,
        )
        .await
        .unwrap();
        let old = super::load_dek(&fixture.pool, &fixture.crypto, "env", 1)
            .await
            .unwrap();
        let new = super::load_dek(&fixture.pool, &fixture.crypto, "env", 2)
            .await
            .unwrap();
        assert_eq!(
            migrate_current_batch(&fixture.pool, &fixture.crypto, &operation, &old, &new)
                .await
                .unwrap(),
            1
        );
        assert!(write_blocked(&fixture.pool, &fixture.crypto).await.unwrap());
        rotate_dek(
            &fixture.pool,
            &fixture.crypto,
            &fixture.sessions,
            &fixture.session,
            &AtomicBool::new(true),
            "env",
            "resume after interruption",
        )
        .await
        .unwrap();
        let status: String =
            sqlx::query_scalar("SELECT status FROM key_rotation_operations WHERE id = ?")
                .bind(&operation.id)
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        assert_eq!(status, "COMPLETED");
        assert!(!write_blocked(&fixture.pool, &fixture.crypto).await.unwrap());
    }

    #[tokio::test]
    async fn failed_dek_stage_is_recorded_without_discarding_resume_state() {
        let fixture = fixture(51).await;
        let operation = load_or_prepare_dek_operation(
            &fixture.pool,
            &fixture.crypto,
            &fixture.session,
            "env",
            4,
        )
        .await
        .unwrap();
        let old = super::load_dek(&fixture.pool, &fixture.crypto, "env", 1)
            .await
            .unwrap();
        let new = super::load_dek(&fixture.pool, &fixture.crypto, "env", 2)
            .await
            .unwrap();
        migrate_current_batch(&fixture.pool, &fixture.crypto, &operation, &old, &new)
            .await
            .unwrap();
        let mut ciphertext: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_value FROM variable_versions WHERE id = 'history'",
        )
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        ciphertext[0] ^= 1;
        sqlx::query("UPDATE variable_versions SET encrypted_value = ? WHERE id = 'history'")
            .bind(ciphertext)
            .execute(&fixture.pool)
            .await
            .unwrap();

        assert!(
            migrate_dek_batches(&fixture.pool, &fixture.crypto, &operation)
                .await
                .is_err()
        );
        let state: (String, i64, Option<String>) = sqlx::query_as(
            "SELECT status, processed_records, failure_code FROM key_rotation_operations WHERE id = ?",
        )
        .bind(&operation.id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(state.0, "MIGRATING");
        assert_eq!(state.1, 1);
        assert_eq!(state.2.as_deref(), Some("DEK_HISTORY_MIGRATION"));
    }

    #[tokio::test]
    async fn prepared_dek_operation_resumes_after_restart_boundary() {
        let fixture = fixture(49).await;
        let operation = load_or_prepare_dek_operation(
            &fixture.pool,
            &fixture.crypto,
            &fixture.session,
            "env",
            4,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM key_rotation_operations WHERE id = ?",
            )
            .bind(&operation.id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap(),
            "MIGRATING"
        );
        rotate_dek(
            &fixture.pool,
            &fixture.crypto,
            &fixture.sessions,
            &fixture.session,
            &AtomicBool::new(true),
            "env",
            "resume prepared operation",
        )
        .await
        .unwrap();
        let completed: String =
            sqlx::query_scalar("SELECT status FROM key_rotation_operations WHERE id = ?")
                .bind(&operation.id)
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        assert_eq!(completed, "COMPLETED");
    }

    #[tokio::test]
    async fn verification_failure_keeps_old_dek_material_and_pending_key() {
        let fixture = fixture(50).await;
        let operation = load_or_prepare_dek_operation(
            &fixture.pool,
            &fixture.crypto,
            &fixture.session,
            "env",
            4,
        )
        .await
        .unwrap();
        migrate_dek_batches(&fixture.pool, &fixture.crypto, &operation)
            .await
            .unwrap();
        let mut ciphertext: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_value FROM variables WHERE id = 'variable'")
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        ciphertext[0] ^= 1;
        sqlx::query("UPDATE variables SET encrypted_value = ? WHERE id = 'variable'")
            .bind(ciphertext)
            .execute(&fixture.pool)
            .await
            .unwrap();
        assert!(
            verify_and_finalize_dek(
                &fixture.pool,
                &fixture.crypto,
                &fixture.session,
                &AtomicBool::new(true),
                &operation,
                4,
            )
            .await
            .is_err()
        );
        let old = sqlx::query("SELECT status, wrapped_dek FROM environment_keys WHERE environment_id = 'env' AND dek_version = 1")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_eq!(old.try_get::<String, _>("status").unwrap(), "ACTIVE");
        assert!(
            old.try_get::<Option<Vec<u8>>, _>("wrapped_dek")
                .unwrap()
                .is_some()
        );
        let pending: String = sqlx::query_scalar(
            "SELECT status FROM environment_keys WHERE environment_id = 'env' AND dek_version = 2",
        )
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(pending, "PENDING");
    }

    #[tokio::test]
    async fn rotation_requires_high_impact_recent_auth() {
        let fixture = fixture(48).await;
        let stale = admin_session(false);
        assert!(
            rotate_dek(
                &fixture.pool,
                &fixture.crypto,
                &fixture.sessions,
                &stale,
                &AtomicBool::new(true),
                "env",
                "must fail",
            )
            .await
            .is_err()
        );
        let operations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM key_rotation_operations")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_eq!(operations, 0);
    }
}
