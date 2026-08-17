use http::Uri;
use serde::Serialize;
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    auth::{AuthenticatedSession, PrivilegedAuthLevel},
    crypto::{CryptoManager, CurrentValueContext, EncryptedBlob, ProposedValueContext},
    db::now_rfc3339,
    environments,
    error::AppError,
    services::validate_description,
    users::{Capability, can_access_service},
};

const MAX_VALUE_BYTES: usize = 32 * 1024;
const MAX_REASON_CHARS: usize = 1_000;

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct EnvironmentContext {
    pub id: String,
    pub name: String,
    pub service_id: String,
    pub service_name: String,
    pub archived_at: Option<String>,
    pub service_archived_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VariableView {
    pub id: String,
    pub key: String,
    pub value: Option<String>,
    pub visibility: String,
    pub value_type: String,
    pub description: Option<String>,
    pub version: i64,
    pub deployment_status: String,
    pub updated_at: String,
    #[serde(skip_serializing)]
    pub updated_display: String,
    pub updated_by: String,
    pub last_applied_at: Option<String>,
}

#[derive(Clone, Debug, FromRow)]
struct VariableRow {
    id: String,
    key: String,
    encrypted_value: Vec<u8>,
    value_nonce: Vec<u8>,
    dek_version: i64,
    visibility: String,
    value_type: String,
    description: Option<String>,
    version: i64,
    deployment_status: String,
    updated_at: String,
    updated_by: String,
    last_applied_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AppliedVariableInput {
    pub key: String,
    pub value: String,
    pub visibility: String,
    pub value_type: String,
    pub description: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct VariableFilter {
    pub query: String,
    pub visibility: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryView {
    pub id: String,
    pub version: i64,
    pub operation: String,
    pub value: Option<String>,
    pub visibility: String,
    pub value_type: String,
    pub description: Option<String>,
    pub lifecycle_status: String,
    pub changed_at: String,
    pub changed_by: String,
}

#[derive(Clone, Debug, FromRow)]
struct HistoryRow {
    id: String,
    variable_id: String,
    environment_id: String,
    service_id: String,
    version: i64,
    operation: String,
    encrypted_value: Vec<u8>,
    value_nonce: Vec<u8>,
    dek_version: i64,
    visibility: String,
    value_type: String,
    description: Option<String>,
    lifecycle_status: String,
    changed_at: String,
    changed_by: String,
}

pub async fn list_for_environment(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    environment_id: &str,
) -> Result<(EnvironmentContext, Vec<VariableView>), AppError> {
    list_for_environment_filtered(
        pool,
        crypto,
        session,
        environment_id,
        &VariableFilter::default(),
    )
    .await
}

pub async fn list_for_environment_filtered(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    environment_id: &str,
    filter: &VariableFilter,
) -> Result<(EnvironmentContext, Vec<VariableView>), AppError> {
    session.require_full()?;
    let environment = environment_context(pool, session, environment_id).await?;
    let query = filter.query.trim();
    if query.len() > 255 {
        return Err(AppError::InvalidRequest);
    }
    let visibility = filter.visibility.trim();
    if !visibility.is_empty() {
        validate_visibility(visibility)?;
    }
    let rows = sqlx::query_as::<_, VariableRow>(
        "SELECT v.id, v.key, v.encrypted_value, v.value_nonce, v.dek_version, v.visibility, \
                v.value_type, v.description, v.version, v.deployment_status, v.updated_at, \
                updater.email AS updated_by, v.last_applied_at \
         FROM variables v JOIN users updater ON updater.id = v.updated_by \
         WHERE v.environment_id = ? AND v.lifecycle_status = 'ACTIVE' \
           AND (? = '' OR instr(lower(v.key), lower(?)) > 0) \
           AND (? = '' OR v.visibility = ?) ORDER BY v.key",
    )
    .bind(environment_id)
    .bind(query)
    .bind(query)
    .bind(visibility)
    .bind(visibility)
    .fetch_all(pool)
    .await?;

    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let value = if row.visibility == "public" {
            Some(decrypt_row_value(pool, crypto, &environment, &row).await?)
        } else {
            None
        };
        let updated_display = display_timestamp(&row.updated_at);
        result.push(VariableView {
            id: row.id,
            key: row.key,
            value,
            visibility: row.visibility,
            value_type: row.value_type,
            description: row.description,
            version: row.version,
            deployment_status: row.deployment_status,
            updated_at: row.updated_at,
            updated_display,
            updated_by: row.updated_by,
            last_applied_at: row.last_applied_at,
        });
    }
    Ok((environment, result))
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

pub async fn record_applied(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    environment_id: &str,
    input: AppliedVariableInput,
) -> Result<String, AppError> {
    let write = prepare_applied(pool, crypto, session, environment_id, input).await?;
    persist_applied(pool, session, &write).await?;
    Ok(write.variable_id)
}

async fn prepare_applied(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    environment_id: &str,
    input: AppliedVariableInput,
) -> Result<AppliedWrite, AppError> {
    require_direct_apply(session)?;
    let environment = environment_context(pool, session, environment_id).await?;
    ensure_mutable(&environment)?;
    let key = validate_key(&input.key)?;
    let visibility = validate_visibility(&input.visibility)?;
    let value_type = validate_value_type(&input.value_type)?;
    validate_value(&input.value, value_type)?;
    let description = validate_description(input.description)?;
    let reason = validate_reason(&input.reason)?;

    let existing = sqlx::query_as::<_, ExistingVariable>(
        "SELECT id, version, lifecycle_status FROM variables WHERE environment_id = ? AND key = ?",
    )
    .bind(environment_id)
    .bind(&key)
    .fetch_optional(pool)
    .await?;
    let (variable_id, version, action, base_version, expected_version, mutation) = match existing {
        Some(existing) if existing.lifecycle_status == "ACTIVE" => (
            existing.id,
            existing.version + 1,
            "UPDATE",
            Some(existing.version),
            Some(existing.version),
            CurrentMutation::Update,
        ),
        Some(existing) => (
            existing.id,
            existing.version + 1,
            "ADD",
            None,
            Some(existing.version),
            CurrentMutation::Revive,
        ),
        None => (
            Uuid::new_v4().to_string(),
            1,
            "ADD",
            None,
            None,
            CurrentMutation::Insert,
        ),
    };
    let version_u64 = u64::try_from(version).map_err(|_| AppError::Crypto)?;
    let (dek_version, dek) = environments::active_dek(pool, crypto, environment_id).await?;
    let request_id = Uuid::new_v4().to_string();
    let item_id = Uuid::new_v4().to_string();
    let encrypted = crypto
        .encrypt_current_value(
            &dek,
            &CurrentValueContext {
                service_id: &environment.service_id,
                environment_id,
                variable_id: &variable_id,
                version: version_u64,
                dek_version,
            },
            input.value.as_bytes(),
        )
        .map_err(|_| AppError::Crypto)?;
    let proposed_encrypted = crypto
        .encrypt_proposed_value(
            &dek,
            &ProposedValueContext {
                service_id: &environment.service_id,
                environment_id,
                change_request_id: &request_id,
                item_id: &item_id,
                item_revision: 1,
                dek_version,
            },
            input.value.as_bytes(),
        )
        .map_err(|_| AppError::Crypto)?;

    let write = AppliedWrite {
        environment,
        request_id,
        item_id,
        variable_id,
        version,
        action,
        base_version,
        expected_version,
        mutation,
        key,
        visibility: visibility.to_owned(),
        value_type: value_type.to_owned(),
        description,
        reason,
        dek_version: i64::try_from(dek_version).map_err(|_| AppError::Crypto)?,
        encrypted,
        proposed_encrypted: Some(proposed_encrypted),
    };
    Ok(write)
}

pub async fn import_applied(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    environment_id: &str,
    inputs: Vec<AppliedVariableInput>,
) -> Result<usize, AppError> {
    require_direct_apply(session)?;
    if inputs.is_empty() || inputs.len() > crate::dotenv::MAX_ENTRIES {
        return Err(AppError::InvalidRequest);
    }
    let mut writes = Vec::with_capacity(inputs.len());
    for input in inputs {
        writes.push(prepare_applied(pool, crypto, session, environment_id, input).await?);
    }
    let now = now_rfc3339().map_err(AppError::Internal)?;
    let mut transaction = pool.begin().await?;
    for write in &writes {
        persist_applied_in_transaction(&mut transaction, session, write, &now).await?;
    }
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id, environment_id, metadata_json) \
         VALUES(?, ?, 'IMPORT_ENV', ?, ?, ?)",
    )
    .bind(&now)
    .bind(&session.user.id)
    .bind(&writes[0].environment.service_id)
    .bind(environment_id)
    .bind(format!("{{\"variable_count\":{}}}", writes.len()))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(writes.len())
}

pub async fn delete_applied(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    variable_id: &str,
    reason: &str,
) -> Result<String, AppError> {
    require_direct_apply(session)?;
    let reason = validate_reason(reason)?;
    let row = sqlx::query_as::<_, DeleteVariableRow>(
        "SELECT v.id, v.environment_id, v.key, v.encrypted_value, v.value_nonce, v.dek_version, \
                v.visibility, v.value_type, v.description, v.version \
         FROM variables v WHERE v.id = ? AND v.lifecycle_status = 'ACTIVE'",
    )
    .bind(variable_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    let environment = environment_context(pool, session, &row.environment_id).await?;
    ensure_mutable(&environment)?;

    let old_dek_version = u64::try_from(row.dek_version).map_err(|_| AppError::Crypto)?;
    let old_dek =
        environments::dek_by_version(pool, crypto, &row.environment_id, old_dek_version).await?;
    let plaintext = crypto
        .decrypt_current_value(
            &old_dek,
            &CurrentValueContext {
                service_id: &environment.service_id,
                environment_id: &row.environment_id,
                variable_id: &row.id,
                version: u64::try_from(row.version).map_err(|_| AppError::Crypto)?,
                dek_version: old_dek_version,
            },
            &row.encrypted_value,
            &row.value_nonce,
        )
        .map_err(|_| AppError::Crypto)?;
    let version = row.version + 1;
    let (dek_version, dek) = environments::active_dek(pool, crypto, &row.environment_id).await?;
    let request_id = Uuid::new_v4().to_string();
    let item_id = Uuid::new_v4().to_string();
    let encrypted = crypto
        .encrypt_current_value(
            &dek,
            &CurrentValueContext {
                service_id: &environment.service_id,
                environment_id: &row.environment_id,
                variable_id: &row.id,
                version: u64::try_from(version).map_err(|_| AppError::Crypto)?,
                dek_version,
            },
            &plaintext,
        )
        .map_err(|_| AppError::Crypto)?;
    let write = AppliedWrite {
        environment,
        request_id,
        item_id,
        variable_id: row.id,
        version,
        action: "DELETE",
        base_version: Some(row.version),
        expected_version: Some(row.version),
        mutation: CurrentMutation::Delete,
        key: row.key,
        visibility: row.visibility,
        value_type: row.value_type,
        description: row.description,
        reason,
        dek_version: i64::try_from(dek_version).map_err(|_| AppError::Crypto)?,
        encrypted,
        proposed_encrypted: None,
    };
    persist_applied(pool, session, &write).await?;
    Ok(write.environment.id.clone())
}

#[derive(Clone, Copy)]
enum CurrentMutation {
    Insert,
    Update,
    Revive,
    Delete,
}

struct AppliedWrite {
    environment: EnvironmentContext,
    request_id: String,
    item_id: String,
    variable_id: String,
    version: i64,
    action: &'static str,
    base_version: Option<i64>,
    expected_version: Option<i64>,
    mutation: CurrentMutation,
    key: String,
    visibility: String,
    value_type: String,
    description: Option<String>,
    reason: String,
    dek_version: i64,
    encrypted: EncryptedBlob,
    proposed_encrypted: Option<EncryptedBlob>,
}

async fn persist_applied(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    write: &AppliedWrite,
) -> Result<(), AppError> {
    let now = now_rfc3339().map_err(AppError::Internal)?;
    let mut transaction = pool.begin().await?;
    persist_applied_in_transaction(&mut transaction, session, write, &now).await?;
    transaction.commit().await?;
    Ok(())
}

async fn persist_applied_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    write: &AppliedWrite,
    now: &str,
) -> Result<(), AppError> {
    insert_direct_change(transaction, session, write, now).await?;
    mutate_current(transaction, session, write, now).await?;
    insert_version_and_audit(transaction, session, write, now).await?;
    Ok(())
}

async fn insert_direct_change(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    write: &AppliedWrite,
    now: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO change_requests(\
            id, service_id, environment_id, title, reason, status, requested_by, requested_at, \
            approved_by, approved_at, applied_by, applied_at\
         ) VALUES(?, ?, ?, 'Direct registry apply', ?, 'APPLIED', ?, ?, ?, ?, ?, ?)",
    )
    .bind(&write.request_id)
    .bind(&write.environment.service_id)
    .bind(&write.environment.id)
    .bind(&write.reason)
    .bind(&session.user.id)
    .bind(now)
    .bind(&session.user.id)
    .bind(now)
    .bind(&session.user.id)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    if write.action == "DELETE" {
        sqlx::query(
            "INSERT INTO change_request_items(\
                id, change_request_id, variable_id, action, key, base_variable_version, \
                proposed_visibility, proposed_value_type, proposed_description, created_at\
             ) VALUES(?, ?, ?, 'DELETE', ?, ?, ?, ?, ?, ?)",
        )
        .bind(&write.item_id)
        .bind(&write.request_id)
        .bind(&write.variable_id)
        .bind(&write.key)
        .bind(write.base_version)
        .bind(&write.visibility)
        .bind(&write.value_type)
        .bind(&write.description)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    } else {
        let proposed = write.proposed_encrypted.as_ref().ok_or(AppError::Crypto)?;
        sqlx::query(
            "INSERT INTO change_request_items(\
                id, change_request_id, variable_id, action, key, base_variable_version, \
                encrypted_proposed_value, proposed_value_nonce, proposed_crypto_version, proposed_dek_version, \
                proposed_visibility, proposed_value_type, proposed_description, value_source, \
                value_fulfilled_by, value_fulfilled_at, created_at\
             ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'OPERATOR_PROVIDED', ?, ?, ?)",
        )
        .bind(&write.item_id)
        .bind(&write.request_id)
        .bind((write.action == "UPDATE").then_some(write.variable_id.as_str()))
        .bind(write.action)
        .bind(&write.key)
        .bind(write.base_version)
        .bind(&proposed.ciphertext)
        .bind(proposed.nonce.as_slice())
        .bind(write.dek_version)
        .bind(&write.visibility)
        .bind(&write.value_type)
        .bind(&write.description)
        .bind(&session.user.id)
        .bind(now)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn mutate_current(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    write: &AppliedWrite,
    now: &str,
) -> Result<(), AppError> {
    if matches!(write.mutation, CurrentMutation::Insert) {
        sqlx::query(
            "INSERT INTO variables(\
                id, environment_id, key, encrypted_value, value_nonce, crypto_version, dek_version, \
                visibility, value_type, description, version, lifecycle_status, deployment_status, \
                created_at, created_by, updated_at, updated_by, last_applied_at, last_applied_by\
             ) VALUES(?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 'ACTIVE', 'APPLIED', ?, ?, ?, ?, ?, ?)",
        )
        .bind(&write.variable_id)
        .bind(&write.environment.id)
        .bind(&write.key)
        .bind(&write.encrypted.ciphertext)
        .bind(write.encrypted.nonce.as_slice())
        .bind(write.dek_version)
        .bind(&write.visibility)
        .bind(&write.value_type)
        .bind(&write.description)
        .bind(write.version)
        .bind(now)
        .bind(&session.user.id)
        .bind(now)
        .bind(&session.user.id)
        .bind(now)
        .bind(&session.user.id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let (lifecycle_status, deleted_at, expected_lifecycle) = match write.mutation {
        CurrentMutation::Update => ("ACTIVE", None, "ACTIVE"),
        CurrentMutation::Revive => ("ACTIVE", None, "DELETED"),
        CurrentMutation::Delete => ("DELETED", Some(now), "ACTIVE"),
        CurrentMutation::Insert => unreachable!(),
    };
    let result = sqlx::query(
        "UPDATE variables SET encrypted_value = ?, value_nonce = ?, crypto_version = 1, \
                dek_version = ?, visibility = ?, value_type = ?, description = ?, version = ?, \
                lifecycle_status = ?, deleted_at = ?, deployment_status = 'APPLIED', \
                updated_at = ?, updated_by = ?, last_applied_at = ?, last_applied_by = ? \
         WHERE id = ? AND environment_id = ? AND version = ? AND lifecycle_status = ?",
    )
    .bind(&write.encrypted.ciphertext)
    .bind(write.encrypted.nonce.as_slice())
    .bind(write.dek_version)
    .bind(&write.visibility)
    .bind(&write.value_type)
    .bind(&write.description)
    .bind(write.version)
    .bind(lifecycle_status)
    .bind(deleted_at)
    .bind(now)
    .bind(&session.user.id)
    .bind(now)
    .bind(&session.user.id)
    .bind(&write.variable_id)
    .bind(&write.environment.id)
    .bind(write.expected_version)
    .bind(expected_lifecycle)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AppError::Conflict)
    }
}

async fn insert_version_and_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    write: &AppliedWrite,
    now: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO variable_versions(\
            id, variable_id, environment_id, version, operation, encrypted_value, value_nonce, \
            crypto_version, dek_version, visibility, value_type, description, lifecycle_status, \
            changed_by, changed_at, change_request_id, change_request_item_id\
         ) VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&write.variable_id)
    .bind(&write.environment.id)
    .bind(write.version)
    .bind(write.action)
    .bind(&write.encrypted.ciphertext)
    .bind(write.encrypted.nonce.as_slice())
    .bind(write.dek_version)
    .bind(&write.visibility)
    .bind(&write.value_type)
    .bind(&write.description)
    .bind(if write.action == "DELETE" {
        "DELETED"
    } else {
        "ACTIVE"
    })
    .bind(&session.user.id)
    .bind(now)
    .bind(&write.request_id)
    .bind(&write.item_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO audit_logs(\
            occurred_at, actor_user_id, action, service_id, environment_id, variable_id, variable_key, change_request_id\
         ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(now)
    .bind(&session.user.id)
    .bind(if write.action == "DELETE" {
        "DELETE_VARIABLE"
    } else {
        "DIRECT_APPLY_VARIABLE"
    })
    .bind(&write.environment.service_id)
    .bind(&write.environment.id)
    .bind(&write.variable_id)
    .bind(&write.key)
    .bind(&write.request_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub async fn reveal_current(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session_manager: &crate::auth::SessionManager,
    session: &AuthenticatedSession,
    variable_id: &str,
) -> Result<(String, Zeroizing<String>), AppError> {
    session.require_full()?;
    let row = sqlx::query_as::<_, RevealRow>(
        "SELECT v.id, v.key, v.encrypted_value, v.value_nonce, v.dek_version, v.version, v.visibility, \
                e.id AS environment_id, s.id AS service_id, s.organization_id \
         FROM variables v JOIN environments e ON e.id = v.environment_id \
         JOIN services s ON s.id = e.service_id \
         WHERE v.id = ? AND v.lifecycle_status = 'ACTIVE'",
    )
    .bind(variable_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    authorize_value_read(pool, session_manager, session, &row).await?;
    let dek = environments::dek_by_version(
        pool,
        crypto,
        &row.environment_id,
        u64::try_from(row.dek_version).map_err(|_| AppError::Crypto)?,
    )
    .await?;
    let plaintext = crypto
        .decrypt_current_value(
            &dek,
            &CurrentValueContext {
                service_id: &row.service_id,
                environment_id: &row.environment_id,
                variable_id: &row.id,
                version: u64::try_from(row.version).map_err(|_| AppError::Crypto)?,
                dek_version: u64::try_from(row.dek_version).map_err(|_| AppError::Crypto)?,
            },
            &row.encrypted_value,
            &row.value_nonce,
        )
        .map_err(|_| AppError::Crypto)?;
    let value = String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Crypto)?;
    if row.visibility == "restricted" {
        sqlx::query(
            "INSERT INTO audit_logs(\
                occurred_at, actor_user_id, action, service_id, environment_id, variable_id, variable_key\
             ) VALUES(?, ?, 'VIEW_SECRET', ?, ?, ?, ?)",
        )
        .bind(now_rfc3339().map_err(AppError::Internal)?)
        .bind(&session.user.id)
        .bind(&row.service_id)
        .bind(&row.environment_id)
        .bind(&row.id)
        .bind(&row.key)
        .execute(pool)
        .await?;
    }
    Ok((row.key, Zeroizing::new(value)))
}

pub async fn history(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    variable_id: &str,
) -> Result<(String, Vec<HistoryView>), AppError> {
    session.require_full()?;
    let current = sqlx::query_as::<_, RevealRow>(
        "SELECT v.id, v.key, v.encrypted_value, v.value_nonce, v.dek_version, v.version, v.visibility, \
                e.id AS environment_id, s.id AS service_id, s.organization_id \
         FROM variables v JOIN environments e ON e.id = v.environment_id \
         JOIN services s ON s.id = e.service_id WHERE v.id = ?",
    )
    .bind(variable_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    if current.organization_id != session.user.organization_id
        || !can_access_service(
            pool,
            &session.user.id,
            session.user.role,
            &current.service_id,
        )
        .await?
    {
        return Err(AppError::NotFound);
    }
    let rows = sqlx::query_as::<_, HistoryRow>(
        "SELECT vv.id, vv.variable_id, vv.environment_id, e.service_id, vv.version, vv.operation, \
                vv.encrypted_value, vv.value_nonce, vv.dek_version, vv.visibility, vv.value_type, \
                vv.description, vv.lifecycle_status, vv.changed_at, u.email AS changed_by \
         FROM variable_versions vv JOIN environments e ON e.id = vv.environment_id \
         JOIN users u ON u.id = vv.changed_by WHERE vv.variable_id = ? ORDER BY vv.version DESC",
    )
    .bind(variable_id)
    .fetch_all(pool)
    .await?;
    let mut history = Vec::with_capacity(rows.len());
    for row in rows {
        let value = if row.visibility == "public" {
            Some(decrypt_history_row(pool, crypto, &row).await?)
        } else {
            None
        };
        history.push(HistoryView {
            id: row.id,
            version: row.version,
            operation: row.operation,
            value,
            visibility: row.visibility,
            value_type: row.value_type,
            description: row.description,
            lifecycle_status: row.lifecycle_status,
            changed_at: row.changed_at,
            changed_by: row.changed_by,
        });
    }
    Ok((current.key, history))
}

pub async fn reveal_version(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session_manager: &crate::auth::SessionManager,
    session: &AuthenticatedSession,
    version_id: &str,
) -> Result<(String, i64, Zeroizing<String>), AppError> {
    session.require_full()?;
    let row = sqlx::query_as::<_, HistoryRevealRow>(
        "SELECT vv.id, vv.variable_id, v.key, vv.environment_id, e.service_id, s.organization_id, \
                vv.version, vv.encrypted_value, vv.value_nonce, vv.dek_version, vv.visibility \
         FROM variable_versions vv JOIN variables v ON v.id = vv.variable_id \
         JOIN environments e ON e.id = vv.environment_id JOIN services s ON s.id = e.service_id \
         WHERE vv.id = ?",
    )
    .bind(version_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    let authorization_row = RevealRow {
        id: row.variable_id.clone(),
        key: row.key.clone(),
        encrypted_value: row.encrypted_value.clone(),
        value_nonce: row.value_nonce.clone(),
        dek_version: row.dek_version,
        version: row.version,
        visibility: row.visibility.clone(),
        environment_id: row.environment_id.clone(),
        service_id: row.service_id.clone(),
        organization_id: row.organization_id,
    };
    authorize_value_read(pool, session_manager, session, &authorization_row).await?;
    let history_row = HistoryRow {
        id: row.id,
        variable_id: row.variable_id,
        environment_id: row.environment_id,
        service_id: row.service_id,
        version: row.version,
        operation: String::new(),
        encrypted_value: row.encrypted_value,
        value_nonce: row.value_nonce,
        dek_version: row.dek_version,
        visibility: row.visibility.clone(),
        value_type: String::new(),
        description: None,
        lifecycle_status: String::new(),
        changed_at: String::new(),
        changed_by: String::new(),
    };
    let plaintext = decrypt_history_row(pool, crypto, &history_row).await?;
    if row.visibility == "restricted" {
        sqlx::query(
            "INSERT INTO audit_logs(\
                occurred_at, actor_user_id, action, service_id, environment_id, variable_id, variable_key, metadata_json\
             ) VALUES(?, ?, 'VIEW_PREVIOUS_SECRET', ?, ?, ?, ?, ?)",
        )
        .bind(now_rfc3339().map_err(AppError::Internal)?)
        .bind(&session.user.id)
        .bind(&history_row.service_id)
        .bind(&history_row.environment_id)
        .bind(&history_row.variable_id)
        .bind(&row.key)
        .bind(format!("{{\"version\":{}}}", row.version))
        .execute(pool)
        .await?;
    }
    Ok((row.key, row.version, Zeroizing::new(plaintext)))
}

pub async fn export_environment(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session_manager: &crate::auth::SessionManager,
    session: &AuthenticatedSession,
    environment_id: &str,
) -> Result<(EnvironmentContext, Zeroizing<String>), AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ExportEnvironment)
        || !session_manager.has_recent_auth(session, PrivilegedAuthLevel::Standard)
    {
        return Err(AppError::Forbidden);
    }
    let environment = environment_context(pool, session, environment_id).await?;
    let rows = sqlx::query_as::<_, VariableRow>(
        "SELECT v.id, v.key, v.encrypted_value, v.value_nonce, v.dek_version, v.visibility, \
                v.value_type, v.description, v.version, v.deployment_status, v.updated_at, \
                updater.email AS updated_by, v.last_applied_at \
         FROM variables v JOIN users updater ON updater.id = v.updated_by \
         WHERE v.environment_id = ? AND v.lifecycle_status = 'ACTIVE' ORDER BY v.key",
    )
    .bind(environment_id)
    .fetch_all(pool)
    .await?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        entries.push(crate::dotenv::Entry {
            key: row.key.clone(),
            value: decrypt_row_value(pool, crypto, &environment, &row).await?,
        });
    }
    let rendered = Zeroizing::new(crate::dotenv::render(&entries));
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id, environment_id, metadata_json) \
         VALUES(?, ?, 'EXPORT_ENV', ?, ?, ?)",
    )
    .bind(now_rfc3339().map_err(AppError::Internal)?)
    .bind(&session.user.id)
    .bind(&environment.service_id)
    .bind(environment_id)
    .bind(format!("{{\"variable_count\":{}}}", entries.len()))
    .execute(pool)
    .await?;
    Ok((environment, rendered))
}

pub async fn copy_current(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session_manager: &crate::auth::SessionManager,
    session: &AuthenticatedSession,
    variable_id: &str,
) -> Result<Zeroizing<String>, AppError> {
    let (key, value) = reveal_current(pool, crypto, session_manager, session, variable_id).await?;
    let rendered = crate::dotenv::render(&[crate::dotenv::Entry {
        key,
        value: value.to_string(),
    }]);
    let row = sqlx::query_as::<_, CopyAuditRow>(
        "SELECT v.key, v.visibility, e.id AS environment_id, e.service_id \
         FROM variables v JOIN environments e ON e.id = v.environment_id WHERE v.id = ?",
    )
    .bind(variable_id)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id, environment_id, variable_id, variable_key) \
         VALUES(?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(now_rfc3339().map_err(AppError::Internal)?)
    .bind(&session.user.id)
    .bind(if row.visibility == "restricted" {
        "COPY_SECRET"
    } else {
        "COPY_VARIABLE"
    })
    .bind(&row.service_id)
    .bind(&row.environment_id)
    .bind(variable_id)
    .bind(&row.key)
    .execute(pool)
    .await?;
    Ok(Zeroizing::new(rendered))
}

#[derive(FromRow)]
struct ExistingVariable {
    id: String,
    version: i64,
    lifecycle_status: String,
}

#[derive(FromRow)]
struct DeleteVariableRow {
    id: String,
    environment_id: String,
    key: String,
    encrypted_value: Vec<u8>,
    value_nonce: Vec<u8>,
    dek_version: i64,
    visibility: String,
    value_type: String,
    description: Option<String>,
    version: i64,
}

#[derive(FromRow)]
struct RevealRow {
    id: String,
    key: String,
    encrypted_value: Vec<u8>,
    value_nonce: Vec<u8>,
    dek_version: i64,
    version: i64,
    visibility: String,
    environment_id: String,
    service_id: String,
    organization_id: String,
}

#[derive(FromRow)]
struct HistoryRevealRow {
    id: String,
    variable_id: String,
    key: String,
    environment_id: String,
    service_id: String,
    organization_id: String,
    version: i64,
    encrypted_value: Vec<u8>,
    value_nonce: Vec<u8>,
    dek_version: i64,
    visibility: String,
}

#[derive(FromRow)]
struct CopyAuditRow {
    key: String,
    visibility: String,
    environment_id: String,
    service_id: String,
}

async fn authorize_value_read(
    pool: &SqlitePool,
    session_manager: &crate::auth::SessionManager,
    session: &AuthenticatedSession,
    row: &RevealRow,
) -> Result<(), AppError> {
    if row.organization_id != session.user.organization_id
        || !can_access_service(pool, &session.user.id, session.user.role, &row.service_id).await?
    {
        return Err(AppError::NotFound);
    }
    if row.visibility == "restricted"
        && (!session.user.role.allows(Capability::ReadRestrictedValue)
            || !session_manager.has_recent_auth(session, PrivilegedAuthLevel::Standard))
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

async fn decrypt_row_value(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment: &EnvironmentContext,
    row: &VariableRow,
) -> Result<String, AppError> {
    let dek_version = u64::try_from(row.dek_version).map_err(|_| AppError::Crypto)?;
    let dek = environments::dek_by_version(pool, crypto, &environment.id, dek_version).await?;
    let plaintext = crypto
        .decrypt_current_value(
            &dek,
            &CurrentValueContext {
                service_id: &environment.service_id,
                environment_id: &environment.id,
                variable_id: &row.id,
                version: u64::try_from(row.version).map_err(|_| AppError::Crypto)?,
                dek_version,
            },
            &row.encrypted_value,
            &row.value_nonce,
        )
        .map_err(|_| AppError::Crypto)?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Crypto)
}

async fn decrypt_history_row(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    row: &HistoryRow,
) -> Result<String, AppError> {
    let dek_version = u64::try_from(row.dek_version).map_err(|_| AppError::Crypto)?;
    let dek = environments::dek_by_version(pool, crypto, &row.environment_id, dek_version).await?;
    let plaintext = crypto
        .decrypt_current_value(
            &dek,
            &CurrentValueContext {
                service_id: &row.service_id,
                environment_id: &row.environment_id,
                variable_id: &row.variable_id,
                version: u64::try_from(row.version).map_err(|_| AppError::Crypto)?,
                dek_version,
            },
            &row.encrypted_value,
            &row.value_nonce,
        )
        .map_err(|_| AppError::Crypto)?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Crypto)
}

pub(crate) async fn environment_context(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    environment_id: &str,
) -> Result<EnvironmentContext, AppError> {
    let environment = sqlx::query_as::<_, EnvironmentContext>(
        "SELECT e.id, e.name, e.service_id, s.name AS service_name, e.archived_at, \
                s.archived_at AS service_archived_at \
         FROM environments e JOIN services s ON s.id = e.service_id \
         WHERE e.id = ? AND s.organization_id = ?",
    )
    .bind(environment_id)
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    if !can_access_service(
        pool,
        &session.user.id,
        session.user.role,
        &environment.service_id,
    )
    .await?
    {
        return Err(AppError::NotFound);
    }
    Ok(environment)
}

fn require_direct_apply(session: &AuthenticatedSession) -> Result<(), AppError> {
    session.require_full()?;
    if session.user.role.allows(Capability::ApplyRequest) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(crate) fn ensure_mutable(environment: &EnvironmentContext) -> Result<(), AppError> {
    if environment.archived_at.is_some() || environment.service_archived_at.is_some() {
        Err(AppError::Conflict)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_key(value: &str) -> Result<String, AppError> {
    let key = value.trim();
    let valid = !key.is_empty()
        && key.len() <= 255
        && key.bytes().enumerate().all(|(index, byte)| {
            byte == b'_'
                || byte.is_ascii_alphanumeric() && (index > 0 || byte.is_ascii_alphabetic())
        });
    if valid {
        Ok(key.to_owned())
    } else {
        Err(AppError::InvalidRequest)
    }
}

pub(crate) fn validate_visibility(value: &str) -> Result<&str, AppError> {
    match value {
        "public" | "restricted" => Ok(value),
        _ => Err(AppError::InvalidRequest),
    }
}

pub(crate) fn validate_value_type(value: &str) -> Result<&str, AppError> {
    match value {
        "string" | "boolean" | "integer" | "url" | "multiline" => Ok(value),
        _ => Err(AppError::InvalidRequest),
    }
}

pub(crate) fn suggest_value_type(value: &str) -> &'static str {
    if value.contains(['\n', '\r']) {
        return "multiline";
    }
    if matches!(value, "true" | "false") {
        return "boolean";
    }
    if !value.is_empty() && value.parse::<i64>().is_ok() {
        return "integer";
    }
    if let Ok(uri) = value.parse::<Uri>()
        && matches!(uri.scheme_str(), Some("http" | "https"))
        && uri.authority().is_some()
    {
        return "url";
    }
    "string"
}

pub(crate) fn validate_value(value: &str, value_type: &str) -> Result<(), AppError> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(AppError::InvalidRequest);
    }
    match value_type {
        "boolean" if !matches!(value, "true" | "false") => Err(AppError::InvalidRequest),
        "integer" if value.parse::<i64>().is_err() => Err(AppError::InvalidRequest),
        "url" => {
            let uri: Uri = value.parse().map_err(|_| AppError::InvalidRequest)?;
            if matches!(uri.scheme_str(), Some("http" | "https")) && uri.authority().is_some() {
                Ok(())
            } else {
                Err(AppError::InvalidRequest)
            }
        }
        _ => Ok(()),
    }
}

pub(crate) fn validate_reason(value: &str) -> Result<String, AppError> {
    let reason = value.trim();
    if reason.is_empty() || reason.chars().count() > MAX_REASON_CHARS {
        Err(AppError::InvalidRequest)
    } else {
        Ok(reason.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};
    use zeroize::Zeroizing;

    use crate::{
        auth::{
            AuthenticatedSession, AuthenticationState, PrivilegedAuthLevel, SessionManager,
            SessionUser,
        },
        config::SessionSettings,
        crypto::{CryptoManager, ProposedValueContext},
        db::{initialize_and_validate_key_registry, test_pool},
        environments::{self, EnvironmentInput},
        error::AppError,
        services::{self, ServiceInput},
        users::Role,
    };

    use super::{
        AppliedVariableInput, delete_applied, export_environment, history, import_applied,
        list_for_environment, record_applied, reveal_current, reveal_version, suggest_value_type,
    };

    #[test]
    fn suggests_conservative_types_for_import_preview() {
        assert_eq!(suggest_value_type("true"), "boolean");
        assert_eq!(suggest_value_type("false"), "boolean");
        assert_eq!(suggest_value_type("8080"), "integer");
        assert_eq!(suggest_value_type("https://example.test/path?a=1"), "url");
        assert_eq!(suggest_value_type("first\nsecond"), "multiline");
        assert_eq!(suggest_value_type("TRUE"), "string");
        assert_eq!(suggest_value_type("0012x"), "string");
        assert_eq!(suggest_value_type(""), "string");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn contributor_never_receives_restricted_plaintext_and_reveal_requires_recent_auth() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([41; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let operator = session("operator", Role::Operator);
        let contributor = session("contributor", Role::Contributor);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Payment API".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let environment_id = environments::create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "staging".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) \
             VALUES('contributor', ?, '2026-08-14T00:00:00Z', 'admin')",
        )
        .bind(&service_id)
        .execute(&pool)
        .await
        .unwrap();

        record_applied(
            &pool,
            &crypto,
            &operator,
            &environment_id,
            input("API_URL", "https://staging.example.test", "public", "url"),
        )
        .await
        .unwrap();
        let restricted_id = record_applied(
            &pool,
            &crypto,
            &operator,
            &environment_id,
            input(
                "DATABASE_URL",
                "postgres://user:top-secret@example.test/db",
                "restricted",
                "string",
            ),
        )
        .await
        .unwrap();

        let (_, contributor_view) =
            list_for_environment(&pool, &crypto, &contributor, &environment_id)
                .await
                .unwrap();
        assert_eq!(contributor_view.len(), 2);
        assert_eq!(
            contributor_view
                .iter()
                .find(|row| row.key == "API_URL")
                .unwrap()
                .value
                .as_deref(),
            Some("https://staging.example.test")
        );
        assert!(
            contributor_view
                .iter()
                .find(|row| row.key == "DATABASE_URL")
                .unwrap()
                .value
                .is_none()
        );
        let serialized = serde_json::to_string(&contributor_view).unwrap();
        assert!(!serialized.contains("top-secret"));

        let manager = session_manager(pool.clone(), crypto.clone());
        assert!(matches!(
            reveal_current(&pool, &crypto, &manager, &contributor, &restricted_id).await,
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            reveal_current(&pool, &crypto, &manager, &operator, &restricted_id).await,
            Err(AppError::Forbidden)
        ));
        let mut recent_operator = operator.clone();
        recent_operator.privileged_authenticated_at = Some(OffsetDateTime::now_utc());
        recent_operator.privileged_auth_level = Some(PrivilegedAuthLevel::Standard);
        let (key, secret) =
            reveal_current(&pool, &crypto, &manager, &recent_operator, &restricted_id)
                .await
                .unwrap();
        assert_eq!(key, "DATABASE_URL");
        assert!(secret.contains("top-secret"));

        let (_, contributor_history) = history(&pool, &crypto, &contributor, &restricted_id)
            .await
            .unwrap();
        assert_eq!(contributor_history.len(), 1);
        assert!(contributor_history[0].value.is_none());
        assert!(
            !serde_json::to_string(&contributor_history)
                .unwrap()
                .contains("top-secret")
        );
        let version_id = &contributor_history[0].id;
        assert!(matches!(
            reveal_version(&pool, &crypto, &manager, &contributor, version_id).await,
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            reveal_version(&pool, &crypto, &manager, &operator, version_id).await,
            Err(AppError::Forbidden)
        ));
        let (_, version, previous_secret) =
            reveal_version(&pool, &crypto, &manager, &recent_operator, version_id)
                .await
                .unwrap();
        assert_eq!(version, 1);
        assert!(previous_secret.contains("top-secret"));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn direct_update_creates_immutable_versions_and_applied_change_sets() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([42; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let operator = session("operator", Role::Operator);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Auth API".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let environment_id = environments::create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "production".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let variable_id = record_applied(
            &pool,
            &crypto,
            &operator,
            &environment_id,
            input("LOG_LEVEL", "info", "public", "string"),
        )
        .await
        .unwrap();
        let updated_id = record_applied(
            &pool,
            &crypto,
            &operator,
            &environment_id,
            input("LOG_LEVEL", "debug", "public", "string"),
        )
        .await
        .unwrap();
        assert_eq!(variable_id, updated_id);
        let version: i64 = sqlx::query_scalar("SELECT version FROM variables WHERE id = ?")
            .bind(&variable_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let history_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM variable_versions WHERE variable_id = ?")
                .bind(&variable_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let request_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM change_requests WHERE environment_id = ? AND status = 'APPLIED'",
        )
        .bind(&environment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(version, 2);
        assert_eq!(history_count, 2);
        assert_eq!(request_count, 2);

        let proposal: (String, String, i64, Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
            "SELECT r.id, i.id, i.item_revision, i.encrypted_proposed_value, i.proposed_value_nonce, i.proposed_dek_version \
             FROM variable_versions vv JOIN change_request_items i ON i.id = vv.change_request_item_id \
             JOIN change_requests r ON r.id = i.change_request_id \
             WHERE vv.variable_id = ? AND vv.version = 2",
        )
        .bind(&variable_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let proposal_dek_version = u64::try_from(proposal.5).unwrap();
        let proposal_dek =
            environments::dek_by_version(&pool, &crypto, &environment_id, proposal_dek_version)
                .await
                .unwrap();
        let proposal_plaintext = crypto
            .decrypt_proposed_value(
                &proposal_dek,
                &ProposedValueContext {
                    service_id: &service_id,
                    environment_id: &environment_id,
                    change_request_id: &proposal.0,
                    item_id: &proposal.1,
                    item_revision: u64::try_from(proposal.2).unwrap(),
                    dek_version: proposal_dek_version,
                },
                &proposal.3,
                &proposal.4,
            )
            .unwrap();
        assert_eq!(proposal_plaintext.as_slice(), b"debug");

        let ciphertext: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_value FROM variables WHERE id = ?")
                .bind(&variable_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!ciphertext.windows(5).any(|window| window == b"debug"));

        let (_, history_before_delete) = history(&pool, &crypto, &operator, &variable_id)
            .await
            .unwrap();
        assert_eq!(history_before_delete[0].value.as_deref(), Some("debug"));
        assert_eq!(history_before_delete[1].value.as_deref(), Some("info"));

        let deleted_environment = delete_applied(
            &pool,
            &crypto,
            &operator,
            &variable_id,
            "Confirmed removal in deployment platform",
        )
        .await
        .unwrap();
        assert_eq!(deleted_environment, environment_id);
        let lifecycle: String =
            sqlx::query_scalar("SELECT lifecycle_status FROM variables WHERE id = ?")
                .bind(&variable_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(lifecycle, "DELETED");
        assert!(
            list_for_environment(&pool, &crypto, &operator, &environment_id)
                .await
                .unwrap()
                .1
                .is_empty()
        );
        let delete_value_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM change_request_items \
             WHERE variable_id = ? AND action = 'DELETE' AND encrypted_proposed_value IS NULL",
        )
        .bind(&variable_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(delete_value_count, 1);

        let revived_id = record_applied(
            &pool,
            &crypto,
            &operator,
            &environment_id,
            input("LOG_LEVEL", "warn", "public", "string"),
        )
        .await
        .unwrap();
        assert_eq!(revived_id, variable_id);
        let (_, complete_history) = history(&pool, &crypto, &operator, &variable_id)
            .await
            .unwrap();
        assert_eq!(complete_history.len(), 4);
        assert_eq!(complete_history[0].operation, "ADD");
        assert_eq!(complete_history[0].version, 4);
        assert_eq!(complete_history[0].value.as_deref(), Some("warn"));
        assert_eq!(complete_history[1].operation, "DELETE");
        assert_eq!(complete_history[1].lifecycle_status, "DELETED");
        assert_eq!(complete_history[1].value.as_deref(), Some("debug"));

        let contributor = session("contributor", Role::Contributor);
        assert!(
            record_applied(
                &pool,
                &crypto,
                &contributor,
                &environment_id,
                input("FORBIDDEN", "value", "public", "string"),
            )
            .await
            .is_err()
        );
        assert!(
            delete_applied(&pool, &crypto, &contributor, &variable_id, "Not allowed")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn import_is_atomic_and_export_requires_recent_operator_auth() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([43; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let operator = session("operator", Role::Operator);
        let contributor = session("contributor", Role::Contributor);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Import API".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let environment_id = environments::create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "staging".into(),
                description: None,
            },
        )
        .await
        .unwrap();

        let invalid_batch = vec![
            input("WILL_ROLL_BACK", "valid", "restricted", "string"),
            input("INVALID_BOOL", "yes", "public", "boolean"),
        ];
        assert!(
            import_applied(&pool, &crypto, &operator, &environment_id, invalid_batch)
                .await
                .is_err()
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM variables")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);

        let imported = import_applied(
            &pool,
            &crypto,
            &operator,
            &environment_id,
            vec![
                input("API_URL", "https://example.test/a=b", "public", "url"),
                input(
                    "DATABASE_URL",
                    "postgres://user:secret@example.test/db",
                    "restricted",
                    "string",
                ),
            ],
        )
        .await
        .unwrap();
        assert_eq!(imported, 2);
        let import_audits: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = 'IMPORT_ENV'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(import_audits, 1);

        let manager = session_manager(pool.clone(), crypto.clone());
        assert!(matches!(
            export_environment(&pool, &crypto, &manager, &operator, &environment_id).await,
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            export_environment(&pool, &crypto, &manager, &contributor, &environment_id).await,
            Err(AppError::Forbidden)
        ));
        let mut recent_operator = operator;
        recent_operator.privileged_authenticated_at = Some(OffsetDateTime::now_utc());
        recent_operator.privileged_auth_level = Some(PrivilegedAuthLevel::Standard);
        let (_, exported) =
            export_environment(&pool, &crypto, &manager, &recent_operator, &environment_id)
                .await
                .unwrap();
        assert!(exported.contains("API_URL=\"https://example.test/a=b\""));
        assert!(exported.contains("DATABASE_URL=postgres://user:secret@example.test/db"));
    }

    fn input(key: &str, value: &str, visibility: &str, value_type: &str) -> AppliedVariableInput {
        AppliedVariableInput {
            key: key.into(),
            value: value.into(),
            visibility: visibility.into(),
            value_type: value_type.into(),
            description: None,
            reason: "Confirmed as applied in deployment platform".into(),
        }
    }

    fn session_manager(pool: sqlx::SqlitePool, crypto: CryptoManager) -> SessionManager {
        SessionManager::new(
            pool,
            crypto,
            SessionSettings {
                cookie_name: "test".into(),
                secure_cookie: false,
                idle_timeout: Duration::minutes(30),
                absolute_timeout: Duration::hours(12),
                recent_auth_timeout: Duration::minutes(5),
            },
        )
    }

    fn session(id: &str, role: Role) -> AuthenticatedSession {
        AuthenticatedSession {
            id: format!("session-{id}"),
            token_hash: vec![1; 32],
            csrf_token_hash: vec![2; 32],
            user: SessionUser {
                id: id.into(),
                organization_id: "org".into(),
                email: format!("{id}@example.test"),
                role,
                auth_version: 1,
                totp_enabled: role.requires_totp(),
                must_change_password: false,
            },
            authentication_state: AuthenticationState::Full,
            privileged_authenticated_at: None,
            privileged_auth_level: None,
        }
    }

    async fn seed_identity(pool: &sqlx::SqlitePool) {
        let now = "2026-08-14T00:00:00Z";
        sqlx::query(
            "INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org', 'ConfigDeck', ?, ?)",
        )
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
        for (id, email, role) in [
            ("admin", "admin@example.test", "ADMINISTRATOR"),
            ("operator", "operator@example.test", "OPERATOR"),
            ("contributor", "contributor@example.test", "CONTRIBUTOR"),
        ] {
            sqlx::query(
                "INSERT INTO users(\
                    id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at\
                 ) VALUES(?, 'org', ?, ?, 'hash', ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(email)
            .bind(email)
            .bind(role)
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}
