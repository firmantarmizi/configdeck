use std::collections::{BTreeMap, HashMap, HashSet};

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    auth::{AuthenticatedSession, PrivilegedAuthLevel, SessionManager},
    crypto::{CryptoManager, CurrentValueContext, EncryptedBlob, ProposedValueContext},
    db::now_rfc3339,
    environments,
    error::AppError,
    services::validate_description,
    users::{Capability, can_access_service},
    variables::{
        EnvironmentContext, ensure_mutable, environment_context, validate_key, validate_reason,
        validate_value, validate_value_type, validate_visibility,
    },
};

const MAX_ITEMS: usize = 50;
const MAX_TITLE_CHARS: usize = 200;

#[derive(Clone, Deserialize)]
pub struct ChangeRequestInput {
    pub environment_id: String,
    pub title: Option<String>,
    pub reason: String,
    pub items: Vec<ChangeRequestItemInput>,
}

#[derive(Clone, Deserialize)]
pub struct ChangeRequestItemInput {
    pub action: String,
    pub key: String,
    pub value: Option<String>,
    pub value_source: Option<String>,
    pub visibility: Option<String>,
    pub value_type: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ChangeRequestSummary {
    pub id: String,
    pub environment_id: String,
    pub service_name: String,
    pub environment_name: String,
    pub title: Option<String>,
    pub reason: String,
    pub status: String,
    pub requested_at: String,
    pub item_count: i64,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ChangeRequestDetail {
    pub id: String,
    pub service_id: String,
    pub service_name: String,
    pub environment_id: String,
    pub environment_name: String,
    pub title: Option<String>,
    pub reason: String,
    pub status: String,
    pub requested_by: String,
    pub requested_by_email: String,
    pub requested_at: String,
    pub approved_at: Option<String>,
    pub rejected_at: Option<String>,
    pub rejection_reason: Option<String>,
    pub applied_at: Option<String>,
}

#[derive(Clone, Debug, FromRow)]
struct ItemRow {
    id: String,
    change_request_id: String,
    variable_id: Option<String>,
    action: String,
    key: String,
    base_variable_version: Option<i64>,
    encrypted_proposed_value: Option<Vec<u8>>,
    proposed_value_nonce: Option<Vec<u8>>,
    proposed_dek_version: Option<i64>,
    proposed_visibility: String,
    proposed_value_type: String,
    proposed_description: Option<String>,
    value_source: Option<String>,
    value_fulfilled_at: Option<String>,
    item_revision: i64,
}

#[derive(Clone, Debug, FromRow)]
struct WorkflowRequestRow {
    id: String,
    organization_id: String,
    service_id: String,
    environment_id: String,
    status: String,
    revision: i64,
    approved_at: Option<String>,
    preview_fingerprint: Option<Vec<u8>>,
}

#[derive(Clone, Debug, FromRow)]
struct CurrentRow {
    id: String,
    key: String,
    encrypted_value: Vec<u8>,
    value_nonce: Vec<u8>,
    dek_version: i64,
    visibility: String,
    value_type: String,
    description: Option<String>,
    version: i64,
    lifecycle_status: String,
}

#[derive(Debug)]
pub struct ResultingPreview {
    pub environment: EnvironmentContext,
    pub dotenv: Zeroizing<String>,
    pub fingerprint: String,
    pub request_ids: Vec<String>,
    pub item_count: usize,
}

struct PreparedApply {
    request_id: String,
    item_id: String,
    action: String,
    key: String,
    variable_id: String,
    expected_version: Option<i64>,
    expected_lifecycle: Option<&'static str>,
    version: i64,
    visibility: String,
    value_type: String,
    description: Option<String>,
    encrypted: EncryptedBlob,
    dek_version: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChangeRequestItemView {
    pub id: String,
    pub action: String,
    pub key: String,
    pub base_variable_version: Option<i64>,
    pub value: Option<String>,
    pub visibility: String,
    pub value_type: String,
    pub description: Option<String>,
    pub value_source: Option<String>,
    pub fulfilled: bool,
}

#[derive(FromRow)]
struct ExistingVariable {
    id: String,
    version: i64,
    lifecycle_status: String,
    visibility: String,
    value_type: String,
    description: Option<String>,
}

#[derive(FromRow)]
struct FulfillRow {
    request_id: String,
    service_id: String,
    environment_id: String,
    status: String,
    action: String,
    proposed_visibility: String,
    proposed_value_type: String,
    item_revision: i64,
}

struct PreparedItem {
    id: String,
    action: String,
    key: String,
    variable_id: Option<String>,
    base_version: Option<i64>,
    encrypted_value: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    dek_version: Option<i64>,
    visibility: String,
    value_type: String,
    description: Option<String>,
    value_source: Option<String>,
    fulfilled: bool,
}

#[allow(clippy::too_many_lines)]
pub async fn create(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    input: ChangeRequestInput,
) -> Result<String, AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::CreateChangeRequest) {
        return Err(AppError::Forbidden);
    }
    let environment = environment_context(pool, session, &input.environment_id).await?;
    ensure_mutable(&environment)?;
    if input.items.is_empty() || input.items.len() > MAX_ITEMS {
        return Err(AppError::InvalidRequest);
    }
    let title = validate_title(input.title)?;
    let reason = validate_reason(&input.reason)?;
    let request_id = Uuid::new_v4().to_string();
    let (active_dek_version, dek) =
        environments::active_dek(pool, crypto, &input.environment_id).await?;
    let active_dek_version_i64 = i64::try_from(active_dek_version).map_err(|_| AppError::Crypto)?;
    let mut keys = HashSet::with_capacity(input.items.len());
    let mut prepared = Vec::with_capacity(input.items.len());
    for input_item in input.items {
        let key = validate_key(&input_item.key)?;
        if !keys.insert(key.clone()) {
            return Err(AppError::InvalidRequest);
        }
        let existing = sqlx::query_as::<_, ExistingVariable>(
            "SELECT id, version, lifecycle_status, visibility, value_type, description FROM variables WHERE environment_id = ? AND key = ?",
        )
        .bind(&input.environment_id)
        .bind(&key)
        .fetch_optional(pool)
        .await?;
        let item_id = Uuid::new_v4().to_string();
        let item = prepare_item(
            crypto,
            &environment,
            &request_id,
            &item_id,
            active_dek_version,
            active_dek_version_i64,
            input_item,
            key,
            existing,
            &dek,
        )?;
        prepared.push(item);
    }
    let status = if prepared
        .iter()
        .any(|item| matches!(item.action.as_str(), "ADD" | "UPDATE") && !item.fulfilled)
    {
        "NEEDS_INPUT"
    } else {
        "REQUESTED"
    };
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO change_requests(id, service_id, environment_id, title, reason, status, requested_by, requested_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&request_id)
    .bind(&environment.service_id)
    .bind(&input.environment_id)
    .bind(&title)
    .bind(&reason)
    .bind(status)
    .bind(&session.user.id)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    for item in &prepared {
        sqlx::query(
            "INSERT INTO change_request_items(id, change_request_id, variable_id, action, key, base_variable_version, encrypted_proposed_value, proposed_value_nonce, proposed_crypto_version, proposed_dek_version, proposed_visibility, proposed_value_type, proposed_description, value_source, value_fulfilled_by, value_fulfilled_at, item_revision, created_at) \
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE 1 END, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
        )
        .bind(&item.id)
        .bind(&request_id)
        .bind(&item.variable_id)
        .bind(&item.action)
        .bind(&item.key)
        .bind(item.base_version)
        .bind(&item.encrypted_value)
        .bind(&item.nonce)
        .bind(&item.encrypted_value)
        .bind(item.dek_version)
        .bind(&item.visibility)
        .bind(&item.value_type)
        .bind(&item.description)
        .bind(&item.value_source)
        .bind(item.fulfilled.then_some(session.user.id.as_str()))
        .bind(item.fulfilled.then_some(now.as_str()))
        .bind(&now)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id, environment_id, change_request_id, metadata_json) VALUES(?, ?, 'CREATE_REQUEST', ?, ?, ?, ?)",
    )
    .bind(&now)
    .bind(&session.user.id)
    .bind(&environment.service_id)
    .bind(&input.environment_id)
    .bind(&request_id)
    .bind(serde_json::json!({"item_count": prepared.len(), "status": status}).to_string())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(request_id)
}

#[allow(clippy::too_many_arguments)]
fn prepare_item(
    crypto: &CryptoManager,
    environment: &EnvironmentContext,
    request_id: &str,
    item_id: &str,
    dek_version: u64,
    dek_version_i64: i64,
    input: ChangeRequestItemInput,
    key: String,
    existing: Option<ExistingVariable>,
    dek: &[u8; 32],
) -> Result<PreparedItem, AppError> {
    let action = input.action.trim().to_ascii_uppercase();
    if action == "DELETE" {
        let existing = existing
            .filter(|row| row.lifecycle_status == "ACTIVE")
            .ok_or(AppError::Conflict)?;
        return Ok(PreparedItem {
            id: item_id.to_owned(),
            action,
            key,
            variable_id: Some(existing.id),
            base_version: Some(existing.version),
            encrypted_value: None,
            nonce: None,
            dek_version: None,
            visibility: existing.visibility,
            value_type: existing.value_type,
            description: existing.description,
            value_source: None,
            fulfilled: false,
        });
    }
    let (variable_id, base_version) = match action.as_str() {
        "ADD"
            if existing
                .as_ref()
                .is_none_or(|row| row.lifecycle_status != "ACTIVE") =>
        {
            (None, None)
        }
        "UPDATE" => {
            let existing = existing
                .filter(|row| row.lifecycle_status == "ACTIVE")
                .ok_or(AppError::Conflict)?;
            (Some(existing.id), Some(existing.version))
        }
        _ => return Err(AppError::Conflict),
    };
    let visibility = validate_visibility(input.visibility.as_deref().unwrap_or("restricted"))?;
    let value_type = validate_value_type(input.value_type.as_deref().unwrap_or("string"))?;
    let description = validate_description(input.description)?;
    let value_source = input
        .value_source
        .as_deref()
        .ok_or(AppError::InvalidRequest)?;
    let (encrypted_value, nonce, fulfilled) = match value_source {
        "REQUESTER_PROVIDED" => {
            let value = input.value.ok_or(AppError::InvalidRequest)?;
            validate_value(&value, value_type)?;
            let encrypted = crypto
                .encrypt_proposed_value(
                    dek,
                    &ProposedValueContext {
                        service_id: &environment.service_id,
                        environment_id: &environment.id,
                        change_request_id: request_id,
                        item_id,
                        item_revision: 1,
                        dek_version,
                    },
                    value.as_bytes(),
                )
                .map_err(|_| AppError::Crypto)?;
            (
                Some(encrypted.ciphertext),
                Some(encrypted.nonce.to_vec()),
                true,
            )
        }
        "OPERATOR_PROVIDED" if input.value.as_deref().is_none_or(str::is_empty) => {
            (None, None, false)
        }
        _ => return Err(AppError::InvalidRequest),
    };
    let proposed_dek_version = encrypted_value.as_ref().map(|_| dek_version_i64);
    Ok(PreparedItem {
        id: item_id.to_owned(),
        action,
        key,
        variable_id,
        base_version,
        encrypted_value,
        nonce,
        dek_version: proposed_dek_version,
        visibility: visibility.to_owned(),
        value_type: value_type.to_owned(),
        description,
        value_source: Some(value_source.to_owned()),
        fulfilled,
    })
}

pub async fn list_visible(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
) -> Result<Vec<ChangeRequestSummary>, AppError> {
    session.require_full()?;
    Ok(sqlx::query_as::<_, ChangeRequestSummary>(
        "SELECT r.id, r.environment_id, s.name AS service_name, e.name AS environment_name, r.title, r.reason, r.status, r.requested_at, COUNT(i.id) AS item_count \
         FROM change_requests r JOIN services s ON s.id = r.service_id JOIN environments e ON e.id = r.environment_id \
         JOIN change_request_items i ON i.change_request_id = r.id \
         WHERE s.organization_id = ? AND (? <> 'CONTRIBUTOR' OR r.requested_by = ?) GROUP BY r.id ORDER BY r.requested_at DESC",
    )
    .bind(&session.user.organization_id)
    .bind(session.user.role.as_str())
    .bind(&session.user.id)
    .fetch_all(pool)
    .await?)
}

pub async fn fulfill_value(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    item_id: &str,
    value: String,
) -> Result<String, AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::FulfillValue) {
        return Err(AppError::Forbidden);
    }
    let row = sqlx::query_as::<_, FulfillRow>(
        "SELECT r.id AS request_id, r.service_id, r.environment_id, r.status, i.action, i.proposed_visibility, i.proposed_value_type, i.item_revision \
         FROM change_request_items i JOIN change_requests r ON r.id = i.change_request_id JOIN services s ON s.id = r.service_id \
         WHERE i.id = ? AND s.organization_id = ? AND i.value_source = 'OPERATOR_PROVIDED' AND i.encrypted_proposed_value IS NULL",
    )
    .bind(item_id)
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    if !matches!(row.status.as_str(), "NEEDS_INPUT" | "REQUESTED")
        || !matches!(row.action.as_str(), "ADD" | "UPDATE")
    {
        return Err(AppError::Conflict);
    }
    if row.proposed_visibility == "restricted"
        && !sessions.has_recent_auth(session, PrivilegedAuthLevel::Standard)
    {
        return Err(AppError::Forbidden);
    }
    validate_value(&value, &row.proposed_value_type)?;
    let (dek_version, dek) = environments::active_dek(pool, crypto, &row.environment_id).await?;
    let next_revision = row.item_revision.checked_add(1).ok_or(AppError::Conflict)?;
    let encrypted = crypto
        .encrypt_proposed_value(
            &dek,
            &ProposedValueContext {
                service_id: &row.service_id,
                environment_id: &row.environment_id,
                change_request_id: &row.request_id,
                item_id,
                item_revision: u64::try_from(next_revision).map_err(|_| AppError::Crypto)?,
                dek_version,
            },
            value.as_bytes(),
        )
        .map_err(|_| AppError::Crypto)?;
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE change_request_items SET encrypted_proposed_value = ?, proposed_value_nonce = ?, proposed_crypto_version = 1, proposed_dek_version = ?, value_fulfilled_by = ?, value_fulfilled_at = ?, item_revision = ? \
         WHERE id = ? AND item_revision = ? AND encrypted_proposed_value IS NULL",
    )
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.to_vec())
    .bind(i64::try_from(dek_version).map_err(|_| AppError::Crypto)?)
    .bind(&session.user.id)
    .bind(&now)
    .bind(next_revision)
    .bind(item_id)
    .bind(row.item_revision)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::Conflict);
    }
    let missing: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM change_request_items WHERE change_request_id = ? AND action IN ('ADD', 'UPDATE') AND encrypted_proposed_value IS NULL)",
    )
    .bind(&row.request_id)
    .fetch_one(&mut *transaction)
    .await?;
    let approved: bool =
        sqlx::query_scalar("SELECT approved_at IS NOT NULL FROM change_requests WHERE id = ?")
            .bind(&row.request_id)
            .fetch_one(&mut *transaction)
            .await?;
    let status = if missing {
        "NEEDS_INPUT"
    } else if approved {
        "READY_TO_APPLY"
    } else {
        "REQUESTED"
    };
    sqlx::query("UPDATE change_requests SET status = ?, revision = revision + 1, preview_fingerprint = NULL WHERE id = ?")
        .bind(status)
        .bind(&row.request_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id, environment_id, change_request_id, metadata_json) VALUES(?, ?, 'FULFILL_REQUEST_VALUE', ?, ?, ?, ?)")
        .bind(&now).bind(&session.user.id).bind(&row.service_id).bind(&row.environment_id).bind(&row.request_id)
        .bind(serde_json::json!({"item_id": item_id, "visibility": row.proposed_visibility}).to_string())
        .execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(row.request_id)
}

pub async fn detail(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    request_id: &str,
) -> Result<(ChangeRequestDetail, Vec<ChangeRequestItemView>), AppError> {
    session.require_full()?;
    let request = sqlx::query_as::<_, ChangeRequestDetail>(
        "SELECT r.id, r.service_id, s.name AS service_name, r.environment_id, e.name AS environment_name, r.title, r.reason, r.status, r.requested_by, u.email AS requested_by_email, r.requested_at, r.approved_at, r.rejected_at, r.rejection_reason, r.applied_at \
         FROM change_requests r JOIN services s ON s.id = r.service_id JOIN environments e ON e.id = r.environment_id JOIN users u ON u.id = r.requested_by \
         WHERE r.id = ? AND s.organization_id = ?",
    )
    .bind(request_id)
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    if matches!(session.user.role, crate::users::Role::Contributor)
        && request.requested_by != session.user.id
    {
        return Err(AppError::NotFound);
    }
    if request.requested_by != session.user.id
        && !can_access_service(
            pool,
            &session.user.id,
            session.user.role,
            &request.service_id,
        )
        .await?
    {
        return Err(AppError::NotFound);
    }
    let rows = sqlx::query_as::<_, ItemRow>(
        "SELECT id, change_request_id, variable_id, action, key, base_variable_version, encrypted_proposed_value, proposed_value_nonce, proposed_dek_version, proposed_visibility, proposed_value_type, proposed_description, value_source, value_fulfilled_at, item_revision \
         FROM change_request_items WHERE change_request_id = ? ORDER BY created_at, id",
    )
    .bind(request_id)
    .fetch_all(pool)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let value = if row.proposed_visibility == "public" {
            decrypt_public_item(pool, crypto, &request, &row).await?
        } else {
            None
        };
        items.push(ChangeRequestItemView {
            id: row.id,
            action: row.action,
            key: row.key,
            base_variable_version: row.base_variable_version,
            value,
            visibility: row.proposed_visibility,
            value_type: row.proposed_value_type,
            description: row.proposed_description,
            value_source: row.value_source,
            fulfilled: row.value_fulfilled_at.is_some(),
        });
    }
    Ok((request, items))
}

async fn decrypt_public_item(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    request: &ChangeRequestDetail,
    row: &ItemRow,
) -> Result<Option<String>, AppError> {
    let (Some(ciphertext), Some(nonce), Some(dek_version)) = (
        row.encrypted_proposed_value.as_deref(),
        row.proposed_value_nonce.as_deref(),
        row.proposed_dek_version,
    ) else {
        return Ok(None);
    };
    let dek_version = u64::try_from(dek_version).map_err(|_| AppError::Crypto)?;
    let dek =
        environments::dek_by_version(pool, crypto, &request.environment_id, dek_version).await?;
    let plaintext = crypto
        .decrypt_proposed_value(
            &dek,
            &ProposedValueContext {
                service_id: &request.service_id,
                environment_id: &request.environment_id,
                change_request_id: &request.id,
                item_id: &row.id,
                item_revision: u64::try_from(row.item_revision).map_err(|_| AppError::Crypto)?,
                dek_version,
            },
            ciphertext,
            nonce,
        )
        .map_err(|_| AppError::Crypto)?;
    Ok(Some(
        String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Crypto)?,
    ))
}

pub async fn approve(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    request_id: &str,
) -> Result<(), AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ReviewRequest) {
        return Err(AppError::Forbidden);
    }
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    let request = workflow_request_in_transaction(&mut transaction, request_id).await?;
    authorize_workflow_request(session, &request)?;
    if !matches!(request.status.as_str(), "REQUESTED" | "NEEDS_INPUT")
        || request.approved_at.is_some()
    {
        return Err(AppError::Conflict);
    }
    let missing: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM change_request_items WHERE change_request_id = ? AND action IN ('ADD', 'UPDATE') AND encrypted_proposed_value IS NULL)",
    )
    .bind(request_id)
    .fetch_one(&mut *transaction)
    .await?;
    let status = if missing {
        "NEEDS_INPUT"
    } else {
        "READY_TO_APPLY"
    };
    let changed = sqlx::query(
        "UPDATE change_requests SET status = ?, approved_by = ?, approved_at = ?, revision = revision + 1, preview_fingerprint = NULL WHERE id = ? AND revision = ? AND approved_at IS NULL",
    )
    .bind(status)
    .bind(&session.user.id)
    .bind(&now)
    .bind(request_id)
    .bind(request.revision)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::Conflict);
    }
    insert_request_audit(
        &mut transaction,
        session,
        &request,
        "APPROVE_REQUEST",
        serde_json::json!({"status": status}),
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn reject(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    request_id: &str,
    reason: &str,
) -> Result<(), AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ReviewRequest) {
        return Err(AppError::Forbidden);
    }
    let reason = validate_reason(reason)?;
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    let request = workflow_request_in_transaction(&mut transaction, request_id).await?;
    authorize_workflow_request(session, &request)?;
    if !matches!(
        request.status.as_str(),
        "REQUESTED" | "NEEDS_INPUT" | "READY_TO_APPLY"
    ) {
        return Err(AppError::Conflict);
    }
    let changed = sqlx::query(
        "UPDATE change_requests SET status = 'REJECTED', rejected_by = ?, rejected_at = ?, rejection_reason = ?, revision = revision + 1, preview_fingerprint = NULL WHERE id = ? AND revision = ? AND status = ?",
    )
    .bind(&session.user.id)
    .bind(&now)
    .bind(&reason)
    .bind(request_id)
    .bind(request.revision)
    .bind(&request.status)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::Conflict);
    }
    insert_request_audit(
        &mut transaction,
        session,
        &request,
        "REJECT_REQUEST",
        serde_json::json!({"reason_length": reason.chars().count()}),
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn preview_resulting(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    request_ids: Vec<String>,
) -> Result<ResultingPreview, AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ReviewRequest)
        || !sessions.has_recent_auth(session, PrivilegedAuthLevel::Standard)
    {
        return Err(AppError::Forbidden);
    }
    let request_ids = normalize_request_ids(request_ids)?;
    let requests = load_workflow_requests(pool, &request_ids).await?;
    authorize_selection(session, &requests)?;
    let environment_id = &requests[0].environment_id;
    let environment = environment_context(pool, session, environment_id).await?;
    ensure_mutable(&environment)?;
    let items = load_workflow_items(pool, &request_ids).await?;
    validate_selection(&requests, &items)?;
    let current = load_current_rows(pool, environment_id).await?;
    let fingerprint = selection_fingerprint(&requests, &items, &current);
    let dotenv = resolve_dotenv(pool, crypto, &environment, &items, &current).await?;

    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    for request in &requests {
        let changed = sqlx::query(
            "UPDATE change_requests SET preview_fingerprint = ? WHERE id = ? AND revision = ? AND status = 'READY_TO_APPLY'",
        )
        .bind(&fingerprint)
        .bind(&request.id)
        .bind(request.revision)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::Conflict);
        }
        insert_request_audit(
            &mut transaction,
            session,
            request,
            "PREVIEW_REQUEST",
            serde_json::json!({"selection_size": requests.len()}),
            &now,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(ResultingPreview {
        environment,
        dotenv,
        fingerprint: HEXLOWER.encode(&fingerprint),
        request_ids,
        item_count: items.len(),
    })
}

#[allow(clippy::too_many_lines)]
pub async fn mark_applied(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    request_ids: Vec<String>,
    expected_fingerprint: &str,
) -> Result<String, AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ApplyRequest)
        || !sessions.has_recent_auth(session, PrivilegedAuthLevel::Standard)
    {
        return Err(AppError::Forbidden);
    }
    let expected_fingerprint = HEXLOWER
        .decode(expected_fingerprint.as_bytes())
        .map_err(|_| AppError::InvalidRequest)?;
    if expected_fingerprint.len() != 32 {
        return Err(AppError::InvalidRequest);
    }
    let request_ids = normalize_request_ids(request_ids)?;
    let requests = load_workflow_requests(pool, &request_ids).await?;
    authorize_selection(session, &requests)?;
    let environment_id = requests[0].environment_id.clone();
    let items = load_workflow_items(pool, &request_ids).await?;
    validate_selection(&requests, &items)?;
    let environment = environment_context(pool, session, &environment_id).await?;
    ensure_mutable(&environment)?;
    let current = load_current_rows(pool, &environment_id).await?;
    let prepared = prepare_apply_items(pool, crypto, &environment, &items, &current).await?;

    let mut transaction = pool.begin().await?;
    let requests = load_workflow_requests_in_transaction(&mut transaction, &request_ids).await?;
    authorize_selection(session, &requests)?;
    let items = load_workflow_items_in_transaction(&mut transaction, &request_ids).await?;
    validate_selection(&requests, &items)?;
    let current = load_current_rows_in_transaction(&mut transaction, &environment_id).await?;
    let actual_fingerprint = selection_fingerprint(&requests, &items, &current);
    let active_dek_version: i64 = sqlx::query_scalar(
        "SELECT dek_version FROM environment_keys WHERE environment_id = ? AND status = 'ACTIVE'",
    )
    .bind(&environment_id)
    .fetch_one(&mut *transaction)
    .await?;
    if actual_fingerprint.as_slice() != expected_fingerprint.as_slice()
        || prepared
            .iter()
            .any(|write| write.dek_version != active_dek_version)
        || requests.iter().any(|request| {
            request.preview_fingerprint.as_deref() != Some(expected_fingerprint.as_slice())
        })
    {
        return Err(AppError::Conflict);
    }
    let now = now_rfc3339()?;
    for write in &prepared {
        persist_apply_item(&mut transaction, session, &environment, write, &now).await?;
    }
    for request in &requests {
        let changed = sqlx::query(
            "UPDATE change_requests SET status = 'APPLIED', applied_by = ?, applied_at = ?, revision = revision + 1 WHERE id = ? AND revision = ? AND status = 'READY_TO_APPLY' AND preview_fingerprint = ?",
        )
        .bind(&session.user.id)
        .bind(&now)
        .bind(&request.id)
        .bind(request.revision)
        .bind(&expected_fingerprint)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::Conflict);
        }
        insert_request_audit(
            &mut transaction,
            session,
            request,
            "APPLY_REQUEST",
            serde_json::json!({"selection_size": requests.len()}),
            &now,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(environment_id)
}

fn normalize_request_ids(request_ids: Vec<String>) -> Result<Vec<String>, AppError> {
    let mut unique = request_ids
        .into_iter()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .collect::<Vec<_>>();
    unique.sort();
    unique.dedup();
    if unique.is_empty() || unique.len() > MAX_ITEMS {
        return Err(AppError::InvalidRequest);
    }
    if unique.iter().any(|id| Uuid::parse_str(id).is_err()) {
        return Err(AppError::InvalidRequest);
    }
    Ok(unique)
}

async fn load_workflow_requests(
    pool: &SqlitePool,
    request_ids: &[String],
) -> Result<Vec<WorkflowRequestRow>, AppError> {
    let mut requests = Vec::with_capacity(request_ids.len());
    for id in request_ids {
        requests.push(
            sqlx::query_as::<_, WorkflowRequestRow>(
                "SELECT r.id, s.organization_id, r.service_id, r.environment_id, r.status, r.revision, r.approved_at, r.preview_fingerprint FROM change_requests r JOIN services s ON s.id = r.service_id WHERE r.id = ?",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound)?,
        );
    }
    Ok(requests)
}

async fn load_workflow_requests_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_ids: &[String],
) -> Result<Vec<WorkflowRequestRow>, AppError> {
    let mut requests = Vec::with_capacity(request_ids.len());
    for id in request_ids {
        requests.push(workflow_request_in_transaction(transaction, id).await?);
    }
    Ok(requests)
}

async fn workflow_request_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_id: &str,
) -> Result<WorkflowRequestRow, AppError> {
    sqlx::query_as::<_, WorkflowRequestRow>(
        "SELECT r.id, s.organization_id, r.service_id, r.environment_id, r.status, r.revision, r.approved_at, r.preview_fingerprint FROM change_requests r JOIN services s ON s.id = r.service_id WHERE r.id = ?",
    )
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AppError::NotFound)
}

async fn load_workflow_items(
    pool: &SqlitePool,
    request_ids: &[String],
) -> Result<Vec<ItemRow>, AppError> {
    let mut items = Vec::new();
    for id in request_ids {
        items.extend(
            sqlx::query_as::<_, ItemRow>(
                "SELECT id, change_request_id, variable_id, action, key, base_variable_version, encrypted_proposed_value, proposed_value_nonce, proposed_dek_version, proposed_visibility, proposed_value_type, proposed_description, value_source, value_fulfilled_at, item_revision FROM change_request_items WHERE change_request_id = ? ORDER BY key, id",
            )
            .bind(id)
            .fetch_all(pool)
            .await?,
        );
    }
    Ok(items)
}

async fn load_workflow_items_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_ids: &[String],
) -> Result<Vec<ItemRow>, AppError> {
    let mut items = Vec::new();
    for id in request_ids {
        items.extend(
            sqlx::query_as::<_, ItemRow>(
                "SELECT id, change_request_id, variable_id, action, key, base_variable_version, encrypted_proposed_value, proposed_value_nonce, proposed_dek_version, proposed_visibility, proposed_value_type, proposed_description, value_source, value_fulfilled_at, item_revision FROM change_request_items WHERE change_request_id = ? ORDER BY key, id",
            )
            .bind(id)
            .fetch_all(&mut **transaction)
            .await?,
        );
    }
    Ok(items)
}

async fn load_current_rows(
    pool: &SqlitePool,
    environment_id: &str,
) -> Result<Vec<CurrentRow>, AppError> {
    Ok(sqlx::query_as::<_, CurrentRow>(
        "SELECT id, key, encrypted_value, value_nonce, dek_version, visibility, value_type, description, version, lifecycle_status FROM variables WHERE environment_id = ? ORDER BY key, id",
    )
    .bind(environment_id)
    .fetch_all(pool)
    .await?)
}

async fn load_current_rows_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    environment_id: &str,
) -> Result<Vec<CurrentRow>, AppError> {
    Ok(sqlx::query_as::<_, CurrentRow>(
        "SELECT id, key, encrypted_value, value_nonce, dek_version, visibility, value_type, description, version, lifecycle_status FROM variables WHERE environment_id = ? ORDER BY key, id",
    )
    .bind(environment_id)
    .fetch_all(&mut **transaction)
    .await?)
}

fn authorize_selection(
    session: &AuthenticatedSession,
    requests: &[WorkflowRequestRow],
) -> Result<(), AppError> {
    if requests.is_empty() || !session.user.role.allows(Capability::ReviewRequest) {
        return Err(AppError::Forbidden);
    }
    if requests
        .iter()
        .any(|request| request.organization_id != session.user.organization_id)
    {
        return Err(AppError::NotFound);
    }
    Ok(())
}

fn authorize_workflow_request(
    session: &AuthenticatedSession,
    request: &WorkflowRequestRow,
) -> Result<(), AppError> {
    if request.organization_id == session.user.organization_id {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

fn validate_selection(requests: &[WorkflowRequestRow], items: &[ItemRow]) -> Result<(), AppError> {
    let environment_id = requests
        .first()
        .map(|request| request.environment_id.as_str())
        .ok_or(AppError::InvalidRequest)?;
    if requests.iter().any(|request| {
        request.environment_id != environment_id
            || request.status != "READY_TO_APPLY"
            || request.approved_at.is_none()
    }) {
        return Err(AppError::Conflict);
    }
    let request_ids = requests
        .iter()
        .map(|request| request.id.as_str())
        .collect::<HashSet<_>>();
    if items.is_empty()
        || items
            .iter()
            .any(|item| !request_ids.contains(item.change_request_id.as_str()))
    {
        return Err(AppError::Conflict);
    }
    let mut keys = HashSet::with_capacity(items.len());
    for item in items {
        if !keys.insert(item.key.as_str())
            || (matches!(item.action.as_str(), "ADD" | "UPDATE")
                && item.encrypted_proposed_value.is_none())
        {
            return Err(AppError::Conflict);
        }
    }
    Ok(())
}

fn selection_fingerprint(
    requests: &[WorkflowRequestRow],
    items: &[ItemRow],
    current: &[CurrentRow],
) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"configdeck-resulting-preview-v1");
    for request in requests {
        digest_field(&mut digest, request.id.as_bytes());
        digest.update(request.revision.to_be_bytes());
    }
    for item in items {
        for value in [
            item.change_request_id.as_bytes(),
            item.id.as_bytes(),
            item.action.as_bytes(),
            item.key.as_bytes(),
        ] {
            digest_field(&mut digest, value);
        }
        digest.update(item.item_revision.to_be_bytes());
        digest.update(item.base_variable_version.unwrap_or(-1).to_be_bytes());
        digest.update(item.proposed_dek_version.unwrap_or(-1).to_be_bytes());
        for value in [
            item.variable_id.as_deref().unwrap_or("").as_bytes(),
            item.proposed_visibility.as_bytes(),
            item.proposed_value_type.as_bytes(),
            item.proposed_description
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
            item.value_source.as_deref().unwrap_or("").as_bytes(),
            item.encrypted_proposed_value.as_deref().unwrap_or_default(),
            item.proposed_value_nonce.as_deref().unwrap_or_default(),
        ] {
            digest_field(&mut digest, value);
        }
    }
    for variable in current {
        digest_field(&mut digest, variable.id.as_bytes());
        digest_field(&mut digest, variable.key.as_bytes());
        digest_field(&mut digest, variable.lifecycle_status.as_bytes());
        digest_field(&mut digest, variable.visibility.as_bytes());
        digest_field(&mut digest, variable.value_type.as_bytes());
        digest_field(
            &mut digest,
            variable.description.as_deref().unwrap_or("").as_bytes(),
        );
        digest.update(variable.version.to_be_bytes());
    }
    digest.finalize().to_vec()
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

async fn resolve_dotenv(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment: &EnvironmentContext,
    items: &[ItemRow],
    current: &[CurrentRow],
) -> Result<Zeroizing<String>, AppError> {
    let mut values = BTreeMap::<String, String>::new();
    for row in current
        .iter()
        .filter(|row| row.lifecycle_status == "ACTIVE")
    {
        values.insert(
            row.key.clone(),
            decrypt_current_row(pool, crypto, environment, row).await?,
        );
    }
    for item in items {
        match item.action.as_str() {
            "DELETE" => {
                let current_row = current
                    .iter()
                    .find(|row| item.variable_id.as_deref() == Some(row.id.as_str()))
                    .filter(|row| {
                        row.lifecycle_status == "ACTIVE"
                            && Some(row.version) == item.base_variable_version
                            && row.key == item.key
                    })
                    .ok_or(AppError::Conflict)?;
                if current_row.key != item.key {
                    return Err(AppError::Conflict);
                }
                if values.remove(&item.key).is_none() {
                    return Err(AppError::Conflict);
                }
            }
            "ADD" => {
                if values.contains_key(&item.key) {
                    return Err(AppError::Conflict);
                }
                values.insert(
                    item.key.clone(),
                    decrypt_proposed_row(pool, crypto, environment, item).await?,
                );
            }
            "UPDATE" => {
                let current_row = current
                    .iter()
                    .find(|row| item.variable_id.as_deref() == Some(row.id.as_str()))
                    .filter(|row| {
                        row.lifecycle_status == "ACTIVE"
                            && Some(row.version) == item.base_variable_version
                    })
                    .ok_or(AppError::Conflict)?;
                if current_row.key != item.key {
                    return Err(AppError::Conflict);
                }
                values.insert(
                    item.key.clone(),
                    decrypt_proposed_row(pool, crypto, environment, item).await?,
                );
            }
            _ => return Err(AppError::Conflict),
        }
    }
    let entries = values
        .into_iter()
        .map(|(key, value)| crate::dotenv::Entry { key, value })
        .collect::<Vec<_>>();
    Ok(Zeroizing::new(crate::dotenv::render(&entries)))
}

async fn decrypt_current_row(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment: &EnvironmentContext,
    row: &CurrentRow,
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

async fn decrypt_proposed_row(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment: &EnvironmentContext,
    item: &ItemRow,
) -> Result<String, AppError> {
    let dek_version = u64::try_from(item.proposed_dek_version.ok_or(AppError::Conflict)?)
        .map_err(|_| AppError::Crypto)?;
    let dek = environments::dek_by_version(pool, crypto, &environment.id, dek_version).await?;
    let plaintext = crypto
        .decrypt_proposed_value(
            &dek,
            &ProposedValueContext {
                service_id: &environment.service_id,
                environment_id: &environment.id,
                change_request_id: &item.change_request_id,
                item_id: &item.id,
                item_revision: u64::try_from(item.item_revision).map_err(|_| AppError::Crypto)?,
                dek_version,
            },
            item.encrypted_proposed_value
                .as_deref()
                .ok_or(AppError::Conflict)?,
            item.proposed_value_nonce
                .as_deref()
                .ok_or(AppError::Conflict)?,
        )
        .map_err(|_| AppError::Crypto)?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Crypto)
}

#[allow(clippy::too_many_lines)]
async fn prepare_apply_items(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment: &EnvironmentContext,
    items: &[ItemRow],
    current: &[CurrentRow],
) -> Result<Vec<PreparedApply>, AppError> {
    let (active_dek_version, active_dek) =
        environments::active_dek(pool, crypto, &environment.id).await?;
    let active_dek_version_i64 = i64::try_from(active_dek_version).map_err(|_| AppError::Crypto)?;
    let by_id = current
        .iter()
        .map(|row| (row.id.as_str(), row))
        .collect::<HashMap<_, _>>();
    let by_key = current
        .iter()
        .map(|row| (row.key.as_str(), row))
        .collect::<HashMap<_, _>>();
    let mut prepared = Vec::with_capacity(items.len());
    for item in items {
        let (variable_id, expected_version, expected_lifecycle, version, plaintext) =
            match item.action.as_str() {
                "ADD" => match by_key.get(item.key.as_str()) {
                    Some(row) if row.lifecycle_status == "DELETED" => (
                        row.id.clone(),
                        Some(row.version),
                        Some("DELETED"),
                        row.version + 1,
                        decrypt_proposed_row(pool, crypto, environment, item).await?,
                    ),
                    None => (
                        Uuid::new_v4().to_string(),
                        None,
                        None,
                        1,
                        decrypt_proposed_row(pool, crypto, environment, item).await?,
                    ),
                    _ => return Err(AppError::Conflict),
                },
                "UPDATE" => {
                    let row = item
                        .variable_id
                        .as_deref()
                        .and_then(|id| by_id.get(id).copied())
                        .filter(|row| {
                            row.lifecycle_status == "ACTIVE"
                                && Some(row.version) == item.base_variable_version
                                && row.key == item.key
                        })
                        .ok_or(AppError::Conflict)?;
                    (
                        row.id.clone(),
                        Some(row.version),
                        Some("ACTIVE"),
                        row.version + 1,
                        decrypt_proposed_row(pool, crypto, environment, item).await?,
                    )
                }
                "DELETE" => {
                    let row = item
                        .variable_id
                        .as_deref()
                        .and_then(|id| by_id.get(id).copied())
                        .filter(|row| {
                            row.lifecycle_status == "ACTIVE"
                                && Some(row.version) == item.base_variable_version
                                && row.key == item.key
                        })
                        .ok_or(AppError::Conflict)?;
                    (
                        row.id.clone(),
                        Some(row.version),
                        Some("ACTIVE"),
                        row.version + 1,
                        decrypt_current_row(pool, crypto, environment, row).await?,
                    )
                }
                _ => return Err(AppError::Conflict),
            };
        let encrypted = crypto
            .encrypt_current_value(
                &active_dek,
                &CurrentValueContext {
                    service_id: &environment.service_id,
                    environment_id: &environment.id,
                    variable_id: &variable_id,
                    version: u64::try_from(version).map_err(|_| AppError::Crypto)?,
                    dek_version: active_dek_version,
                },
                plaintext.as_bytes(),
            )
            .map_err(|_| AppError::Crypto)?;
        prepared.push(PreparedApply {
            request_id: item.change_request_id.clone(),
            item_id: item.id.clone(),
            action: item.action.clone(),
            key: item.key.clone(),
            variable_id,
            expected_version,
            expected_lifecycle,
            version,
            visibility: item.proposed_visibility.clone(),
            value_type: item.proposed_value_type.clone(),
            description: item.proposed_description.clone(),
            encrypted,
            dek_version: active_dek_version_i64,
        });
    }
    Ok(prepared)
}

async fn persist_apply_item(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    environment: &EnvironmentContext,
    write: &PreparedApply,
    now: &str,
) -> Result<(), AppError> {
    let lifecycle = if write.action == "DELETE" {
        "DELETED"
    } else {
        "ACTIVE"
    };
    if write.expected_version.is_none() {
        sqlx::query(
            "INSERT INTO variables(id, environment_id, key, encrypted_value, value_nonce, crypto_version, dek_version, visibility, value_type, description, version, lifecycle_status, deployment_status, created_at, created_by, updated_at, updated_by, last_applied_at, last_applied_by) VALUES(?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 1, 'ACTIVE', 'APPLIED', ?, ?, ?, ?, ?, ?)",
        )
        .bind(&write.variable_id)
        .bind(&environment.id)
        .bind(&write.key)
        .bind(&write.encrypted.ciphertext)
        .bind(write.encrypted.nonce.as_slice())
        .bind(write.dek_version)
        .bind(&write.visibility)
        .bind(&write.value_type)
        .bind(&write.description)
        .bind(now)
        .bind(&session.user.id)
        .bind(now)
        .bind(&session.user.id)
        .bind(now)
        .bind(&session.user.id)
        .execute(&mut **transaction)
        .await?;
    } else {
        let changed = sqlx::query(
            "UPDATE variables SET encrypted_value = ?, value_nonce = ?, crypto_version = 1, dek_version = ?, visibility = ?, value_type = ?, description = ?, version = ?, lifecycle_status = ?, deleted_at = ?, deployment_status = 'APPLIED', updated_at = ?, updated_by = ?, last_applied_at = ?, last_applied_by = ? WHERE id = ? AND environment_id = ? AND version = ? AND lifecycle_status = ?",
        )
        .bind(&write.encrypted.ciphertext)
        .bind(write.encrypted.nonce.as_slice())
        .bind(write.dek_version)
        .bind(&write.visibility)
        .bind(&write.value_type)
        .bind(&write.description)
        .bind(write.version)
        .bind(lifecycle)
        .bind((write.action == "DELETE").then_some(now))
        .bind(now)
        .bind(&session.user.id)
        .bind(now)
        .bind(&session.user.id)
        .bind(&write.variable_id)
        .bind(&environment.id)
        .bind(write.expected_version)
        .bind(write.expected_lifecycle)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::Conflict);
        }
    }
    sqlx::query(
        "INSERT INTO variable_versions(id, variable_id, environment_id, version, operation, encrypted_value, value_nonce, crypto_version, dek_version, visibility, value_type, description, lifecycle_status, changed_by, changed_at, change_request_id, change_request_item_id) VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&write.variable_id)
    .bind(&environment.id)
    .bind(write.version)
    .bind(&write.action)
    .bind(&write.encrypted.ciphertext)
    .bind(write.encrypted.nonce.as_slice())
    .bind(write.dek_version)
    .bind(&write.visibility)
    .bind(&write.value_type)
    .bind(&write.description)
    .bind(lifecycle)
    .bind(&session.user.id)
    .bind(now)
    .bind(&write.request_id)
    .bind(&write.item_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_request_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    request: &WorkflowRequestRow,
    action: &str,
    metadata: serde_json::Value,
    now: &str,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id, environment_id, change_request_id, metadata_json) VALUES(?, ?, ?, ?, ?, ?, ?)")
        .bind(now)
        .bind(&session.user.id)
        .bind(action)
        .bind(&request.service_id)
        .bind(&request.environment_id)
        .bind(&request.id)
        .bind(metadata.to_string())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn validate_title(value: Option<String>) -> Result<Option<String>, AppError> {
    let title = value.map(|value| value.trim().to_owned());
    match title {
        Some(value) if value.chars().count() > MAX_TITLE_CHARS => Err(AppError::InvalidRequest),
        Some(value) if value.is_empty() => Ok(None),
        value => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use sqlx::SqlitePool;
    use time::{Duration, OffsetDateTime};
    use zeroize::Zeroizing;

    use crate::{
        auth::{
            AuthenticatedSession, AuthenticationState, PrivilegedAuthLevel, SessionManager,
            SessionUser,
        },
        config::SessionSettings,
        crypto::CryptoManager,
        db::{initialize_and_validate_key_registry, test_pool},
        environments::{self, EnvironmentInput},
        error::AppError,
        services::{self, ServiceInput},
        users::Role,
        variables::{self, AppliedVariableInput},
    };

    use super::{
        ChangeRequestInput, ChangeRequestItemInput, approve, create, detail, fulfill_value,
        list_visible, mark_applied, preview_resulting,
    };

    #[tokio::test]
    async fn contributor_creates_atomic_multi_item_request_without_restricted_disclosure() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([72; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let contributor = session("contributor", Role::Contributor);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Payments".into(),
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
        let unassigned = create(&pool, &crypto, &contributor, request(&environment_id)).await;
        assert!(matches!(unassigned, Err(AppError::NotFound)));
        sqlx::query("INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) VALUES('contributor', ?, '2026-08-14T00:00:00Z', 'admin')")
            .bind(&service_id)
            .execute(&pool)
            .await
            .unwrap();

        let request_id = create(&pool, &crypto, &contributor, request(&environment_id))
            .await
            .unwrap();
        let status: String = sqlx::query_scalar("SELECT status FROM change_requests WHERE id = ?")
            .bind(&request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "NEEDS_INPUT");
        let variable_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM variables")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(variable_count, 0);
        let encrypted: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_proposed_value FROM change_request_items WHERE key = 'SECRET_TOKEN'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !encrypted
                .windows(b"do-not-return".len())
                .any(|bytes| bytes == b"do-not-return")
        );
        let (_, items) = detail(&pool, &crypto, &contributor, &request_id)
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
        assert!(
            items
                .iter()
                .find(|item| item.key == "SECRET_TOKEN")
                .unwrap()
                .value
                .is_none()
        );
        assert!(
            items
                .iter()
                .find(|item| item.key == "OPERATOR_VALUE")
                .unwrap()
                .value
                .is_none()
        );
        create(&pool, &crypto, &admin, request(&environment_id))
            .await
            .unwrap();
        assert_eq!(list_visible(&pool, &contributor).await.unwrap().len(), 1);
        assert_eq!(list_visible(&pool, &admin).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn duplicate_key_rejects_entire_change_set() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([73; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "API".into(),
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
                name: "prod".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let item = ChangeRequestItemInput {
            action: "ADD".into(),
            key: "DUPLICATE".into(),
            value: Some("one".into()),
            value_source: Some("REQUESTER_PROVIDED".into()),
            visibility: Some("restricted".into()),
            value_type: Some("string".into()),
            description: None,
        };
        let result = create(
            &pool,
            &crypto,
            &admin,
            ChangeRequestInput {
                environment_id,
                title: None,
                reason: "test duplicate".into(),
                items: vec![item.clone(), item],
            },
        )
        .await;
        assert!(matches!(result, Err(AppError::InvalidRequest)));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM change_requests")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn only_recent_operator_can_fulfill_restricted_value() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([74; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let contributor = session("contributor", Role::Contributor);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Worker".into(),
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
                name: "test".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) VALUES('contributor', ?, '2026-08-14T00:00:00Z', 'admin')")
            .bind(&service_id).execute(&pool).await.unwrap();
        let request_id = create(&pool, &crypto, &contributor, request(&environment_id))
            .await
            .unwrap();
        approve(&pool, &admin, &request_id).await.unwrap();
        let approved_status: String =
            sqlx::query_scalar("SELECT status FROM change_requests WHERE id = ?")
                .bind(&request_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(approved_status, "NEEDS_INPUT");
        let item_id: String = sqlx::query_scalar("SELECT id FROM change_request_items WHERE change_request_id = ? AND key = 'OPERATOR_VALUE'")
            .bind(&request_id).fetch_one(&pool).await.unwrap();
        let manager = SessionManager::new(
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
        assert!(matches!(
            fulfill_value(
                &pool,
                &crypto,
                &manager,
                &contributor,
                &item_id,
                "denied".into()
            )
            .await,
            Err(AppError::Forbidden)
        ));
        let operator = session("operator", Role::Operator);
        assert!(matches!(
            fulfill_value(
                &pool,
                &crypto,
                &manager,
                &operator,
                &item_id,
                "too-soon".into()
            )
            .await,
            Err(AppError::Forbidden)
        ));
        let mut recent_operator = operator;
        recent_operator.privileged_authenticated_at = Some(OffsetDateTime::now_utc());
        recent_operator.privileged_auth_level = Some(PrivilegedAuthLevel::Standard);
        fulfill_value(
            &pool,
            &crypto,
            &manager,
            &recent_operator,
            &item_id,
            "operator-secret".into(),
        )
        .await
        .unwrap();
        let status: String = sqlx::query_scalar("SELECT status FROM change_requests WHERE id = ?")
            .bind(&request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "READY_TO_APPLY");
        let (_, items) = detail(&pool, &crypto, &contributor, &request_id)
            .await
            .unwrap();
        assert!(
            items
                .iter()
                .find(|item| item.key == "OPERATOR_VALUE")
                .unwrap()
                .value
                .is_none()
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn workflow_preview_and_atomic_apply_cover_add_update_delete() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([75; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let contributor = session("contributor", Role::Contributor);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Workflow".into(),
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
        variables::import_applied(
            &pool,
            &crypto,
            &admin,
            &environment_id,
            vec![
                applied_input("UPDATE_ME", "old"),
                applied_input("DELETE_ME", "remove"),
            ],
        )
        .await
        .unwrap();
        let request_id = create(
            &pool,
            &crypto,
            &admin,
            ChangeRequestInput {
                environment_id: environment_id.clone(),
                title: Some("Atomic workflow".into()),
                reason: "exercise all actions".into(),
                items: vec![
                    proposed_item("ADD", "ADD_ME", Some("added")),
                    proposed_item("UPDATE", "UPDATE_ME", Some("updated")),
                    proposed_item("DELETE", "DELETE_ME", None),
                ],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            approve(&pool, &contributor, &request_id).await,
            Err(AppError::Forbidden)
        ));
        approve(&pool, &admin, &request_id).await.unwrap();
        let manager = session_manager(&pool, &crypto);
        assert!(matches!(
            preview_resulting(&pool, &crypto, &manager, &admin, vec![request_id.clone()]).await,
            Err(AppError::Forbidden)
        ));
        let recent_admin = recent(session("admin", Role::Administrator));
        let preview = preview_resulting(
            &pool,
            &crypto,
            &manager,
            &recent_admin,
            vec![request_id.clone()],
        )
        .await
        .unwrap();
        assert!(preview.dotenv.contains("ADD_ME=added\n"));
        assert!(preview.dotenv.contains("UPDATE_ME=updated\n"));
        assert!(!preview.dotenv.contains("DELETE_ME"));
        mark_applied(
            &pool,
            &crypto,
            &manager,
            &recent_admin,
            vec![request_id.clone()],
            &preview.fingerprint,
        )
        .await
        .unwrap();
        let status: String = sqlx::query_scalar("SELECT status FROM change_requests WHERE id = ?")
            .bind(&request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "APPLIED");
        let linked_versions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM variable_versions WHERE change_request_id = ?",
        )
        .bind(&request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(linked_versions, 3);
        let deleted: String = sqlx::query_scalar(
            "SELECT lifecycle_status FROM variables WHERE environment_id = ? AND key = 'DELETE_ME'",
        )
        .bind(&environment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(deleted, "DELETED");
        assert!(matches!(
            mark_applied(
                &pool,
                &crypto,
                &manager,
                &recent_admin,
                vec![request_id],
                &preview.fingerprint
            )
            .await,
            Err(AppError::Conflict)
        ));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn stale_or_overlapping_selection_is_rejected_without_partial_apply() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([76; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = recent(session("admin", Role::Administrator));
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Conflicts".into(),
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
        variables::record_applied(
            &pool,
            &crypto,
            &admin,
            &environment_id,
            applied_input("STALE_KEY", "v1"),
        )
        .await
        .unwrap();
        let stale_id = create(
            &pool,
            &crypto,
            &admin,
            ChangeRequestInput {
                environment_id: environment_id.clone(),
                title: None,
                reason: "stale update".into(),
                items: vec![proposed_item("UPDATE", "STALE_KEY", Some("requested"))],
            },
        )
        .await
        .unwrap();
        approve(&pool, &admin, &stale_id).await.unwrap();
        let manager = session_manager(&pool, &crypto);
        let stale_preview =
            preview_resulting(&pool, &crypto, &manager, &admin, vec![stale_id.clone()])
                .await
                .unwrap();
        variables::record_applied(
            &pool,
            &crypto,
            &admin,
            &environment_id,
            applied_input("STALE_KEY", "v2-direct"),
        )
        .await
        .unwrap();
        assert!(matches!(
            mark_applied(
                &pool,
                &crypto,
                &manager,
                &admin,
                vec![stale_id.clone()],
                &stale_preview.fingerprint
            )
            .await,
            Err(AppError::Conflict)
        ));
        let status: String = sqlx::query_scalar("SELECT status FROM change_requests WHERE id = ?")
            .bind(&stale_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "READY_TO_APPLY");
        let linked_versions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM variable_versions WHERE change_request_id = ?",
        )
        .bind(&stale_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(linked_versions, 0);

        let first = create(
            &pool,
            &crypto,
            &admin,
            single_add_request(&environment_id, "OVERLAP", "one"),
        )
        .await
        .unwrap();
        let second = create(
            &pool,
            &crypto,
            &admin,
            single_add_request(&environment_id, "OVERLAP", "two"),
        )
        .await
        .unwrap();
        approve(&pool, &admin, &first).await.unwrap();
        approve(&pool, &admin, &second).await.unwrap();
        assert!(matches!(
            preview_resulting(&pool, &crypto, &manager, &admin, vec![first, second]).await,
            Err(AppError::Conflict)
        ));
        let overlap_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM variables WHERE environment_id = ? AND key = 'OVERLAP'",
        )
        .bind(&environment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(overlap_count, 0);
    }

    fn applied_input(key: &str, value: &str) -> AppliedVariableInput {
        AppliedVariableInput {
            key: key.into(),
            value: value.into(),
            visibility: "public".into(),
            value_type: "string".into(),
            description: None,
            reason: "test setup".into(),
        }
    }

    fn proposed_item(action: &str, key: &str, value: Option<&str>) -> ChangeRequestItemInput {
        ChangeRequestItemInput {
            action: action.into(),
            key: key.into(),
            value: value.map(str::to_owned),
            value_source: value.map(|_| "REQUESTER_PROVIDED".into()),
            visibility: Some("public".into()),
            value_type: Some("string".into()),
            description: None,
        }
    }

    fn single_add_request(environment_id: &str, key: &str, value: &str) -> ChangeRequestInput {
        ChangeRequestInput {
            environment_id: environment_id.into(),
            title: None,
            reason: "overlap test".into(),
            items: vec![proposed_item("ADD", key, Some(value))],
        }
    }

    fn session_manager(pool: &SqlitePool, crypto: &CryptoManager) -> SessionManager {
        SessionManager::new(
            pool.clone(),
            crypto.clone(),
            SessionSettings {
                cookie_name: "test".into(),
                secure_cookie: false,
                idle_timeout: Duration::minutes(30),
                absolute_timeout: Duration::hours(12),
                recent_auth_timeout: Duration::minutes(5),
            },
        )
    }

    fn recent(mut session: AuthenticatedSession) -> AuthenticatedSession {
        session.privileged_authenticated_at = Some(OffsetDateTime::now_utc());
        session.privileged_auth_level = Some(PrivilegedAuthLevel::Standard);
        session
    }

    fn request(environment_id: &str) -> ChangeRequestInput {
        ChangeRequestInput {
            environment_id: environment_id.into(),
            title: Some("Rotate integration settings".into()),
            reason: "credential maintenance".into(),
            items: vec![
                ChangeRequestItemInput {
                    action: "ADD".into(),
                    key: "SECRET_TOKEN".into(),
                    value: Some("do-not-return".into()),
                    value_source: Some("REQUESTER_PROVIDED".into()),
                    visibility: Some("restricted".into()),
                    value_type: Some("string".into()),
                    description: None,
                },
                ChangeRequestItemInput {
                    action: "ADD".into(),
                    key: "OPERATOR_VALUE".into(),
                    value: None,
                    value_source: Some("OPERATOR_PROVIDED".into()),
                    visibility: Some("restricted".into()),
                    value_type: Some("string".into()),
                    description: None,
                },
            ],
        }
    }

    async fn seed_identity(pool: &SqlitePool) {
        let now = "2026-08-14T00:00:00Z";
        sqlx::query("INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org', 'ConfigDeck', ?, ?)")
            .bind(now).bind(now).execute(pool).await.unwrap();
        for (id, email, role) in [
            ("admin", "admin@example.test", "ADMINISTRATOR"),
            ("contributor", "contributor@example.test", "CONTRIBUTOR"),
            ("operator", "operator@example.test", "OPERATOR"),
        ] {
            sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES(?, 'org', ?, ?, 'hash', ?, ?, ?, ?)")
                .bind(id).bind(email).bind(email).bind(role).bind(now).bind(now).bind(now)
                .execute(pool).await.unwrap();
        }
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
}
