use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;
use sqlx::{FromRow, Row, SqlitePool};
use uuid::Uuid;

use crate::{
    auth::AuthenticatedSession,
    crypto::{CryptoManager, CurrentValueContext, ProposedValueContext},
    db::now_rfc3339,
    error::AppError,
    services::{map_write_error, validate_description, validate_name},
    users::{Capability, Role, can_access_service},
};

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct EnvironmentRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub archived_at: Option<String>,
    pub variable_count: i64,
    pub is_standard: bool,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ServiceContext {
    pub id: String,
    pub name: String,
    pub archived_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EnvironmentInput {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ComparisonWorkspace {
    pub service: ServiceContext,
    pub environments: Vec<EnvironmentRecord>,
    pub archived_environments: Vec<EnvironmentRecord>,
    pub keys: Vec<ComparisonKey>,
    pub column_count: usize,
}

#[derive(Clone, Debug)]
pub struct ComparisonKey {
    pub key: String,
    pub cells: Vec<ComparisonCell>,
    pub existing_count: usize,
    pub visibility_label: String,
    pub value_type_label: String,
    pub has_present: bool,
    pub has_pending: bool,
    pub has_missing: bool,
}

#[derive(Clone, Debug)]
pub struct ComparisonCell {
    pub environment_id: String,
    pub environment_name: String,
    pub variable_id: Option<String>,
    pub status_label: &'static str,
    pub status_class: &'static str,
    pub value: Option<String>,
    pub visibility: Option<String>,
    pub value_type: Option<String>,
    pub description: Option<String>,
    pub version: Option<i64>,
    pub pending_request_id: Option<String>,
    pub pending_action: Option<String>,
    pub proposed_value: Option<String>,
    pub proposed_visibility: Option<String>,
    pub proposal_state: Option<String>,
}

#[derive(Clone, Debug, FromRow)]
struct ComparisonVariableRow {
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
    deployment_status: String,
}

#[derive(Clone, Debug)]
struct VariableMetadata {
    id: String,
    environment_id: String,
    key: String,
    value: Option<String>,
    visibility: String,
    value_type: String,
    description: Option<String>,
    version: i64,
    deployment_status: String,
}

#[derive(Clone, Debug, FromRow)]
struct PendingKeyRow {
    request_id: String,
    environment_id: String,
    item_id: String,
    key: String,
    action: String,
    encrypted_proposed_value: Option<Vec<u8>>,
    proposed_value_nonce: Option<Vec<u8>>,
    proposed_dek_version: Option<i64>,
    proposed_visibility: String,
    value_fulfilled_at: Option<String>,
    item_revision: i64,
}

#[derive(Clone, Debug)]
struct PendingMetadata {
    request_id: String,
    action: String,
    proposed_value: Option<String>,
    proposed_visibility: String,
    proposal_state: String,
}

async fn load_comparison_variables(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    service_id: &str,
) -> Result<Vec<VariableMetadata>, AppError> {
    let rows = sqlx::query_as::<_, ComparisonVariableRow>(
        "SELECT v.id, v.environment_id, v.key, v.encrypted_value, v.value_nonce, v.dek_version, \
                v.visibility, v.value_type, v.description, v.version, v.deployment_status \
         FROM variables v \
         JOIN environments e ON e.id = v.environment_id \
         WHERE e.service_id = ? AND e.archived_at IS NULL AND v.lifecycle_status = 'ACTIVE' \
         ORDER BY v.key, e.name_normalized",
    )
    .bind(service_id)
    .fetch_all(pool)
    .await?;
    let restricted_keys: HashSet<_> = rows
        .iter()
        .filter(|row| row.visibility == "restricted")
        .map(|row| row.key.clone())
        .collect();
    let mut variables = Vec::with_capacity(rows.len());
    let mut deks = HashMap::new();
    for row in rows {
        let value = if row.visibility == "public" && !restricted_keys.contains(&row.key) {
            let dek_version = u64::try_from(row.dek_version).map_err(|_| AppError::Crypto)?;
            let cache_key = (row.environment_id.clone(), row.dek_version);
            if !deks.contains_key(&cache_key) {
                let dek = dek_by_version(pool, crypto, &row.environment_id, dek_version).await?;
                deks.insert(cache_key.clone(), dek);
            }
            let dek = deks.get(&cache_key).ok_or(AppError::Crypto)?;
            let plaintext = crypto
                .decrypt_current_value(
                    dek,
                    &CurrentValueContext {
                        service_id,
                        environment_id: &row.environment_id,
                        variable_id: &row.id,
                        version: u64::try_from(row.version).map_err(|_| AppError::Crypto)?,
                        dek_version,
                    },
                    &row.encrypted_value,
                    &row.value_nonce,
                )
                .map_err(|_| AppError::Crypto)?;
            Some(String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Crypto)?)
        } else {
            None
        };
        variables.push(VariableMetadata {
            id: row.id,
            environment_id: row.environment_id,
            key: row.key,
            value,
            visibility: row.visibility,
            value_type: row.value_type,
            description: row.description,
            version: row.version,
            deployment_status: row.deployment_status,
        });
    }
    Ok(variables)
}

async fn load_pending_metadata(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    service_id: &str,
) -> Result<HashMap<String, HashMap<String, PendingMetadata>>, AppError> {
    let rows = sqlx::query_as::<_, PendingKeyRow>(
        "SELECT r.id AS request_id, r.environment_id, i.id AS item_id, i.key, i.action, \
                i.encrypted_proposed_value, i.proposed_value_nonce, i.proposed_dek_version, \
                i.proposed_visibility, i.value_fulfilled_at, i.item_revision \
         FROM change_requests r \
         JOIN change_request_items i ON i.change_request_id = r.id \
         JOIN environments e ON e.id = r.environment_id \
         WHERE r.service_id = ? AND e.archived_at IS NULL \
           AND r.status IN ('REQUESTED', 'NEEDS_INPUT', 'READY_TO_APPLY') \
         ORDER BY r.requested_at DESC, r.id DESC, i.key",
    )
    .bind(service_id)
    .fetch_all(pool)
    .await?;
    let mut restricted_keys: HashSet<String> = rows
        .iter()
        .filter(|row| row.proposed_visibility == "restricted")
        .map(|row| row.key.clone())
        .collect();
    restricted_keys.extend(
        sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT v.key FROM variables v \
             JOIN environments e ON e.id = v.environment_id \
             WHERE e.service_id = ? AND e.archived_at IS NULL \
               AND v.lifecycle_status = 'ACTIVE' AND v.visibility = 'restricted'",
        )
        .bind(service_id)
        .fetch_all(pool)
        .await?,
    );
    let mut pending: HashMap<String, HashMap<String, PendingMetadata>> = HashMap::new();
    let mut deks = HashMap::new();
    for row in rows {
        if pending
            .get(&row.environment_id)
            .is_some_and(|keys| keys.contains_key(&row.key))
        {
            continue;
        }
        let fulfilled = row.value_fulfilled_at.is_some();
        let proposal_state = if row.action == "DELETE" {
            "delete".to_owned()
        } else if !fulfilled {
            "awaiting".to_owned()
        } else if restricted_keys.contains(&row.key) {
            "masked".to_owned()
        } else {
            "value".to_owned()
        };
        let proposed_value = if proposal_state == "value" {
            let (Some(ciphertext), Some(nonce), Some(dek_version)) = (
                row.encrypted_proposed_value.as_deref(),
                row.proposed_value_nonce.as_deref(),
                row.proposed_dek_version,
            ) else {
                return Err(AppError::Crypto);
            };
            let dek_version_u64 = u64::try_from(dek_version).map_err(|_| AppError::Crypto)?;
            let cache_key = (row.environment_id.clone(), dek_version);
            if !deks.contains_key(&cache_key) {
                let dek =
                    dek_by_version(pool, crypto, &row.environment_id, dek_version_u64).await?;
                deks.insert(cache_key.clone(), dek);
            }
            let dek = deks.get(&cache_key).ok_or(AppError::Crypto)?;
            let plaintext = crypto
                .decrypt_proposed_value(
                    dek,
                    &ProposedValueContext {
                        service_id,
                        environment_id: &row.environment_id,
                        change_request_id: &row.request_id,
                        item_id: &row.item_id,
                        item_revision: u64::try_from(row.item_revision)
                            .map_err(|_| AppError::Crypto)?,
                        dek_version: dek_version_u64,
                    },
                    ciphertext,
                    nonce,
                )
                .map_err(|_| AppError::Crypto)?;
            Some(String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Crypto)?)
        } else {
            None
        };
        pending.entry(row.environment_id).or_default().insert(
            row.key,
            PendingMetadata {
                request_id: row.request_id,
                action: row.action,
                proposed_value,
                proposed_visibility: row.proposed_visibility,
                proposal_state,
            },
        );
    }
    Ok(pending)
}

fn comparison_key(
    key: String,
    metadata: &HashMap<String, VariableMetadata>,
    environments: &[EnvironmentRecord],
    pending: &HashMap<String, HashMap<String, PendingMetadata>>,
) -> ComparisonKey {
    let mut cells: Vec<_> = environments
        .iter()
        .map(|environment| {
            let variable = metadata.get(&environment.id);
            let proposal = pending.get(&environment.id).and_then(|keys| keys.get(&key));
            let has_pending = proposal.is_some();
            let (status_label, status_class) = match (variable, has_pending) {
                (Some(_), true) => ("Pending change", "pending"),
                (Some(variable), false) if variable.deployment_status == "NOT_APPLIED" => {
                    ("Not applied", "pending")
                }
                (Some(_), false) => ("Present", "present"),
                (None, true) => ("Proposed", "pending"),
                (None, false) => ("Missing", "missing"),
            };
            ComparisonCell {
                environment_id: environment.id.clone(),
                environment_name: environment.name.clone(),
                variable_id: variable.map(|value| value.id.clone()),
                status_label,
                status_class,
                value: variable.and_then(|value| value.value.clone()),
                visibility: variable.map(|value| value.visibility.clone()),
                value_type: variable.map(|value| value.value_type.clone()),
                description: variable.and_then(|value| value.description.clone()),
                version: variable.map(|value| value.version),
                pending_request_id: proposal.map(|value| value.request_id.clone()),
                pending_action: proposal.map(|value| value.action.clone()),
                proposed_value: proposal.and_then(|value| value.proposed_value.clone()),
                proposed_visibility: proposal.map(|value| value.proposed_visibility.clone()),
                proposal_state: proposal.map(|value| value.proposal_state.clone()),
            }
        })
        .collect();
    let visibilities: HashSet<_> = cells
        .iter()
        .filter_map(|cell| cell.visibility.as_deref())
        .collect();
    let value_types: HashSet<_> = cells
        .iter()
        .filter_map(|cell| cell.value_type.as_deref())
        .collect();
    let visibility_label = match visibilities.len() {
        0 => "Missing".to_owned(),
        1 => (*visibilities.iter().next().expect("one visibility")).to_owned(),
        _ => "Inconsistent".to_owned(),
    };
    let value_type_label = match value_types.len() {
        0 => "No type".to_owned(),
        1 => (*value_types.iter().next().expect("one value type")).to_owned(),
        _ => "Inconsistent type".to_owned(),
    };
    if visibilities.len() > 1 {
        for cell in &mut cells {
            cell.value = None;
        }
    }
    ComparisonKey {
        key,
        existing_count: cells
            .iter()
            .filter(|cell| cell.variable_id.is_some())
            .count(),
        visibility_label,
        value_type_label,
        has_present: cells.iter().any(|cell| cell.status_class == "present"),
        has_pending: cells.iter().any(|cell| cell.status_class == "pending"),
        has_missing: cells.iter().any(|cell| cell.status_class == "missing"),
        cells,
    }
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct KeySearchResult {
    pub environment_id: String,
    pub app_name: String,
    pub environment_name: String,
    pub key: String,
    pub visibility: String,
    pub value_type: String,
}

pub async fn list_for_service(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    service_id: &str,
) -> Result<(ServiceContext, Vec<EnvironmentRecord>), AppError> {
    session.require_full()?;
    let service = service_context(pool, session, service_id).await?;
    let rows = sqlx::query_as::<_, EnvironmentRecord>(
        "SELECT e.id, e.name, e.description, e.archived_at, \
                COUNT(v.id) AS variable_count, \
                e.name_normalized IN ('development', 'staging', 'production') AS is_standard \
         FROM environments e \
         LEFT JOIN variables v ON v.environment_id = e.id AND v.lifecycle_status = 'ACTIVE' \
         WHERE e.service_id = ? \
         GROUP BY e.id, e.name, e.name_normalized, e.description, e.archived_at \
         ORDER BY e.archived_at IS NOT NULL, CASE e.name_normalized WHEN 'development' THEN 1 WHEN 'staging' THEN 2 WHEN 'production' THEN 3 ELSE 4 END, e.name_normalized",
    )
    .bind(service_id)
    .fetch_all(pool)
    .await?;
    Ok((service, rows))
}

/// Returns only configuration metadata needed by the cross-environment workspace.
/// Restricted plaintext is never decrypted. Public values are decrypted only after the
/// service-scope authorization check and are used for the inline comparison details.
pub async fn comparison_for_service(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    service_id: &str,
) -> Result<ComparisonWorkspace, AppError> {
    let (service, all_environments) = list_for_service(pool, session, service_id).await?;
    let (environments, archived_environments): (Vec<_>, Vec<_>) = all_environments
        .into_iter()
        .partition(|environment| environment.archived_at.is_none());

    let variables = load_comparison_variables(pool, crypto, &service.id).await?;
    let pending_by_environment = load_pending_metadata(pool, crypto, &service.id).await?;

    let mut by_key: BTreeMap<String, HashMap<String, VariableMetadata>> = BTreeMap::new();
    for variable in variables {
        by_key
            .entry(variable.key.clone())
            .or_default()
            .insert(variable.environment_id.clone(), variable);
    }
    for keys in pending_by_environment.values() {
        for key in keys.keys() {
            by_key.entry(key.clone()).or_default();
        }
    }

    let keys = by_key
        .into_iter()
        .map(|(key, metadata)| {
            comparison_key(key, &metadata, &environments, &pending_by_environment)
        })
        .collect();

    Ok(ComparisonWorkspace {
        service,
        column_count: environments.len() + 1,
        environments,
        archived_environments,
        keys,
    })
}

/// Searches portable key names across the caller's authorized App scope.
/// Values and encryption material are intentionally not part of the result projection.
pub async fn search_accessible_keys(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    query: &str,
) -> Result<Vec<KeySearchResult>, AppError> {
    session.require_full()?;
    let query = query.trim();
    if query.chars().count() < 2 {
        return Ok(Vec::new());
    }
    if query.chars().count() > 100 {
        return Err(AppError::InvalidRequest);
    }
    let rows = if session.user.role == Role::Contributor {
        sqlx::query_as::<_, KeySearchResult>(
            "SELECT e.id AS environment_id, s.name AS app_name, e.name AS environment_name, \
                    v.key, v.visibility, v.value_type \
             FROM variables v \
             JOIN environments e ON e.id = v.environment_id \
             JOIN services s ON s.id = e.service_id \
             JOIN user_service_access access ON access.service_id = s.id AND access.user_id = ? \
             WHERE s.organization_id = ? AND s.archived_at IS NULL AND e.archived_at IS NULL \
               AND v.lifecycle_status = 'ACTIVE' AND instr(upper(v.key), upper(?)) > 0 \
             ORDER BY v.key, s.name_normalized, e.name_normalized LIMIT 20",
        )
        .bind(&session.user.id)
        .bind(&session.user.organization_id)
        .bind(query)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, KeySearchResult>(
            "SELECT e.id AS environment_id, s.name AS app_name, e.name AS environment_name, \
                    v.key, v.visibility, v.value_type \
             FROM variables v \
             JOIN environments e ON e.id = v.environment_id \
             JOIN services s ON s.id = e.service_id \
             WHERE s.organization_id = ? AND s.archived_at IS NULL AND e.archived_at IS NULL \
               AND v.lifecycle_status = 'ACTIVE' AND instr(upper(v.key), upper(?)) > 0 \
             ORDER BY v.key, s.name_normalized, e.name_normalized LIMIT 20",
        )
        .bind(&session.user.organization_id)
        .bind(query)
        .fetch_all(pool)
        .await?
    };
    Ok(rows)
}

pub async fn create(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    service_id: &str,
    input: EnvironmentInput,
) -> Result<String, AppError> {
    require_manage_metadata(session)?;
    let (name, normalized) = validate_name(&input.name)?;
    let description = validate_description(input.description)?;
    let environment_id = Uuid::new_v4().to_string();
    let environment_key_id = Uuid::new_v4().to_string();
    let now = now_rfc3339().map_err(AppError::Internal)?;

    let mut transaction = pool.begin().await?;
    let service_archived: Option<String> =
        sqlx::query_scalar("SELECT archived_at FROM services WHERE id = ? AND organization_id = ?")
            .bind(service_id)
            .bind(&session.user.organization_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(AppError::NotFound)?;
    if service_archived.is_some() {
        return Err(AppError::Conflict);
    }
    let kek_version: i64 =
        sqlx::query_scalar("SELECT kek_version FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_one(&mut *transaction)
            .await?;
    let kek_version_u64 = u64::try_from(kek_version).map_err(|_| AppError::Crypto)?;
    let dek = crypto.generate_dek().map_err(|_| AppError::Crypto)?;
    let wrapped = crypto
        .wrap_dek(&environment_id, 1, kek_version_u64, &dek)
        .map_err(|_| AppError::Crypto)?;

    sqlx::query(
        "INSERT INTO environments(\
            id, service_id, name, name_normalized, description, created_at, updated_at, created_by, updated_by\
         ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&environment_id)
    .bind(service_id)
    .bind(name)
    .bind(normalized)
    .bind(description)
    .bind(&now)
    .bind(&now)
    .bind(&session.user.id)
    .bind(&session.user.id)
    .execute(&mut *transaction)
    .await
    .map_err(map_write_error)?;
    sqlx::query(
        "INSERT INTO environment_keys(\
            id, environment_id, dek_version, wrapped_dek, wrapped_dek_nonce, crypto_version, kek_version, status, created_at\
         ) VALUES(?, ?, 1, ?, ?, 1, ?, 'ACTIVE', ?)",
    )
    .bind(environment_key_id)
    .bind(&environment_id)
    .bind(wrapped.ciphertext)
    .bind(wrapped.nonce.as_slice())
    .bind(kek_version)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    audit_environment(
        &mut transaction,
        session,
        service_id,
        &environment_id,
        "CREATE_ENVIRONMENT",
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(environment_id)
}

pub async fn update(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    environment_id: &str,
    input: EnvironmentInput,
) -> Result<String, AppError> {
    require_manage_metadata(session)?;
    let (name, normalized) = validate_name(&input.name)?;
    let description = validate_description(input.description)?;
    let now = now_rfc3339().map_err(AppError::Internal)?;
    let mut transaction = pool.begin().await?;
    let service_id: String = sqlx::query_scalar(
        "SELECT e.service_id FROM environments e \
         JOIN services s ON s.id = e.service_id \
         WHERE e.id = ? AND s.organization_id = ?",
    )
    .bind(environment_id)
    .bind(&session.user.organization_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AppError::NotFound)?;
    sqlx::query(
        "UPDATE environments SET name = ?, name_normalized = ?, description = ?, updated_at = ?, updated_by = ? \
         WHERE id = ?",
    )
    .bind(name)
    .bind(normalized)
    .bind(description)
    .bind(&now)
    .bind(&session.user.id)
    .bind(environment_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_write_error)?;
    audit_environment(
        &mut transaction,
        session,
        &service_id,
        environment_id,
        "UPDATE_ENVIRONMENT",
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(service_id)
}

pub async fn set_archived(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    environment_id: &str,
    archived: bool,
) -> Result<String, AppError> {
    require_manage_metadata(session)?;
    let now = now_rfc3339().map_err(AppError::Internal)?;
    let mut transaction = pool.begin().await?;
    let service_id: String = sqlx::query_scalar(
        "SELECT e.service_id FROM environments e \
         JOIN services s ON s.id = e.service_id \
         WHERE e.id = ? AND s.organization_id = ?",
    )
    .bind(environment_id)
    .bind(&session.user.organization_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AppError::NotFound)?;
    sqlx::query(
        "UPDATE environments SET archived_at = ?, updated_at = ?, updated_by = ? WHERE id = ?",
    )
    .bind(archived.then_some(now.as_str()))
    .bind(&now)
    .bind(&session.user.id)
    .bind(environment_id)
    .execute(&mut *transaction)
    .await?;
    let action = if archived {
        "ARCHIVE_ENVIRONMENT"
    } else {
        "RESTORE_ENVIRONMENT"
    };
    audit_environment(
        &mut transaction,
        session,
        &service_id,
        environment_id,
        action,
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(service_id)
}

async fn service_context(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    service_id: &str,
) -> Result<ServiceContext, AppError> {
    let service = sqlx::query_as::<_, ServiceContext>(
        "SELECT id, name, archived_at FROM services WHERE id = ? AND organization_id = ?",
    )
    .bind(service_id)
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    if !can_access_service(pool, &session.user.id, session.user.role, service_id).await? {
        return Err(AppError::NotFound);
    }
    Ok(service)
}

fn require_manage_metadata(session: &AuthenticatedSession) -> Result<(), AppError> {
    session.require_full()?;
    if session.user.role.allows(Capability::ManageMetadata) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

async fn audit_environment(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    service_id: &str,
    environment_id: &str,
    action: &str,
    now: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO audit_logs(\
            occurred_at, actor_user_id, action, service_id, environment_id\
         ) VALUES(?, ?, ?, ?, ?)",
    )
    .bind(now)
    .bind(&session.user.id)
    .bind(action)
    .bind(service_id)
    .bind(environment_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub async fn active_dek(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment_id: &str,
) -> Result<(u64, zeroize::Zeroizing<[u8; 32]>), AppError> {
    let row = sqlx::query(
        "SELECT dek_version, kek_version, wrapped_dek, wrapped_dek_nonce \
         FROM environment_keys WHERE environment_id = ? AND status = 'ACTIVE'",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::Crypto)?;
    let dek_version =
        u64::try_from(row.try_get::<i64, _>("dek_version")?).map_err(|_| AppError::Crypto)?;
    let kek_version =
        u64::try_from(row.try_get::<i64, _>("kek_version")?).map_err(|_| AppError::Crypto)?;
    let wrapped_dek: Vec<u8> = row.try_get("wrapped_dek")?;
    let nonce: Vec<u8> = row.try_get("wrapped_dek_nonce")?;
    let dek = crypto
        .unwrap_dek(
            environment_id,
            dek_version,
            kek_version,
            &wrapped_dek,
            &nonce,
        )
        .map_err(|_| AppError::Crypto)?;
    Ok((dek_version, dek))
}

pub async fn dek_by_version(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment_id: &str,
    dek_version: u64,
) -> Result<zeroize::Zeroizing<[u8; 32]>, AppError> {
    let dek_version_i64 = i64::try_from(dek_version).map_err(|_| AppError::Crypto)?;
    let row = sqlx::query(
        "SELECT kek_version, wrapped_dek, wrapped_dek_nonce FROM environment_keys \
         WHERE environment_id = ? AND dek_version = ? AND wrapped_dek IS NOT NULL",
    )
    .bind(environment_id)
    .bind(dek_version_i64)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::Crypto)?;
    let kek_version =
        u64::try_from(row.try_get::<i64, _>("kek_version")?).map_err(|_| AppError::Crypto)?;
    let wrapped_dek: Vec<u8> = row.try_get("wrapped_dek")?;
    let nonce: Vec<u8> = row.try_get("wrapped_dek_nonce")?;
    crypto
        .unwrap_dek(
            environment_id,
            dek_version,
            kek_version,
            &wrapped_dek,
            &nonce,
        )
        .map_err(|_| AppError::Crypto)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use crate::{
        auth::{AuthenticatedSession, AuthenticationState, SessionUser},
        crypto::CryptoManager,
        db::{initialize_and_validate_key_registry, test_pool},
        error::AppError,
        requests::{self, ChangeRequestInput, ChangeRequestItemInput},
        services::{self, ServiceInput},
        users::Role,
        variables::{self, AppliedVariableInput},
    };

    use super::{
        EnvironmentInput, active_dek, comparison_for_service, create, list_for_service,
        search_accessible_keys, set_archived,
    };

    #[tokio::test]
    async fn environment_creation_atomically_creates_an_active_dek() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([31; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
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
        let environment_id = create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: " Staging ".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let (version, dek) = active_dek(&pool, &crypto, &environment_id).await.unwrap();
        assert_eq!(version, 1);
        assert_eq!(dek.len(), 32);
        let (_, environments) = list_for_service(&pool, &admin, &service_id).await.unwrap();
        assert_eq!(environments[0].name, "Staging");
        assert!(environments[0].is_standard);

        let contributor = session("contributor", Role::Contributor);
        assert!(matches!(
            list_for_service(&pool, &contributor, &service_id).await,
            Err(AppError::NotFound)
        ));
        assert!(
            create(
                &pool,
                &crypto,
                &contributor,
                &service_id,
                EnvironmentInput {
                    name: "production".into(),
                    description: None,
                },
            )
            .await
            .is_err()
        );

        services::set_archived(&pool, &admin, &service_id, true)
            .await
            .unwrap();
        let blocked = create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "production".into(),
                description: None,
            },
        )
        .await;
        assert!(matches!(blocked, Err(AppError::Conflict)));
    }

    #[tokio::test]
    async fn custom_environment_archive_is_visible_for_restore_but_not_comparison() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([32; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Custom targets".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let qa_id = create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "QA".into(),
                description: Some("Custom test target".into()),
            },
        )
        .await
        .unwrap();
        let (_, environments) = list_for_service(&pool, &admin, &service_id).await.unwrap();
        assert!(
            environments
                .iter()
                .any(|environment| environment.id == qa_id && !environment.is_standard)
        );

        set_archived(&pool, &admin, &qa_id, true).await.unwrap();
        let comparison = comparison_for_service(&pool, &crypto, &admin, &service_id)
            .await
            .unwrap();
        assert!(
            comparison
                .environments
                .iter()
                .all(|environment| environment.id != qa_id)
        );
        assert!(
            comparison
                .archived_environments
                .iter()
                .any(|environment| environment.id == qa_id)
        );
    }

    #[tokio::test]
    async fn comparison_is_access_scoped_and_masks_restricted_values() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([19; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let contributor = session("contributor", Role::Contributor);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Comparison App".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let staging_id = create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "Staging".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "Production".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO variables(\
                id, environment_id, key, encrypted_value, value_nonce, dek_version, visibility, value_type, \
                version, created_at, created_by, updated_at, updated_by\
             ) VALUES('variable', ?, 'API_TOKEN', ?, ?, 1, 'restricted', 'string', 1, ?, 'admin', ?, 'admin')",
        )
        .bind(&staging_id)
        .bind(b"classified-value".as_slice())
        .bind([7_u8; 12].as_slice())
        .bind("2026-08-17T00:00:00Z")
        .bind("2026-08-17T00:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        assert!(matches!(
            comparison_for_service(&pool, &crypto, &contributor, &service_id).await,
            Err(AppError::NotFound)
        ));
        assert!(
            search_accessible_keys(&pool, &contributor, "TOKEN")
                .await
                .unwrap()
                .is_empty()
        );
        sqlx::query(
            "INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) \
             VALUES('contributor', ?, '2026-08-17T00:00:00Z', 'admin')",
        )
        .bind(&service_id)
        .execute(&pool)
        .await
        .unwrap();

        let workspace = comparison_for_service(&pool, &crypto, &contributor, &service_id)
            .await
            .unwrap();
        assert_eq!(workspace.keys.len(), 1);
        assert_eq!(workspace.keys[0].key, "API_TOKEN");
        assert!(workspace.keys[0].has_present);
        assert!(workspace.keys[0].has_missing);
        assert_eq!(
            workspace.keys[0].cells[0].visibility.as_deref(),
            Some("restricted")
        );
        assert!(!format!("{workspace:?}").contains("classified-value"));
        let results = search_accessible_keys(&pool, &contributor, "token")
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "API_TOKEN");
        assert_eq!(results[0].visibility, "restricted");
        assert!(!format!("{results:?}").contains("classified-value"));
    }

    #[tokio::test]
    async fn comparison_decrypts_public_value_after_service_authorization() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([21; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Public Comparison".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let environment_id = create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "Development".into(),
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
            AppliedVariableInput {
                key: "PUBLIC_HOST".into(),
                value: "example.internal".into(),
                visibility: "public".into(),
                value_type: "string".into(),
                description: Some("Public endpoint".into()),
                group_name: Some("Application".into()),
                display_order: 0,
                reason: "seed comparison".into(),
            },
        )
        .await
        .unwrap();

        let workspace = comparison_for_service(&pool, &crypto, &admin, &service_id)
            .await
            .unwrap();
        assert_eq!(workspace.keys.len(), 1);
        assert_eq!(
            workspace.keys[0].cells[0].value.as_deref(),
            Some("example.internal")
        );
        assert_eq!(
            workspace.keys[0].cells[0].description.as_deref(),
            Some("Public endpoint")
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn comparison_exposes_public_proposal_but_never_restricted_proposal() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([22; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let service_id = services::create(
            &pool,
            &admin,
            ServiceInput {
                name: "Proposal comparison".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let environment_id = create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "Development".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let restricted_environment_id = create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "Production".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        for (key, value, visibility) in [
            ("PUBLIC_HOST", "current.example", "public"),
            ("API_TOKEN", "current-secret", "restricted"),
            ("MIXED_KEY", "current-public", "public"),
        ] {
            variables::record_applied(
                &pool,
                &crypto,
                &admin,
                &environment_id,
                AppliedVariableInput {
                    key: key.into(),
                    value: value.into(),
                    visibility: visibility.into(),
                    value_type: "string".into(),
                    description: None,
                    group_name: None,
                    display_order: 0,
                    reason: "seed proposal comparison".into(),
                },
            )
            .await
            .unwrap();
        }
        variables::record_applied(
            &pool,
            &crypto,
            &admin,
            &restricted_environment_id,
            AppliedVariableInput {
                key: "MIXED_KEY".into(),
                value: "current-restricted".into(),
                visibility: "restricted".into(),
                value_type: "string".into(),
                description: None,
                group_name: None,
                display_order: 0,
                reason: "seed inconsistent visibility".into(),
            },
        )
        .await
        .unwrap();
        requests::create(
            &pool,
            &crypto,
            &admin,
            ChangeRequestInput {
                environment_id: environment_id.clone(),
                title: Some("Update comparison values".into()),
                reason: "Verify proposal presentation".into(),
                items: vec![
                    ChangeRequestItemInput {
                        action: "UPDATE".into(),
                        key: "PUBLIC_HOST".into(),
                        value: Some("preview.example".into()),
                        value_source: Some("REQUESTER_PROVIDED".into()),
                        visibility: Some("public".into()),
                        value_type: Some("string".into()),
                        description: None,
                        group_name: None,
                        display_order: None,
                    },
                    ChangeRequestItemInput {
                        action: "UPDATE".into(),
                        key: "API_TOKEN".into(),
                        value: Some("proposed-secret".into()),
                        value_source: Some("REQUESTER_PROVIDED".into()),
                        visibility: Some("restricted".into()),
                        value_type: Some("string".into()),
                        description: None,
                        group_name: None,
                        display_order: None,
                    },
                    ChangeRequestItemInput {
                        action: "UPDATE".into(),
                        key: "MIXED_KEY".into(),
                        value: Some("mixed-public-proposal".into()),
                        value_source: Some("REQUESTER_PROVIDED".into()),
                        visibility: Some("public".into()),
                        value_type: Some("string".into()),
                        description: None,
                        group_name: None,
                        display_order: None,
                    },
                ],
            },
        )
        .await
        .unwrap();

        let workspace = comparison_for_service(&pool, &crypto, &admin, &service_id)
            .await
            .unwrap();
        let public = workspace
            .keys
            .iter()
            .find(|row| row.key == "PUBLIC_HOST")
            .unwrap();
        assert_eq!(public.cells[0].proposal_state.as_deref(), Some("value"));
        assert_eq!(
            public.cells[0].proposed_value.as_deref(),
            Some("preview.example")
        );
        let restricted = workspace
            .keys
            .iter()
            .find(|row| row.key == "API_TOKEN")
            .unwrap();
        assert_eq!(
            restricted.cells[0].proposal_state.as_deref(),
            Some("masked")
        );
        assert!(restricted.cells[0].proposed_value.is_none());
        assert!(!format!("{workspace:?}").contains("proposed-secret"));
        let mixed = workspace
            .keys
            .iter()
            .find(|row| row.key == "MIXED_KEY")
            .unwrap();
        assert_eq!(mixed.visibility_label, "Inconsistent");
        assert!(mixed.cells.iter().all(|cell| cell.value.is_none()));
        let mixed_proposal = mixed
            .cells
            .iter()
            .find(|cell| cell.environment_id == environment_id)
            .unwrap();
        assert_eq!(mixed_proposal.proposal_state.as_deref(), Some("masked"));
        assert!(mixed_proposal.proposed_value.is_none());
        let debug = format!("{workspace:?}");
        assert!(!debug.contains("current-public"));
        assert!(!debug.contains("mixed-public-proposal"));
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
