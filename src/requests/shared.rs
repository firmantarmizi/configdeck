use super::{
    AppError, AuthenticatedSession, CryptoManager, CurrentValueContext, FromRow, SqlitePool,
    ValidatedSharedInlineEdit, Zeroizing, ensure_mutable, environment_context, environments,
    persist_shared_requests, prepare_shared_request, validate_description, validate_value,
};
use sqlx::SqliteConnection;

#[cfg(test)]
mod tests;

#[derive(FromRow, PartialEq, Eq)]
struct Target {
    environment_id: String,
    id: String,
    key: String,
    version: i64,
    visibility: String,
    value_type: String,
    description: Option<String>,
    group_name: Option<String>,
    display_order: i64,
    encrypted_value: Vec<u8>,
    value_nonce: Vec<u8>,
    dek_version: i64,
}

#[derive(PartialEq, Eq)]
pub(super) struct Snapshot {
    targets: Vec<Target>,
    keys: Vec<KeySnapshot>,
    proposals: Vec<(String, String, i64, String)>,
}

#[derive(FromRow, PartialEq, Eq)]
struct KeySnapshot {
    environment_id: String,
    dek_version: i64,
    wrapped_dek: Vec<u8>,
    wrapped_dek_nonce: Vec<u8>,
    kek_version: i64,
}

impl Snapshot {
    async fn load(
        connection: &mut SqliteConnection,
        input: &ValidatedSharedInlineEdit,
    ) -> Result<Self, AppError> {
        let targets = sqlx::query_as(
            "SELECT v.environment_id, v.id, v.key, v.version, v.visibility, v.value_type, \
             v.description, v.group_name, v.display_order, v.encrypted_value, v.value_nonce, v.dek_version \
             FROM variables v JOIN environments e ON e.id = v.environment_id \
             JOIN services s ON s.id = e.service_id \
             WHERE e.service_id = ? AND e.archived_at IS NULL AND s.archived_at IS NULL \
             AND v.lifecycle_status = 'ACTIVE' AND v.key IN (?, ?) ORDER BY e.id, v.key",
        )
        .bind(&input.service_id).bind(&input.current_key).bind(&input.new_key)
        .fetch_all(&mut *connection).await?;
        let keys = sqlx::query_as(
            "SELECT k.environment_id, k.dek_version, k.wrapped_dek, k.wrapped_dek_nonce, k.kek_version \
             FROM environment_keys k JOIN environments e ON e.id = k.environment_id \
             WHERE e.service_id = ? AND e.archived_at IS NULL AND k.status = 'ACTIVE' ORDER BY e.id",
        ).bind(&input.service_id).fetch_all(&mut *connection).await?;
        let proposals = sqlx::query_as(
            "SELECT i.id, r.status, r.revision, i.proposed_visibility FROM change_request_items i \
             JOIN change_requests r ON r.id = i.change_request_id \
             JOIN environments e ON e.id = r.environment_id \
             WHERE r.service_id = ? AND e.archived_at IS NULL \
             AND r.status IN ('REQUESTED', 'NEEDS_INPUT', 'READY_TO_APPLY') \
             AND i.key IN (?, ?) ORDER BY i.id",
        )
        .bind(&input.service_id)
        .bind(&input.current_key)
        .bind(&input.new_key)
        .fetch_all(connection)
        .await?;
        Ok(Self {
            targets,
            keys,
            proposals,
        })
    }

    pub(super) async fn validate(
        &self,
        connection: &mut SqliteConnection,
        input: &ValidatedSharedInlineEdit,
    ) -> Result<(), AppError> {
        if *self != Self::load(connection, input).await? {
            return Err(AppError::Conflict);
        }
        Ok(())
    }
}

pub(super) async fn create_changed(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    mut input: ValidatedSharedInlineEdit,
) -> Result<usize, AppError> {
    let snapshot = Snapshot::load(&mut *pool.acquire().await?, &input).await?;
    let targets: Vec<_> = snapshot
        .targets
        .iter()
        .filter(|row| row.key == input.current_key)
        .collect();
    if targets.len() != input.values.len() {
        return Err(AppError::Conflict);
    }
    // Never turn this ordinary request path into an equality oracle for masked values.
    // Match the current-value projection used by the comparison page. Pending
    // proposals have their own visibility and do not replace current configuration.
    let public = targets.iter().all(|row| row.visibility == "public");
    let mut prepared = Vec::new();
    for target in targets {
        let environment = environment_context(pool, session, &target.environment_id).await?;
        ensure_mutable(&environment)?;
        let submitted = input
            .values
            .get_mut(&target.environment_id)
            .filter(|value| value.variable_id == target.id && value.base_version == target.version)
            .ok_or(AppError::Conflict)?;
        submitted.description = validate_description(submitted.description.take())?;
        let metadata_changed = input.current_key != input.new_key
            || input.visibility != target.visibility
            || input.value_type != target.value_type
            || submitted.description != target.description;
        match submitted.value_source.as_str() {
            "KEEP_CURRENT" if !metadata_changed => continue,
            "KEEP_CURRENT" | "REQUESTER_PROVIDED" | "OPERATOR_PROVIDED" => (),
            _ => return Err(AppError::InvalidRequest),
        }
        if submitted.value_source == "REQUESTER_PROVIDED" {
            validate_value(&submitted.value, &input.value_type)?;
        }
        if public && submitted.value_source != "OPERATOR_PROVIDED" {
            let value = current_public_value(pool, crypto, &input.service_id, target).await?;
            if submitted.value_source == "KEEP_CURRENT" {
                submitted.value.clone_from(&value);
                submitted.value_source = "REQUESTER_PROVIDED".into();
            } else if form_lines(&submitted.value) == form_lines(&value) {
                if !metadata_changed {
                    continue;
                }
                // Browser form transport normalizes line endings. Retain the stored
                // bytes when only metadata changes, including existing CR/LF values.
                submitted.value.clone_from(&value);
            }
        } else if submitted.value_source == "KEEP_CURRENT" {
            // The ordinary editor cannot reuse/decrypt masked values. A metadata change
            // remains a proposal and the reviewer supplies its value before approval/apply.
            submitted.value.clear();
            submitted.value_source = "OPERATOR_PROVIDED".into();
        }
        prepared.push(
            prepare_shared_request(
                pool,
                crypto,
                session,
                &input,
                &target.environment_id,
                &target.id,
            )
            .await?,
        );
    }
    persist_shared_requests(pool, session, &prepared, &input, &snapshot).await?;
    Ok(prepared.len())
}

fn form_lines(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}

async fn current_public_value(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    service_id: &str,
    target: &Target,
) -> Result<Zeroizing<String>, AppError> {
    let dek_version = u64::try_from(target.dek_version).map_err(|_| AppError::Crypto)?;
    let dek =
        environments::dek_by_version(pool, crypto, &target.environment_id, dek_version).await?;
    let plaintext = crypto
        .decrypt_current_value(
            &dek,
            &CurrentValueContext {
                service_id,
                environment_id: &target.environment_id,
                variable_id: &target.id,
                version: u64::try_from(target.version).map_err(|_| AppError::Crypto)?,
                dek_version,
            },
            &target.encrypted_value,
            &target.value_nonce,
        )
        .map_err(|_| AppError::Crypto)?;
    Ok(Zeroizing::new(
        String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Crypto)?,
    ))
}
