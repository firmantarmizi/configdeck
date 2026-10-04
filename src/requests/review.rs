use super::{
    AppError, AuthenticatedSession, Capability, CryptoManager, EnvironmentContext, HEXLOWER,
    ItemRow, PrivilegedAuthLevel, ProposedValueContext, SessionManager, SqlitePool, Zeroizing,
    authorize_selection, decrypt_proposed_row, ensure_mutable, environment_context, environments,
    insert_request_audit, load_current_rows, load_current_rows_in_transaction, load_workflow_items,
    load_workflow_items_in_transaction, load_workflow_requests,
    load_workflow_requests_in_transaction, normalize_request_ids, now_rfc3339,
    selection_fingerprint, validate_display_order, validate_group_name, validate_selection,
    validate_value,
};

pub struct PreviewEdit {
    pub request_ids: Vec<String>,
    pub fingerprint: String,
    pub item_id: String,
    pub value: Option<String>,
    pub group_name: Option<String>,
    pub display_order: i64,
}

pub struct EditablePreviewItem {
    pub id: String,
    pub key: String,
    pub value: Zeroizing<String>,
    pub group_name: Option<String>,
    pub display_order: i64,
}

pub struct PreviewLine {
    pub number: usize,
    pub text: Zeroizing<String>,
    pub kind: &'static str,
    pub label: &'static str,
}

pub struct DeletedPreviewItem {
    pub key: String,
    pub group_name: Option<String>,
}

pub(super) fn annotate_lines(
    dotenv: &str,
    entries: &[crate::dotenv::Entry],
    items: &[ItemRow],
) -> Vec<PreviewLine> {
    let assignments = entries
        .iter()
        .map(|entry| {
            let action = items
                .iter()
                .find(|item| item.key == entry.key)
                .map(|item| item.action.as_str());
            let marker = match action {
                Some("ADD") => ("add", "NEW"),
                Some("UPDATE") => ("update", "UPDATE"),
                _ => ("unchanged", ""),
            };
            (
                entry.key.as_str(),
                (
                    entry.value.bytes().filter(|byte| *byte == b'\n').count(),
                    marker,
                ),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut remaining = 0;
    let mut marker = ("unchanged", "");
    dotenv
        .split('\n')
        .enumerate()
        .map(|(index, line)| {
            if remaining > 0 {
                remaining -= 1;
            } else {
                marker = ("unchanged", "");
                if let Some((key, _)) = line.split_once('=')
                    && let Some((continuations, assignment_marker)) = assignments.get(key)
                {
                    remaining = *continuations;
                    marker = *assignment_marker;
                }
            }
            PreviewLine {
                number: index + 1,
                text: Zeroizing::new(line.to_owned()),
                kind: marker.0,
                label: marker.1,
            }
        })
        .collect()
}

pub(super) async fn editable_items(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    environment: &EnvironmentContext,
    items: &[ItemRow],
) -> Result<Vec<EditablePreviewItem>, AppError> {
    let mut result = Vec::new();
    for item in items.iter().filter(|item| item.action != "DELETE") {
        result.push(EditablePreviewItem {
            id: item.id.clone(),
            key: item.key.clone(),
            value: Zeroizing::new(decrypt_proposed_row(pool, crypto, environment, item).await?),
            group_name: item.proposed_group_name.clone(),
            display_order: item.proposed_display_order,
        });
    }
    result.sort_by_key(|item| item.display_order);
    Ok(result)
}

/// Save an explicit reviewer correction without changing deployed state.
#[allow(clippy::too_many_lines)]
pub async fn edit_preview(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    input: PreviewEdit,
) -> Result<Vec<String>, AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ReviewRequest)
        || !sessions.has_recent_auth(session, PrivilegedAuthLevel::Standard)
    {
        return Err(AppError::Forbidden);
    }
    let ids = normalize_request_ids(input.request_ids)?;
    let requests = load_workflow_requests(pool, &ids).await?;
    authorize_selection(session, &requests)?;
    let environment = environment_context(pool, session, &requests[0].environment_id).await?;
    ensure_mutable(&environment)?;
    let items = load_workflow_items(pool, &ids).await?;
    validate_selection(&requests, &items)?;
    let current = load_current_rows(pool, &environment.id).await?;
    let fingerprint = selection_fingerprint(&requests, &items, &current);
    if HEXLOWER.encode(&fingerprint) != input.fingerprint
        || requests
            .iter()
            .any(|request| request.preview_fingerprint.as_deref() != Some(&fingerprint))
    {
        return Err(AppError::Conflict);
    }
    let item = items
        .iter()
        .find(|item| item.id == input.item_id && item.action != "DELETE")
        .ok_or(AppError::InvalidRequest)?;
    let previous_value =
        Zeroizing::new(decrypt_proposed_row(pool, crypto, &environment, item).await?);
    let value = Zeroizing::new(input.value.unwrap_or_else(|| previous_value.to_string()));
    validate_value(&value, &item.proposed_value_type)?;
    let group = validate_group_name(input.group_name)?;
    let order = validate_display_order(input.display_order)?;
    let unchanged = *previous_value == *value
        && group == item.proposed_group_name
        && order == item.proposed_display_order;
    let revision = item
        .item_revision
        .checked_add(1)
        .ok_or(AppError::Conflict)?;
    let (dek_version, dek) = environments::active_dek(pool, crypto, &environment.id).await?;
    let encrypted = crypto
        .encrypt_proposed_value(
            &dek,
            &ProposedValueContext {
                service_id: &environment.service_id,
                environment_id: &environment.id,
                change_request_id: &item.change_request_id,
                item_id: &item.id,
                item_revision: u64::try_from(revision).map_err(|_| AppError::Crypto)?,
                dek_version,
            },
            value.as_bytes(),
        )
        .map_err(|_| AppError::Crypto)?;
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    let latest_requests = load_workflow_requests_in_transaction(&mut transaction, &ids).await?;
    authorize_selection(session, &latest_requests)?;
    let latest_items = load_workflow_items_in_transaction(&mut transaction, &ids).await?;
    validate_selection(&latest_requests, &latest_items)?;
    let latest_current =
        load_current_rows_in_transaction(&mut transaction, &environment.id).await?;
    let active: bool = sqlx::query_scalar("SELECT e.archived_at IS NULL AND s.archived_at IS NULL FROM environments e JOIN services s ON s.id = e.service_id WHERE e.id = ?")
        .bind(&environment.id).fetch_one(&mut *transaction).await?;
    let active_dek: i64 = sqlx::query_scalar(
        "SELECT dek_version FROM environment_keys WHERE environment_id = ? AND status = 'ACTIVE'",
    )
    .bind(&environment.id)
    .fetch_one(&mut *transaction)
    .await?;
    if !active
        || u64::try_from(active_dek).ok() != Some(dek_version)
        || selection_fingerprint(&latest_requests, &latest_items, &latest_current) != fingerprint
        || latest_requests
            .iter()
            .any(|request| request.preview_fingerprint.as_deref() != Some(&fingerprint))
    {
        return Err(AppError::Conflict);
    }
    if !unchanged {
        let now = now_rfc3339()?;
        sqlx::query("UPDATE change_request_items SET encrypted_proposed_value = ?, proposed_value_nonce = ?, proposed_crypto_version = 1, proposed_dek_version = ?, proposed_group_name = ?, proposed_display_order = ?, item_revision = ? WHERE id = ?")
            .bind(&encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(active_dek)
            .bind(group).bind(order).bind(revision).bind(&item.id)
            .execute(&mut *transaction).await?;
        sqlx::query("UPDATE change_requests SET revision = revision + 1, preview_fingerprint = NULL, approved_by = ?, approved_at = ? WHERE id = ?")
            .bind(&session.user.id).bind(&now).bind(&item.change_request_id)
            .execute(&mut *transaction).await?;
        let request = latest_requests
            .iter()
            .find(|request| request.id == item.change_request_id)
            .ok_or(AppError::Conflict)?;
        insert_request_audit(
            &mut transaction,
            session,
            request,
            "EDIT_REQUEST",
            serde_json::json!({"item_id": item.id, "version": revision}),
            &now,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(ids)
}
