use super::{
    AppError, CryptoManager, CurrentRow, CurrentValueContext, EnvironmentContext, PreparedItem,
    SqlitePool, load_current_rows, load_current_rows_in_transaction,
};

pub(super) struct Snapshot {
    rows: Vec<CurrentRow>,
    key: (i64, i64, Vec<u8>, Vec<u8>),
}

const KEY_SQL: &str = "SELECT dek_version, kek_version, wrapped_dek, wrapped_dek_nonce FROM environment_keys WHERE environment_id = ? AND status = 'ACTIVE'";

impl Snapshot {
    pub(super) async fn capture(
        pool: &SqlitePool,
        environment_id: &str,
        version: i64,
    ) -> Result<Self, AppError> {
        let key: (i64, i64, Vec<u8>, Vec<u8>) = sqlx::query_as(KEY_SQL)
            .bind(environment_id)
            .fetch_one(pool)
            .await?;
        if key.0 != version {
            return Err(AppError::Conflict);
        }
        Ok(Self {
            rows: load_current_rows(pool, environment_id).await?,
            key,
        })
    }

    pub(super) fn unchanged(
        &self,
        crypto: &CryptoManager,
        environment: &EnvironmentContext,
        item: &PreparedItem,
        value: Option<&str>,
        dek: &[u8; 32],
    ) -> Result<bool, AppError> {
        if item.action != "UPDATE" || item.value_source.as_deref() != Some("REQUESTER_PROVIDED") {
            return Ok(false);
        }
        let Some(current) = self
            .rows
            .iter()
            .find(|row| Some(&row.id) == item.variable_id.as_ref())
        else {
            return Ok(false);
        };
        // Restricted equality must never be observable through request creation.
        if current.visibility != "public"
            || item.visibility != current.visibility
            || item.value_type != current.value_type
            || item.description != current.description
            || item.group_name != current.group_name
            || item.display_order != current.display_order
        {
            return Ok(false);
        }
        if Some(current.version) != item.base_version
            || current.dek_version != self.key.0
            || current.lifecycle_status != "ACTIVE"
        {
            return Err(AppError::Conflict);
        }
        let plaintext = crypto
            .decrypt_current_value(
                dek,
                &CurrentValueContext {
                    service_id: &environment.service_id,
                    environment_id: &environment.id,
                    variable_id: &current.id,
                    version: u64::try_from(current.version).map_err(|_| AppError::Crypto)?,
                    dek_version: u64::try_from(current.dek_version)
                        .map_err(|_| AppError::Crypto)?,
                },
                &current.encrypted_value,
                &current.value_nonce,
            )
            .map_err(|_| AppError::Crypto)?;
        Ok(value.is_some_and(|value| value.as_bytes() == plaintext.as_slice()))
    }

    pub(super) async fn validate(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        environment_id: &str,
    ) -> Result<(), AppError> {
        let key = sqlx::query_as(KEY_SQL)
            .bind(environment_id)
            .fetch_one(&mut **transaction)
            .await?;
        let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM environments e JOIN services s ON s.id = e.service_id WHERE e.id = ? AND e.archived_at IS NULL AND s.archived_at IS NULL")
            .bind(environment_id).fetch_one(&mut **transaction).await?;
        if active != 1
            || self.key != key
            || self.rows != load_current_rows_in_transaction(transaction, environment_id).await?
        {
            return Err(AppError::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::{initialize_and_validate_key_registry, test_pool},
        requests::{
            ChangeRequestInput, ChangeRequestItemInput, create,
            tests::{seed_identity, session},
        },
        services::{self, ServiceInput},
        users::Role,
        variables::{self, AppliedVariableInput},
    };
    use zeroize::Zeroizing;

    fn item(action: &str, key: &str, value: &str) -> ChangeRequestItemInput {
        ChangeRequestItemInput {
            action: action.into(),
            key: key.into(),
            value: Some(value.into()),
            value_source: Some("REQUESTER_PROVIDED".into()),
            visibility: Some("public".into()),
            value_type: Some("integer".into()),
            description: None,
            group_name: None,
            display_order: None,
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn bulk_public_noops_skip_without_hiding_metadata_changes_or_invalid_input() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([83; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let app = services::create_with_default_environments(
            &pool,
            &crypto,
            &admin,
            ServiceInput {
                name: "Noop requests".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let env: String =
            sqlx::query_scalar("SELECT id FROM environments WHERE service_id = ? LIMIT 1")
                .bind(&app)
                .fetch_one(&pool)
                .await
                .unwrap();
        for (key, value) in [("TIMEOUT", "120"), ("TRIES", "25")] {
            variables::record_applied(
                &pool,
                &crypto,
                &admin,
                &env,
                AppliedVariableInput {
                    key: key.into(),
                    value: value.into(),
                    visibility: "public".into(),
                    value_type: "integer".into(),
                    description: None,
                    group_name: Some("STORAGE".into()),
                    display_order: 0,
                    reason: "Synthetic fixture".into(),
                },
            )
            .await
            .unwrap();
        }
        let input = ChangeRequestInput {
            environment_id: env.clone(),
            title: None,
            reason: "Synthetic edit".into(),
            items: vec![
                item("UPDATE", "TIMEOUT", "120"),
                item("UPDATE", "TRIES", "25"),
            ],
        };
        let before: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM change_requests), (SELECT COUNT(*) FROM audit_logs), (SELECT COUNT(*) FROM variable_versions)").fetch_one(&pool).await.unwrap();
        assert!(matches!(
            create(&pool, &crypto, &admin, input.clone()).await,
            Err(AppError::NoChanges)
        ));
        let after = sqlx::query_as("SELECT (SELECT COUNT(*) FROM change_requests), (SELECT COUNT(*) FROM audit_logs), (SELECT COUNT(*) FROM variable_versions)").fetch_one(&pool).await.unwrap();
        assert_eq!(before, after);
        let mut mixed = input.clone();
        mixed.items.extend([
            item("ADD", "MAX_ATTEMPTS", "5"),
            item("ADD", "LEASE_SECONDS", "180"),
        ]);
        let id = create(&pool, &crypto, &admin, mixed).await.unwrap();
        let keys: Vec<String> = sqlx::query_scalar(
            "SELECT key FROM change_request_items WHERE change_request_id = ? ORDER BY key",
        )
        .bind(&id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(keys, ["LEASE_SECONDS", "MAX_ATTEMPTS"]);
        let mut changed = input.clone();
        changed.items[0].group_name = Some("TIMEOUTS".into());
        let id = create(&pool, &crypto, &admin, changed).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM change_request_items WHERE change_request_id = ?"
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        let mut invalid = input;
        invalid.items.push(item("ADD", "INVALID", "not-an-integer"));
        assert!(matches!(
            create(&pool, &crypto, &admin, invalid).await,
            Err(AppError::InvalidRequest)
        ));
        sqlx::query("UPDATE variables SET visibility = 'restricted', encrypted_value = zeroblob(16) WHERE key = 'TIMEOUT'").execute(&pool).await.unwrap();
        let mut restricted = item("UPDATE", "TIMEOUT", "120");
        restricted.visibility = Some("restricted".into());
        let id = create(
            &pool,
            &crypto,
            &admin,
            ChangeRequestInput {
                environment_id: env.clone(),
                title: None,
                reason: "Synthetic replacement".into(),
                items: vec![restricted],
            },
        )
        .await
        .unwrap();
        assert!(!id.is_empty());
        let snapshot = Snapshot::capture(&pool, &env, 1).await.unwrap();
        sqlx::query(
            "UPDATE variables SET group_name = 'Changed after capture' WHERE key = 'TRIES'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert!(matches!(
            snapshot.validate(&mut transaction, &env).await,
            Err(AppError::Conflict)
        ));
        transaction.rollback().await.unwrap();
    }
}
