use serde::Serialize;
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use crate::{
    auth::AuthenticatedSession,
    crypto::CryptoManager,
    db::now_rfc3339,
    error::AppError,
    users::{Capability, Role},
};

pub const DEFAULT_ENVIRONMENTS: [&str; 3] = ["Development", "Staging", "Production"];

const MAX_NAME_CHARS: usize = 100;
const MAX_DESCRIPTION_CHARS: usize = 1_000;

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ServiceRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub archived_at: Option<String>,
    pub updated_at: String,
    pub environment_count: i64,
    pub contributor_count: i64,
}

#[derive(Clone, Debug)]
pub struct ServiceInput {
    pub name: String,
    pub description: Option<String>,
}

pub async fn list_accessible(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
) -> Result<Vec<ServiceRecord>, AppError> {
    session.require_full()?;
    let rows = if session.user.role == Role::Contributor {
        sqlx::query_as::<_, ServiceRecord>(
            "SELECT s.id, s.name, s.description, s.archived_at, s.updated_at, \
                    COUNT(e.id) AS environment_count, \
                    (SELECT COUNT(*) FROM user_service_access access \
                     JOIN users access_user ON access_user.id = access.user_id \
                     WHERE access.service_id = s.id AND access_user.active = 1 \
                       AND access_user.role = 'CONTRIBUTOR') AS contributor_count \
             FROM services s \
             JOIN user_service_access a ON a.service_id = s.id AND a.user_id = ? \
             LEFT JOIN environments e ON e.service_id = s.id AND e.archived_at IS NULL \
             WHERE s.organization_id = ? \
             GROUP BY s.id, s.name, s.description, s.archived_at, s.updated_at \
             ORDER BY s.archived_at IS NOT NULL, s.name_normalized",
        )
        .bind(&session.user.id)
        .bind(&session.user.organization_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, ServiceRecord>(
            "SELECT s.id, s.name, s.description, s.archived_at, s.updated_at, \
                    COUNT(e.id) AS environment_count, \
                    (SELECT COUNT(*) FROM user_service_access access \
                     JOIN users access_user ON access_user.id = access.user_id \
                     WHERE access.service_id = s.id AND access_user.active = 1 \
                       AND access_user.role = 'CONTRIBUTOR') AS contributor_count \
             FROM services s \
             LEFT JOIN environments e ON e.service_id = s.id AND e.archived_at IS NULL \
             WHERE s.organization_id = ? \
             GROUP BY s.id, s.name, s.description, s.archived_at, s.updated_at \
             ORDER BY s.archived_at IS NOT NULL, s.name_normalized",
        )
        .bind(&session.user.organization_id)
        .fetch_all(pool)
        .await?
    };
    Ok(rows)
}

pub async fn create(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    input: ServiceInput,
) -> Result<String, AppError> {
    require_manage_metadata(session)?;
    let (name, normalized) = validate_name(&input.name)?;
    let description = validate_description(input.description)?;
    let id = Uuid::new_v4().to_string();
    let now = now_rfc3339().map_err(AppError::Internal)?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO services(\
            id, organization_id, name, name_normalized, description, created_at, updated_at, created_by, updated_by\
         ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&session.user.organization_id)
    .bind(&name)
    .bind(&normalized)
    .bind(description)
    .bind(&now)
    .bind(&now)
    .bind(&session.user.id)
    .bind(&session.user.id)
    .execute(&mut *transaction)
    .await
    .map_err(map_write_error)?;
    audit_service(&mut transaction, session, &id, "CREATE_SERVICE", &now).await?;
    transaction.commit().await?;
    Ok(id)
}

pub async fn create_with_default_environments(
    pool: &SqlitePool,
    crypto: &CryptoManager,
    session: &AuthenticatedSession,
    input: ServiceInput,
) -> Result<String, AppError> {
    require_manage_metadata(session)?;
    let (name, normalized) = validate_name(&input.name)?;
    let description = validate_description(input.description)?;
    let service_id = Uuid::new_v4().to_string();
    let now = now_rfc3339().map_err(AppError::Internal)?;
    let mut transaction = pool.begin().await?;
    let kek_version: i64 =
        sqlx::query_scalar("SELECT kek_version FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_one(&mut *transaction)
            .await?;
    let kek_version_u64 = u64::try_from(kek_version).map_err(|_| AppError::Crypto)?;

    sqlx::query(
        "INSERT INTO services(\
            id, organization_id, name, name_normalized, description, created_at, updated_at, created_by, updated_by\
         ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&service_id)
    .bind(&session.user.organization_id)
    .bind(&name)
    .bind(&normalized)
    .bind(description)
    .bind(&now)
    .bind(&now)
    .bind(&session.user.id)
    .bind(&session.user.id)
    .execute(&mut *transaction)
    .await
    .map_err(map_write_error)?;
    audit_service(
        &mut transaction,
        session,
        &service_id,
        "CREATE_SERVICE",
        &now,
    )
    .await?;

    for environment_name in DEFAULT_ENVIRONMENTS {
        let environment_id = Uuid::new_v4().to_string();
        let environment_key_id = Uuid::new_v4().to_string();
        let dek = crypto.generate_dek().map_err(|_| AppError::Crypto)?;
        let wrapped = crypto
            .wrap_dek(&environment_id, 1, kek_version_u64, &dek)
            .map_err(|_| AppError::Crypto)?;
        sqlx::query(
            "INSERT INTO environments(\
                id, service_id, name, name_normalized, created_at, updated_at, created_by, updated_by\
             ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&environment_id)
        .bind(&service_id)
        .bind(environment_name)
        .bind(environment_name.to_lowercase())
        .bind(&now)
        .bind(&now)
        .bind(&session.user.id)
        .bind(&session.user.id)
        .execute(&mut *transaction)
        .await?;
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
        sqlx::query(
            "INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id, environment_id) VALUES(?, ?, 'CREATE_ENVIRONMENT', ?, ?)",
        )
        .bind(&now)
        .bind(&session.user.id)
        .bind(&service_id)
        .bind(&environment_id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(service_id)
}

pub async fn update(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    service_id: &str,
    input: ServiceInput,
) -> Result<(), AppError> {
    require_manage_metadata(session)?;
    let (name, normalized) = validate_name(&input.name)?;
    let description = validate_description(input.description)?;
    let now = now_rfc3339().map_err(AppError::Internal)?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "UPDATE services SET name = ?, name_normalized = ?, description = ?, updated_at = ?, updated_by = ? \
         WHERE id = ? AND organization_id = ?",
    )
    .bind(name)
    .bind(normalized)
    .bind(description)
    .bind(&now)
    .bind(&session.user.id)
    .bind(service_id)
    .bind(&session.user.organization_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_write_error)?;
    if result.rows_affected() != 1 {
        return Err(AppError::NotFound);
    }
    audit_service(
        &mut transaction,
        session,
        service_id,
        "UPDATE_SERVICE",
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn set_archived(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    service_id: &str,
    archived: bool,
) -> Result<(), AppError> {
    require_manage_metadata(session)?;
    let now = now_rfc3339().map_err(AppError::Internal)?;
    let archived_at = archived.then_some(now.as_str());
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "UPDATE services SET archived_at = ?, updated_at = ?, updated_by = ? \
         WHERE id = ? AND organization_id = ?",
    )
    .bind(archived_at)
    .bind(&now)
    .bind(&session.user.id)
    .bind(service_id)
    .bind(&session.user.organization_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::NotFound);
    }
    let action = if archived {
        "ARCHIVE_SERVICE"
    } else {
        "RESTORE_SERVICE"
    };
    audit_service(&mut transaction, session, service_id, action, &now).await?;
    transaction.commit().await?;
    Ok(())
}

fn require_manage_metadata(session: &AuthenticatedSession) -> Result<(), AppError> {
    session.require_full()?;
    if session.user.role.allows(Capability::ManageMetadata) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(crate) fn validate_name(value: &str) -> Result<(String, String), AppError> {
    let name = value.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest);
    }
    Ok((name.to_owned(), name.to_lowercase()))
}

pub(crate) fn validate_description(value: Option<String>) -> Result<Option<String>, AppError> {
    let value = value
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty());
    if value
        .as_ref()
        .is_some_and(|item| item.chars().count() > MAX_DESCRIPTION_CHARS)
    {
        return Err(AppError::InvalidRequest);
    }
    Ok(value)
}

pub(crate) fn map_write_error(error: sqlx::Error) -> AppError {
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        AppError::Conflict
    } else {
        AppError::Database(error)
    }
}

async fn audit_service(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    service_id: &str,
    action: &str,
    now: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id) VALUES(?, ?, ?, ?)",
    )
    .bind(now)
    .bind(&session.user.id)
    .bind(action)
    .bind(service_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        auth::{AuthenticatedSession, AuthenticationState, SessionUser},
        crypto::CryptoManager,
        db::{initialize_and_validate_key_registry, test_pool},
        error::AppError,
        users::Role,
    };

    use super::{
        ServiceInput, create, create_with_default_environments, list_accessible, set_archived,
    };
    use zeroize::Zeroizing;

    #[tokio::test]
    async fn administrator_manages_services_and_contributor_needs_assignment() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let admin = session("admin", Role::Administrator);
        let contributor = session("contributor", Role::Contributor);

        let service_id = create(
            &pool,
            &admin,
            ServiceInput {
                name: " Payment API ".into(),
                description: Some("Payments".into()),
            },
        )
        .await
        .unwrap();
        let duplicate = create(
            &pool,
            &admin,
            ServiceInput {
                name: "payment api".into(),
                description: None,
            },
        )
        .await;
        assert!(matches!(duplicate, Err(AppError::Conflict)));
        assert!(
            list_accessible(&pool, &contributor)
                .await
                .unwrap()
                .is_empty()
        );

        sqlx::query(
            "INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) \
             VALUES('contributor', ?, '2026-08-14T00:00:00Z', 'admin')",
        )
        .bind(&service_id)
        .execute(&pool)
        .await
        .unwrap();
        let visible = list_accessible(&pool, &contributor).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "Payment API");
        assert_eq!(visible[0].contributor_count, 1);

        assert!(
            create(
                &pool,
                &contributor,
                ServiceInput {
                    name: "Forbidden".into(),
                    description: None,
                },
            )
            .await
            .is_err()
        );
        set_archived(&pool, &admin, &service_id, true)
            .await
            .unwrap();
        assert!(
            list_accessible(&pool, &admin).await.unwrap()[0]
                .archived_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn service_creation_atomically_provisions_three_standard_environments() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([81; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let service_id = create_with_default_environments(
            &pool,
            &crypto,
            &session("admin", Role::Administrator),
            ServiceInput {
                name: "Membership API".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM environments WHERE service_id = ? ORDER BY CASE name WHEN 'Development' THEN 1 WHEN 'Staging' THEN 2 ELSE 3 END",
        )
        .bind(&service_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(names, ["Development", "Staging", "Production"]);
        let active_keys: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environment_keys k JOIN environments e ON e.id = k.environment_id WHERE e.service_id = ? AND k.status = 'ACTIVE'",
        )
        .bind(&service_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active_keys, 3);
    }

    pub(super) async fn seed_identity(pool: &sqlx::SqlitePool) {
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

    pub(super) fn session(id: &str, role: Role) -> AuthenticatedSession {
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
