use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    auth::{
        AuthenticatedSession, PasswordService, PrivilegedAuthLevel, SessionManager, normalize_email,
    },
    db::now_rfc3339,
    error::AppError,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    Contributor,
    Operator,
    Administrator,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contributor => "CONTRIBUTOR",
            Self::Operator => "OPERATOR",
            Self::Administrator => "ADMINISTRATOR",
        }
    }

    pub const fn allows(self, capability: Capability) -> bool {
        match self {
            Self::Contributor => matches!(
                capability,
                Capability::ReadAssignedService
                    | Capability::ReadPublicValue
                    | Capability::CreateChangeRequest
            ),
            Self::Operator => !matches!(
                capability,
                Capability::ManageUsers
                    | Capability::ManageMetadata
                    | Capability::ManageSystem
                    | Capability::CreateBackup
                    | Capability::CreateRestoreIntent
                    | Capability::RotateKeys
            ),
            Self::Administrator => true,
        }
    }

    pub const fn requires_totp(self) -> bool {
        matches!(self, Self::Operator | Self::Administrator)
    }
}

impl FromStr for Role {
    type Err = RoleParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "CONTRIBUTOR" => Ok(Self::Contributor),
            "OPERATOR" => Ok(Self::Operator),
            "ADMINISTRATOR" => Ok(Self::Administrator),
            _ => Err(RoleParseError),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    ReadAssignedService,
    ReadPublicValue,
    ReadRestrictedValue,
    CreateChangeRequest,
    FulfillValue,
    ReviewRequest,
    ApplyRequest,
    ExportEnvironment,
    ViewAudit,
    ManageUsers,
    ManageMetadata,
    ManageSystem,
    CreateBackup,
    CreateRestoreIntent,
    RotateKeys,
}

#[derive(Debug, Error)]
#[error("unknown role")]
pub struct RoleParseError;

pub async fn can_access_service(
    pool: &SqlitePool,
    user_id: &str,
    role: Role,
    service_id: &str,
) -> Result<bool, sqlx::Error> {
    if matches!(role, Role::Operator | Role::Administrator) {
        return Ok(true);
    }
    let granted: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_service_access WHERE user_id = ? AND service_id = ?)",
    )
    .bind(user_id)
    .bind(service_id)
    .fetch_one(pool)
    .await?;
    Ok(granted)
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ServiceAccessUser {
    pub id: String,
    pub email: String,
    pub granted: bool,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ServiceAccessContext {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, FromRow, Serialize)]
#[allow(clippy::struct_excessive_bools)] // Read-only SSR projection of independent account states.
pub struct UserRecord {
    pub id: String,
    pub email: String,
    pub role: String,
    pub active: bool,
    pub totp_enabled: bool,
    pub last_login_at: Option<String>,
    pub created_at: String,
    pub must_change_password: bool,
    pub is_self: bool,
}

#[derive(Debug)]
pub struct UserCreateInput {
    pub email: String,
    pub initial_password: Zeroizing<String>,
    pub role: String,
}

pub async fn list_users(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
) -> Result<Vec<UserRecord>, AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ManageUsers) {
        return Err(AppError::Forbidden);
    }
    Ok(sqlx::query_as(
        "SELECT id, email, role, active, totp_enabled_at IS NOT NULL AS totp_enabled, last_login_at, created_at, must_change_password, id = ? AS is_self FROM users WHERE organization_id = ? ORDER BY email_normalized",
    )
    .bind(&session.user.id)
    .bind(&session.user.organization_id)
    .fetch_all(pool)
    .await?)
}

pub async fn create_user(
    pool: &SqlitePool,
    passwords: &PasswordService,
    session: &AuthenticatedSession,
    input: UserCreateInput,
) -> Result<String, AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ManageUsers) {
        return Err(AppError::Forbidden);
    }
    let email_normalized = normalize_email(&input.email).map_err(|_| AppError::InvalidRequest)?;
    let role = Role::from_str(&input.role).map_err(|_| AppError::InvalidRequest)?;
    if input.initial_password.len() < 12 || input.initial_password.len() > 1_024 {
        return Err(AppError::InvalidRequest);
    }
    let password_hash = passwords
        .hash(input.initial_password)
        .await
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error)))?;
    let user_id = Uuid::new_v4().to_string();
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, active, password_changed_at, must_change_password, created_at, updated_at, created_by) VALUES(?, ?, ?, ?, ?, ?, 1, ?, 1, ?, ?, ?)",
    )
    .bind(&user_id)
    .bind(&session.user.organization_id)
    .bind(input.email.trim())
    .bind(&email_normalized)
    .bind(password_hash)
    .bind(role.as_str())
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .bind(&session.user.id)
    .execute(&mut *transaction)
    .await;
    match result {
        Ok(_) => {}
        Err(error) if error.to_string().contains("UNIQUE constraint failed") => {
            return Err(AppError::Conflict);
        }
        Err(error) => return Err(AppError::Database(error)),
    }
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json, request_id) VALUES(?, ?, 'CREATE_USER', ?, ?)",
    )
    .bind(&now)
    .bind(&session.user.id)
    .bind(serde_json::json!({"target_user_id": user_id, "role": role.as_str()}).to_string())
    .bind(Uuid::new_v4().to_string())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(user_id)
}

pub async fn list_service_access(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    service_id: &str,
) -> Result<(ServiceAccessContext, Vec<ServiceAccessUser>), AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ManageUsers) {
        return Err(AppError::Forbidden);
    }
    let service = sqlx::query_as::<_, ServiceAccessContext>(
        "SELECT id, name FROM services WHERE id = ? AND organization_id = ?",
    )
    .bind(service_id)
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    let users = sqlx::query_as::<_, ServiceAccessUser>(
        "SELECT u.id, u.email, EXISTS(SELECT 1 FROM user_service_access a WHERE a.user_id = u.id AND a.service_id = ?) AS granted \
         FROM users u WHERE u.organization_id = ? AND u.role = 'CONTRIBUTOR' AND u.active = 1 ORDER BY u.email_normalized",
    )
    .bind(service_id)
    .bind(&session.user.organization_id)
    .fetch_all(pool)
    .await?;
    Ok((service, users))
}

pub async fn set_service_access(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    service_id: &str,
    user_id: &str,
    granted: bool,
) -> Result<(), AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ManageUsers) {
        return Err(AppError::Forbidden);
    }
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    let valid_service: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM services WHERE id = ? AND organization_id = ?)",
    )
    .bind(service_id)
    .bind(&session.user.organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    let valid_user: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND organization_id = ? AND role = 'CONTRIBUTOR' AND active = 1)",
    )
    .bind(user_id)
    .bind(&session.user.organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !valid_service || !valid_user {
        return Err(AppError::NotFound);
    }
    let changed = if granted {
        sqlx::query(
            "INSERT OR IGNORE INTO user_service_access(user_id, service_id, access_level, granted_at, granted_by) VALUES(?, ?, 'READ_REQUEST', ?, ?)",
        )
        .bind(user_id)
        .bind(service_id)
        .bind(&now)
        .bind(&session.user.id)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
    } else {
        sqlx::query("DELETE FROM user_service_access WHERE user_id = ? AND service_id = ?")
            .bind(user_id)
            .bind(service_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
    };
    if changed > 0 {
        sqlx::query(
            "UPDATE users SET auth_version = auth_version + 1, updated_at = ? WHERE id = ?",
        )
        .bind(&now)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE sessions SET revoked_at = ?, revoke_reason = 'service_access_changed' WHERE user_id = ? AND revoked_at IS NULL")
            .bind(&now)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "INSERT INTO audit_logs(occurred_at, actor_user_id, action, service_id, metadata_json, request_id) VALUES(?, ?, 'UPDATE_USER_ACCESS', ?, ?, ?)",
        )
        .bind(&now)
        .bind(&session.user.id)
        .bind(service_id)
        .bind(serde_json::json!({"target_user_id": user_id, "granted": granted}).to_string())
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

#[derive(FromRow)]
struct ManagedUser {
    role: String,
    active: bool,
    totp_enabled: bool,
}

pub async fn change_own_password(
    pool: &SqlitePool,
    passwords: &PasswordService,
    session: &AuthenticatedSession,
    current_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
) -> Result<(), AppError> {
    session.require_full()?;
    if new_password.len() < 12 || new_password.len() > 1_024 || *new_password == *current_password {
        return Err(AppError::InvalidRequest);
    }
    let password_hash: String = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE id = ? AND organization_id = ? AND active = 1",
    )
    .bind(&session.user.id)
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::Unauthorized)?;
    if !passwords
        .verify(current_password, password_hash)
        .await
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error)))?
    {
        return Err(AppError::Authentication);
    }
    let replacement = passwords
        .hash(new_password)
        .await
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error)))?;
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "UPDATE users SET password_hash = ?, password_changed_at = ?, must_change_password = 0, auth_version = auth_version + 1, updated_at = ? WHERE id = ?",
    )
    .bind(replacement)
    .bind(&now)
    .bind(&now)
    .bind(&session.user.id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE sessions SET revoked_at = ?, revoke_reason = 'password_changed' WHERE user_id = ? AND revoked_at IS NULL")
        .bind(&now)
        .bind(&session.user.id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json, request_id) VALUES(?, ?, 'CHANGE_PASSWORD', ?, ?)")
        .bind(&now)
        .bind(&session.user.id)
        .bind(serde_json::json!({"forced": session.user.must_change_password}).to_string())
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn update_role(
    pool: &SqlitePool,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    user_id: &str,
    role: &str,
) -> Result<(), AppError> {
    require_recent_admin(sessions, session)?;
    if user_id == session.user.id {
        return Err(AppError::Forbidden);
    }
    let new_role = Role::from_str(role).map_err(|_| AppError::InvalidRequest)?;
    let target = managed_user(pool, session, user_id).await?;
    if target.role == new_role.as_str() {
        return Ok(());
    }
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE users SET role = ?, auth_version = auth_version + 1, updated_at = ? \
         WHERE id = ? AND organization_id = ? AND (role != 'ADMINISTRATOR' OR active = 0 OR ? = 'ADMINISTRATOR' OR EXISTS(SELECT 1 FROM users other WHERE other.organization_id = users.organization_id AND other.role = 'ADMINISTRATOR' AND other.active = 1 AND other.id != users.id))",
    )
    .bind(new_role.as_str())
    .bind(&now)
    .bind(user_id)
    .bind(&session.user.organization_id)
    .bind(new_role.as_str())
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::Conflict);
    }
    sqlx::query("DELETE FROM user_service_access WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    revoke_and_audit(
        &mut transaction,
        session,
        user_id,
        "role_changed",
        "UPDATE_USER_ROLE",
        serde_json::json!({"target_user_id": user_id, "old_role": target.role, "new_role": new_role.as_str()}),
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn set_active(
    pool: &SqlitePool,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    user_id: &str,
    active: bool,
) -> Result<(), AppError> {
    require_recent_admin(sessions, session)?;
    if user_id == session.user.id {
        return Err(AppError::Forbidden);
    }
    let target = managed_user(pool, session, user_id).await?;
    if target.active == active {
        return Ok(());
    }
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE users SET active = ?, auth_version = auth_version + 1, updated_at = ? \
         WHERE id = ? AND organization_id = ? AND (? = 1 OR role != 'ADMINISTRATOR' OR active = 0 OR EXISTS(SELECT 1 FROM users other WHERE other.organization_id = users.organization_id AND other.role = 'ADMINISTRATOR' AND other.active = 1 AND other.id != users.id))",
    )
    .bind(active)
    .bind(&now)
    .bind(user_id)
    .bind(&session.user.organization_id)
    .bind(active)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::Conflict);
    }
    revoke_and_audit(
        &mut transaction,
        session,
        user_id,
        "active_state_changed",
        "UPDATE_USER_STATUS",
        serde_json::json!({"target_user_id": user_id, "active": active}),
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn reset_totp(
    pool: &SqlitePool,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    user_id: &str,
) -> Result<(), AppError> {
    require_recent_admin(sessions, session)?;
    if user_id == session.user.id {
        return Err(AppError::Forbidden);
    }
    let target = managed_user(pool, session, user_id).await?;
    if !target.totp_enabled {
        return Err(AppError::InvalidRequest);
    }
    let now = now_rfc3339()?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "UPDATE users SET totp_secret_ciphertext = NULL, totp_secret_nonce = NULL, totp_crypto_version = NULL, totp_kek_version = NULL, totp_enabled_at = NULL, totp_last_used_step = NULL, auth_version = auth_version + 1, updated_at = ? WHERE id = ? AND organization_id = ?",
    )
    .bind(&now)
    .bind(user_id)
    .bind(&session.user.organization_id)
    .execute(&mut *transaction)
    .await?;
    revoke_and_audit(
        &mut transaction,
        session,
        user_id,
        "totp_reset",
        "RESET_USER_TOTP",
        serde_json::json!({"target_user_id": user_id}),
        &now,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

fn require_recent_admin(
    sessions: &SessionManager,
    session: &AuthenticatedSession,
) -> Result<(), AppError> {
    session.require_full()?;
    if session.user.role.allows(Capability::ManageUsers)
        && sessions.has_recent_auth(session, PrivilegedAuthLevel::Standard)
    {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

async fn managed_user(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    user_id: &str,
) -> Result<ManagedUser, AppError> {
    sqlx::query_as(
        "SELECT role, active, totp_enabled_at IS NOT NULL AS totp_enabled FROM users WHERE id = ? AND organization_id = ?",
    )
    .bind(user_id)
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)
}

async fn revoke_and_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &AuthenticatedSession,
    user_id: &str,
    reason: &str,
    action: &str,
    metadata: serde_json::Value,
    now: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(reason)
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json, request_id) VALUES(?, ?, ?, ?, ?)")
        .bind(now)
        .bind(&session.user.id)
        .bind(action)
        .bind(metadata.to_string())
        .bind(Uuid::new_v4().to_string())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        auth::{
            AuthenticatedSession, AuthenticationState, PasswordService, PrivilegedAuthLevel,
            SessionManager, SessionUser,
        },
        config::SessionSettings,
        crypto::CryptoManager,
        db::{initialize_and_validate_key_registry, test_pool},
    };
    use time::{Duration, OffsetDateTime};
    use zeroize::Zeroizing;

    use super::{
        Capability, Role, UserCreateInput, can_access_service, change_own_password, create_user,
        reset_totp, set_active, set_service_access, update_role,
    };

    #[test]
    fn contributor_cannot_read_restricted_or_apply() {
        assert!(!Role::Contributor.allows(Capability::ReadRestrictedValue));
        assert!(!Role::Contributor.allows(Capability::ApplyRequest));
        assert!(Role::Contributor.allows(Capability::ReadPublicValue));
    }

    #[test]
    fn operator_cannot_manage_users_or_rotate_keys() {
        assert!(Role::Operator.allows(Capability::ReadRestrictedValue));
        assert!(!Role::Operator.allows(Capability::ManageUsers));
        assert!(!Role::Operator.allows(Capability::RotateKeys));
    }

    #[test]
    fn administrator_has_all_capabilities() {
        assert!(Role::Administrator.allows(Capability::RotateKeys));
        assert!(Role::Administrator.allows(Capability::ManageUsers));
    }

    #[tokio::test]
    async fn contributor_cannot_access_unassigned_service() {
        let pool = test_pool().await;
        let now = "2026-08-13T00:00:00Z";
        sqlx::query("INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org', 'ConfigDeck', ?, ?)")
            .bind(now)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        for (id, email, role) in [
            ("admin", "admin@example.test", "ADMINISTRATOR"),
            ("contributor", "contributor@example.test", "CONTRIBUTOR"),
        ] {
            sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES(?, 'org', ?, ?, 'hash', ?, ?, ?, ?)")
                .bind(id)
                .bind(email)
                .bind(email)
                .bind(role)
                .bind(now)
                .bind(now)
                .bind(now)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO services(id, organization_id, name, name_normalized, created_at, updated_at, created_by, updated_by) VALUES('service', 'org', 'Payment', 'payment', ?, ?, 'admin', 'admin')")
            .bind(now)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !can_access_service(&pool, "contributor", Role::Contributor, "service")
                .await
                .unwrap()
        );
        sqlx::query("INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) VALUES('contributor', 'service', ?, 'admin')")
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            can_access_service(&pool, "contributor", Role::Contributor, "service")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn administrator_grant_invalidates_sessions_and_is_audited() {
        let pool = test_pool().await;
        let now = "2026-08-13T00:00:00Z";
        sqlx::query("INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org', 'ConfigDeck', ?, ?)")
            .bind(now).bind(now).execute(&pool).await.unwrap();
        for (id, email, role) in [
            ("admin", "admin@example.test", "ADMINISTRATOR"),
            ("contributor", "contributor@example.test", "CONTRIBUTOR"),
        ] {
            sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES(?, 'org', ?, ?, 'hash', ?, ?, ?, ?)")
                .bind(id).bind(email).bind(email).bind(role).bind(now).bind(now).bind(now)
                .execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO services(id, organization_id, name, name_normalized, created_at, updated_at, created_by, updated_by) VALUES('service', 'org', 'Payment', 'payment', ?, ?, 'admin', 'admin')")
            .bind(now).bind(now).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO sessions(id, token_hash, csrf_token_hash, user_id, auth_version, authentication_state, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES('session-c', ?, ?, 'contributor', 1, 'FULL', ?, ?, '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')")
            .bind(vec![1_u8; 32]).bind(vec![2_u8; 32]).bind(now).bind(now)
            .execute(&pool).await.unwrap();
        let admin = session("admin", Role::Administrator);
        set_service_access(&pool, &admin, "service", "contributor", true)
            .await
            .unwrap();
        let (version, revoked): (i64, Option<String>) = sqlx::query_as("SELECT u.auth_version, s.revoked_at FROM users u JOIN sessions s ON s.user_id = u.id WHERE u.id = 'contributor'")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(version, 2);
        assert!(revoked.is_some());
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'UPDATE_USER_ACCESS'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audits, 1);
    }

    #[tokio::test]
    async fn administrator_creates_hashed_user_and_duplicate_is_rejected() {
        let pool = test_pool().await;
        seed_admin(&pool).await;
        let admin = session("admin", Role::Administrator);
        let passwords = PasswordService::for_tests();
        let user_id = create_user(
            &pool,
            &passwords,
            &admin,
            UserCreateInput {
                email: " New.User@Example.test ".into(),
                initial_password: Zeroizing::new("initial-password".into()),
                role: "CONTRIBUTOR".into(),
            },
        )
        .await
        .unwrap();
        let (normalized, hash, must_change): (String, String, bool) = sqlx::query_as(
            "SELECT email_normalized, password_hash, must_change_password FROM users WHERE id = ?",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(normalized, "new.user@example.test");
        assert_ne!(hash, "initial-password");
        assert!(must_change);
        assert!(
            passwords
                .verify(Zeroizing::new("initial-password".into()), hash)
                .await
                .unwrap()
        );
        assert!(
            create_user(
                &pool,
                &passwords,
                &admin,
                UserCreateInput {
                    email: "new.user@example.test".into(),
                    initial_password: Zeroizing::new("another-password".into()),
                    role: "OPERATOR".into(),
                },
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn contributor_cannot_create_users() {
        let pool = test_pool().await;
        seed_admin(&pool).await;
        let result = create_user(
            &pool,
            &PasswordService::for_tests(),
            &session("contributor", Role::Contributor),
            UserCreateInput {
                email: "blocked@example.test".into(),
                initial_password: Zeroizing::new("initial-password".into()),
                role: "CONTRIBUTOR".into(),
            },
        )
        .await;
        assert!(result.is_err());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn password_change_clears_initial_flag_and_revokes_sessions() {
        let pool = test_pool().await;
        seed_admin(&pool).await;
        let passwords = PasswordService::for_tests();
        let old_hash = passwords
            .hash(Zeroizing::new("initial-password".into()))
            .await
            .unwrap();
        sqlx::query(
            "UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = 'admin'",
        )
        .bind(old_hash)
        .execute(&pool)
        .await
        .unwrap();
        seed_session(&pool, "admin").await;
        let mut admin = session("admin", Role::Administrator);
        admin.user.must_change_password = true;
        change_own_password(
            &pool,
            &passwords,
            &admin,
            Zeroizing::new("initial-password".into()),
            Zeroizing::new("replacement-password".into()),
        )
        .await
        .unwrap();
        let (hash, must_change, version): (String, bool, i64) = sqlx::query_as(
            "SELECT password_hash, must_change_password, auth_version FROM users WHERE id = 'admin'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!must_change);
        assert_eq!(version, 2);
        assert!(
            passwords
                .verify(Zeroizing::new("replacement-password".into()), hash)
                .await
                .unwrap()
        );
        let revoked: Option<String> =
            sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = 'session-admin'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked.is_some());
    }

    #[tokio::test]
    async fn role_change_revokes_session_and_last_admin_is_protected() {
        let pool = test_pool().await;
        seed_admin(&pool).await;
        let manager = session_manager(pool.clone());
        let external_admin = recent_session("external-admin", Role::Administrator);
        assert!(
            update_role(&pool, &manager, &external_admin, "admin", "OPERATOR")
                .await
                .is_err()
        );
        assert!(
            set_active(&pool, &manager, &external_admin, "admin", false)
                .await
                .is_err()
        );

        let now = "2026-08-15T00:00:00Z";
        sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES('contributor', 'org', 'contributor@example.test', 'contributor@example.test', 'hash', 'CONTRIBUTOR', ?, ?, ?)")
            .bind(now).bind(now).bind(now).execute(&pool).await.unwrap();
        seed_session(&pool, "contributor").await;
        let admin = recent_session("admin", Role::Administrator);
        update_role(&pool, &manager, &admin, "contributor", "OPERATOR")
            .await
            .unwrap();
        let (role, version): (String, i64) =
            sqlx::query_as("SELECT role, auth_version FROM users WHERE id = 'contributor'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let revoked: Option<String> =
            sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = 'session-contributor'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(role, "OPERATOR");
        assert_eq!(version, 2);
        assert!(revoked.is_some());
    }

    #[tokio::test]
    async fn totp_reset_removes_seed_and_revokes_target_sessions() {
        let pool = test_pool().await;
        seed_admin(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([29; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let encrypted = crypto
            .encrypt_totp_seed("operator", 1, b"01234567890123456789")
            .unwrap();
        let kek_version: i64 =
            sqlx::query_scalar("SELECT kek_version FROM kek_registry WHERE status = 'ACTIVE'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let now = "2026-08-15T00:00:00Z";
        sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at, totp_secret_ciphertext, totp_secret_nonce, totp_crypto_version, totp_kek_version, totp_enabled_at) VALUES('operator', 'org', 'operator@example.test', 'operator@example.test', 'hash', 'OPERATOR', ?, ?, ?, ?, ?, 1, ?, ?)")
            .bind(now).bind(now).bind(now).bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(kek_version).bind(now)
            .execute(&pool).await.unwrap();
        seed_session(&pool, "operator").await;
        let admin = recent_session("admin", Role::Administrator);
        reset_totp(&pool, &session_manager(pool.clone()), &admin, "operator")
            .await
            .unwrap();
        let (enabled_at, ciphertext, version): (Option<String>, Option<Vec<u8>>, i64) = sqlx::query_as("SELECT totp_enabled_at, totp_secret_ciphertext, auth_version FROM users WHERE id = 'operator'")
            .fetch_one(&pool).await.unwrap();
        assert!(enabled_at.is_none());
        assert!(ciphertext.is_none());
        assert_eq!(version, 2);
        let revoked: Option<String> =
            sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = 'session-operator'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked.is_some());
    }

    async fn seed_admin(pool: &sqlx::SqlitePool) {
        let now = "2026-08-14T00:00:00Z";
        sqlx::query("INSERT INTO organizations(id, name, onboarding_completed_at, created_at, updated_at) VALUES('org', 'ConfigDeck', ?, ?, ?)")
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES('admin', 'org', 'admin@example.test', 'admin@example.test', 'hash', 'ADMINISTRATOR', ?, ?, ?)")
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
    }

    fn session(id: &str, role: Role) -> AuthenticatedSession {
        AuthenticatedSession {
            id: format!("session-{id}"),
            token_hash: vec![3; 32],
            csrf_token_hash: vec![4; 32],
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

    fn recent_session(id: &str, role: Role) -> AuthenticatedSession {
        let mut value = session(id, role);
        value.privileged_authenticated_at = Some(OffsetDateTime::now_utc());
        value.privileged_auth_level = Some(PrivilegedAuthLevel::Standard);
        value
    }

    fn session_manager(pool: sqlx::SqlitePool) -> SessionManager {
        SessionManager::new(
            pool,
            CryptoManager::new(Zeroizing::new([27; 32])),
            SessionSettings {
                cookie_name: "test".into(),
                secure_cookie: false,
                idle_timeout: Duration::minutes(30),
                absolute_timeout: Duration::hours(12),
                recent_auth_timeout: Duration::minutes(5),
            },
        )
    }

    async fn seed_session(pool: &sqlx::SqlitePool, user_id: &str) {
        let now = "2026-08-15T00:00:00Z";
        sqlx::query("INSERT INTO sessions(id, token_hash, csrf_token_hash, user_id, auth_version, authentication_state, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES(?, ?, ?, ?, 1, 'FULL', ?, ?, '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')")
            .bind(format!("session-{user_id}"))
            .bind(vec![31_u8; 32])
            .bind(vec![32_u8; 32])
            .bind(user_id)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
    }
}
