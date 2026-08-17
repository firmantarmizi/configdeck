use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, SqlitePool};
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    config::SessionSettings,
    crypto::CryptoManager,
    error::AppError,
    users::{Role, RoleParseError},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuthenticationState {
    PasswordOnly,
    Full,
}

impl AuthenticationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PasswordOnly => "PASSWORD_ONLY",
            Self::Full => "FULL",
        }
    }
}

impl FromStr for AuthenticationState {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "PASSWORD_ONLY" => Ok(Self::PasswordOnly),
            "FULL" => Ok(Self::Full),
            _ => Err(AppError::Authentication),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegedAuthLevel {
    Standard,
    HighImpact,
}

impl PrivilegedAuthLevel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "STANDARD",
            Self::HighImpact => "HIGH_IMPACT",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionTokens {
    pub session_token: String,
    pub csrf_token: String,
}

#[derive(Clone, Debug)]
pub struct SessionUser {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: Role,
    pub auth_version: i64,
    pub totp_enabled: bool,
    pub must_change_password: bool,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedSession {
    pub id: String,
    pub token_hash: Vec<u8>,
    pub csrf_token_hash: Vec<u8>,
    pub user: SessionUser,
    pub authentication_state: AuthenticationState,
    pub privileged_authenticated_at: Option<OffsetDateTime>,
    pub privileged_auth_level: Option<PrivilegedAuthLevel>,
}

impl AuthenticatedSession {
    pub fn require_full(&self) -> Result<(), AppError> {
        if self.authentication_state == AuthenticationState::Full {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

#[derive(Clone)]
pub struct SessionManager {
    pool: SqlitePool,
    crypto: CryptoManager,
    settings: SessionSettings,
}

#[derive(FromRow)]
struct SessionRow {
    session_id: String,
    token_hash: Vec<u8>,
    csrf_token_hash: Vec<u8>,
    authentication_state: String,
    auth_version: i64,
    last_seen_at: String,
    idle_expires_at: String,
    absolute_expires_at: String,
    privileged_authenticated_at: Option<String>,
    privileged_auth_level: Option<String>,
    user_id: String,
    organization_id: String,
    email: String,
    role: String,
    user_auth_version: i64,
    active: bool,
    totp_enabled_at: Option<String>,
    must_change_password: bool,
}

impl SessionManager {
    pub fn new(pool: SqlitePool, crypto: CryptoManager, settings: SessionSettings) -> Self {
        Self {
            pool,
            crypto,
            settings,
        }
    }

    pub async fn create(
        &self,
        user: &SessionUser,
        state: AuthenticationState,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<SessionTokens, AppError> {
        let now = OffsetDateTime::now_utc();
        let raw = random_token()?;
        let csrf = self.crypto.csrf_token(&raw).map_err(|_| AppError::Crypto)?;
        let token_hash = hash(raw.as_bytes());
        let csrf_hash = hash(csrf.as_bytes());
        let user_agent_hash = user_agent.map(|value| hash(value.as_bytes()));
        sqlx::query(
            "INSERT INTO sessions(\
                id, token_hash, csrf_token_hash, user_id, auth_version, authentication_state, \
                created_at, last_seen_at, idle_expires_at, absolute_expires_at, client_ip, user_agent_hash\
             ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(token_hash)
        .bind(csrf_hash)
        .bind(&user.id)
        .bind(user.auth_version)
        .bind(state.as_str())
        .bind(format_time(now)?)
        .bind(format_time(now)?)
        .bind(format_time(now + self.settings.idle_timeout)?)
        .bind(format_time(now + self.settings.absolute_timeout)?)
        .bind(client_ip)
        .bind(user_agent_hash)
        .execute(&self.pool)
        .await?;
        Ok(SessionTokens {
            session_token: raw,
            csrf_token: csrf,
        })
    }

    pub async fn load(&self, raw_token: &str) -> Result<AuthenticatedSession, AppError> {
        let token_hash = hash(raw_token.as_bytes());
        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT s.id AS session_id, s.token_hash, s.csrf_token_hash, s.authentication_state, \
                    s.auth_version, s.last_seen_at, s.idle_expires_at, s.absolute_expires_at, \
                    s.privileged_authenticated_at, s.privileged_auth_level, \
                    u.id AS user_id, u.organization_id, u.email, u.role, u.auth_version AS user_auth_version, \
                    u.active, u.totp_enabled_at, u.must_change_password \
             FROM sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.token_hash = ? AND s.revoked_at IS NULL",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

        if row.token_hash.ct_eq(&token_hash).unwrap_u8() != 1 {
            return Err(AppError::Unauthorized);
        }
        let now = OffsetDateTime::now_utc();
        let idle_expires = parse_time(&row.idle_expires_at)?;
        let absolute_expires = parse_time(&row.absolute_expires_at)?;
        if !row.active
            || row.auth_version != row.user_auth_version
            || now >= idle_expires
            || now >= absolute_expires
        {
            self.revoke_by_id(&row.session_id, "expired_or_invalidated")
                .await?;
            return Err(AppError::Unauthorized);
        }

        let last_seen = parse_time(&row.last_seen_at)?;
        if now - last_seen >= time::Duration::minutes(1) {
            let bounded_idle = std::cmp::min(now + self.settings.idle_timeout, absolute_expires);
            sqlx::query("UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?")
                .bind(format_time(now)?)
                .bind(format_time(bounded_idle)?)
                .bind(&row.session_id)
                .execute(&self.pool)
                .await?;
        }

        Ok(AuthenticatedSession {
            id: row.session_id,
            token_hash: row.token_hash,
            csrf_token_hash: row.csrf_token_hash,
            user: SessionUser {
                id: row.user_id,
                organization_id: row.organization_id,
                email: row.email,
                role: row
                    .role
                    .parse()
                    .map_err(|_: RoleParseError| AppError::Authentication)?,
                auth_version: row.user_auth_version,
                totp_enabled: row.totp_enabled_at.is_some(),
                must_change_password: row.must_change_password,
            },
            authentication_state: row.authentication_state.parse()?,
            privileged_authenticated_at: row
                .privileged_authenticated_at
                .as_deref()
                .map(parse_time)
                .transpose()?,
            privileged_auth_level: match row.privileged_auth_level.as_deref() {
                Some("STANDARD") => Some(PrivilegedAuthLevel::Standard),
                Some("HIGH_IMPACT") => Some(PrivilegedAuthLevel::HighImpact),
                Some(_) => return Err(AppError::Authentication),
                None => None,
            },
        })
    }

    pub fn verify_csrf(
        &self,
        session: &AuthenticatedSession,
        provided: &str,
    ) -> Result<(), AppError> {
        let provided_hash = hash(provided.as_bytes());
        if session.csrf_token_hash.ct_eq(&provided_hash).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    pub async fn revoke(&self, raw_token: &str, reason: &str) -> Result<(), AppError> {
        let token_hash = hash(raw_token.as_bytes());
        sqlx::query("UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE token_hash = ? AND revoked_at IS NULL")
            .bind(format_time(OffsetDateTime::now_utc())?)
            .bind(reason)
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn rotate(
        &self,
        old: &AuthenticatedSession,
        user: &SessionUser,
        state: AuthenticationState,
        privileged_level: Option<PrivilegedAuthLevel>,
    ) -> Result<SessionTokens, AppError> {
        let tokens = self.create(user, state, None, None).await?;
        if let Some(level) = privileged_level {
            let token_hash = hash(tokens.session_token.as_bytes());
            sqlx::query(
                "UPDATE sessions SET privileged_authenticated_at = ?, privileged_auth_level = ? \
                 WHERE token_hash = ?",
            )
            .bind(format_time(OffsetDateTime::now_utc())?)
            .bind(level.as_str())
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        }
        self.revoke_by_id(&old.id, "rotated").await?;
        Ok(tokens)
    }

    pub fn has_recent_auth(
        &self,
        session: &AuthenticatedSession,
        required: PrivilegedAuthLevel,
    ) -> bool {
        let Some(at) = session.privileged_authenticated_at else {
            return false;
        };
        let level_ok = matches!(
            (session.privileged_auth_level, required),
            (Some(PrivilegedAuthLevel::HighImpact), _)
                | (
                    Some(PrivilegedAuthLevel::Standard),
                    PrivilegedAuthLevel::Standard
                )
        );
        level_ok && OffsetDateTime::now_utc() - at <= self.settings.recent_auth_timeout
    }

    async fn revoke_by_id(&self, id: &str, reason: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(format_time(OffsetDateTime::now_utc())?)
            .bind(reason)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn random_token() -> Result<String, AppError> {
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token).map_err(|_| AppError::Crypto)?;
    Ok(URL_SAFE_NO_PAD.encode(token))
}

fn hash(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

fn format_time(value: OffsetDateTime) -> Result<String, AppError> {
    value
        .format(&Rfc3339)
        .map_err(|error| AppError::Internal(error.into()))
}

fn parse_time(value: &str) -> Result<OffsetDateTime, AppError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AppError::Authentication)
}

#[cfg(test)]
mod tests {
    use time::Duration;
    use zeroize::Zeroizing;

    use crate::{config::SessionSettings, crypto::CryptoManager, db::test_pool, users::Role};

    use super::{AuthenticationState, SessionManager, SessionUser};

    #[tokio::test]
    async fn stores_hashes_and_rejects_cross_session_csrf() {
        let pool = test_pool().await;
        seed_user(&pool).await;
        let manager = manager(pool.clone());
        let user = user();
        let first = manager
            .create(&user, AuthenticationState::Full, None, None)
            .await
            .unwrap();
        let second = manager
            .create(&user, AuthenticationState::Full, None, None)
            .await
            .unwrap();
        let loaded = manager.load(&first.session_token).await.unwrap();
        manager.verify_csrf(&loaded, &first.csrf_token).unwrap();
        assert!(manager.verify_csrf(&loaded, &second.csrf_token).is_err());
        let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM sessions WHERE id = ?")
            .bind(&loaded.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(stored, first.session_token.as_bytes());
    }

    #[tokio::test]
    async fn auth_version_change_invalidates_session() {
        let pool = test_pool().await;
        seed_user(&pool).await;
        let manager = manager(pool.clone());
        let tokens = manager
            .create(&user(), AuthenticationState::Full, None, None)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET auth_version = auth_version + 1 WHERE id = 'user-1'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(manager.load(&tokens.session_token).await.is_err());
    }

    #[tokio::test]
    async fn session_survives_manager_restart_but_not_expiry() {
        let pool = test_pool().await;
        seed_user(&pool).await;
        let first_manager = manager(pool.clone());
        let tokens = first_manager
            .create(&user(), AuthenticationState::Full, None, None)
            .await
            .unwrap();
        let restarted_manager = manager(pool.clone());
        assert!(restarted_manager.load(&tokens.session_token).await.is_ok());
        sqlx::query("UPDATE sessions SET idle_expires_at = '2000-01-01T00:00:00Z'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(restarted_manager.load(&tokens.session_token).await.is_err());
    }

    fn manager(pool: sqlx::SqlitePool) -> SessionManager {
        SessionManager::new(
            pool,
            CryptoManager::new(Zeroizing::new([9; 32])),
            SessionSettings {
                cookie_name: "test".into(),
                secure_cookie: false,
                idle_timeout: Duration::minutes(30),
                absolute_timeout: Duration::hours(12),
                recent_auth_timeout: Duration::minutes(5),
            },
        )
    }

    fn user() -> SessionUser {
        SessionUser {
            id: "user-1".into(),
            organization_id: "org-1".into(),
            email: "user@example.test".into(),
            role: Role::Contributor,
            auth_version: 1,
            totp_enabled: false,
            must_change_password: false,
        }
    }

    async fn seed_user(pool: &sqlx::SqlitePool) {
        let now = "2026-08-13T00:00:00Z";
        sqlx::query("INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org-1', 'ConfigDeck', ?, ?)")
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES('user-1', 'org-1', 'user@example.test', 'user@example.test', 'hash', 'CONTRIBUTOR', ?, ?, ?)")
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
    }
}
