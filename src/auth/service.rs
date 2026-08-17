use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use anyhow::{Context, anyhow};
use sqlx::{FromRow, Row, SqlitePool};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::CryptoManager,
    db::now_rfc3339,
    error::AppError,
    users::{Role, RoleParseError},
};

use super::{
    AuthenticatedSession, AuthenticationState, PasswordService, PrivilegedAuthLevel,
    SessionManager, SessionTokens, bootstrap::normalize_email, session::SessionUser, totp,
};

const HOUSEKEEPING_INTERVAL_SECONDS: i64 = 24 * 60 * 60;
const LOGIN_ATTEMPT_RETENTION: Duration = Duration::hours(24);
const SESSION_RETENTION_AFTER_EXPIRY: Duration = Duration::days(30);

#[derive(Clone)]
pub struct AuthService {
    pool: SqlitePool,
    crypto: CryptoManager,
    passwords: PasswordService,
    sessions: SessionManager,
    dummy_password_hash: String,
    last_housekeeping_unix: Arc<AtomicI64>,
}

#[derive(Debug)]
pub struct AuthOutcome {
    pub tokens: SessionTokens,
    pub enrollment_required: bool,
    pub password_change_required: bool,
}

#[derive(Debug)]
pub struct EnrollmentData {
    pub encoded_secret: String,
    pub provisioning_uri: String,
}

#[derive(FromRow)]
struct UserAuthRow {
    id: String,
    organization_id: String,
    email: String,
    password_hash: String,
    role: String,
    active: bool,
    auth_version: i64,
    require_totp_all: bool,
    totp_secret_ciphertext: Option<Vec<u8>>,
    totp_secret_nonce: Option<Vec<u8>>,
    totp_crypto_version: Option<i64>,
    totp_enabled_at: Option<String>,
    totp_last_used_step: Option<i64>,
    must_change_password: bool,
}

impl AuthService {
    pub async fn new(
        pool: SqlitePool,
        crypto: CryptoManager,
        passwords: PasswordService,
        sessions: SessionManager,
    ) -> anyhow::Result<Self> {
        let dummy_password_hash = passwords
            .hash(Zeroizing::new(
                "configdeck-dummy-password-never-valid".to_owned(),
            ))
            .await
            .context("unable to initialize password verifier")?;
        Ok(Self {
            pool,
            crypto,
            passwords,
            sessions,
            dummy_password_hash,
            last_housekeeping_unix: Arc::new(AtomicI64::new(0)),
        })
    }

    pub async fn authenticate(
        &self,
        email: &str,
        password: Zeroizing<String>,
        totp_code: Option<&str>,
        client_identity: &str,
        user_agent: Option<&str>,
    ) -> Result<AuthOutcome, AppError> {
        self.maybe_prune_ephemeral_auth_state().await;
        let normalized = normalize_email(email).map_err(|_| AppError::Authentication)?;
        let account_hash = self
            .crypto
            .blind_index(b"login-account-index-v1", normalized.as_bytes())
            .map_err(|_| AppError::Crypto)?;
        let client_hash = self
            .crypto
            .blind_index(b"login-client-index-v1", client_identity.as_bytes())
            .map_err(|_| AppError::Crypto)?;
        if self.is_rate_limited(&account_hash, &client_hash).await? {
            return Err(AppError::RateLimited);
        }

        let user = sqlx::query_as::<_, UserAuthRow>(
            "SELECT u.id, u.organization_id, u.email, u.password_hash, u.role, u.active, u.auth_version, \
                    o.require_totp_all, u.totp_secret_ciphertext, u.totp_secret_nonce, \
                    u.totp_crypto_version, u.totp_enabled_at, u.totp_last_used_step, u.must_change_password \
             FROM users u JOIN organizations o ON o.id = u.organization_id \
             WHERE u.email_normalized = ?",
        )
        .bind(&normalized)
        .fetch_optional(&self.pool)
        .await?;

        let encoded_hash = user.as_ref().map_or_else(
            || self.dummy_password_hash.clone(),
            |row| row.password_hash.clone(),
        );
        let password_for_rehash = user
            .as_ref()
            .is_some_and(|row| self.passwords.needs_rehash(&row.password_hash))
            .then(|| Zeroizing::new(password.to_string()));
        let password_valid = self
            .passwords
            .verify(password, encoded_hash)
            .await
            .map_err(|error| AppError::Internal(anyhow!(error)))?;
        let Some(mut user) = user else {
            self.record_attempt(&account_hash, &client_hash, false)
                .await?;
            return Err(AppError::Authentication);
        };
        if !password_valid || !user.active {
            self.record_attempt(&account_hash, &client_hash, false)
                .await?;
            return Err(AppError::Authentication);
        }
        self.upgrade_password_if_needed(&user.id, password_for_rehash)
            .await?;

        let role: Role = user
            .role
            .parse()
            .map_err(|_: RoleParseError| AppError::Authentication)?;
        let requires_totp = role.requires_totp() || user.require_totp_all;
        let state = if requires_totp && user.totp_enabled_at.is_none() {
            if user.totp_secret_ciphertext.is_none() {
                self.create_pending_totp(&mut user).await?;
            }
            AuthenticationState::PasswordOnly
        } else {
            if requires_totp || user.totp_enabled_at.is_some() {
                let code = totp_code.ok_or(AppError::Authentication)?;
                self.verify_and_consume_totp(&user, code).await?;
            }
            AuthenticationState::Full
        };

        let now = now_rfc3339().map_err(AppError::Internal)?;
        sqlx::query("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&now)
            .bind(&user.id)
            .execute(&self.pool)
            .await?;
        self.record_attempt(&account_hash, &client_hash, true)
            .await?;
        self.audit_login(&user.id, client_identity, state).await?;

        let session_user = SessionUser {
            id: user.id,
            organization_id: user.organization_id,
            email: user.email,
            role,
            auth_version: user.auth_version,
            totp_enabled: user.totp_enabled_at.is_some(),
            must_change_password: user.must_change_password,
        };
        let tokens = self
            .sessions
            .create(&session_user, state, Some(client_identity), user_agent)
            .await?;
        Ok(AuthOutcome {
            tokens,
            enrollment_required: state == AuthenticationState::PasswordOnly,
            password_change_required: user.must_change_password,
        })
    }

    pub async fn enrollment_data(
        &self,
        session: &AuthenticatedSession,
    ) -> Result<EnrollmentData, AppError> {
        if session.authentication_state != AuthenticationState::PasswordOnly {
            return Err(AppError::Forbidden);
        }
        let row = self.load_user_auth(&session.user.id).await?;
        if row.totp_enabled_at.is_some() {
            return Err(AppError::Forbidden);
        }
        let seed = self.decrypt_seed(&row)?;
        Ok(EnrollmentData {
            encoded_secret: totp::encoded_secret(&seed),
            provisioning_uri: totp::provisioning_uri(&seed, &row.email),
        })
    }

    pub async fn confirm_totp(
        &self,
        session: &AuthenticatedSession,
        code: &str,
    ) -> Result<SessionTokens, AppError> {
        if session.authentication_state != AuthenticationState::PasswordOnly {
            return Err(AppError::Forbidden);
        }
        let row = self.load_user_auth(&session.user.id).await?;
        if row.totp_enabled_at.is_some() {
            return Err(AppError::Forbidden);
        }
        let seed = self.decrypt_seed(&row)?;
        let step = totp::verify_at(
            &seed,
            code,
            OffsetDateTime::now_utc().unix_timestamp(),
            None,
        )
        .map_err(|_| AppError::Authentication)?;
        let now = now_rfc3339().map_err(AppError::Internal)?;
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE users SET totp_enabled_at = ?, totp_last_used_step = ?, \
                    auth_version = auth_version + 1, updated_at = ? \
             WHERE id = ? AND totp_enabled_at IS NULL",
        )
        .bind(&now)
        .bind(step)
        .bind(&now)
        .bind(&row.id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AppError::Authentication);
        }
        sqlx::query(
            "INSERT INTO audit_logs(occurred_at, actor_user_id, action) VALUES(?, ?, 'ENABLE_TOTP')",
        )
        .bind(&now)
        .bind(&row.id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        let role = row
            .role
            .parse()
            .map_err(|_: RoleParseError| AppError::Authentication)?;
        let user = SessionUser {
            id: row.id,
            organization_id: row.organization_id,
            email: row.email,
            role,
            auth_version: row.auth_version + 1,
            totp_enabled: true,
            must_change_password: row.must_change_password,
        };
        self.sessions
            .rotate(session, &user, AuthenticationState::Full, None)
            .await
    }

    pub async fn recent_authenticate(
        &self,
        session: &AuthenticatedSession,
        password: Zeroizing<String>,
        totp_code: Option<&str>,
        level: PrivilegedAuthLevel,
    ) -> Result<SessionTokens, AppError> {
        session.require_full()?;
        let user = self.load_user_auth(&session.user.id).await?;
        let valid = self
            .passwords
            .verify(password, user.password_hash.clone())
            .await
            .map_err(|error| AppError::Internal(anyhow!(error)))?;
        if !valid || !user.active {
            return Err(AppError::Authentication);
        }
        if user
            .role
            .parse::<Role>()
            .map_err(|_| AppError::Authentication)?
            .requires_totp()
            || user.require_totp_all
            || user.totp_enabled_at.is_some()
        {
            self.verify_and_consume_totp(&user, totp_code.ok_or(AppError::Authentication)?)
                .await?;
        }
        self.sessions
            .rotate(
                session,
                &session.user,
                AuthenticationState::Full,
                Some(level),
            )
            .await
    }

    async fn create_pending_totp(&self, user: &mut UserAuthRow) -> Result<(), AppError> {
        let active_fingerprint: Vec<u8> =
            sqlx::query_scalar("SELECT fingerprint FROM kek_registry WHERE status = 'ACTIVE'")
                .fetch_one(&self.pool)
                .await?;
        if active_fingerprint != self.crypto.fingerprint() {
            return Err(AppError::Conflict);
        }
        let seed = totp::generate_secret().map_err(|_| AppError::Crypto)?;
        let encrypted = self
            .crypto
            .encrypt_totp_seed(&user.id, 1, &seed)
            .map_err(|_| AppError::Crypto)?;
        let kek_version: i64 =
            sqlx::query_scalar("SELECT kek_version FROM kek_registry WHERE status = 'ACTIVE'")
                .fetch_one(&self.pool)
                .await?;
        sqlx::query(
            "UPDATE users SET totp_secret_ciphertext = ?, totp_secret_nonce = ?, \
                    totp_crypto_version = 1, totp_kek_version = ?, updated_at = ? \
             WHERE id = ? AND totp_secret_ciphertext IS NULL",
        )
        .bind(&encrypted.ciphertext)
        .bind(encrypted.nonce.as_slice())
        .bind(kek_version)
        .bind(now_rfc3339().map_err(AppError::Internal)?)
        .bind(&user.id)
        .execute(&self.pool)
        .await?;
        user.totp_secret_ciphertext = Some(encrypted.ciphertext);
        user.totp_secret_nonce = Some(encrypted.nonce.to_vec());
        user.totp_crypto_version = Some(1);
        Ok(())
    }

    async fn upgrade_password_if_needed(
        &self,
        user_id: &str,
        password: Option<Zeroizing<String>>,
    ) -> Result<(), AppError> {
        let Some(password) = password else {
            return Ok(());
        };
        let upgraded = self
            .passwords
            .hash(password)
            .await
            .map_err(|error| AppError::Internal(anyhow!(error)))?;
        sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(upgraded)
            .bind(now_rfc3339().map_err(AppError::Internal)?)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn verify_and_consume_totp(
        &self,
        user: &UserAuthRow,
        code: &str,
    ) -> Result<(), AppError> {
        let seed = self.decrypt_seed(user)?;
        let step = totp::verify_at(
            &seed,
            code,
            OffsetDateTime::now_utc().unix_timestamp(),
            user.totp_last_used_step,
        )
        .map_err(|_| AppError::Authentication)?;
        let result = sqlx::query(
            "UPDATE users SET totp_last_used_step = ? WHERE id = ? \
             AND (totp_last_used_step IS NULL OR totp_last_used_step < ?)",
        )
        .bind(step)
        .bind(&user.id)
        .bind(step)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(AppError::Authentication)
        }
    }

    fn decrypt_seed(&self, user: &UserAuthRow) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let ciphertext = user
            .totp_secret_ciphertext
            .as_deref()
            .ok_or(AppError::Authentication)?;
        let nonce = user
            .totp_secret_nonce
            .as_deref()
            .ok_or(AppError::Authentication)?;
        let version = user
            .totp_crypto_version
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(AppError::Authentication)?;
        self.crypto
            .decrypt_totp_seed(&user.id, version, ciphertext, nonce)
            .map_err(|_| AppError::Crypto)
    }

    async fn load_user_auth(&self, user_id: &str) -> Result<UserAuthRow, AppError> {
        sqlx::query_as::<_, UserAuthRow>(
            "SELECT u.id, u.organization_id, u.email, u.password_hash, u.role, u.active, u.auth_version, \
                    o.require_totp_all, u.totp_secret_ciphertext, u.totp_secret_nonce, \
                    u.totp_crypto_version, u.totp_enabled_at, u.totp_last_used_step, u.must_change_password \
             FROM users u JOIN organizations o ON o.id = u.organization_id WHERE u.id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::Unauthorized)
    }

    async fn is_rate_limited(
        &self,
        account_hash: &[u8],
        client_hash: &[u8],
    ) -> Result<bool, AppError> {
        let cutoff = (OffsetDateTime::now_utc() - Duration::minutes(15))
            .format(&Rfc3339)
            .map_err(|error| AppError::Internal(error.into()))?;
        let client_failures: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM login_attempts \
             WHERE client_identity_hash = ? AND succeeded = 0 AND attempted_at >= ?",
        )
        .bind(client_hash)
        .bind(&cutoff)
        .fetch_one(&self.pool)
        .await?;
        if client_failures >= 30 {
            return Ok(true);
        }
        let row = sqlx::query(
            "SELECT COUNT(*) AS failures, MAX(attempted_at) AS last_attempt \
             FROM login_attempts WHERE account_key_hash = ? AND succeeded = 0 AND attempted_at >= ?",
        )
        .bind(account_hash)
        .bind(&cutoff)
        .fetch_one(&self.pool)
        .await?;
        let failures: i64 = row.try_get("failures")?;
        let last_attempt: Option<String> = row.try_get("last_attempt")?;
        if failures < 5 {
            return Ok(false);
        }
        let exponent = u32::try_from((failures - 5).min(8)).unwrap_or(8);
        let delay = i64::from(2_u32.pow(exponent)).min(300);
        let last = last_attempt
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
        Ok(last.is_some_and(|at| OffsetDateTime::now_utc() < at + Duration::seconds(delay)))
    }

    async fn maybe_prune_ephemeral_auth_state(&self) {
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let previous = self.last_housekeeping_unix.load(Ordering::Relaxed);
        if now_unix.saturating_sub(previous) < HOUSEKEEPING_INTERVAL_SECONDS {
            return;
        }
        if self
            .last_housekeeping_unix
            .compare_exchange(previous, now_unix, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        if let Err(error) = prune_ephemeral_auth_state(&self.pool, now).await {
            self.last_housekeeping_unix.store(0, Ordering::Release);
            tracing::warn!(error = %error, "ephemeral authentication state cleanup failed");
        }
    }

    async fn record_attempt(
        &self,
        account_hash: &[u8],
        client_hash: &[u8],
        succeeded: bool,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO login_attempts(account_key_hash, client_identity_hash, attempted_at, succeeded) \
             VALUES(?, ?, ?, ?)",
        )
        .bind(account_hash)
        .bind(client_hash)
        .bind(now_rfc3339().map_err(AppError::Internal)?)
        .bind(succeeded)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn audit_login(
        &self,
        user_id: &str,
        client_identity: &str,
        state: AuthenticationState,
    ) -> Result<(), AppError> {
        let action = if state == AuthenticationState::Full {
            "LOGIN"
        } else {
            "LOGIN_PASSWORD_ONLY"
        };
        sqlx::query(
            "INSERT INTO audit_logs(occurred_at, actor_user_id, action, client_ip, request_id) \
             VALUES(?, ?, ?, ?, ?)",
        )
        .bind(now_rfc3339().map_err(AppError::Internal)?)
        .bind(user_id)
        .bind(action)
        .bind(client_identity)
        .bind(Uuid::new_v4().to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

async fn prune_ephemeral_auth_state(
    pool: &SqlitePool,
    now: OffsetDateTime,
) -> Result<(), AppError> {
    let login_cutoff = (now - LOGIN_ATTEMPT_RETENTION)
        .format(&Rfc3339)
        .map_err(|error| AppError::Internal(error.into()))?;
    let session_cutoff = (now - SESSION_RETENTION_AFTER_EXPIRY)
        .format(&Rfc3339)
        .map_err(|error| AppError::Internal(error.into()))?;
    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM login_attempts WHERE attempted_at < ?")
        .bind(login_cutoff)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE absolute_expires_at < ?")
        .bind(session_cutoff)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE32_NOPAD;
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
    use zeroize::Zeroizing;

    use crate::{
        auth::{
            AuthenticationState, PasswordService, SessionManager, bootstrap_initial_admin, totp,
        },
        config::{BootstrapSettings, SessionSettings},
        crypto::CryptoManager,
        db::{initialize_and_validate_key_registry, test_pool},
        error::AppError,
    };

    use super::{AuthService, prune_ephemeral_auth_state};

    #[tokio::test]
    async fn bootstrap_admin_is_limited_until_totp_is_confirmed() {
        let pool = test_pool().await;
        let crypto = CryptoManager::new(Zeroizing::new([11; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let passwords = PasswordService::for_tests();
        bootstrap_initial_admin(
            &pool,
            &crypto,
            &passwords,
            &BootstrapSettings {
                admin_email: Some("admin@example.test".into()),
                admin_password: Some(Zeroizing::new("bootstrap-password".into())),
            },
        )
        .await
        .unwrap();
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
        let auth = AuthService::new(pool, crypto, passwords, sessions.clone())
            .await
            .unwrap();

        let outcome = auth
            .authenticate(
                "admin@example.test",
                Zeroizing::new("bootstrap-password".into()),
                None,
                "127.0.0.1",
                Some("test-agent"),
            )
            .await
            .unwrap();
        assert!(outcome.enrollment_required);
        let limited = sessions.load(&outcome.tokens.session_token).await.unwrap();
        assert_eq!(
            limited.authentication_state,
            AuthenticationState::PasswordOnly
        );
        assert!(limited.require_full().is_err());

        let enrollment = auth.enrollment_data(&limited).await.unwrap();
        let seed = BASE32_NOPAD
            .decode(enrollment.encoded_secret.as_bytes())
            .unwrap();
        let code = totp::code_at(&seed, time::OffsetDateTime::now_utc().unix_timestamp());
        let full_tokens = auth.confirm_totp(&limited, &code).await.unwrap();
        assert!(sessions.load(&outcome.tokens.session_token).await.is_err());
        let full = sessions.load(&full_tokens.session_token).await.unwrap();
        assert_eq!(full.authentication_state, AuthenticationState::Full);
        assert!(full.user.totp_enabled);
    }

    #[tokio::test]
    async fn repeated_account_failures_trigger_backoff_without_locking_account() {
        let pool = test_pool().await;
        let crypto = CryptoManager::new(Zeroizing::new([12; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let passwords = PasswordService::for_tests();
        bootstrap_initial_admin(
            &pool,
            &crypto,
            &passwords,
            &BootstrapSettings {
                admin_email: Some("admin@example.test".into()),
                admin_password: Some(Zeroizing::new("bootstrap-password".into())),
            },
        )
        .await
        .unwrap();
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
        let auth = AuthService::new(pool, crypto, passwords, sessions)
            .await
            .unwrap();
        for _ in 0..5 {
            assert!(
                auth.authenticate(
                    "admin@example.test",
                    Zeroizing::new("wrong-password".into()),
                    None,
                    "127.0.0.1",
                    None,
                )
                .await
                .is_err()
            );
        }
        let result = auth
            .authenticate(
                "admin@example.test",
                Zeroizing::new("bootstrap-password".into()),
                None,
                "127.0.0.1",
                None,
            )
            .await;
        assert!(matches!(result, Err(AppError::RateLimited)));
    }

    #[tokio::test]
    async fn ephemeral_authentication_rows_are_pruned_without_touching_recent_state() {
        let pool = test_pool().await;
        let crypto = CryptoManager::new(Zeroizing::new([13; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let passwords = PasswordService::for_tests();
        bootstrap_initial_admin(
            &pool,
            &crypto,
            &passwords,
            &BootstrapSettings {
                admin_email: Some("admin@example.test".into()),
                admin_password: Some(Zeroizing::new("bootstrap-password".into())),
            },
        )
        .await
        .unwrap();
        let user_id: String = sqlx::query_scalar("SELECT id FROM users LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        for (attempted_at, marker) in [
            ("2026-08-16T00:00:00Z", 1_u8),
            ("2026-08-17T12:00:00Z", 2_u8),
        ] {
            sqlx::query(
                "INSERT INTO login_attempts(account_key_hash, client_identity_hash, attempted_at, succeeded) \
                 VALUES(?, ?, ?, 0)",
            )
            .bind(vec![marker; 32])
            .bind(vec![marker + 10; 32])
            .bind(attempted_at)
            .execute(&pool)
            .await
            .unwrap();
        }
        for (id, absolute_expires_at, marker) in [
            ("old", "2026-06-01T00:00:00Z", 21_u8),
            ("recent", "2026-08-17T18:00:00Z", 22_u8),
        ] {
            sqlx::query(
                "INSERT INTO sessions(id, token_hash, csrf_token_hash, user_id, auth_version, \
                 created_at, last_seen_at, idle_expires_at, absolute_expires_at) \
                 VALUES(?, ?, ?, ?, 1, '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z', ?, ?)",
            )
            .bind(id)
            .bind(vec![marker; 32])
            .bind(vec![marker + 10; 32])
            .bind(&user_id)
            .bind(absolute_expires_at)
            .bind(absolute_expires_at)
            .execute(&pool)
            .await
            .unwrap();
        }

        let now = OffsetDateTime::parse("2026-08-18T00:00:00Z", &Rfc3339).unwrap();
        prune_ephemeral_auth_state(&pool, now).await.unwrap();

        let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM login_attempts")
            .fetch_one(&pool)
            .await
            .unwrap();
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(attempts, 1);
        assert_eq!(sessions, 1);
    }
}
