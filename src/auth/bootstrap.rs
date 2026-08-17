use anyhow::{Context, Result};
use sqlx::SqlitePool;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{config::BootstrapSettings, crypto::CryptoManager, db::now_rfc3339};

use super::PasswordService;

const ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000001";

pub async fn bootstrap_initial_admin(
    pool: &SqlitePool,
    _crypto: &CryptoManager,
    passwords: &PasswordService,
    settings: &BootstrapSettings,
) -> Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    if count > 0 {
        return Ok(());
    }

    let email = settings
        .admin_email
        .as_deref()
        .context("database has no users; CONFIGDECK_ADMIN_EMAIL is required")?;
    let password = settings
        .admin_password
        .as_ref()
        .context("database has no users; CONFIGDECK_ADMIN_PASSWORD is required")?;
    let normalized = normalize_email(email)?;
    if password.len() < 12 {
        anyhow::bail!("bootstrap administrator password must contain at least 12 bytes");
    }
    let password_hash = passwords
        .hash(Zeroizing::new(password.to_string()))
        .await
        .context("unable to hash bootstrap administrator password")?;
    let now = now_rfc3339()?;
    let user_id = Uuid::new_v4().to_string();

    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT OR IGNORE INTO organizations(id, name, created_at, updated_at) \
         VALUES(?, 'ConfigDeck', ?, ?)",
    )
    .bind(ORGANIZATION_ID)
    .bind(&now)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO users(\
            id, organization_id, email, email_normalized, password_hash, role, active, \
            password_changed_at, must_change_password, created_at, updated_at\
         ) VALUES(?, ?, ?, ?, ?, 'ADMINISTRATOR', 1, ?, 1, ?, ?)",
    )
    .bind(&user_id)
    .bind(ORGANIZATION_ID)
    .bind(email.trim())
    .bind(normalized)
    .bind(password_hash)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json) \
         VALUES(?, ?, 'CREATE_USER', '{\"bootstrap\":true}')",
    )
    .bind(&now)
    .bind(&user_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    tracing::warn!("bootstrap administrator created; remove bootstrap password from deployment");
    Ok(())
}

pub(crate) fn normalize_email(email: &str) -> Result<String> {
    let normalized = email.trim().to_lowercase();
    if normalized.len() > 320
        || !normalized.contains('@')
        || normalized.starts_with('@')
        || normalized.ends_with('@')
    {
        anyhow::bail!("invalid administrator email address");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use crate::{
        auth::PasswordService,
        config::BootstrapSettings,
        crypto::CryptoManager,
        db::{initialize_and_validate_key_registry, test_pool},
    };

    use super::bootstrap_initial_admin;

    #[tokio::test]
    async fn bootstrap_creates_admin_only_when_user_table_is_empty() {
        let pool = test_pool().await;
        let crypto = CryptoManager::new(Zeroizing::new([5; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let passwords = PasswordService::for_tests();
        let first = BootstrapSettings {
            admin_email: Some("ADMIN@example.test".into()),
            admin_password: Some(Zeroizing::new("first-password".into())),
        };
        bootstrap_initial_admin(&pool, &crypto, &passwords, &first)
            .await
            .unwrap();
        let second = BootstrapSettings {
            admin_email: Some("other@example.test".into()),
            admin_password: Some(Zeroizing::new("second-password".into())),
        };
        bootstrap_initial_admin(&pool, &crypto, &passwords, &second)
            .await
            .unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        let email: String = sqlx::query_scalar("SELECT email_normalized FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(email, "admin@example.test");
        let onboarding: Option<String> =
            sqlx::query_scalar("SELECT onboarding_completed_at FROM organizations")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(onboarding.is_none());
        let must_change: bool = sqlx::query_scalar("SELECT must_change_password FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(must_change);
    }
}
