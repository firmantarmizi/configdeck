use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::{config::DatabaseSettings, crypto::CryptoManager};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn connect_and_migrate(settings: &DatabaseSettings) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(&settings.url)
        .context("invalid SQLite URL")?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(settings.busy_timeout);
    let pool = SqlitePoolOptions::new()
        .max_connections(settings.max_connections)
        .min_connections(1)
        .connect_with(options)
        .await
        .context("unable to open SQLite database")?;
    MIGRATOR
        .run(&pool)
        .await
        .context("unable to apply database migrations")?;
    Ok(pool)
}

pub async fn ready(pool: &SqlitePool) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(pool)
        .await
        .is_ok()
}

pub async fn initialize_and_validate_key_registry(
    pool: &SqlitePool,
    crypto: &CryptoManager,
) -> Result<()> {
    let fingerprint = crypto.fingerprint();
    let active =
        sqlx::query("SELECT kek_version, fingerprint FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_optional(pool)
            .await?;
    if let Some(row) = active {
        let stored: Vec<u8> = row.try_get("fingerprint")?;
        let previous_matches = crypto
            .previous_fingerprint()
            .is_some_and(|previous| previous == stored);
        if stored != fingerprint && !previous_matches {
            anyhow::bail!("configured master key does not match the active KEK fingerprint");
        }
    } else {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kek_registry")
            .fetch_one(pool)
            .await?;
        if count != 0 {
            anyhow::bail!("KEK registry has no active key");
        }
        sqlx::query(
            "INSERT INTO kek_registry(kek_version, fingerprint, status, activated_at) \
             VALUES(1, ?, 'ACTIVE', ?)",
        )
        .bind(fingerprint)
        .bind(now_rfc3339()?)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn validate_active_environment_keys(
    pool: &SqlitePool,
    crypto: &CryptoManager,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT environment_id, dek_version, kek_version, wrapped_dek, wrapped_dek_nonce \
         FROM environment_keys WHERE status = 'ACTIVE'",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let environment_id: String = row.try_get("environment_id")?;
        let dek_version: i64 = row.try_get("dek_version")?;
        let kek_version: i64 = row.try_get("kek_version")?;
        let ciphertext: Vec<u8> = row.try_get("wrapped_dek")?;
        let nonce: Vec<u8> = row.try_get("wrapped_dek_nonce")?;
        crypto
            .unwrap_dek(
                &environment_id,
                u64::try_from(dek_version)?,
                u64::try_from(kek_version)?,
                &ciphertext,
                &nonce,
            )
            .context("an active environment DEK could not be validated")?;
    }
    Ok(())
}

pub async fn validate_totp_seeds(pool: &SqlitePool, crypto: &CryptoManager) -> Result<()> {
    let active_kek_version: i64 =
        sqlx::query_scalar("SELECT kek_version FROM kek_registry WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;
    let rows = sqlx::query(
        "SELECT id, totp_secret_ciphertext, totp_secret_nonce, totp_crypto_version, totp_kek_version \
         FROM users WHERE totp_secret_ciphertext IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let user_id: String = row.try_get("id")?;
        let ciphertext: Vec<u8> = row.try_get("totp_secret_ciphertext")?;
        let nonce: Vec<u8> = row.try_get("totp_secret_nonce")?;
        let crypto_version: i64 = row.try_get("totp_crypto_version")?;
        let kek_version: i64 = row.try_get("totp_kek_version")?;
        if kek_version != active_kek_version {
            anyhow::bail!("a TOTP seed does not reference the active KEK version");
        }
        crypto
            .decrypt_totp_seed(
                &user_id,
                u64::try_from(crypto_version)?,
                &ciphertext,
                &nonce,
            )
            .context("a TOTP seed could not be validated")?;
    }
    Ok(())
}

pub fn now_rfc3339() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?)
}

#[cfg(test)]
pub async fn test_pool() -> SqlitePool {
    let options = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("valid test database URL")
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("test database opens");
    MIGRATOR.run(&pool).await.expect("migrations apply");
    pool
}

#[cfg(test)]
mod tests {
    use sqlx::Row;
    use zeroize::Zeroizing;

    use crate::crypto::CryptoManager;

    use super::{initialize_and_validate_key_registry, test_pool};

    #[tokio::test]
    async fn migration_applies_to_empty_database_with_foreign_keys_enabled() {
        let pool = test_pool().await;
        let enabled: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(enabled, 1);
        let row = sqlx::query("PRAGMA foreign_key_check")
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert!(row.is_none());
        let count: i64 =
            sqlx::query("SELECT COUNT(*) AS count FROM sqlite_schema WHERE type='table'")
                .fetch_one(&pool)
                .await
                .unwrap()
                .try_get("count")
                .unwrap();
        assert!(count >= 17);
    }

    #[tokio::test]
    async fn organization_logo_columns_reject_incomplete_or_unsupported_data() {
        let pool = test_pool().await;
        let incomplete = sqlx::query(
            "INSERT INTO organizations(id, name, logo_mime_type, created_at, updated_at) VALUES('incomplete', 'Incomplete', 'image/png', '2026-08-15T00:00:00Z', '2026-08-15T00:00:00Z')",
        )
        .execute(&pool)
        .await;
        assert!(incomplete.is_err());
        let unsupported = sqlx::query(
            "INSERT INTO organizations(id, name, logo_mime_type, logo_data, logo_updated_at, created_at, updated_at) VALUES('unsupported', 'Unsupported', 'image/svg+xml', ?, '2026-08-15T00:00:00Z', '2026-08-15T00:00:00Z', '2026-08-15T00:00:00Z')",
        )
        .bind(b"<svg></svg>".as_slice())
        .execute(&pool)
        .await;
        assert!(unsupported.is_err());
    }

    #[tokio::test]
    async fn wrong_startup_key_fails_without_changing_registry() {
        let pool = test_pool().await;
        let first = CryptoManager::new(Zeroizing::new([1; 32]));
        let wrong = CryptoManager::new(Zeroizing::new([2; 32]));
        initialize_and_validate_key_registry(&pool, &first)
            .await
            .unwrap();
        let stored_before: Vec<u8> =
            sqlx::query_scalar("SELECT fingerprint FROM kek_registry WHERE status = 'ACTIVE'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            initialize_and_validate_key_registry(&pool, &wrong)
                .await
                .is_err()
        );
        let stored_after: Vec<u8> =
            sqlx::query_scalar("SELECT fingerprint FROM kek_registry WHERE status = 'ACTIVE'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_before, stored_after);
    }
}
