use crate::{
    auth::{AuthenticatedSession, SessionManager},
    config::OperationsSettings,
    error::AppError,
    users::Capability,
};
use sha2::{Digest as _, Sha256};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};
use std::{
    fs::OpenOptions,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::Path,
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const BATCH_SIZE: i64 = 1_000;
const RETENTION_DAYS: i64 = 180;
const DELETE_GUARD: &str = "CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit_logs are append-only'); END";

pub async fn archive(
    pool: &SqlitePool,
    settings: &OperationsSettings,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
) -> Result<usize, AppError> {
    super::require_recent_administrator(sessions, session, Capability::CreateBackup)?;
    let directory = super::checked_directory(&settings.backup_dir).await?;
    archive_batch(
        pool,
        &directory,
        &session.user.id,
        OffsetDateTime::now_utc(),
    )
    .await
}

async fn archive_batch(
    pool: &SqlitePool,
    directory: &Path,
    actor: &str,
    now: OffsetDateTime,
) -> Result<usize, AppError> {
    let cutoff = (now - Duration::days(RETENTION_DAYS))
        .format(&Rfc3339)
        .map_err(|e| AppError::Internal(e.into()))?;
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    // Preserve original columns and resolved names; archive never selects configuration values.
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT a.id, json_object('id', a.id, 'occurred_at', a.occurred_at, 'actor_user_id', a.actor_user_id,
        'action', a.action, 'outcome', a.outcome, 'service_id', a.service_id, 'environment_id', a.environment_id,
        'variable_id', a.variable_id, 'variable_key', a.variable_key, 'change_request_id', a.change_request_id,
        'request_id', a.request_id, 'client_ip', a.client_ip, 'user_agent', a.user_agent, 'metadata_json', a.metadata_json,
        'actor_email', u.email, 'service_name', s.name, 'environment_name', e.name)
        FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id
        LEFT JOIN services s ON s.id = a.service_id LEFT JOIN environments e ON e.id = a.environment_id
        WHERE a.occurred_at < ? ORDER BY a.occurred_at, a.id LIMIT ?")
        .bind(&cutoff).bind(BATCH_SIZE).fetch_all(&mut *transaction).await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let count = rows.len();
    let identifier = format!(
        "audit-{}-{}.jsonl",
        now.unix_timestamp(),
        Uuid::new_v4().simple()
    );
    let destination = directory.join(&identifier);
    let header =
        serde_json::json!({"format": "configdeck-audit-v1", "cutoff": cutoff, "records": count});
    let mut contents = header.to_string();
    contents.push('\n');
    for (_, row) in &rows {
        contents.push_str(row);
        contents.push('\n');
    }
    let checksum =
        tokio::task::spawn_blocking(move || write_verified(&destination, contents.as_bytes()))
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .map_err(AppError::Internal)?;
    // The exclusive writer transaction isolates the short deletion exception. On every failure
    // SQLite rolls back both deletion and DDL, restoring the original append-only guard.
    sqlx::query("DROP TRIGGER audit_logs_no_delete")
        .execute(&mut *transaction)
        .await?;
    let mut delete = QueryBuilder::<Sqlite>::new("DELETE FROM audit_logs WHERE id IN (");
    let mut ids = delete.separated(",");
    for (id, _) in &rows {
        ids.push_bind(*id);
    }
    ids.push_unseparated(")");
    let deleted = delete
        .build()
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    if deleted != u64::try_from(count).map_err(|_| AppError::InvalidRequest)? {
        return Err(AppError::Conflict);
    }
    sqlx::query(DELETE_GUARD).execute(&mut *transaction).await?;
    let metadata = serde_json::json!({"archive_identifier": identifier, "archive_sha256": checksum, "record_count": count, "retention_days": RETENTION_DAYS});
    sqlx::query("INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json) VALUES(?, ?, 'ARCHIVE_AUDIT', ?)")
        .bind(now.format(&Rfc3339).map_err(|e| AppError::Internal(e.into()))?).bind(actor).bind(metadata.to_string())
        .execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(count)
}

fn write_verified(path: &Path, contents: &[u8]) -> anyhow::Result<String> {
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    // Read back through the same file handle, never following a replacement symlink.
    file.seek(SeekFrom::Start(0))?;
    let expected = Sha256::digest(contents);
    let mut actual = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        actual.update(&buffer[..n]);
    }
    anyhow::ensure!(
        actual.finalize() == expected,
        "audit archive verification failed"
    );
    #[cfg(unix)]
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("archive directory missing"))?,
    )?
    .sync_all()?;
    Ok(data_encoding::HEXLOWER.encode(&expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn archive_is_bounded_durable_and_preserves_recent_events_and_delete_guard() {
        let pool = crate::db::test_pool().await;
        sqlx::query("INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org', 'Test', 'now', 'now')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES('admin', 'org', 'admin@example.test', 'admin@example.test', 'synthetic', 'ADMINISTRATOR', 'now', 'now', 'now')").execute(&pool).await.unwrap();
        for _ in 0..1001 {
            sqlx::query("INSERT INTO audit_logs(occurred_at, action) VALUES('2025-01-01T00:00:00Z', 'LOGIN')").execute(&pool).await.unwrap();
        }
        sqlx::query(
            "INSERT INTO audit_logs(occurred_at, action) VALUES('2026-09-28T00:00:00Z', 'LOGOUT')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let now = OffsetDateTime::parse("2026-09-28T12:00:00Z", &Rfc3339).unwrap();
        // Filesystem failure cannot remove a single event.
        assert!(
            archive_batch(&pool, &dir.path().join("missing"), "admin", now)
                .await
                .is_err()
        );
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(before, 1002);
        // A database failure after verification leaves recoverable evidence and rolls back DDL.
        sqlx::query("CREATE TRIGGER archive_test_fail BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT, 'synthetic fault'); END").execute(&pool).await.unwrap();
        assert!(
            archive_batch(&pool, dir.path(), "admin", now)
                .await
                .is_err()
        );
        sqlx::query("DROP TRIGGER archive_test_fail")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            sqlx::query("DELETE FROM audit_logs")
                .execute(&pool)
                .await
                .is_err()
        );
        assert_eq!(
            archive_batch(&pool, dir.path(), "admin", now)
                .await
                .unwrap(),
            1000
        );
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 3); // expired remainder, recent event, archival receipt
        assert!(
            sqlx::query("DELETE FROM audit_logs")
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("UPDATE audit_logs SET action = 'ALTERED'")
                .execute(&pool)
                .await
                .is_err()
        );
        let receipt: String = sqlx::query_scalar(
            "SELECT metadata_json FROM audit_logs WHERE action = 'ARCHIVE_AUDIT'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        let bytes = std::fs::read(
            dir.path()
                .join(receipt["archive_identifier"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&Sha256::digest(&bytes)),
            receipt["archive_sha256"].as_str().unwrap()
        );
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().count(), 1001);
        assert!(!text.contains("LOGOUT"));
        assert_eq!(
            archive_batch(&pool, dir.path(), "admin", now)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            archive_batch(&pool, dir.path(), "admin", now)
                .await
                .unwrap(),
            0
        );
    }
}
