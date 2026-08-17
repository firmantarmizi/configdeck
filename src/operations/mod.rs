use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    str::FromStr as _,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    auth::{AuthenticatedSession, PrivilegedAuthLevel, SessionManager},
    config::OperationsSettings,
    db::now_rfc3339,
    error::AppError,
    users::Capability,
};

const MAX_REASON_BYTES: usize = 1_000;

#[derive(Clone, Debug)]
pub struct BackupRecord {
    pub identifier: String,
    pub size_bytes: u64,
    pub created_display: String,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RestoreIntent {
    pub requested_by_user_id: String,
    pub requested_at: String,
    pub backup_identifier: String,
    pub reason: String,
    pub backup_sha256: String,
    pub backup_size_bytes: u64,
}

#[derive(Debug)]
struct SnapshotIdentity {
    size_bytes: u64,
    sha256: String,
}

pub async fn list_backups(
    settings: &OperationsSettings,
    session: &AuthenticatedSession,
) -> Result<Vec<BackupRecord>, AppError> {
    require_administrator(session, Capability::CreateBackup)?;
    let backup_dir = checked_directory(&settings.backup_dir).await?;
    tokio::task::spawn_blocking(move || list_backups_blocking(&backup_dir))
        .await
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error)))?
}

pub async fn create_backup(
    pool: &SqlitePool,
    settings: &OperationsSettings,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
) -> Result<BackupRecord, AppError> {
    require_recent_administrator(sessions, session, Capability::CreateBackup)?;
    let backup_dir = checked_directory(&settings.backup_dir).await?;
    let identifier = generate_backup_identifier();
    validate_backup_identifier(&identifier)?;
    let destination = backup_dir.join(&identifier);
    reject_existing_path(&destination).await?;

    let destination_text = destination
        .to_str()
        .ok_or(AppError::InvalidRequest)?
        .to_owned();
    if let Err(error) = sqlx::query("VACUUM INTO ?")
        .bind(destination_text)
        .execute(pool)
        .await
    {
        return Err(AppError::Database(error));
    }

    let identity = match validate_snapshot_file(&backup_dir, &destination).await {
        Ok(identity) => identity,
        Err(error) => {
            let _ = remove_regular_file(&destination).await;
            return Err(error);
        }
    };
    if let Err(error) = validate_sqlite_snapshot(&destination).await {
        let _ = remove_regular_file(&destination).await;
        return Err(error);
    }

    let now = now_rfc3339()?;
    let metadata = serde_json::json!({
        "backup_identifier": identifier,
        "backup_sha256": identity.sha256,
        "backup_size_bytes": identity.size_bytes,
    });
    if let Err(error) = sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json) VALUES(?, ?, 'CREATE_BACKUP', ?)",
    )
    .bind(&now)
    .bind(&session.user.id)
    .bind(metadata.to_string())
    .execute(pool)
    .await
    {
        let _ = remove_regular_file(&destination).await;
        return Err(AppError::Database(error));
    }

    Ok(BackupRecord {
        identifier,
        size_bytes: identity.size_bytes,
        created_display: display_time(&now),
        sha256: Some(identity.sha256),
    })
}

pub async fn create_restore_intent(
    pool: &SqlitePool,
    settings: &OperationsSettings,
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    backup_identifier: &str,
    reason: &str,
) -> Result<(), AppError> {
    require_recent_administrator(sessions, session, Capability::CreateRestoreIntent)?;
    validate_backup_identifier(backup_identifier)?;
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
        return Err(AppError::InvalidRequest);
    }

    let backup_dir = checked_directory(&settings.backup_dir).await?;
    let backup_path = backup_dir.join(backup_identifier);
    let identity = validate_snapshot_file(&backup_dir, &backup_path).await?;
    validate_sqlite_snapshot(&backup_path).await?;
    let requested_at = now_rfc3339()?;
    let intent = RestoreIntent {
        requested_by_user_id: session.user.id.clone(),
        requested_at: requested_at.clone(),
        backup_identifier: backup_identifier.to_owned(),
        reason: reason.to_owned(),
        backup_sha256: identity.sha256.clone(),
        backup_size_bytes: identity.size_bytes,
    };
    write_restore_intent(&settings.restore_intent_path, &intent).await?;

    let metadata = serde_json::json!({
        "backup_identifier": backup_identifier,
        "backup_sha256": identity.sha256,
        "backup_size_bytes": identity.size_bytes,
        "reason_length": reason.len(),
    });
    if let Err(error) = sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json) VALUES(?, ?, 'CREATE_RESTORE_INTENT', ?)",
    )
    .bind(requested_at)
    .bind(&session.user.id)
    .bind(metadata.to_string())
    .execute(pool)
    .await
    {
        let _ = remove_regular_file(&settings.restore_intent_path).await;
        return Err(AppError::Database(error));
    }
    Ok(())
}

pub async fn read_restore_intent(
    settings: &OperationsSettings,
    session: &AuthenticatedSession,
) -> Result<Option<RestoreIntent>, AppError> {
    require_administrator(session, Capability::CreateRestoreIntent)?;
    read_and_validate_restore_intent(settings).await
}

pub async fn reconcile_restore_intent(
    pool: &SqlitePool,
    settings: &OperationsSettings,
) -> anyhow::Result<()> {
    let Some(intent) = read_and_validate_restore_intent(settings)
        .await
        .map_err(|error| anyhow::anyhow!(error))?
    else {
        return Ok(());
    };

    validate_live_database(pool).await?;
    let actor_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)")
        .bind(&intent.requested_by_user_id)
        .fetch_one(pool)
        .await?;
    let metadata = serde_json::json!({
        "backup_identifier": intent.backup_identifier,
        "backup_sha256": intent.backup_sha256,
        "backup_size_bytes": intent.backup_size_bytes,
        "reason_length": intent.reason.len(),
        "requested_at": intent.requested_at,
        "requested_by_user_id": intent.requested_by_user_id,
    });
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json) VALUES(?, ?, 'RESTORE_BACKUP', ?)",
    )
    .bind(now_rfc3339()?)
    .bind(actor_exists.then_some(intent.requested_by_user_id))
    .bind(metadata.to_string())
    .execute(pool)
    .await?;
    sqlx::query("PRAGMA wal_checkpoint(FULL)")
        .execute(pool)
        .await?;
    remove_regular_file(&settings.restore_intent_path)
        .await
        .map_err(|error| anyhow::anyhow!(error))?;
    sync_parent(&settings.restore_intent_path)?;
    Ok(())
}

pub async fn preflight_restore_intent(
    settings: &OperationsSettings,
    database_url: &str,
) -> anyhow::Result<()> {
    let Some(intent) = read_and_validate_restore_intent(settings)
        .await
        .map_err(|error| anyhow::anyhow!(error))?
    else {
        return Ok(());
    };
    let options = sqlx::sqlite::SqliteConnectOptions::from_str(database_url)
        .map_err(|_| anyhow::anyhow!("invalid SQLite URL during restore preflight"))?;
    let database_path = options.get_filename().to_owned();
    if database_path == Path::new(":memory:") {
        anyhow::bail!("restore intent cannot target an in-memory database");
    }
    let database_identity = regular_file_identity(&database_path).await?;
    if database_identity.size_bytes != intent.backup_size_bytes
        || database_identity.sha256 != intent.backup_sha256
    {
        anyhow::bail!("active database does not match the restore intent snapshot");
    }
    Ok(())
}

async fn read_and_validate_restore_intent(
    settings: &OperationsSettings,
) -> Result<Option<RestoreIntent>, AppError> {
    let marker = settings.restore_intent_path.clone();
    let bytes = match tokio::task::spawn_blocking(move || read_regular_file(&marker)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(Err(error)) => return Err(AppError::Internal(error.into())),
        Err(error) => return Err(AppError::Internal(error.into())),
    };
    if bytes.len() > 8 * 1024 {
        return Err(AppError::InvalidRequest);
    }
    let intent: RestoreIntent =
        serde_json::from_slice(&bytes).map_err(|_| AppError::InvalidRequest)?;
    validate_restore_intent_fields(&intent)?;
    let backup_dir = checked_directory(&settings.backup_dir).await?;
    let backup_path = backup_dir.join(&intent.backup_identifier);
    let identity = validate_snapshot_file(&backup_dir, &backup_path).await?;
    if identity.size_bytes != intent.backup_size_bytes || identity.sha256 != intent.backup_sha256 {
        return Err(AppError::Conflict);
    }
    validate_sqlite_snapshot(&backup_path).await?;
    Ok(Some(intent))
}

fn validate_restore_intent_fields(intent: &RestoreIntent) -> Result<(), AppError> {
    validate_backup_identifier(&intent.backup_identifier)?;
    if Uuid::parse_str(&intent.requested_by_user_id).is_err()
        || OffsetDateTime::parse(&intent.requested_at, &Rfc3339).is_err()
        || intent.reason.trim().is_empty()
        || intent.reason.len() > MAX_REASON_BYTES
        || intent.backup_size_bytes == 0
        || intent.backup_sha256.len() != 64
        || !intent
            .backup_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AppError::InvalidRequest);
    }
    Ok(())
}

fn require_administrator(
    session: &AuthenticatedSession,
    capability: Capability,
) -> Result<(), AppError> {
    session.require_full()?;
    if session.user.role.allows(capability) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn require_recent_administrator(
    sessions: &SessionManager,
    session: &AuthenticatedSession,
    capability: Capability,
) -> Result<(), AppError> {
    require_administrator(session, capability)?;
    if sessions.has_recent_auth(session, PrivilegedAuthLevel::Standard) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn generate_backup_identifier() -> String {
    let now = OffsetDateTime::now_utc();
    let random = Uuid::new_v4().simple().to_string();
    format!(
        "configdeck-{:04}{:02}{:02}T{:02}{:02}{:02}Z-{}.db",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        &random[..8]
    )
}

pub fn validate_backup_identifier(identifier: &str) -> Result<(), AppError> {
    let bytes = identifier.as_bytes();
    let valid = bytes.len() == 39
        && identifier.starts_with("configdeck-")
        && &bytes[36..] == b".db"
        && bytes[19] == b'T'
        && bytes[26] == b'Z'
        && bytes[27] == b'-'
        && bytes[11..19].iter().all(u8::is_ascii_digit)
        && bytes[20..26].iter().all(u8::is_ascii_digit)
        && bytes[28..36].iter().all(u8::is_ascii_hexdigit)
        && !identifier.contains(['/', '\\']);
    if valid {
        Ok(())
    } else {
        Err(AppError::InvalidRequest)
    }
}

async fn checked_directory(path: &Path) -> Result<PathBuf, AppError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("configured backup directory is not a real directory");
        }
        Ok(fs::canonicalize(path)?)
    })
    .await
    .map_err(|error| AppError::Internal(error.into()))?
    .map_err(AppError::Internal)
}

async fn reject_existing_path(path: &Path) -> Result<(), AppError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(AppError::Conflict),
        Err(error) => Err(AppError::Internal(error.into())),
    })
    .await
    .map_err(|error| AppError::Internal(error.into()))?
}

async fn validate_snapshot_file(
    backup_dir: &Path,
    path: &Path,
) -> Result<SnapshotIdentity, AppError> {
    let backup_dir = backup_dir.to_owned();
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            anyhow::bail!("backup snapshot must be a non-empty regular file");
        }
        let canonical = fs::canonicalize(&path)?;
        if canonical.parent() != Some(backup_dir.as_path()) {
            anyhow::bail!("backup snapshot resolved outside the configured directory");
        }
        let mut file = File::open(&canonical)?;
        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        let mut sha256 = String::with_capacity(64);
        for byte in digest.finalize() {
            write!(&mut sha256, "{byte:02x}")?;
        }
        Ok(SnapshotIdentity {
            size_bytes: metadata.len(),
            sha256,
        })
    })
    .await
    .map_err(|error| AppError::Internal(error.into()))?
    .map_err(AppError::Internal)
}

async fn regular_file_identity(path: &Path) -> anyhow::Result<SnapshotIdentity> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            anyhow::bail!("database must be a non-empty regular file");
        }
        snapshot_identity_blocking(&path, &metadata)
    })
    .await
    .map_err(|error| anyhow::anyhow!(error))?
}

async fn validate_sqlite_snapshot(path: &Path) -> Result<(), AppError> {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    validate_live_database(&pool)
        .await
        .map_err(AppError::Internal)?;
    pool.close().await;
    Ok(())
}

async fn validate_live_database(pool: &SqlitePool) -> anyhow::Result<()> {
    let quick_check: String = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_one(pool)
        .await?;
    if quick_check != "ok" {
        anyhow::bail!("SQLite integrity check failed");
    }
    let foreign_key_violation = sqlx::query("PRAGMA foreign_key_check")
        .fetch_optional(pool)
        .await?;
    if foreign_key_violation.is_some() {
        anyhow::bail!("SQLite foreign key check failed");
    }
    let migrations_table: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = '_sqlx_migrations')",
    )
    .fetch_one(pool)
    .await?;
    if !migrations_table {
        anyhow::bail!("SQLite migration metadata is missing");
    }
    Ok(())
}

async fn write_restore_intent(path: &Path, intent: &RestoreIntent) -> Result<(), AppError> {
    let path = path.to_owned();
    let bytes = serde_json::to_vec(intent).map_err(|error| AppError::Internal(error.into()))?;
    tokio::task::spawn_blocking(move || write_restore_intent_blocking(&path, &bytes))
        .await
        .map_err(|error| AppError::Internal(error.into()))?
        .map_err(AppError::Internal)
}

fn write_restore_intent_blocking(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("restore marker has no parent directory"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        anyhow::bail!("restore marker parent is not a real directory");
    }
    if fs::symlink_metadata(path).is_ok() {
        anyhow::bail!("a restore intent is already active");
    }
    let temporary = parent.join(format!(".restore-intent-{}.tmp", Uuid::new_v4().simple()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    if let Err(error) = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        sync_parent(path)?;
        Ok(())
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    {
        let target = path.parent().unwrap_or(path);
        let _ = fs::metadata(target)?;
    }
    Ok(())
}

fn read_regular_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::other("path is not a regular file"));
    }
    fs::read(path)
}

async fn remove_regular_file(path: &Path) -> Result<(), AppError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(std::io::Error::other(
                "refusing to remove a non-regular file",
            ));
        }
        fs::remove_file(path)
    })
    .await
    .map_err(|error| AppError::Internal(error.into()))?
    .map_err(|error| AppError::Internal(error.into()))
}

fn list_backups_blocking(backup_dir: &Path) -> Result<Vec<BackupRecord>, AppError> {
    let mut backups = Vec::new();
    for entry in fs::read_dir(backup_dir).map_err(|error| AppError::Internal(error.into()))? {
        let entry = entry.map_err(|error| AppError::Internal(error.into()))?;
        let identifier = entry.file_name().to_string_lossy().into_owned();
        if validate_backup_identifier(&identifier).is_err() {
            continue;
        }
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|error| AppError::Internal(error.into()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            continue;
        }
        let created = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .and_then(|timestamp| OffsetDateTime::from_unix_timestamp(timestamp).ok())
            .and_then(|value| value.format(&Rfc3339).ok())
            .unwrap_or_default();
        let identity =
            snapshot_identity_blocking(&entry.path(), &metadata).map_err(AppError::Internal)?;
        backups.push(BackupRecord {
            identifier,
            size_bytes: metadata.len(),
            created_display: display_time(&created),
            sha256: Some(identity.sha256),
        });
    }
    backups.sort_by(|left, right| right.identifier.cmp(&left.identifier));
    Ok(backups)
}

fn snapshot_identity_blocking(
    path: &Path,
    metadata: &fs::Metadata,
) -> anyhow::Result<SnapshotIdentity> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let mut sha256 = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut sha256, "{byte:02x}")?;
    }
    Ok(SnapshotIdentity {
        size_bytes: metadata.len(),
        sha256,
    })
}

fn display_time(value: &str) -> String {
    OffsetDateTime::parse(value, &Rfc3339).ok().map_or_else(
        || value.to_owned(),
        |time| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                time.year(),
                u8::from(time.month()),
                time.day(),
                time.hour(),
                time.minute()
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration as StdDuration};

    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};
    use zeroize::Zeroizing;

    use crate::{
        auth::{
            AuthenticatedSession, AuthenticationState, PrivilegedAuthLevel, SessionManager,
            SessionUser,
        },
        config::{DatabaseSettings, OperationsSettings, SessionSettings},
        crypto::CryptoManager,
        db::{
            connect_and_migrate, initialize_and_validate_key_registry,
            validate_active_environment_keys,
        },
        users::Role,
    };

    use super::{
        create_backup, create_restore_intent, list_backups, preflight_restore_intent,
        reconcile_restore_intent, validate_backup_identifier,
    };

    #[test]
    fn backup_identifier_rejects_paths_and_confusables() {
        assert!(validate_backup_identifier("configdeck-20260817T120000Z-a1b2c3d4.db").is_ok());
        for invalid in [
            "../configdeck-20260817T120000Z-a1b2c3d4.db",
            "configdeck-20260817T120000Z-a1b2c3d4.db/extra",
            "configdeck-２０２６0817T120000Z-a1b2c3d4.db",
            "configdeck-20260817T120000Z-a1b2c3zz.db",
        ] {
            assert!(validate_backup_identifier(invalid).is_err());
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn backup_and_offline_restore_drill_preserves_marker_until_durable_audit() {
        let root = tempdir().unwrap();
        let data_dir = root.path().join("data");
        let backup_dir = root.path().join("backup");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        let database_path = data_dir.join("configdeck.db");
        let database_url = format!(
            "sqlite://{}",
            database_path.to_string_lossy().replace('\\', "/")
        );
        let database = DatabaseSettings {
            url: database_url,
            max_connections: 2,
            busy_timeout: StdDuration::from_secs(2),
        };
        let operations = OperationsSettings {
            backup_dir: backup_dir.clone(),
            restore_intent_path: data_dir.join("restore-intent.json"),
        };
        let pool = connect_and_migrate(&database).await.unwrap();
        let crypto = CryptoManager::new(Zeroizing::new([31; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        seed_administrator(&pool).await;
        let session = recent_administrator();
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

        let backup = create_backup(&pool, &operations, &sessions, &session)
            .await
            .unwrap();
        assert!(
            backup
                .sha256
                .as_ref()
                .is_some_and(|value| value.len() == 64)
        );
        let listed = list_backups(&operations, &session).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].identifier, backup.identifier);
        let mut stale_session = session.clone();
        stale_session.privileged_authenticated_at = None;
        stale_session.privileged_auth_level = None;
        assert!(
            create_backup(&pool, &operations, &sessions, &stale_session)
                .await
                .is_err()
        );
        assert_eq!(list_backups(&operations, &session).await.unwrap().len(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let symlink_identifier = "configdeck-20260817T120000Z-a1b2c3d4.db";
            symlink(
                backup_dir.join(&backup.identifier),
                backup_dir.join(symlink_identifier),
            )
            .unwrap();
            assert!(
                create_restore_intent(
                    &pool,
                    &operations,
                    &sessions,
                    &session,
                    symlink_identifier,
                    "Symlink must be rejected",
                )
                .await
                .is_err()
            );
        }

        create_restore_intent(
            &pool,
            &operations,
            &sessions,
            &session,
            &backup.identifier,
            "Disposable restore drill",
        )
        .await
        .unwrap();
        let marker_before = fs::read(&operations.restore_intent_path).unwrap();
        assert!(
            create_restore_intent(
                &pool,
                &operations,
                &sessions,
                &session,
                &backup.identifier,
                "Must not replace the active marker",
            )
            .await
            .is_err()
        );
        assert_eq!(
            marker_before,
            fs::read(&operations.restore_intent_path).unwrap()
        );

        let snapshot_path = backup_dir.join(&backup.identifier);
        let original_snapshot = fs::read(&snapshot_path).unwrap();
        let mut changed_snapshot = original_snapshot.clone();
        changed_snapshot.push(0);
        fs::write(&snapshot_path, changed_snapshot).unwrap();
        assert!(reconcile_restore_intent(&pool, &operations).await.is_err());
        assert!(operations.restore_intent_path.exists());
        fs::write(&snapshot_path, original_snapshot).unwrap();

        pool.close().await;
        assert!(
            preflight_restore_intent(&operations, &database.url)
                .await
                .is_err()
        );
        assert!(operations.restore_intent_path.exists());
        let safety_path = data_dir.join("configdeck-before-restore.db");
        fs::rename(&database_path, &safety_path).unwrap();
        fs::copy(backup_dir.join(&backup.identifier), &database_path).unwrap();
        preflight_restore_intent(&operations, &database.url)
            .await
            .unwrap();

        let restored_pool = connect_and_migrate(&database).await.unwrap();
        initialize_and_validate_key_registry(&restored_pool, &crypto)
            .await
            .unwrap();
        validate_active_environment_keys(&restored_pool, &crypto)
            .await
            .unwrap();
        reconcile_restore_intent(&restored_pool, &operations)
            .await
            .unwrap();
        assert!(!operations.restore_intent_path.exists());
        let restore_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = 'RESTORE_BACKUP'")
                .fetch_one(&restored_pool)
                .await
                .unwrap();
        assert_eq!(restore_events, 1);
        restored_pool.close().await;
    }

    #[tokio::test]
    async fn operator_cannot_list_or_create_backups() {
        let root = tempdir().unwrap();
        let operations = OperationsSettings {
            backup_dir: root.path().to_owned(),
            restore_intent_path: root.path().join("restore-intent.json"),
        };
        let mut session = recent_administrator();
        session.user.role = Role::Operator;
        assert!(list_backups(&operations, &session).await.is_err());
    }

    async fn seed_administrator(pool: &sqlx::SqlitePool) {
        let now = "2026-08-17T00:00:00Z";
        sqlx::query(
            "INSERT INTO organizations(id, name, onboarding_completed_at, created_at, updated_at) VALUES('org', 'ConfigDeck', ?, ?, ?)",
        )
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, active, password_changed_at, created_at, updated_at) VALUES(?, 'org', 'admin@example.test', 'admin@example.test', 'hash', 'ADMINISTRATOR', 1, ?, ?, ?)",
        )
        .bind("11111111-1111-4111-8111-111111111111")
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
    }

    fn recent_administrator() -> AuthenticatedSession {
        AuthenticatedSession {
            id: "session".into(),
            token_hash: vec![1; 32],
            csrf_token_hash: vec![2; 32],
            user: SessionUser {
                id: "11111111-1111-4111-8111-111111111111".into(),
                organization_id: "org".into(),
                email: "admin@example.test".into(),
                role: Role::Administrator,
                auth_version: 1,
                totp_enabled: true,
                must_change_password: false,
            },
            authentication_state: AuthenticationState::Full,
            privileged_authenticated_at: Some(OffsetDateTime::now_utc()),
            privileged_auth_level: Some(PrivilegedAuthLevel::Standard),
        }
    }
}
