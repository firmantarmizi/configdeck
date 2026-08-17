use serde::Deserialize;
use sqlx::{FromRow, QueryBuilder, Sqlite, SqlitePool};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{auth::AuthenticatedSession, error::AppError, users::Capability};

const PAGE_LIMIT: i64 = 200;
const METADATA_ALLOWLIST: &[&str] = &[
    "active",
    "backup_identifier",
    "backup_sha256",
    "backup_size_bytes",
    "bootstrap",
    "forced",
    "granted",
    "item_count",
    "item_id",
    "logo_uploaded",
    "new_role",
    "old_role",
    "reason_length",
    "record_count",
    "requested_at",
    "requested_by_user_id",
    "role",
    "selection_size",
    "status",
    "rotation_type",
    "source_dek_version",
    "source_kek_version",
    "target_user_id",
    "target_dek_version",
    "target_kek_version",
    "variable_count",
    "version",
    "visibility",
];

#[derive(Clone, Debug, Default, Deserialize)]
pub struct AuditFilter {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub actor: String,
}

#[derive(Debug)]
pub struct AuditEntry {
    pub id: i64,
    pub occurred_display: String,
    pub actor_email: Option<String>,
    pub action: String,
    pub outcome: String,
    pub service_name: Option<String>,
    pub environment_name: Option<String>,
    pub variable_key: Option<String>,
    pub change_request_id: Option<String>,
    pub client_ip: Option<String>,
    pub metadata: Vec<AuditMetadata>,
}

#[derive(Debug)]
pub struct AuditMetadata {
    pub key: String,
    pub value: String,
}

#[derive(FromRow)]
struct AuditRow {
    id: i64,
    occurred_at: String,
    actor_email: Option<String>,
    action: String,
    outcome: String,
    service_name: Option<String>,
    environment_name: Option<String>,
    variable_key: Option<String>,
    change_request_id: Option<String>,
    client_ip: Option<String>,
    metadata_json: String,
}

pub async fn list(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    filter: &AuditFilter,
) -> Result<(Vec<AuditEntry>, Vec<String>), AppError> {
    session.require_full()?;
    if !session.user.role.allows(Capability::ViewAudit) {
        return Err(AppError::Forbidden);
    }
    validate_filter(filter)?;
    let mut query = QueryBuilder::<Sqlite>::new(
        "SELECT a.id, a.occurred_at, actor.email AS actor_email, a.action, a.outcome, \
                service.name AS service_name, environment.name AS environment_name, \
                a.variable_key, a.change_request_id, a.client_ip, a.metadata_json \
         FROM audit_logs a \
         LEFT JOIN users actor ON actor.id = a.actor_user_id \
         LEFT JOIN services service ON service.id = a.service_id \
         LEFT JOIN environments environment ON environment.id = a.environment_id WHERE 1 = 1",
    );
    if !filter.action.is_empty() {
        query.push(" AND a.action = ").push_bind(&filter.action);
    }
    if !filter.outcome.is_empty() {
        query.push(" AND a.outcome = ").push_bind(&filter.outcome);
    }
    if !filter.actor.is_empty() {
        query
            .push(" AND actor.email_normalized LIKE ")
            .push_bind(format!("%{}%", filter.actor.trim().to_lowercase()));
    }
    query
        .push(" ORDER BY a.id DESC LIMIT ")
        .push_bind(PAGE_LIMIT);
    let rows: Vec<AuditRow> = query.build_query_as().fetch_all(pool).await?;
    let actions =
        sqlx::query_scalar::<_, String>("SELECT DISTINCT action FROM audit_logs ORDER BY action")
            .fetch_all(pool)
            .await?;
    Ok((rows.into_iter().map(entry_from_row).collect(), actions))
}

fn validate_filter(filter: &AuditFilter) -> Result<(), AppError> {
    if filter.action.len() > 100
        || filter.actor.len() > 320
        || !matches!(
            filter.outcome.as_str(),
            "" | "SUCCESS" | "DENIED" | "FAILED"
        )
    {
        return Err(AppError::InvalidRequest);
    }
    Ok(())
}

fn entry_from_row(row: AuditRow) -> AuditEntry {
    AuditEntry {
        id: row.id,
        occurred_display: display_time(&row.occurred_at),
        actor_email: row.actor_email,
        action: row.action,
        outcome: row.outcome,
        service_name: row.service_name,
        environment_name: row.environment_name,
        variable_key: row.variable_key,
        change_request_id: row.change_request_id,
        client_ip: row.client_ip,
        metadata: safe_metadata(&row.metadata_json),
    }
}

fn safe_metadata(raw: &str) -> Vec<AuditMetadata> {
    let Ok(serde_json::Value::Object(object)) = serde_json::from_str(raw) else {
        return Vec::new();
    };
    let mut entries = object
        .into_iter()
        .filter(|(key, value)| {
            METADATA_ALLOWLIST.contains(&key.as_str())
                && matches!(
                    value,
                    serde_json::Value::String(_)
                        | serde_json::Value::Number(_)
                        | serde_json::Value::Bool(_)
                )
        })
        .map(|(key, value)| AuditMetadata {
            key: key.replace('_', " "),
            value: match value {
                serde_json::Value::String(value) => value,
                other => other.to_string(),
            },
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    entries
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
    use crate::{
        auth::{AuthenticatedSession, AuthenticationState, SessionUser},
        db::test_pool,
        users::Role,
    };

    use super::{AuditFilter, list, safe_metadata};

    #[test]
    fn metadata_renderer_ignores_unknown_and_structured_values() {
        let metadata = safe_metadata(
            r#"{"role":"OPERATOR","password":"never","nested":{"secret":"never"},"active":true}"#,
        );
        assert_eq!(metadata.len(), 2);
        assert!(
            metadata
                .iter()
                .any(|entry| entry.key == "role" && entry.value == "OPERATOR")
        );
        assert!(
            metadata
                .iter()
                .any(|entry| entry.key == "active" && entry.value == "true")
        );
    }

    #[tokio::test]
    async fn contributor_cannot_open_audit_log() {
        let pool = test_pool().await;
        let session = AuthenticatedSession {
            id: "session".into(),
            token_hash: vec![1; 32],
            csrf_token_hash: vec![2; 32],
            user: SessionUser {
                id: "contributor".into(),
                organization_id: "org".into(),
                email: "contributor@example.test".into(),
                role: Role::Contributor,
                auth_version: 1,
                totp_enabled: false,
                must_change_password: false,
            },
            authentication_state: AuthenticationState::Full,
            privileged_authenticated_at: None,
            privileged_auth_level: None,
        };
        assert!(
            list(&pool, &session, &AuditFilter::default())
                .await
                .is_err()
        );
    }
}
