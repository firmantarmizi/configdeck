use serde::Serialize;
use sqlx::{FromRow, SqlitePool};

use crate::{
    auth::AuthenticatedSession, error::AppError, requests::ChangeRequestSummary, services,
    users::Role,
};

#[derive(Clone, Debug, Serialize)]
pub struct DashboardOverview {
    pub service_count: usize,
    pub environment_count: i64,
    pub variable_count: i64,
    pub open_request_count: i64,
    pub needs_input_count: i64,
    pub attention: Vec<ChangeRequestSummary>,
}

#[derive(FromRow)]
struct RequestCounts {
    open_request_count: i64,
    needs_input_count: i64,
}

pub async fn overview(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
) -> Result<DashboardOverview, AppError> {
    session.require_full()?;
    let services = services::list_accessible(pool, session).await?;
    let environment_count = services
        .iter()
        .map(|service| service.environment_count)
        .sum();
    let request_counts = sqlx::query_as::<_, RequestCounts>(
        "SELECT COUNT(*) AS open_request_count, \
                COALESCE(SUM(r.status = 'NEEDS_INPUT'), 0) AS needs_input_count \
         FROM change_requests r JOIN services s ON s.id = r.service_id \
         WHERE s.organization_id = ? AND (? <> 'CONTRIBUTOR' OR r.requested_by = ?) \
           AND r.status NOT IN ('APPLIED', 'REJECTED')",
    )
    .bind(&session.user.organization_id)
    .bind(session.user.role.as_str())
    .bind(&session.user.id)
    .fetch_one(pool)
    .await?;
    let attention = sqlx::query_as::<_, ChangeRequestSummary>(
        "SELECT r.id, r.environment_id, s.name AS service_name, e.name AS environment_name, \
                r.title, r.reason, r.status, r.requested_at, COUNT(i.id) AS item_count \
         FROM change_requests r \
         JOIN services s ON s.id = r.service_id \
         JOIN environments e ON e.id = r.environment_id \
         JOIN change_request_items i ON i.change_request_id = r.id \
         WHERE s.organization_id = ? AND (? <> 'CONTRIBUTOR' OR r.requested_by = ?) \
           AND r.status NOT IN ('APPLIED', 'REJECTED') \
         GROUP BY r.id ORDER BY r.requested_at DESC, r.id DESC LIMIT 5",
    )
    .bind(&session.user.organization_id)
    .bind(session.user.role.as_str())
    .bind(&session.user.id)
    .fetch_all(pool)
    .await?;
    let variable_count: i64 = if session.user.role == Role::Contributor {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM variables v JOIN environments e ON e.id = v.environment_id \
             JOIN services s ON s.id = e.service_id JOIN user_service_access a ON a.service_id = s.id \
             WHERE a.user_id = ? AND s.organization_id = ? AND v.lifecycle_status = 'ACTIVE' \
             AND e.archived_at IS NULL AND s.archived_at IS NULL",
        )
        .bind(&session.user.id)
        .bind(&session.user.organization_id)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM variables v JOIN environments e ON e.id = v.environment_id \
             JOIN services s ON s.id = e.service_id WHERE s.organization_id = ? \
             AND v.lifecycle_status = 'ACTIVE' AND e.archived_at IS NULL AND s.archived_at IS NULL",
        )
        .bind(&session.user.organization_id)
        .fetch_one(pool)
        .await?
    };
    Ok(DashboardOverview {
        service_count: services.len(),
        environment_count,
        variable_count,
        open_request_count: request_counts.open_request_count,
        needs_input_count: request_counts.needs_input_count,
        attention,
    })
}

#[cfg(test)]
mod tests {
    use sqlx::SqlitePool;
    use zeroize::Zeroizing;

    use crate::{
        auth::{AuthenticatedSession, AuthenticationState, SessionUser},
        crypto::CryptoManager,
        db::{initialize_and_validate_key_registry, test_pool},
        environments::{self, EnvironmentInput},
        services::{self, ServiceInput},
        users::Role,
        variables::{self, AppliedVariableInput},
    };

    use super::overview;

    #[tokio::test]
    async fn contributor_dashboard_counts_only_assigned_services() {
        let pool = test_pool().await;
        seed_identity(&pool).await;
        let crypto = CryptoManager::new(Zeroizing::new([91; 32]));
        initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let admin = session("admin", Role::Administrator);
        let contributor = session("contributor", Role::Contributor);
        for (index, name) in ["Visible", "Hidden"].into_iter().enumerate() {
            let service_id = services::create(
                &pool,
                &admin,
                ServiceInput {
                    name: name.into(),
                    description: None,
                },
            )
            .await
            .unwrap();
            let environment_id = environments::create(
                &pool,
                &crypto,
                &admin,
                &service_id,
                EnvironmentInput {
                    name: "production".into(),
                    description: None,
                },
            )
            .await
            .unwrap();
            variables::record_applied(
                &pool,
                &crypto,
                &admin,
                &environment_id,
                AppliedVariableInput {
                    key: format!("VALUE_{index}"),
                    value: "encrypted-at-rest".into(),
                    visibility: "restricted".into(),
                    value_type: "string".into(),
                    description: None,
                    group_name: None,
                    display_order: i64::try_from(index).unwrap(),
                    reason: "Test dashboard scope".into(),
                },
            )
            .await
            .unwrap();
            if index == 0 {
                sqlx::query("INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) VALUES('contributor', ?, '2026-08-14T00:00:00Z', 'admin')")
                    .bind(service_id)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        }

        let result = overview(&pool, &contributor).await.unwrap();
        assert_eq!(result.service_count, 1);
        assert_eq!(result.environment_count, 1);
        assert_eq!(result.variable_count, 1);
    }

    async fn seed_identity(pool: &SqlitePool) {
        let now = "2026-08-14T00:00:00Z";
        sqlx::query("INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org', 'ConfigDeck', ?, ?)")
            .bind(now)
            .bind(now)
            .execute(pool)
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
                .execute(pool)
                .await
                .unwrap();
        }
    }

    fn session(id: &str, role: Role) -> AuthenticatedSession {
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
