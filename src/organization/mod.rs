use serde::Serialize;
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use crate::{
    auth::AuthenticatedSession,
    db::now_rfc3339,
    error::AppError,
    users::{Capability, Role},
};

pub const MAX_LOGO_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct OrganizationBranding {
    pub name: String,
    pub logo_present: bool,
}

#[derive(Clone, Debug)]
pub struct OrganizationLogo {
    pub mime_type: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct UploadedLogo {
    pub mime_type: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct OrganizationSetupInput {
    pub name: String,
    pub logo: Option<UploadedLogo>,
}

pub async fn is_onboarding_complete(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
) -> Result<bool, AppError> {
    let complete = sqlx::query_scalar::<_, bool>(
        "SELECT onboarding_completed_at IS NOT NULL FROM organizations WHERE id = ?",
    )
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(complete)
}

pub async fn branding(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
) -> Result<OrganizationBranding, AppError> {
    sqlx::query_as(
        "SELECT name, logo_data IS NOT NULL AS logo_present FROM organizations WHERE id = ?",
    )
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)
}

pub async fn logo(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
) -> Result<OrganizationLogo, AppError> {
    sqlx::query_as::<_, (String, Vec<u8>)>(
        "SELECT logo_mime_type, logo_data FROM organizations WHERE id = ? AND logo_data IS NOT NULL",
    )
    .bind(&session.user.organization_id)
    .fetch_optional(pool)
    .await?
    .map(|(mime_type, data)| OrganizationLogo { mime_type, data })
    .ok_or(AppError::NotFound)
}

pub async fn complete_setup(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    input: OrganizationSetupInput,
) -> Result<(), AppError> {
    session.require_full()?;
    if session.user.role != Role::Administrator
        || !session.user.role.allows(Capability::ManageSystem)
    {
        return Err(AppError::Forbidden);
    }
    let name = input.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::InvalidRequest);
    }
    if let Some(upload) = &input.logo {
        validate_logo(upload)?;
    }

    let now = now_rfc3339()?;
    let logo_uploaded = input.logo.is_some();
    let (mime_type, data) = input.logo.map_or((None, None), |upload| {
        (Some(upload.mime_type), Some(upload.data))
    });
    let logo_updated_at = data.as_ref().map(|_| now.clone());
    let mut transaction = pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE organizations SET name = ?, logo_mime_type = ?, logo_data = ?, logo_updated_at = ?, onboarding_completed_at = ?, updated_at = ? WHERE id = ? AND onboarding_completed_at IS NULL",
    )
    .bind(name)
    .bind(mime_type)
    .bind(data)
    .bind(logo_updated_at)
    .bind(&now)
    .bind(&now)
    .bind(&session.user.organization_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(AppError::Conflict);
    }
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action, metadata_json, request_id) VALUES(?, ?, 'COMPLETE_ORGANIZATION_SETUP', ?, ?)",
    )
    .bind(&now)
    .bind(&session.user.id)
    .bind(serde_json::json!({"logo_uploaded": logo_uploaded}).to_string())
    .bind(Uuid::new_v4().to_string())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

fn validate_logo(upload: &UploadedLogo) -> Result<(), AppError> {
    if upload.data.is_empty() || upload.data.len() > MAX_LOGO_BYTES {
        return Err(AppError::InvalidRequest);
    }
    let valid = match upload.mime_type.as_str() {
        "image/png" => upload
            .data
            .starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
        "image/webp" => {
            upload.data.len() >= 12
                && &upload.data[..4] == b"RIFF"
                && &upload.data[8..12] == b"WEBP"
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(AppError::InvalidRequest)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        auth::{AuthenticatedSession, AuthenticationState, SessionUser},
        db::test_pool,
        users::Role,
    };

    use super::{OrganizationSetupInput, UploadedLogo, complete_setup, is_onboarding_complete};

    #[tokio::test]
    async fn administrator_completes_setup_once_without_auditing_logo_bytes() {
        let pool = test_pool().await;
        seed_organization(&pool).await;
        let session = session(Role::Administrator);
        let png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 1];
        complete_setup(
            &pool,
            &session,
            OrganizationSetupInput {
                name: "Acme Platform".into(),
                logo: Some(UploadedLogo {
                    mime_type: "image/png".into(),
                    data: png,
                }),
            },
        )
        .await
        .unwrap();
        assert!(is_onboarding_complete(&pool, &session).await.unwrap());
        let metadata: String = sqlx::query_scalar(
            "SELECT metadata_json FROM audit_logs WHERE action = 'COMPLETE_ORGANIZATION_SETUP'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(metadata, r#"{"logo_uploaded":true}"#);
        assert!(
            complete_setup(
                &pool,
                &session,
                OrganizationSetupInput {
                    name: "Again".into(),
                    logo: None
                },
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn contributor_and_disguised_image_are_rejected() {
        let pool = test_pool().await;
        seed_organization(&pool).await;
        assert!(
            complete_setup(
                &pool,
                &session(Role::Contributor),
                OrganizationSetupInput {
                    name: "Acme".into(),
                    logo: None
                },
            )
            .await
            .is_err()
        );
        assert!(
            complete_setup(
                &pool,
                &session(Role::Administrator),
                OrganizationSetupInput {
                    name: "Acme".into(),
                    logo: Some(UploadedLogo {
                        mime_type: "image/png".into(),
                        data: b"not a png".to_vec(),
                    }),
                },
            )
            .await
            .is_err()
        );
    }

    async fn seed_organization(pool: &sqlx::SqlitePool) {
        let now = "2026-08-14T00:00:00Z";
        sqlx::query("INSERT INTO organizations(id, name, created_at, updated_at) VALUES('org', 'ConfigDeck', ?, ?)")
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id, organization_id, email, email_normalized, password_hash, role, password_changed_at, created_at, updated_at) VALUES('user', 'org', 'admin@example.test', 'admin@example.test', 'hash', 'ADMINISTRATOR', ?, ?, ?)")
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
    }

    fn session(role: Role) -> AuthenticatedSession {
        AuthenticatedSession {
            id: "session".into(),
            token_hash: vec![1; 32],
            csrf_token_hash: vec![2; 32],
            user: SessionUser {
                id: "user".into(),
                organization_id: "org".into(),
                email: "admin@example.test".into(),
                role,
                auth_version: 1,
                totp_enabled: true,
                must_change_password: false,
            },
            authentication_state: AuthenticationState::Full,
            privileged_authenticated_at: None,
            privileged_auth_level: None,
        }
    }
}
