use super::{EnvironmentContext, ensure_mutable, environment_context, require_direct_apply};
use crate::{auth::AuthenticatedSession, error::AppError};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqliteConnection, SqlitePool};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Reference {
    id: String,
    environment_id: String,
    name: String,
    key: String,
    visibility: String,
    active: bool,
    pending: bool,
    revision: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReview {
    pub key: String,
    pub status: String,
    pub label: String,
    pub visibility: String,
    pub sources: String,
    pub locked: bool,
    pub conflict: bool,
    references: Vec<Reference>,
}

pub async fn preview(
    pool: &SqlitePool,
    session: &AuthenticatedSession,
    environment_id: &str,
    keys: &[String],
) -> Result<(EnvironmentContext, Vec<ImportReview>), AppError> {
    require_direct_apply(session)?;
    let environment = environment_context(pool, session, environment_id).await?;
    ensure_mutable(&environment)?;
    let references = load(&mut *pool.acquire().await?, &environment.service_id).await?;
    Ok((environment, review(&references, environment_id, keys)))
}

pub(super) async fn load(
    connection: &mut SqliteConnection,
    service_id: &str,
) -> Result<Vec<Reference>, AppError> {
    Ok(sqlx::query_as::<_, Reference>(
        "SELECT v.id, e.id AS environment_id, e.name, v.key, v.visibility,
                (e.archived_at IS NULL AND v.lifecycle_status = 'ACTIVE') AS active,
                0 AS pending, v.version AS revision
         FROM variables v JOIN environments e ON e.id = v.environment_id WHERE e.service_id = ?
         UNION ALL
         SELECT i.id, e.id AS environment_id, e.name, i.key,
                COALESCE(i.proposed_visibility, v.visibility, 'restricted') AS visibility,
                e.archived_at IS NULL AS active, 1 AS pending, i.item_revision AS revision
         FROM change_request_items i JOIN change_requests r ON r.id = i.change_request_id
         JOIN environments e ON e.id = r.environment_id
         LEFT JOIN variables v ON v.environment_id = e.id AND v.key = i.key
         WHERE e.service_id = ? AND r.status IN ('REQUESTED','NEEDS_INPUT','READY_TO_APPLY')
         ORDER BY 4, 2, 7, 1",
    )
    .bind(service_id)
    .bind(service_id)
    .fetch_all(connection)
    .await?)
}

pub(crate) fn review(
    references: &[Reference],
    environment_id: &str,
    keys: &[String],
) -> Vec<ImportReview> {
    keys.iter()
        .map(|key| {
            let matches: Vec<_> = references
                .iter()
                .filter(|row| &row.key == key)
                .cloned()
                .collect();
            let current: Vec<_> = matches
                .iter()
                .filter(|row| row.active && !row.pending)
                .collect();
            let visibility = current
                .first()
                .map_or("restricted", |row| row.visibility.as_str());
            let conflict = current.iter().any(|row| row.visibility != visibility)
                || matches.iter().any(|row| {
                    row.active
                        && row.pending
                        && (row.environment_id == environment_id || row.visibility != visibility)
                });
            let (status, label) = if conflict {
                ("conflict", "Visibility / pending conflict")
            } else if current
                .iter()
                .any(|row| row.environment_id == environment_id)
            {
                ("existing", "Existing key")
            } else if !current.is_empty() {
                ("inherited", "New in this environment")
            } else if matches.is_empty() {
                ("new", "New key")
            } else {
                ("historical", "Previously used / proposed")
            };
            let sources = if matches.is_empty() {
                "Safe default".to_owned()
            } else {
                matches
                    .iter()
                    .map(|row| {
                        format!(
                            "{}: {}{}",
                            row.name,
                            row.visibility,
                            if row.pending {
                                " (pending)"
                            } else if !row.active {
                                " (historical)"
                            } else {
                                ""
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            ImportReview {
                key: key.clone(),
                status: status.into(),
                label: label.into(),
                visibility: if conflict { "restricted" } else { visibility }.into(),
                sources,
                locked: !current.is_empty()
                    || conflict
                    || matches.iter().any(|row| row.active && row.pending),
                conflict,
                references: matches,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference(pending: bool, visibility: &str, environment_id: &str) -> Reference {
        Reference {
            id: "synthetic".into(),
            environment_id: environment_id.into(),
            name: "Staging".into(),
            key: "KEY".into(),
            visibility: visibility.into(),
            active: true,
            pending,
            revision: 1,
        }
    }
    #[test]
    fn pending_changes_never_supply_public_defaults_or_override_restrictions() {
        let keys = ["KEY".into()];
        assert!(review(&[reference(true, "public", "source")], "target", &keys)[0].conflict);
        assert!(
            review(
                &[
                    reference(false, "public", "source"),
                    reference(true, "restricted", "third")
                ],
                "target",
                &keys
            )[0]
            .conflict
        );
        assert!(review(&[reference(true, "restricted", "target")], "target", &keys)[0].conflict);
        let pending_restricted =
            review(&[reference(true, "restricted", "source")], "target", &keys);
        assert!(pending_restricted[0].locked);
        assert_eq!(pending_restricted[0].visibility, "restricted");
        let known = review(
            &[
                reference(false, "public", "source"),
                reference(true, "public", "third"),
            ],
            "target",
            &keys,
        );
        assert!(!known[0].conflict);
        assert_eq!(known[0].visibility, "public");
    }
}
