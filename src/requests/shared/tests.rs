use super::*;
use crate::requests::{
    SharedInlineEditInput, SharedInlineValueInput, approve, create_shared_inline_edit,
    preview_resulting, validate_shared_inline_edit,
};
use crate::{
    db::{initialize_and_validate_key_registry, test_pool},
    environments::EnvironmentInput,
    requests::tests::{recent, seed_identity, session},
    services::{self, ServiceInput},
    users::Role,
    variables::{self, AppliedVariableInput},
};

async fn fixture(
    visibility: &str,
    value: &str,
) -> (SqlitePool, CryptoManager, SharedInlineEditInput) {
    let pool = test_pool().await;
    seed_identity(&pool).await;
    let crypto = CryptoManager::new(Zeroizing::new([72; 32]));
    initialize_and_validate_key_registry(&pool, &crypto)
        .await
        .unwrap();
    let admin = recent(session("admin", Role::Administrator));
    let service_id = services::create(
        &pool,
        &admin,
        ServiceInput {
            name: "Selective requests".into(),
            description: None,
        },
    )
    .await
    .unwrap();
    for name in ["Staging", "Production", "Worker Prod", "Worker Stg"] {
        environments::create(
            &pool,
            &crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: name.into(),
                description: None,
            },
        )
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) VALUES('contributor', ?, '2026-10-05T00:00:00Z', 'admin')")
        .bind(&service_id).execute(&pool).await.unwrap();
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM environments WHERE service_id = ? ORDER BY id")
            .bind(&service_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    let mut values = Vec::new();
    for environment_id in ids {
        variables::import_applied(
            &pool,
            &crypto,
            &admin,
            &environment_id,
            vec![AppliedVariableInput {
                key: "QUEUE".into(),
                value: value.into(),
                visibility: visibility.into(),
                value_type: "string".into(),
                description: None,
                group_name: Some("Queue".into()),
                display_order: 7,
                reason: "Synthetic fixture".into(),
            }],
        )
        .await
        .unwrap();
        let (variable_id, base_version) =
            sqlx::query_as("SELECT id, version FROM variables WHERE environment_id = ?")
                .bind(&environment_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        values.push(SharedInlineValueInput {
            environment_id,
            variable_id,
            base_version,
            description: None,
            value: if visibility == "public" {
                value.into()
            } else {
                String::new()
            },
            value_source: if visibility == "public" {
                "REQUESTER_PROVIDED"
            } else {
                "KEEP_CURRENT"
            }
            .into(),
        });
    }
    (
        pool,
        crypto,
        SharedInlineEditInput {
            service_id,
            current_key: "QUEUE".into(),
            new_key: "QUEUE".into(),
            visibility: visibility.into(),
            value_type: "string".into(),
            reason: "Synthetic edit".into(),
            values,
        },
    )
}

async fn counts(pool: &SqlitePool) -> (i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT COUNT(*) FROM change_requests), (SELECT COUNT(*) FROM variable_versions), (SELECT COUNT(*) FROM audit_logs)")
        .fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn metadata_normalization_skips_matching_rows_and_rename_covers_all() {
    let (pool, crypto, mut input) = fixture("public", "inventory").await;
    let actor = session("contributor", Role::Contributor);
    sqlx::query("UPDATE variables SET value_type = 'multiline' WHERE id IN (?, ?)")
        .bind(&input.values[1].variable_id)
        .bind(&input.values[2].variable_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input.clone())
            .await
            .unwrap(),
        2
    );
    input.new_key = "RENAMED_QUEUE".into();
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input)
            .await
            .unwrap(),
        4
    );
    let renames: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM change_request_items WHERE action = 'DELETE' AND key = 'QUEUE'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(renames, 4);
}

#[tokio::test]
async fn mixed_visibility_never_compares_hidden_public_values() {
    let (pool, crypto, mut input) = fixture("public", "inventory").await;
    let actor = session("contributor", Role::Contributor);
    sqlx::query("UPDATE variables SET visibility = 'restricted' WHERE id = ?")
        .bind(&input.values[0].variable_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE variables SET encrypted_value = zeroblob(16)")
        .execute(&pool)
        .await
        .unwrap();
    // Normalizing mixed metadata may create a proposal, but never tests the masked value.
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input.clone())
            .await
            .unwrap(),
        4
    );
    for value in &mut input.values {
        value.value = "different-guess".into();
    }
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input)
            .await
            .unwrap(),
        4
    );
}

#[tokio::test]
async fn skips_noops_and_records_only_changed_environments() {
    let (pool, crypto, input) = fixture("public", "inventory").await;
    let actor = session("contributor", Role::Contributor);
    let before = counts(&pool).await;
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input.clone())
            .await
            .unwrap(),
        0
    );
    assert_eq!(counts(&pool).await, before);
    let mut changed = input.clone();
    changed.values[0].value = "inventory-redis".into();
    changed.values[3].value = "inventory-redis".into();
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, changed)
            .await
            .unwrap(),
        2
    );
    assert_eq!(counts(&pool).await, (before.0 + 2, before.1, before.2 + 2));
    let targets: Vec<String> = sqlx::query_scalar("SELECT environment_id FROM change_requests WHERE requested_by = 'contributor' ORDER BY environment_id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(
        targets,
        vec![
            input.values[0].environment_id.clone(),
            input.values[3].environment_id.clone()
        ]
    );
    let statuses: Vec<(i64, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT version, deployment_status, group_name, display_order FROM variables",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        statuses
            .iter()
            .all(|row| row == &(1, "APPLIED".into(), Some("Queue".into()), 7))
    );
}

#[tokio::test]
async fn shared_metadata_targets_only_differences_and_preserves_line_endings() {
    let (pool, crypto, mut input) = fixture("public", "line1\r\nline2\rline3").await;
    let actor = session("contributor", Role::Contributor);
    for value in &mut input.values {
        value.value = "line1\nline2\nline3".into();
    }
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input.clone())
            .await
            .unwrap(),
        0
    );
    let unchanged = input.clone();
    input.visibility = "restricted".into();
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input)
            .await
            .unwrap(),
        4
    );
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM change_requests WHERE requested_by = 'contributor'")
            .fetch_all(&pool)
            .await
            .unwrap();
    let admin = recent(session("admin", Role::Administrator));
    let manager = crate::requests::tests::session_manager(&pool, &crypto);
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, unchanged)
            .await
            .unwrap(),
        0
    );
    for id in ids {
        approve(&pool, &actor, &id).await.unwrap_err();
        approve(&pool, &admin, &id).await.unwrap();
        let preview = preview_resulting(&pool, &crypto, &manager, &admin, vec![id])
            .await
            .unwrap();
        assert_eq!(
            preview.editable_items[0].value.as_str(),
            "line1\r\nline2\rline3"
        );
    }
}

#[tokio::test]
async fn masked_untouched_rows_skip_without_decrypt_or_equality_oracle() {
    let (pool, crypto, mut input) = fixture("restricted", "synthetic-secret").await;
    let actor = session("contributor", Role::Contributor);
    // Corrupt current ciphertext proves neither untouched nor explicitly replaced secrets decrypt.
    sqlx::query("UPDATE variables SET encrypted_value = zeroblob(16)")
        .execute(&pool)
        .await
        .unwrap();
    let before = counts(&pool).await;
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input.clone())
            .await
            .unwrap(),
        0
    );
    assert_eq!(counts(&pool).await, before);
    input.values[0].value_source = "REQUESTER_PROVIDED".into();
    input.values[0].value = "synthetic-secret".into();
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input.clone())
            .await
            .unwrap(),
        1
    );
    input.values[0].value = "different-guess".into();
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input.clone())
            .await
            .unwrap(),
        1
    );
    input.values[0].value_source = "KEEP_CURRENT".into();
    input.value_type = "url".into();
    assert_eq!(
        create_shared_inline_edit(&pool, &crypto, &actor, input)
            .await
            .unwrap(),
        4
    );
    let needs_input: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM change_requests WHERE requested_by = 'contributor' AND status = 'NEEDS_INPUT'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(needs_input, 4);
}

#[tokio::test]
async fn rejects_invalid_scope_stale_forms_and_changed_snapshots_atomically() {
    let (pool, crypto, input) = fixture("public", "inventory").await;
    let actor = session("contributor", Role::Contributor);
    let before = counts(&pool).await;
    let mut invalids = Vec::new();
    let mut bad = input.clone();
    bad.values.pop();
    invalids.push(bad);
    let mut bad = input.clone();
    bad.values[0].base_version += 1;
    invalids.push(bad);
    let mut bad = input.clone();
    bad.values[0].variable_id = input.values[1].variable_id.clone();
    invalids.push(bad);
    let mut bad = input.clone();
    bad.values[0].value_source = "BOGUS".into();
    invalids.push(bad);
    let mut bad = input.clone();
    bad.values.push(input.values[0].clone());
    invalids.push(bad);
    let mut bad = input.clone();
    bad.value_type = "boolean".into();
    invalids.push(bad);
    for mut bad in invalids {
        bad.values.last_mut().unwrap().value = "changed".into();
        assert!(
            create_shared_inline_edit(&pool, &crypto, &actor, bad)
                .await
                .is_err()
        );
        assert_eq!(counts(&pool).await, before);
    }
    let validated = validate_shared_inline_edit(input.clone()).unwrap();
    let snapshot = Snapshot::load(&mut pool.acquire().await.unwrap(), &validated)
        .await
        .unwrap();
    sqlx::query("UPDATE variables SET display_order = display_order + 1 WHERE id = ?")
        .bind(&input.values[0].variable_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        persist_shared_requests(&pool, &actor, &[], &validated, &snapshot).await,
        Err(AppError::Conflict)
    ));
    assert_eq!(counts(&pool).await, before);
    sqlx::query("DELETE FROM user_service_access WHERE user_id = 'contributor'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        create_shared_inline_edit(&pool, &crypto, &actor, input).await,
        Err(AppError::Forbidden)
    ));
}
