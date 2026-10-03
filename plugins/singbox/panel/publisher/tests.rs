use super::*;
use crate::config::Config;
use anyhow::Result;
use sqlx::PgPool;

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn capability_and_its_preserved_old_flag_cannot_create_a_deployment(
    pool: PgPool,
) -> Result<()> {
    let state = AppState::new(
        pool.clone(),
        Config {
            database_url: String::new(),
            listen: "127.0.0.1:0".parse()?,
            public_url: "http://127.0.0.1".into(),
            data_dir: std::env::temp_dir(),
            admin_password: Some("TEST_ONLY-plugin-publication-password".into()),
        },
    )
    .await?;
    let server: i64 = sqlx::query_scalar(
        "INSERT INTO servers(name,capabilities,dirty_at) VALUES('Candidate','[\"singbox\"]',0) RETURNING id",
    )
    .fetch_one(&pool)
    .await?;
    sqlx::query("INSERT INTO server_plugins(server_id,plugin,source,enabled_at) VALUES($1,'sing-box','agent_capability',0)")
        .bind(server).execute(&pool).await?;
    publish_server(&state, server).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployments WHERE server_id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        0
    );
    // Capability changes must not turn the preserved old marker into a choice.
    sqlx::query("UPDATE servers SET capabilities='[]' WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    publish_server(&state, server).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployments WHERE server_id=$1")
        .bind(server)
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);
    let pending: (i64, Option<i64>) =
        sqlx::query_as("SELECT manifest_rev,dirty_at FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?;
    assert_eq!(pending, (0, Some(0)));

    // An explicit administrator choice remains eligible without device support.
    sqlx::query("UPDATE server_plugins SET source='administrator' WHERE server_id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    publish_server(&state, server).await?;
    let completed: (i64, Option<i64>) =
        sqlx::query_as("SELECT manifest_rev,dirty_at FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?;
    assert_eq!(completed, (1, None));
    Ok(())
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn stale_candidate_cannot_publish_after_enablement_is_withdrawn(
    pool: PgPool,
) -> anyhow::Result<()> {
    let state = AppState::new(
        pool.clone(),
        Config {
            database_url: String::new(),
            listen: "127.0.0.1:0".parse()?,
            public_url: "http://127.0.0.1".into(),
            data_dir: std::env::temp_dir().join(format!("sinan-publish-{}", uuid::Uuid::new_v4())),
            admin_password: Some("test-only-plugin-publisher".into()),
        },
    )
    .await?;
    let server: i64 = sqlx::query_scalar("INSERT INTO servers(name,capabilities,dirty_at) VALUES('Candidate','[\"singbox\"]',0) RETURNING id").fetch_one(&pool).await?;
    sqlx::query("INSERT INTO server_plugins(server_id,plugin,source,enabled_at) VALUES($1,'sing-box','administrator',0)")
        .bind(server).execute(&pool).await?;
    let candidate: Option<i64> = sqlx::query_scalar(&format!("SELECT s.id FROM servers s LEFT JOIN server_plugins p ON p.server_id=s.id AND p.plugin='sing-box' WHERE s.id=$1 AND {DUE} AND ({}) IS NOT NULL",super::super::settings::SOURCE_SQL))
        .bind(server).fetch_optional(&pool).await?;
    assert_eq!(candidate, Some(server));
    // The explicit choice changes after candidate selection. Publication
    // must validate the locked server again instead of creating legacy proof.
    sqlx::query("UPDATE server_plugins SET enabled=FALSE WHERE server_id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    publish_server(&state, server).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployments WHERE server_id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        0
    );
    let pending: (i64, Option<i64>) =
        sqlx::query_as("SELECT manifest_rev,dirty_at FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?;
    assert_eq!(pending, (0, Some(0)));
    sqlx::query("UPDATE server_plugins SET enabled=TRUE WHERE server_id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    publish_server(&state, server).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployments WHERE server_id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<i64>>("SELECT dirty_at FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        None
    );
    Ok(())
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn shared_controller_rotation_is_transactional_and_never_rewrites_old_deployment_bytes(
    pool: PgPool,
) -> Result<()> {
    let server: i64 = sqlx::query_scalar(
        "INSERT INTO servers(name) VALUES('TEST_ONLY shared controller') RETURNING id",
    )
    .fetch_one(&pool)
    .await?;
    let old = crate::auth::random_token();
    sqlx::query("INSERT INTO singbox_path_controls(server_id,secret,test_url) VALUES($1,$2,'https://panel.example.com/health')").bind(server).bind(&old).execute(&pool).await?;
    let old_bundle = serde_json::json!({"files":{"config.json":format!("TEST_ONLY immutable old secret {old}")}}).to_string();
    let old_hash = crate::auth::hash_token(&old_bundle);
    sqlx::query("INSERT INTO deployments(server_id,module,rev,bundle,bundle_sha256,source_json,created_at) VALUES($1,'singbox',1,$2,$3,'[]',1)").bind(server).bind(&old_bundle).bind(&old_hash).execute(&pool).await?;
    let new = "a".repeat(64);
    let mut tx = pool.begin().await?;
    synchronize_path_secret_on(&mut tx, server, &new).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT secret FROM singbox_path_controls WHERE server_id=$1"
        )
        .bind(server)
        .fetch_one(&mut *tx)
        .await?,
        new
    );
    tx.rollback().await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT secret FROM singbox_path_controls WHERE server_id=$1"
        )
        .bind(server)
        .fetch_one(&pool)
        .await?,
        old
    );
    let mut tx = pool.begin().await?;
    synchronize_path_secret_on(&mut tx, server, &new).await?;
    tx.commit().await?;
    let preserved: (String,String) = sqlx::query_as("SELECT bundle,bundle_sha256 FROM deployments WHERE server_id=$1 AND module='singbox' AND rev=1").bind(server).fetch_one(&pool).await?;
    assert_eq!(preserved, (old_bundle, old_hash));
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT secret FROM singbox_path_controls WHERE server_id=$1"
        )
        .bind(server)
        .fetch_one(&pool)
        .await?,
        new
    );
    Ok(())
}
