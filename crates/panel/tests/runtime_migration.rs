#![forbid(unsafe_code)]

use anyhow::Result;
use serde_json::{Value, json};
use sqlx::{PgPool, migrate::Migrator};
use std::borrow::Cow;
use uuid::Uuid;

#[sqlx::test(migrations = false)]
async fn runtime_extensions_upgrade_the_existing_installation_schema_without_replacing_history(
    pool: PgPool,
) -> Result<()> {
    let migrations = sqlx::migrate!();
    let old = Migrator {
        migrations: Cow::Owned(
            migrations
                .iter()
                .filter(|m| m.version <= 23)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    old.run(&pool).await?;
    let server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY upgrade') RETURNING id")
            .fetch_one(&pool)
            .await?;
    sqlx::query("INSERT INTO singbox_installation(server_id,target_rev,error,checked_at) VALUES($1,7,'TEST_ONLY retained failure',123)")
        .bind(server).execute(&pool).await?;
    let pending = Uuid::new_v4();
    let completed = Uuid::new_v4();
    let result = json!({"id":completed,"status":"succeeded","finished_at":20,"stdout":"preserved","stderr":"","timed_out":false,"truncated":false});
    for (id, value) in [(pending, None), (completed, Some(result.clone()))] {
        sqlx::query("INSERT INTO remote_commands(id,server_id,requested_at,spec,result,result_digest) VALUES($1,$2,10,$3,$4,$5)")
            .bind(id).bind(server)
            .bind(json!({"id":id,"command":"TEST_ONLY inert history","timeout_secs":1,"expires_at":100}))
            .bind(value).bind(if id == completed { Some("original-digest") } else { None })
            .execute(&pool).await?;
    }
    let legacy_probe = Uuid::new_v4();
    let granted_probe = Uuid::new_v4();
    let legacy_spec = json!({"id":legacy_probe,"name":"TEST_ONLY legacy","kind":"tcp",
        "target":"127.0.0.1","port":443,"interval_secs":30,"carrier":"","enabled":true});
    let granted_spec = json!({"id":granted_probe,"name":"TEST_ONLY retained grant","kind":"tcp",
        "target":"127.0.0.1","port":443,"interval_secs":30,"carrier":"","enabled":true,
        "monitor":{"region":"TEST_ONLY owned loopback","address_family":"ipv4","authorization":{
            "kind":"owned","source":"TEST_ONLY owner record","scope":"TEST_ONLY exact loopback endpoint",
            "enabled":true,"expires_at":null,"identity":{"kind":"tcp","target":"127.0.0.1",
                "port":443,"address_family":"ipv4"}}}});
    for (id, spec) in [(legacy_probe, &legacy_spec), (granted_probe, &granted_spec)] {
        sqlx::query(
            "INSERT INTO latency_tasks(id,spec,default_enabled,revision) VALUES($1,$2,TRUE,7)",
        )
        .bind(id)
        .bind(spec)
        .execute(&pool)
        .await?;
        sqlx::query("INSERT INTO network_probes(id,server_id,spec,task_id) VALUES($1,$2,$3,$1)")
            .bind(id)
            .bind(server)
            .bind(spec)
            .execute(&pool)
            .await?;
    }
    let sample = Uuid::new_v4();
    let sample_result = json!({"id":sample,"probe_id":legacy_probe,"sampled_at":1000,
        "latency_ms":3.0,"loss_percent":0.0,"error":null});
    sqlx::query("INSERT INTO probe_results(id,server_id,probe_id,sampled_at,result,digest) VALUES($1,$2,$3,1000,$4,'TEST_ONLY original probe digest')")
        .bind(sample).bind(server).bind(legacy_probe).bind(&sample_result).execute(&pool).await?;
    migrations.run(&pool).await?;
    migrations.run(&pool).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM remote_commands WHERE id=$1")
            .bind(pending)
            .fetch_one(&pool)
            .await?,
        "claimed"
    );
    let preserved: (String, Value, String) =
        sqlx::query_as("SELECT state,result,result_digest FROM remote_commands WHERE id=$1")
            .bind(completed)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        preserved,
        ("succeeded".into(), result, "original-digest".into())
    );
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await?;
    assert_eq!(
        versions,
        migrations
            .iter()
            .map(|migration| migration.version)
            .collect::<Vec<_>>()
    );
    let mut paused_spec = legacy_spec;
    paused_spec["enabled"] = json!(false);
    for (id, spec, enabled, revision) in [
        (legacy_probe, paused_spec, false, 8_i64),
        (granted_probe, granted_spec, true, 7_i64),
    ] {
        let task: (Value, bool, i64) =
            sqlx::query_as("SELECT spec,default_enabled,revision FROM latency_tasks WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(task, (spec.clone(), enabled, revision));
        assert_eq!(
            sqlx::query_scalar::<_, Value>("SELECT spec FROM network_probes WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await?,
            spec
        );
    }
    let sample_after: (Value, String) =
        sqlx::query_as("SELECT result,digest FROM probe_results WHERE id=$1")
            .bind(sample)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        sample_after,
        (sample_result, "TEST_ONLY original probe digest".into())
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT to_regclass('singbox_installation')::text")
            .fetch_one(&pool)
            .await?,
        "singbox_installation"
    );
    let installation: (i64, String, i64) = sqlx::query_as(
        "SELECT target_rev,error,checked_at FROM singbox_installation WHERE server_id=$1",
    )
    .bind(server)
    .fetch_one(&pool)
    .await?;
    assert_eq!(installation, (7, "TEST_ONLY retained failure".into(), 123));
    Ok(())
}
