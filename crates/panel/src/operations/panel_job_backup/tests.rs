use super::*;
use crate::config::Config;
use sqlx::PgPool;
use std::path::PathBuf;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn setup(pool: PgPool) -> anyhow::Result<(AppState, Directory, Uuid, Uuid)> {
    sqlx::query("INSERT INTO admins(id,password_hash) VALUES(1,'TEST_ONLY no login')")
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,created_at,updated_at) VALUES(1,'admin','TEST_ONLY owner','owner',true,0,0)").execute(&pool).await?;
    let directory =
        Directory(std::env::temp_dir().join(format!("sinan-job-backup-test-{}", Uuid::new_v4())));
    std::fs::create_dir(&directory.0)?;
    let state = AppState::new(
        pool.clone(),
        Config {
            database_url: String::new(),
            listen: "127.0.0.1:0".parse()?,
            public_url: "http://127.0.0.1".into(),
            data_dir: directory.0.clone(),
            admin_password: None,
        },
    )
    .await?;
    let mut targets = Vec::new();
    for name in ["TEST_ONLY backup target one", "TEST_ONLY backup target two"] {
        targets.push(
            sqlx::query_scalar::<_, i64>("INSERT INTO servers(name) VALUES($1) RETURNING id")
                .bind(name)
                .fetch_one(&pool)
                .await?,
        );
    }
    let schedule = Uuid::new_v4();
    let now = now_timestamp();
    sqlx::query("INSERT INTO operations_backup_schedules(id,name,requested_by,interval_secs,next_run_at,paused,recipient,retention_count,retention_days,created_at,updated_at) VALUES($1,'TEST_ONLY paused backup plan',1,86400,$2,true,$3,7,30,$2,$2)")
        .bind(schedule).bind(now+86400).bind(format!("age1{}","q".repeat(58))).execute(&pool).await?;
    let plan = Plan {
        name: "TEST_ONLY one recovery point".into(),
        steps: vec![super::super::model::Step {
            kind: "panel_backup".into(),
            service: None,
            timeout_secs: 600,
            runtime_version: None,
            backup_schedule_id: Some(schedule),
        }],
        batch_size: 2,
        concurrency: 1,
        pause_between_batches: false,
        max_duration_secs: 1800,
    };
    plan.validate(&targets)?;
    let mut tx = pool.begin().await?;
    let typed = typed_steps::preview(&state, &mut tx, &targets, &plan).await?;
    let spec = json!({"plan":plan,"typed_steps":typed});
    let job = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,spec,targets,status,created_at,updated_at,expires_at,preview_digest) VALUES($1,'TEST_ONLY backup job',1,$2,$3,'running',$4,$4,$5,$6)")
        .bind(job).bind(&spec).bind(&targets).bind(now).bind(now+1800).bind(digest(&spec)?).execute(&mut *tx).await?;
    super::super::api::materialize(&mut tx, job, &targets, &plan, &spec).await?;
    typed_steps::queue_backup(&mut tx, job, now).await?;
    tx.commit().await?;
    Ok((state, directory, job, schedule))
}

#[sqlx::test]
async fn many_targets_share_one_claim_and_restart_never_replays_it(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (state, _directory, job, schedule) = setup(pool.clone()).await?;
    let execution = claim(&state).await?.expect("one backup claim");
    assert_eq!(execution.job, job);
    assert_eq!(execution.schedule, schedule);
    let claims: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations_panel_steps WHERE job_id=$1")
            .bind(job)
            .fetch_one(&pool)
            .await?;
    assert_eq!(claims, 1);
    let target_steps: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations_target_steps WHERE job_id=$1")
            .bind(job)
            .fetch_one(&pool)
            .await?;
    assert_eq!(target_steps, 2);
    assert!(claim(&state).await?.is_none());
    sqlx::query("UPDATE operations_panel_steps SET claimed_at=$2 WHERE job_id=$1")
        .bind(job)
        .bind(state.started_at - 1)
        .execute(&pool)
        .await?;
    interrupted(&state).await?;
    assert!(claim(&state).await?.is_none());
    let row =
        sqlx::query("SELECT state,execution_id,result FROM operations_panel_steps WHERE job_id=$1")
            .bind(job)
            .fetch_one(&pool)
            .await?;
    assert_eq!(row.get::<String, _>("state"), "uncertain");
    assert_eq!(row.get::<Uuid, _>("execution_id"), execution.id);
    assert_eq!(row.get::<Value, _>("result")["cleanup_confirmed"], false);
    let paused: bool =
        sqlx::query_scalar("SELECT paused FROM operations_backup_schedules WHERE id=$1")
            .bind(schedule)
            .fetch_one(&pool)
            .await?;
    assert!(paused);
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM operations_backup_records")
        .fetch_one(&pool)
        .await?;
    assert_eq!(records, 0);
    Ok(())
}

#[sqlx::test]
async fn changed_backup_settings_fail_without_executing_or_selecting_a_new_key(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (state, _directory, job, schedule) = setup(pool.clone()).await?;
    sqlx::query("UPDATE operations_backup_schedules SET paused=false WHERE id=$1")
        .bind(schedule)
        .execute(&pool)
        .await?;
    assert!(claim(&state).await?.is_none());
    let row =
        sqlx::query("SELECT state,claimed_at,result FROM operations_panel_steps WHERE job_id=$1")
            .bind(job)
            .fetch_one(&pool)
            .await?;
    assert_eq!(row.get::<String, _>("state"), "failed");
    assert_eq!(row.get::<Option<i64>, _>("claimed_at"), None);
    assert_eq!(row.get::<Value, _>("result")["executed"], false);
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM operations_backup_records")
        .fetch_one(&pool)
        .await?;
    assert_eq!(records, 0);
    Ok(())
}
