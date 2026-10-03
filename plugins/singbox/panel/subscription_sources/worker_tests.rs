use super::*;
use crate::{config::Config, subscription_parser::parse_subscription};
use serde_json::{Value, json};
use sqlx::PgPool;

async fn state(pool: PgPool) -> AppState {
    AppState::new(
        pool,
        Config {
            database_url: String::new(),
            listen: "127.0.0.1:0".parse().expect("loopback"),
            public_url: "http://127.0.0.1".into(),
            data_dir: std::env::temp_dir(),
            admin_password: Some("TEST_ONLY-source-password".into()),
        },
    )
    .await
    .expect("test state")
}

fn parsed(password: &str) -> subscription_parser::ParsedSubscription {
    parse_subscription(json!({"outbounds":[{"type":"socks","tag":"Fixture","server":"proxy.example.com","server_port":1080,"version":"5","username":"TEST_ONLY-user","password":password}]}).to_string().as_bytes(),FormatHint::Auto).expect("fixture parse")
}

async fn seed(state: &AppState) -> i64 {
    let id:i64=sqlx::query_scalar("INSERT INTO singbox_ordered_subscription_sources(name,kind,host,input_config,refresh_interval_secs,created_at,updated_at) VALUES('Worker fixture','url','feeds.example.com',$1,86400,$2,$2) RETURNING id")
        .bind(json!({"kind":"url","url":"https://feeds.example.com/TEST_ONLY-token","auth_headers":{}})).bind(now_timestamp()).fetch_one(&state.pool).await.expect("source fixture");
    enqueue(state, id).await;
    id
}

async fn enqueue(state: &AppState, id: i64) -> Uuid {
    let mut tx = state.pool.begin().await.expect("transaction");
    let source = service::load_source(&mut tx, id, true)
        .await
        .expect("source");
    let job = jobs::enqueue(&mut tx, &source)
        .await
        .expect("enqueue")
        .expect("task ID");
    tx.commit().await.expect("commit");
    job
}

async fn one_claim(state: &AppState) -> Claim {
    let mut claims = claim_due(state, &BTreeSet::new()).await.expect("claim");
    assert_eq!(claims.len(), 1);
    claims.pop().expect("claim")
}

async fn success(state: &AppState) -> (i64, Uuid) {
    let source = seed(state).await;
    let claim = one_claim(state).await;
    snapshots::save(
        state,
        &claim,
        parsed("TEST_ONLY-password-original"),
        Some("TEST_ONLY-etag".into()),
        None,
    )
    .await
    .expect("first success");
    let revision: Uuid = sqlx::query_scalar(
        "SELECT current_success_revision FROM singbox_ordered_subscription_sources WHERE id=$1",
    )
    .bind(source)
    .fetch_one(&state.pool)
    .await
    .expect("success revision");
    (source, revision)
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn late_parse_results_cannot_cross_settings_epoch_archive_or_cancel(pool: PgPool) {
    let state = state(pool).await;
    for change in ["settings", "epoch", "archive", "cancel"] {
        let (source, previous) = success(&state).await;
        enqueue(&state, source).await;
        let claim = one_claim(&state).await;
        let query = match change {
            "settings" => {
                "UPDATE singbox_ordered_subscription_sources SET settings_revision=settings_revision+1 WHERE id=$1"
            }
            "epoch" => {
                "UPDATE singbox_ordered_subscription_sources SET identity_epoch=identity_epoch+1 WHERE id=$1"
            }
            "archive" => {
                "UPDATE singbox_ordered_subscription_sources SET archived=TRUE WHERE id=$1"
            }
            _ => {
                "UPDATE singbox_subscription_source_jobs SET status='cancelling',error='{\"stage\":\"done\",\"kind\":\"cancelled\",\"message\":\"测试取消\",\"http_status\":null}'::jsonb WHERE source_id=$1 AND status='running'"
            }
        };
        sqlx::query(query)
            .bind(source)
            .execute(&state.pool)
            .await
            .expect("concurrent change");
        snapshots::save(
            &state,
            &claim,
            parsed("TEST_ONLY-password-late"),
            None,
            None,
        )
        .await
        .expect("fenced result");
        let current: Uuid = sqlx::query_scalar(
            "SELECT current_success_revision FROM singbox_ordered_subscription_sources WHERE id=$1",
        )
        .bind(source)
        .fetch_one(&state.pool)
        .await
        .expect("current");
        assert_eq!(current, previous);
        let (status, token): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT status,claim_token FROM singbox_subscription_source_jobs WHERE id=$1",
        )
        .bind(claim.job_id)
        .fetch_one(&state.pool)
        .await
        .expect("terminal");
        assert_eq!(
            status,
            if change == "cancel" {
                "cancelled"
            } else {
                "superseded"
            }
        );
        assert!(token.is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM singbox_subscription_source_revisions WHERE source_id=$1"
            )
            .bind(source)
            .fetch_one(&state.pool)
            .await
            .expect("count"),
            1
        );
    }
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn source_failure_categories_preserve_last_success_and_immutable_credentials(pool: PgPool) {
    let state = state(pool).await;
    let (source, previous) = success(&state).await;
    for (kind, http_status) in [
        ("http_403", Some(403u16)),
        ("http_429", Some(429)),
        ("timeout", None),
    ] {
        enqueue(&state, source).await;
        let claim = one_claim(&state).await;
        let error = SourceFailure {
            stage: "fetch".into(),
            kind: kind.into(),
            message: "来源获取失败，保留上次成功结果".into(),
            http_status,
        };
        snapshots::failure(&state, &claim, error.clone())
            .await
            .expect("failure");
        let(current,last_error):(Uuid,Value)=sqlx::query_as("SELECT current_success_revision,last_error FROM singbox_ordered_subscription_sources WHERE id=$1").bind(source).fetch_one(&state.pool).await.expect("source");
        assert_eq!(current, previous);
        assert_eq!(last_error, json!(error));
        let stored:Value=sqlx::query_scalar("SELECT normalized_config FROM singbox_ordered_external_node_versions WHERE source_revision_id=$1").bind(previous).fetch_one(&state.pool).await.expect("original credentials");
        assert_eq!(stored["password"], "TEST_ONLY-password-original");
    }
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn conditional_304_reuses_only_matching_epoch_and_does_not_create_new_versions(pool: PgPool) {
    let state = state(pool).await;
    let (source, previous) = success(&state).await;
    enqueue(&state, source).await;
    let claim = one_claim(&state).await;
    assert_eq!(claim.previous_revision, Some(previous));
    assert!(claim.etag.is_some());
    snapshots::unchanged(&state, &claim, Some("TEST_ONLY-etag-next".into()), None)
        .await
        .expect("304");
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM singbox_subscription_source_jobs WHERE id=$1"
        )
        .bind(claim.job_id)
        .fetch_one(&state.pool)
        .await
        .expect("status"),
        "unchanged"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM singbox_ordered_external_node_versions")
            .fetch_one(&state.pool)
            .await
            .expect("versions"),
        1
    );
    enqueue(&state, source).await;
    let late = one_claim(&state).await;
    sqlx::query("UPDATE singbox_ordered_subscription_sources SET identity_epoch=2,settings_revision=2,last_success_at=1,conditional_etag=NULL,conditional_settings_revision=NULL,conditional_identity_epoch=NULL WHERE id=$1").bind(source).execute(&state.pool).await.expect("replace source");
    snapshots::unchanged(&state, &late, Some("TEST_ONLY-late-etag".into()), None)
        .await
        .expect("late 304");
    let(current,time,etag):(Uuid,i64,Option<String>)=sqlx::query_as("SELECT current_success_revision,last_success_at,conditional_etag FROM singbox_ordered_subscription_sources WHERE id=$1").bind(source).fetch_one(&state.pool).await.expect("source");
    assert_eq!(current, previous);
    assert_eq!(time, 1);
    assert!(etag.is_none());
    let new = seed(&state).await;
    let empty = one_claim(&state).await;
    assert_eq!(empty.source_id, new);
    snapshots::unchanged(&state, &empty, None, None)
        .await
        .expect("unexpected 304");
    let error: Value =
        sqlx::query_scalar("SELECT error FROM singbox_subscription_source_jobs WHERE id=$1")
            .bind(empty.job_id)
            .fetch_one(&state.pool)
            .await
            .expect("error");
    assert_eq!(error["kind"], "unexpected_304");
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn active_source_slots_renew_through_cancelling_and_release_only_on_terminal_ack(
    pool: PgPool,
) {
    let state = state(pool).await;
    let mut sources = Vec::new();
    for _ in 0..5 {
        sources.push(seed(&state).await);
    }
    let claims = claim_due(&state, &BTreeSet::new()).await.expect("claims");
    assert_eq!(claims.len(), 4);
    let local: BTreeSet<Uuid> = claims.iter().map(|claim| claim.job_id).collect();
    sqlx::query("UPDATE singbox_subscription_source_jobs SET deadline_at=$1 WHERE id=ANY($2)")
        .bind(now_timestamp() - 1)
        .bind(local.iter().copied().collect::<Vec<_>>())
        .execute(&state.pool)
        .await
        .expect("old lease");
    let claim = &claims[0];
    sqlx::query("UPDATE singbox_subscription_source_jobs SET status='cancelling',error='{\"stage\":\"done\",\"kind\":\"cancelled\",\"message\":\"测试取消\",\"http_status\":null}'::jsonb WHERE id=$1").bind(claim.job_id).execute(&state.pool).await.expect("cancel request");
    assert!(
        claim_due(&state, &local)
            .await
            .expect("renewed ownership")
            .is_empty()
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM singbox_subscription_source_jobs WHERE status IN ('running','cancelling')").fetch_one(&state.pool).await.expect("active slots"),4);
    let mut tx = state.pool.begin().await.expect("transaction");
    let source = service::load_source(&mut tx, claim.source_id, true)
        .await
        .expect("source");
    assert!(
        jobs::enqueue(&mut tx, &source)
            .await
            .expect("same source")
            .is_none()
    );
    tx.commit().await.expect("commit");
    snapshots::failure(
        &state,
        claim,
        SourceFailure::new("done", "cancelled", "测试取消确认"),
    )
    .await
    .expect("cancel acknowledgement");
    let mut remaining = local.clone();
    remaining.remove(&claim.job_id);
    let next = claim_due(&state, &remaining).await.expect("next work");
    assert_eq!(next.len(), 1);
    assert!(next.iter().all(|next| next.source_id != claim.source_id));
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM singbox_subscription_source_jobs WHERE id=$1"
        )
        .bind(claim.job_id)
        .fetch_one(&state.pool)
        .await
        .expect("status"),
        "cancelled"
    );
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn restart_expired_claim_and_monotonic_deadline_fence_old_success(pool: PgPool) {
    let state = state(pool).await;
    let (source, previous) = success(&state).await;
    enqueue(&state, source).await;
    let old = one_claim(&state).await;
    sqlx::query("UPDATE singbox_subscription_source_jobs SET deadline_at=$2 WHERE id=$1")
        .bind(old.job_id)
        .bind(now_timestamp() - 1)
        .execute(&state.pool)
        .await
        .expect("expired owner");
    assert!(
        claim_due(&state, &BTreeSet::new())
            .await
            .expect("restart cleanup")
            .is_empty()
    );
    snapshots::save(&state, &old, parsed("TEST_ONLY-password-late"), None, None)
        .await
        .expect("old result");
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "SELECT current_success_revision FROM singbox_ordered_subscription_sources WHERE id=$1"
        )
        .bind(source)
        .fetch_one(&state.pool)
        .await
        .expect("success"),
        previous
    );
    enqueue(&state, source).await;
    let mut deadline = one_claim(&state).await;
    deadline.work_deadline = Instant::now() - Duration::from_secs(1);
    snapshots::save(
        &state,
        &deadline,
        parsed("TEST_ONLY-password-too-late"),
        None,
        None,
    )
    .await
    .expect("work deadline");
    let (status, error): (String, Value) =
        sqlx::query_as("SELECT status,error FROM singbox_subscription_source_jobs WHERE id=$1")
            .bind(deadline.job_id)
            .fetch_one(&state.pool)
            .await
            .expect("deadline terminal");
    assert_eq!(status, "failed");
    assert_eq!(error["kind"], "timeout");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM singbox_subscription_source_revisions WHERE source_id=$1"
        )
        .bind(source)
        .fetch_one(&state.pool)
        .await
        .expect("history"),
        1
    );
    enqueue(&state, source).await;
    let mut waiting = one_claim(&state).await;
    let mut held = Vec::new();
    for _ in 0..state.pool.options().get_max_connections() {
        held.push(state.pool.acquire().await.expect("exhaust test pool"));
    }
    waiting.work_deadline = Instant::now() + Duration::from_millis(200);
    let error = tokio::time::timeout(Duration::from_secs(2), interrupted(&state, &waiting))
        .await
        .expect("status-query wait must respect work deadline");
    assert_eq!(error.kind, "timeout");
    drop(held);
    snapshots::failure(&state, &waiting, error)
        .await
        .expect("persist bounded interruption");
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "SELECT current_success_revision FROM singbox_ordered_subscription_sources WHERE id=$1"
        )
        .bind(source)
        .fetch_one(&state.pool)
        .await
        .expect("success after database wait"),
        previous
    );
}
