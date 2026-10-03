use super::*;
use anyhow::Result;
use sqlx::PgPool;

fn node(credential: &str) -> sinan_compiler::Node {
    serde_json::from_value(json!({"id":1,"name":"Example node","port":443,"public_host":"proxy.example.invalid","sni":"proxy.example.invalid","private_key":"TEST_ONLY-private-key","public_key":"TEST_ONLY-public-key","short_id":"01020304","users":[{"user_id":1,"uuid":"00000000-0000-4000-8000-000000000001","credential":credential}]})).expect("node fixture")
}

#[test]
fn credential_only_change_is_visible_without_exposing_secrets() {
    let changes = runtime::differences(&[node("TEST_ONLY-old")], &[node("TEST_ONLY-new")])
        .expect("comparison");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["change"], "changed");
    assert_eq!(changes[0]["affected_users"], json!([1]));
    let serialized = serde_json::to_string(&changes).expect("output");
    for secret in ["TEST_ONLY-old", "TEST_ONLY-new", "TEST_ONLY-private-key"] {
        assert!(!serialized.contains(secret));
    }
}

#[test]
fn client_template_rejects_unknown_fields_and_missing_outbounds() {
    let content=json!({"outbounds":[{"type":"selector","tag":"proxy","outbounds":["node-1"]},{"type":"vless","tag":"node-1","uuid":"TEST_ONLY-credential"},{"type":"direct","tag":"direct"}],"route":{"final":"proxy"}}).to_string();
    assert!(
        client::apply_definition(
            content.clone(),
            Some(&json!({"selection_groups":[],"dns":null,"route":null,"unknown_field":true}))
        )
        .is_err()
    );
    assert!(client::apply_definition(content.clone(),Some(&json!({"selection_groups":[{"tag":"proxy","outbounds":["node-2"],"default":null}],"dns":null,"route":null}))).is_err());
    assert!(
        client::apply_definition(
            content,
            Some(&json!({"selection_groups":[],"dns":null,"route":{"unsupported_rule_source":[]}}))
        )
        .is_err()
    );
}

#[test]
fn client_template_preserves_credentials_and_expressible_fields() {
    let content=json!({"outbounds":[{"type":"selector","tag":"proxy","outbounds":["node-1"]},{"type":"vless","tag":"node-1","uuid":"TEST_ONLY-credential","packet_encoding":"xudp"},{"type":"direct","tag":"direct"}],"route":{"final":"proxy"}}).to_string();
    let definition = json!({"selection_groups":[{"tag":"proxy","outbounds":["node-1"],"default":"node-1"}],"dns":{"servers":[{"type":"udp","tag":"dns-example","server":"192.0.2.53","detour":"proxy"}],"final":"dns-example"},"route":{"final":"proxy","rules":[{"domain_suffix":["example.invalid"],"action":"route","outbound":"node-1"}]}});
    let output: Value = serde_json::from_str(
        &client::apply_definition(content, Some(&definition)).expect("template"),
    )
    .expect("config");
    assert_eq!(output["dns"], definition["dns"]);
    assert_eq!(output["route"], definition["route"]);
    let original = output["outbounds"]
        .as_array()
        .expect("outbounds")
        .iter()
        .find(|v| v["tag"] == "node-1")
        .expect("retained node");
    assert_eq!(original["uuid"], "TEST_ONLY-credential");
    assert_eq!(original["packet_encoding"], "xudp");
}

#[test]
fn distinct_business_operations_cannot_be_confused_by_extra_fields() {
    assert!(
        serde_json::from_value::<Operation>(
            json!({"operation":"extend_validity","user_id":1,"days":30,"reset_quota":true})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<Operation>(
            json!({"operation":"reset_quota","user_id":1,"days":30})
        )
        .is_err()
    );
    assert!(ids(&[1, 1], false).is_err());
    assert!(ids(&[0], false).is_err());
    assert_eq!(ids(&[3, 1, 2], false).expect("fixed ids"), vec![1, 2, 3]);
}

#[test]
fn template_read_projection_hides_all_custom_dns_headers() {
    let definition = json!({"selection_groups":[{"tag":"proxy","outbounds":["node-1"],"default":"node-1"}],"dns":{"servers":[{"type":"https","tag":"private-dns","server":"dns.example.invalid","headers":{"X-Custom-Header":"TEST_ONLY-secret","Authorization":"TEST_ONLY-authorization"}}]},"route":{"final":"proxy"}});
    let public = client::redact_definition(&definition);
    assert_eq!(public["selection_groups"], definition["selection_groups"]);
    assert_eq!(public["dns"]["servers"][0]["server"], "dns.example.invalid");
    let serialized = serde_json::to_string(&public).expect("public template");
    assert!(!serialized.contains("TEST_ONLY-secret"));
    assert!(!serialized.contains("TEST_ONLY-authorization"));
}

#[test]
fn checkpoint_failure_uses_evidence_without_exposing_raw_runtime_output() {
    assert_eq!(
        runtime::inspection_reason("configuration file differs from the deployment").0,
        "configuration_mismatch"
    );
    assert_eq!(
        runtime::inspection_reason("controlled instance is executing another binary").0,
        "runtime_identity_mismatch"
    );
    assert_eq!(
        runtime::inspection_reason("runtime is not healthy").0,
        "unhealthy"
    );
    assert_eq!(
        runtime::inspection_reason("TEST_ONLY-secret-bearing-unclassified-error").0,
        "inspection_failed"
    );
    assert!(
        !runtime::inspection_reason("TEST_ONLY-secret-bearing-unclassified-error")
            .1
            .contains("TEST_ONLY")
    );
}

async fn fixture(pool: &PgPool) -> Result<(i64, i64, i64, i64)> {
    let server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('Operations fixture') RETURNING id")
            .fetch_one(pool)
            .await?;
    let user:i64=sqlx::query_scalar("INSERT INTO users(name,subscription_token) VALUES('Fixture user','TEST_ONLY-operations-token') RETURNING id").fetch_one(pool).await?;
    let node:i64=sqlx::query_scalar("INSERT INTO nodes(name,server_id,port,public_host,sni,private_key,public_key,short_id) VALUES('Fixture node',$1,443,'proxy.example.invalid','proxy.example.invalid','TEST_ONLY-private','TEST_ONLY-public','01020304') RETURNING id").bind(server).fetch_one(pool).await?;
    let package:i64=sqlx::query_scalar("INSERT INTO singbox_package_groups(name,monthly_bytes,reset_day,reset_hour,reset_minute,timezone,duration_days) VALUES('Fixture package',1000,1,0,0,'UTC',365) RETURNING id").fetch_one(pool).await?;
    let assignment:i64=sqlx::query_scalar("INSERT INTO singbox_package_assignments(user_id,request_id,package_group_id,package_name,monthly_bytes,reset_day,reset_hour,reset_minute,timezone,starts_at,expires_at) VALUES($1,$2,$3,'Fixture package',1000,1,0,0,'UTC',$4-1,$4+86400) RETURNING id").bind(user).bind(Uuid::new_v4()).bind(package).bind(sinan_protocol::now_timestamp()).fetch_one(pool).await?;
    sqlx::query("INSERT INTO singbox_user_packages(user_id,assignment_id) VALUES($1,$2)")
        .bind(user)
        .bind(assignment)
        .execute(pool)
        .await?;
    Ok((server, user, node, assignment))
}

async fn usage(
    pool: &PgPool,
    server: i64,
    user: i64,
    node: i64,
    bytes: i64,
    at: i64,
) -> Result<()> {
    let epoch = Uuid::new_v4();
    sqlx::query("INSERT INTO usage_batches(server_id,epoch,seq,payload_hash,received_at) VALUES($1,$2,1,'TEST_ONLY-hash',$3)").bind(server).bind(epoch).bind(sinan_protocol::now_timestamp()).execute(pool).await?;
    sqlx::query("INSERT INTO usage_records(server_id,epoch,seq,stat_name,user_id,node_id,uplink,downlink,period_start,period_end) VALUES($1,$2,1,$3,$4,$5,$6,0,$7-1,$7)").bind(server).bind(epoch).bind(format!("u{user}_n{node}")).bind(user).bind(node).bind(bytes).bind(at).execute(pool).await?;
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn quota_reset_preserves_ledger_and_late_batches_still_charge(pool: PgPool) -> Result<()> {
    let (server, user, node, _) = fixture(&pool).await?;
    let at = sinan_protocol::now_timestamp();
    usage(&pool, server, user, node, 700, at).await?;
    let mut tx = pool.begin().await?;
    snapshots::snapshot(&mut tx, &Operation::ResetQuota { user_id: user }).await?;
    let receipt = mutations::execute(
        &mut tx,
        1,
        Uuid::new_v4(),
        &Operation::ResetQuota { user_id: user },
    )
    .await?;
    assert_eq!(receipt["credit_bytes"], "700");
    tx.commit().await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT used_bytes FROM singbox_entitlements($1) WHERE user_id=$2"
        )
        .bind(at)
        .bind(user)
        .fetch_one(&pool)
        .await?,
        "0"
    );
    usage(&pool, server, user, node, 100, at).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT used_bytes FROM singbox_entitlements($1) WHERE user_id=$2"
        )
        .bind(at)
        .bind(user)
        .fetch_one(&pool)
        .await?,
        "100"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM usage_records WHERE user_id=$1")
            .bind(user)
            .fetch_one(&pool)
            .await?,
        2
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn extension_creates_snapshot_without_resetting_cycle_or_used_bytes(
    pool: PgPool,
) -> Result<()> {
    let (server, user, node, original) = fixture(&pool).await?;
    let at = sinan_protocol::now_timestamp();
    usage(&pool, server, user, node, 600, at).await?;
    let before:(i64,i64,String,i64)=sqlx::query_as("SELECT starts_at,expires_at,used_bytes,cycle_start FROM singbox_entitlements($1) WHERE user_id=$2").bind(at).bind(user).fetch_one(&pool).await?;
    let mut tx = pool.begin().await?;
    snapshots::snapshot(
        &mut tx,
        &Operation::ExtendValidity {
            user_id: user,
            days: 30,
        },
    )
    .await?;
    let receipt = mutations::execute(
        &mut tx,
        1,
        Uuid::new_v4(),
        &Operation::ExtendValidity {
            user_id: user,
            days: 30,
        },
    )
    .await?;
    tx.commit().await?;
    let after:(i64,i64,String,i64)=sqlx::query_as("SELECT starts_at,expires_at,used_bytes,cycle_start FROM singbox_entitlements($1) WHERE user_id=$2").bind(at).bind(user).fetch_one(&pool).await?;
    assert_eq!(after, (before.0, before.1 + 30 * 86400, before.2, before.3));
    assert_ne!(receipt["assignment_id"], json!(original));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM singbox_package_assignments WHERE user_id=$1"
        )
        .bind(user)
        .fetch_one(&pool)
        .await?,
        2
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn preview_fingerprint_changes_after_late_usage_and_group_changes(
    pool: PgPool,
) -> Result<()> {
    let (server, user, node, _) = fixture(&pool).await?;
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO singbox_policy_groups(name) VALUES('Initial group') RETURNING id",
    )
    .fetch_one(&pool)
    .await?;
    let operation = Operation::PolicyBatch {
        user_ids: vec![user],
        group_ids: vec![group],
    };
    let mut tx = pool.begin().await?;
    let (first, _) = snapshots::snapshot(&mut tx, &operation).await?;
    tx.commit().await?;
    usage(
        &pool,
        server,
        user,
        node,
        1,
        sinan_protocol::now_timestamp(),
    )
    .await?;
    let mut tx = pool.begin().await?;
    let (second, _) = snapshots::snapshot(&mut tx, &operation).await?;
    tx.commit().await?;
    assert_ne!(first, second);
    sqlx::query("UPDATE singbox_policy_groups SET name='Changed group' WHERE id=$1")
        .bind(group)
        .execute(&pool)
        .await?;
    let mut tx = pool.begin().await?;
    let (third, _) = snapshots::snapshot(&mut tx, &operation).await?;
    tx.commit().await?;
    assert_ne!(second, third);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn rotation_requires_exact_new_applied_identity_and_recent_device_evidence(
    pool: PgPool,
) -> Result<()> {
    let (server, user, node_id, _) = fixture(&pool).await?;
    sqlx::query("INSERT INTO accesses(user_id,node_id,uuid,stat_name,credential) VALUES($1,$2,$3,$4,'TEST_ONLY-before')").bind(user).bind(node_id).bind(Uuid::new_v4()).bind(format!("u{user}_n{node_id}")).execute(&pool).await?;
    sqlx::query("INSERT INTO server_module_status(server_id,module,target_rev,applied_rev,healthy,updated_at) VALUES($1,'singbox',1,1,TRUE,$2)").bind(server).bind(sinan_protocol::now_timestamp()).execute(&pool).await?;
    let mut tx = pool.begin().await?;
    mutations::execute(
        &mut tx,
        1,
        Uuid::new_v4(),
        &Operation::RotateNodeCredentials {
            user_id: user,
            node_ids: vec![node_id],
        },
    )
    .await?;
    tx.commit().await?;
    let (uuid, credential): (Uuid, String) =
        sqlx::query_as("SELECT uuid,credential FROM accesses WHERE user_id=$1 AND node_id=$2")
            .bind(user)
            .bind(node_id)
            .fetch_one(&pool)
            .await?;
    let mut applied = node(&credential);
    applied.id = node_id;
    applied.users = vec![sinan_compiler::Access {
        user_id: user,
        uuid,
        credential,
    }];
    sqlx::query("INSERT INTO deployments(server_id,module,rev,bundle,bundle_sha256,source_json,created_at) VALUES($1,'singbox',2,'TEST_ONLY-bundle','TEST_ONLY-hash',$2,$3)").bind(server).bind(json!([applied])).bind(sinan_protocol::now_timestamp()).execute(&pool).await?;
    sqlx::query("UPDATE server_module_status SET target_rev=2,applied_rev=2,healthy=TRUE,updated_at=$2 WHERE server_id=$1 AND module='singbox'").bind(server).bind(sinan_protocol::now_timestamp()).execute(&pool).await?;
    sqlx::query("UPDATE servers SET dirty_at=NULL WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    let mut tx = pool.begin().await?;
    let offline = diagnosis::rotations(&mut tx, user).await?;
    assert_eq!(offline[0]["old_downloaded_credentials_revoked"], false);
    tx.commit().await?;
    sqlx::query("UPDATE servers SET last_seen=$2 WHERE id=$1")
        .bind(server)
        .bind(sinan_protocol::now_timestamp())
        .execute(&pool)
        .await?;
    let mut tx = pool.begin().await?;
    let online = diagnosis::rotations(&mut tx, user).await?;
    assert_eq!(online[0]["state"], "device_confirmed");
    assert_eq!(online[0]["old_downloaded_credentials_revoked"], true);
    tx.commit().await?;
    sqlx::query("UPDATE servers SET capabilities='[\"runtime:checkpoint-v1\"]' WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    let mut tx = pool.begin().await?;
    let missing_checkpoint = diagnosis::rotations(&mut tx, user).await?;
    assert_eq!(
        missing_checkpoint[0]["old_downloaded_credentials_revoked"],
        false
    );
    assert_eq!(missing_checkpoint[0]["state"], "confirmation_stale");
    tx.commit().await?;
    Ok(())
}
