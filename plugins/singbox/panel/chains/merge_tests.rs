use super::*;
use anyhow::Result;
use sqlx::PgPool;

async fn endpoint(tx: &mut Transaction<'_, Postgres>, enabled: bool) -> Result<i64> {
    let server: i64 = sqlx::query_scalar(
        "INSERT INTO servers(name) VALUES('TEST_ONLY legacy endpoint') RETURNING id",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(sqlx::query_scalar("INSERT INTO nodes(name,server_id,port,public_host,sni,private_key,public_key,short_id,enabled) VALUES('TEST_ONLY node',$1,443,'node.example.com','www.example.com','TEST_ONLY private','TEST_ONLY public','1234abcd',$2) RETURNING id")
        .bind(server).bind(enabled).fetch_one(&mut **tx).await?)
}
async fn legacy(tx: &mut Transaction<'_, Postgres>, entry: i64, exit: i64) -> Result<i64> {
    let id = sqlx::query_scalar("INSERT INTO singbox_chains(name,entry_node_id,exit_node_id,relay_uuid) VALUES('TEST_ONLY legacy',$1,$2,$3) RETURNING id")
        .bind(entry).bind(exit).bind(Uuid::new_v4()).fetch_one(&mut **tx).await?;
    super::super::mixed_paths::seed_legacy_on(tx, id).await?;
    seed_legacy_projection_on(tx, id).await?;
    Ok(id)
}

#[sqlx::test(migrations = "./migrations")]
async fn newly_created_legacy_chain_preserves_both_snapshot_namespaces_and_disabled_projection(
    pool: PgPool,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let entry = endpoint(&mut tx, true).await?;
    let exit = endpoint(&mut tx, false).await?;
    let id = legacy(&mut tx, entry, exit).await?;
    let value: Chain = sqlx::query_as(&format!("{SELECT} AND c.id=$1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    assert!(!value.available);
    let numeric: serde_json::Value = sqlx::query_scalar(
        "SELECT path_json FROM singbox_chain_versions WHERE chain_id=$1 AND generation=1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let ordered = super::super::ordered_paths::storage::version(&mut tx, id, 1).await?;
    assert!(ordered.legacy);
    assert_eq!(
        numeric["hops"][0]["identity"],
        serde_json::to_value(ordered.snapshot.legacy_relay_uuid)?
    );
    assert_eq!(ordered.snapshot.entry.node.id, entry);
    let super::super::ordered_paths::models::FrozenHop::Managed { endpoint, .. } =
        &ordered.snapshot.hops[0]
    else {
        panic!("legacy hop must remain managed")
    };
    assert_eq!(endpoint.node.id, exit);
    assert!(!endpoint.node.enabled);
    assert_eq!(numeric["hops"][0]["endpoint"]["enabled"], false);
    let generations: (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT active_generation,applied_generation FROM singbox_chains WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(generations, (Some(1), Some(1)));
    tx.commit().await?;
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn node_deletion_guard_retains_policy_numeric_and_ordered_cleanup_owners(
    pool: PgPool,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let target = endpoint(&mut tx, true).await?;
    let entry = endpoint(&mut tx, true).await?;
    super::super::nodes::ensure_unreferenced_on(&mut tx, target).await?;
    let group: i64 = sqlx::query_scalar("INSERT INTO singbox_policy_groups(name) VALUES('TEST_ONLY private name must not leak') RETURNING id").fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO singbox_policy_nodes(group_id,node_id) VALUES($1,$2)")
        .bind(group)
        .bind(target)
        .execute(&mut *tx)
        .await?;
    assert!(matches!(
        super::super::nodes::ensure_unreferenced_on(&mut tx, target).await,
        Err(ApiError::Conflict(_))
    ));
    sqlx::query("DELETE FROM singbox_policy_nodes WHERE group_id=$1")
        .bind(group)
        .execute(&mut *tx)
        .await?;
    let id = legacy(&mut tx, entry, target).await?;
    assert!(matches!(
        super::super::nodes::ensure_unreferenced_on(&mut tx, target).await,
        Err(ApiError::Conflict(_))
    ));
    sqlx::query(
        "UPDATE singbox_chains SET path_kind='mixed',exit_node_id=NULL,relay_uuid=NULL WHERE id=$1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    assert!(matches!(
        super::super::nodes::ensure_unreferenced_on(&mut tx, target).await,
        Err(ApiError::Conflict(_))
    ));
    sqlx::query(
        "UPDATE singbox_chains SET path_kind='ordered',phase='retiring',deleted_at=1 WHERE id=$1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    assert!(matches!(
        super::super::nodes::ensure_unreferenced_on(&mut tx, target).await,
        Err(ApiError::Conflict(_))
    ));
    sqlx::query("UPDATE singbox_chains SET phase='retired',applied_generation=NULL WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    super::super::nodes::ensure_unreferenced_on(&mut tx, target).await?;
    tx.rollback().await?;
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn numeric_retained_hop_deletion_returns_its_public_owner_without_reading_snapshots(
    pool: PgPool,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let entry = endpoint(&mut tx, true).await?;
    let previous_exit = endpoint(&mut tx, true).await?;
    let current_exit = endpoint(&mut tx, true).await?;
    let id = legacy(&mut tx, entry, previous_exit).await?;
    // TEST_ONLY keep the previous raw hop while the numeric lineage selects a
    // different managed exit. This exercises deletion ownership, not execution.
    sqlx::query("INSERT INTO singbox_chain_versions(chain_id,generation,previous_generation,legacy,path_json,semantic_hash,networks,stage,created_at,updated_at) SELECT chain_id,2,1,FALSE,path_json,semantic_hash,networks,'active',created_at,updated_at FROM singbox_chain_versions WHERE chain_id=$1 AND generation=1")
        .bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO singbox_chain_hops(chain_id,generation,position,kind,managed_node_id,managed_server_id,endpoint_json,relay_uuid) SELECT h.chain_id,2,h.position,h.kind,n.id,n.server_id,h.endpoint_json,$3 FROM singbox_chain_hops h JOIN nodes n ON n.id=$2 WHERE h.chain_id=$1 AND h.generation=1")
        .bind(id).bind(current_exit).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("UPDATE singbox_chains SET path_kind='mixed',exit_node_id=NULL,relay_uuid=NULL,active_generation=2 WHERE id=$1")
        .bind(id).execute(&mut *tx).await?;
    let result =
        super::super::proxy_resources::ensure_direct_node_unreferenced_on(&mut tx, previous_exit)
            .await;
    let Err(ApiError::ConflictReferences { references, .. }) = result else {
        panic!("retained numeric ownership must return public references")
    };
    assert_eq!(references["policies"], serde_json::json!([]));
    assert_eq!(
        references["chains"],
        serde_json::json!([{
            "id":id,"name":"TEST_ONLY legacy","role":"exit",
            "generation":1,"hop_position":1,"state":"retained"
        }])
    );
    let history: serde_json::Value = sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(h) ORDER BY generation,position) FROM singbox_chain_hops h WHERE chain_id=$1")
        .bind(id).fetch_one(&mut *tx).await?;
    super::super::mixed_paths::resources::remove_on(&mut tx, id).await?;
    for node in [previous_exit, current_exit] {
        assert_eq!(
            sqlx::query_scalar::<_, Option<i64>>("SELECT deleted_at FROM nodes WHERE id=$1")
                .bind(node)
                .fetch_one(&mut *tx)
                .await?,
            None
        );
        super::super::proxy_resources::ensure_direct_node_unreferenced_on(&mut tx, node).await?;
    }
    assert_eq!(sqlx::query_scalar::<_, serde_json::Value>("SELECT jsonb_agg(to_jsonb(h) ORDER BY generation,position) FROM singbox_chain_hops h WHERE chain_id=$1")
        .bind(id).fetch_one(&mut *tx).await?, history);
    tx.rollback().await?;
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn ordered_deletion_projection_tracks_selected_generations_and_corruption_fallback(
    pool: PgPool,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let entry = endpoint(&mut tx, true).await?;
    let target = endpoint(&mut tx, true).await?;
    let id = legacy(&mut tx, entry, target).await?;
    // TEST_ONLY preserve five immutable generations, with four selected owners.
    // These raw fixtures do not claim execution or applied device evidence.
    for generation in 2_i64..=5 {
        sqlx::query("INSERT INTO singbox_ordered_chain_versions(chain_id,generation,legacy,entry_endpoint_version,semantic_sha256,capabilities,snapshot,created_at) SELECT chain_id,$2,legacy,entry_endpoint_version,semantic_sha256,capabilities,snapshot,created_at FROM singbox_ordered_chain_versions WHERE chain_id=$1 AND generation=1")
            .bind(id).bind(generation).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO singbox_ordered_chain_hops(chain_id,generation,position,kind,endpoint_version_id,managed_node_id,managed_server_id,relay_uuid) SELECT chain_id,$2,position,kind,endpoint_version_id,managed_node_id,managed_server_id,$3 FROM singbox_ordered_chain_hops WHERE chain_id=$1 AND generation=1")
            .bind(id).bind(generation).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE singbox_chains SET path_kind='ordered',exit_node_id=NULL,relay_uuid=NULL,desired_generation=5,applied_generation=2,candidate_generation=3,recovery_generation=4,phase='retiring',deleted_at=1 WHERE id=$1")
        .bind(id).execute(&mut *tx).await?;
    let result =
        super::super::proxy_resources::ensure_direct_node_unreferenced_on(&mut tx, target).await;
    let Err(ApiError::ConflictReferences { references, .. }) = result else {
        panic!("selected ordered ownership must return public references")
    };
    let rows = references["chains"]
        .as_array()
        .expect("public chain references");
    assert_eq!(
        rows.iter()
            .map(|row| (
                row["generation"].as_i64().unwrap(),
                row["state"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        vec![
            (2, "applied"),
            (3, "candidate"),
            (4, "recovery"),
            (5, "desired")
        ]
    );
    sqlx::query("UPDATE singbox_chains SET desired_generation=99 WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let result =
        super::super::proxy_resources::ensure_direct_node_unreferenced_on(&mut tx, target).await;
    let Err(ApiError::ConflictReferences { references, .. }) = result else {
        panic!("damaged ordered ownership must return public references")
    };
    let rows = references["chains"]
        .as_array()
        .expect("raw fallback references");
    assert_eq!(
        rows.iter()
            .map(|row| (
                row["generation"].as_i64().unwrap(),
                row["state"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        vec![
            (1, "unresolved"),
            (2, "applied"),
            (3, "candidate"),
            (4, "recovery"),
            (5, "unresolved")
        ]
    );
    sqlx::query("UPDATE singbox_chains SET phase='retired' WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    super::super::proxy_resources::ensure_direct_node_unreferenced_on(&mut tx, target).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM singbox_ordered_chain_versions WHERE chain_id=$1"
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?,
        5
    );
    // Even an incomplete owner with no snapshots or hops must identify its
    // dedicated entry; a generic conflict would hide the resource to clean.
    let bare_entry = endpoint(&mut tx, true).await?;
    let bare: i64 = sqlx::query_scalar("INSERT INTO singbox_chains(name,entry_node_id,path_kind) VALUES('TEST_ONLY incomplete owner',$1,'ordered') RETURNING id")
        .bind(bare_entry).fetch_one(&mut *tx).await?;
    let result =
        super::super::proxy_resources::ensure_direct_node_unreferenced_on(&mut tx, bare_entry)
            .await;
    let Err(ApiError::ConflictReferences { references, .. }) = result else {
        panic!("an incomplete dedicated entry must retain its public owner")
    };
    assert_eq!(
        references["chains"],
        serde_json::json!([{
            "id":bare,"name":"TEST_ONLY incomplete owner","role":"entry",
            "generation":1,"hop_position":null,"state":"unresolved"
        }])
    );
    tx.rollback().await?;
    Ok(())
}
