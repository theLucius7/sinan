use super::NodeChainReference;
use crate::error::ApiResult;
use sqlx::PgConnection;

/// Project raw cleanup ownership without requiring readable frozen snapshots.
/// Exclude the resource being removed before bounding the public response.
pub(super) async fn node_chain_references(
    connection: &mut PgConnection,
    id: i64,
    excluded_chain: Option<i64>,
) -> ApiResult<Vec<NodeChainReference>> {
    Ok(sqlx::query_as(
        "WITH ordered_owners AS (
            SELECT c.*,EXISTS(
                SELECT 1 FROM unnest(ARRAY[c.desired_generation,c.applied_generation,
                    c.candidate_generation,c.recovery_generation]) AS selected(generation)
                WHERE selected.generation IS NOT NULL AND NOT EXISTS(
                    SELECT 1 FROM singbox_ordered_chain_versions v
                    WHERE v.chain_id=c.id AND v.generation=selected.generation)
            ) AS unresolved
            FROM singbox_chains c
            WHERE c.path_kind='ordered' AND (c.deleted_at IS NULL OR c.phase<>'retired')
        ), refs AS (
            SELECT c.id,c.name,'entry' AS role,
                COALESCE(c.pending_generation,c.active_generation,1) AS generation,
                NULL::integer AS hop_position,
                CASE WHEN c.pending_generation IS NOT NULL THEN 'candidate'
                    ELSE 'applied' END AS state
            FROM singbox_live_chains c WHERE c.entry_node_id=$1
            UNION ALL
            SELECT c.id,c.name,'exit',
                COALESCE(h.generation,c.pending_generation,c.active_generation,1),
                COALESCE(h.position+1,1),
                CASE WHEN h.generation=c.pending_generation THEN 'candidate'
                    WHEN h.generation=c.active_generation OR h.generation IS NULL THEN 'applied'
                    ELSE 'retained' END
            FROM singbox_live_chains c LEFT JOIN singbox_chain_hops h
                ON h.chain_id=c.id AND h.managed_node_id=$1
            WHERE c.exit_node_id=$1
            UNION ALL
            SELECT c.id,c.name,'exit',h.generation,h.position+1,
                CASE WHEN h.generation=c.pending_generation THEN 'candidate'
                    WHEN h.generation=c.active_generation THEN 'applied'
                    ELSE 'retained' END
            FROM singbox_live_chains c JOIN singbox_chain_hops h ON h.chain_id=c.id
            WHERE h.managed_node_id=$1
            UNION ALL
            SELECT c.id,c.name,'entry',selected.generation,NULL::integer,
                CASE WHEN NOT EXISTS(SELECT 1 FROM singbox_ordered_chain_versions v
                        WHERE v.chain_id=c.id AND v.generation=selected.generation) THEN 'unresolved'
                    WHEN selected.generation=c.applied_generation THEN 'applied'
                    WHEN selected.generation=c.candidate_generation THEN 'candidate'
                    WHEN selected.generation=c.recovery_generation THEN 'recovery'
                    ELSE 'desired' END
            FROM ordered_owners c CROSS JOIN LATERAL (
                SELECT DISTINCT generation FROM unnest(ARRAY[c.desired_generation,
                    c.applied_generation,c.candidate_generation,c.recovery_generation])
                    AS selected(generation) WHERE generation IS NOT NULL
            ) selected WHERE c.entry_node_id=$1
            UNION ALL
            SELECT c.id,c.name,'exit',h.generation,h.position,
                CASE WHEN h.generation=c.applied_generation THEN 'applied'
                    WHEN h.generation=c.candidate_generation THEN 'candidate'
                    WHEN h.generation=c.recovery_generation THEN 'recovery'
                    WHEN h.generation=c.desired_generation THEN 'desired'
                    ELSE 'unresolved' END
            FROM ordered_owners c JOIN singbox_ordered_chain_hops h ON h.chain_id=c.id
            WHERE h.managed_node_id=$1 AND (c.unresolved OR h.generation=ANY(
                ARRAY[c.desired_generation,c.applied_generation,c.candidate_generation,
                    c.recovery_generation]))
        ) SELECT DISTINCT id,name,role,generation,hop_position,state FROM refs
            WHERE $2::bigint IS NULL OR id<>$2
            ORDER BY id,generation,hop_position,state LIMIT 32",
    )
    .bind(id)
    .bind(excluded_chain)
    .fetch_all(connection)
    .await?)
}
