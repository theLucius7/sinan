use super::{Principal, authenticate};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;

const CATEGORY_LIMIT: usize = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    q: String,
}

struct SearchScope {
    unrestricted: bool,
    servers: Vec<i64>,
    capabilities: Vec<String>,
}

impl SearchScope {
    fn for_actor(actor: &Principal) -> Self {
        // Tokens narrow the administrator's grants; they never replace those grants.
        let mut servers = if actor.all_servers {
            actor.token_servers.clone().unwrap_or_default()
        } else {
            actor
                .server_ids
                .iter()
                .copied()
                .filter(|id| actor.allows_server(*id))
                .collect()
        };
        servers.retain(|id| *id > 0);
        servers.sort_unstable();
        servers.dedup();
        let capabilities = super::access::FEATURES
            .iter()
            .flat_map(|feature| [format!("{feature}:read"), format!("{feature}:write")])
            .filter(|capability| actor.allows(capability))
            .collect();
        Self {
            unrestricted: actor.global_servers(),
            servers,
            capabilities,
        }
    }
}

struct SearchResults {
    items: Vec<Value>,
    categories: Vec<Value>,
}

impl SearchResults {
    async fn append(
        &mut self,
        state: &AppState,
        scope: &SearchScope,
        pattern: &str,
        category: &str,
        extra_ctes: &str,
        select: &str,
    ) -> ApiResult<()> {
        // Every SELECT applies object visibility before this limit. The extra row is
        // only a truncation sentinel and is never returned as an inaccessible result.
        let sql = format!(
            "WITH RECURSIVE visibility AS (SELECT $2::boolean AS unrestricted, \
             $3::bigint[] AS server_ids, $5::text[] AS capabilities) \
             {extra_ctes} {select} LIMIT $4"
        );
        let mut rows: Vec<Value> = sqlx::query_scalar(&sql)
            .bind(pattern)
            .bind(scope.unrestricted)
            .bind(&scope.servers)
            .bind((CATEGORY_LIMIT + 1) as i64)
            .bind(&scope.capabilities)
            .fetch_all(&state.pool)
            .await?;
        let truncated = rows.len() > CATEGORY_LIMIT;
        rows.truncate(CATEGORY_LIMIT);
        self.categories
            .push(json!({"kind":category,"limit":CATEGORY_LIMIT,
                                    "returned":rows.len(),"truncated":truncated}));
        self.items.extend(rows);
        Ok(())
    }
}

// Configuration references can cross server boundaries. Traverse domain and
// forwarding dependencies, then include each related DNS rule's server grant.
// The document handler permits records without server associations with
// network:read alone. An empty scope therefore stays visible with that capability.
const DOCUMENT_SCOPE: &str = r#",
document_references AS (
 SELECT d.id AS parent_id, referenced.id AS child_id
 FROM network_documents d
 CROSS JOIN LATERAL (
   SELECT jsonb_array_elements_text(COALESCE(d.config->'domain_ids','[]'::jsonb)) AS id
   UNION SELECT jsonb_array_elements_text(COALESCE(d.config->'dependency_ids','[]'::jsonb))
 ) references_to
 JOIN network_documents referenced ON referenced.id::text=references_to.id
), document_links(origin_id,document_id) AS (
 SELECT id,id FROM network_documents
 UNION
 SELECT links.origin_id,refs.child_id FROM document_links links
 JOIN document_references refs ON refs.parent_id=links.document_id
), document_servers AS (
 SELECT links.origin_id,associated.server_id
 FROM document_links links JOIN network_documents d ON d.id=links.document_id
 CROSS JOIN LATERAL (
   SELECT (d.config->>'server_id')::bigint AS server_id
   UNION SELECT value::bigint FROM jsonb_array_elements_text(COALESCE(d.config->'server_ids','[]'::jsonb))
   UNION SELECT (value->>'server_id')::bigint FROM jsonb_array_elements(COALESCE(d.config->'targets','[]'::jsonb))
   UNION SELECT rule.server_id FROM ddns_rules rule WHERE rule.id::text IN (
     SELECT jsonb_array_elements_text(COALESCE(d.config->'ddns_rule_ids','[]'::jsonb))
     UNION SELECT d.config#>>'{renewal,ddns_rule_id}'
   )
 ) associated
 WHERE associated.server_id IS NOT NULL
), document_scope AS (
 SELECT d.id,COALESCE(array_agg(DISTINCT ds.server_id) FILTER(WHERE ds.server_id IS NOT NULL),
                     '{}'::bigint[]) AS server_ids
 FROM network_documents d LEFT JOIN document_servers ds ON ds.origin_id=d.id GROUP BY d.id
)"#;

// Panel-only plans and reports require diagnostics:read, not global server
// grants, matching network_workbench::api::authorize and the route guard.
const PLAN_SCOPE: &str = r#",
plan_scope AS (
 SELECT p.id,ARRAY(
   SELECT DISTINCT servers.server_id FROM jsonb_array_elements(p.definition#>'{plan,steps}') step
   CROSS JOIN LATERAL (
     SELECT (step#>>'{source,server_id}')::bigint AS server_id
     UNION SELECT value::bigint FROM jsonb_array_elements_text(COALESCE(step#>'{source,server_ids}','[]'::jsonb))
     UNION SELECT (step#>>'{check,receiver_server}')::bigint
     UNION SELECT (step#>>'{check,reverse_server}')::bigint
   ) servers WHERE servers.server_id IS NOT NULL
 ) AS server_ids FROM network_workbench_plans p
)"#;

const RUN_SCOPE: &str = r#",
run_executions AS (
 SELECT r.id,execution
 FROM network_workbench_runs r
 CROSS JOIN LATERAL jsonb_array_elements(COALESCE(r.snapshot->'executions','[]'::jsonb)) execution_group
 CROSS JOIN LATERAL jsonb_array_elements(execution_group) execution
), run_steps AS (
 SELECT r.id,step FROM network_workbench_runs r
 CROSS JOIN LATERAL jsonb_array_elements(COALESCE(r.snapshot#>'{plan,steps}','[]'::jsonb)) step
 UNION ALL
 SELECT r.id,step FROM network_workbench_runs r
 JOIN network_workbench_plans p ON p.id=r.plan_id
 CROSS JOIN LATERAL jsonb_array_elements(COALESCE(p.definition#>'{plan,steps}','[]'::jsonb)) step
), run_server_references AS (
 SELECT e.id,associated.server_id FROM run_executions e
 CROSS JOIN LATERAL (
   SELECT (e.execution->>'source_server')::bigint AS server_id
   UNION SELECT (e.execution#>>'{check,receiver_server}')::bigint
   UNION SELECT (e.execution#>>'{check,reverse_server}')::bigint
 ) associated
 UNION
 SELECT s.id,associated.server_id FROM run_steps s
 CROSS JOIN LATERAL (
   SELECT (s.step#>>'{source,server_id}')::bigint AS server_id
   UNION SELECT value::bigint FROM jsonb_array_elements_text(COALESCE(s.step#>'{source,server_ids}','[]'::jsonb))
   UNION SELECT (s.step#>>'{check,receiver_server}')::bigint
   UNION SELECT (s.step#>>'{check,reverse_server}')::bigint
 ) associated
 UNION SELECT run_id,server_id FROM network_workbench_results
),
run_scope AS (
 SELECT r.id,COALESCE(array_agg(DISTINCT refs.server_id) FILTER(WHERE refs.server_id IS NOT NULL),
                      '{}'::bigint[]) AS server_ids
 FROM network_workbench_runs r LEFT JOIN run_server_references refs ON refs.id=r.id GROUP BY r.id
)"#;

pub async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input): Query<SearchQuery>,
) -> ApiResult<Json<Value>> {
    let actor = authenticate(&state, &headers).await?;
    let text = input.q.trim();
    if text.is_empty() || text.len() > 100 || text.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "搜索词须为1至100字节，且不包含控制字符".into(),
        ));
    }
    let pattern = format!(
        "%{}%",
        text.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let scope = SearchScope::for_actor(&actor);
    let mut output = SearchResults {
        items: Vec::new(),
        categories: Vec::new(),
    };

    if actor.allows("servers:read") {
        output
            .append(
                &state,
                &scope,
                &pattern,
                "server",
                "",
                r#"
 SELECT jsonb_build_object('kind','server','id',s.id,'label',s.name,
   'path','/servers/'||s.id,'server_id',s.id,'sampled_at',NULLIF(s.metrics_sampled_at,0),
   'sampled_at_unit','milliseconds','received_at',s.static_info_received_at)
 FROM servers s CROSS JOIN visibility v
 WHERE s.deleted_at IS NULL AND (v.unrestricted OR s.id=ANY(v.server_ids))
   AND (s.name ILIKE $1 OR s.id::text ILIKE $1 OR s.static_info->>'hostname' ILIKE $1)
 ORDER BY s.name,s.id"#,
            )
            .await?;
        output.append(&state, &scope, &pattern, "ip", r#",
visible_servers AS (
 SELECT s.* FROM servers s CROSS JOIN visibility v
 WHERE s.deleted_at IS NULL AND (v.unrestricted OR s.id=ANY(v.server_ids))
), server_addresses AS (
 SELECT s.id,s.name,s.static_info_received_at,address.value AS address,address.source
 FROM visible_servers s CROSS JOIN LATERAL (
   SELECT value,'interface' AS source FROM jsonb_array_elements_text(
     CASE WHEN jsonb_typeof(s.static_info->'ip_addresses')='array'
          THEN s.static_info->'ip_addresses' ELSE '[]'::jsonb END)
   UNION
   SELECT value,'public-discovery' FROM jsonb_array_elements_text(
     CASE WHEN jsonb_typeof(s.static_info->'discovered_public_ips')='array'
          THEN s.static_info->'discovered_public_ips' ELSE '[]'::jsonb END)
   UNION
   SELECT addresses.value,'interface:'||interfaces.key
   FROM jsonb_each(CASE WHEN jsonb_typeof(s.static_info->'interface_addresses')='object'
                       THEN s.static_info->'interface_addresses' ELSE '{}'::jsonb END) interfaces
   CROSS JOIN LATERAL jsonb_array_elements_text(
     CASE WHEN jsonb_typeof(interfaces.value)='array' THEN interfaces.value ELSE '[]'::jsonb END) addresses
 ) address
)"#, r#"
 SELECT jsonb_build_object('kind','ip','id',id::text||':'||address,
   'label',address||' · '||name,'path','/servers/'||id||'/ip-info','server_id',id,
   'address',address,'sources',array_agg(DISTINCT source),'sampled_at',NULL,
   'received_at',static_info_received_at,'time_basis','static_info_received')
 FROM server_addresses WHERE address ILIKE $1
 GROUP BY id,name,address,static_info_received_at ORDER BY address,id"#).await?;
    }

    if actor.allows("diagnostics:read") {
        output.append(&state, &scope, &pattern, "ip-observation", "", r#"
 SELECT jsonb_build_object('kind','ip-observation','id',e.id,'label',e.address||' · '||e.source||' · '||e.status,
   'path',CASE WHEN e.server_id IS NULL THEN '/network-workbench' ELSE '/servers/'||e.server_id||'/network-workbench' END,
   'server_id',e.server_id,'address',e.address,'source',e.source,'status',e.status,
   'sampled_at',e.observed_at,'sampled_at_unit','seconds','expires_at',e.expires_at)
 FROM network_workbench_ip_evidence e CROSS JOIN visibility v
 WHERE (v.unrestricted OR e.server_id=ANY(v.server_ids))
   AND (e.address ILIKE $1 OR e.id::text ILIKE $1 OR e.source ILIKE $1)
 ORDER BY e.observed_at DESC,e.id"#).await?;
        output
            .append(
                &state,
                &scope,
                &pattern,
                "ip-quality",
                "",
                r#"
 SELECT jsonb_build_object('kind','ip-quality','id',q.server_id::text||':'||q.ip,
   'label',q.ip||' · IP质量资料','path','/servers/'||q.server_id||'/ip-info',
   'server_id',q.server_id,'address',q.ip,'sampled_at',q.checked_at,'sampled_at_unit','seconds')
 FROM server_ip_quality q CROSS JOIN visibility v
 WHERE (v.unrestricted OR q.server_id=ANY(v.server_ids)) AND q.ip ILIKE $1
 ORDER BY q.checked_at DESC,q.server_id,q.ip"#,
            )
            .await?;
        output.append(&state, &scope, &pattern, "diagnostic-task", "", r#"
 SELECT jsonb_build_object('kind','diagnostic-task','id',j.id,
   'label',COALESCE(j.job->>'plugin','诊断')||' · '||j.status||' · '||j.id,
   'path','/servers/'||j.server_id||CASE j.job->>'plugin' WHEN 'nodequality' THEN '/node-quality' WHEN 'tcpquality' THEN '/tcp-quality' ELSE '/network-workbench' END,
   'server_id',j.server_id,'status',j.status,'updated_at',j.updated_at,'sampled_at',NULL)
 FROM diagnostic_jobs j CROSS JOIN visibility v
 WHERE (v.unrestricted OR j.server_id=ANY(v.server_ids))
   AND (j.id::text ILIKE $1 OR j.status ILIKE $1 OR j.job->>'plugin' ILIKE $1)
 ORDER BY j.created_at DESC,j.id"#).await?;
        output.append(&state, &scope, &pattern, "test-plan", PLAN_SCOPE, r#"
 SELECT jsonb_build_object('kind','test-plan','id',p.id,'label',p.name||' · '||p.id,
   'path',CASE WHEN cardinality(ps.server_ids)=1 THEN '/servers/'||ps.server_ids[1]||'/network-workbench' ELSE '/network-workbench' END,
   'server_ids',ps.server_ids,'updated_at',p.updated_at,'sampled_at',NULL)
 FROM network_workbench_plans p JOIN plan_scope ps ON ps.id=p.id CROSS JOIN visibility v
 WHERE (v.unrestricted OR ps.server_ids <@ v.server_ids)
   AND (p.name ILIKE $1 OR p.id::text ILIKE $1)
 ORDER BY p.updated_at DESC,p.id"#).await?;
        output.append(&state, &scope, &pattern, "test-run", RUN_SCOPE, r#"
 SELECT jsonb_build_object('kind','test-run','id',r.id,
   'label',COALESCE(r.snapshot#>>'{plan,name}','综合测试')||' · '||r.status||' · '||r.id,
   'path',CASE WHEN cardinality(rs.server_ids)=1 THEN '/servers/'||rs.server_ids[1]||'/network-workbench' ELSE '/network-workbench' END,
   'server_ids',rs.server_ids,'status',r.status,'updated_at',r.updated_at,'sampled_at',NULL)
 FROM network_workbench_runs r JOIN run_scope rs ON rs.id=r.id CROSS JOIN visibility v
 WHERE (v.unrestricted OR rs.server_ids <@ v.server_ids)
   AND (r.id::text ILIKE $1 OR r.status ILIKE $1 OR r.snapshot#>>'{plan,name}' ILIKE $1)
 ORDER BY r.created_at DESC,r.id"#).await?;
    }

    if actor.allows("dns:read") {
        output.append(&state, &scope, &pattern, "dns-rule", "", r#"
 SELECT jsonb_build_object('kind','dns-rule','id',r.id,
   'label',COALESCE(r.config->>'record_name','DNS记录')||' · '||COALESCE(r.config->>'record_type','')||' · '||r.id,
   'path','/servers/'||r.server_id||'/ddns','server_id',r.server_id,
   'address',r.last_ip,'status',r.status,'last_success_at',r.last_success_at,
   'sampled_at',NULL,'time_basis','provider_update_accepted')
 FROM ddns_rules r CROSS JOIN visibility v
 WHERE (v.unrestricted OR r.server_id=ANY(v.server_ids))
   AND (r.config->>'record_name' ILIKE $1 OR r.last_ip ILIKE $1 OR r.id::text ILIKE $1)
 ORDER BY r.server_id,r.id"#).await?;
    }

    if actor.allows("network:read") {
        output.append(&state, &scope, &pattern, "network-document", DOCUMENT_SCOPE, r#"
 SELECT jsonb_build_object('kind',CASE d.kind WHEN 'domain' THEN 'domain' WHEN 'certificate' THEN 'certificate' ELSE 'network-rule' END,
   'id',d.id,'label',COALESCE(d.config->>'name',d.kind)||' · '||d.kind||' · '||d.id,
   'path',CASE WHEN cardinality(ds.server_ids)=1 THEN '/servers/'||ds.server_ids[1]||'/network-configuration' ELSE '/network-configuration' END,
   'document_kind',d.kind,'server_ids',ds.server_ids,'updated_at',d.updated_at,
   'sampled_at',(SELECT MAX(observed_at) FROM network_observations o
                 WHERE o.document_id=d.id AND (v.unrestricted OR o.server_id=ANY(v.server_ids))),
   'sampled_at_unit','seconds')
 FROM network_documents d JOIN document_scope ds ON ds.id=d.id CROSS JOIN visibility v
 WHERE (v.unrestricted OR ds.server_ids <@ v.server_ids)
   AND (d.id::text ILIKE $1 OR d.config->>'name' ILIKE $1
     OR d.config->>'public_address' ILIKE $1 OR d.config->>'listen_address' ILIKE $1
     OR d.config->>'target_address' ILIKE $1 OR d.config->>'relay_address' ILIKE $1
     OR d.config->>'address' ILIKE $1
     OR EXISTS(SELECT 1 FROM document_links links JOIN network_documents related ON related.id=links.document_id
               WHERE links.origin_id=d.id AND related.kind='domain' AND related.config->>'name' ILIKE $1)
     OR EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(d.config->'targets','[]'::jsonb)) target WHERE target->>'domain' ILIKE $1))
 ORDER BY d.updated_at DESC,d.id"#).await?;
    }

    // Proxy users and nodes lead to the existing global business workspace. A
    // server-scoped administrator cannot enter that workspace through search.
    if actor.allows("proxy:read") && actor.global_servers() {
        output
            .append(
                &state,
                &scope,
                &pattern,
                "node",
                "",
                r#"
 SELECT jsonb_build_object('kind','node','id',n.id,'label',n.name||' · '||n.id,
   'path','/plugins/sing-box/nodes/direct/'||n.id,'server_id',n.server_id,'sampled_at',NULL)
 FROM nodes n CROSS JOIN visibility v WHERE v.unrestricted AND n.deleted_at IS NULL
   AND (n.name ILIKE $1 OR n.public_host ILIKE $1 OR n.sni ILIKE $1 OR n.id::text ILIKE $1)
 ORDER BY n.name,n.id"#,
            )
            .await?;
        output
            .append(
                &state,
                &scope,
                &pattern,
                "proxy-user",
                "",
                r#"
 SELECT jsonb_build_object('kind','proxy-user','id',u.id,'label',u.name||' · '||u.id,
   'path','/plugins/sing-box/users','sampled_at',NULL)
 FROM users u CROSS JOIN visibility v WHERE v.unrestricted AND u.deleted_at IS NULL
   AND (u.name ILIKE $1 OR u.id::text ILIKE $1) ORDER BY u.name,u.id"#,
            )
            .await?;
    }

    if actor.allows("terminal:read") {
        output.append(&state, &scope, &pattern, "command-task", "", r#"
 SELECT jsonb_build_object('kind','command-task','id',c.id,
   'label','远程命令 · '||c.state||' · '||c.id,'path','/servers/'||c.server_id,
   'server_id',c.server_id,'status',c.state,'updated_at',COALESCE(c.finished_at,c.started_at,c.requested_at),'sampled_at',NULL)
 FROM remote_commands c CROSS JOIN visibility v
 WHERE (v.unrestricted OR c.server_id=ANY(v.server_ids)) AND (c.id::text ILIKE $1 OR c.state ILIKE $1)
 ORDER BY c.requested_at DESC,c.id"#).await?;
    }

    if actor.allows("operations:read") {
        output.append(&state, &scope, &pattern, "fleet-task", "", r#"
 SELECT jsonb_build_object('kind','fleet-task','id',f.id,
   'label',COALESCE(f.operation->>'kind','设备操作')||' · '||f.status||' · '||f.id,
   'path','/servers/'||f.server_id||'/fleet','server_id',f.server_id,'status',f.status,
   'updated_at',COALESCE(f.dispatched_at,f.requested_at),'sampled_at',NULL)
 FROM fleet_operations f CROSS JOIN visibility v
 WHERE (v.unrestricted OR f.server_id=ANY(v.server_ids)) AND (
   CASE f.operation->>'kind'
     WHEN 'snapshot' THEN 'operations:read'
     WHEN 'services' THEN 'services:read'
     WHEN 'logs' THEN 'services:read'
     WHEN 'service' THEN CASE WHEN f.operation->>'action'='status' THEN 'services:read' ELSE 'services:write' END
     WHEN 'ports' THEN 'monitoring:read'
     WHEN 'file_read' THEN 'files:read'
     WHEN 'file_write' THEN 'files:write'
     WHEN 'system_network' THEN CASE WHEN f.operation#>>'{operation,action}'='inventory' THEN 'network:read' ELSE 'network:write' END
     WHEN 'port_forward' THEN CASE WHEN f.operation#>>'{operation,action}'='status' THEN 'network:read' ELSE 'network:write' END
     WHEN 'certificate_deploy' THEN 'network:write'
     ELSE 'unrecognized'
   END = ANY(v.capabilities))
   AND (f.id::text ILIKE $1 OR f.status ILIKE $1 OR f.operation->>'kind' ILIKE $1 OR f.operation->>'unit' ILIKE $1)
 ORDER BY f.requested_at DESC,f.id"#).await?;
        for (kind, table, plan_field) in [
            ("operation-task", "operations_jobs", "spec->'plan'"),
            ("operation-schedule", "operations_schedules", "spec->'plan'"),
            ("remediation-rule", "operations_remediation_rules", "plan"),
        ] {
            // These identifiers are compile-time constants, never request fields.
            let query = format!(
                r#"
 SELECT jsonb_build_object('kind','{kind}','id',o.id,'label',o.name||' · '||o.id,
   'path',CASE WHEN cardinality(o.targets)=1 THEN '/servers/'||o.targets[1]||'/operations' ELSE '/operations' END,
   'server_ids',o.targets,'updated_at',o.updated_at,'sampled_at',NULL)
 FROM {table} o CROSS JOIN visibility v
 WHERE (v.unrestricted OR o.targets <@ v.server_ids)
   AND ('services:read'=ANY(v.capabilities) OR NOT EXISTS(
     SELECT 1 FROM jsonb_array_elements(o.{plan_field}->'steps') step
     WHERE step->>'service' IS NOT NULL))
   AND (o.name ILIKE $1 OR o.id::text ILIKE $1)
 ORDER BY o.updated_at DESC,o.id"#
            );
            output
                .append(&state, &scope, &pattern, kind, "", &query)
                .await?;
        }
        output.append(&state, &scope, &pattern, "maintenance", "", r#"
 SELECT jsonb_build_object('kind','maintenance','id',m.id,'label',m.name||' · '||m.id,
   'path',CASE WHEN cardinality(m.targets)=1 THEN '/servers/'||m.targets[1]||'/operations' ELSE '/operations' END,
   'server_ids',m.targets,'starts_at',m.starts_at,'ends_at',m.ends_at,'sampled_at',NULL)
 FROM operations_maintenance m CROSS JOIN visibility v
 WHERE (v.unrestricted OR m.targets <@ v.server_ids) AND (m.name ILIKE $1 OR m.id::text ILIKE $1)
 ORDER BY m.starts_at DESC,m.id"#).await?;
        output.append(&state, &scope, &pattern, "incident", "", r#"
 SELECT jsonb_build_object('kind','incident','id',i.id,
   'label',i.title||' · '||i.status||' · '||i.id,
   'path',CASE WHEN i.server_id IS NULL THEN '/operations' ELSE '/servers/'||i.server_id||'/operations' END,
   'server_id',i.server_id,'status',i.status,'sampled_at',i.observed_at,'sampled_at_unit','seconds')
 FROM operations_incidents i CROSS JOIN visibility v
 WHERE (v.unrestricted OR i.server_id=ANY(v.server_ids))
   AND i.source_key NOT LIKE 'certificate:%'
   AND (i.source_key NOT LIKE 'service:%' OR 'services:read'=ANY(v.capabilities))
   AND (i.source_key NOT LIKE 'cloud:%' OR 'cloud:read'=ANY(v.capabilities))
   AND (i.source_key NOT LIKE 'backup:%' OR (v.unrestricted AND 'recovery:read'=ANY(v.capabilities)))
   AND (i.source_key NOT LIKE 'job:%' OR EXISTS(
     SELECT 1 FROM operations_jobs job WHERE i.source_key='job:'||job.id
       AND (v.unrestricted OR job.targets <@ v.server_ids)
       AND ('services:read'=ANY(v.capabilities) OR NOT EXISTS(
         SELECT 1 FROM jsonb_array_elements(job.spec#>'{plan,steps}') step
         WHERE step->>'service' IS NOT NULL))))
   AND (i.title ILIKE $1 OR i.id::text ILIKE $1 OR i.source_key ILIKE $1)
 ORDER BY i.observed_at DESC,i.id"#).await?;
    }

    if actor.allows("monitoring:read") {
        output.append(&state, &scope, &pattern, "probe-rule", "", r#"
 SELECT jsonb_build_object('kind','probe-rule','id',p.id,
   'label',COALESCE(p.spec->>'name',p.spec->>'target','网络探测')||' · '||p.id,
   'path','/servers/'||p.server_id||'/tcp-quality','server_id',p.server_id,
   'sampled_at',(SELECT MAX(r.sampled_at) FROM probe_results r WHERE r.probe_id=p.id AND r.server_id=p.server_id),
   'sampled_at_unit','milliseconds')
 FROM network_probes p CROSS JOIN visibility v
 WHERE (v.unrestricted OR p.server_id=ANY(v.server_ids))
   AND (p.id::text ILIKE $1 OR p.spec->>'name' ILIKE $1 OR p.spec->>'target' ILIKE $1)
 ORDER BY p.server_id,p.id"#).await?;
        if actor.global_servers() {
            output
                .append(
                    &state,
                    &scope,
                    &pattern,
                    "alert-rule",
                    "",
                    r#"
 SELECT jsonb_build_object('kind','alert-rule','id',a.id,
   'label',COALESCE(a.spec->>'name','告警规则')||' · '||a.id,
   'path','/system/notifications','sampled_at',NULL)
 FROM alert_rules a CROSS JOIN visibility v WHERE v.unrestricted
   AND (a.spec->>'name' ILIKE $1 OR a.id::text ILIKE $1) ORDER BY a.id"#,
                )
                .await?;
            output.append(&state, &scope, &pattern, "latency-task", "", r#"
 SELECT jsonb_build_object('kind','latency-task','id',t.id,
   'label',COALESCE(t.spec->>'name','延迟监测')||' · '||t.id,'path','/latency',
   'sampled_at',(SELECT MAX(r.sampled_at) FROM probe_results r JOIN network_probes p ON p.id=r.probe_id WHERE p.task_id=t.id),
   'sampled_at_unit','milliseconds')
 FROM latency_tasks t CROSS JOIN visibility v WHERE v.unrestricted
   AND (t.spec->>'name' ILIKE $1 OR t.id::text ILIKE $1) ORDER BY t.id"#).await?;
        }
    }

    let truncated = output
        .categories
        .iter()
        .any(|category| category["truncated"] == true);
    Ok(Json(
        json!({"query":text,"results":output.items,"categories":output.categories,
                   "limited":truncated,"category_limit":CATEGORY_LIMIT,
                   "served_at":now_timestamp(),"scope_applied_before_limit":true}),
    ))
}
