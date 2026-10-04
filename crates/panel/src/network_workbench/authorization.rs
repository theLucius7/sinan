use super::{
    engine::Snapshot,
    models::{Check, Execution},
};
use crate::error::{ApiError, ApiResult};
use serde_json::Value;
use sinan_protocol::now_timestamp;
use sqlx::{PgConnection, Row};

pub(super) async fn current(
    connection: &mut PgConnection,
    snapshot: &Snapshot,
    index: usize,
    execution: &Execution,
) -> ApiResult<()> {
    if let Some(target) = &execution.target {
        if target
            .authorized_until
            .is_some_and(|end| end <= now_timestamp())
        {
            return Err(ApiError::Conflict("探测目标授权已到期".into()));
        }
        if execution.role.starts_with("reverse:") {
            let server = snapshot
                .executions
                .get(index)
                .and_then(|entries| entries.iter().find(|v| v.role.starts_with("source:")))
                .and_then(|v| v.source_server)
                .ok_or_else(|| ApiError::Conflict("反向采集缺少固定正向来源".into()))?;
            current_address(connection, server, &target.host).await?;
        } else {
            let row = sqlx::query("SELECT host,authorization_snapshot,authorized_until FROM network_workbench_targets WHERE id=$1")
                .bind(target.id).fetch_optional(&mut *connection).await?
                .ok_or_else(|| ApiError::Conflict("探测目标授权已撤销，请重新选择目标".into()))?;
            if row.get::<String, _>("host") != target.host
                || row.get::<String, _>("authorization_snapshot") != target.authorization
                || row.get::<Option<i64>, _>("authorized_until") != target.authorized_until
            {
                return Err(ApiError::Conflict(
                    "探测目标授权已改变，请重新冻结方案".into(),
                ));
            }
        }
    }
    if let Check::Throughput {
        receiver_server,
        receiver_host,
        latency_target,
        ..
    } = &execution.check
    {
        current_address(connection, *receiver_server, receiver_host).await?;
        if let Some(host) = latency_target {
            let frozen = execution.latency_target.as_ref().ok_or_else(|| {
                ApiError::Conflict(
                    "旧吞吐快照缺少负载延迟目标的精确授权身份，请重新冻结方案".into(),
                )
            })?;
            if frozen.host != *host
                || frozen
                    .authorized_until
                    .is_some_and(|end| end <= now_timestamp())
            {
                return Err(ApiError::Conflict(
                    "负载延迟目标与原方案不同或授权已到期".into(),
                ));
            }
            let row = sqlx::query("SELECT host,authorization_snapshot,authorized_until FROM network_workbench_targets WHERE id=$1")
                .bind(frozen.id).fetch_optional(&mut *connection).await?
                .ok_or_else(|| ApiError::Conflict("固定负载延迟目标授权已撤销，不能以同地址其他授权替换".into()))?;
            if row.get::<String, _>("host") != frozen.host
                || row.get::<String, _>("authorization_snapshot") != frozen.authorization
                || row.get::<Option<i64>, _>("authorized_until") != frozen.authorized_until
            {
                return Err(ApiError::Conflict(
                    "固定负载延迟目标授权已变化，请重新冻结方案".into(),
                ));
            }
        } else if execution.latency_target.is_some() {
            return Err(ApiError::Conflict("负载延迟目标不属于原吞吐请求".into()));
        }
    }
    if let Some((tool, version)) = execution.check.tool() {
        let licensed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_workbench_tools WHERE id=$1 AND version=$2 AND licensed)")
            .bind(tool).bind(version).fetch_one(&mut *connection).await?;
        if !licensed {
            return Err(ApiError::Conflict("固定工具版本或许可已改变".into()));
        }
    }
    Ok(())
}

pub(crate) async fn delivery(
    state: &crate::AppState,
    connection: &mut PgConnection,
    server: i64,
    job: &Value,
) -> ApiResult<()> {
    let run = job["workbench"]["run_id"]
        .as_str()
        .and_then(|id| id.parse::<uuid::Uuid>().ok())
        .ok_or_else(|| ApiError::Conflict("工作台任务缺少原方案身份".into()))?;
    let index = job["workbench"]["step_index"]
        .as_u64()
        .and_then(|index| usize::try_from(index).ok())
        .ok_or(ApiError::NotFound)?;
    let role = job["workbench"]["role"]
        .as_str()
        .ok_or(ApiError::NotFound)?;
    let row = sqlx::query(
        "SELECT snapshot,actor,current_step,status FROM network_workbench_runs WHERE id=$1",
    )
    .bind(run)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(ApiError::NotFound)?;
    if !["queued", "running", "paused"].contains(&row.get::<String, _>("status").as_str())
        || row.get::<i32, _>("current_step") != index as i32
    {
        return Err(ApiError::Conflict(
            "固定工作台方案已停止或步骤已改变".into(),
        ));
    }
    let actor = row
        .get::<String, _>("actor")
        .parse::<i64>()
        .map_err(anyhow::Error::from)?;
    crate::control_center::require_actor_capability(state, actor, "diagnostics:write").await?;
    let snapshot: Snapshot =
        serde_json::from_value(row.get("snapshot")).map_err(anyhow::Error::from)?;
    for execution in snapshot.executions.iter().flatten() {
        if let Some(source) = execution.source_server {
            crate::control_center::require_actor_server(state, actor, source, "diagnostics:write")
                .await?;
        }
    }
    let execution = snapshot
        .executions
        .get(index)
        .and_then(|entries| {
            entries
                .iter()
                .find(|execution| execution.role == role && execution.source_server == Some(server))
        })
        .ok_or_else(|| ApiError::Conflict("工作台实际来源与原方案不一致".into()))?;
    let encoded = job["options"]["execution"]
        .as_str()
        .ok_or(ApiError::NotFound)?;
    if serde_json::from_str::<Value>(encoded).map_err(anyhow::Error::from)?
        != serde_json::to_value(execution).map_err(anyhow::Error::from)?
    {
        return Err(ApiError::Conflict(
            "工作台任务消费输入与固定方案不同".into(),
        ));
    }
    current(connection, &snapshot, index, execution).await
}

async fn current_address(connection: &mut PgConnection, server: i64, host: &str) -> ApiResult<()> {
    let info: Option<Value> =
        sqlx::query_scalar("SELECT static_info FROM servers WHERE id=$1 AND deleted_at IS NULL")
            .bind(server)
            .fetch_optional(&mut *connection)
            .await?;
    if !info.is_some_and(|info| {
        info["ip_addresses"]
            .as_array()
            .is_some_and(|items| items.iter().any(|ip| ip.as_str() == Some(host)))
    }) {
        return Err(ApiError::Conflict(
            "受管目标地址已改变，请重新取得设备观测".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::models::{Budget, Family, Plan, Source, Step, Target};
    use super::*;
    use serde_json::json;
    use sqlx::PgPool;
    use uuid::Uuid;
    fn snapshot(id: Uuid) -> (Snapshot, Execution) {
        let check = Check::Tcp {
            target_id: id,
            port: 12345,
            family: Family::Ipv4,
            samples: 1,
        };
        let execution = Execution {
            schema: 1,
            source_server: None,
            role: "source:panel".into(),
            source_label: "面板".into(),
            budget: Budget::default(),
            check: check.clone(),
            target: Some(Target {
                id,
                name: "TEST_ONLY".into(),
                host: "127.0.0.1".into(),
                region: String::new(),
                carrier: String::new(),
                purpose: "isolated".into(),
                authorization: "TEST_ONLY".into(),
                authorized_until: None,
            }),
            latency_target: None,
        };
        let plan = Plan {
            name: "TEST_ONLY".into(),
            budget: Budget::default(),
            steps: vec![Step {
                name: "TEST_ONLY".into(),
                source: Source::Panel,
                check,
                stop_on_failure: true,
            }],
            schedule: None,
        };
        (
            Snapshot {
                plan,
                executions: vec![vec![execution.clone()]],
            },
            execution,
        )
    }
    #[sqlx::test]
    async fn queued_target_changes_and_deletion_revoke_the_frozen_execution(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO network_workbench_targets(id,name,host,region,carrier,purpose,authorization_snapshot,created_at,updated_at) VALUES($1,'TEST_ONLY','127.0.0.1','','','isolated','TEST_ONLY',0,0)")
            .bind(id).execute(&pool).await?;
        let (snapshot, execution) = snapshot(id);
        let mut connection = pool.acquire().await?;
        current(&mut connection, &snapshot, 0, &execution).await?;
        for field in ["host", "authorization_snapshot"] {
            sqlx::query(&format!(
                "UPDATE network_workbench_targets SET {field}='changed' WHERE id=$1"
            ))
            .bind(id)
            .execute(&mut *connection)
            .await?;
            assert!(
                current(&mut connection, &snapshot, 0, &execution)
                    .await
                    .is_err()
            );
            sqlx::query("UPDATE network_workbench_targets SET host='127.0.0.1',authorization_snapshot='TEST_ONLY' WHERE id=$1")
                .bind(id).execute(&mut *connection).await?;
        }
        sqlx::query("DELETE FROM network_workbench_targets WHERE id=$1")
            .bind(id)
            .execute(&mut *connection)
            .await?;
        assert!(
            current(&mut connection, &snapshot, 0, &execution)
                .await
                .is_err()
        );
        Ok(())
    }
    #[sqlx::test]
    async fn reverse_address_must_still_belong_to_the_frozen_managed_source(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        let server: i64 = sqlx::query_scalar(
            "INSERT INTO servers(name,static_info) VALUES('TEST_ONLY',$1) RETURNING id",
        )
        .bind(json!({"ip_addresses":["127.0.0.1"]}))
        .fetch_one(&pool)
        .await?;
        let (mut snapshot, mut execution) = snapshot(Uuid::new_v4());
        snapshot.executions[0][0].source_server = Some(server);
        snapshot.executions[0][0].role = format!("source:{server}");
        execution.role = "reverse:2".into();
        let mut connection = pool.acquire().await?;
        current(&mut connection, &snapshot, 0, &execution).await?;
        sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
            .bind(server)
            .bind(json!({"ip_addresses":["192.0.2.2"]}))
            .execute(&mut *connection)
            .await?;
        assert!(
            current(&mut connection, &snapshot, 0, &execution)
                .await
                .is_err()
        );
        Ok(())
    }

    #[sqlx::test]
    async fn throughput_latency_authorization_cannot_be_replaced_or_extended_by_same_host(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        let server: i64 = sqlx::query_scalar(
            "INSERT INTO servers(name,static_info) VALUES('TEST_ONLY receiver',$1) RETURNING id",
        )
        .bind(json!({"ip_addresses":["127.0.0.1"]}))
        .fetch_one(&pool)
        .await?;
        sqlx::query("INSERT INTO network_workbench_tools(id,version,license,source_url,licensed,updated_at) VALUES('iperf3','TEST_ONLY','TEST_ONLY','https://tools.example.test/iperf3',TRUE,0)")
            .execute(&pool).await?;
        let id = Uuid::new_v4();
        let end = now_timestamp() + 3600;
        sqlx::query("INSERT INTO network_workbench_targets(id,name,host,purpose,authorization_snapshot,authorized_until,created_at,updated_at) VALUES($1,'TEST_ONLY latency','latency.example.test','isolated','original authorization',$2,0,0)")
            .bind(id).bind(end).execute(&pool).await?;
        let check = Check::Throughput {
            client_mode: "local".into(),
            receiver_server: server,
            receiver_host: "127.0.0.1".into(),
            port: 5201,
            family: Family::Ipv4,
            direction: "forward".into(),
            protocol: "tcp".into(),
            streams: 1,
            duration_secs: 1,
            rate_bps: 1000,
            tool_version: "TEST_ONLY".into(),
            latency_target: Some("latency.example.test".into()),
        };
        let frozen = super::super::prepare::latency_target(&pool, &check).await?;
        let execution = Execution {
            schema: 1,
            source_server: None,
            target: None,
            latency_target: frozen,
            check: check.clone(),
            budget: Budget::default(),
            role: "source:panel".into(),
            source_label: "面板".into(),
        };
        let mut listener = execution.clone();
        listener.source_server = Some(server);
        listener.role = format!("listener:{server}");
        let snapshot = Snapshot {
            plan: Plan {
                name: "TEST_ONLY".into(),
                budget: Budget::default(),
                schedule: None,
                steps: vec![Step {
                    name: "TEST_ONLY".into(),
                    source: Source::Panel,
                    check,
                    stop_on_failure: true,
                }],
            },
            executions: vec![vec![listener.clone(), execution.clone()]],
        };
        let mut connection = pool.acquire().await?;
        for item in [&execution, &listener] {
            current(&mut connection, &snapshot, 0, item).await?;
        }
        let mut expired = execution.clone();
        expired.latency_target.as_mut().unwrap().authorized_until = Some(now_timestamp() - 1);
        assert!(
            current(&mut connection, &snapshot, 0, &expired)
                .await
                .is_err()
        );
        let mut mismatched = execution.clone();
        if let Check::Throughput { latency_target, .. } = &mut mismatched.check {
            *latency_target = Some("different.example.test".into());
        }
        assert!(
            current(&mut connection, &snapshot, 0, &mismatched)
                .await
                .is_err()
        );
        for (host, authorization, expiry) in [
            ("changed.example.test", "original authorization", Some(end)),
            ("latency.example.test", "different authorization", Some(end)),
            (
                "latency.example.test",
                "original authorization",
                Some(end + 1),
            ),
            ("latency.example.test", "original authorization", None),
            (
                "latency.example.test",
                "original authorization",
                Some(now_timestamp() - 1),
            ),
        ] {
            sqlx::query("UPDATE network_workbench_targets SET host=$2,authorization_snapshot=$3,authorized_until=$4 WHERE id=$1")
                .bind(id).bind(host).bind(authorization).bind(expiry).execute(&mut *connection).await?;
            for item in [&execution, &listener] {
                assert!(current(&mut connection, &snapshot, 0, item).await.is_err());
            }
        }
        sqlx::query("DELETE FROM network_workbench_targets WHERE id=$1")
            .bind(id)
            .execute(&mut *connection)
            .await?;
        sqlx::query("INSERT INTO network_workbench_targets(id,name,host,purpose,authorization_snapshot,authorized_until,created_at,updated_at) VALUES($1,'TEST_ONLY replacement','latency.example.test','isolated','original authorization',$2,0,0)")
            .bind(Uuid::new_v4()).bind(end).execute(&mut *connection).await?;
        for item in [&execution, &listener] {
            assert!(current(&mut connection, &snapshot, 0, item).await.is_err());
        }
        Ok(())
    }

    #[sqlx::test]
    async fn old_throughput_host_only_snapshot_fails_closed_but_old_no_latency_snapshot_remains_compatible(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        let server: i64 = sqlx::query_scalar(
            "INSERT INTO servers(name,static_info) VALUES('TEST_ONLY receiver',$1) RETURNING id",
        )
        .bind(json!({"ip_addresses":["127.0.0.1"]}))
        .fetch_one(&pool)
        .await?;
        sqlx::query("INSERT INTO network_workbench_tools(id,version,license,source_url,licensed,updated_at) VALUES('iperf3','TEST_ONLY','TEST_ONLY','https://tools.example.test/iperf3',TRUE,0)")
            .execute(&pool).await?;
        let (mut snapshot, mut execution) = snapshot(Uuid::new_v4());
        execution.target = None;
        execution.check = Check::Throughput {
            client_mode: "local".into(),
            receiver_server: server,
            receiver_host: "127.0.0.1".into(),
            port: 5201,
            family: Family::Ipv4,
            direction: "forward".into(),
            protocol: "tcp".into(),
            streams: 1,
            duration_secs: 1,
            rate_bps: 1000,
            tool_version: "TEST_ONLY".into(),
            latency_target: Some("latency.example.test".into()),
        };
        let old_encoded = serde_json::to_value(&execution)?;
        assert!(old_encoded.get("latency_target").is_none());
        execution = serde_json::from_value(old_encoded)?;
        assert!(execution.latency_target.is_none());
        snapshot.executions = vec![vec![execution.clone()]];
        let mut connection = pool.acquire().await?;
        assert!(
            current(&mut connection, &snapshot, 0, &execution)
                .await
                .is_err()
        );
        if let Check::Throughput { latency_target, .. } = &mut execution.check {
            *latency_target = None;
        }
        current(&mut connection, &snapshot, 0, &execution).await?;
        assert!(
            serde_json::to_value(&execution)?
                .get("latency_target")
                .is_none()
        );
        execution.latency_target = Some(Target {
            id: Uuid::new_v4(),
            name: "TEST_ONLY".into(),
            host: "latency.example.test".into(),
            region: String::new(),
            carrier: String::new(),
            purpose: "isolated".into(),
            authorization: "TEST_ONLY".into(),
            authorized_until: None,
        });
        assert!(
            current(&mut connection, &snapshot, 0, &execution)
                .await
                .is_err()
        );
        Ok(())
    }
}
