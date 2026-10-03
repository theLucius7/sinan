//! Preserve actual service status receipts without interpreting missing samples as exits.
use crate::error::ApiResult;
use serde_json::{Value, json};
use sinan_protocol::fleet::{JobResult, Operation};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
struct Status {
    active: bool,
    state: String,
    substate: Option<String>,
    result: Option<String>,
    exit_status: Option<u32>,
    main_pid: Option<u32>,
}
fn status(details: &str) -> Option<Status> {
    if details.len() > 16384 {
        return None;
    }
    let mut values = BTreeMap::new();
    for line in details.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if [
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainStatus",
            "MainPID",
            "active",
        ]
        .contains(&key)
            && values.insert(key, value).is_some()
        {
            return None;
        }
    }
    if let Some(active) = values.get("active") {
        let active = match *active {
            "true" => true,
            "false" => false,
            _ => return None,
        };
        return Some(Status {
            active,
            state: if active { "active" } else { "inactive" }.into(),
            substate: None,
            result: None,
            exit_status: None,
            main_pid: None,
        });
    }
    let state = *values.get("ActiveState")?;
    if ![
        "active",
        "reloading",
        "inactive",
        "failed",
        "activating",
        "deactivating",
    ]
    .contains(&state)
    {
        return None;
    }
    Some(Status {
        active: ["active", "reloading"].contains(&state),
        state: state.into(),
        substate: values.get("SubState").map(|value| value.to_string()),
        result: values.get("Result").map(|value| value.to_string()),
        exit_status: values
            .get("ExecMainStatus")
            .and_then(|value| value.parse().ok()),
        main_pid: values.get("MainPID").and_then(|value| value.parse().ok()),
    })
}
fn exit_observed(current: &Status, previous: Option<&Status>) -> bool {
    if current.active || !["inactive", "failed"].contains(&current.state.as_str()) {
        return false;
    }
    (current.state == "failed" && current.exit_status.is_some_and(|code| code > 0))
        || previous.is_some_and(|old| old.active && old.main_pid.is_none_or(|pid| pid > 0))
}
pub(in crate::fleet) async fn observe(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    operation: &Operation,
    receipt: &JobResult,
) -> ApiResult<()> {
    if !receipt.succeeded || receipt.completed_at <= 0 {
        return Ok(());
    }
    let mut results = Vec::new();
    match operation {
        Operation::Service { unit, .. }
            if receipt.result["unit"].as_str() == Some(unit.as_str()) =>
        {
            results.push((&unit[..], &receipt.result))
        }
        Operation::Services {} => {
            for result in receipt.result["services"]
                .as_array()
                .into_iter()
                .flatten()
                .take(128)
            {
                if let Some(unit) = result["unit"].as_str() {
                    results.push((unit, result));
                }
            }
        }
        _ => return Ok(()),
    }
    for (unit, result) in results {
        if unit.is_empty() || unit.len() > 128 {
            continue;
        }
        let Some(current) = result["details"].as_str().and_then(status) else {
            continue;
        };
        let observations = "WITH observations AS (SELECT f.id,(f.result->>'completed_at')::bigint AS completed_at,o.payload FROM fleet_operations f CROSS JOIN LATERAL (SELECT f.result->'result' AS payload WHERE f.operation->>'kind'='service' UNION ALL SELECT item FROM jsonb_array_elements(CASE WHEN f.operation->>'kind'='services' AND jsonb_typeof(f.result->'result'->'services')='array' THEN f.result->'result'->'services' ELSE '[]'::jsonb END) item) o WHERE f.server_id=$1 AND f.id<>$2 AND f.status='succeeded' AND o.payload->>'unit'=$3 AND (f.result->>'completed_at')::bigint<$4)";
        let previous_sql = format!(
            "{observations} SELECT payload FROM observations ORDER BY completed_at DESC,id DESC LIMIT 1"
        );
        let row = sqlx::query(&previous_sql)
            .bind(server)
            .bind(receipt.id)
            .bind(unit)
            .bind(receipt.completed_at)
            .fetch_optional(&mut **tx)
            .await?;
        let previous = row
            .as_ref()
            .map(|row| row.get::<Value, _>("payload"))
            .and_then(|value| value["details"].as_str().and_then(status));
        if !exit_observed(&current, previous.as_ref()) {
            continue;
        }
        let fingerprint = json!({"state":current.state,"substate":current.substate,"result":current.result,"exit_status":current.exit_status,"main_pid":current.main_pid});
        let duplicate_sql = format!(
            "{observations} SELECT EXISTS(SELECT 1 FROM fleet_events WHERE server_id=$1 AND kind='service_exit_observed' AND detail->>'unit'=$3 AND detail->'status'=$5 AND occurred_at>COALESCE((SELECT max(completed_at) FROM observations WHERE payload->>'details' LIKE '%ActiveState=active%' OR payload->>'details'='active=true'),0))"
        );
        let duplicate: bool = sqlx::query_scalar(&duplicate_sql)
            .bind(server)
            .bind(receipt.id)
            .bind(unit)
            .bind(receipt.completed_at)
            .bind(&fingerprint)
            .fetch_one(&mut **tx)
            .await?;
        if duplicate {
            continue;
        }
        sqlx::query("INSERT INTO fleet_events(id,server_id,kind,source,occurred_at,detail) VALUES($1,$2,'service_exit_observed','agent_service_status',$3,$4)")
            .bind(Uuid::new_v4()).bind(server).bind(receipt.completed_at)
            .bind(json!({"unit":unit,"operation_id":receipt.id,"requested_action":match operation { Operation::Service{action,..}=>Some(action.as_str()),_=>None },"service_exit_confirmed":true,"status":fingerprint,"previous_status":previous.map(|value|json!({"state":value.state,"main_pid":value.main_pid})),"observed_at":receipt.completed_at,"exit_time":null,"reason":"真实服务状态或进程退出码；观测时间不等于精确退出时间"})).execute(&mut **tx).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_or_stale_process_groups_and_never_started_services_are_not_exit_evidence() {
        assert!(status("").is_none());
        assert!(status("ActiveState=active\nActiveState=inactive").is_none());
        let inactive = status(
            "ActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\nMainPID=0",
        )
        .unwrap();
        assert!(!exit_observed(&inactive, None));
        let active = status("ActiveState=active\nSubState=running\nMainPID=123").unwrap();
        assert!(exit_observed(&inactive, Some(&active)));
        let failed =
            status("ActiveState=failed\nResult=exit-code\nExecMainStatus=1\nMainPID=0").unwrap();
        assert!(exit_observed(&failed, None));
        assert!(!exit_observed(&active, Some(&failed)));
    }
    #[sqlx::test]
    async fn actual_status_receipts_are_deduplicated_and_a_later_restart_allows_a_new_exit(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let server: i64 =
            sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY status') RETURNING id")
                .fetch_one(&pool)
                .await?;
        let operation = Operation::Service {
            unit: "example.service".into(),
            action: "status".into(),
        };
        let mut tx = pool.begin().await?;
        for (at, details) in [
            (10, "ActiveState=active\nMainPID=123"),
            (
                20,
                "ActiveState=inactive\nResult=success\nExecMainStatus=0\nMainPID=0",
            ),
            (
                30,
                "ActiveState=inactive\nResult=success\nExecMainStatus=0\nMainPID=0",
            ),
            (40, "ActiveState=active\nMainPID=124"),
            (
                50,
                "ActiveState=inactive\nResult=success\nExecMainStatus=0\nMainPID=0",
            ),
        ] {
            let result = json!({"unit":"example.service","details":details});
            let operation = if [10, 30, 40].contains(&at) {
                Operation::Services {}
            } else {
                operation.clone()
            };
            let receipt = JobResult {
                id: Uuid::new_v4(),
                succeeded: true,
                result: if matches!(operation, Operation::Services {}) {
                    json!({"services":[result]})
                } else {
                    result
                },
                error: None,
                completed_at: at,
            };
            sqlx::query("INSERT INTO fleet_operations(id,server_id,operation,policy,requested_at,expires_at,status,result) VALUES($1,$2,$3,'{}',1,100,'succeeded',$4)")
                .bind(receipt.id).bind(server).bind(json!(operation)).bind(json!(receipt)).execute(&mut *tx).await?;
            observe(&mut tx, server, &operation, &receipt).await?;
            observe(&mut tx, server, &operation, &receipt).await?;
        }
        let times:Vec<i64>=sqlx::query_scalar("SELECT occurred_at FROM fleet_events WHERE kind='service_exit_observed' ORDER BY occurred_at").fetch_all(&mut *tx).await?;
        assert_eq!(times, vec![20, 50]);
        tx.commit().await?;
        Ok(())
    }
}
