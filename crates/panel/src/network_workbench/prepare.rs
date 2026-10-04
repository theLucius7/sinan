use super::models::{Check, Target};
use crate::error::{ApiError, ApiResult};
use sinan_protocol::now_timestamp;
use sqlx::{PgPool, Row};

pub(super) async fn latency_target(pool: &PgPool, check: &Check) -> ApiResult<Option<Target>> {
    let Check::Throughput {
        latency_target: Some(host),
        ..
    } = check
    else {
        return Ok(None);
    };
    let rows = sqlx::query("SELECT * FROM network_workbench_targets WHERE host=$1 AND (authorized_until IS NULL OR authorized_until>$2) ORDER BY id LIMIT 2")
        .bind(host).bind(now_timestamp()).fetch_all(pool).await?;
    if rows.len() != 1 {
        return Err(ApiError::Conflict(
            "负载延迟目标需对应唯一仍有效的授权目标；缺失或同地址存在多个授权时请先明确目标身份"
                .into(),
        ));
    }
    let row = &rows[0];
    Ok(Some(Target {
        id: row.get("id"),
        name: row.get("name"),
        host: row.get("host"),
        region: row.get("region"),
        carrier: row.get("carrier"),
        purpose: row.get("purpose"),
        authorization: row.get("authorization_snapshot"),
        authorized_until: row.get("authorized_until"),
    }))
}

#[cfg(test)]
mod tests {
    use super::super::models::Family;
    use super::*;
    use uuid::Uuid;

    pub(super) fn check(server: i64) -> Check {
        Check::Throughput {
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
        }
    }

    #[sqlx::test]
    async fn latency_host_requires_one_live_identity_and_freezes_its_complete_authorization(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        let check = check(1);
        assert!(latency_target(&pool, &check).await.is_err());
        let original = Uuid::new_v4();
        let end = now_timestamp() + 3600;
        sqlx::query("INSERT INTO network_workbench_targets(id,name,host,region,carrier,purpose,authorization_snapshot,authorized_until,created_at,updated_at) VALUES($1,'TEST_ONLY','latency.example.test','region','carrier','isolated','original authorization',$2,0,0)")
            .bind(original).bind(end).execute(&pool).await?;
        let frozen = latency_target(&pool, &check).await?.unwrap();
        assert_eq!(frozen.id, original);
        assert_eq!(frozen.name, "TEST_ONLY");
        assert_eq!(frozen.host, "latency.example.test");
        assert_eq!(frozen.region, "region");
        assert_eq!(frozen.carrier, "carrier");
        assert_eq!(frozen.purpose, "isolated");
        assert_eq!(frozen.authorization, "original authorization");
        assert_eq!(frozen.authorized_until, Some(end));
        let alias = Uuid::new_v4();
        sqlx::query("INSERT INTO network_workbench_targets(id,name,host,purpose,authorization_snapshot,created_at,updated_at) VALUES($1,'TEST_ONLY alias','latency.example.test','isolated','different authorization',0,0)")
            .bind(alias).execute(&pool).await?;
        assert!(latency_target(&pool, &check).await.is_err());
        sqlx::query("UPDATE network_workbench_targets SET authorized_until=$2 WHERE id=$1")
            .bind(alias)
            .bind(now_timestamp() - 1)
            .execute(&pool)
            .await?;
        assert_eq!(latency_target(&pool, &check).await?.unwrap().id, original);
        sqlx::query("UPDATE network_workbench_targets SET authorized_until=$2 WHERE id=$1")
            .bind(original)
            .bind(now_timestamp() - 1)
            .execute(&pool)
            .await?;
        assert!(latency_target(&pool, &check).await.is_err());
        let mut without_latency = check;
        if let Check::Throughput { latency_target, .. } = &mut without_latency {
            *latency_target = None;
        }
        assert!(latency_target(&pool, &without_latency).await?.is_none());
        Ok(())
    }
}
