#![forbid(unsafe_code)]
mod business_support;
#[path = "alicloud/regressions.rs"]
mod regressions;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;
use anyhow::Result;
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const KEY: &str = "TEST_ONLY_ALICLOUD_ID";
const SECRET: &str = "TEST_ONLY_ALICLOUD_SECRET";
#[sqlx::test]
async fn cloud_account_crud_never_returns_credentials_and_enforces_revisions_and_resource_identity(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let mut account_body = json!({"name":"测试账号","site":"china","enabled":false,"auto_enabled":false,"limit_gb":100,"access_key_id":KEY,"access_key_secret":SECRET});
    assert_eq!(
        panel
            .admin(
                Method::POST,
                "/api/plugins/alicloud/accounts",
                &cookie,
                Some(account_body.clone()),
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    account_body["legacy_credentials"] = true.into();
    let id: Value = panel
        .admin(
            Method::POST,
            "/api/plugins/alicloud/accounts",
            &cookie,
            Some(account_body.clone()),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let id = id["id"].as_str().unwrap();
    let overview: Value = panel
        .admin(Method::GET, "/api/plugins/alicloud", &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    let text = overview.to_string();
    assert!(!text.contains(KEY) && !text.contains(SECRET) && !text.contains("access_key"));
    for method in [Method::GET, Method::POST] {
        let path = if method == Method::GET {
            "/api/plugins/alicloud"
        } else {
            "/api/plugins/alicloud/accounts"
        };
        assert_eq!(
            panel
                .client
                .request(method, format!("{}{path}", panel.base))
                .json(&account_body)
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let mut edit = account_body.clone();
    edit.as_object_mut().unwrap().remove("access_key_id");
    edit.as_object_mut().unwrap().remove("access_key_secret");
    edit["revision"] = 1.into();
    let account_path = format!("/api/plugins/alicloud/accounts/{id}");
    assert_eq!(
        panel
            .admin(Method::PATCH, &account_path, &cookie, Some(edit.clone()))
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT access_key_secret FROM alicloud_accounts")
            .fetch_one(&pool)
            .await?,
        SECRET
    );
    assert_eq!(
        panel
            .admin(Method::PATCH, &account_path, &cookie, Some(edit.clone()))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    edit["revision"] = 2.into();
    edit["access_key_id"] = "TEST_ONLY_REPLACEMENT".into();
    assert_eq!(
        panel
            .admin(Method::PATCH, &account_path, &cookie, Some(edit))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let resource_body = json!({"account_id":id,"name":"测试 EIP","kind":"eip","region":"cn-hangzhou","cloud_id":"eip-testonly","auto_enabled":false,"cap_mbps":1});
    let resource: Value = panel
        .admin(
            Method::POST,
            "/api/plugins/alicloud/resources",
            &cookie,
            Some(resource_body.clone()),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        panel
            .admin(
                Method::POST,
                "/api/plugins/alicloud/resources",
                &cookie,
                Some(resource_body.clone())
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        panel
            .admin(Method::DELETE, &account_path, &cookie, None)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let resource_path = format!(
        "/api/plugins/alicloud/resources/{}",
        resource["id"].as_str().unwrap()
    );
    let mut edit = resource_body;
    edit["revision"] = 1.into();
    edit["region"] = "cn-beijing".into();
    assert_eq!(
        panel
            .admin(Method::PATCH, &resource_path, &cookie, Some(edit))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("{resource_path}/refresh"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    // Disabled account rejects preview locally; no test credential reaches a real cloud.
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("{resource_path}/preview"),
                &cookie,
                Some(
                    json!({"revision":1,"target":{"bandwidth_mbps":1,"charge_type":"PayByTraffic"}})
                )
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        panel
            .admin(Method::DELETE, &resource_path, &cookie, None)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        panel
            .admin(Method::DELETE, &account_path, &cookie, None)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let stored: (String, String, bool) =
        sqlx::query_as("SELECT access_key_id,access_key_secret,archived FROM alicloud_accounts")
            .fetch_one(&pool)
            .await?;
    assert_eq!(stored, (String::new(), String::new(), true));
    Ok(())
}
#[sqlx::test]
async fn every_cloud_mutation_requires_administrator_session(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let id = Uuid::new_v4();
    for path in [
        format!("accounts/{id}/refresh"),
        format!("resources/{id}/refresh"),
        format!("operations/{id}/confirm"),
        format!("operations/{id}/cancel"),
        format!("operations/{id}/dismiss"),
        format!("resources/{id}/power-resume"),
        format!("power-jobs/{id}/confirm"),
        format!("power-jobs/{id}/cancel"),
        format!("power-jobs/{id}/dismiss"),
    ] {
        assert_eq!(
            panel
                .client
                .post(format!("{}/api/plugins/alicloud/{path}", panel.base))
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

#[sqlx::test]
async fn manual_refresh_cannot_bypass_provider_rate_limit(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let id = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret,error_code,last_attempt_at,next_run_at) VALUES($1,'TEST_ONLY throttled',$2,$3,'rate_limited',$4,$5)")
        .bind(id).bind(KEY).bind(SECRET).bind(now-61).bind(now+900).execute(&pool).await?;
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/plugins/alicloud/accounts/{id}/refresh"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_run_at FROM alicloud_accounts WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await?,
        now + 900
    );
    Ok(())
}

#[sqlx::test]
async fn power_policy_validates_revisions_and_power_jobs_are_admin_only_and_cancellable(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let account = Uuid::new_v4();
    let resource = Uuid::new_v4();
    let eip = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret,enabled) VALUES($1,'测试账号',$2,$3,false)").bind(account).bind(KEY).bind(SECRET).execute(&pool).await?;
    for (id, kind, cloud_id) in [
        (resource, "ecs", "i-testonly"),
        (eip, "eip", "eip-testonly"),
    ] {
        sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id) VALUES($1,$2,'测试资源',$3,'cn-hangzhou',$4)").bind(id).bind(account).bind(kind).bind(cloud_id).execute(&pool).await?;
    }
    let policy: Value =
        sqlx::query_scalar("SELECT power_policy FROM alicloud_resources WHERE id=$1")
            .bind(resource)
            .fetch_one(&pool)
            .await?;
    assert_eq!(policy["enabled"], false);
    assert_eq!(policy["stop_mode"], "KeepCharging");
    let path = format!("/api/plugins/alicloud/resources/{resource}/power-policy");
    let body = json!({"revision":1,"policy":policy});
    assert_eq!(
        panel
            .client
            .patch(format!("{}{path}", panel.base))
            .json(&body)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .admin(Method::PATCH, &path, &cookie, Some(body.clone()))
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        panel
            .admin(Method::PATCH, &path, &cookie, Some(body.clone()))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let mut invalid = body.clone();
    invalid["revision"] = 2.into();
    invalid["policy"]["threshold_percent"] = 101.into();
    assert_eq!(
        panel
            .admin(Method::PATCH, &path, &cookie, Some(invalid))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &format!("/api/plugins/alicloud/resources/{eip}/power-policy"),
                &cookie,
                Some(body)
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let preview_path = format!("/api/plugins/alicloud/resources/{resource}/power-preview");
    let preview = json!({"revision":2,"action":"stop","stop_mode":"StopCharging"});
    assert_eq!(
        panel
            .client
            .post(format!("{}{preview_path}", panel.base))
            .json(&preview)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Disabled accounts reject before any cloud I/O.
    assert_eq!(
        panel
            .admin(Method::POST, &preview_path, &cookie, Some(preview))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let job = Uuid::new_v4();
    let state = json!({"cloud_id":"i-testonly","region":"cn-hangzhou","status":"Running","stopped_mode":"KeepCharging","charge_type":"PostPaid","network_type":"vpc","spot_strategy":"NoSpot","interruption_behavior":null,"public_ips":["192.0.2.1"],"locked":false});
    sqlx::query("INSERT INTO alicloud_power_jobs(id,resource_id,account_revision,resource_revision,action,stop_mode,source,before_state,status,created_at,expires_at,updated_at) VALUES($1,$2,1,2,'stop','KeepCharging','manual',$3,'preview',$4,$5,$4)").bind(job).bind(resource).bind(state).bind(now).bind(now+300).execute(&pool).await?;
    sqlx::query("UPDATE alicloud_accounts SET enabled=true WHERE id=$1")
        .bind(account)
        .execute(&pool)
        .await?;
    for _ in 0..2 {
        assert_eq!(
            panel
                .admin(
                    Method::POST,
                    &format!("/api/plugins/alicloud/power-jobs/{job}/confirm"),
                    &cookie,
                    None
                )
                .await?
                .status(),
            StatusCode::ACCEPTED
        );
    }
    assert_eq!(
        panel
            .admin(
                Method::DELETE,
                &format!("/api/plugins/alicloud/resources/{resource}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/plugins/alicloud/power-jobs/{job}/cancel"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT manual_hold FROM alicloud_resources WHERE id=$1")
            .bind(resource)
            .fetch_one(&pool)
            .await?
    );
    let resume_path = format!("/api/plugins/alicloud/resources/{resource}/power-resume");
    assert_eq!(
        panel
            .admin(Method::POST, &resume_path, &cookie, None)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &resume_path,
                &cookie,
                Some(json!({"revision":1}))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT manual_hold FROM alicloud_resources WHERE id=$1")
            .bind(resource)
            .fetch_one(&pool)
            .await?
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/plugins/alicloud/resources/{resource}/power-resume"),
                &cookie,
                Some(json!({"revision":2}))
            )
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &resume_path,
                &cookie,
                Some(json!({"revision":2}))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT revision FROM alicloud_resources WHERE id=$1")
            .bind(resource)
            .fetch_one(&pool)
            .await?,
        3
    );
    let overview: Value = panel
        .admin(Method::GET, "/api/plugins/alicloud", &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(overview["power_jobs"][0]["status"], "cancelled");
    assert!(!overview.to_string().contains(SECRET));
    Ok(())
}
