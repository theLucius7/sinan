use super::*;

#[sqlx::test]
async fn unresolved_cloud_receipts_block_credential_identity_changes_but_allow_disable(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let account = Uuid::new_v4();
    let bandwidth_resource = Uuid::new_v4();
    let power_resource = Uuid::new_v4();
    let bandwidth = Uuid::new_v4();
    let power = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret) VALUES($1,'测试账号',$2,$3)")
        .bind(account).bind(KEY).bind(SECRET).execute(&pool).await?;
    for (id, cloud_id) in [
        (bandwidth_resource, "i-bandwidth-testonly"),
        (power_resource, "i-power-testonly"),
    ] {
        sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id) VALUES($1,$2,'测试实例','ecs','cn-hangzhou',$3)")
            .bind(id).bind(account).bind(cloud_id).execute(&pool).await?;
    }
    let snapshot = json!({"kind":"ecs","cloud_id":"i-bandwidth-testonly","region":"cn-hangzhou","public_ip":"192.0.2.1","bandwidth_mbps":10,"charge_type":"PayByTraffic","resource_charge_type":"PostPaid","status":"Running"});
    sqlx::query("INSERT INTO alicloud_operations(id,resource_id,account_revision,resource_revision,before_state,target,source,status,created_at,expires_at,updated_at) VALUES($1,$2,1,1,$3,$4,'manual','uncertain',$5,$6,$5)")
        .bind(bandwidth).bind(bandwidth_resource).bind(snapshot).bind(json!({"bandwidth_mbps":1,"charge_type":"PayByTraffic"})).bind(now).bind(now+300).execute(&pool).await?;
    let state = json!({"cloud_id":"i-power-testonly","region":"cn-hangzhou","status":"Running","stopped_mode":"KeepCharging","charge_type":"PostPaid","network_type":"vpc","spot_strategy":"NoSpot","interruption_behavior":null,"public_ips":["192.0.2.2"],"locked":false});
    sqlx::query("INSERT INTO alicloud_power_jobs(id,resource_id,account_revision,resource_revision,action,stop_mode,source,before_state,status,created_at,expires_at,updated_at) VALUES($1,$2,1,1,'stop','KeepCharging','manual',$3,'running',$4,$5,$4)")
        .bind(power).bind(power_resource).bind(state).bind(now).bind(now+300).execute(&pool).await?;
    let path = format!("/api/plugins/alicloud/accounts/{account}");
    let body = json!({"name":"测试账号","site":"china","enabled":true,"auto_enabled":false,"limit_gb":100,"revision":1,"access_key_id":"","access_key_secret":"","legacy_credentials":true});
    let mut rotate = body.clone();
    rotate["access_key_id"] = "TEST_ONLY_NEW_KEY".into();
    rotate["access_key_secret"] = "TEST_ONLY_NEW_SECRET".into();
    let mut move_site = body.clone();
    move_site["site"] = "international".into();
    for edit in [rotate.clone(), move_site] {
        assert_eq!(
            panel
                .admin(Method::PATCH, &path, &cookie, Some(edit))
                .await?
                .status(),
            StatusCode::CONFLICT
        );
    }
    let stored: (String, String, String, i64) = sqlx::query_as(
        "SELECT site,access_key_id,access_key_secret,revision FROM alicloud_accounts WHERE id=$1",
    )
    .bind(account)
    .fetch_one(&pool)
    .await?;
    assert_eq!(stored, ("china".into(), KEY.into(), SECRET.into(), 1));
    let mut disable = body;
    disable["enabled"] = false.into();
    disable["name"] = "暂停核对账号".into();
    assert_eq!(
        panel
            .admin(Method::PATCH, &path, &cookie, Some(disable))
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/plugins/alicloud/operations/{bandwidth}/dismiss"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    rotate["revision"] = 2.into();
    rotate["enabled"] = false.into();
    assert_eq!(
        panel
            .admin(Method::PATCH, &path, &cookie, Some(rotate.clone()))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let stored: (String, String, bool, i64) = sqlx::query_as("SELECT access_key_id,access_key_secret,enabled,revision FROM alicloud_accounts WHERE id=$1")
        .bind(account).fetch_one(&pool).await?;
    assert_eq!(stored, (KEY.into(), SECRET.into(), false, 2));
    sqlx::query("UPDATE alicloud_power_jobs SET status='uncertain' WHERE id=$1")
        .bind(power)
        .execute(&pool)
        .await?;
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/plugins/alicloud/power-jobs/{power}/dismiss"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        panel
            .admin(Method::PATCH, &path, &cookie, Some(rotate))
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let stored: (String, String, i64) = sqlx::query_as(
        "SELECT access_key_id,access_key_secret,revision FROM alicloud_accounts WHERE id=$1",
    )
    .bind(account)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        stored,
        ("TEST_ONLY_NEW_KEY".into(), "TEST_ONLY_NEW_SECRET".into(), 3)
    );
    let overview: Value = panel
        .admin(Method::GET, "/api/plugins/alicloud", &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(!overview.to_string().contains("TEST_ONLY_NEW_KEY"));
    assert!(!overview.to_string().contains("TEST_ONLY_NEW_SECRET"));
    Ok(())
}

#[sqlx::test]
async fn supplied_delete_revisions_reject_stale_resource_and_account_views(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let account = Uuid::new_v4();
    let resource = Uuid::new_v4();
    sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret,revision) VALUES($1,'测试账号',$2,$3,2)")
        .bind(account).bind(KEY).bind(SECRET).execute(&pool).await?;
    sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id,revision) VALUES($1,$2,'测试实例','ecs','cn-hangzhou','i-testonly',2)")
        .bind(resource).bind(account).execute(&pool).await?;
    for (path, table, id) in [
        (
            format!("/api/plugins/alicloud/resources/{resource}"),
            "alicloud_resources",
            resource,
        ),
        (
            format!("/api/plugins/alicloud/accounts/{account}"),
            "alicloud_accounts",
            account,
        ),
    ] {
        assert_eq!(
            panel
                .admin(Method::DELETE, &path, &cookie, Some(json!({"revision":1})))
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        let archived: bool =
            sqlx::query_scalar(&format!("SELECT archived FROM {table} WHERE id=$1"))
                .bind(id)
                .fetch_one(&pool)
                .await?;
        assert!(!archived);
        assert_eq!(
            panel
                .admin(Method::DELETE, &path, &cookie, Some(json!({"revision":2})))
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    Ok(())
}
