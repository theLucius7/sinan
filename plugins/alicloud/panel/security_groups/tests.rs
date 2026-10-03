use super::*;
use crate::auth::{hash_token, random_token};
use crate::plugins::cloud_api::test_support::{Mock, Reply};

const BASE: &str = "sg-base";
const EXTRA: &str = "sg-extra";
struct Fixture {
    state: AppState,
    headers: HeaderMap,
    resource: Uuid,
    account: Uuid,
    server: i64,
    directory: std::path::PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Fixture {
    async fn new(pool: PgPool) -> anyhow::Result<Self> {
        let directory =
            std::env::temp_dir().join(format!("sinan-security-groups-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let state = AppState::new(
            pool.clone(),
            crate::config::Config {
                database_url: String::new(),
                listen: "127.0.0.1:0".parse()?,
                public_url: "http://127.0.0.1:1".into(),
                data_dir: directory.clone(),
                admin_password: Some("TEST_ONLY security group fixture".into()),
            },
        )
        .await?;
        let account = Uuid::new_v4();
        let resource = Uuid::new_v4();
        sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret) VALUES($1,'TEST_ONLY','TEST_ONLY_CLOUD_ID','TEST_ONLY_CLOUD_SECRET')").bind(account).execute(&pool).await?;
        sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id) VALUES($1,$2,'TEST_ONLY ECS','ecs','cn-hangzhou','i-testonly')").bind(resource).bind(account).execute(&pool).await?;
        let server: i64 =
            sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY linked') RETURNING id")
                .fetch_one(&pool)
                .await?;
        sqlx::query("INSERT INTO operations_cloud_links(resource_id,server_id,purchase_reference,notes,updated_at,updated_by) VALUES($1,$2,'','',1,1)").bind(resource).bind(server).execute(&pool).await?;
        let token = random_token();
        let hash = hash_token(&token);
        let now = now_timestamp();
        sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,1,$2)")
            .bind(&hash)
            .bind(now + 3600)
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3)").bind(&hash).bind(now).bind(now+300).execute(&pool).await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("sinan_session={token}").parse()?,
        );
        Ok(Self {
            state,
            headers,
            resource,
            account,
            server,
            directory,
        })
    }
    async fn preview(&self, mock: &Mock, target: Vec<String>) -> ApiResult<Operation> {
        preview_with(
            &self.state,
            &self.headers,
            self.resource,
            Preview {
                target_groups: target,
                resource_revision: 1,
            },
            &Cloud::local(&mock.endpoint),
        )
        .await
    }
    async fn confirm(&self, mock: &Mock, preview: &Operation) -> ApiResult<Operation> {
        execution::confirm(
            &self.state,
            &self.headers,
            preview.id,
            Confirm {
                confirm: true,
                snapshot_digest: preview.snapshot_digest.clone(),
            },
            &Cloud::local(&mock.endpoint),
        )
        .await
    }
}
fn instance(ids: &[&str]) -> Reply {
    Reply::ok(
        "DescribeInstances",
        json!({"RequestId":"fixture-read","TotalCount":1,"Instances":{"Instance":[{"InstanceId":"i-testonly","RegionId":"cn-hangzhou","VpcAttributes":{"VpcId":"vpc-testonly"},"SecurityGroupIds":{"SecurityGroupId":ids}}]}}),
    )
}
fn attribute(id: &str) -> Reply {
    Reply::ok(
        "DescribeSecurityGroupAttribute",
        json!({"RequestId":"fixture-rule","SecurityGroupId":id,"VpcId":"vpc-testonly","SecurityGroupType":"normal","InnerAccessPolicy":"Accept","Permissions":{"Permission":[{"Direction":"egress","Policy":"Accept","IpProtocol":"all","PortRange":"-1/-1","DestCidrIp":"0.0.0.0/0","Priority":"1"}]}}),
    )
}
fn read(ids: &[&str], extra: bool) -> Vec<Reply> {
    let mut replies = vec![instance(ids), attribute(BASE)];
    if extra {
        replies.push(attribute(EXTRA));
    }
    replies
}
fn baseline() -> Snapshot {
    Snapshot {
        resource_id: Uuid::nil(),
        account_id: Uuid::nil(),
        account_revision: 1,
        resource_revision: 1,
        instance_id: "i-testonly".into(),
        region: "cn-hangzhou".into(),
        vpc_id: "vpc-testonly".into(),
        server_ids: vec![],
        link_updated_at: None,
        current_groups: vec![BASE.into()],
        managed_groups: vec![],
        protected_groups: vec![BASE.into()],
        groups: vec![Group {
            id: EXTRA.into(),
            vpc_id: "vpc-testonly".into(),
            kind: "normal".into(),
            inner_access_policy: "Accept".into(),
            permissions: json!([{"Policy":"Accept"}]),
        }],
    }
}
#[test]
fn baseline_is_protected_and_explicit_deny_or_unsupported_groups_are_rejected() {
    assert!(groups(vec![]).is_err());
    assert!(groups(vec![BASE.into(), BASE.into()]).is_err());
    assert!(groups(vec!["sg-$(id)".into()]).is_err());
    let before = baseline();
    assert!(impact(&before, &[EXTRA.into()]).is_err());
    assert!(impact(&before, &[BASE.into(), EXTRA.into()]).is_ok());
    let mut denied = before.clone();
    denied.groups[0].permissions = json!([{"Policy":"Drop"}]);
    assert!(impact(&denied, &[BASE.into(), EXTRA.into()]).is_err());
    denied.groups[0].permissions = json!([{"Policy":"Accept"}]);
    denied.groups[0].kind = "enterprise".into();
    assert!(impact(&denied, &[BASE.into(), EXTRA.into()]).is_err());
}
#[sqlx::test]
async fn official_join_is_verified_once_and_confirmation_cannot_replay(
    pool: PgPool,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(pool).await?;
    let mut replies = read(&[BASE], true);
    replies.extend(read(&[BASE], true));
    replies.extend([
        instance(&[BASE]),
        attribute(EXTRA),
        Reply::ok("JoinSecurityGroup", json!({"RequestId":"fixture-join"})),
        instance(&[BASE, EXTRA]),
    ]);
    let mock = Mock::start(replies).await;
    let preview = fixture
        .preview(&mock, vec![BASE.into(), EXTRA.into()])
        .await?;
    assert_eq!(preview.before.server_ids, vec![fixture.server]);
    assert_eq!(preview.impact["fee"]["status"], "unknown");
    let result = fixture.confirm(&mock, &preview).await?;
    assert_eq!(result.status, "succeeded");
    assert_eq!(result.steps[0]["state"], "verified");
    assert_eq!(fixture.confirm(&mock, &preview).await?.status, "succeeded");
    let writes: Vec<_> = mock
        .requests()
        .into_iter()
        .filter(|request| request.action == "JoinSecurityGroup")
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].params["InstanceId"], "i-testonly");
    assert_eq!(writes[0].params["SecurityGroupId"], EXTRA);
    assert_eq!(writes[0].params["RegionId"], "cn-hangzhou");
    let owned: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_managed_security_groups")
        .fetch_one(&fixture.state.pool)
        .await?;
    assert_eq!(owned, 1);
    mock.exhausted();
    Ok(())
}
#[sqlx::test]
async fn uncertain_join_is_not_repeated_and_read_only_reconciliation_preserves_unknown(
    pool: PgPool,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(pool).await?;
    let mut replies = read(&[BASE], true);
    replies.extend(read(&[BASE], true));
    let mut error = Reply::ok("JoinSecurityGroup", json!({"Code":"ServiceUnavailable"}));
    error.status = 503;
    replies.extend([
        instance(&[BASE]),
        attribute(EXTRA),
        error,
        instance(&[BASE]),
    ]);
    let mock = Mock::start(replies).await;
    let preview = fixture
        .preview(&mock, vec![BASE.into(), EXTRA.into()])
        .await?;
    assert_eq!(fixture.confirm(&mock, &preview).await?.status, "unknown");
    assert_eq!(fixture.confirm(&mock, &preview).await?.status, "unknown");
    let reconciled=execution::reconcile(&fixture.state,&fixture.headers,preview.id,Reconcile{process_stopped:true,evidence:"TEST_ONLY local fixture proves handler finished; official membership read separately".into()},&Cloud::local(&mock.endpoint)).await?;
    assert_eq!(reconciled.status, "reconciled");
    assert_eq!(reconciled.original_result.as_deref(), Some("unknown"));
    assert_eq!(
        reconciled.reconciliation.as_ref().unwrap()["target_matches"],
        false
    );
    assert_eq!(
        mock.requests()
            .iter()
            .filter(|request| request.action == "JoinSecurityGroup")
            .count(),
        1
    );
    mock.exhausted();
    Ok(())
}
#[sqlx::test]
async fn leaving_a_verified_owned_extra_keeps_every_baseline_group(
    pool: PgPool,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(pool).await?;
    let cloud_group = Group {
        id: EXTRA.into(),
        vpc_id: "vpc-testonly".into(),
        kind: "normal".into(),
        inner_access_policy: "Accept".into(),
        permissions: attribute(EXTRA).value["Permissions"]["Permission"].clone(),
    };
    let prior = Uuid::new_v4();
    let before = baseline();
    sqlx::query("INSERT INTO alicloud_security_group_operations(id,resource_id,requested_by,before_state,target_groups,impact,snapshot_digest,status,created_at,expires_at,updated_at) VALUES($1,$2,1,$3,$4,'{}','fixture','succeeded',1,2,1)")
        .bind(prior).bind(fixture.resource).bind(DbJson(before)).bind(vec![BASE,EXTRA]).execute(&fixture.state.pool).await?;
    sqlx::query("INSERT INTO alicloud_managed_security_groups(resource_id,group_id,group_digest,operation_id,confirmed_at) VALUES($1,$2,$3,$4,1)")
        .bind(fixture.resource).bind(EXTRA).bind(digest(&cloud_group)?).bind(prior).execute(&fixture.state.pool).await?;
    let mut replies = read(&[BASE, EXTRA], true);
    replies.extend(read(&[BASE, EXTRA], true));
    replies.extend([
        instance(&[BASE, EXTRA]),
        attribute(EXTRA),
        Reply::ok("LeaveSecurityGroup", json!({"RequestId":"fixture-leave"})),
        instance(&[BASE]),
    ]);
    let mock = Mock::start(replies).await;
    let preview = fixture.preview(&mock, vec![BASE.into()]).await?;
    assert_eq!(preview.before.protected_groups, vec![BASE]);
    assert_eq!(preview.before.managed_groups, vec![EXTRA]);
    let result = fixture.confirm(&mock, &preview).await?;
    assert_eq!(result.status, "succeeded");
    assert_eq!(result.actual_groups, Some(vec![BASE.into()]));
    let requests = mock.requests();
    let writes: Vec<_> = requests
        .iter()
        .filter(|request| request.action == "LeaveSecurityGroup")
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].params["SecurityGroupId"], EXTRA);
    let owned: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_managed_security_groups")
        .fetch_one(&fixture.state.pool)
        .await?;
    assert_eq!(owned, 0);
    mock.exhausted();
    Ok(())
}
#[sqlx::test]
async fn fresh_membership_change_stale_account_and_changed_link_refuse_confirmation(
    pool: PgPool,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(pool).await?;
    let mut replies = read(&[BASE], true);
    replies.extend(read(&[BASE, EXTRA], true));
    let mock = Mock::start(replies).await;
    let preview = fixture
        .preview(&mock, vec![BASE.into(), EXTRA.into()])
        .await?;
    assert!(fixture.confirm(&mock, &preview).await.is_err());
    assert_eq!(
        load(&fixture.state.pool, preview.id).await?.status,
        "preview"
    );
    sqlx::query("UPDATE alicloud_accounts SET revision=revision+1 WHERE id=$1")
        .bind(fixture.account)
        .execute(&fixture.state.pool)
        .await?;
    assert!(fixture.confirm(&mock, &preview).await.is_err());
    sqlx::query("UPDATE alicloud_accounts SET revision=1 WHERE id=$1")
        .bind(fixture.account)
        .execute(&fixture.state.pool)
        .await?;
    sqlx::query("UPDATE operations_cloud_links SET updated_at=2 WHERE resource_id=$1")
        .bind(fixture.resource)
        .execute(&fixture.state.pool)
        .await?;
    assert!(fixture.confirm(&mock, &preview).await.is_err());
    assert!(!mock.requests().iter().any(|request| matches!(
        request.action.as_str(),
        "JoinSecurityGroup" | "LeaveSecurityGroup"
    )));
    mock.exhausted();
    Ok(())
}
#[sqlx::test]
async fn queued_cloud_operations_are_blocked_by_unknown_membership_mutations(
    pool: PgPool,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(pool).await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO alicloud_security_group_operations(id,resource_id,requested_by,before_state,target_groups,impact,snapshot_digest,status,created_at,expires_at,updated_at) VALUES($1,$2,1,$3,$4,'{}','fixture','unknown',1,2,1)")
        .bind(id).bind(fixture.resource).bind(DbJson(baseline())).bind(vec![BASE]).execute(&fixture.state.pool).await?;
    let mut tx = lock(&fixture.state.pool, fixture.account).await?;
    assert!(
        super::super::operations::idle(&mut tx, fixture.resource)
            .await
            .is_err()
    );
    Ok(())
}
#[sqlx::test]
async fn global_account_scope_creator_and_token_restrictions_are_enforced_before_remote_reads(
    pool: PgPool,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(pool).await?;
    let actor:i64=sqlx::query_scalar("INSERT INTO admins(password_hash) SELECT password_hash FROM admins WHERE id=1 RETURNING id").fetch_one(&fixture.state.pool).await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,capabilities,created_at,updated_at) VALUES($1,$2,'TEST_ONLY scoped','operator',false,$3,0,0)")
        .bind(actor).bind(format!("sg-scoped-{actor}")).bind(json!(["cloud:read","cloud:write"])).execute(&fixture.state.pool).await?;
    sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
        .bind(actor)
        .bind(fixture.server)
        .execute(&fixture.state.pool)
        .await?;
    let session = random_token();
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
        .bind(hash_token(&session))
        .bind(actor)
        .bind(now_timestamp() + 3600)
        .execute(&fixture.state.pool)
        .await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        format!("sinan_session={session}").parse()?,
    );
    assert!(matches!(
        permission(&fixture.state, &headers, fixture.resource, &[], false).await,
        Err(ApiError::Forbidden(_))
    ));
    for all_servers in [false, true] {
        let token = format!("sinan_api_{}", random_token());
        sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,1,$2,'TEST_ONLY SG',$3,$4,$5,$6,0)")
            .bind(Uuid::new_v4()).bind(hash_token(&token)).bind(json!(["cloud:read","cloud:write"])).bind(json!([fixture.server])).bind(all_servers).bind(now_timestamp()+3600).execute(&fixture.state.pool).await?;
        let mut token_headers = HeaderMap::new();
        token_headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse()?,
        );
        assert!(matches!(
            permission(&fixture.state, &token_headers, fixture.resource, &[], true).await,
            Err(ApiError::Forbidden(_))
        ));
        if !all_servers {
            assert!(matches!(
                permission(&fixture.state, &token_headers, fixture.resource, &[], false).await,
                Err(ApiError::Forbidden(_))
            ));
        }
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO alicloud_security_group_operations(id,resource_id,requested_by,before_state,target_groups,impact,snapshot_digest,status,created_at,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,'{}','fixture','preview',1,$6,1)")
        .bind(id).bind(fixture.resource).bind(actor).bind(DbJson(baseline())).bind(vec![BASE,EXTRA]).bind(now_timestamp()+300).execute(&fixture.state.pool).await?;
    let mock = Mock::start(vec![]).await;
    let operation = load(&fixture.state.pool, id).await?;
    assert!(matches!(
        fixture.confirm(&mock, &operation).await,
        Err(ApiError::Forbidden(_))
    ));
    assert!(mock.requests().is_empty());
    mock.exhausted();
    // A broken authorization lookup remains a database failure, never an empty
    // inventory or a fabricated permission success.
    sqlx::query("ALTER TABLE operations_cloud_links RENAME TO fixture_unavailable_cloud_links")
        .execute(&fixture.state.pool)
        .await?;
    assert!(matches!(
        permission(
            &fixture.state,
            &fixture.headers,
            fixture.resource,
            &[],
            false
        )
        .await,
        Err(ApiError::Database(_))
    ));
    Ok(())
}
#[sqlx::test]
async fn group_policy_changed_after_confirmation_snapshot_blocks_join_and_leave(
    pool: PgPool,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(pool).await?;
    let mut changed = attribute(EXTRA);
    changed.value["Permissions"]["Permission"][0]["Policy"] = json!("Drop");
    let mut replies = read(&[BASE], true);
    replies.extend(read(&[BASE], true));
    replies.extend([
        instance(&[BASE]),
        Reply::ok(&changed.action, changed.value.clone()),
    ]);
    let mock = Mock::start(replies).await;
    let preview = fixture
        .preview(&mock, vec![BASE.into(), EXTRA.into()])
        .await?;
    let result = fixture.confirm(&mock, &preview).await?;
    assert_eq!(result.status, "failed");
    assert_eq!(result.steps[0]["state"], "not_submitted");
    assert!(!mock.requests().iter().any(|request| matches!(
        request.action.as_str(),
        "JoinSecurityGroup" | "LeaveSecurityGroup"
    )));
    mock.exhausted();
    let prior = Uuid::new_v4();
    let cloud_group = Group {
        id: EXTRA.into(),
        vpc_id: "vpc-testonly".into(),
        kind: "normal".into(),
        inner_access_policy: "Accept".into(),
        permissions: attribute(EXTRA).value["Permissions"]["Permission"].clone(),
    };
    sqlx::query("INSERT INTO alicloud_security_group_operations(id,resource_id,requested_by,before_state,target_groups,impact,snapshot_digest,status,created_at,expires_at,updated_at) VALUES($1,$2,1,$3,$4,'{}','fixture','succeeded',1,2,1)")
        .bind(prior).bind(fixture.resource).bind(DbJson(baseline())).bind(vec![BASE,EXTRA]).execute(&fixture.state.pool).await?;
    sqlx::query("INSERT INTO alicloud_managed_security_groups(resource_id,group_id,group_digest,operation_id,confirmed_at) VALUES($1,$2,$3,$4,1)")
        .bind(fixture.resource).bind(EXTRA).bind(digest(&cloud_group)?).bind(prior).execute(&fixture.state.pool).await?;
    let mut replies = read(&[BASE, EXTRA], true);
    replies.extend(read(&[BASE, EXTRA], true));
    replies.extend([instance(&[BASE, EXTRA]), changed]);
    let mock = Mock::start(replies).await;
    let preview = fixture.preview(&mock, vec![BASE.into()]).await?;
    let result = fixture.confirm(&mock, &preview).await?;
    assert_eq!(result.status, "failed");
    assert_eq!(result.steps[0]["state"], "not_submitted");
    assert!(!mock.requests().iter().any(|request| matches!(
        request.action.as_str(),
        "JoinSecurityGroup" | "LeaveSecurityGroup"
    )));
    mock.exhausted();
    Ok(())
}
