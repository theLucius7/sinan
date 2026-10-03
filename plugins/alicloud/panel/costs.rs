use super::{
    account_on, billing,
    client::Cloud,
    lock,
    model::{Account, Resource},
};
use crate::{
    error::ApiResult,
    plugins::cloud_api::{Failure, aliyun::Aliyun},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, types::Json};
use std::collections::BTreeSet;
use uuid::Uuid;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Balance {
    pub available: String,
    pub currency: String,
    pub queried_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct CostRow {
    pub item: String,
    pub amount: String,
    pub currency: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct InstanceBill {
    pub month: String,
    pub queried_at: i64,
    pub rows: Vec<CostRow>,
}
fn currency(value: &Value) -> Result<String, Failure> {
    value
        .as_str()
        .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase()))
        .map(str::to_owned)
        .ok_or("invalid_response".into())
}
fn amount(value: &Value) -> Result<String, Failure> {
    let raw = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return Err("invalid_response".into()),
    };
    let unsigned = raw.strip_prefix('-').unwrap_or(&raw);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let groups: Vec<_> = whole.split(',').collect();
    if raw.len() > 64
        || whole.is_empty()
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 12
        || groups
            .iter()
            .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
        || (groups.len() > 1 && (groups[0].len() > 3 || groups[1..].iter().any(|s| s.len() != 3)))
    {
        return Err("invalid_response".into());
    }
    Ok(raw.replace(',', ""))
}
impl Cloud {
    fn costs_service(&self, account: &Account) -> &Aliyun {
        if account.site == "international" {
            &self.bss_international
        } else {
            &self.bss
        }
    }
    pub(super) async fn balance(&self, account: &Account, now: i64) -> Result<Balance, Failure> {
        let resolved = self.resolved_account(account).await?;
        let account = &resolved;
        let value = self
            .costs_service(account)
            .call(
                &account.access_key_id,
                &account.access_key_secret,
                "QueryAccountBalance",
                &[],
            )
            .await?;
        Ok(Balance {
            available: amount(&value["Data"]["AvailableAmount"])?,
            currency: currency(&value["Data"]["Currency"])?,
            queried_at: now,
        })
    }
    pub(super) async fn instance_bill(
        &self,
        account: &Account,
        r: &Resource,
        now: i64,
    ) -> Result<InstanceBill, Failure> {
        let resolved = self.resolved_account(account).await?;
        let account = &resolved;
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.instance_bill_pages(account, r, now),
        )
        .await
        .unwrap_or(Err("request_timeout".into()))
    }
    async fn instance_bill_pages(
        &self,
        account: &Account,
        r: &Resource,
        now: i64,
    ) -> Result<InstanceBill, Failure> {
        let month = billing::month(now);
        let mut rows = Vec::new();
        let mut token = String::new();
        let mut tokens = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut total = None;
        for _ in 0..10 {
            let mut params = vec![
                ("BillingCycle", month.clone()),
                ("InstanceID", r.cloud_id.clone()),
                ("Granularity", "MONTHLY".into()),
                ("IsBillingItem", "false".into()),
                ("IsHideZeroCharge", "false".into()),
                ("MaxResults", "100".into()),
            ];
            if !token.is_empty() {
                params.push(("NextToken", token.clone()));
            }
            let value = self
                .costs_service(account)
                .call(
                    &account.access_key_id,
                    &account.access_key_secret,
                    "DescribeInstanceBill",
                    &params,
                )
                .await?;
            let data = &value["Data"];
            if data["BillingCycle"] != month {
                return Err("billing_incomplete".into());
            }
            let count = data["TotalCount"]
                .as_u64()
                .ok_or(Failure::from("billing_incomplete"))?;
            if count > 1000 || total.is_some_and(|v| v != count) {
                return Err("billing_incomplete".into());
            }
            total = Some(count);
            let entries = data["Items"]
                .as_array()
                .ok_or(Failure::from("billing_incomplete"))?;
            if entries.len() > 100 {
                return Err("billing_incomplete".into());
            }
            for row in entries {
                if row["InstanceID"] != r.cloud_id || !seen.insert(row.to_string()) {
                    return Err("billing_incomplete".into());
                }
                let item = row["Item"]
                    .as_str()
                    .filter(|s| {
                        matches!(
                            *s,
                            "SubscriptionOrder" | "PayAsYouGoBill" | "Refund" | "Adjustment"
                        )
                    })
                    .ok_or(Failure::from("invalid_response"))?;
                rows.push(CostRow {
                    item: item.into(),
                    amount: amount(&row["PretaxAmount"])?,
                    currency: currency(&row["Currency"])?,
                });
            }
            token = match &data["NextToken"] {
                Value::Null => String::new(),
                Value::String(s) if s.len() <= 2048 => s.clone(),
                _ => return Err("billing_incomplete".into()),
            };
            if token.is_empty() {
                if rows.len() as u64 != count {
                    return Err("billing_incomplete".into());
                }
                return Ok(InstanceBill {
                    month,
                    queried_at: now,
                    rows,
                });
            }
            if entries.is_empty() || rows.len() as u64 >= count || !tokens.insert(token.clone()) {
                return Err("billing_incomplete".into());
            }
        }
        Err("billing_incomplete".into())
    }
}
pub(super) async fn refresh_balance(
    pool: &PgPool,
    id: Uuid,
    cloud: &Cloud,
    now: i64,
) -> ApiResult<()> {
    let mut tx = lock(pool, id).await?;
    let a = account_on(&mut tx, id).await?;
    if !a.enabled || a.balance_next_at > now {
        return Ok(());
    }
    match cloud.balance(&a, now).await {
        Ok(value) => {
            sqlx::query("UPDATE alicloud_accounts SET balance=$2,balance_error=NULL,balance_next_at=$3 WHERE id=$1").bind(id).bind(Json(value)).bind(now+21600).execute(&mut *tx).await?;
        }
        Err(error) => {
            sqlx::query(
                "UPDATE alicloud_accounts SET balance_error=$2,balance_next_at=$3 WHERE id=$1",
            )
            .bind(id)
            .bind(error.code)
            .bind(now + error.retry_after.max(300))
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
pub(super) async fn refresh_bill(
    pool: &PgPool,
    id: Uuid,
    cloud: &Cloud,
    now: i64,
) -> ApiResult<()> {
    let initial = super::resource(pool, id).await?;
    let mut tx = lock(pool, initial.account_id).await?;
    let a = account_on(&mut tx, initial.account_id).await?;
    let r: Resource =
        sqlx::query_as("SELECT * FROM alicloud_resources WHERE id=$1 AND NOT archived")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let stale_month = r
        .instance_bill
        .as_ref()
        .is_some_and(|b| b.month != billing::month(now));
    if !a.enabled || (r.bill_next_at > now && !(stale_month && r.bill_error.is_none())) {
        return Ok(());
    }
    match cloud.instance_bill(&a, &r, now).await {
        Ok(value) => {
            sqlx::query("UPDATE alicloud_resources SET instance_bill=$2,bill_error=NULL,bill_next_at=$3 WHERE id=$1").bind(id).bind(Json(value)).bind(now+21600).execute(&mut *tx).await?;
        }
        Err(error) => {
            sqlx::query("UPDATE alicloud_resources SET bill_error=$2,bill_next_at=$3 WHERE id=$1")
                .bind(id)
                .bind(error.code)
                .bind(now + error.retry_after.max(300))
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
pub(super) async fn tick(pool: &PgPool, cloud: &Cloud) -> ApiResult<()> {
    let now = sinan_protocol::now_timestamp();
    let accounts:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM alicloud_accounts WHERE enabled AND NOT archived AND balance_next_at<=$1 ORDER BY balance_next_at,id LIMIT 1").bind(now).fetch_all(pool).await?;
    for id in accounts {
        refresh_balance(pool, id, cloud, now).await?;
    }
    let resources:Vec<Uuid>=sqlx::query_scalar("SELECT r.id FROM alicloud_resources r JOIN alicloud_accounts a ON a.id=r.account_id WHERE a.enabled AND NOT a.archived AND NOT r.archived AND (r.bill_next_at<=$1 OR (r.instance_bill->>'month'<>$2 AND r.bill_error IS NULL)) ORDER BY r.bill_next_at,r.id LIMIT 1").bind(now).bind(billing::month(now)).fetch_all(pool).await?;
    for id in resources {
        refresh_bill(pool, id, cloud, now).await?;
    }
    Ok(())
}
