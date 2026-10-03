use super::model::Account;
use crate::plugins::cloud_api::{Failure, aliyun::Aliyun, signing};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct BillRow {
    pub instance_id: String,
    pub region: String,
    pub product_type: String,
    pub billing_item: String,
    pub usage: String,
    pub unit: String,
    pub amount: String,
    pub currency: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Bill {
    pub month: String,
    pub queried_at: i64,
    pub rows: Vec<BillRow>,
    // None means the complete response cannot be used for automatic control.
    pub usage_micro_gb: Option<u64>,
}

pub(super) fn month(now: i64) -> String {
    signing::iso_time(now.saturating_add(8 * 3600))[..7].into()
}

fn field(value: &Value, key: &str) -> Result<String, Failure> {
    match &value[key] {
        Value::String(v) if v.len() <= 256 && !v.chars().any(char::is_control) => Ok(v.clone()),
        Value::Number(v) => Ok(v.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err("invalid_response".into()),
    }
}

// Decimal parsing avoids floating point rounding crossing a control threshold.
fn micro_gb(value: &str) -> Option<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|v| v.is_ascii_digit())
        || !fraction.bytes().all(|v| v.is_ascii_digit())
        || fraction.len() > 12
    {
        return None;
    }
    let whole: u64 = whole.parse().ok()?;
    let digits = &fraction[..fraction.len().min(6)];
    let tail = if digits.is_empty() {
        0
    } else {
        digits.parse::<u64>().ok()?
    };
    whole
        .checked_mul(1_000_000)?
        .checked_add(tail.checked_mul(10_u64.pow(6 - digits.len() as u32))?)
}

pub(super) async fn query(client: &Aliyun, account: &Account, now: i64) -> Result<Bill, Failure> {
    let cycle = month(now);
    let mut rows = Vec::new();
    let mut total_count = None;
    let mut total = Some(0_u64);
    let mut identities = BTreeSet::new();
    for page in 1..=10 {
        let result = client
            .call(
                &account.access_key_id,
                &account.access_key_secret,
                "QueryInstanceBill",
                &[
                    (
                        "RegionId",
                        if account.site == "international" {
                            "ap-southeast-1"
                        } else {
                            "cn-hangzhou"
                        }
                        .into(),
                    ),
                    ("BillingCycle", cycle.clone()),
                    ("ProductCode", "cdt".into()),
                    ("IsBillingItem", "true".into()),
                    ("Granularity", "MONTHLY".into()),
                    ("IsHideZeroCharge", "false".into()),
                    ("PageNum", page.to_string()),
                    ("PageSize", "100".into()),
                ],
            )
            .await?;
        let data = &result["Data"];
        if data["BillingCycle"] != cycle || data["PageNum"] != page {
            return Err("billing_incomplete".into());
        }
        let count = data["TotalCount"]
            .as_u64()
            .ok_or(Failure::from("billing_incomplete"))?;
        if count > 1000 || total_count.is_some_and(|v| v != count) {
            return Err("billing_incomplete".into());
        }
        total_count = Some(count);
        let entries = data["Items"]["Item"]
            .as_array()
            .ok_or(Failure::from("billing_incomplete"))?;
        if entries.len() > 100 || (entries.is_empty() && count > rows.len() as u64) {
            return Err("billing_incomplete".into());
        }
        for entry in entries {
            if entry["ProductCode"] != "cdt" {
                return Err("billing_incomplete".into());
            }
            let row = BillRow {
                instance_id: field(entry, "InstanceID")?,
                region: field(entry, "Region")?,
                product_type: field(entry, "ProductType")?,
                billing_item: field(entry, "BillingItem")?,
                usage: field(entry, "Usage")?,
                unit: field(entry, "UsageUnit")?,
                amount: field(entry, "PretaxAmount")?,
                currency: field(entry, "Currency")?,
            };
            // Repeated rows indicate unstable pagination rather than extra consumption.
            // Monthly rows are aggregates of these billing dimensions. A changed
            // nickname, amount or usage on a repeated page is not another charge.
            let key = serde_json::to_string(&(
                &row.instance_id,
                &row.region,
                &row.product_type,
                &row.billing_item,
                field(entry, "Item")?,
                &row.currency,
                field(entry, "OwnerID")?,
                field(entry, "SubscriptionType")?,
            ))
            .map_err(|_| Failure::from("invalid_response"))?;
            if !identities.insert(key) {
                return Err("billing_incomplete".into());
            }
            total = total.and_then(|sum| {
                (row.unit == "GB"
                    && entry["Item"] == "PayAsYouGoBill"
                    && !row.instance_id.is_empty())
                .then_some(())
                .and_then(|_| micro_gb(&row.usage))
                .and_then(|v| sum.checked_add(v))
            });
            rows.push(row);
        }
        if rows.len() as u64 == count {
            return Ok(Bill {
                month: cycle,
                queried_at: now,
                usage_micro_gb: if rows.is_empty() { None } else { total },
                rows,
            });
        }
        if rows.len() as u64 > count {
            return Err("billing_incomplete".into());
        }
    }
    Err("billing_incomplete".into())
}

pub(super) fn exceeded(account: &Account, now: i64) -> bool {
    account.enabled
        && account.auto_enabled
        && account.error_code.is_none()
        && account.bill.as_ref().is_some_and(|bill| {
            bill.month == month(now)
                && bill.queried_at <= now
                && bill.queried_at + 900 >= now
                && bill
                    .usage_micro_gb
                    .is_some_and(|value| value >= account.limit_gb as u64 * 1_000_000)
        })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Traffic {
    pub queried_at: i64,
    pub mainland_bytes: String,
    pub overseas_bytes: String,
    pub regions: Vec<TrafficRegion>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct TrafficRegion {
    pub region: String,
    pub bytes: String,
}

pub(super) fn traffic(result: &Value, now: i64) -> Result<Traffic, Failure> {
    let entries = result
        .get("TrafficDetails")
        .or_else(|| result["Data"].get("TrafficDetails"))
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or(Failure::from("invalid_response"))?;
    // A nested compatibility response must prove the same complete snapshot.
    // Metadata at either level can advertise additional pages; never discard it.
    for metadata in [result, &result["Data"]] {
        if metadata
            .get("NextToken")
            .is_some_and(|v| !v.is_null() && v != "")
            || metadata
                .get("TotalCount")
                .is_some_and(|v| v.as_u64() != Some(entries.len() as u64))
        {
            return Err("invalid_response".into());
        }
    }
    let mut seen = BTreeSet::new();
    let (mut mainland, mut overseas) = (0_u64, 0_u64);
    let mut regions = Vec::new();
    for item in entries {
        let region = field(item, "BusinessRegionId")?;
        if !super::model::identifier(&region, "") || !seen.insert(region.clone()) {
            return Err("invalid_response".into());
        }
        let bytes = item["Traffic"]
            .as_u64()
            .or_else(|| item["Traffic"].as_str().and_then(|v| v.parse::<u64>().ok()))
            .ok_or(Failure::from("invalid_response"))?;
        let sum = if region.starts_with("cn-") && region != "cn-hongkong" {
            &mut mainland
        } else {
            &mut overseas
        };
        *sum = sum
            .checked_add(bytes)
            .ok_or(Failure::from("invalid_response"))?;
        regions.push(TrafficRegion {
            region,
            bytes: bytes.to_string(),
        });
    }
    regions.sort_by(|a, b| a.region.cmp(&b.region));
    Ok(Traffic {
        queried_at: now,
        mainland_bytes: mainland.to_string(),
        overseas_bytes: overseas.to_string(),
        regions,
    })
}
