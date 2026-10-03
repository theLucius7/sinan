use super::{
    Failure, Provider, id,
    records::{RecordClient, canonical, relative},
};
use reqwest::Method;
use serde_json::{Value, json};

async fn page(
    client: &RecordClient,
    zone: &str,
    zone_name: &str,
    index: u32,
    filter: Option<&str>,
) -> Result<Value, Failure> {
    let offset = (index - 1) * 100;
    let (entries, total) = match client.provider {
        Provider::Cloudflare => {
            let number = index.to_string();
            let mut query = vec![("per_page", "100"), ("page", number.as_str())];
            if let Some(name) = filter {
                query.push(("name.exact", name));
            }
            let result = client
                .cf(
                    Method::GET,
                    &format!("zones/{zone}/dns_records"),
                    &query,
                    None,
                )
                .await?;
            (
                result["result"].clone(),
                result["result_info"]["total_count"].clone(),
            )
        }
        Provider::Aliyun => {
            let mut params = vec![
                ("DomainName", zone.into()),
                ("PageNumber", index.to_string()),
                ("PageSize", "100".into()),
            ];
            if let Some(name) = filter {
                params.push(("SubDomain", name.into()));
            }
            let result = client
                .ali(
                    if filter.is_some() {
                        "DescribeSubDomainRecords"
                    } else {
                        "DescribeDomainRecords"
                    },
                    &params,
                )
                .await?;
            if result["PageNumber"] != index {
                return Err("invalid_response".into());
            }
            (
                result["DomainRecords"]["Record"].clone(),
                result["TotalCount"].clone(),
            )
        }
        Provider::Tencent => {
            let mut body = json!({"Domain":zone,"Limit":100,"Offset":offset,"ErrorOnEmpty":"no"});
            if let Some(name) = filter {
                body["SubDomain"] = relative(name, zone_name)?.into();
            }
            let result = client.tc("DescribeRecordList", body).await?;
            (
                result["RecordList"].clone(),
                result["RecordCountInfo"]["TotalCount"].clone(),
            )
        }
        Provider::Huawei => {
            let mut query = vec![("limit", "100".into()), ("offset", offset.to_string())];
            if let Some(name) = filter {
                query.push(("name", format!("{name}.")));
                query.push(("search_mode", "equal".into()));
            }
            let result = client
                .hw(
                    Method::GET,
                    &format!("v2/zones/{zone}/recordsets"),
                    &query,
                    None,
                )
                .await?;
            (
                result["recordsets"].clone(),
                result["metadata"]["total_count"].clone(),
            )
        }
    };
    let entries = entries
        .as_array()
        .ok_or(Failure::from("invalid_response"))?;
    let total = total.as_u64().ok_or(Failure::from("invalid_response"))?;
    if entries.len() > 100 || total < entries.len() as u64 {
        return Err("invalid_response".into());
    }
    let records = entries
        .iter()
        .map(|entry| {
            if client.provider == Provider::Aliyun
                && entry["DomainName"]
                    .as_str()
                    .is_some_and(|name| name != zone)
            {
                return Err("zone_mismatch".into());
            }
            if client.provider == Provider::Huawei
                && entry["zone_id"].as_str().is_some_and(|id| id != zone)
            {
                return Err("zone_mismatch".into());
            }
            canonical(entry, client.provider, zone_name)
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    if filter.is_some_and(|name| records.iter().any(|record| record["name"] != name)) {
        return Err("invalid_response".into());
    }
    Ok(
        json!({"records":records,"pagination":{"page":index,"total_count":total,"total_pages":total.div_ceil(100).max(1)}}),
    )
}

pub(super) async fn list(
    client: &RecordClient,
    zone: &str,
    zone_name: &str,
    index: u32,
) -> Result<Value, Failure> {
    page(client, zone, zone_name, index, None).await
}

pub(super) async fn find(
    client: &RecordClient,
    zone: &str,
    name: &str,
    zone_name: &str,
) -> Result<Vec<Value>, Failure> {
    let result = page(client, zone, zone_name, 1, Some(name)).await?;
    let records = result["records"]
        .as_array()
        .ok_or(Failure::from("invalid_response"))?;
    if result["pagination"]["total_count"].as_u64() != Some(records.len() as u64)
        || result["pagination"]["total_pages"]
            .as_u64()
            .is_none_or(|pages| pages > 1)
    {
        return Err("record_conflict".into());
    }
    Ok(records.clone())
}

pub(super) async fn get(
    client: &RecordClient,
    zone: &str,
    record_id: &str,
    zone_name: &str,
) -> Result<Value, Failure> {
    let entry=match client.provider{
        Provider::Cloudflare=>client.cf(Method::GET,&format!("zones/{zone}/dns_records/{record_id}"),&[],None).await?["result"].clone(),
        Provider::Aliyun=>{
            let result=client.ali("DescribeDomainRecordInfo",&[("RecordId",record_id.into())]).await?;
            if result["DomainName"]!=zone{return Err("zone_mismatch".into());}result
        }
        Provider::Tencent=>client.tc("DescribeRecord",json!({"Domain":zone,"RecordId":record_id.parse::<u64>().map_err(|_|Failure::from("invalid_configuration"))?})).await?["RecordInfo"].clone(),
        Provider::Huawei=>{
            let result=client.hw(Method::GET,&format!("v2/zones/{zone}/recordsets/{record_id}"),&[],None).await?;
            if result["zone_id"].as_str().is_some_and(|id|id!=zone){return Err("zone_mismatch".into());}result
        }
    };
    if id(&entry[match client.provider {
        Provider::Cloudflare | Provider::Huawei => "id",
        Provider::Aliyun => "RecordId",
        Provider::Tencent => "Id",
    }])? != record_id
    {
        return Err("invalid_response".into());
    }
    if entry["zone_id"].as_str().is_some_and(|id| id != zone) {
        return Err("zone_mismatch".into());
    }
    canonical(&entry, client.provider, zone_name)
}
