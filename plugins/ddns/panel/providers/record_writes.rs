use super::{
    Failure, Provider, id,
    records::{RecordClient, canonical, relative},
};
use crate::plugins::ddns::dns_records::Request;
use reqwest::Method;
use serde_json::{Value, json};

pub(super) async fn write(
    client: &RecordClient,
    request: &Request,
    zone_name: &str,
) -> Result<Value, Failure> {
    let record_id = request.record_id.as_deref().unwrap_or_default();
    let delete = request.operation == "delete";
    let create = request.operation == "create";
    let record = &request.record;
    let written_id = match client.provider {
        Provider::Cloudflare => {
            let path = format!("zones/{}/dns_records", request.zone_id);
            let result = client
                .cf(
                    if delete {
                        Method::DELETE
                    } else if create {
                        Method::POST
                    } else {
                        Method::PATCH
                    },
                    &if create {
                        path
                    } else {
                        format!("{path}/{record_id}")
                    },
                    &[],
                    if delete { None } else { Some(record.clone()) },
                )
                .await?;
            let written_id = id(&result["result"]["id"])?;
            if delete {
                if written_id != record_id {
                    return Err("invalid_response".into());
                }
                return Ok(Value::Null);
            }
            return canonical(&result["result"], client.provider, zone_name);
        }
        Provider::Aliyun => {
            let mut params = if delete {
                vec![("RecordId", record_id.into())]
            } else {
                let mut params = vec![
                    (
                        "RR",
                        relative(
                            record["name"]
                                .as_str()
                                .ok_or(Failure::from("invalid_configuration"))?,
                            zone_name,
                        )?,
                    ),
                    ("Type", record["type"].as_str().unwrap_or_default().into()),
                    (
                        "Value",
                        record["content"].as_str().unwrap_or_default().into(),
                    ),
                    ("TTL", record["ttl"].to_string()),
                    ("Line", record["line"].as_str().unwrap_or("default").into()),
                ];
                if record["type"] == "MX" {
                    params.push(("Priority", record["priority"].to_string()));
                }
                params
            };
            if !delete {
                params.push(if create {
                    ("DomainName", request.zone_id.clone())
                } else {
                    ("RecordId", record_id.into())
                });
            }
            let result = client
                .ali(
                    if delete {
                        "DeleteDomainRecord"
                    } else if create {
                        "AddDomainRecord"
                    } else {
                        "UpdateDomainRecord"
                    },
                    &params,
                )
                .await?;
            let written_id = id(&result["RecordId"])?;
            if !create && written_id != record_id {
                return Err("invalid_response".into());
            }
            if delete {
                return Ok(Value::Null);
            }
            if let Some(comment) = record["comment"].as_str() {
                client
                    .ali(
                        "UpdateDomainRecordRemark",
                        &[("RecordId", written_id.clone()), ("Remark", comment.into())],
                    )
                    .await?;
            }
            written_id
        }
        Provider::Tencent => {
            let mut body = if delete {
                json!({"Domain":request.zone_id,"RecordId":record_id.parse::<u64>().map_err(|_|Failure::from("invalid_configuration"))?})
            } else {
                let mut body = json!({"Domain":request.zone_id,"SubDomain":relative(record["name"].as_str().ok_or(Failure::from("invalid_configuration"))?,zone_name)?,"RecordType":record["type"],"RecordLine":"默认","RecordLineId":record["line"],"Value":record["content"],"TTL":record["ttl"]});
                if record["type"] == "MX" {
                    body["MX"] = record["priority"].clone();
                }
                body
            };
            if !delete && !create {
                body["RecordId"] = record_id
                    .parse::<u64>()
                    .map_err(|_| Failure::from("invalid_configuration"))?
                    .into();
            }
            let result = client
                .tc(
                    if delete {
                        "DeleteRecord"
                    } else if create {
                        "CreateRecord"
                    } else {
                        "ModifyRecord"
                    },
                    body,
                )
                .await?;
            if delete {
                return Ok(Value::Null);
            }
            let written_id = id(&result["RecordId"])?;
            if !create && written_id != record_id {
                return Err("invalid_response".into());
            }
            if let Some(comment) = record["comment"].as_str() {
                client.tc("ModifyRecordRemark",json!({"Domain":request.zone_id,"RecordId":written_id.parse::<u64>().map_err(|_|Failure::from("invalid_response"))?,"Remark":comment})).await?;
            }
            written_id
        }
        Provider::Huawei => {
            let path = format!("v2/zones/{}/recordsets", request.zone_id);
            let body = if delete {
                None
            } else {
                let values = if let Some(values) = record["data"]["records"].as_array() {
                    values.clone()
                } else if record["type"] == "MX" {
                    vec![
                        format!(
                            "{} {}",
                            record["priority"],
                            record["content"].as_str().unwrap_or_default()
                        )
                        .into(),
                    ]
                } else {
                    vec![record["content"].clone()]
                };
                let mut body = json!({"name":format!("{}.",record["name"].as_str().unwrap_or_default()),"type":record["type"],"ttl":record["ttl"],"records":values});
                if let Some(comment) = record.get("comment") {
                    body["description"] = comment.clone();
                }
                Some(body)
            };
            let result = client
                .hw(
                    if delete {
                        Method::DELETE
                    } else if create {
                        Method::POST
                    } else {
                        Method::PUT
                    },
                    &if create {
                        path
                    } else {
                        format!("{path}/{record_id}")
                    },
                    &[],
                    body,
                )
                .await?;
            if delete {
                if id(&result["id"])? != record_id {
                    return Err("invalid_response".into());
                }
                if result["status"] == "PENDING_DELETE" {
                    return Ok(json!({"id":record_id,"provider_state":"pending_delete"}));
                }
                return Err("provider_pending".into());
            }
            if result["zone_id"]
                .as_str()
                .is_some_and(|id| id != request.zone_id)
            {
                return Err("zone_mismatch".into());
            }
            let written = canonical(&result, client.provider, zone_name)?;
            if !create && written["id"] != record_id {
                return Err("invalid_response".into());
            }
            return Ok(written);
        }
    };
    client.get(&request.zone_id, &written_id, zone_name).await
}
