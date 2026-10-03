use reqwest::{Client, Response, header::HeaderValue};
use serde_json::{Value, json};
use std::{collections::HashSet, time::Duration};

const ENDPOINT: &str = "https://api.hetzner.cloud/v1/servers";
const PAGE_SIZE: u64 = 50;
const MAX_PAGES: usize = 10;
const MAX_SERVERS: usize = 500;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Default)]
pub(super) struct Inventory {
    pub servers: Vec<RemoteServer>,
    pub complete: bool,
    pub pages: usize,
    pub error_code: Option<String>,
}

#[derive(Debug)]
pub(super) struct RemoteServer {
    pub cloud_id: String,
    pub name: String,
    pub snapshot: Value,
}

pub(super) async fn fetch(token: &str) -> Inventory {
    if authorization(token).is_none() {
        return failed_inventory("credential_invalid");
    }
    let client = match client_builder().https_only(true).build() {
        Ok(client) => client,
        Err(_) => return failed_inventory("network_error"),
    };
    fetch_with_client(&client, ENDPOINT, token).await
}

fn client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
}

fn authorization(token: &str) -> Option<HeaderValue> {
    if !(20..=512).contains(&token.len()) || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
    header.set_sensitive(true);
    Some(header)
}

fn failed_inventory(code: &str) -> Inventory {
    Inventory {
        error_code: Some(code.into()),
        ..Inventory::default()
    }
}

async fn fetch_with_client(client: &Client, endpoint: &str, token: &str) -> Inventory {
    let Some(header) = authorization(token) else {
        return failed_inventory("credential_invalid");
    };
    let mut inventory = Inventory::default();
    match tokio::time::timeout(
        Duration::from_secs(120),
        collect(client, endpoint, &header, &mut inventory),
    )
    .await
    {
        Ok(Ok(())) => inventory.complete = true,
        Ok(Err(code)) => inventory.error_code = Some(code.into()),
        Err(_) => inventory.error_code = Some("network_timeout".into()),
    }
    inventory
}

async fn collect(
    client: &Client,
    endpoint: &str,
    header: &HeaderValue,
    inventory: &mut Inventory,
) -> Result<(), &'static str> {
    let mut ids = HashSet::new();
    let mut expected_total = None;
    for index in 0..MAX_PAGES {
        let page_number = index as u64 + 1;
        let response = client
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, header.clone())
            .query(&[
                ("page", page_number.to_string()),
                ("per_page", PAGE_SIZE.to_string()),
            ])
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Err(if status.as_u16() == 401 {
                "http_401"
            } else if status.as_u16() == 403 {
                "http_403"
            } else if status.as_u16() == 429 {
                "http_429"
            } else if status.is_server_error() {
                "http_5xx"
            } else {
                "http_other"
            });
        }
        let body = bounded_body(response).await?;
        let document: Value = serde_json::from_slice(&body).map_err(|_| "invalid_response")?;
        let raw_servers = document["servers"].as_array().ok_or("invalid_response")?;
        let pagination = pagination(&document, page_number, expected_total, raw_servers.len())?;
        let mut page_ids = HashSet::new();
        let mut servers = Vec::with_capacity(raw_servers.len());
        for raw in raw_servers {
            let server = parse_server(raw)?;
            if ids.contains(&server.cloud_id) || !page_ids.insert(server.cloud_id.clone()) {
                return Err("pagination_inconsistent");
            }
            servers.push(server);
        }
        if inventory.servers.len() + servers.len() > MAX_SERVERS {
            return Err("inventory_limit");
        }
        // Only a completely validated page becomes evidence for the inventory.
        ids.extend(page_ids);
        inventory.servers.extend(servers);
        inventory.pages += 1;
        expected_total = Some(pagination.total);
        if pagination.next.is_none() {
            return if inventory.servers.len() as u64 == pagination.total {
                Ok(())
            } else {
                Err("pagination_inconsistent")
            };
        }
    }
    Err("inventory_limit")
}

fn network_error(error: reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "network_timeout"
    } else {
        "network_error"
    }
}

async fn bounded_body(mut response: Response) -> Result<Vec<u8>, &'static str> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err("invalid_response");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
        if chunk.len() > MAX_BODY_BYTES.saturating_sub(body.len()) {
            return Err("invalid_response");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

struct Pagination {
    total: u64,
    next: Option<u64>,
}

fn pagination(
    document: &Value,
    page: u64,
    expected_total: Option<u64>,
    entries: usize,
) -> Result<Pagination, &'static str> {
    let value = &document["meta"]["pagination"];
    let total = value["total_entries"]
        .as_u64()
        .ok_or("pagination_inconsistent")?;
    let last = total.div_ceil(PAGE_SIZE).max(1);
    let previous = optional_page(
        value
            .get("previous_page")
            .ok_or("pagination_inconsistent")?,
    )?;
    let next = optional_page(value.get("next_page").ok_or("pagination_inconsistent")?)?;
    if value["current_page"].as_u64() != Some(page)
        || value["per_page"].as_u64() != Some(PAGE_SIZE)
        || value["last_page"].as_u64() != Some(last)
        || expected_total.is_some_and(|expected| expected != total)
        || page > last
        || previous != if page == 1 { None } else { Some(page - 1) }
        || next != if page < last { Some(page + 1) } else { None }
    {
        return Err("pagination_inconsistent");
    }
    let expected_entries = total.saturating_sub((page - 1) * PAGE_SIZE).min(PAGE_SIZE);
    if entries as u64 != expected_entries {
        return Err("pagination_inconsistent");
    }
    Ok(Pagination { total, next })
}

fn optional_page(value: &Value) -> Result<Option<u64>, &'static str> {
    if value.is_null() {
        Ok(None)
    } else {
        value
            .as_u64()
            .filter(|page| *page > 0)
            .map(Some)
            .ok_or("pagination_inconsistent")
    }
}

fn parse_server(raw: &Value) -> Result<RemoteServer, &'static str> {
    let cloud_id = positive_id(&raw["id"])?;
    let name = required_text(&raw["name"], 200)?;
    let server_type = &raw["server_type"];
    let datacenter = &raw["datacenter"];
    let location = &datacenter["location"];
    let snapshot = json!({
        "status": required_text(&raw["status"], 512)?,
        "ipv4": optional_text(&raw["public_net"]["ipv4"]["ip"]),
        "ipv6": optional_text(&raw["public_net"]["ipv6"]["ip"]),
        "created_at": optional_text(&raw["created"]),
        "server_type": {
            "id": positive_id(&server_type["id"])?,
            "name": required_text(&server_type["name"], 512)?,
            "cores": server_type["cores"].as_u64(),
            "memory_gb": server_type["memory"].as_f64().filter(|number| *number >= 0.0),
            "disk_gb": server_type["disk"].as_u64(),
            "architecture": optional_text(&server_type["architecture"]),
        },
        "location": {
            "id": location["id"].as_u64().filter(|id| *id > 0),
            "name": optional_text(&location["name"]),
            "country": optional_text(&location["country"]),
            "city": optional_text(&location["city"]),
        },
        "datacenter": {
            "id": positive_id(&datacenter["id"])?,
            "name": required_text(&datacenter["name"], 512)?,
        },
        "traffic": {
            "included_bytes": byte_count(&raw["included_traffic"]),
            "ingoing_bytes": byte_count(&raw["ingoing_traffic"]),
            "outgoing_bytes": byte_count(&raw["outgoing_traffic"]),
        },
        "protection": {
            "delete": raw["protection"]["delete"].as_bool(),
            "rebuild": raw["protection"]["rebuild"].as_bool(),
        },
    });
    Ok(RemoteServer {
        cloud_id: cloud_id.to_string(),
        name,
        snapshot,
    })
}

fn positive_id(value: &Value) -> Result<u64, &'static str> {
    value
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or("invalid_response")
}

fn required_text(value: &Value, limit: usize) -> Result<String, &'static str> {
    value
        .as_str()
        .filter(|text| !text.is_empty())
        .map(|text| text.chars().take(limit).collect())
        .ok_or("invalid_response")
}

fn optional_text(value: &Value) -> Option<String> {
    value.as_str().map(|text| text.chars().take(512).collect())
}

fn byte_count(value: &Value) -> Option<String> {
    value.as_u64().map(|bytes| bytes.to_string())
}

#[cfg(test)]
#[path = "client/tests.rs"]
mod tests;
