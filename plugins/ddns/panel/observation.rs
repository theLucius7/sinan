use super::model::{AddressSource, Config, Provider, Rule};
use crate::error::{ApiError, ApiResult};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use std::{collections::BTreeSet, net::IpAddr};

#[derive(FromRow)]
pub(super) struct Observation {
    pub name: String,
    pub static_info: Value,
    pub static_info_received_at: Option<i64>,
    pub last_seen: Option<i64>,
    pub deleted_at: Option<i64>,
    pub retiring: bool,
    pub plugin_enabled: bool,
}

impl Observation {
    pub fn select(
        &self,
        config: &Config,
        previous: Option<&str>,
        now: i64,
    ) -> Result<IpAddr, &'static str> {
        if !self.plugin_enabled {
            return Err("plugin_disabled");
        }
        if self.deleted_at.is_some() || self.retiring {
            return Err("server_retired");
        }
        if config.address_source == AddressSource::Manual {
            return config
                .manual_ip
                .as_deref()
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                .filter(|ip| ddns_public_ip(*ip) && ip.is_ipv4() == (config.record_type == "A"))
                .ok_or("invalid_configuration");
        }
        if self
            .last_seen
            .is_none_or(|at| at > now + 5 || now.saturating_sub(at) > 60)
        {
            return Err("server_offline");
        }
        if self
            .static_info_received_at
            .is_none_or(|at| at > now + 5 || now.saturating_sub(at) > 600)
        {
            return Err("ip_stale");
        }
        let values = match config.address_source {
            AddressSource::Agent => self.static_info.get("ip_addresses"),
            AddressSource::Interface => config
                .interface_name
                .as_deref()
                .and_then(|name| self.static_info["interface_addresses"].get(name)),
            AddressSource::Discovered => self.static_info.get("discovered_public_ips"),
            AddressSource::Manual => None,
        }
        .and_then(Value::as_array)
        .ok_or(if config.address_source == AddressSource::Agent {
            "no_public_ip"
        } else {
            "source_unavailable"
        })?;
        let candidates: BTreeSet<IpAddr> = values
            .iter()
            .take(256)
            .filter_map(|value| value.as_str()?.parse::<IpAddr>().ok())
            .filter(|ip| ddns_public_ip(*ip) && ip.is_ipv4() == (config.record_type == "A"))
            .collect();
        if let Some(previous) = previous
            .and_then(|ip| ip.parse().ok())
            .filter(|ip| candidates.contains(ip))
        {
            return Ok(previous);
        }
        candidates.into_iter().next().ok_or("no_public_ip")
    }
}

// Ordinary server addresses only; exclude special non-unicast uses even when a
// historical general IP classifier did not include the newer documentation block.
pub(super) fn ddns_public_ip(ip: IpAddr) -> bool {
    if !crate::ip_quality::public_ip(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 192 && b == 88 && c == 99)
        }
        IpAddr::V6(ip) => {
            let [a, b, c, _, _, _, _, _] = ip.segments();
            !(a == 0x2001 && b == 2 && c == 0) && !(a == 0x3fff && b < 0x1000)
        }
    }
}

const OBSERVATION: &str = "SELECT name,static_info,static_info_received_at,last_seen,deleted_at,EXISTS(SELECT 1 FROM server_retirements WHERE server_id=servers.id) AS retiring,EXISTS(SELECT 1 FROM server_plugins WHERE server_id=servers.id AND plugin='ddns' AND enabled) AS plugin_enabled FROM servers WHERE id=$1";

pub(super) async fn observation(pool: &PgPool, server_id: i64) -> ApiResult<Observation> {
    sqlx::query_as(OBSERVATION)
        .bind(server_id)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}

pub(super) async fn locked_observation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    server_id: i64,
) -> ApiResult<Observation> {
    // Acquire the lifecycle lock in its own statement. If retirement commits
    // while this waits, its inserted row must be read using the next statement's
    // fresh READ COMMITTED snapshot, not a snapshot captured before the wait.
    sqlx::query_scalar::<_, i64>("SELECT id FROM servers WHERE id=$1 FOR SHARE")
        .bind(server_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    sqlx::query_as(OBSERVATION)
        .bind(server_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)
}

pub(super) async fn view(pool: &PgPool, rule: Rule) -> ApiResult<Value> {
    let now = sinan_protocol::now_timestamp();
    let info = observation(pool, rule.config.server_id).await?;
    let selected = info.select(&rule.config, rule.last_ip.as_deref(), now);
    let mut value = serde_json::to_value(&rule).map_err(anyhow::Error::from)?;
    let effective_credential = if let Some(id) = rule.config.account_id {
        let account = super::dns_accounts::load(pool, id).await?;
        if account.config.enabled
            && account.config.provider == rule.config.provider
            && account.config.zone_ids.contains(&rule.config.zone_id)
            && (account.config.server_ids.is_empty()
                || account.config.server_ids.contains(&rule.config.server_id))
        {
            Some(account.config.credential_id)
        } else {
            None
        }
    } else {
        rule.config.credential_id
    };
    let credential_configured = if let Some(id) = effective_credential {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM credential_entries WHERE id=$1 AND kind='dns' AND enabled)")
            .bind(id).fetch_one(pool).await?
    } else if rule.config.account_id.is_some() {
        false
    } else if rule.config.provider == Provider::Cloudflare {
        !rule.api_token.is_empty()
    } else {
        !rule.access_key_id.is_empty() && !rule.access_key_secret.is_empty()
    };
    value["token_configured"] = credential_configured.into();
    value["plugin_enabled"] = info.plugin_enabled.into();
    value["busy"] = (rule.lease_until > now).into();
    value["server_name"] = info.name.into();
    value["candidate_ip"] = selected.as_ref().ok().map(ToString::to_string).into();
    value["ip_status"] = selected.err().unwrap_or("ready").into();
    value["ip_received_at"] = if rule.config.address_source == AddressSource::Manual {
        None
    } else {
        info.static_info_received_at
    }
    .into();
    Ok(value)
}
