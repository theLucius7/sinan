use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) fn kind(value: &str) -> Option<u16> {
    Some(match value {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "SVCB" => 64,
        "HTTPS" => 65,
        "CAA" => 257,
        _ => return None,
    })
}
fn label(kind: u16) -> String {
    [
        "A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA", "SRV", "SVCB", "HTTPS", "CAA",
    ]
    .into_iter()
    .find(|value| self::kind(value) == Some(kind))
    .map_or_else(|| format!("TYPE{kind}"), str::to_owned)
}

pub(super) fn request(id: u16, name: &str, kind: u16) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend(id.to_be_bytes());
    bytes.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        bytes.push(label.len() as u8);
        bytes.extend(label.bytes());
    }
    bytes.push(0);
    bytes.extend(kind.to_be_bytes());
    bytes.extend([0, 1]);
    (bytes.len() <= 512).then_some(bytes)
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, &'static str> {
    Ok(u16::from_be_bytes(
        bytes
            .get(at..at + 2)
            .ok_or("invalid_dns_response")?
            .try_into()
            .map_err(|_| "invalid_dns_response")?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, &'static str> {
    Ok(u32::from_be_bytes(
        bytes
            .get(at..at + 4)
            .ok_or("invalid_dns_response")?
            .try_into()
            .map_err(|_| "invalid_dns_response")?,
    ))
}

fn name(bytes: &[u8], at: &mut usize) -> Result<String, &'static str> {
    let mut position = *at;
    let mut resume = None;
    let mut visited = BTreeSet::new();
    let mut labels = Vec::new();
    for _ in 0..128 {
        if !visited.insert(position) {
            return Err("invalid_dns_response");
        }
        let size = *bytes.get(position).ok_or("invalid_dns_response")?;
        position += 1;
        if size & 0xc0 == 0xc0 {
            let second = *bytes.get(position).ok_or("invalid_dns_response")?;
            position += 1;
            if resume.is_none() {
                resume = Some(position);
            }
            position = ((usize::from(size) & 0x3f) << 8) | usize::from(second);
            continue;
        }
        if size & 0xc0 != 0 {
            return Err("invalid_dns_response");
        }
        if size == 0 {
            *at = resume.unwrap_or(position);
            let value = labels.join(".");
            return (value.len() <= 253)
                .then_some(value)
                .ok_or("invalid_dns_response");
        }
        let label = bytes
            .get(position..position + usize::from(size))
            .ok_or("invalid_dns_response")?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-*".contains(byte))
        {
            return Err("invalid_dns_response");
        }
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| "invalid_dns_response")?
                .to_ascii_lowercase(),
        );
        position += usize::from(size);
    }
    Err("invalid_dns_response")
}

fn value(bytes: &[u8], at: usize, length: usize, kind: u16) -> Result<String, &'static str> {
    let data = bytes.get(at..at + length).ok_or("invalid_dns_response")?;
    let mut position = at;
    Ok(match kind {
        1 if length == 4 => std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        28 if length == 16 => std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(data).map_err(|_| "invalid_dns_response")?,
        )
        .to_string(),
        1 | 28 => return Err("invalid_dns_response"),
        2 | 5 | 12 => {
            let result = name(bytes, &mut position)?;
            if position > at + length {
                return Err("invalid_dns_response");
            }
            result
        }
        15 if length >= 3 => {
            let preference = u16_at(bytes, at)?;
            position += 2;
            {
                let host = name(bytes, &mut position)?;
                if position > at + length {
                    return Err("invalid_dns_response");
                }
                format!("{preference} {host}")
            }
        }
        33 if length >= 7 => {
            let priority = u16_at(bytes, at)?;
            let weight = u16_at(bytes, at + 2)?;
            let port = u16_at(bytes, at + 4)?;
            position += 6;
            {
                let host = name(bytes, &mut position)?;
                if position > at + length {
                    return Err("invalid_dns_response");
                }
                format!("{priority} {weight} {port} {host}")
            }
        }
        16 => {
            let mut result = String::new();
            let mut offset = 0;
            while offset < data.len() {
                let size = usize::from(data[offset]);
                offset += 1;
                let part = data
                    .get(offset..offset + size)
                    .ok_or("invalid_dns_response")?;
                result.push_str(std::str::from_utf8(part).map_err(|_| "dns_non_utf8_text")?);
                offset += size;
            }
            result
        }
        _ => data.iter().map(|byte| format!("{byte:02x}")).collect(),
    })
}

pub(super) fn response(
    bytes: &[u8],
    id: u16,
    owner: &str,
    kind: u16,
) -> Result<Value, &'static str> {
    if bytes.len() < 12
        || u16_at(bytes, 0)? != id
        || bytes[2] & 0x80 == 0
        || bytes[2] & 0x78 != 0
        || bytes[2] & 2 != 0
        || u16_at(bytes, 4)? != 1
    {
        return Err("invalid_dns_response");
    }
    let answers = usize::from(u16_at(bytes, 6)?);
    let total = answers + usize::from(u16_at(bytes, 8)?) + usize::from(u16_at(bytes, 10)?);
    if total > 256 {
        return Err("resolver_response_too_large");
    }
    let mut position = 12;
    if name(bytes, &mut position)? != owner.to_ascii_lowercase()
        || u16_at(bytes, position)? != kind
        || u16_at(bytes, position + 2)? != 1
    {
        return Err("invalid_dns_response");
    }
    position += 4;
    let mut records = Vec::new();
    for index in 0..total {
        let owner = name(bytes, &mut position)?;
        let kind = u16_at(bytes, position)?;
        let class = u16_at(bytes, position + 2)?;
        let ttl = u32_at(bytes, position + 4)?;
        let length = usize::from(u16_at(bytes, position + 8)?);
        position += 10;
        if position + length > bytes.len() {
            return Err("invalid_dns_response");
        }
        if index < answers && class == 1 {
            records.push(json!({"name":owner,"kind":label(kind),"value":value(bytes,position,length,kind)?,"ttl":ttl}));
        }
        position += length;
    }
    let rcode = bytes[3] & 0x0f;
    Ok(
        json!({"status":if rcode==0{if records.is_empty(){"no_data"}else{"answered"}}else if rcode==3{"nxdomain"}else{"resolver_error"},"rcode":rcode,"answers":records,"authenticated_data":bytes[3]&0x20!=0,"error_code":null}),
    )
}

#[cfg(test)]
#[path = "tests/dns_wire.rs"]
mod tests;
