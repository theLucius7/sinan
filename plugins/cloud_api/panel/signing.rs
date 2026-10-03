use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{Duration, UNIX_EPOCH},
};

pub fn encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(result, "%{byte:02X}").expect("string write");
        }
    }
    result
}

pub fn query(values: &BTreeMap<String, String>) -> String {
    values
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn huawei_query(url: &reqwest::Url) -> String {
    // Signing must retain every transmitted pair, including repeated names.
    let mut pairs: Vec<_> = url
        .query_pairs()
        .map(|(key, value)| (encode(&key), encode(&value)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn iso_time(timestamp: i64) -> String {
    let date = httpdate::fmt_http_date(
        UNIX_EPOCH + Duration::from_secs(timestamp.clamp(0, 253402300799) as u64),
    );
    let parts: Vec<_> = date.split_whitespace().collect();
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|v| *v == parts[2])
    .expect("HTTP month")
        + 1;
    format!("{}-{month:02}-{}T{}Z", parts[3], parts[1], parts[4])
}

pub fn hash(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

fn mac(key: &[u8], message: &str) -> Vec<u8> {
    let mut signer = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    signer.update(message.as_bytes());
    signer.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn aliyun(secret: &str, parameters: &BTreeMap<String, String>) -> String {
    let text = format!("POST&%2F&{}", encode(&query(parameters)));
    let mut signer =
        Hmac::<Sha1>::new_from_slice(format!("{secret}&").as_bytes()).expect("HMAC key");
    signer.update(text.as_bytes());
    STANDARD.encode(signer.finalize().into_bytes())
}

pub fn tencent(
    id: &str,
    secret: &str,
    host: &str,
    action: &str,
    body: &str,
    timestamp: i64,
) -> String {
    let date = iso_time(timestamp);
    let scope = format!("{}/dnspod/tc3_request", &date[..10]);
    let headers = "content-type;host;x-tc-action";
    let canonical = format!(
        "POST\n/\n\ncontent-type:application/json\nhost:{host}\nx-tc-action:{}\n\n{headers}\n{}",
        action.to_ascii_lowercase(),
        hash(body)
    );
    let text = format!("TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}", hash(canonical));
    let day = mac(format!("TC3{secret}").as_bytes(), &date[..10]);
    let service = mac(&day, "dnspod");
    let signing = mac(&service, "tc3_request");
    format!(
        "TC3-HMAC-SHA256 Credential={id}/{scope}, SignedHeaders={headers}, Signature={}",
        hex(&mac(&signing, &text))
    )
}

pub fn huawei(
    id: &str,
    secret: &str,
    method: &str,
    url: &reqwest::Url,
    body: &str,
    date: &str,
) -> String {
    let path = format!("{}/", url.path().trim_end_matches('/'));
    let headers = "content-type;host;x-sdk-date";
    let canonical = format!(
        "{method}\n{path}\n{}\ncontent-type:application/json\nhost:{}\nx-sdk-date:{date}\n\n{headers}\n{}",
        huawei_query(url),
        url.host_str().expect("fixed host"),
        hash(body)
    );
    let text = format!("SDK-HMAC-SHA256\n{date}\n{}", hash(canonical));
    format!(
        "SDK-HMAC-SHA256 Access={id}, SignedHeaders={headers}, Signature={}",
        hex(&mac(secret.as_bytes(), &text))
    )
}
