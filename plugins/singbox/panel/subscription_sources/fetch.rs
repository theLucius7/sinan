//! Ordered-source adapter over the shared subscription fetcher.
//!
//! Keeps this stack's request and outcome types and its stored failure
//! vocabulary (`stage`/`kind`/`message`); the network policy lives in
//! `crate::subscription_fetch`.

use super::models::{MAX_CONTENT_BYTES, SourceFailure};
use crate::subscription_fetch::{self as shared, Failure, FailureKind};
use reqwest::Url;
use std::collections::BTreeMap;

const _: () = assert!(MAX_CONTENT_BYTES == shared::MAX_BODY_BYTES);

// These types deliberately do not implement Debug: paths and headers are secrets.
pub(crate) struct FetchConfig {
    pub url: String,
    pub auth_headers: BTreeMap<String, String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

pub(crate) enum FetchOutcome {
    Modified {
        body: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
    NotModified {
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

fn kind(failure: &Failure) -> &'static str {
    match failure.kind {
        FailureKind::Url => "url",
        FailureKind::PrivateAddress => "private_address",
        FailureKind::AuthHeaders => "auth_headers",
        FailureKind::UserAgent => "user_agent",
        FailureKind::Cache | FailureKind::UnexpectedNotModified => "cache",
        FailureKind::Dns | FailureKind::DnsEmpty => "dns",
        FailureKind::DnsLimit => "dns_limit",
        FailureKind::Timeout => "timeout",
        FailureKind::Tls => "tls",
        FailureKind::Connection | FailureKind::Read | FailureKind::Client => "connection",
        FailureKind::RedirectLimit => "redirect_limit",
        FailureKind::Redirect => "redirect",
        FailureKind::RedirectOrigin => "redirect_origin",
        FailureKind::Http => match failure.http_status {
            Some(403) => "http_403",
            Some(429) => "http_429",
            _ => "http",
        },
        FailureKind::Html => "non_subscription",
        FailureKind::BodyLimit => "body_limit",
        FailureKind::DecompressedLimit => "decompressed_limit",
        FailureKind::UnsupportedEncoding
        | FailureKind::CorruptBody
        | FailureKind::InvalidLength
        | FailureKind::InvalidEncodingHeader => "encoding",
    }
}

fn source_failure(failure: Failure) -> SourceFailure {
    let mut error = SourceFailure::new("fetch", kind(&failure), failure.message);
    error.http_status = failure.http_status;
    error
}

pub(crate) fn validate_auth_headers(
    input: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, SourceFailure> {
    shared::validate_auth_headers(input).map_err(source_failure)
}

pub(crate) fn validate_url(input: &str) -> Result<Url, SourceFailure> {
    shared::validate_url(input).map_err(source_failure)
}

pub(crate) async fn fetch(config: &FetchConfig) -> Result<FetchOutcome, SourceFailure> {
    let request = shared::Request {
        url: &config.url,
        auth_headers: &config.auth_headers,
        etag: config.etag.as_deref(),
        last_modified: config.last_modified.as_deref(),
        user_agent: None,
    };
    Ok(
        match shared::fetch(&request).await.map_err(source_failure)? {
            shared::Outcome::Modified {
                body,
                etag,
                last_modified,
                ..
            } => FetchOutcome::Modified {
                body,
                etag,
                last_modified,
            },
            shared::Outcome::NotModified {
                etag,
                last_modified,
                ..
            } => FetchOutcome::NotModified {
                etag,
                last_modified,
            },
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(kind: FailureKind, http_status: Option<u16>) -> Failure {
        Failure {
            kind,
            message: "固定失败说明",
            http_status,
        }
    }

    #[test]
    fn stored_failure_kinds_stay_in_this_stack_vocabulary() {
        for (failure, expected) in [
            (failure(FailureKind::Url, None), "url"),
            (
                failure(FailureKind::PrivateAddress, None),
                "private_address",
            ),
            (failure(FailureKind::AuthHeaders, None), "auth_headers"),
            (failure(FailureKind::Cache, None), "cache"),
            (failure(FailureKind::UnexpectedNotModified, None), "cache"),
            (failure(FailureKind::Dns, None), "dns"),
            (failure(FailureKind::DnsEmpty, None), "dns"),
            (failure(FailureKind::DnsLimit, None), "dns_limit"),
            (failure(FailureKind::Timeout, None), "timeout"),
            (failure(FailureKind::Tls, None), "tls"),
            (failure(FailureKind::Connection, None), "connection"),
            (failure(FailureKind::Read, None), "connection"),
            (failure(FailureKind::Client, None), "connection"),
            (failure(FailureKind::RedirectLimit, None), "redirect_limit"),
            (failure(FailureKind::Redirect, None), "redirect"),
            (
                failure(FailureKind::RedirectOrigin, None),
                "redirect_origin",
            ),
            (failure(FailureKind::Http, Some(403)), "http_403"),
            (failure(FailureKind::Http, Some(429)), "http_429"),
            (failure(FailureKind::Http, Some(500)), "http"),
            (failure(FailureKind::Html, None), "non_subscription"),
            (failure(FailureKind::BodyLimit, None), "body_limit"),
            (
                failure(FailureKind::DecompressedLimit, None),
                "decompressed_limit",
            ),
            (failure(FailureKind::UnsupportedEncoding, None), "encoding"),
            (failure(FailureKind::CorruptBody, None), "encoding"),
            (failure(FailureKind::InvalidLength, None), "encoding"),
            (
                failure(FailureKind::InvalidEncodingHeader, None),
                "encoding",
            ),
        ] {
            let error = source_failure(failure);
            assert_eq!(error.stage, "fetch");
            assert_eq!(error.kind, expected);
            assert_eq!(error.message, "固定失败说明");
            assert_eq!(error.http_status, failure.http_status);
        }
    }

    #[test]
    fn validation_keeps_the_existing_messages_and_never_echoes_input() {
        let error = validate_url("https://user:secret@download.example.invalid/").unwrap_err();
        assert_eq!(error.kind, "url");
        assert!(!serde_json::to_string(&error).unwrap().contains("secret"));
        let error = validate_url("https://metadata.internal/").unwrap_err();
        assert_eq!(error.kind, "private_address");
        assert_eq!(error.message, "订阅地址不属于允许公网范围");
        let error =
            validate_auth_headers(&BTreeMap::from([("Host".into(), "secret".into())])).unwrap_err();
        assert_eq!(
            (error.kind.as_str(), error.message.as_str()),
            ("auth_headers", "认证头名称或内容不符合要求")
        );
    }
}
