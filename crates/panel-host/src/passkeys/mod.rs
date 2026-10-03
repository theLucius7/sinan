mod ceremonies;
mod credentials;

pub use ceremonies::{
    Ceremony, FinishAuthentication, FinishRegistration, PendingAuthentication, PendingRegistration,
    consume, start_authentication, start_registration,
};
pub use credentials::{authenticate, insert, list, lock, revoke};

use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

pub(crate) const ADMIN: uuid::Uuid = uuid::Uuid::from_u128(1);
pub(crate) const ADMIN_BINDING: &str = "sinan_admin_passkey";
pub const PORTAL_BINDING: &str = "sinan_proxy_passkey";
pub const TTL: i64 = 300;

pub struct Service {
    engine: Option<Arc<Webauthn>>,
    origin: String,
    reason: Option<String>,
}

impl Service {
    pub fn new(origin: &str) -> Self {
        let build = || -> anyhow::Result<Webauthn> {
            let url = Url::parse(origin)?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host"))?;
            anyhow::ensure!(
                url.domain().is_some()
                    && (url.scheme() == "https" || (url.scheme() == "http" && host == "localhost")),
                "secure DNS origin required"
            );
            Ok(WebauthnBuilder::new(host, &url)?
                .rp_name("司南")
                .allow_subdomains(false)
                .allow_any_port(false)
                .build()?)
        };
        let engine = build().ok().map(Arc::new);
        let reason = engine.is_none().then(|| "Passkey 需要将 SINAN_PUBLIC_URL 设置为 HTTPS 域名；本地调试可使用 http://localhost。".into());
        Self {
            engine,
            origin: Url::parse(origin)
                .map(|url| url.origin().ascii_serialization())
                .unwrap_or_else(|_| origin.to_owned()),
            reason,
        }
    }

    pub(crate) fn engine(&self) -> ApiResult<Arc<Webauthn>> {
        self.engine
            .clone()
            .ok_or_else(|| ApiError::BadRequest(self.reason.clone().unwrap_or_default()))
    }

    pub fn info(&self) -> Value {
        json!({"enabled": self.engine.is_some(), "reason": self.reason, "origin": self.origin})
    }

    pub async fn registration(
        &self,
        credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
        pending: &PendingRegistration,
    ) -> ApiResult<webauthn_rs::prelude::Passkey> {
        let engine = self.engine()?;
        let registration = pending.registration.clone();
        tokio::task::spawn_blocking(move || {
            engine.finish_passkey_registration(&credential, &registration)
        })
        .await
        .map_err(anyhow::Error::from)?
        .map_err(|_| invalid())
    }

    pub async fn authentication(
        &self,
        credential: webauthn_rs::prelude::PublicKeyCredential,
        pending: &PendingAuthentication,
    ) -> ApiResult<webauthn_rs::prelude::AuthenticationResult> {
        let engine = self.engine()?;
        let authentication = pending.authentication.clone();
        tokio::task::spawn_blocking(move || {
            engine.finish_passkey_authentication(&credential, &authentication)
        })
        .await
        .map_err(anyhow::Error::from)?
        .map_err(|_| invalid())
    }

    pub fn check_origin(&self, headers: &HeaderMap) -> ApiResult<()> {
        self.engine()?;
        if headers.get_all(header::ORIGIN).iter().count() != 1
            || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(&self.origin)
        {
            return Err(ApiError::BadRequest(
                "访问地址与面板配置不一致，请使用配置的公开地址打开页面。".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn json_value(value: impl serde::Serialize) -> ApiResult<Value> {
    serde_json::to_value(value).map_err(|e| ApiError::Internal(e.into()))
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(value: Value) -> ApiResult<T> {
    serde_json::from_value(value).map_err(|e| ApiError::Internal(e.into()))
}

pub fn invalid() -> ApiError {
    ApiError::BadRequest("Passkey 验证失败或请求已失效，请重新开始。".into())
}

pub async fn permit(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
    state.passkeys.check_origin(headers)?;
    let permit = state
        .login_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    auth::rate_limit::consume(&state.pool, peer).await?;
    Ok(permit)
}

pub fn cookie<'a>(headers: &'a HeaderMap, wanted: &str) -> Option<&'a str> {
    let mut token = None;
    for header in headers.get_all(header::COOKIE) {
        for item in header.to_str().ok()?.split(';') {
            if let Some((name, value)) = item.trim().split_once('=')
                && name == wanted
            {
                if token.is_some() || value.is_empty() || value.len() > 512 {
                    return None;
                }
                token = Some(value);
            }
        }
    }
    token
}

pub fn set_cookie(
    state: &AppState,
    response: &mut Response,
    name: &str,
    value: &str,
    ttl: i64,
) -> ApiResult<()> {
    let secure = if state.config.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}{secure}"
        ))
        .map_err(|e| ApiError::Internal(e.into()))?,
    );
    Ok(())
}

pub fn reply(value: Value) -> Response {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_origin_is_canonical_and_never_accepts_another_port_or_subdomain() {
        let service = Service::new("https://panel.example.com:443");
        assert!(service.engine().is_ok());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://panel.example.com"),
        );
        assert!(service.check_origin(&headers).is_ok());
        for origin in [
            "https://panel.example.com:8443",
            "https://child.panel.example.com",
            "http://panel.example.com",
            "null",
        ] {
            headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert!(service.check_origin(&headers).is_err());
        }
        for origin in [
            "http://panel.example.com",
            "https://127.0.0.1",
            "https://[::1]",
        ] {
            assert!(Service::new(origin).engine().is_err());
        }
        assert!(Service::new("http://localhost:8080").engine().is_ok());
    }

    #[test]
    fn duplicate_binding_cookies_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static(
                "sinan_session=TEST_ONLY_ADMIN; sinan_proxy_session=TEST_ONLY_PROXY",
            ),
        );
        assert_eq!(
            cookie(&headers, "sinan_proxy_session"),
            Some("TEST_ONLY_PROXY")
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("sinan_proxy_session=TEST_ONLY_SECOND"),
        );
        assert!(cookie(&headers, "sinan_proxy_session").is_none());
    }
}
