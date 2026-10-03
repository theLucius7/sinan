use super::{LoginRequest, require_admin, security, totp, verified_password};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
    passkeys,
};
use axum::http::HeaderMap;
use sinan_protocol::now_timestamp;
use sqlx::{Postgres, Row, Transaction};
use std::net::SocketAddr;

pub struct Proof {
    pub session: String,
    hash: String,
    code: Option<String>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

pub async fn prepare(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    input: LoginRequest,
) -> ApiResult<Proof> {
    require_admin(state, headers).await?;
    let session = security::session_hash(headers)?;
    let permit = passkeys::permit(state, headers, peer).await?;
    let (hash, permit) = verified_password(state, input.password, permit).await?;
    Ok(Proof {
        session,
        hash: hash.ok_or_else(|| ApiError::BadRequest("管理员密码或验证码不正确。".into()))?,
        code: input.totp_code,
        _permit: permit,
    })
}

impl Proof {
    pub async fn lock(&self, tx: &mut Transaction<'_, Postgres>) -> ApiResult<()> {
        let row = security::locked_admin(tx, &self.session).await?;
        if row.try_get::<String, _>("password_hash")? != self.hash {
            return Err(ApiError::Unauthorized);
        }
        if let Some(secret) = row.try_get::<Option<Vec<u8>>, _>("totp_secret")? {
            let step = totp::verify(
                &secret,
                self.code.as_deref().unwrap_or(""),
                now_timestamp(),
                row.try_get("totp_last_step")?,
            )
            .ok_or_else(|| {
                ApiError::BadRequest("管理员密码或验证码不正确、已过期或已使用。".into())
            })?;
            sqlx::query("UPDATE admins SET totp_last_step=$1 WHERE id=1")
                .bind(step)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }
}
