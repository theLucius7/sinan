use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("too many concurrent requests")]
    Busy,
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("resource not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("{message}")]
    ConflictReferences {
        message: String,
        references: serde_json::Value,
    },
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::ConflictReferences {
            message,
            references,
        } = &self
        {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":message,"references":references})),
            )
                .into_response();
        }
        let (status, message) = match &self {
            Self::Busy => (
                StatusCode::TOO_MANY_REQUESTS,
                "请求过于频繁，请稍后再试".into(),
            ),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message.clone()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "请先登录或检查设备凭证".into()),
            Self::NotFound => (StatusCode::NOT_FOUND, "资源不存在".into()),
            Self::Conflict(message) => (StatusCode::CONFLICT, message.clone()),
            _ => {
                tracing::error!(error = %self, "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "服务器内部错误".into())
            }
        };
        (status, Json(json!({"error":message}))).into_response()
    }
}
pub type ApiResult<T> = Result<T, ApiError>;
