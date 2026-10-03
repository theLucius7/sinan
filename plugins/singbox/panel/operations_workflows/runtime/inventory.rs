use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::HeaderMap};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(crate) async fn inventory(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_capability(&state, &headers, "proxy:read").await?;
    Ok(Json(signed_inventory(&state).await?))
}

pub(super) fn compatibility(version: &str) -> (bool, &'static str) {
    if version == "1.14.2" {
        (
            true,
            "固定编译器模型、签名制品清单和有序链路门禁采用此版本；仍需目标平台制品与实际设备确认",
        )
    } else {
        (
            false,
            "当前有序链路运行时依赖及部署事实受数据库 1.14.2 不变式约束，探测计划、清单和原生验收也绑定 1.14.2；仅有官方签名制品不证明协议与计量兼容，不能部署此版本",
        )
    }
}

pub(super) async fn signed_inventory(state: &AppState) -> ApiResult<Value> {
    // The shared release inventory verifies signed metadata and every stored
    // payload. A directory name or a remotely announced version is not stock.
    let entries = crate::releases::entries(state).await?;
    let mut versions: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for entry in entries.into_iter().filter(|entry| entry.name == "sing-box") {
        versions.entry(entry.version).or_default().push(json!({"platform":entry.arch,"sha256":entry.sha256,"bytes":entry.bytes.to_string(),"signature_verified":true,"payload_verified":true}));
    }
    Ok(
        json!({"source":"本地已导入的签名发布及真实制品","versions":versions.into_iter().map(|(version,artifacts)|{ let (compatible,reason)=compatibility(&version);json!({"version":version,"compatible":compatible,"reason":reason,"upstream_release":format!("https://github.com/SagerNet/sing-box/releases/tag/v{version}"),"artifacts":artifacts}) }).collect::<Vec<_>>(),"remote_versions_fetched":false,"compatibility_model":"固定 1.14.2 协议、路径与计量门禁"}),
    )
}

pub(super) async fn require_version(state: &AppState, version: &str) -> ApiResult<()> {
    let (compatible, reason) = compatibility(version);
    if !compatible {
        return Err(ApiError::BadRequest(reason.into()));
    }
    let inventory = signed_inventory(state).await?;
    if !inventory["versions"].as_array().is_some_and(|versions| {
        versions
            .iter()
            .any(|candidate| candidate["version"] == version && candidate["compatible"] == true)
    }) {
        return Err(ApiError::Conflict(
            "所选版本不在已验签且载荷完整的实际运行时库存中；请先导入可信发布制品".into(),
        ));
    }
    Ok(())
}
