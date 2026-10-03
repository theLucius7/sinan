use crate::error::{ApiError, ApiResult};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_compiler::{AcmeChallenge, ProtocolConfig, SsMethod, TlsConfig};

#[derive(Default, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProtocolInput {
    #[default]
    VlessReality,
    Hysteria2 {
        tls: TlsInput,
    },
    Shadowsocks2022 {
        #[serde(default)]
        method: SsMethod,
    },
    Tuic {
        tls: TlsInput,
    },
    Anytls {
        tls: TlsInput,
    },
    Naive {
        tls: TlsInput,
    },
    SnellV6,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TlsInput {
    Manual {
        certificate: Option<String>,
        key: Option<String>,
    },
    Acme {
        email: String,
        challenge: AcmeChallenge,
    },
}

impl ProtocolInput {
    pub fn build(self, previous: Option<&ProtocolConfig>) -> ApiResult<ProtocolConfig> {
        let previous_tls = previous.and_then(ProtocolConfig::tls);
        let config = match self {
            Self::VlessReality => ProtocolConfig::VlessReality,
            Self::Hysteria2 { tls } => ProtocolConfig::Hysteria2 {
                tls: tls.build(previous_tls)?,
            },
            Self::Tuic { tls } => ProtocolConfig::Tuic {
                tls: tls.build(previous_tls)?,
            },
            Self::Anytls { tls } => ProtocolConfig::Anytls {
                tls: tls.build(previous_tls)?,
            },
            Self::Naive { tls } => ProtocolConfig::Naive {
                tls: tls.build(previous_tls)?,
            },
            Self::Shadowsocks2022 { method } => {
                let password = if let Some(ProtocolConfig::Shadowsocks2022 {
                    method: old,
                    password,
                }) = previous
                {
                    if method != *old {
                        return Err(ApiError::BadRequest(
                            "加密方法创建后不可更改，请创建新节点".into(),
                        ));
                    }
                    password.clone()
                } else {
                    credential(method.key_size())
                };
                ProtocolConfig::Shadowsocks2022 { method, password }
            }
            Self::SnellV6 => ProtocolConfig::SnellV6 {
                psk: match previous {
                    Some(ProtocolConfig::SnellV6 { psk }) => psk.clone(),
                    _ => credential(32),
                },
            },
        };
        if previous.is_some_and(|old| old.kind() != config.kind()) {
            return Err(ApiError::BadRequest(
                "协议创建后不可更改，请创建新节点".into(),
            ));
        }
        Ok(config)
    }
}

impl TlsInput {
    fn build(self, previous: Option<&TlsConfig>) -> ApiResult<TlsConfig> {
        Ok(match self {
            Self::Acme { email, challenge } => TlsConfig::Acme { email, challenge },
            Self::Manual { certificate, key } => {
                let (certificate, key) = match (certificate, key, previous) {
                    (None, None, Some(TlsConfig::Manual { certificate, key })) => {
                        (certificate.clone(), key.clone())
                    }
                    (Some(certificate), Some(key), _) => (certificate, key),
                    _ => {
                        return Err(ApiError::BadRequest(
                            "请同时提供 PEM 证书链与私钥；不修改时可同时省略".into(),
                        ));
                    }
                };
                validate_pem(&certificate, &key)?;
                TlsConfig::Manual { certificate, key }
            }
        })
    }
}

pub(super) fn validate_pem(certificate: &str, key: &str) -> ApiResult<()> {
    let invalid = || ApiError::BadRequest("TLS 证书链或私钥无效，或两者不匹配".into());
    if certificate.len() > 65536 || key.len() > 16384 {
        return Err(ApiError::BadRequest(
            "证书链不能超过 64 KiB，私钥不能超过 16 KiB".into(),
        ));
    }
    let chain = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if chain.is_empty() {
        return Err(invalid());
    }
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).map_err(|_| invalid())?;
    rustls::sign::CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider())
        .map_err(|_| invalid())?;
    Ok(())
}

pub(crate) fn credential(size: usize) -> String {
    let mut bytes = vec![0; size];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

/// Configuration returned by management endpoints must never include secrets.
pub(crate) fn view(config: &ProtocolConfig) -> Value {
    let mut result = json!({"type": config.kind()});
    if let ProtocolConfig::Shadowsocks2022 { method, .. } = config {
        result["method"] = json!(method);
    }
    if let Some(tls) = config.tls() {
        result["tls"] = match tls {
            TlsConfig::Manual { .. } => json!({"mode": "manual", "configured": true}),
            TlsConfig::Acme { email, challenge } => {
                json!({"mode": "acme", "email": email, "challenge": challenge})
            }
        };
    }
    result
}
