use anyhow::{Context, bail};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub listen: SocketAddr,
    pub public_url: String,
    pub data_dir: PathBuf,
    pub admin_password: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let public_url =
            std::env::var("SINAN_PUBLIC_URL").context("SINAN_PUBLIC_URL is required")?;
        let parsed = validate_public_url(&public_url)?;
        Ok(Self {
            database_url: std::env::var("SINAN_DATABASE_URL")
                .context("SINAN_DATABASE_URL is required")?,
            listen: std::env::var("SINAN_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8080".into())
                .parse()?,
            public_url: parsed,
            data_dir: std::env::var_os("SINAN_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("./data")),
            admin_password: std::env::var("SINAN_ADMIN_PASSWORD").ok(),
        })
    }
}

fn validate_public_url(value: &str) -> anyhow::Result<String> {
    let value = value.trim_end_matches('/');
    let uri: axum::http::Uri = value.parse().context("invalid panel public URL")?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.host().is_none()
        || uri.query().is_some()
        || uri.path() != "/"
        || value.contains(['@', '"', '\\', '#'])
        || value.chars().any(char::is_control)
    {
        bail!("SINAN_PUBLIC_URL must be an HTTP(S) origin without credentials or path");
    }
    let authority = uri.authority().context("missing panel authority")?;
    let host = authority.host();
    let valid_host = if let Some(ip) = host.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        ip.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        !host.is_empty()
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    };
    if !valid_host {
        bail!("invalid panel hostname");
    }
    let suffix = &authority.as_str()[host.len()..];
    let port = if suffix.is_empty() {
        String::new()
    } else {
        let port: u16 = suffix
            .strip_prefix(':')
            .context("invalid port separator")?
            .parse()
            .context("invalid panel port")?;
        if port == 0 {
            bail!("panel port must be nonzero");
        }
        format!(":{port}")
    };
    Ok(format!(
        "{}://{}{port}",
        uri.scheme_str().unwrap_or_default(),
        host.to_ascii_lowercase()
    ))
}

#[cfg(test)]
mod tests {
    use super::validate_public_url;

    #[test]
    fn public_origin_is_normalized_and_unsafe_components_rejected() {
        assert_eq!(
            validate_public_url("HTTPS://EXAMPLE.INVALID/").unwrap(),
            "https://example.invalid"
        );
        assert_eq!(
            validate_public_url("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );
        for input in [
            "https://example.invalid/#ignored",
            "http://example.invalid:invalid",
            "http://example.invalid:70000",
            "http://example.invalid:0",
            "https://user:secret@example.invalid",
            "https://example.invalid/api",
            "https://example.invalid?token=x",
        ] {
            assert!(validate_public_url(input).is_err(), "{input}");
        }
    }
}
