use crate::error::ApiResult;
use sqlx::{ConnectOptions, postgres::PgConnectOptions};
use tokio::process::Command;

fn invalid() -> crate::error::ApiError {
    super::failure("数据库备份连接参数或凭据编码无效")
}

fn decode(value: &str) -> ApiResult<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = if bytes[index] == b'%' {
            let high = bytes.get(index + 1).and_then(|v| (*v as char).to_digit(16));
            let low = bytes.get(index + 2).and_then(|v| (*v as char).to_digit(16));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(invalid());
            };
            index += 3;
            ((high << 4) | low) as u8
        } else {
            let byte = bytes[index];
            index += 1;
            byte
        };
        if byte == 0 {
            return Err(invalid());
        }
        output.push(byte);
    }
    String::from_utf8(output).map_err(|_| invalid())
}

// Use the running pool's effective settings: SQLx has already applied URI
// aliases, query form decoding, repeated options and environment/pgpass defaults.
// libpq expands an explicit dbname conninfo before environment defaults; a
// PGDATABASE environment value containing a URI does not do that expansion.
pub(super) fn configure(command: &mut Command, options: &PgConnectOptions) -> ApiResult<()> {
    let database = options.get_database().unwrap_or(options.get_username());
    let host = match options.get_socket() {
        Some(socket) => socket.to_str().ok_or_else(invalid)?,
        None => options.get_host(),
    };
    let host = if options.get_socket().is_none() {
        host.strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .filter(|value| value.parse::<std::net::Ipv6Addr>().is_ok())
            .unwrap_or(host)
    } else {
        host
    };
    let mut environment = vec![
        ("PGHOST", host.to_owned()),
        ("PGPORT", options.get_port().to_string()),
        ("PGUSER", options.get_username().to_owned()),
        ("PGDATABASE", database.to_owned()),
    ];
    // SQLx exposes no password or certificate-path getter. Only extract those
    // fields from a serialization clone with safe placeholder identity fields;
    // never replace real host/user/db, options or application name with its URL.
    let serialized = options
        .clone()
        .host("localhost")
        .username("backup_serialization")
        .database("backup_serialization")
        .to_url_lossy();
    // URL serialization normalizes an empty password to absence; libpq also
    // treats both as no supplied password. Disable its independent pgpass lookup
    // so it cannot pick a credential different from the running pool's value.
    environment.push((
        "PGPASSWORD",
        serialized
            .password()
            .map(decode)
            .transpose()?
            .unwrap_or_default(),
    ));
    environment.push(("PGPASSFILE", "/dev/null".into()));
    for (key, value) in serialized.query_pairs() {
        let name = match key.as_ref() {
            "sslmode" => Some("PGSSLMODE"),
            "sslrootcert" => Some("PGSSLROOTCERT"),
            "sslcert" => Some("PGSSLCERT"),
            "sslkey" => Some("PGSSLKEY"),
            // This changes SQLx client caching, not the database connection.
            "statement-cache-capacity" => None,
            _ => return Err(invalid()),
        };
        if let Some(name) = name {
            let value = if name == "PGSSLMODE" {
                value.into_owned()
            } else {
                // CertificateInput::Display prefixes file paths. Inline PEM
                // needs a separate private-file lifecycle and is not forwarded.
                value
                    .strip_prefix("file: ")
                    .ok_or_else(|| {
                        super::failure("完整备份不支持内联TLS材料，请配置受保护的证书文件路径")
                    })?
                    .to_owned()
            };
            environment.push((name, value));
        }
    }
    if let Some(value) = options.get_options() {
        environment.push(("PGOPTIONS", value.to_owned()));
    }
    if let Some(value) = options.get_application_name() {
        environment.push(("PGAPPNAME", value.to_owned()));
    }
    if environment.iter().any(|(_, value)| value.contains('\0')) {
        return Err(invalid());
    }
    let database = database.replace('\\', "\\\\").replace('\'', "\\'");
    command
        .env_clear()
        .envs(environment)
        .arg("--dbname")
        .arg(format!("dbname='{database}'"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, str::FromStr};

    fn connection(value: &str) -> Command {
        let options = PgConnectOptions::from_str(value).expect("valid controlled pool fixture");
        let mut command = Command::new("/usr/local/bin/pg_dump");
        configure(&mut command, &options).expect("valid controlled dump fixture");
        command
    }

    fn environment<'a>(command: &'a Command, name: &str) -> Option<&'a OsStr> {
        command
            .as_std()
            .get_envs()
            .find_map(|(key, value)| (key == name).then_some(value).flatten())
    }

    #[test]
    fn credentials_stay_out_of_argv_and_percent_and_plus_preserve_identity() {
        let command = connection(
            "postgres://TEST%2BUSER:TEST%25PASS%3A+@db.example:5439/panel?sslmode=verify-full&sslrootcert=%2Fetc%2Fca.pem",
        );
        let args: Vec<_> = command.as_std().get_args().collect();
        assert_eq!(args, [OsStr::new("--dbname"), OsStr::new("dbname='panel'")]);
        assert_eq!(
            environment(&command, "PGHOST"),
            Some(OsStr::new("db.example"))
        );
        assert_eq!(environment(&command, "PGPORT"), Some(OsStr::new("5439")));
        assert_eq!(
            environment(&command, "PGUSER"),
            Some(OsStr::new("TEST+USER"))
        );
        assert_eq!(
            environment(&command, "PGPASSWORD"),
            Some(OsStr::new("TEST%PASS:+"))
        );
        assert_eq!(
            environment(&command, "PGSSLMODE"),
            Some(OsStr::new("verify-full"))
        );
        assert_eq!(
            environment(&command, "PGSSLROOTCERT"),
            Some(OsStr::new("/etc/ca.pem"))
        );
    }

    #[test]
    fn query_password_last_value_and_form_plus_match_the_running_pool() {
        let command = connection(
            "postgres://u:first@db.example/panel?password=SECOND&p%61ssword=FINAL+%2B%26%3D",
        );
        assert_eq!(
            command.as_std().get_args().last(),
            Some(OsStr::new("dbname='panel'"))
        );
        assert_eq!(
            environment(&command, "PGPASSWORD"),
            Some(OsStr::new("FINAL +&="))
        );
    }

    #[test]
    fn sqlx_tls_aliases_client_cache_and_accumulated_options_keep_effective_values() {
        let command = connection(
            "postgres://u:p@db.example/panel?ssl-mode=require&ssl-ca=%2Fetc%2Froot+ca.pem&ssl-cert=%2Fetc%2Fclient.pem&ssl-key=%2Fetc%2Fclient.key&statement-cache-capacity=0&application_name=panel+backup&options=-c+search_path%3Dtest&options[statement_timeout]=1000&options=-c+timezone%3DUTC",
        );
        assert_eq!(
            environment(&command, "PGSSLMODE"),
            Some(OsStr::new("require"))
        );
        assert_eq!(
            environment(&command, "PGSSLROOTCERT"),
            Some(OsStr::new("/etc/root ca.pem"))
        );
        assert_eq!(
            environment(&command, "PGSSLCERT"),
            Some(OsStr::new("/etc/client.pem"))
        );
        assert_eq!(
            environment(&command, "PGSSLKEY"),
            Some(OsStr::new("/etc/client.key"))
        );
        assert_eq!(
            environment(&command, "PGAPPNAME"),
            Some(OsStr::new("panel backup"))
        );
        assert_eq!(
            environment(&command, "PGOPTIONS"),
            Some(OsStr::new(
                "-c search_path=test -c statement_timeout=1000 -c timezone=UTC"
            ))
        );
        assert_eq!(command.as_std().get_args().count(), 2);
    }

    #[test]
    fn socket_empty_password_and_quoted_database_use_actual_pool_settings() {
        let options = PgConnectOptions::new()
            .host("unused.example")
            .socket("/run/postgresql")
            .port(5439)
            .username("user/with@symbols")
            .password("")
            .database("db'with\\symbols");
        let mut command = Command::new("/usr/local/bin/pg_dump");
        command.env("UNRELATED_INHERITED_SECRET", "TEST_ONLY");
        configure(&mut command, &options).expect("controlled socket identity");
        assert_eq!(
            environment(&command, "PGHOST"),
            Some(OsStr::new("/run/postgresql"))
        );
        assert_eq!(
            environment(&command, "PGUSER"),
            Some(OsStr::new("user/with@symbols"))
        );
        assert_eq!(
            environment(&command, "PGDATABASE"),
            Some(OsStr::new("db'with\\symbols"))
        );
        assert_eq!(environment(&command, "PGPASSWORD"), Some(OsStr::new("")));
        assert_eq!(environment(&command, "UNRELATED_INHERITED_SECRET"), None);
        assert_eq!(
            command.as_std().get_args().last(),
            Some(OsStr::new("dbname='db\\'with\\\\symbols'"))
        );
    }

    #[test]
    fn invalid_utf8_nul_and_escape_fail_without_process_arguments() {
        for value in ["%FF", "%00", "bad%Q1", "bad%"] {
            assert!(decode(value).is_err());
        }
        assert_eq!(decode("+%2B%20").expect("encoded identity"), "++ ");
        let options = PgConnectOptions::new().password("TEST\0ONLY");
        let mut command = Command::new("/usr/local/bin/pg_dump");
        assert!(configure(&mut command, &options).is_err());
        assert_eq!(command.as_std().get_args().count(), 0);
    }

    #[test]
    fn ipv6_and_tls_file_metadata_preserve_identity_without_inline_secrets() {
        for host in ["[::1]", "::1"] {
            let options = PgConnectOptions::new()
                .host(host)
                .username("TEST_ONLY")
                .database("panel")
                .ssl_root_cert("file: /literal/root.pem");
            let mut command = Command::new("/usr/local/bin/pg_dump");
            configure(&mut command, &options).expect("controlled IPv6 connection");
            assert_eq!(environment(&command, "PGHOST"), Some(OsStr::new("::1")));
            assert_eq!(
                environment(&command, "PGSSLROOTCERT"),
                Some(OsStr::new("file: /literal/root.pem"))
            );
        }
        let options = PgConnectOptions::new().ssl_client_key_from_pem(
            b"-----BEGIN PRIVATE KEY-----\nTEST_ONLY\n-----END PRIVATE KEY-----",
        );
        let mut command = Command::new("/usr/local/bin/pg_dump");
        let error = configure(&mut command, &options)
            .expect_err("inline key rejected before tool invocation");
        assert!(
            matches!(error, crate::error::ApiError::Conflict(value) if value.contains("内联TLS材料") && !value.contains("TEST_ONLY"))
        );
        assert_eq!(command.as_std().get_args().count(), 0);
    }
}
