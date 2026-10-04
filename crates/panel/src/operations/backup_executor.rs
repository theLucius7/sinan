use super::model::digest;
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use uuid::Uuid;

mod connection;

fn failure(message: &str) -> ApiError {
    ApiError::Conflict(message.into())
}
fn image(name: &str) -> ApiResult<String> {
    let value = std::env::var(name)
        .map_err(|_| failure("完整备份需要明确配置面板及PostgreSQL固定镜像身份"))?;
    let hash = value.strip_prefix("sha256:").unwrap_or(&value);
    if hash.len() != 64 || !hash.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err(failure("备份镜像身份必须为完整sha256，不能使用浮动标签"));
    }
    Ok(value)
}
fn root(state: &AppState) -> PathBuf {
    std::env::var_os("SINAN_BACKUP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| state.config.data_dir.join("backups"))
}

async fn private_directory(path: &Path) -> ApiResult<()> {
    if let Ok(metadata) = tokio::fs::symlink_metadata(path).await
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        return Err(failure("备份目录不能是链接或普通文件"));
    }
    tokio::fs::create_dir_all(path)
        .await
        .map_err(anyhow::Error::from)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(anyhow::Error::from)?;
    }
    Ok(())
}
fn private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn file_hash(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

async fn checked(command: &mut Command, stage: &'static str) -> ApiResult<()> {
    command
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let mut process = command
        .spawn()
        .map_err(|_| failure("备份所需pg_dump或age工具不可用"))?;
    let status = match tokio::time::timeout(Duration::from_secs(600), process.wait()).await {
        Ok(status) => status.map_err(anyhow::Error::from)?,
        Err(_) => {
            process.kill().await.map_err(anyhow::Error::from)?;
            process.wait().await.map_err(anyhow::Error::from)?;
            return Err(failure("备份工具达到十分钟预算，进程停止已确认"));
        }
    };
    if !status.success() {
        let code = status
            .code()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "signal".into());
        return Err(failure(&format!(
            "备份{stage}工具执行失败（退出码 {code}）；未产生可恢复的完成记录"
        )));
    }
    Ok(())
}

async fn version_output(command: &mut Command, budget: Duration) -> ApiResult<String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut process = command
        .spawn()
        .map_err(|_| failure("备份工具版本检查无法启动"))?;
    let mut stdout = process
        .stdout
        .take()
        .ok_or_else(|| failure("备份工具版本输出不可用"))?;
    let deadline = tokio::time::Instant::now() + budget;
    let mut bytes = Vec::new();
    let read =
        tokio::time::timeout_at(deadline, (&mut stdout).take(4097).read_to_end(&mut bytes)).await;
    drop(stdout);
    let read_valid = matches!(read, Ok(Ok(_))) && bytes.len() <= 4096;
    let status = if read_valid {
        tokio::time::timeout_at(deadline, process.wait())
            .await
            .ok()
            .transpose()
            .map_err(anyhow::Error::from)?
    } else {
        None
    };
    let Some(status) = status else {
        process.kill().await.map_err(anyhow::Error::from)?;
        process.wait().await.map_err(anyhow::Error::from)?;
        return Err(failure("备份工具版本输出超限或检查超时，进程停止已确认"));
    };
    if !status.success() {
        return Err(failure("备份工具版本检查失败"));
    }
    String::from_utf8(bytes).map_err(|_| failure("备份工具版本输出无效"))
}

pub(super) async fn execute(
    state: &AppState,
    id: Uuid,
    schedule: Uuid,
    recipient: &str,
    actor: i64,
    name: &str,
) -> ApiResult<Uuid> {
    let mut serialization = state.pool.begin().await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(530118)")
        .fetch_one(&mut *serialization)
        .await?;
    if !acquired {
        return Err(failure(
            "已有完整备份执行中，本次未执行；请核对既有任务结果",
        ));
    }
    let uncertain: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM operations_panel_steps WHERE state='uncertain')",
    )
    .fetch_one(&mut *serialization)
    .await?;
    if uncertain {
        return Err(failure(
            "已有完整备份的进程或清理结果未确认，本次未执行；请先人工核对",
        ));
    }
    let base = root(state);
    private_directory(&base).await?;
    let stage = base.join(format!("staging-{id}"));
    tokio::fs::create_dir(&stage)
        .await
        .map_err(anyhow::Error::from)?;
    private_directory(&stage).await?;
    let result = execute_in(state, id, schedule, recipient, actor, name, &base, &stage).await;
    // Only this execution owns this exact directory; durable encrypted output
    // is kept separately. Cleanup failure must not claim a safe completed backup.
    if tokio::fs::remove_dir_all(&stage).await.is_err() {
        return Err(failure("备份私有暂存材料未确认清理，请检查此执行目录"));
    }
    serialization.commit().await?;
    result
}

#[allow(clippy::too_many_arguments)]
async fn execute_in(
    state: &AppState,
    id: Uuid,
    schedule: Uuid,
    recipient: &str,
    actor: i64,
    name: &str,
    base: &Path,
    stage: &Path,
) -> ApiResult<Uuid> {
    let panel_image = image("SINAN_BACKUP_PANEL_IMAGE")?;
    let postgres_image = image("SINAN_BACKUP_POSTGRES_IMAGE")?;
    let dump_path = std::env::var_os("SINAN_BACKUP_PG_DUMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/pg_dump"));
    if !dump_path.is_absolute() {
        return Err(failure("pg_dump必须使用明确的绝对工具路径"));
    }
    let mut dump_version = Command::new(&dump_path);
    dump_version.arg("--version").env_clear();
    let client = version_output(&mut dump_version, Duration::from_secs(10)).await?;
    let major = client
        .split_whitespace()
        .find_map(|word| word.split('.').next()?.parse::<i32>().ok())
        .ok_or_else(|| failure("无法确定pg_dump大版本"))?;
    let mut age_version_command = Command::new("/usr/bin/age");
    age_version_command.arg("--version").env_clear();
    let age_version = version_output(&mut age_version_command, Duration::from_secs(10)).await?;
    let artifact_lock =
        tokio::time::timeout(Duration::from_secs(30), state.release_permits.acquire())
            .await
            .map_err(|_| failure("制品正在写入，备份等待超时"))?
            .map_err(|_| failure("制品快照锁不可用"))?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let server_version: i32 =
        sqlx::query_scalar("SELECT current_setting('server_version_num')::integer")
            .fetch_one(&mut *tx)
            .await?;
    if server_version / 10000 != major {
        return Err(failure("pg_dump与数据库服务大版本不一致，拒绝不配套备份"));
    }
    let snapshot: String = sqlx::query_scalar("SELECT pg_export_snapshot()")
        .fetch_one(&mut *tx)
        .await?;
    let migrations:Value=sqlx::query_scalar("SELECT COALESCE(jsonb_agg(jsonb_build_object('version',version,'checksum',encode(checksum,'hex')) ORDER BY version),'[]'::jsonb) FROM _sqlx_migrations WHERE success").fetch_one(&mut *tx).await?;
    let key_ids: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT key_id FROM credential_entries ORDER BY key_id")
            .fetch_all(&mut *tx)
            .await?;
    let key_reference = std::env::var("SINAN_BACKUP_KEYRING_REFERENCE").ok();
    if !key_ids.is_empty() && key_reference.as_ref().is_none_or(|v| v.trim().is_empty()) {
        return Err(failure(
            "数据库含加密凭据，必须记录独立密钥环保管位置后才能完成恢复点",
        ));
    }
    if state.config.database_url.contains(['\n', '\r']) {
        return Err(failure("数据库地址不能写入受限备份环境格式"));
    }
    let environment = format!(
        "SINAN_DATABASE_URL={}\nSINAN_PUBLIC_URL={}\n",
        state.config.database_url, state.config.public_url
    );
    private_file(&stage.join("environment"))
        .and_then(|mut f| f.write_all(environment.as_bytes()))
        .map_err(anyhow::Error::from)?;
    let dump = private_file(&stage.join("database.dump")).map_err(anyhow::Error::from)?;
    let mut command = Command::new(&dump_path);
    command
        .arg("--format=custom")
        .arg("--no-password")
        .arg(format!("--snapshot={snapshot}"))
        .stdout(Stdio::from(dump));
    connection::configure(&mut command, &state.pool.connect_options())?;
    checked(&mut command, "数据库导出 pg_dump").await?;
    let data_root = state.config.data_dir.clone();
    let archive_path = stage.join("panel-data.tar.gz");
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let encoder = GzEncoder::new(private_file(&archive_path)?, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        archive.follow_symlinks(false);
        let artifacts = data_root.join("artifacts/releases");
        if artifacts.exists() {
            reject_links(&artifacts)?;
            archive.append_dir_all("artifacts/releases", artifacts)?;
        }
        let encoder = archive.into_inner()?;
        encoder.finish()?.sync_all()?;
        Ok(())
    })
    .await
    .map_err(anyhow::Error::from)??;
    tx.commit().await?;
    drop(artifact_lock);
    let mut hashes = serde_json::Map::new();
    for filename in ["environment", "database.dump", "panel-data.tar.gz"] {
        let path = stage.join(filename);
        let hash = tokio::task::spawn_blocking(move || file_hash(&path))
            .await
            .map_err(anyhow::Error::from)??;
        hashes.insert(filename.into(), json!(hash));
    }
    let manifest = json!({"format":2,"complete":true,"created_at":crate::plugins::cloud_api::signing::iso_time(now_timestamp()),"project":"native-scheduled-backup","source_revision":option_env!("SINAN_SOURCE_REVISION"),"image":panel_image,"postgres_image":postgres_image,"postgres_version_num":server_version,"pg_dump_version":client.trim(),"age_version":age_version.trim(),"schema_migrations":migrations,"sha256":hashes,"restore_scope":["database","panel_environment","signed_release_artifacts"],"restore_database_authentication":"fresh_isolated_credential","excluded_transient_data":["network-acme-work","backups"],"node_data_included":false,"snapshot_consistency":"pg_export_snapshot + release_permits for immutable signed release storage","keyring_reference":key_reference,"required_key_ids":key_ids,"keyring_included":false,"dependency_manifest_sha256":[]});
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(anyhow::Error::from)?;
    private_file(&stage.join("manifest.json"))
        .and_then(|mut f| f.write_all(&manifest_bytes))
        .map_err(anyhow::Error::from)?;
    let archive_path = stage.join("complete.tar.gz");
    let archive_root = stage.to_path_buf();
    let archive_output = archive_path.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let encoder = GzEncoder::new(private_file(&archive_output)?, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for filename in [
            "environment",
            "database.dump",
            "panel-data.tar.gz",
            "manifest.json",
        ] {
            archive.append_path_with_name(archive_root.join(filename), filename)?;
        }
        archive.into_inner()?.finish()?.sync_all()?;
        Ok(())
    })
    .await
    .map_err(anyhow::Error::from)??;
    let destination = base.join(format!("snapshot-{id}.age"));
    let encrypted = private_file(&destination).map_err(anyhow::Error::from)?;
    let mut age = Command::new("/usr/bin/age");
    age.arg("--encrypt")
        .arg("--recipient")
        .arg(recipient)
        .arg(&archive_path)
        .env_clear()
        .stdout(Stdio::from(encrypted));
    if let Err(error) = checked(&mut age, "加密 age").await {
        tokio::fs::remove_file(&destination)
            .await
            .map_err(anyhow::Error::from)?;
        return Err(error);
    }
    let encrypted_path = destination.clone();
    let storage_hash = tokio::task::spawn_blocking(move || file_hash(&encrypted_path))
        .await
        .map_err(anyhow::Error::from)??;
    let hash = digest(&manifest)?;
    sqlx::query("INSERT INTO operations_backup_records(id,name,manifest,manifest_sha256,location,encrypted,verification,created_at,imported_at,imported_by,storage_sha256,source_schedule) VALUES($1,$2,$3,$4,$5,true,'integrity_verified',$6,$6,$7,$8,$9)").bind(id).bind(name).bind(manifest).bind(hash).bind(destination.to_string_lossy().as_ref()).bind(now_timestamp()).bind(actor).bind(storage_hash).bind(schedule).execute(&state.pool).await?;
    Ok(id)
}

fn reject_links(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("backup storage contains a symbolic link");
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            reject_links(&entry?.path())?;
        }
    } else if !metadata.is_file() {
        anyhow::bail!("backup storage contains a special file");
    }
    Ok(())
}

pub(super) async fn retention(
    state: &AppState,
    schedule: Uuid,
    count: i32,
    days: i32,
) -> ApiResult<()> {
    let base = tokio::fs::canonicalize(root(state))
        .await
        .map_err(anyhow::Error::from)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(530018)")
        .execute(&mut *tx)
        .await?;
    let rows=sqlx::query("SELECT id,location,created_at,retain_until FROM operations_backup_records WHERE source_schedule=$1 AND encrypted AND retired_at IS NULL ORDER BY created_at DESC,id DESC FOR UPDATE").bind(schedule).fetch_all(&mut *tx).await?;
    let mut retired = Vec::new();
    for (index, row) in rows.into_iter().enumerate() {
        let id: Uuid = row.get("id");
        if index < count as usize
            || row.get::<i64, _>("created_at") > now_timestamp() - i64::from(days) * 86400
            || row
                .get::<Option<i64>, _>("retain_until")
                .is_some_and(|v| v > now_timestamp())
        {
            continue;
        }
        let dependent:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_backup_records WHERE $1=ANY(dependency_ids) AND retired_at IS NULL) OR EXISTS(SELECT 1 FROM operations_panel_steps p JOIN operations_jobs j ON j.id=p.job_id WHERE (p.backup_id=$1 OR p.execution_id=$1) AND (j.status IN ('queued','running','paused','cancel_requested','uncertain') OR p.state IN ('running','uncertain')))").bind(id).fetch_one(&mut *tx).await?;
        if dependent {
            continue;
        }
        let path = PathBuf::from(row.get::<String, _>("location"));
        if path.file_name().and_then(|v| v.to_str()) != Some(format!("snapshot-{id}.age").as_str())
            || tokio::fs::canonicalize(&path)
                .await
                .map_err(anyhow::Error::from)?
                .parent()
                != Some(base.as_path())
        {
            continue;
        }
        if tokio::fs::symlink_metadata(&path)
            .await
            .map_err(anyhow::Error::from)?
            .file_type()
            .is_symlink()
        {
            continue;
        }
        sqlx::query("UPDATE operations_backup_records SET retired_at=$2 WHERE id=$1")
            .bind(id)
            .bind(now_timestamp())
            .execute(&mut *tx)
            .await?;
        retired.push(path);
    }
    tx.commit().await?;
    // A retired record cannot gain new restore dependencies. Remove storage
    // only after its durable retirement; database rollback must not lose a file.
    for path in retired {
        if tokio::fs::symlink_metadata(&path)
            .await
            .map_err(anyhow::Error::from)?
            .file_type()
            .is_symlink()
        {
            return Err(failure("保留清理发现存储路径改变，未继续删除"));
        }
        tokio::fs::remove_file(path)
            .await
            .map_err(anyhow::Error::from)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use sqlx::PgPool;

    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn version_checks_bound_output_and_stop_timed_out_processes() -> anyhow::Result<()> {
        let mut valid = Command::new("/bin/sh");
        valid.args(["-c", "printf 'pg_dump (PostgreSQL) 16.0'"]);
        assert_eq!(
            version_output(&mut valid, Duration::from_secs(2)).await?,
            "pg_dump (PostgreSQL) 16.0"
        );
        let mut excessive = Command::new("/bin/sh");
        excessive.args(["-c", "printf '%4100s' x"]);
        assert!(
            version_output(&mut excessive, Duration::from_secs(2))
                .await
                .is_err()
        );
        let mut stalled = Command::new("/bin/sh");
        stalled.args(["-c", "exec sleep 30"]);
        let started = tokio::time::Instant::now();
        assert!(
            version_output(&mut stalled, Duration::from_millis(100))
                .await
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }

    #[sqlx::test]
    async fn complete_backups_do_not_overlap_or_follow_uncertain_execution(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let directory = Directory(std::env::temp_dir().join(format!(
            "sinan-backup-serialization-test-{}",
            Uuid::new_v4()
        )));
        std::fs::create_dir(&directory.0)?;
        let state = AppState::new(
            pool.clone(),
            Config {
                database_url: String::new(),
                listen: "127.0.0.1:0".parse()?,
                public_url: "http://127.0.0.1".into(),
                data_dir: directory.0.clone(),
                admin_password: Some("TEST_ONLY backup serialization password".into()),
            },
        )
        .await?;
        let schedule = Uuid::new_v4();
        let recipient = format!("age1{}", "a".repeat(58));
        let mut existing = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(530118)")
            .execute(&mut *existing)
            .await?;
        let error = execute(&state, Uuid::new_v4(), schedule, &recipient, 1, "TEST_ONLY")
            .await
            .unwrap_err();
        assert!(
            matches!(error, ApiError::Conflict(message) if message.contains("已有完整备份执行中"))
        );
        existing.rollback().await?;
        let server: i64 = sqlx::query_scalar(
            "INSERT INTO servers(name) VALUES('TEST_ONLY backup serialization') RETURNING id",
        )
        .fetch_one(&pool)
        .await?;
        let job = Uuid::new_v4();
        let now = now_timestamp();
        sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,spec,targets,status,created_at,updated_at,expires_at,preview_digest) VALUES($1,'TEST_ONLY uncertain backup',1,'{}'::jsonb,$2,'uncertain',$3,$3,$4,$5)")
            .bind(job).bind(vec![server]).bind(now).bind(now+3600).bind("0".repeat(64)).execute(&pool).await?;
        sqlx::query("INSERT INTO operations_panel_steps(job_id,position,state,execution_id,spec) VALUES($1,0,'uncertain',$2,'{}'::jsonb)")
            .bind(job).bind(Uuid::new_v4()).execute(&pool).await?;
        let error = execute(&state, Uuid::new_v4(), schedule, &recipient, 1, "TEST_ONLY")
            .await
            .unwrap_err();
        assert!(matches!(error, ApiError::Conflict(message) if message.contains("结果未确认")));
        assert!(!directory.0.join("backups").exists());
        Ok(())
    }
}
