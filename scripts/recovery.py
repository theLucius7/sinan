#!/usr/bin/env python3
"""Restore a complete panel backup without depending on a running panel."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import quote

FILES = ("environment", "database.dump", "panel-data.tar.gz")


class Failure(Exception):
    pass


def private_write(path, data):
    if path.parent.is_symlink():
        raise Failure("输出目录不能是符号链接。")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(data)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def recovery_keyring(path, required_ids):
    if path is None or path.is_symlink() or not path.is_file() or (os.name == "posix" and path.stat().st_mode & 0o077):
        raise Failure("此恢复点需要独立保管的密钥环，使用 --keyring-file 指定权限600的普通密钥环文件。")
    if path.stat().st_size > 65536:
        raise Failure("独立密钥环超过64KiB材料预算。")
    def unique_fields(pairs):
        fields = {}
        for name, value in pairs:
            if name in fields:
                raise Failure("独立密钥环包含重复JSON字段。")
            fields[name] = value
        return fields

    try:
        value = json.loads(path.read_text(), object_pairs_hook=unique_fields)
    except (OSError, ValueError, UnicodeError) as error:
        raise Failure("独立密钥环无法读取或不是有效JSON对象。") from error
    if not isinstance(value, dict) or set(value) != {"current", "keys"}:
        raise Failure("独立密钥环须包含current及keys字段。")
    current, keys = value["current"], value["keys"]
    if not isinstance(keys, dict) or not 1 <= len(keys) <= 16 or not isinstance(current, str) or current not in keys:
        raise Failure("独立密钥环的当前版本或版本数量无效。")
    for identifier, encoded in keys.items():
        if not isinstance(identifier, str) or not identifier or len(identifier) > 100 or any(ord(char) < 32 or ord(char) == 127 for char in identifier) or not isinstance(encoded, str):
            raise Failure("独立密钥环的版本或密钥编码无效。")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise Failure("独立密钥环的密钥须为有效base64编码。") from error
        if len(decoded) != 32:
            raise Failure("独立密钥环的每个密钥必须为32字节。")
    if not isinstance(required_ids, list) or not all(isinstance(identifier, str) and identifier in keys for identifier in required_ids):
        raise Failure("独立密钥环缺少恢复点所需密钥版本。")
    return value


def verify(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise Failure("备份必须为普通目录。")
    manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 1024 * 1024:
        raise Failure("备份清单缺失或无效。")
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict) or type(manifest.get("format")) is not int or manifest.get("format") not in (1, 2) or manifest.get("complete") is not True:
        raise Failure("备份尚未完成或清单格式不支持。")
    required_ids = manifest.get("required_key_ids", [])
    if not isinstance(required_ids, list) or len(required_ids) > 16 or not all(isinstance(identifier, str) and identifier and len(identifier) <= 100 for identifier in required_ids) or len(set(required_ids)) != len(required_ids):
        raise Failure("备份清单所需密钥版本必须为不重复的明确版本清单。")
    hashes = manifest.get("sha256", {})
    if not isinstance(hashes, dict):
        raise Failure("备份完整性清单格式无效。")
    for name in FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise Failure(f"备份材料缺失：{name}。")
        expected = hashes.get(name, "")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or sha256(path) != expected:
            raise Failure(f"备份完整性检查失败：{name}。")
    image = manifest.get("image", "")
    if not isinstance(image, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{12,64}", image):
        raise Failure("清单必须固定面板镜像身份，不能用浮动标签代替。")
    with tarfile.open(directory / "panel-data.tar.gz", "r:gz") as archive:
        total = 0
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if member.name.startswith("/") or ".." in parts or not (member.isdir() or member.isfile()):
                raise Failure("数据归档包含越界路径、链接或特殊设备。")
            total += member.size
            if total > 500 * 1024**3:
                raise Failure("数据归档超过独立恢复工具的 500 GiB 上限。")
    return manifest


def run(command, *, input_file=None, env=None, capture=True):
    result = subprocess.run(command, stdin=input_file, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE, env=env, timeout=600)
    if result.returncode:
        raise Failure(f"恢复步骤失败（退出码 {result.returncode}）；请按报告核对 Docker 或数据库状态。")
    return result.stdout.decode().strip() if capture else None


def env_values(directory):
    values = {}
    for line in (directory / "environment").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator and key.startswith("SINAN_"):
            values[key] = value.strip().strip("\"'")
    # The target is a fresh, owned database. Its login must not depend on the
    # source pool's userinfo, query-password override, pgpass or process env.
    # SQL dump ownership is deliberately stripped during isolated restore.
    values["SINAN_DB_PASSWORD"] = secrets.token_urlsafe(32)
    return values


def isolation_sql(migrations):
    available = {item["version"] for item in migrations}
    statements = ["UPDATE sessions SET expires_at=0;"]
    if 18 in available:
        statements.append("UPDATE panel_settings SET settings=settings || '{\"notification_enabled\":false}'::jsonb;")
    if 32 in available:
        statements.append("UPDATE ddns_rules SET config=jsonb_set(config,'{enabled}','false'::jsonb),revision=revision+1;")
    if 37 in available:
        statements.append("UPDATE alicloud_accounts SET enabled=false,auto_enabled=false;")
    if 50 in available:
        statements.append("UPDATE network_workbench_plans SET enabled=false;UPDATE network_workbench_runs SET status='paused' WHERE status IN ('queued','running');")
    if 51 in available:
        statements.append("UPDATE network_acme_plans SET config=jsonb_set(config,'{automatic_renewal}','false'::jsonb);UPDATE network_acme_jobs SET status='cancelled' WHERE status='queued';")
    if 53 in available:
        statements.append("UPDATE operations_schedules SET paused=true;UPDATE operations_remediation_rules SET paused=true;UPDATE operations_backup_schedules SET paused=true;UPDATE operations_jobs SET status='paused' WHERE status IN ('queued','running');UPDATE operations_cancellation_reminders SET enabled=false;")
    if 54 in available:
        statements.append("UPDATE management_api_tokens SET revoked_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE revoked_at IS NULL;")
    if 57 in available:
        statements.append("UPDATE alicloud_security_group_operations SET status='unknown',original_result='unknown' WHERE status='running';")
    return "".join(statements)


class Restore:
    def __init__(self, args, manifest):
        self.args = args
        self.manifest = manifest
        self.project = args.project or "sinan-recovery-" + uuid.uuid4().hex[:12]
        if not re.fullmatch(r"sinan-recovery-[a-z0-9][a-z0-9_-]{0,40}", self.project):
            raise Failure("恢复项目名须以 sinan-recovery- 开头。")
        if self.project == manifest.get("project"):
            raise Failure("不能覆盖原面板项目。")
        self.label = f"sinan.recovery.project={self.project}"
        self.network = self.project + "-network"
        self.postgres = self.project + "-postgres"
        self.panel = self.project + "-panel"
        self.data_restore = self.project + "-data-restore"
        self.volumes = [self.project + "-database", self.project + "-data"]
        self.created = {"containers": [], "volumes": [], "network": False}
        self.checks = {"integrity": True, "database_restore": False, "panel_health": False,
                       "schema_pairing": False, "temporary_resources_removed": False,
                       "host_loopback_reachable": False}
        self.health_source = None

    def docker(self, *arguments, **kwargs):
        return run(["docker", *arguments], **kwargs)

    def fresh(self):
        if not shutil.which("docker"):
            raise Failure("独立恢复需要 Docker；不需要面板能够启动。")
        for kind, arguments in [("容器", ["ps", "-aq", "--filter", f"label={self.label}"]),
                                ("卷", ["volume", "ls", "-q", "--filter", f"label={self.label}"]),
                                ("网络", ["network", "ls", "-q", "--filter", f"label={self.label}"])]:
            if self.docker(*arguments):
                raise Failure(f"恢复项目已有{kind}；不能覆盖现有恢复环境。")
        container_names = set(self.docker("ps", "-a", "--format", "{{.Names}}").splitlines())
        volume_names = set(self.docker("volume", "ls", "-q").splitlines())
        network_names = set(self.docker("network", "ls", "--format", "{{.Name}}").splitlines())
        if {self.postgres, self.panel, self.data_restore} & container_names or set(self.volumes) & volume_names or self.network in network_names:
            raise Failure("目标恢复名称已被占用，未覆盖任何现有资源。")
        self.docker("image", "inspect", self.manifest["image"])
        postgres_image = self.manifest.get("postgres_image")
        if not postgres_image:
            if not self.args.legacy_postgres_image:
                raise Failure("旧清单缺少 PostgreSQL 镜像身份，需明确提供 --legacy-postgres-image 后复核版本。")
            postgres_image = self.args.legacy_postgres_image
        if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{12,64}", postgres_image):
            raise Failure("PostgreSQL 镜像也必须使用固定身份。")
        self.docker("image", "inspect", postgres_image)
        return postgres_image

    def restore(self):
        postgres_image = self.fresh()
        values = env_values(self.args.backup)
        self.docker("network", "create", "--internal", "--label", self.label, self.network)
        self.created["network"] = True
        for volume in self.volumes:
            self.docker("volume", "create", "--label", self.label, volume)
            self.created["volumes"].append(volume)
        with tempfile.TemporaryDirectory(prefix="sinan-recovery-private-") as temp:
            temp = Path(temp)
            postgres_env = temp / "postgres.env"
            private_write(postgres_env, ("POSTGRES_DB=sinan\nPOSTGRES_USER=sinan\nPOSTGRES_PASSWORD=" + values["SINAN_DB_PASSWORD"] + "\n").encode())
            self.docker("create", "--pull", "never", "--name", self.postgres, "--label", self.label,
                        "--network", self.network, "--network-alias", "postgres", "--env-file", str(postgres_env),
                        "-v", self.volumes[0] + ":/var/lib/postgresql/data", postgres_image)
            self.created["containers"].append(self.postgres)
            self.docker("start", self.postgres)
            deadline = time.monotonic() + 180
            while True:
                try:
                    self.docker("exec", self.postgres, "pg_isready", "-U", "sinan", "-d", "sinan")
                    break
                except Failure:
                    if time.monotonic() >= deadline:
                        raise Failure("隔离数据库在 180 秒内未就绪。")
                    time.sleep(1)
            with (self.args.backup / "database.dump").open("rb") as source:
                self.docker("exec", "-i", self.postgres, "pg_restore", "--exit-on-error", "--no-owner",
                            "--no-privileges", "-U", "sinan", "-d", "sinan", input_file=source)
            self.checks["database_restore"] = True
            actual = self.docker("exec", self.postgres, "psql", "-U", "sinan", "-d", "sinan", "-Atc",
                                 "SELECT COALESCE(json_agg(json_build_object('version',version,'checksum',encode(checksum,'hex')) ORDER BY version)::text,'[]') FROM _sqlx_migrations WHERE success")
            migrations = json.loads(actual)
            expected = self.manifest.get("schema_migrations")
            if expected is not None and migrations != expected:
                raise Failure("数据库迁移身份与恢复清单不一致。")
            self.checks["schema_pairing"] = expected is not None
            if any(migration["version"] >= 54 for migration in migrations):
                actual_keys = json.loads(self.docker("exec", self.postgres, "psql", "-U", "sinan", "-d", "sinan", "-Atc",
                                                    "SELECT COALESCE(json_agg(DISTINCT key_id ORDER BY key_id)::text,'[]') FROM credential_entries"))
                if sorted(actual_keys) != sorted(self.manifest.get("required_key_ids", [])):
                    raise Failure("数据库所需解密密钥版本与恢复清单不一致，不能忽略必要材料。")
            actual_version = int(self.docker("exec", self.postgres, "psql", "-U", "sinan", "-d", "sinan", "-Atc", "SHOW server_version_num"))
            if self.manifest.get("postgres_version_num", actual_version) // 10000 != actual_version // 10000:
                raise Failure("数据库恢复目标与源数据库大版本不一致。")
            self.docker("create", "--pull", "never", "--network", "none", "--user", "0:0",
                        "--name", self.data_restore, "--label", self.label,
                        "--entrypoint", "sh", "-v", self.volumes[1] + ":/data",
                        "--mount", f"type=bind,src={self.args.backup.resolve()},dst=/backup,readonly",
                        self.manifest["image"], "-c", "tar -xzf /backup/panel-data.tar.gz -C /data --no-same-owner && chown -R 10001:10001 /data")
            self.created["containers"].append(self.data_restore)
            self.docker("start", "-a", self.data_restore)
            self.docker("rm", self.data_restore)
            self.created["containers"].remove(self.data_restore)
            # Internal Docker networking prevents restored schedules, DNS and cloud
            # integrations from reaching any production service or notification API.
            self.docker("exec", self.postgres, "psql", "-v", "ON_ERROR_STOP=1", "-U", "sinan", "-d", "sinan", "-c", isolation_sql(migrations))
            panel_env = temp / "panel.env"
            selected = {"SINAN_DATABASE_URL": "postgres://sinan:" + quote(values["SINAN_DB_PASSWORD"], safe="") + "@postgres:5432/sinan",
                        "SINAN_PUBLIC_URL": f"http://127.0.0.1:{self.args.port}", "SINAN_LISTEN": "0.0.0.0:8080",
                        "SINAN_DATA_DIR": "/data", "RUST_LOG": "warn",
                        "SINAN_RECOVERY_VERIFY_CREDENTIALS": "true"}
            if self.manifest.get("required_key_ids"):
                keyring = recovery_keyring(self.args.keyring_file, self.manifest["required_key_ids"])
                keys = keyring["keys"]
                selected["SINAN_CREDENTIAL_KEYS"] = json.dumps(keys, separators=(",", ":"))
                selected["SINAN_CREDENTIAL_CURRENT_KEY"] = keyring["current"]
                self.checks["keyring_material"] = True
            private_write(panel_env, ("\n".join(key + "=" + value for key, value in selected.items()) + "\n").encode())
            self.docker("create", "--pull", "never", "--name", self.panel, "--label", self.label,
                        "--network", self.network, "--env-file", str(panel_env),
                        "-p", f"127.0.0.1:{self.args.port}:8080", "-v", self.volumes[1] + ":/data", self.manifest["image"])
            self.created["containers"].append(self.panel)
            self.docker("start", self.panel)
            deadline = time.monotonic() + 180
            while True:
                if self.healthy():
                    self.checks["panel_health"] = True
                    break
                if self.docker("inspect", "--format", "{{.State.Status}}", self.panel) in ("exited", "dead"):
                    raise Failure("隔离面板启动失败；请核对固定版本和独立解密材料，不能视为恢复通过。")
                if time.monotonic() >= deadline:
                    raise Failure("恢复后的隔离面板在 180 秒内未通过本机健康检查。")
                time.sleep(1)

    def healthy(self):
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{self.args.port}/healthz", timeout=5) as response:
                if response.status == 200 and response.read(16) == b"ok":
                    self.checks["host_loopback_reachable"] = True
                    self.health_source = "host_loopback"
                    if self.manifest.get("required_key_ids"):
                        if response.headers.get("x-sinan-recovery-material-verified") != "true":
                            raise Failure("恢复镜像未确认凭据内容认证，不能将本次恢复标为通过。")
                        self.checks["keyring_authenticated"] = True
                    return True
        except (OSError, urllib.error.URLError) as error:
            if isinstance(error, urllib.error.HTTPError):
                error.close()
        # Some Docker-in-Docker engines cannot route a published port from an
        # internal bridge. Keep isolation and test the actual application inside
        # its owned container; report the host reachability as a separate fact.
        try:
            headers = ["--include"] if self.manifest.get("required_key_ids") else []
            result = self.docker("exec", self.panel, "curl", "--fail", "--silent", "--show-error",
                                 "--max-time", "5", *headers, "http://127.0.0.1:8080/healthz")
        except Failure:
            return False
        if self.manifest.get("required_key_ids"):
            header_text, separator, body = result.replace("\r\n", "\n").partition("\n\n")
            if body != "ok" or not separator:
                return False
            verified = any(line.partition(":")[0].lower() == "x-sinan-recovery-material-verified" and line.partition(":")[2].strip() == "true" for line in header_text.splitlines())
            if not verified:
                raise Failure("恢复镜像未确认凭据内容认证，不能将本次恢复标为通过。")
            self.checks["keyring_authenticated"] = True
            self.health_source = "isolated_container_loopback"
            return True
        if result == "ok":
            self.health_source = "isolated_container_loopback"
            return True
        return False

    def cleanup(self):
        clean = True
        for container in reversed(self.created["containers"]):
            try:
                owner = self.docker("inspect", "--format", '{{index .Config.Labels "sinan.recovery.project"}}', container)
                if owner != self.project:
                    raise Failure("容器所有权与恢复项目不符。")
                self.docker("rm", "-f", container)
            except Failure:
                clean = False
        for volume in reversed(self.created["volumes"]):
            try:
                owner = self.docker("volume", "inspect", "--format", '{{index .Labels "sinan.recovery.project"}}', volume)
                if owner != self.project:
                    raise Failure("数据卷所有权与恢复项目不符。")
                self.docker("volume", "rm", volume)
            except Failure:
                clean = False
        if self.created["network"]:
            try:
                owner = self.docker("network", "inspect", "--format", '{{index .Labels "sinan.recovery.project"}}', self.network)
                if owner != self.project:
                    raise Failure("网络所有权与恢复项目不符。")
                self.docker("network", "rm", self.network)
            except Failure:
                clean = False
        self.checks["temporary_resources_removed"] = clean
        return clean


def encrypt(args):
    verify(args.backup)
    if not shutil.which("age") or not args.recipient or not re.fullmatch(r"age1[0-9a-z]{58}", args.recipient):
        raise Failure("加密导出需要官方 age 工具和显式 age1 公钥；恢复私钥由独立保管方保存。")
    if not args.output:
        raise Failure("加密导出需要 --output 指向独立存储目标。")
    output = args.output.absolute()
    with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as target:
        process = None
        try:
            process = subprocess.Popen(["age", "--encrypt", "--recipient", args.recipient], stdin=subprocess.PIPE,
                                       stdout=target, stderr=subprocess.PIPE)
            with tarfile.open(fileobj=process.stdin, mode="w|gz") as archive:
                for name in (*FILES, "manifest.json"):
                    archive.add(args.backup / name, arcname=name, recursive=False)
            process.stdin.close()
            process.stdin = None
            _, _ = process.communicate(timeout=600)
            if process.returncode:
                raise Failure("age 加密未完成，不能将输出当作有效异地备份。")
        except BaseException:
            if process is not None:
                process.kill()
                process.wait()
            output.unlink(missing_ok=True)
            raise
        finally:
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
    return {"output": str(output), "sha256": sha256(output), "encrypted": True}


def decrypt(args):
    if not shutil.which("age") or not args.identity or not args.output:
        raise Failure("解密需要官方 age、--identity 私钥文件及新的 --output 目录。")
    if args.identity.is_symlink() or not args.identity.is_file() or (os.name == "posix" and args.identity.stat().st_mode & 0o077):
        raise Failure("age 私钥文件必须为权限600的普通文件。")
    destination = args.output.absolute()
    destination.mkdir(mode=0o700)
    process = None
    try:
        process = subprocess.Popen(["age", "--decrypt", "--identity", str(args.identity), str(args.backup)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        seen = set()
        with tarfile.open(fileobj=process.stdout, mode="r|gz") as archive:
            for member in archive:
                if member.name not in (*FILES, "manifest.json") or member.name in seen or not member.isfile() or member.size > 500 * 1024**3:
                    raise Failure("加密归档包含意外路径、重复材料或特殊文件。")
                seen.add(member.name)
                with archive.extractfile(member) as source, os.fdopen(os.open(destination / member.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
        process.stdout.close()
        process.wait(timeout=600)
        if process.returncode or seen != set((*FILES, "manifest.json")):
            raise Failure("age 解密或材料检查失败。")
        manifest = verify(destination)
        return {"output": str(destination), "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest()}
    except BaseException:
        if process is not None:
            process.kill()
            process.wait()
        shutil.rmtree(destination)
        raise
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def retention(args):
    base = args.backup.absolute()
    if base.is_symlink() or not base.is_dir() or args.keep_count < 1 or args.keep_days < 1:
        raise Failure("保留清理需要普通备份根目录、至少一份备份及至少一天保留期。")
    candidates = []
    for path in base.iterdir():
        if path.is_symlink() or not path.is_dir():
            continue
        try:
            manifest = verify(path)
            created = datetime.fromisoformat(manifest["created_at"]).timestamp()
            candidates.append((created, path, manifest))
        except (Failure, ValueError, KeyError, json.JSONDecodeError, tarfile.TarError):
            continue
    candidates.sort(reverse=True)
    protected = set()
    for _, _, manifest in candidates:
        protected.update(manifest.get("dependency_manifest_sha256", []))
    cutoff = time.time() - args.keep_days * 86400
    remove = [path for index, (created, path, manifest) in enumerate(candidates)
              if index >= args.keep_count and created < cutoff
              and hashlib.sha256(canonical(manifest)).hexdigest() not in protected
              and not (path / ".restore-in-use").exists()]
    if args.confirm:
        for path in remove:
            if path.parent != base or path.is_symlink():
                raise Failure("待删除目录越界或已变化。")
            shutil.rmtree(path)
    return {"confirmed": args.confirm, "paths": [str(path) for path in remove],
            "protected_dependencies": len(protected), "latest_retained": min(len(candidates), args.keep_count)}


def main():
    parser = argparse.ArgumentParser(description="Sinan 独立备份校验、隔离恢复、演练和加密导出")
    parser.add_argument("action", choices=["verify", "restore", "drill", "encrypt", "decrypt", "retention"])
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--project")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--legacy-postgres-image")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recipient")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--keyring-file", type=Path)
    parser.add_argument("--keep-count", type=int, default=7)
    parser.add_argument("--keep-days", type=int, default=30)
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("隔离面板端口须为 1024–65535。")
    report = {"tool": "sinan-recovery", "format": 1, "action": args.action, "passed": False,
              "isolated": args.action in ("drill", "restore"), "checks": {"integrity": False}}
    restore = None
    marker = None
    code = 0
    try:
        if args.action == "decrypt":
            report["result"] = decrypt(args)
            report["manifest_sha256"] = report["result"]["manifest_sha256"]
            report["checks"]["integrity"] = True
        elif args.action == "retention":
            report["result"] = retention(args)
        else:
            manifest = verify(args.backup)
            report["manifest_sha256"] = hashlib.sha256(canonical(manifest)).hexdigest()
            report["checks"]["integrity"] = True
            if args.action == "encrypt":
                report["result"] = encrypt(args)
            elif args.action in ("restore", "drill"):
                candidate = args.backup / ".restore-in-use"
                private_write(candidate, (str(os.getpid()) + "\n").encode())
                marker = candidate
                restore = Restore(args, manifest)
                report["project"] = restore.project
                restore.restore()
                report["checks"] = restore.checks
                report["panel_health_source"] = restore.health_source
                report["source_revision"] = manifest.get("source_revision")
                report["image"] = manifest["image"]
                report["endpoint"] = f"http://127.0.0.1:{args.port}"
        report["passed"] = True
    except (Failure, OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        code = 1
        report["error"] = str(error) if isinstance(error, Failure) else "恢复工具步骤未完成，请核对输入文件、Docker 与磁盘状态。"
    except KeyboardInterrupt:
        code = 130
        report["error"] = "操作中断。"
    finally:
        if restore is not None:
            report["checks"] = restore.checks
            if args.action == "drill" or code:
                if not restore.cleanup():
                    report["passed"] = False
                    code = 1
                    report["cleanup_error"] = "部分精确恢复资源未清理，请按 project 核对；未执行全局清理。"
        if marker is not None:
            marker.unlink(missing_ok=True)
        report["completed_at"] = int(time.time())
    if args.report:
        private_write(args.report, json.dumps(report, ensure_ascii=False, indent=2).encode() + b"\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
