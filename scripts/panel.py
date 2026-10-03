#!/usr/bin/env python3
"""Manage the repository's Docker Compose panel without replacing credentials."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]


class Failure(Exception):
    pass


@contextmanager
def operation_lock(project):
    directory = ROOT / ".local"
    directory.mkdir(mode=0o700, exist_ok=True)
    lock = directory / f"panel-{project}.lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as error:
        raise Failure(f"已有面板操作正在执行；异常退出后请确认没有其他操作，再移除锁目录 {lock}。") from error
    try:
        yield
    finally:
        lock.rmdir()


class Panel:
    def __init__(self, args):
        self.args = args
        self.env_file = args.env_file.absolute()
        # The selected file is authoritative; shell variables must not silently
        # replace passwords, volumes, build trust roots or the public origin.
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("SINAN_", "COMPOSE_")) and key != "RUST_LOG"}
        self.command = ["docker", "compose", "--project-name", args.project,
                        "--env-file", str(self.env_file), "-f", str(ROOT / "deploy/docker-compose.yml")]

    def execute(self, command, *, output=None, quiet=False):
        result = subprocess.run(command, cwd=ROOT, env=self.env,
                                stdout=output if output else subprocess.PIPE if quiet else None,
                                stderr=subprocess.PIPE)
        if result.returncode:
            # Compose diagnostics can interpolate secrets. Only explicitly
            # requested service logs are streamed to the operator.
            raise Failure(f"命令失败（退出码 {result.returncode}）：{' '.join(command[:2])}；请检查 Docker 与服务状态。")
        return result.stdout.decode().strip() if quiet else None

    def compose(self, *arguments, **kwargs):
        return self.execute([*self.command, *arguments], **kwargs)

    def initialize(self):
        if self.env_file.is_symlink():
            raise Failure("环境文件不能是符号链接。")
        if self.env_file.exists():
            print("保留现有环境文件与凭据。")
            return
        if not self.args.public_url:
            raise Failure("首次初始化需要 --public-url，例如 https://panel.example.com。")
        self.execute([sys.executable, str(ROOT / "scripts/init-env.py"), "--output", str(self.env_file),
                      "--public-url", self.args.public_url, "--port", str(self.args.port),
                      "--release-keys-file", str(self.args.release_keys_file)])
        print("已初始化；管理员初始密码保存在私有环境文件中。默认仅监听本机，HTTPS 由反向代理提供。")

    def prepare(self):
        if self.env_file.is_symlink() or not self.env_file.is_file():
            raise Failure("需要有效的普通环境文件；请先运行 init。")
        if os.name == "posix" and self.env_file.stat().st_mode & 0o077:
            raise Failure("环境文件含凭据，请将权限设为 600 后继续。")
        if not shutil.which("docker"):
            raise Failure("未找到 Docker；请按 Docker 官方文档安装 Engine 与 Compose 插件。")
        self.execute(["docker", "compose", "version"], quiet=True)
        self.execute(["docker", "info"], quiet=True)
        self.compose("config", "--quiet", quiet=True)

    def require_fresh_project(self):
        if not shutil.which("docker"):
            raise Failure("未找到 Docker；无法确认是否已有面板数据，尚未生成新凭据。")
        project = f"label=com.docker.compose.project={self.args.project}"
        containers = self.execute(["docker", "ps", "-aq", "--filter", project], quiet=True)
        volumes = self.execute(["docker", "volume", "ls", "--filter", project, "--quiet"], quiet=True)
        if containers or volumes:
            raise Failure("已有此项目的容器或数据卷，但环境文件缺失。请找回原环境文件与凭据后继续；尚未生成新凭据。")

    def backup(self):
        services = self.compose("ps", "--status", "running", "--services", quiet=True).splitlines()
        if "postgres" not in services:
            raise Failure("数据库未运行，无法备份；请先恢复现有数据库服务。")
        base = self.args.backup_dir.absolute()
        if base.is_symlink():
            raise Failure("备份目录不能是符号链接。")
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix" and base.stat().st_mode & 0o077:
            raise Failure("备份含凭据，请将备份目录权限设为 700。")
        destination = base / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
        destination.mkdir(mode=0o700)
        was_running = "panel" in services
        try:
            if was_running:
                self.compose("stop", "panel", quiet=True)
            environment_lines = self.env_file.read_text().splitlines(keepends=True)
            protected = re.compile(r"^\s*(?:export\s+)?SINAN_CREDENTIAL_(?:KEYS|CURRENT_KEY)\s*=")
            self.private_write(destination / "environment", "".join(line for line in environment_lines if not protected.match(line)).encode())
            for filename, arguments in [
                ("database.dump", ["exec", "-T", "postgres", "pg_dump", "-U", "sinan", "-d", "sinan", "-Fc"]),
                ("panel-data.tar.gz", ["run", "--rm", "--no-deps", "-T", "--pull", "never", "--entrypoint", "tar", "panel", "-C", "/data", "-czf", "-", "."]),
            ]:
                with self.private_file(destination / filename) as output:
                    self.compose(*arguments, output=output)
                if (destination / filename).stat().st_size == 0:
                    raise Failure("备份输出为空，已中止。")
            hashes = {}
            for filename in ("environment", "database.dump", "panel-data.tar.gz"):
                digest = hashlib.sha256()
                with (destination / filename).open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                hashes[filename] = digest.hexdigest()
            revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
            migrations = json.loads(self.compose("exec", "-T", "postgres", "psql", "-U", "sinan", "-d", "sinan", "-Atc",
                "SELECT COALESCE(json_agg(json_build_object('version',version,'checksum',encode(checksum,'hex')) ORDER BY version)::text,'[]') FROM _sqlx_migrations WHERE success", quiet=True))
            database_version = self.compose("exec", "-T", "postgres", "psql", "-U", "sinan", "-d", "sinan", "-Atc", "SHOW server_version_num", quiet=True)
            required_key_ids = []
            if any(item["version"] == 54 for item in migrations):
                required_key_ids = json.loads(self.compose("exec", "-T", "postgres", "psql", "-U", "sinan", "-d", "sinan", "-Atc",
                    "SELECT COALESCE(json_agg(key_id)::text,'[]') FROM (SELECT DISTINCT key_id FROM credential_entries ORDER BY key_id) keys", quiet=True))
            keyring_reference = next((line.partition("=")[2].strip().strip("\"'") for line in environment_lines if line.startswith("SINAN_BACKUP_KEYRING_REFERENCE=")), None)
            if required_key_ids and not keyring_reference:
                raise Failure("数据库含加密凭据，需在环境文件中配置 SINAN_BACKUP_KEYRING_REFERENCE 记录独立密钥环保管位置；主密钥不会写入备份。")
            manifest = {"format": 2, "complete": True, "created_at": datetime.now(timezone.utc).isoformat(),
                        "project": self.args.project, "source_revision": revision.stdout.strip() if revision.returncode == 0 else None,
                        "image": self.compose("images", "-q", "panel", quiet=True), "sha256": hashes,
                        "postgres_image": self.compose("images", "-q", "postgres", quiet=True),
                        "postgres_version_num": int(database_version), "schema_migrations": migrations,
                        "restore_scope": ["database", "panel_environment", "panel_data", "artifact_metadata"],
                        "node_data_included": False, "dependency_manifest_sha256": [],
                        "required_key_ids": required_key_ids, "keyring_reference": keyring_reference,
                        "keyring_included": False}
            self.private_write(destination / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
        except BaseException:
            print(f"备份未完成：{destination}；请勿用于恢复。", file=sys.stderr)
            raise
        finally:
            if was_running:
                # Start the same stopped container, never recreate it on a
                # backup failure or apply a new image before backup completes.
                self.compose("start", "panel", quiet=True)
        print(f"完整备份：{destination}")
        return destination

    @staticmethod
    def private_file(path):
        return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")

    @classmethod
    def private_write(cls, path, data):
        with cls.private_file(path) as output:
            output.write(data)

    def up(self, existing=False):
        self.compose("up", "-d", "--no-build", *(["--no-recreate"] if existing else []), "--wait", "--wait-timeout", "180")

    def run(self):
        action = self.args.action
        if action == "install" and not self.env_file.exists() and not self.env_file.is_symlink():
            # Existing containers or either data volume can outlive the file.
            # Never create unrelated credentials before discovering that state.
            self.require_fresh_project()
        if action in ("init", "install"):
            self.initialize()
        if action == "init":
            return
        self.prepare()
        if action == "install":
            # Repeated installation is an upgrade and requires a backup too.
            if self.compose("ps", "-aq", "postgres", quiet=True):
                self.backup()
            elif self.execute(["docker", "volume", "ls", "--filter", f"label=com.docker.compose.project={self.args.project}",
                               "--quiet"], quiet=True):
                raise Failure("已有数据卷但缺少数据库服务容器。请使用原镜像恢复服务并备份，再运行 upgrade。")
            self.compose("build", "--pull", "panel")
            self.up()
        elif action == "upgrade":
            self.backup()
            self.compose("build", "--pull", "panel")
            self.up()
            print("升级完成。备份已保留；数据库迁移不支持自动降级，请先在隔离环境演练恢复。")
        elif action == "backup":
            self.backup()
        elif action == "start":
            self.up(existing=True)
        elif action == "stop":
            self.compose("stop")
            print("服务已停止，数据卷与凭据保留。")
        elif action == "status":
            self.compose("ps", "-a")
        elif action == "logs":
            self.compose("logs", "--tail", str(self.args.tail), *( ["--follow"] if self.args.follow else []), "panel", "postgres")
        elif action == "doctor":
            self.compose("ps", "-a")
            self.compose("exec", "-T", "postgres", "pg_isready", "-h", "127.0.0.1", "-U", "sinan", "-d", "sinan", quiet=True)
            self.compose("exec", "-T", "panel", "curl", "-fsS", "--max-time", "10", "http://127.0.0.1:8080/healthz", quiet=True)
            print("Compose、数据库与面板本机健康检查通过；公网 HTTPS 和 Agent 连接需从外部另行验证。")


def main():
    parser = argparse.ArgumentParser(description="Sinan 面板安装与运维（Docker Compose）")
    parser.add_argument("action", choices=["init", "install", "start", "stop", "upgrade", "backup", "status", "logs", "doctor"])
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--project", default="sinan")
    parser.add_argument("--public-url")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--release-keys-file", type=Path, default=ROOT / "deploy/release-public-keys.json")
    parser.add_argument("--backup-dir", type=Path, default=ROOT / "backups")
    parser.add_argument("--tail", type=int, default=100)
    parser.add_argument("--follow", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", args.project) or not 1 <= args.tail <= 10000:
        parser.error("项目名需为小写字母、数字、横线或下划线；日志行数需为 1 至 10000。")
    try:
        if args.action in ("init", "install", "upgrade", "backup", "start", "stop"):
            with operation_lock(args.project):
                Panel(args).run()
        else:
            Panel(args).run()
    except (Failure, OSError) as error:
        parser.exit(1, f"{error}\n")
    except KeyboardInterrupt:
        parser.exit(130, "操作已中断；请检查服务状态。\n")


if __name__ == "__main__":
    main()
