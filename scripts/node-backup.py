#!/usr/bin/env python3
"""Capture explicitly allowed node files through typed Agent operations and encrypt them."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
import urllib.error
import urllib.request


class Failure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, stream, code, message, headers, new_url):
        return None


def api(origin, session, path, *, body=None):
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(origin + path, data=payload,
                                     headers={"Cookie": "sinan_session=" + session,
                                              "Origin": origin,
                                              "Content-Type": "application/json"},
                                     method="POST" if body is not None else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            value = response.read(1024 * 1024 + 1)
            if len(value) > 1024 * 1024:
                raise Failure("节点文件回执超过 1 MiB 上限。")
            return json.loads(value)
    except urllib.error.HTTPError as error:
        error.close()
        raise Failure(f"节点备份接口未完成（HTTP {error.code}）；请检查服务器范围、文件权限和 Agent 状态。") from error
    except (OSError, ValueError) as error:
        raise Failure("面板请求结果未确认，不自动重发文件读取任务；请先核对任务记录。") from error


def private_write(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(value)


def capture(args):
    origin = args.origin.rstrip("/")
    parsed = urlsplit(origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise Failure("面板地址必须为明确 HTTP(S) origin。")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise Failure("远端面板需通过 HTTPS 传输节点文件。")
    if args.session_file.is_symlink() or not args.session_file.is_file() or (os.name == "posix" and args.session_file.stat().st_mode & 0o077):
        raise Failure("管理员会话文件必须为权限600的普通文件。")
    session = args.session_file.read_text().strip()
    if not 32 <= len(session) <= 512 or not all(character.isascii() and (character.isalnum() or character in "-_") for character in session) or session.startswith("sinan_api_"):
        raise Failure("会话文件内容无效；异步设备操作需要实际管理员会话。")
    if not shutil.which("age") or not args.recipient.startswith("age1"):
        raise Failure("节点备份需要官方 age 工具和明确独立加密公钥。")
    paths = args.file
    if not paths or len(paths) > 32 or len(set(paths)) != len(paths) or args.server < 1:
        raise Failure("请选择一台受管服务器的 1–32 个明确文件，不能重复或选择整盘。")
    for path in paths:
        if not path.startswith("/") or ".." in PurePosixPath(path).parts or len(path) > 4096 or "\0" in path:
            raise Failure("文件路径无效。")
    output = args.output.absolute()
    files = []
    with tempfile.TemporaryDirectory(prefix="sinan-node-backup-private-") as directory:
        directory = Path(directory)
        total = 0
        for index, path in enumerate(paths):
            # A timeout after submission is an unknown task, not permission to
            # submit a replacement. The operator can inspect the original ID.
            operation = api(origin, session, f"/api/servers/{args.server}/fleet/operations",
                            body={"kind": "file_read", "path": path})
            operation_id = operation["id"]
            deadline = time.monotonic() + args.timeout
            while True:
                result = api(origin, session, f"/api/fleet/operations/{operation_id}")
                status = result["status"]
                if status == "succeeded":
                    result = result["result"]["result"]
                    content = base64.b64decode(result["content"], validate=True)
                    digest = hashlib.sha256(content).hexdigest()
                    if len(content) > 256 * 1024 or digest != result["sha256"]:
                        raise Failure("节点文件大小或完整性回执无效。")
                    total += len(content)
                    if total > 8 * 1024 * 1024:
                        raise Failure("节点关键数据超过本次 8 MiB 显式预算。")
                    name = f"file-{index:03d}"
                    private_write(directory / name, content)
                    files.append({"source_path": path, "archive_name": name, "sha256": digest,
                                  "bytes": len(content), "operation_id": operation_id,
                                  "observed_at": int(time.time())})
                    break
                if status in ("failed", "expired", "cancelled", "unknown", "reconciled") or time.monotonic() >= deadline:
                    raise Failure(f"节点文件读取未完成，任务 {operation_id}；未自动重发。")
                time.sleep(1)
        manifest = {"tool": "sinan-node-backup", "format": 1, "complete": True,
                    "server_id": args.server, "created_at": int(time.time()), "scope": "explicit_managed_files",
                    "files": files, "agent_identity_auto_copied": False,
                    "consistency": "各文件独立读取时间与hash；不宣称多文件或运行数据具有事务快照"}
        private_write(directory / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode())
        archive_path = directory / "complete.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            for file in files:
                archive.add(directory / file["archive_name"], arcname=file["archive_name"], recursive=False)
            archive.add(directory / "manifest.json", arcname="manifest.json", recursive=False)
        created = False
        try:
            with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as encrypted:
                created = True
                result = subprocess.run(["age", "--encrypt", "--recipient", args.recipient, str(archive_path)],
                                        stdout=encrypted, stderr=subprocess.PIPE, timeout=600)
                if result.returncode:
                    raise Failure("节点备份加密未完成。")
        except BaseException:
            if created:
                output.unlink(missing_ok=True)
            raise
        return {"tool": "sinan-node-backup", "passed": True, "server_id": args.server,
                "files": len(files), "bytes": total, "encrypted_output": str(output),
                "storage_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "created_at": int(time.time()), "multi_file_snapshot": False}


def main():
    parser = argparse.ArgumentParser(description="Sinan 节点关键数据显式选择与加密备份")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--session-file", type=Path, required=True)
    parser.add_argument("--server", type=int, required=True)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if not 30 <= args.timeout <= 600:
        parser.error("单个文件领取期限须为 30–600 秒。")
    try:
        print(json.dumps(capture(args), ensure_ascii=False, indent=2))
        return 0
    except (Failure, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, Failure) else "节点备份未完成；请核对私有输入、原任务记录与目标存储。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
