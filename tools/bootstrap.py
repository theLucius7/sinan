#!/usr/bin/env python3
"""Trusted, operator-provisioned bootstrap; never fetched from the panel and executed."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from legacy_agent_checkpoint import preflight as legacy_checkpoint_preflight

from release import (REPOSITORY, VERSION, digest, ensure, load_roots, read_regular,
                     require_protected_file, validate_manifest, verify_manifest)

GITHUB_DOWNLOAD_HOSTS = frozenset(("github.com", "release-assets.githubusercontent.com",
                                    "objects.githubusercontent.com"))
PROTOCOL_VERSION = 1
MINISIGN_LINUX_ARCHIVE_SHA256 = "9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"
MINISIGN_LINUX_BINARIES = {
    "x86_64": (288200, "2c74dffcc1c9a5ee55957c60971998ace2b89f22585631594ec2152c588af8db"),
    "aarch64": (195288, "cec9f88be8c975af76854a53b4d49c3d257feae38d916edb0d16fb55aacd3000"),
}
PROOF_FILES = (("SHA256SUMS", 8192), ("SHA256SUMS.minisig", 16384),
               ("release.json", 32768), ("install.sh", 262144))
PRELOADED_INSTALLER_MARKER = b"# SINAN_BOOTSTRAP_AGENT_SOURCE=preloaded-github-v1"
DOWNLOAD_BUDGET_SECONDS = 300
DOWNLOAD_SOCKET_TIMEOUT = 20
CATALOG_BUDGET_SECONDS = 30


class IncompatibleRelease(ValueError):
    pass


def require_preloaded_installer(installer):
    """Check the actual independently trusted executor, not an unexecuted release file."""
    content = read_regular(Path(installer), 262144)
    ensure(content.splitlines().count(PRELOADED_INSTALLER_MARKER) == 1,
           "trusted Linux installer requires the preloaded-GitHub Agent contract")


def bounded_read(response, size, deadline, message="GitHub download exceeded total time budget"):
    remaining = deadline - time.monotonic()
    ensure(remaining > 0, message)
    # urllib otherwise renews its timeout for every socket read. Bound each
    # active HTTP(S) read by this file's remaining total budget as well.
    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    if sock is not None:
        sock.settimeout(min(DOWNLOAD_SOCKET_TIMEOUT, remaining))
    read = getattr(response, "read1", response.read)
    block = read(size)
    ensure(time.monotonic() < deadline, message)
    return block


def validate_mirror(value, panel=None):
    if not value:
        return ""
    parsed = urllib.parse.urlsplit(value)
    ensure(len(value) <= 512 and not any(ord(c) < 32 or ord(c) == 127 for c in value)
           and parsed.scheme == "https" and parsed.hostname and parsed.hostname != "localhost"
           and parsed.port in (None, 443) and not parsed.username and not parsed.password
           and not parsed.query and not parsed.fragment, "invalid HTTPS mirror prefix")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError("mirror must be a hostname")
    if panel:
        origin = urllib.parse.urlsplit(panel)
        ensure((parsed.hostname, parsed.port or 443) != (origin.hostname, origin.port or (443 if origin.scheme == "https" else 80)), "Agent cannot be downloaded from panel")
    return value.rstrip("/")


def validate_github_url(url, mirror=""):

    parsed = urllib.parse.urlsplit(url)
    ensure(not any(ord(character) < 32 or ord(character) == 127 for character in url)
           and parsed.scheme == "https" and (parsed.hostname in GITHUB_DOWNLOAD_HOSTS or
               (mirror and parsed.netloc == urllib.parse.urlsplit(mirror).netloc))
           and parsed.port in (None, 443) and not parsed.username and not parsed.password
           and not parsed.fragment, "GitHub download URL is outside the fixed HTTPS allowlist")


def validate_panel_origin(value):
    parsed = urllib.parse.urlsplit(value)
    ensure(not any(ord(character) < 32 or ord(character) == 127 for character in value)
           and parsed.scheme in ("http", "https") and parsed.hostname
           and not parsed.username and not parsed.password and parsed.path in ("", "/")
           and not parsed.query and not parsed.fragment
           and (parsed.port is None or 0 < parsed.port <= 65535), "panel must be a valid origin")
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
            address = getattr(address, "ipv4_mapped", None) or address
            loopback = address.is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        ensure(loopback, "HTTP panel origins must use a loopback address; use HTTPS")


class GithubRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def __init__(self, mirror=""):
        super().__init__()
        self.mirror = mirror

    def redirect_request(self, request, response, code, message, headers, new_url):
        validate_github_url(new_url, self.mirror)
        return super().redirect_request(request, response, code, message, headers, new_url)


def github_opener(mirror=""):
    # Bootstrap proof downloads never inherit HTTP_PROXY/HTTPS_PROXY/ALL_PROXY.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), GithubRedirect(mirror))


def download(base, name, destination, limit, mirror=""):
    ensure(Path(name).name == name and name not in (".", ".."), "unsafe asset name")
    url = base + "/" + urllib.parse.quote(name, safe="")
    mirror = validate_mirror(mirror)
    if mirror:
        url = mirror + "/" + url
    validate_github_url(url, mirror)
    deadline = time.monotonic() + DOWNLOAD_BUDGET_SECONDS
    with github_opener(mirror).open(url, timeout=DOWNLOAD_SOCKET_TIMEOUT) as response:
        validate_github_url(response.url, mirror)
        blocks, total = [], 0
        while True:
            block = bounded_read(response, min(65536, limit + 1 - total), deadline)
            if not block:
                break
            total += len(block)
            ensure(total <= limit, "download size outside permitted range")
            blocks.append(block)
        data = b"".join(blocks)
    ensure(0 < len(data) <= limit, "download size outside permitted range")
    destination.write_bytes(data)


def prepare_linux_minisign(staging):
    ensure(platform.system() == "Linux", "minisign 静态后备包仅适用于 Linux")
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
    ensure(machine in MINISIGN_LINUX_BINARIES, "minisign 不支持此 CPU")
    staging = Path(staging)
    require_protected_file(staging)
    archive = staging / "minisign.tar.gz"
    download("https://github.com/jedisct1/minisign/releases/download/0.12",
             "minisign-0.12-linux.tar.gz", archive, 1048576)
    ensure(hashlib.sha256(archive.read_bytes()).hexdigest() == MINISIGN_LINUX_ARCHIVE_SHA256,
           "minisign 官方后备归档摘要不匹配")
    name = "minisign-linux/" + machine + "/minisign"
    size, checksum = MINISIGN_LINUX_BINARIES[machine]
    with tarfile.open(archive, "r:gz") as source:
        matches = [member for member in source if member.name == name]
        ensure(len(matches) == 1 and matches[0].isfile() and matches[0].size == size,
               "minisign 官方后备包缺少唯一目标 CPU 文件")
        binary = source.extractfile(matches[0]).read(size + 1)
    ensure(len(binary) == size and hashlib.sha256(binary).hexdigest() == checksum,
           "minisign 官方后备可执行文件摘要不匹配")
    target = staging / "minisign"
    target.write_bytes(binary)
    target.chmod(0o700)
    return str(target)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise ValueError("面板响应禁止重定向")


def panel_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def host_target():
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    ensure(arch is not None, "仅支持 AMD64 和 ARM64 架构")
    system = platform.system()
    if system == "Darwin":
        ensure(arch == "arm64", "macOS Agent 仅支持 ARM64")
        return "macos-arm64"
    if system == "FreeBSD":
        return "freebsd-" + arch
    ensure(system == "Linux", "此入口支持 Linux、macOS 和 FreeBSD；Windows 请使用 PowerShell 入口")
    libc = platform.libc_ver()[0].lower()
    if libc in ("glibc", "gnu"):
        return "linux-gnu-" + arch
    if libc == "musl" or list(Path("/lib").glob("ld-musl-*.so.1")):
        return "linux-musl-" + arch
    try:
        result = subprocess.run(["ldd", "--version"], capture_output=True, check=False, timeout=10)
        description = (result.stdout + result.stderr).decode("utf-8", errors="replace").lower()
    except (OSError, subprocess.TimeoutExpired):
        description = ""
    if "musl" in description:
        return "linux-musl-" + arch
    if "glibc" in description or "gnu libc" in description:
        return "linux-gnu-" + arch
    raise ValueError("无法识别 Linux libc，拒绝猜测 GNU/musl 制品")


def compatible_targets(actual, requested="auto"):
    if actual.startswith("linux-"):
        arch = actual.rsplit("-", 1)[1]
        targets = ["linux-musl-" + arch, arch]
        if actual.startswith("linux-gnu-"):
            targets.append(actual)
    else:
        targets = [actual]
    ensure(requested == "auto" or requested in targets,
           f"所选平台 {requested} 与本机 {actual} 不兼容，请选择自动匹配或本机平台")
    if requested != "auto":
        targets.remove(requested)
        targets.insert(0, requested)
    return targets


def catalog_refusal(error, deadline):
    """Report known selection failures without reflecting a panel URL or free-form body."""
    if error.code == 401:
        error.close()
        return "接入令牌无效或已过期，请重新签发令牌"
    fallback = "无法获取接入版本，请检查令牌是否有效以及面板是否已导入签名 Release"
    if error.code != 409:
        error.close()
        return fallback
    try:
        with error:
            blocks, total = [], 0
            while total <= 8192:
                block = bounded_read(error, min(4096, 8193 - total), deadline,
                                     "panel catalog refusal exceeded total time budget")
                if not block:
                    break
                blocks.append(block)
                total += len(block)
            if total > 8192:
                return fallback
        value = json.loads(b"".join(blocks))
        message = value.get("error") if isinstance(value, dict) else None
    except (OSError, ValueError, RecursionError):
        return fallback
    known = {
        "所选 Agent 版本尚未导入已校验的签名 Release": "所选 Agent 版本尚未导入已校验的签名 Release",
        "所选 Agent 版本与当前面板协议不兼容，请选择兼容的已签名版本":
            "所选 Agent 版本与当前面板协议不兼容，请选择兼容的已签名版本",
        "所选 Agent 版本不包含该平台可安装的制品，请核对平台、架构及稳定版本要求":
            "所选 Agent 版本不包含本机平台可安装的制品，请核对平台、架构及稳定版本要求",
        "请先导入对应平台且协议兼容的已签名 Agent Release":
            "面板尚无本机平台且协议兼容的已签名 Agent Release，请先导入 Release",
    }
    if isinstance(message, str) and message.startswith("历史 Agent 不支持当前标准安装与服务合同"):
        return "历史 Agent 不支持当前标准安装与服务合同；补签不能补齐旧命令，请选择 0.3.0 或更新的兼容已签版本"
    if isinstance(message, str) and message.startswith("所选历史 Agent 不支持当前标准安装与服务合同"):
        return "历史 Agent 不支持当前标准安装与服务合同；补签不能补齐旧命令，请选择 0.3.0 或更新的兼容已签版本"
    return known.get(message, fallback) if isinstance(message, str) else fallback


def catalog(panel, token, target, version):
    validate_panel_origin(panel)
    parameters = {"token": token, "target": target}
    if version != "latest":
        parameters["agent_version"] = version
    url = panel.rstrip("/") + "/api/bootstrap/versions?" + urllib.parse.urlencode(parameters)
    deadline = time.monotonic() + CATALOG_BUDGET_SECONDS
    try:
        with panel_opener().open(url, timeout=CATALOG_BUDGET_SECONDS) as response:
            ensure(response.status == 200 and response.url == url, "接入版本目录响应无效")
            blocks, total = [], 0
            while True:
                block = bounded_read(response, min(65536, 131073 - total), deadline,
                                     "panel catalog download exceeded total time budget")
                if not block:
                    break
                total += len(block)
                ensure(total <= 131072, "接入版本目录超出大小限制")
                blocks.append(block)
            encoded = b"".join(blocks)
    except urllib.error.HTTPError as error:
        raise ValueError(catalog_refusal(error, deadline)) from None
    ensure(0 < len(encoded) <= 131072, "接入版本目录超出大小限制")
    value = json.loads(encoded)
    ensure(isinstance(value, dict) and isinstance(value.get("versions"), list)
           and len(value["versions"]) <= 256, "接入版本目录格式无效")
    candidates = []
    seen = set()
    for item in value["versions"]:
        ensure(isinstance(item, dict), "接入版本条目无效")
        release_version = item.get("version")
        ensure(isinstance(release_version, str) and VERSION.fullmatch(release_version)
               and item.get("tag") == "agent-v" + release_version
               and isinstance(item.get("targets"), list)
               and all(isinstance(t, str) for t in item["targets"]), "接入版本身份无效")
        if version != "latest" and release_version != version:
            continue
        if version == "latest" and not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", release_version):
            continue
        if release_version not in seen:
            seen.add(release_version)
            candidates.append(item)
    candidates.sort(key=lambda item: tuple(int(part) for part in item["version"].split("-")[0].split("+")[0].split(".")), reverse=True)
    ensure(candidates, f"面板未导入本机 {target} 可用的签名 Agent 版本，请先导入 Release")
    return candidates


def select_artifact(metadata, version, actual, requested="auto"):
    if not actual.startswith("linux-") and not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise IncompatibleRelease("原生平台服务安装仅支持稳定版本，请选择数字三段版本")
    ensure(metadata["tag"] == "agent-v" + version, "签名发布版本与所选版本不匹配")
    if not metadata["protocol_min"] <= PROTOCOL_VERSION <= metadata["protocol_max"]:
        raise IncompatibleRelease("签名 Agent 发布不支持此接入入口的协议版本")
    # This minimum is the registered installation line, not evidence that an
    # arbitrary newer executable implements it. All signed payload and native
    # verify-installed/verify-cache checks remain mandatory after selection.
    core = version.split("-")[0].split("+")[0]
    if tuple(int(part) for part in core.split(".")) < (0, 3, 0):
        raise IncompatibleRelease("历史 Agent 不支持当前标准安装与服务合同：0.1/0.2 原制品缺少所需的验签、缓存预检或 supervisor；补签元数据不能补齐命令，原身份和状态未修改")
    for target in compatible_targets(actual, requested):
        matches = [item for item in metadata["artifacts"] if
                   (item["name"], item["version"], item["arch"]) == ("agent", version, target)]
        if matches:
            ensure(len(matches) == 1, "签名发布重复了本机 Agent 身份")
            item = matches[0]
            ensure(item["format"] == "raw" and item["binary_name"] == "sinan-agent"
                   and item["archive_size"] == item["binary_size"], "签名 Agent 格式不匹配")
            return item
    raise IncompatibleRelease(f"签名发布 {version} 没有本机 {actual} 可运行的 Agent")


def download_agent(item, destination, mirror="", release_dir=None):
    """Fetch only the signed raw asset from its official GitHub tag, never the panel."""
    expected_size = item["archive_size"]
    name = item["asset_name"]
    ensure(type(expected_size) is int and 0 < expected_size <= 256 * 1024 * 1024
           and item["format"] == "raw" and item["binary_size"] == expected_size,
           "已签 Agent 大小或格式无效")
    ensure(VERSION.fullmatch(item["version"]) and Path(name).name == name
           and name not in (".", ".."), "已签 Agent 身份无效")
    mirror = validate_mirror(mirror)
    destination = Path(destination)
    try:
        if release_dir:
            payload = read_regular(Path(release_dir) / name, expected_size)
            ensure(len(payload) == expected_size and digest(payload) == item["binary_sha256"],
                   "离线 Agent 不符合已签大小或摘要，拒绝执行")
            with destination.open("xb") as output:
                output.write(payload)
            return
        url = f"https://github.com/{REPOSITORY}/releases/download/agent-v{item['version']}/{urllib.parse.quote(name, safe='')}"
        if mirror:
            url = mirror + "/" + url
        validate_github_url(url, mirror)
        deadline = time.monotonic() + DOWNLOAD_BUDGET_SECONDS
        with github_opener(mirror).open(url, timeout=DOWNLOAD_SOCKET_TIMEOUT) as response:
            validate_github_url(response.url, mirror)
            ensure(response.status == 200, "GitHub Agent 响应无效")
            declared = response.headers.get("Content-Length")
            ensure(declared is None or int(declared) == expected_size, "GitHub Agent 声明长度不匹配")
            total, checksum = 0, hashlib.sha256()
            with destination.open("xb") as output:
                while True:
                    data = bounded_read(response, min(65536, expected_size + 1 - total), deadline)
                    if not data:
                        break
                    total += len(data)
                    ensure(total <= expected_size, "Agent 超出已签大小")
                    output.write(data)
                    checksum.update(data)
            ensure(total == expected_size and checksum.hexdigest() == item["binary_sha256"],
                   "Agent 不符合已签大小或摘要，拒绝执行")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def checked_agent(agent, arguments):
    result = subprocess.run([str(agent)] + arguments, check=False)
    ensure(result.returncode == 0, "Agent 验证、接入或服务安装失败；已有版本未通过切换验收")


def native_paths(actual):
    configuration = Path("/private/etc/sinan/agent.toml" if actual == "macos-arm64" else "/etc/sinan/agent.toml")
    base = Path("/private/var" if actual == "macos-arm64" else "/var")
    return configuration, Path("/usr/local/bin/sinan-agent"), base, Path("/opt/sinan/core")


def normalized_origin(value):
    validate_panel_origin(value)
    parsed = urllib.parse.urlsplit(value)
    hostname = parsed.hostname.lower()
    try:
        hostname = ipaddress.ip_address(hostname).compressed
    except ValueError:
        hostname = hostname.encode("idna").decode("ascii")
    return parsed.scheme.lower(), hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def validate_partial_identity(identity, panel):
    if not identity.exists() and not identity.is_symlink():
        return
    require_protected_file(identity)
    ensure(identity.is_dir() and not identity.is_symlink(), "首次接入身份目录必须是普通受控目录")
    names = {path.name for path in identity.iterdir()}
    if not names:
        return
    ensure("panel_origin" in names and names <= {"device.key", "panel_origin", "server_id"}
           and ("server_id" not in names or "device.key" in names),
           "已有身份不是可恢复的首次接入状态，请先核对已有安装")
    key = identity / "device.key"
    if "device.key" in names:
        require_protected_file(key)
        ensure(key.stat().st_mode & 0o077 == 0 and len(read_regular(key, 32)) == 32,
               "首次接入的设备密钥必须是私有 32 字节文件")
    origin = identity / "panel_origin"
    require_protected_file(origin)
    recorded = read_regular(origin, 8192).decode("utf-8").strip()
    ensure(normalized_origin(recorded) == normalized_origin(panel),
           "首次接入身份属于另一面板，请使用原面板重新获取令牌")
    server = identity / "server_id"
    if server.exists() or server.is_symlink():
        require_protected_file(server)
        value = read_regular(server, 32).decode("ascii").strip()
        ensure(re.fullmatch(r"[1-9][0-9]{0,18}", value) and int(value) <= 9223372036854775807,
               "首次接入的服务器身份无效")


def install_native(bundle, panel, token, item, actual, mirror="", release_dir=None):
    import tomllib

    agent = bundle / "sinan-agent"
    download_agent(item, agent, validate_mirror(mirror, panel), release_dir)
    agent.chmod(0o755)
    checked_agent(agent, ["verify-installed", "--binary", str(agent), "--name", "agent", "--format", "raw"])
    configuration, command, base, agent_root = native_paths(actual)
    if command.exists() or command.is_symlink():
        ensure(command.is_symlink(), "已有 /usr/local/bin/sinan-agent 普通文件，请先核对安装来源")
    if command.parent.exists():
        require_protected_file(command.parent)
    previous_configuration = None
    if configuration.exists() or configuration.is_symlink():
        require_protected_file(configuration)
        checked_agent(agent, ["--config", str(configuration), "verify-cache"])
        saved = tomllib.loads(read_regular(configuration, 1048576).decode("utf-8"))
        previous_configuration = configuration.read_bytes()
        if "agent_root" in saved:
            ensure(isinstance(saved["agent_root"], str) and Path(saved["agent_root"]).is_absolute(), "已有 Agent 安装目录无效")
            agent_root = Path(saved["agent_root"])
    else:
        identity = configuration.parent / "identity"
        roots = [base / ("lib/sinan/core/state.db" + suffix) for suffix in ("", "-wal", "-shm")]
        roots.append(agent_root / "current")
        roots.extend(Path("/opt/sinan/plugins").glob("*/current"))
        ensure(not any(path.exists() or path.is_symlink() for path in roots),
               "已有 Agent 状态但缺少配置，无法安全预检；请先修复已有安装")
        validate_partial_identity(identity, panel)
    previous_agent = agent_root / "current/sinan-agent"
    if previous_agent.exists():
        previous_agent = previous_agent.resolve(strict=True)
        checked_agent(agent, ["verify-installed", "--binary", str(previous_agent), "--name", "agent", "--format", "raw"])
    try:
        checked_agent(agent, ["--config", str(configuration), "enroll", "--panel", panel, f"--token={token}"])
        checked_agent(agent, ["--config", str(configuration), "install-service"])
    except (ValueError, OSError):
        if previous_configuration is not None:
            with tempfile.NamedTemporaryFile(prefix=".sinan-config-rollback-", dir=configuration.parent, delete=False) as output:
                restoration = Path(output.name)
                output.write(previous_configuration)
                output.flush()
                os.fsync(output.fileno())
            restoration.chmod(0o600)
            restoration.replace(configuration)
            # The native CLI restores its previous current link; reload its restored configuration.
            if previous_agent.exists():
                checked_agent(agent, ["verify-installed", "--binary", str(previous_agent), "--name", "agent", "--format", "raw"])
                checked_agent(previous_agent, ["--config", str(configuration), "install-service"])
        raise
    command.parent.mkdir(parents=True, exist_ok=True)
    temporary = command.with_name(".sinan-agent-" + str(os.getpid()))
    temporary.symlink_to(agent_root / "current/sinan-agent")
    temporary.replace(command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Legacy exact release tag")
    parser.add_argument("--version", help="Exact Agent version or latest; defaults to latest")
    parser.add_argument("--target", default="auto", help="Expected server platform or auto")
    parser.add_argument("--panel", required=True)
    parser.add_argument("--token")
    parser.add_argument("--mirror", default="", help="HTTPS prefix for GitHub downloads")
    parser.add_argument("--trusted-keys", default="/etc/sinan/trust/public-keys.json",
                        help="Operator-provisioned root-owned JSON key set, independent of panel")
    parser.add_argument("--minisign", default="minisign")
    parser.add_argument("--trusted-installer", help="Independent root-protected Linux installer; defaults to bundled trusted-install.sh")
    parser.add_argument("--trusted-agent", help="Previously trusted signed Agent for offline proof verification")
    parser.add_argument("--release-dir", help="Pre-downloaded signed release, including Agent binary; offline installation")
    args = parser.parse_args()
    ensure(os.getuid() == 0, "bootstrap requires root")
    if args.tag:
        ensure(args.tag.startswith("agent-v") and VERSION.fullmatch(args.tag[7:]), "invalid tag")
        ensure(args.version is None or args.version == args.tag[7:], "--tag 与 --version 不一致")
    version = args.tag[7:] if args.tag else args.version or "latest"
    ensure(version == "latest" or VERSION.fullmatch(version), "无效 Agent 版本")
    validate_panel_origin(args.panel)
    actual = host_target()
    compatible_targets(actual, args.target)
    mirror = validate_mirror(args.mirror, args.panel)
    token = args.token or os.environ.pop("SINAN_ENROLLMENT_TOKEN", None)
    ensure(token, "provide one-time token through SINAN_ENROLLMENT_TOKEN")
    roots = None if args.trusted_agent else load_roots(args.trusted_keys, require_protected=True)
    if args.release_dir:
        if version == "latest":
            unverified = json.loads(read_regular(Path(args.release_dir) / "release.json", 32768))
            tag = unverified.get("tag", "")
            ensure(isinstance(tag, str) and tag.startswith("agent-v") and VERSION.fullmatch(tag[7:]), "离线 Release 标签无效")
            version = tag[7:]
        candidates = [{"version": version, "tag": "agent-v" + version}]
    elif args.tag:
        candidates = [{"version": version, "tag": args.tag}]
    else:
        candidates = catalog(args.panel, token, actual if args.target == "auto" else args.target, version)
    os.umask(0o077)
    temporary_root = Path("/opt/sinan")
    temporary_root.mkdir(mode=0o755, parents=True, exist_ok=True)
    require_protected_file(temporary_root)
    with tempfile.TemporaryDirectory(prefix="sinan-bootstrap-", dir=temporary_root) as temporary:
        bundle = None
        item = None
        for candidate in candidates:
            release_version, tag = candidate["version"], candidate["tag"]
            selected = Path(temporary) / release_version
            selected.mkdir()
            base = f"https://github.com/{REPOSITORY}/releases/download/{tag}"
            for name, limit in PROOF_FILES:
                if args.release_dir:
                    (selected / name).write_bytes(read_regular(Path(args.release_dir) / name, limit))
                else:
                    download(base, name, selected / name, limit, mirror)
            if args.trusted_agent:
                trusted_agent = Path(args.trusted_agent).resolve(strict=True)
                require_protected_file(trusted_agent)
                ensure(trusted_agent.name == "sinan-agent", "trusted verifier must be the installed Agent")
                for command in ([str(trusted_agent), "verify-installed", "--binary", str(trusted_agent),
                                 "--name", "agent", "--format", "raw"],
                                [str(trusted_agent), "verify-release", "--proof-dir", str(selected)]):
                    result = subprocess.run(command, capture_output=True, check=False)
                    ensure(result.returncode == 0, "previous Agent refused release verification")
                metadata, _ = validate_manifest(selected, tag, protocol_version=None)
            else:
                metadata, _ = verify_manifest(selected, roots, args.minisign, tag, protocol_version=None)
            try:
                item = select_artifact(metadata, release_version, actual, args.target)
            except IncompatibleRelease:
                if version != "latest":
                    raise
                continue
            bundle, version = selected, release_version
            break
        ensure(bundle is not None and item is not None, f"没有通过签名和本机 {actual} 兼容检查的 Agent 版本")
        print(f"已验证 Agent {version}，安装平台 {item['arch']}（本机 {actual}）", flush=True)
        if not actual.startswith("linux-"):
            install_native(bundle, args.panel, token, item, actual, mirror, args.release_dir)
            return

        legacy_checkpoint_preflight(version)

        installer = Path(args.trusted_installer) if args.trusted_installer else Path(__file__).with_name("trusted-install.sh")
        require_protected_file(installer)
        ensure(installer.is_file(), "独立可信 Linux 安装器缺失，请使用官方自包含 bootstrap.sh")
        # The fixed, independently verified bootstrap supplies this executor.
        # Legacy signed install.sh is proof material only and is never executed.
        require_preloaded_installer(installer)
        download_agent(item, bundle / item["asset_name"], mirror, args.release_dir)
        token_file = bundle / ".enrollment-token"
        token_file.write_text(token)
        command = ["/bin/sh", str(installer), "--bundle", str(bundle),
                   "--panel", args.panel, "--version", version, "--token-file", str(token_file)]
        if item["arch"] not in ("amd64", "arm64"):
            command.extend(["--target", item["arch"]])
        result = subprocess.run(command, check=False)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise SystemExit(f"Bootstrap refused: {error}") from error
