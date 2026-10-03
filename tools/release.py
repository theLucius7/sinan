#!/usr/bin/env python3
"""Build canonical release manifests and verify complete offline-signed bundles."""

import argparse
import base64
import contextlib
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile


REPOSITORY = "theLucius7/sinan"
TEST_ONLY_PUBLIC_KEY = "RWS3NbDikg3VqWRlxJMUyaB1dTvErk0ptJ695xQ50Kyb+MmtynMhN/lq"
TEST_ONLY_ROTATION_PUBLIC_KEY = "RWRURVNUUk9UMjMuvo0ny3Mjs6QBwcE7XdZLzMDhDs2hwrXRGgN3moXl"
SOURCE_ROOT = Path(__file__).resolve().parents[1]
TEST_PUBLIC_KEY_DIRS = (SOURCE_ROOT / "fixtures", SOURCE_ROOT / "crates/protocol/tests/fixtures")
NODEQUALITY_VERSION = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22"
SEGMENT = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\Z")
MAX_BINARY = 256 * 1024 * 1024


def ensure(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, limit=MAX_BINARY):
    ensure(path.is_file() and not path.is_symlink(), "asset must be an ordinary file")
    ensure(0 < path.stat().st_size <= limit, "asset size outside permitted range")
    return path.read_bytes()


def regular_file_proof(path, limit=MAX_BINARY, destination=None):
    """Hash or copy a bounded ordinary asset without loading the asset into memory."""
    path = Path(path)
    ensure(path.is_file() and not path.is_symlink(), "asset must be an ordinary file")
    before = path.lstat()
    ensure(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
           and 0 < before.st_size <= limit, "asset size or identity outside permitted range")

    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    value, consumed = hashlib.sha256(), 0
    with os.fdopen(descriptor, "rb") as source:
        ensure(identity(os.fstat(source.fileno())) == identity(before), "asset changed before reading")
        target = Path(destination).open("xb") if destination is not None else contextlib.nullcontext()
        with target as output:
            while True:
                content = source.read(1024 * 1024)
                if not content:
                    break
                consumed += len(content)
                ensure(consumed <= before.st_size and consumed <= limit, "asset grew while reading")
                value.update(content)
                if output is not None:
                    output.write(content)
        ensure(consumed == before.st_size and identity(os.fstat(source.fileno())) == identity(before)
               and identity(path.lstat()) == identity(before), "asset changed while reading")
    return {"sha256": value.hexdigest(), "size": consumed}


def source_offer_asset_limit(name):
    """Only the fixed paired IPQuality source assets may exceed the binary bound."""
    if not isinstance(name, str) or not re.fullmatch(
            r"ipquality-[0-9A-Za-z.+_-]+-linux-(?:amd64|arm64)-sources\.tar\.gz", name):
        return MAX_BINARY
    from ipquality_artifact import MAX_SOURCE_OFFER, VERSION as IPQUALITY_VERSION
    if name in {f"ipquality-{IPQUALITY_VERSION}-linux-{arch}-sources.tar.gz"
                for arch in ("amd64", "arm64")}:
        return MAX_SOURCE_OFFER
    return MAX_BINARY


def source_offer_url(tag, asset):
    ensure(isinstance(tag, str) and tag.startswith("agent-v") and VERSION.fullmatch(tag[7:]),
           "invalid source-offer release tag")
    ensure(source_offer_asset_limit(asset) != MAX_BINARY, "invalid source-offer asset identity")
    return f"https://github.com/{REPOSITORY}/releases/download/{tag}/{asset}"


def canonical_path(entry):
    ensure(entry["name"] in ("agent", "sing-box", "nodequality", "tcpquality", "ipquality"), "unsupported module")
    ensure(SEGMENT.fullmatch(entry["version"]), "invalid version segment")
    ensure(entry["arch"] in ("amd64", "arm64", "linux-gnu-amd64", "linux-gnu-arm64", "linux-musl-amd64", "linux-musl-arm64", "macos-arm64", "freebsd-amd64", "freebsd-arm64", "windows-amd64", "windows-arm64"), "unsupported architecture")
    return "/".join(entry[k] for k in ("name", "version", "arch"))


def asset_name(entry):
    name, version, arch = (entry[k] for k in ("name", "version", "arch"))
    ensure(entry["format"] in ("raw", "tar.gz"), "unsupported format")
    if arch not in ("amd64", "arm64"):
        return f"{name}-{version}-{arch}" + (".tar.gz" if entry["format"] == "tar.gz" else "")
    return (f"{name}-{version}-linux-musl-{arch}" if entry["format"] == "raw"
            else f"{name}-{version}-linux-{arch}.tar.gz")


def validate_auxiliary_files(value, binary_name, archive_format):
    ensure(isinstance(value, dict) and len(value) <= 7, "invalid auxiliary file list")
    ensure(not value or archive_format == "tar.gz", "raw artifacts cannot contain auxiliary files")
    for name, entry in value.items():
        ensure(isinstance(name, str) and re.fullmatch(r"[0-9A-Za-z._-]{1,128}", name)
               and name not in (".", "..", binary_name, "release.json", "SHA256SUMS",
                                "SHA256SUMS.minisig", ".artifact.json") and not name.startswith("-"),
               "invalid auxiliary file name")
        ensure(isinstance(entry, dict) and set(entry) == {"sha256", "size"},
               "invalid auxiliary file metadata")
        ensure(type(entry["size"]) is int and 0 < entry["size"] <= MAX_BINARY,
               "invalid auxiliary file size")
        ensure(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
               "invalid auxiliary file digest")
    return value


def binary_bytes(data, archive_format, binary_name, auxiliary_files=None):
    auxiliary = validate_auxiliary_files(auxiliary_files if auxiliary_files is not None else {},
                                         binary_name, archive_format)
    if archive_format == "raw":
        return data
    ensure(archive_format == "tar.gz", "unsupported format")
    expected = {binary_name} | set(auxiliary)
    seen, binary, consumed = set(), None, 0
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as compressed:
        def read(size):
            nonlocal consumed
            content = compressed.read(min(size, MAX_BINARY - consumed + 1))
            consumed += len(content)
            ensure(consumed <= MAX_BINARY, "archive exceeds unpacked size limit")
            return content

        while True:
            header = read(tarfile.BLOCKSIZE)
            ensure(len(header) in (0, tarfile.BLOCKSIZE), "truncated archive header")
            if not header or not any(header):
                break
            try:
                member = tarfile.TarInfo.frombuf(header, encoding="utf-8", errors="strict")
            except tarfile.HeaderError as error:
                raise ValueError("invalid archive header") from error
            ensure(member.name in expected and member.name not in seen
                   and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE), "unsafe archive member")
            seen.add(member.name)
            ensure(0 < member.size <= MAX_BINARY, "invalid archive member size")
            if member.name != binary_name:
                ensure(member.size == auxiliary[member.name]["size"], "auxiliary file size mismatch")
            content = read(member.size)
            ensure(len(content) == member.size, "archive file length mismatch")
            if member.name == binary_name:
                binary = content
            else:
                ensure(digest(content) == auxiliary[member.name]["sha256"], "auxiliary file digest mismatch")
            padding = (-member.size) % tarfile.BLOCKSIZE
            ensure(len(read(padding)) == padding, "truncated archive padding")
        ensure(seen == expected, "archive does not contain the exact signed file set")
        while True:
            tail = read(8192)
            if not tail:
                break
            ensure(not any(tail), "archive contains trailing data")
    return binary


def assemble(args):
    ensure(VERSION.fullmatch(args.agent_version), "invalid Agent version")
    ensure(args.tag == "agent-v" + args.agent_version, "tag differs from Agent version")
    source, output = Path(args.source), Path(args.output)
    ensure(not output.exists(), "release output already exists")
    output.mkdir(parents=True)
    paths, artifacts = {}, []
    architectures = getattr(args, "arch", None) or ("amd64", "arm64")
    ensure(len(set(architectures)) == len(architectures)
           and set(architectures) <= {"amd64", "arm64"}, "invalid or duplicate architecture")
    modules = [
        ("agent", args.agent_version, "raw", "sinan-agent"),
        ("sing-box", args.runtime_version, "tar.gz", "sing-box"),
        ("nodequality", getattr(args, "nodequality_version", NODEQUALITY_VERSION), "tar.gz", "nodequality"),
    ]
    if getattr(args, "tcp_probe_version", None) is not None:
        modules.append(("tcpquality", args.tcp_probe_version, "tar.gz", "sinan-tcp-probe"))
    if getattr(args, "ipquality_version", None) is not None:
        modules.append(("ipquality", args.ipquality_version, "tar.gz", "ipquality"))
    for name, version, archive_format, binary_name in modules:
        for arch in architectures:
            entry = {"name": name, "version": version, "arch": arch,
                     "format": archive_format, "binary_name": binary_name}
            path = canonical_path(entry)
            data = read_regular(source / path)
            auxiliary = {}
            if name == "tcpquality":
                from tcp_probe_artifact import archive_files, validate_files
                files = archive_files(data)
                validate_files(files, version, arch)
                auxiliary = {name: {"sha256": digest(content), "size": len(content)}
                             for name, content in files.items() if name != binary_name}
                entry["auxiliary_files"] = auxiliary
            if name == "ipquality":
                from ipquality_artifact import (MAX_SOURCE_OFFER, archive_files, source_offer,
                                               validate_files, validate_source_offer)
                files = archive_files(data)
                validate_files(files, version, arch)
                offer = source_offer(files, version, arch)
                paired = source / name / version / (arch + ".sources.tar.gz")
                validate_source_offer(paired, files, version, arch)
                proof = regular_file_proof(paired, MAX_SOURCE_OFFER, output / offer["asset"])
                ensure(proof == {key: offer[key] for key in ("sha256", "size")},
                       "paired source archive differs from the signed declaration")
                auxiliary = {name: {"sha256": digest(content), "size": len(content)}
                             for name, content in files.items() if name != binary_name}
                entry["auxiliary_files"] = auxiliary
            if name == "nodequality" and version in {"a92fca6c0067df29ddd03fdc2fee6f3000f64545-r20", "a92fca6c0067df29ddd03fdc2fee6f3000f64545-offline-rootfs-r1"}:
                if version.endswith("-offline-rootfs-r1"):
                    from nodequality_native_rootfs_artifact import archive_files, validate_files
                else:
                    from nodequality_rootfs_artifact import archive_files, validate_files
                files = archive_files(data)
                validate_files(files, version, arch)
                auxiliary = {name: {"sha256": digest(content), "size": len(content)}
                             for name, content in files.items() if name != binary_name}
                entry["auxiliary_files"] = auxiliary
            if name == "nodequality" and version == "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r21":
                from nodequality_node_query_artifact import archive_files, validate_files
                validate_files(archive_files(data), version, arch)
            binary = binary_bytes(data, archive_format, binary_name, auxiliary)
            entry.update(archive_size=len(data), binary_sha256=digest(binary),
                         binary_size=len(binary), asset_name=asset_name(entry))
            (output / entry["asset_name"]).write_bytes(data)
            paths[path] = digest(data)
            artifacts.append(entry)
    artifacts.sort(key=canonical_path)
    metadata = {"schema": 1, "source_repo": REPOSITORY, "tag": args.tag,
                "protocol_min": 1, "protocol_max": 1, "artifacts": artifacts}
    encoded = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ensure(len(encoded) <= 32768, "metadata too large")
    (output / "release.json").write_bytes(encoded)
    installer = read_regular(Path(args.installer), 256 * 1024)
    (output / "install.sh").write_bytes(installer)
    paths.update({"release.json": digest(encoded), "install.sh": digest(installer)})
    checksums = "".join(f"{paths[path]}  {path}\n" for path in sorted(paths))
    ensure(len(checksums.encode()) <= 8192, "checksums too large")
    (output / "SHA256SUMS").write_bytes(checksums.encode("utf-8"))


def installer_source(template, agent_unit, runtime_unit, source_root=SOURCE_ROOT):
    """Render audited static Linux installation logic for release or trusted bootstrap."""
    source_root = Path(source_root)
    text = read_regular(Path(template), 262144).decode("utf-8")
    if "@@LEGACY_CHECKPOINT_PREFLIGHT@@" in text:
        ensure(text.count("@@LEGACY_CHECKPOINT_PREFLIGHT@@") == 2, "missing or duplicate legacy preflight marker")
        guard = read_regular(source_root / "tools/legacy_agent_checkpoint.py", 65536).decode("utf-8")
        text = text.replace("@@LEGACY_CHECKPOINT_PREFLIGHT@@", guard.rstrip())
    for marker, filename in (("@@AGENT_UNIT@@", agent_unit),
                             ("@@RUNTIME_UNIT@@", runtime_unit)):
        ensure(text.count(marker) == 1, "missing or duplicate installer unit marker")
        text = text.replace(marker, read_regular(Path(filename), 65536).decode("utf-8").rstrip())
    for marker, filename in (("@@AGENT_OPENRC@@", source_root / "deploy/sinan-agent.openrc"),
                             ("@@RUNTIME_OPENRC@@", source_root / "plugins/sing-box/sinan-singbox.openrc")):
        if marker in text:
            ensure(text.count(marker) == 1, "duplicate installer unit marker")
            text = text.replace(marker, read_regular(filename, 65536).decode("utf-8").rstrip())
    ensure("@@" not in text, "unexpanded installer marker")
    return text


def render_installer(args):
    text = installer_source(args.template, args.agent_unit, args.runtime_unit)
    output = Path(args.output)
    ensure(not output.exists(), "installer output exists")
    output.write_bytes(text.encode("utf-8"))


def public_record(key):
    ensure(isinstance(key, str) and len(key.encode()) <= 4096, "invalid public key")
    lines = key.splitlines()
    record = lines[-1] if len(lines) in (1, 2) else ""
    if len(lines) == 2:
        ensure(lines[0].startswith("untrusted comment: "), "invalid public key comment")
    binary = base64.b64decode(record, validate=True)
    ensure(len(binary) == 42 and binary[:2] == b"Ed", "invalid minisign public key")
    return record, binary[10:]


def test_public_material():
    # Include the known roots when trusted bootstrap tools are copied without tests.
    denied = {public_record(key)[1] for key in
              (TEST_ONLY_PUBLIC_KEY, TEST_ONLY_ROTATION_PUBLIC_KEY)}
    for directory in TEST_PUBLIC_KEY_DIRS:
        for path in directory.glob("TEST_ONLY*.pub"):
            denied.add(public_record(read_regular(path, 4096).decode("utf-8"))[1])
    return denied


def load_roots(path, publication=False, require_protected=False):
    path = Path(path)
    if require_protected:
        for part in (path,) + tuple(path.parents):
            stat = part.lstat()
            ensure(not part.is_symlink() and stat.st_uid == 0 and stat.st_mode & 0o022 == 0,
                   "bootstrap trust file and parents must be root-owned and protected")
    value = json.loads(read_regular(path, 32768))
    ensure(isinstance(value, list) and 0 < len(value) <= 8, "invalid trusted key set")
    denied = test_public_material() if publication else set()
    roots, public_material = [], set()
    for key in value:
        record, material = public_record(key)
        ensure(material not in public_material, "duplicate public key")
        if publication:
            ensure(material not in denied, "TEST_ONLY key cannot publish an official release")
        roots.append(record)
        public_material.add(material)
    return roots


def require_protected_file(path):
    path = Path(path)
    for part in (path,) + tuple(path.parents):
        stat = part.lstat()
        ensure(not part.is_symlink() and stat.st_uid == 0 and stat.st_mode & 0o022 == 0,
               "trusted file and parents must be root-owned and protected")


def verify_signature(bundle, roots, minisign):
    signature = read_regular(bundle / "SHA256SUMS.minisig", 16384).decode("utf-8")
    lines = signature.splitlines()
    ensure(len(lines) == 4 and lines[0].startswith("untrusted comment: ")
           and lines[2].startswith("trusted comment: "), "signature must contain all four minisign lines")
    ensure(base64.b64decode(lines[1], validate=True)[:2] == b"ED", "legacy signature prohibited")
    for key in roots:
        result = subprocess.run([minisign, "-V", "-H", "-q", "-m", str(bundle / "SHA256SUMS"),
                                 "-x", str(bundle / "SHA256SUMS.minisig"), "-P", key],
                                capture_output=True, check=False)
        if result.returncode == 0:
            return
    raise ValueError("no trusted key verifies the complete signature")


def verify_manifest(bundle, roots, minisign, expected_tag=None, protocol_version=1):
    verify_signature(Path(bundle), roots, minisign)
    return validate_manifest(bundle, expected_tag, protocol_version)


def validate_manifest(bundle, expected_tag=None, protocol_version=1):
    """Validate contents only after an independently successful signature verifier."""
    bundle = Path(bundle)
    ensure(not bundle.is_symlink(), "bundle must not be a symlink")
    checksums = read_regular(bundle / "SHA256SUMS", 8192).decode("utf-8")
    rows = {}
    for line in checksums.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([0-9A-Za-z.+_/-]+)", line)
        ensure(match is not None, "noncanonical checksum entry")
        value, path = match.groups()
        ensure(path not in rows and not path.startswith("/") and ".." not in path.split("/"),
               "duplicate or unsafe checksum path")
        rows[path] = value
    canonical = "".join(f"{rows[path]}  {path}\n" for path in sorted(rows))
    ensure(checksums == canonical, "checksums must be sorted canonical LF text")
    metadata_bytes = read_regular(bundle / "release.json", 32768)
    ensure(rows.get("release.json") == digest(metadata_bytes), "metadata hash mismatch")
    metadata = json.loads(metadata_bytes)
    ensure(set(metadata) == {"schema", "source_repo", "tag", "protocol_min", "protocol_max", "artifacts"},
           "unexpected metadata fields")
    ensure(type(metadata["schema"]) is int and metadata["schema"] == 1
           and metadata["source_repo"] == REPOSITORY, "wrong release identity")
    ensure(type(metadata["protocol_min"]) is int and type(metadata["protocol_max"]) is int
           and 1 <= metadata["protocol_min"] <= metadata["protocol_max"] <= 65535
           and (protocol_version is None
                or metadata["protocol_min"] <= protocol_version <= metadata["protocol_max"]),
           "unsupported protocol range")
    ensure(expected_tag is None or metadata["tag"] == expected_tag, "wrong release tag")
    ensure(isinstance(metadata["artifacts"], list) and 0 < len(metadata["artifacts"]) <= 30,
           "invalid artifact list")
    expected_paths = {"release.json", "install.sh"}
    for entry in metadata["artifacts"]:
        required = {"name", "version", "arch", "format", "binary_name", "archive_size",
                    "binary_sha256", "binary_size", "asset_name"}
        ensure(isinstance(entry, dict) and set(entry) in (required, required | {"auxiliary_files"}),
               "unexpected artifact fields")
        path = canonical_path(entry)
        ensure(path not in expected_paths, "duplicate artifact identity")
        expected_paths.add(path)
        ensure(entry["asset_name"] == asset_name(entry), "asset name differs from signed identity")
        ensure(type(entry["archive_size"]) is int and 0 < entry["archive_size"] <= MAX_BINARY
               and type(entry["binary_size"]) is int and 0 < entry["binary_size"] <= MAX_BINARY,
               "invalid signed sizes")
        ensure(isinstance(entry["binary_sha256"], str)
               and re.fullmatch(r"[0-9a-f]{64}", entry["binary_sha256"]), "invalid binary digest")
        ensure(isinstance(entry["binary_name"], str) and SEGMENT.fullmatch(entry["binary_name"])
               and entry["binary_name"] not in (".", ".."), "invalid signed binary name")
        validate_auxiliary_files(entry.get("auxiliary_files", {}), entry["binary_name"], entry["format"])
        if entry["name"] == "tcpquality":
            from tcp_probe_artifact import BINARY, FILES, TOOL_VERSION
            ensure(entry["format"] == "tar.gz" and entry["binary_name"] == BINARY
                   and entry["arch"] in ("amd64", "arm64")
                   and re.fullmatch(re.escape(TOOL_VERSION) + r"-[0-9a-f]{40}-r1", entry["version"])
                   and set(entry.get("auxiliary_files", {})) == FILES - {BINARY},
                   "wrong or incomplete native TCP artifact identity")
        if entry["name"] == "ipquality":
            from ipquality_artifact import BINARY, FILES, VERSION as IPQUALITY_VERSION
            ensure(entry["format"] == "tar.gz" and entry["binary_name"] == BINARY
                   and entry["arch"] in ("amd64", "arm64")
                   and entry["version"] == IPQUALITY_VERSION
                   and set(entry.get("auxiliary_files", {})) == FILES - {BINARY},
                   "wrong or incomplete offline IPQuality artifact identity")
        if entry["name"] == "nodequality" and entry["version"] in {"a92fca6c0067df29ddd03fdc2fee6f3000f64545-r20", "a92fca6c0067df29ddd03fdc2fee6f3000f64545-offline-rootfs-r1"}:
            from nodequality_rootfs_artifact import BINARY, FILES
            ensure(entry["format"] == "tar.gz" and entry["binary_name"] == BINARY
                   and entry["arch"] in ("amd64", "arm64")
                   and set(entry.get("auxiliary_files", {})) == FILES - {BINARY},
                   "wrong or incomplete offline NodeQuality artifact identity")
        if entry["name"] == "nodequality" and entry["version"] not in {"a92fca6c0067df29ddd03fdc2fee6f3000f64545-r20", "a92fca6c0067df29ddd03fdc2fee6f3000f64545-offline-rootfs-r1"}:
            ensure(not entry.get("auxiliary_files"),
                   "runner-only NodeQuality identity cannot claim offline auxiliary files")
        if entry["name"] == "nodequality" and entry["version"] == "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r21":
            from nodequality_node_query_artifact import BINARY
            ensure(entry["format"] == "tar.gz" and entry["binary_name"] == BINARY
                   and entry["arch"] in ("amd64", "arm64")
                   and not entry.get("auxiliary_files", {}),
                   "wrong official node-query artifact identity")
        if entry["name"] == "agent":
            binary_name = "sinan-agent.exe" if entry["arch"].startswith("windows-") else "sinan-agent"
            ensure(metadata["tag"] == "agent-v" + entry["version"] and entry["format"] == "raw"
                   and entry["binary_name"] == binary_name, "wrong Agent release identity")
        if entry["format"] == "raw":
            ensure(entry["archive_size"] == entry["binary_size"]
                   and rows.get(path) == entry["binary_sha256"], "raw binary proof mismatch")
    ensure(set(rows) == expected_paths, "unsigned or unused checksum paths")
    ensure(rows["install.sh"] == digest(read_regular(bundle / "install.sh", 256 * 1024)), "installer mismatch")
    return metadata, rows


def verify_bundle(bundle, roots, minisign, expected_tag=None, exact_assets=True):
    bundle = Path(bundle)
    metadata, rows = verify_manifest(bundle, roots, minisign, expected_tag)
    expected_files = {"release.json", "install.sh", "SHA256SUMS", "SHA256SUMS.minisig"}
    for entry in metadata["artifacts"]:
        path = canonical_path(entry)
        expected_files.add(entry["asset_name"])
        data = read_regular(bundle / entry["asset_name"])
        ensure(len(data) == entry["archive_size"] and rows.get(path) == digest(data), "archive mismatch")
        binary = binary_bytes(data, entry["format"], entry["binary_name"], entry.get("auxiliary_files", {}))
        ensure(len(binary) == entry["binary_size"] and digest(binary) == entry["binary_sha256"], "binary mismatch")
        if entry["name"] == "tcpquality":
            from tcp_probe_artifact import archive_files, validate_files
            validate_files(archive_files(data), entry["version"], entry["arch"])
        if entry["name"] == "ipquality":
            from ipquality_artifact import (MAX_SOURCE_OFFER, archive_files, source_offer,
                                           validate_files, validate_source_offer)
            files = archive_files(data)
            validate_files(files, entry["version"], entry["arch"])
            offer = source_offer(files, entry["version"], entry["arch"])
            expected_files.add(offer["asset"])
            paired = bundle / offer["asset"]
            ensure(regular_file_proof(paired, MAX_SOURCE_OFFER)
                   == {key: offer[key] for key in ("sha256", "size")},
                   "paired source archive differs from the signed declaration")
            validate_source_offer(paired, files, entry["version"], entry["arch"])
        if entry["name"] == "nodequality" and entry["version"] == "a92fca6c0067df29ddd03fdc2fee6f3000f64545-offline-rootfs-r1":
            from nodequality_native_rootfs_artifact import archive_files, validate_files
            validate_files(archive_files(data), entry["version"], entry["arch"])
        if entry["name"] == "nodequality" and entry["version"] == "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r20":
            from nodequality_rootfs_artifact import archive_files, validate_files
            validate_files(archive_files(data), entry["version"], entry["arch"])
        if entry["name"] == "nodequality" and entry["version"] == "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r21":
            from nodequality_node_query_artifact import archive_files, validate_files
            validate_files(archive_files(data), entry["version"], entry["arch"])
    if exact_assets:
        ensure({p.name for p in bundle.iterdir()} == expected_files, "missing or extra release assets")
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("assemble")
    for argument in ("source", "output", "tag", "agent-version", "runtime-version", "installer"):
        build.add_argument("--" + argument, required=True)
    build.add_argument("--nodequality-version", default=NODEQUALITY_VERSION)
    build.add_argument("--tcp-probe-version", help="opt-in native TCP version with its full source SHA")
    build.add_argument("--ipquality-version", help="opt-in fixed standalone IPQuality version with its complete signed offline profile")
    build.add_argument("--arch", action="append", choices=("amd64", "arm64"),
                       help="CI test bundle architectures; production requires both")
    render = commands.add_parser("render-installer")
    for argument in ("template", "agent-unit", "runtime-unit", "output"):
        render.add_argument("--" + argument, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--trusted-keys", required=True)
    verify.add_argument("--minisign", default="minisign")
    verify.add_argument("--tag")
    verify.add_argument("--publication", action="store_true")
    args = parser.parse_args()
    if args.command == "assemble":
        assemble(args)
    elif args.command == "render-installer":
        render_installer(args)
    else:
        roots = load_roots(args.trusted_keys, args.publication)
        verify_bundle(args.bundle, roots, args.minisign, args.tag)
        print("Complete signature, canonical metadata, installer, and every artifact verified.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise SystemExit(f"Release verification failed: {error}") from error
