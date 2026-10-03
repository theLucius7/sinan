#!/usr/bin/env python3
"""Render the standalone official bootstrap from audited source files."""

import argparse
import base64
import hashlib
import json
import lzma
import os
from pathlib import Path
import stat
import sys

from release import ensure, installer_source, load_roots
import nodequality_history as history
import nodequality_native_rootfs_artifact as native_rootfs
import nodequality_rootfs_artifact as legacy_rootfs

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("tools/bootstrap.py", "tools/legacy_agent_checkpoint.py", "tools/release.py", "tools/tcp_probe_artifact.py",
           "tools/tcp_probe_notices.py", "tools/artifact_manifest.py",
           "tools/nodequality_rootfs_artifact.py", "tools/nodequality_node_query_artifact.py",
           "tools/nodequality_native_rootfs_artifact.py", "tools/nodequality_history.py",
           "tools/ipquality_artifact.py", "tools/ipquality-rootfs.py", "tools/ipquality-profile.py",
           "tools/ipquality-inputs.py", "tools/ipquality-inputs-capacity.py",
           "tools/nodequality-rootfs-build.py", "tools/nodequality-rootfs-collect.py",
           "tools/build-ipquality.py", "LICENSE",
           "deploy/release-public-keys.json")
PLUGIN_SOURCES = tuple("plugins/nodequality/" + name for name in sorted(
    set(legacy_rootfs.HELPERS.values()) | set(native_rootfs.HELPERS.values())
    | {"source-lock.json", "node-query.py", "rootfs.py"}
    | {"historical-r19/" + name for name in history.IDENTITIES}
    | {"historical-native-r1/" + name for name in history.NATIVE_IDENTITIES}
)) + tuple("plugins/ipquality/" + name for name in (
    "runner.py", "source-lock.json", "source-helper.py", "source-policy.py", "transport.py", "SOURCE.md"
))
MAX_PAYLOAD = 2 * 1024 * 1024
MAX_BOOTSTRAP = 256 * 1024
PAYLOAD_BEGIN = "SINAN_BOOTSTRAP_FILES_PY"


def ordinary_source(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        ensure(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= MAX_BOOTSTRAP,
               "bootstrap input must be a bounded ordinary source")
        content = stream.read(MAX_BOOTSTRAP + 1)
    ensure(len(content) == metadata.st_size, "bootstrap source size changed during reading")
    return content


def source_files(root, trusted_keys, installer):
    files = {}
    for filename in SOURCES + PLUGIN_SOURCES:
        path = trusted_keys if filename == SOURCES[-1] else root / filename
        content = ordinary_source(path)
        if filename.startswith("plugins/nodequality/historical-r19/"):
            ensure(hashlib.sha256(content).hexdigest() == history.IDENTITIES[path.name]
                   and len(content) <= history.MAX_FILE, "historical r19 source identity mismatch")
        if filename.startswith("plugins/nodequality/historical-native-r1/"):
            ensure(hashlib.sha256(content).hexdigest() == history.NATIVE_IDENTITIES[path.name]
                   and len(content) <= history.MAX_FILE, "historical native source identity mismatch")
        destination = "public-keys.json" if filename == SOURCES[-1] else filename
        files[destination] = content
    files["tools/trusted-install.sh"] = installer.encode("utf-8")
    ensure(0 < len(files["tools/trusted-install.sh"]) <= MAX_BOOTSTRAP, "trusted installer exceeds byte budget")
    return files


def materializer(files):
    manifest = {name: {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                for name, content in sorted(files.items())}
    payload = json.dumps({name: content.decode("utf-8") for name, content in sorted(files.items())},
                         ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ensure(len(payload) <= MAX_PAYLOAD, "bootstrap source closure exceeds byte budget")
    compressed = lzma.compress(payload, format=lzma.FORMAT_XZ,
                               filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1024 * 1024}])
    encoded = base64.b85encode(compressed).decode("ascii")
    # Keep every source at its repository-relative location. Historical readers
    # and artifact derivations use __file__ to resolve this private source tree.
    return f'''import base64, hashlib, json, lzma, os, pathlib, sys
manifest = {manifest!r}
payload = {encoded!r}
compressed = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=8 * 1024 * 1024)
content = compressed.decompress(base64.b85decode(payload), max_length={MAX_PAYLOAD} + 1)
if len(content) > {MAX_PAYLOAD} or not compressed.eof or compressed.unused_data:
    raise ValueError("bootstrap source closure exceeds byte budget")
sources = json.loads(content)
if not isinstance(sources, dict) or set(sources) != set(manifest):
    raise ValueError("bootstrap source closure differs from its fixed inventory")
verified = {{}}
for name, identity in manifest.items():
    value = sources[name]
    if not isinstance(value, str):
        raise ValueError("bootstrap source must be UTF-8 text")
    data = value.encode("utf-8")
    if len(data) != identity["size"] or hashlib.sha256(data).hexdigest() != identity["sha256"]:
        raise ValueError("bootstrap source size or digest differs")
    relative = pathlib.PurePosixPath(name)
    if (relative.is_absolute() or str(relative) != name
            or any(part in ("", ".", "..") for part in relative.parts)):
        raise ValueError("bootstrap source path is not canonical")
    verified[name] = data
root = pathlib.Path(sys.argv[1])
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
root_descriptor = os.open(root, directory_flags)
try:
    for name, data in verified.items():
        relative = pathlib.PurePosixPath(name)
        parent_descriptor = os.dup(root_descriptor)
        try:
            for part in relative.parts[:-1]:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=parent_descriptor)
                except FileExistsError:
                    pass
                child_descriptor = os.open(part, directory_flags, dir_fd=parent_descriptor)
                os.close(parent_descriptor)
                parent_descriptor = child_descriptor
            descriptor = os.open(relative.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent_descriptor)
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
        finally:
            os.close(parent_descriptor)
finally:
    os.close(root_descriptor)
'''


def render(root=ROOT, trusted_keys=None, publication=True, test_installer=None):
    root = Path(root)
    trusted_keys = Path(trusted_keys) if trusted_keys else root / SOURCES[-1]
    load_roots(trusted_keys, publication=publication)
    ensure(test_installer is None or not publication, "test installer cannot be published")
    installer = test_installer if test_installer is not None else installer_source(
        root / "deploy/install.sh.tmpl", root / "deploy/sinan-agent.service",
        root / "plugins/sing-box/sinan-singbox@.service", source_root=root)
    if not installer.endswith("\n"):
        installer += "\n"
    program = materializer(source_files(root, trusted_keys, installer))
    section = f'"$PYTHON" -I - "$STAGING" <<\'{PAYLOAD_BEGIN}\'\n{program}{PAYLOAD_BEGIN}\n'
    template = (root / "deploy/bootstrap.sh.tmpl").read_text()
    if template.count("@@BOOTSTRAP_FILES@@") != 1:
        raise ValueError("bootstrap template must contain one source marker")
    rendered = template.replace("@@BOOTSTRAP_FILES@@", section)
    ensure(len(rendered.encode("utf-8")) <= MAX_BOOTSTRAP,
           "bootstrap exceeds pinned download size budget: " + str(len(rendered.encode("utf-8"))))
    return rendered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "deploy/bootstrap.sh")
    args = parser.parse_args()
    rendered = render()
    if args.check:
        if not args.output.is_file() or args.output.read_text() != rendered:
            print("bootstrap.sh is stale; run python3 tools/render-bootstrap.py", file=sys.stderr)
            raise SystemExit(1)
    else:
        args.output.write_text(rendered)
        args.output.chmod(0o755)


if __name__ == "__main__":
    main()
