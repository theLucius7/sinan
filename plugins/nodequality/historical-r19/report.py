#!/usr/bin/env python3
"""Capture and render bounded upstream reports without extracting ZIP paths."""

import base64
import fcntl
import io
import json
import os
import pathlib
import re
import sys
import stat
import tempfile
import time
import zipfile


MAX_CAPTURE = 12 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
MAX_TEXT = 256 * 1024
MAX_SECTION = 64 * 1024
SECTIONS = (
    ("header_info", "报告信息"),
    ("hardware_quality", "硬件质量"),
    ("ip_quality", "IP 质量"),
    ("net_quality", "网络质量"),
    ("backroute_trace", "回程路由"),
)
ALLOWED = {
    "header_info.log", "hardware_quality.log", "hardware_quality.json",
    "ip_quality.log", "ip_quality.json", "net_quality.log", "net_quality.json",
    "backroute_trace.log", "backroute_trace.json", "port.log", "yabs.json",
    "basic_info.log",
}


def write_atomic(path, data):
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    temporary = pathlib.Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
            target.flush()
            os.fchmod(target.fileno(), 0o600)
            os.fsync(target.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def clean_text(text):
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(c for c in text if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)


def capture(root):
    data = sys.stdin.buffer.read(MAX_CAPTURE + 1)
    if len(data) > MAX_CAPTURE:
        raise ValueError("report upload exceeds its size limit")
    write_atomic(root / "upload.base64", data)
    try:
        _, files = archive_files(root)
        publish_sections(root, files, archive=True)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        pass


def stream_log(path):
    tail = b""
    while True:
        block = sys.stdin.buffer.read1(8192)
        if not block:
            break
        tail = (tail + block)[-MAX_TEXT:]
        write_atomic(path, tail)
    if not tail:
        write_atomic(path, b"")


def capture_response(root):
    first = b""
    tail = b""
    while True:
        block = sys.stdin.buffer.read1(8192)
        if not block:
            break
        first = (first + block)[:65536]
        tail = (tail + block)[-64:]
    status = re.search(rb"\nSINAN_RESPONSE_STATUS:(\d{3})$", tail)
    if status and first.endswith(status[0]):
        first = first[:-len(status[0])]
    write_atomic(root / "upload-response.txt", first)
    write_atomic(root / "upload-status.txt", status[1] if status else b"")
    sys.stdout.buffer.write(first)


def validate_json(data):
    text = data.decode("utf-8")
    decoder = json.JSONDecoder()
    count = 0
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        if not isinstance(value, dict) or not value:
            raise ValueError("upstream report JSON must contain objects")
        count += 1
        text = text.lstrip()[end:]
    if not count:
        raise ValueError("upstream report JSON is empty")


def archive_files(root):
    capture_path = root / "upload.base64"
    with capture_path.open("rb") as source:
        encoded = source.read(MAX_CAPTURE + 1)
    if len(encoded) > MAX_CAPTURE:
        raise ValueError("report upload exceeds its size limit")
    archive_bytes = base64.b64decode(b"".join(encoded.split()), validate=True)
    files = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        records = archive.infolist()
        if len(records) > len(ALLOWED):
            raise ValueError("report archive contains too many entries")
        for record in records:
            if record.filename not in ALLOWED or record.filename in files or record.is_dir():
                raise ValueError("report archive contains an unexpected or duplicate path")
            total += record.file_size
            if record.file_size > 8 * 1024 * 1024 or total > MAX_UNPACKED:
                raise ValueError("report archive exceeds its uncompressed size limit")
            files[record.filename] = archive.read(record)
    return archive_bytes, files


def bounded_text(data):
    text = clean_text(data.decode("utf-8", errors="replace")).strip()
    encoded = text.encode("utf-8")
    if len(encoded) <= MAX_SECTION:
        return text
    suffix = "\n章节文本已截断；如已生成压缩包，完整原始结果保存在本地 report.zip。".encode("utf-8")
    return encoded[:MAX_SECTION-len(suffix)].decode("utf-8", errors="ignore") + suffix.decode("utf-8")


def save_section(root, name, text, complete):
    if not text:
        return
    # Capture, the live watcher and cleanup share this stable private lock inode.
    descriptor = os.open(root / ".sections.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError("chapter publication lock is not an ordinary file")
        fcntl.flock(lock, fcntl.LOCK_EX)
        save_section_locked(root, name, text, complete)


def save_section_locked(root, name, text, complete):
    path = root / ("section-" + name + ".json")
    previous = {}
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024:
            raise ValueError("chapter output is not a bounded ordinary file")
        previous = json.loads(path.read_text())
        if (not isinstance(previous, dict) or previous.get("name") != name
                or not isinstance(previous.get("text"), str)
                or type(previous.get("complete")) is not bool
                or type(previous.get("revision")) is not int
                or not 1 <= previous["revision"] <= 2**63 - 1):
            raise ValueError("saved chapter metadata is invalid")
    if previous.get("complete") and not complete:
        return
    if previous.get("text") == text and previous.get("complete") == complete:
        return
    if previous.get("revision", 0) == 2**63 - 1:
        raise ValueError("saved chapter revision is exhausted")
    chapter = {"name": name, "text": text, "complete": complete,
               "revision": previous.get("revision", 0) + 1, "collected_at": int(time.time())}
    write_atomic(path, json.dumps(chapter, ensure_ascii=False).encode("utf-8"))


def publish_sections(root, files, archive=False):
    failed = []
    for index, (name, _) in enumerate(SECTIONS):
        text = bounded_text(files.get(name + ".log", b""))
        if not text:
            continue
        valid = name == "header_info"
        if not valid:
            try:
                validate_json(files.get(name + ".json", b""))
                valid = True
            except (ValueError, UnicodeError):
                pass
        # The pinned entry runs stages sequentially. A following log proves that
        # the preceding pipeline finished; archive capture proves the last stage.
        following = any(other + ".log" in files for other, _ in SECTIONS[index + 1:])
        try:
            save_section(root, name, text, valid and (archive or following))
        except (OSError, ValueError):
            # Keep the rejected sidecar untouched and publish the other chapters
            # before reporting failure to the collector or live watcher.
            failed.append(name)
    if failed:
        raise ValueError("chapter publication failed: " + ", ".join(failed))


def snapshot(root):
    capture_path = root / "upload.base64"
    if capture_path.is_file() and not capture_path.is_symlink():
        try:
            _, files = archive_files(root)
            publish_sections(root, files, archive=True)
            return
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
            pass
    directories = list(root.glob(".nodequality*/BenchOs/result"))[:8]
    for directory in directories:
        if directory.is_symlink() or not directory.is_dir():
            continue
        if any(parent.is_symlink() for parent in (directory.parent, directory.parent.parent)):
            continue
        if not directory.resolve().is_relative_to(root.resolve()):
            continue
        files = {}
        for name, _ in SECTIONS:
            for extension, limit in (("log", 8 * 1024 * 1024), ("json", 2 * 1024 * 1024)):
                path = directory / (name + "." + extension)
                if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
                    continue
                with path.open("rb") as source:
                    files[path.name] = source.read(MAX_SECTION if extension == "log" else limit + 1)
        publish_sections(root, files)


def watch_sections(root):
    while True:
        try:
            snapshot(root)
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
            # Incomplete writes or unavailable stages are retried, without erasing
            # the last atomic chapter snapshot or producing unbounded logs.
            pass
        time.sleep(1)


def render(root):
    capture_path = root / "upload.base64"
    archive_bytes, files = archive_files(root)
    write_atomic(root / "report.zip", archive_bytes)
    publish_sections(root, files, archive=True)
    for name, _ in SECTIONS:
        log = files.get(name + ".log", b"")
        if not clean_text(log.decode("utf-8", errors="replace")).strip():
            raise ValueError("incomplete upstream report: " + name)
        if name != "header_info":
            validate_json(files.get(name + ".json", b""))
    parts = ["NodeQuality 节点报告\n"]
    for name, title in SECTIONS:
        log = clean_text(files[name + ".log"].decode("utf-8", errors="replace")).strip()
        parts.append("\n===== " + title + " =====\n" + log + "\n")
    response_path = root / "upload-response.txt"
    response = response_path.read_bytes()[:65536].decode("utf-8", errors="replace") if response_path.exists() else ""
    status_path = root / "upload-status.txt"
    status = status_path.read_text().strip() if status_path.exists() else ""
    match = re.search(r"https://nodequality\.com/r/([A-Za-z0-9_-]{1,128})(?=$|\s|[\"'<>])", response)
    if (root / "upload-disabled.txt").exists():
        parts.append("\n公开报告上传已关闭，本地报告已保留。\n")
    elif status.isdigit() and 200 <= int(status) < 300 and match:
        report_url = match.group(0)
        write_atomic(root / "report-url.txt", (report_url + "\n").encode())
        parts.append("\n在线报告：" + report_url + "\n")
    else:
        parts.append("\n在线报告上传未成功，本地报告已保留。\n")
        if status:
            parts.append("HTTP 状态：" + status + "\n")
        if response.strip():
            parts.append(clean_text(response[:4096]).strip() + "\n")
    encoded_text = "".join(parts).encode("utf-8")
    if len(encoded_text) > MAX_TEXT:
        suffix = "\n报告文本已截断，完整原始结果保存在本地 report.zip。\n".encode()
        encoded_text = encoded_text[:MAX_TEXT - len(suffix)].decode("utf-8", errors="ignore").encode() + suffix
    write_atomic(root / "result.txt", encoded_text)
    capture_path.unlink()


def main():
    mode, target = sys.argv[1:]
    root = pathlib.Path(target)
    if mode == "capture":
        capture(root)
    elif mode == "stream-log":
        stream_log(root)
    elif mode == "render":
        render(root)
    elif mode == "snapshot":
        snapshot(root)
    elif mode == "watch-sections":
        watch_sections(root)
    elif mode == "response":
        capture_response(root)
    else:
        raise ValueError("unknown report operation")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        print("NodeQuality report collection failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
