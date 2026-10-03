#!/usr/bin/env python3
"""Capture and render bounded upstream reports without extracting ZIP paths."""

import base64
import contextlib
import fcntl
import io
import json
import os
import pathlib
import re
import signal
import sys
import stat
import time
import zipfile


MAX_CAPTURE = 12 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
MAX_TEXT = 256 * 1024
MAX_SECTION = 64 * 1024
SNAPSHOT_SECONDS = 2
MAX_ROOT_ENTRIES = 1024
MAX_RESULT_DIRECTORIES = 8
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


def write_atomic(path, data, *, publication_fd=None):
    if publication_fd is None:
        with retained_directory(path.parent) as directory_fd:
            write_atomic_at(directory_fd, path.name, data)
    else:
        write_atomic_at(publication_fd, path.name, data)


def write_atomic_at(directory_fd, name, data):
    if pathlib.PurePath(name).name != name or name in ("", ".", ".."):
        raise ValueError("chapter output name is invalid")
    temporary = "." + name + "." + os.urandom(16).hex()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
            target.flush()
            os.fchmod(target.fileno(), 0o600)
            os.fsync(target.fileno())
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def read_section_at(directory_fd, name):
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 512 * 1024:
            raise ValueError("chapter output is not a bounded ordinary file")
        data = source.read(512 * 1024 + 1)
    if len(data) > 512 * 1024:
        raise ValueError("chapter output is not a bounded ordinary file")
    return data


def owned_directory(descriptor):
    metadata = os.fstat(descriptor)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022):
        raise ValueError("chapter source directory must be owned and protected")


@contextlib.contextmanager
def retained_directory(root):
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        owned_directory(descriptor)
        yield descriptor
    finally:
        os.close(descriptor)


def read_source_at(directory_fd, name, limit, check, read_limit=None):
    if pathlib.PurePath(name).name != name or name in ("", ".", ".."):
        raise ValueError("chapter source name is invalid")
    check()
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit
                or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022):
            raise ValueError("chapter source is not a bounded owned ordinary file")
        # Live logs may grow while being read. Retain a bounded prefix of this
        # exact file object; JSON and captured archives must fit their full bound.
        maximum = limit + 1 if read_limit is None else read_limit
        data = bytearray()
        while len(data) < maximum:
            check()
            content = source.read(min(65536, maximum - len(data)))
            if not content:
                break
            data.extend(content)
        check()
        if len(data) > limit:
            raise ValueError("chapter source exceeds its byte limit")
    return bytes(data)


def result_directories(directory_fd, check):
    names = []
    with os.scandir(directory_fd) as entries:
        for index, entry in enumerate(entries):
            check()
            if index >= MAX_ROOT_ENTRIES:
                raise ValueError("chapter workspace entry limit exceeded")
            if entry.name.startswith(".nodequality"):
                names.append(entry.name)
                if len(names) > MAX_RESULT_DIRECTORIES:
                    raise ValueError("chapter result directory limit exceeded")
    for name in sorted(names):
        descriptors = []
        try:
            parent = directory_fd
            for component in (name, "BenchOs", "result"):
                check()
                expected = os.stat(component, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(expected.st_mode):
                    raise NotADirectoryError("chapter result component is not an ordinary directory")
                descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=parent)
                descriptors.append(descriptor)
                owned_directory(descriptor)
                actual = os.fstat(descriptor)
                if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
                    raise ValueError("chapter result directory identity changed during open")
                parent = descriptor
            yield parent
        except (FileNotFoundError, NotADirectoryError):
            continue
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)


def clean_text(text):
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(c for c in text if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)


def capture(root, *, publication_fd=None):
    if publication_fd is None:
        with retained_directory(root) as directory_fd:
            return capture(root, publication_fd=directory_fd)
    data = sys.stdin.buffer.read(MAX_CAPTURE + 1)
    if len(data) > MAX_CAPTURE:
        raise ValueError("report upload exceeds its size limit")
    write_atomic(root / "upload.base64", data, publication_fd=publication_fd)
    try:
        _, files = archive_files(root, directory_fd=publication_fd)
        publish_sections(root, files, archive=True, publication_fd=publication_fd)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        pass


def stream_log(path, *, publication_fd=None):
    if publication_fd is None:
        with retained_directory(path.parent) as directory_fd:
            return stream_log(path, publication_fd=directory_fd)
    tail = b""
    while True:
        block = sys.stdin.buffer.read1(8192)
        if not block:
            break
        tail = (tail + block)[-MAX_TEXT:]
        write_atomic(path, tail, publication_fd=publication_fd)
    if not tail:
        write_atomic(path, b"", publication_fd=publication_fd)


def capture_response(root, *, publication_fd=None):
    if publication_fd is None:
        with retained_directory(root) as directory_fd:
            return capture_response(root, publication_fd=directory_fd)
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
    write_atomic(root / "upload-response.txt", first, publication_fd=publication_fd)
    write_atomic(root / "upload-status.txt", status[1] if status else b"", publication_fd=publication_fd)
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


def archive_files(root, *, directory_fd=None, check=None):
    if check is None:
        check = lambda: None
    if directory_fd is None:
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            owned_directory(descriptor)
            return archive_files(root, directory_fd=descriptor, check=check)
        finally:
            os.close(descriptor)
    encoded = read_source_at(directory_fd, "upload.base64", MAX_CAPTURE, check)
    if encoded is None:
        raise ValueError("report upload is absent")
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
            check()
            if record.filename not in ALLOWED or record.filename in files or record.is_dir():
                raise ValueError("report archive contains an unexpected or duplicate path")
            total += record.file_size
            if record.file_size > 8 * 1024 * 1024 or total > MAX_UNPACKED:
                raise ValueError("report archive exceeds its uncompressed size limit")
            files[record.filename] = archive.read(record)
            check()
    return archive_bytes, files


def bounded_text(data):
    text = clean_text(data.decode("utf-8", errors="replace")).strip()
    encoded = text.encode("utf-8")
    if len(encoded) <= MAX_SECTION:
        return text
    suffix = "\n章节文本已截断；如已生成压缩包，完整原始结果保存在本地 report.zip。".encode("utf-8")
    return encoded[:MAX_SECTION-len(suffix)].decode("utf-8", errors="ignore") + suffix.decode("utf-8")


def save_section(root, name, text, complete, *, blocking=True, publication_fd=None, check=None):
    if not text:
        return
    if publication_fd is None:
        with retained_directory(root) as directory_fd:
            return save_section(root, name, text, complete, blocking=blocking,
                                publication_fd=directory_fd, check=check)
    # Capture, the live watcher and cleanup share this stable private lock inode.
    lock_path = root / ".sections.lock" if publication_fd is None else ".sections.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=publication_fd)
    with os.fdopen(descriptor, "r+") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError("chapter publication lock is not an ordinary file")
        end = time.monotonic() + SNAPSHOT_SECONDS
        while True:
            if check is not None:
                check()
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not blocking or time.monotonic() >= end:
                    raise
                time.sleep(0.02)
        if check is not None:
            check()
        save_section_locked(root, name, text, complete, publication_fd=publication_fd,
                            check=check)


def save_section_locked(root, name, text, complete, *, publication_fd=None, check=None):
    path = root / ("section-" + name + ".json")
    previous = {}
    saved = None
    if publication_fd is not None:
        saved = read_section_at(publication_fd, path.name)
    else:
        if path.is_symlink():
            raise ValueError("chapter output is not a bounded ordinary file")
        if path.exists():
            if not path.is_file() or path.stat().st_size > 512 * 1024:
                raise ValueError("chapter output is not a bounded ordinary file")
            saved = path.read_text()
    if saved is not None:
        previous = json.loads(saved)
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
    data = json.dumps(chapter, ensure_ascii=False).encode("utf-8")
    if check is not None:
        check()
    write_atomic(path, data, publication_fd=publication_fd)


def publish_sections(root, files, archive=False, *, blocking=True, publication_fd=None, check=None):
    if publication_fd is None:
        with retained_directory(root) as directory_fd:
            return publish_sections(root, files, archive, blocking=blocking,
                                    publication_fd=directory_fd, check=check)
    failed = []
    for index, (name, _) in enumerate(SECTIONS):
        if check is not None:
            check()
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
            save_section(root, name, text, valid and (archive or following), blocking=blocking,
                         publication_fd=publication_fd, check=check)
        except (OSError, ValueError):
            # Keep the rejected sidecar untouched and publish the other chapters
            # before reporting failure to the collector or live watcher.
            failed.append(name)
    if failed:
        raise ValueError("chapter publication failed: " + ", ".join(failed))


def snapshot(root, *, blocking=True, publication_fd=None, cancelled=None):
    if publication_fd is None:
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            owned_directory(directory_fd)
            return snapshot(root, blocking=blocking, publication_fd=directory_fd,
                            cancelled=cancelled)
        finally:
            os.close(directory_fd)
    end = time.monotonic() + SNAPSHOT_SECONDS

    def check():
        if time.monotonic() >= end or cancelled is not None and cancelled():
            raise ValueError("chapter snapshot stopped or exceeded its deadline")

    owned_directory(publication_fd)
    try:
        _, files = archive_files(root, directory_fd=publication_fd, check=check)
        check()
        publish_sections(root, files, archive=True, blocking=blocking, publication_fd=publication_fd,
                         check=check)
        return
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        check()
    directories = result_directories(publication_fd, check)
    try:
        for directory_fd in directories:
            files = {}
            for name, _ in SECTIONS:
                for extension, limit in (("log", 8 * 1024 * 1024), ("json", 2 * 1024 * 1024)):
                    filename = name + "." + extension
                    try:
                        content = read_source_at(directory_fd, filename, limit, check,
                                                 MAX_SECTION if extension == "log" else None)
                    except (OSError, ValueError):
                        # Reject this source without dropping other chapters.
                        # A cancellation or elapsed deadline still stops the run.
                        check()
                        continue
                    if content is not None:
                        files[filename] = content
            check()
            publish_sections(root, files, blocking=blocking, publication_fd=publication_fd,
                             check=check)
    finally:
        directories.close()


def watch_sections(root, owner_pid):
    if type(owner_pid) is not int or owner_pid <= 1 or os.getppid() != owner_pid:
        raise ValueError("chapter watcher requires its actual direct parent")

    def directory_identity(path):
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("chapter watcher directory is not an ordinary directory")
        return metadata.st_dev, metadata.st_ino

    stopped = False

    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True

    # Retain both original directory objects. Path identity checks stop later
    # iterations; publication must remain in the original root even when a
    # replacement happens after source reads or during an atomic write.
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    runtime_fd = None
    previous = {}
    try:
        owned_directory(directory_fd)
        runtime_fd = os.open(".runner", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=directory_fd)
        owned_directory(runtime_fd)
        root_metadata, runtime_metadata = os.fstat(directory_fd), os.fstat(runtime_fd)
        root_identity = root_metadata.st_dev, root_metadata.st_ino
        runtime_identity = runtime_metadata.st_dev, runtime_metadata.st_ino
        # Restore our own stop handlers when the launcher ignored signals.
        previous = {signum: signal.signal(signum, stop)
                    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}

        def cancelled():
            if stopped or os.getppid() != owner_pid:
                return True
            try:
                return (directory_identity(root) != root_identity
                        or directory_identity(root / ".runner") != runtime_identity)
            except (OSError, ValueError):
                return True

        while not stopped and os.getppid() == owner_pid:
            try:
                if (directory_identity(root) != root_identity
                        or directory_identity(root / ".runner") != runtime_identity):
                    break
            except (OSError, ValueError):
                break
            try:
                # Never wait on a busy publisher while cancellation or owner
                # loss needs to stop this collector.
                snapshot(root, blocking=False, publication_fd=directory_fd,
                         cancelled=cancelled)
            except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
                pass
            if not stopped:
                time.sleep(1)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if runtime_fd is not None:
            os.close(runtime_fd)
        os.close(directory_fd)


def render(root, *, publication_fd=None):
    if publication_fd is None:
        with retained_directory(root) as directory_fd:
            return render(root, publication_fd=directory_fd)
    archive_bytes, files = archive_files(root, directory_fd=publication_fd)
    write_atomic(root / "report.zip", archive_bytes, publication_fd=publication_fd)
    publish_sections(root, files, archive=True, publication_fd=publication_fd)
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
    response = (read_source_at(publication_fd, "upload-response.txt", 65536, lambda: None) or b"").decode("utf-8", errors="replace")
    status = (read_source_at(publication_fd, "upload-status.txt", 64, lambda: None) or b"").decode("utf-8").strip()
    match = re.search(r"https://nodequality\.com/r/([A-Za-z0-9_-]{1,128})(?=$|\s|[\"'<>])", response)
    if read_source_at(publication_fd, "upload-disabled.txt", 1024, lambda: None) is not None:
        parts.append("\n公开报告上传已关闭，本地报告已保留。\n")
    elif status.isdigit() and 200 <= int(status) < 300 and match:
        report_url = match.group(0)
        write_atomic(root / "report-url.txt", (report_url + "\n").encode(), publication_fd=publication_fd)
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
    write_atomic(root / "result.txt", encoded_text, publication_fd=publication_fd)
    os.unlink("upload.base64", dir_fd=publication_fd)


def main():
    mode, target, *arguments = sys.argv[1:]
    root = pathlib.Path(target)
    if mode == "watch-sections":
        if (len(arguments) != 1 or not re.fullmatch(r"[1-9][0-9]*", arguments[0])
                or int(arguments[0]) <= 1):
            raise ValueError("chapter watcher requires a canonical owner PID")
        watch_sections(root, int(arguments[0]))
        return
    if arguments:
        raise ValueError("unexpected report operation arguments")
    if mode == "capture":
        capture(root)
    elif mode == "stream-log":
        stream_log(root)
    elif mode == "render":
        render(root)
    elif mode == "snapshot":
        # Cleanup must not block behind another chapter publisher.
        snapshot(root, blocking=False)
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
