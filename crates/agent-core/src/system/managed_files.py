import base64, fcntl, hashlib, json, os, stat, sys, uuid

path = sys.argv[1]
request = json.load(sys.stdin)
action = request["action"]
maximum = int(request["maximum"])
if action not in ("read", "inspect", "replace", "upload", "snapshot", "update") or not 0 < maximum <= 262144:
    raise ValueError("invalid file action or budget")
components = path.split("/")
if not path.startswith("/") or any(part in (".", "..") for part in components):
    raise ValueError("invalid absolute path")
parts = [part for part in components if part]
if not parts:
    raise ValueError("a regular file is required")
writing = action in ("replace", "upload", "update")
removing = action == "update" and request.get("content") is None
payload = base64.b64decode(request["content"], validate=True) if writing and not removing else b""
if len(payload) > maximum:
    raise ValueError("file exceeds budget")
directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
descriptor = None
parents = []
def identity(metadata, digest):
    return {"dev": metadata.st_dev, "ino": metadata.st_ino, "mtime_ns": metadata.st_mtime_ns,
            "bytes": metadata.st_size, "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid,
            "gid": metadata.st_gid, "sha256": digest}
def snapshot(metadata, digest, content=None):
    result = {"exists": metadata is not None, "parents": parents, "file": identity(metadata, digest) if metadata else None}
    if content is not None:
        result["content"] = base64.b64encode(content).decode()
    return result
try:
    for component in parts[:-1]:
        opened = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        os.close(directory)
        directory = opened
        parent_metadata = os.fstat(directory)
        parents.append({"dev":parent_metadata.st_dev,"ino":parent_metadata.st_ino,"uid":parent_metadata.st_uid,"mode":stat.S_IMODE(parent_metadata.st_mode)})
        if request.get("root_owned") and (parent_metadata.st_uid != 0 or parent_metadata.st_mode & 0o022):
            raise ValueError("certificate parent must be root-owned and not writable by another account")
        if writing and os.fstat(directory).st_mode & 0o022:
            raise ValueError("write path ancestor cannot be group or world writable")
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        if action == "snapshot":
            print(json.dumps(snapshot(None, None)))
            sys.exit(0)
        if action == "inspect":
            print(json.dumps({"exists": False, "bytes": None, "sha256": None}))
            sys.exit(0)
        if action not in ("upload", "update") or request.get("previous_hash") is not None:
            raise ValueError("target absent; explicit new-file upload is required")
    metadata = None
    if descriptor is not None:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("regular file without hard-link aliases required")
        if metadata.st_size > maximum:
            raise ValueError("file exceeds budget")
        fcntl.flock(descriptor, fcntl.LOCK_EX if writing else fcntl.LOCK_SH)
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise ValueError("file exceeds budget")
        content = b"".join(chunks)
        current = os.fstat(descriptor)
        if (current.st_mtime_ns, current.st_size) != (metadata.st_mtime_ns, metadata.st_size) or len(content) != metadata.st_size:
            raise ValueError("file changed while reading; sample again")
        digest = hashlib.sha256(content).hexdigest()
        if action == "snapshot":
            print(json.dumps(snapshot(metadata, digest, content)))
            sys.exit(0)
        if action == "read":
            print(json.dumps({"content": base64.b64encode(content).decode(), "sha256": digest}))
            sys.exit(0)
        if action == "inspect":
            print(json.dumps({"exists": True, "bytes": len(content), "sha256": digest}))
            sys.exit(0)
        if action != "update" and request.get("previous_hash") is None:
            raise ValueError("target already exists; read and explicitly confirm its old checksum")
        if action != "update" and digest != request["previous_hash"]:
            raise ValueError("file changed; read and compare again")
    if action == "update":
        captured = snapshot(metadata, digest if metadata else None)
        expected = request["expected"]
        if any(captured[field] != expected.get(field) for field in ("exists", "parents", "file")):
            raise ValueError("captured file or parent identity changed; refuse update")
        if removing:
            if metadata:
                current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
                if identity(current, digest) != captured["file"]:
                    raise ValueError("file changed before removal")
                os.unlink(parts[-1], dir_fd=directory)
                os.fsync(directory)
            print(json.dumps(snapshot(None, None)))
            sys.exit(0)
    parent = os.fstat(directory)
    if parent.st_mode & 0o022:
        raise ValueError("write directory cannot be group or world writable")
    temporary = ".sinan-" + str(uuid.uuid4())
    output = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     stat.S_IMODE(metadata.st_mode) if metadata else 0o600, dir_fd=directory)
    try:
        if metadata and os.geteuid() == 0:
            os.fchown(output, metadata.st_uid, metadata.st_gid)
        if action == "update":
            permissions = request["metadata"]
            mode, uid, gid = int(permissions["mode"]), int(permissions["uid"]), int(permissions["gid"])
            if not 0 <= mode <= 0o777 or uid < 0 or gid < 0:
                raise ValueError("invalid certificate ownership or permissions")
            os.fchown(output, uid, gid)
            os.fchmod(output, mode)
        offset = 0
        while offset < len(payload):
            offset += os.write(output, payload[offset:])
        os.fsync(output)
        if metadata:
            current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            if (current.st_ino, current.st_dev, current.st_mtime_ns, current.st_size) != (metadata.st_ino, metadata.st_dev, metadata.st_mtime_ns, metadata.st_size):
                raise ValueError("file changed during preparation")
            os.replace(temporary, parts[-1], src_dir_fd=directory, dst_dir_fd=directory)
        else:
            # link creates the final entry exclusively and cannot replace a concurrent file.
            os.link(temporary, parts[-1], src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
        updated = snapshot(os.fstat(output), hashlib.sha256(payload).hexdigest())
    finally:
        os.close(output)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
    print(json.dumps(updated if action == "update" else {"sha256": hashlib.sha256(payload).hexdigest(), "created": metadata is None}))
finally:
    if descriptor is not None:
        os.close(descriptor)
    os.close(directory)
