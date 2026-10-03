import base64, fcntl, hashlib, json, os, stat, sys, uuid

path = sys.argv[1]
request = json.load(sys.stdin)
action = request["action"]
maximum = int(request["maximum"])
if action not in ("read", "inspect", "replace", "upload") or not 0 < maximum <= 262144:
    raise ValueError("invalid file action or budget")
components = path.split("/")
if not path.startswith("/") or any(part in (".", "..") for part in components):
    raise ValueError("invalid absolute path")
parts = [part for part in components if part]
if not parts:
    raise ValueError("a regular file is required")
writing = action in ("replace", "upload")
payload = base64.b64decode(request["content"], validate=True) if writing else b""
if len(payload) > maximum:
    raise ValueError("file exceeds budget")
directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
descriptor = None
try:
    for component in parts[:-1]:
        opened = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        os.close(directory)
        directory = opened
        if writing and os.fstat(directory).st_mode & 0o022:
            raise ValueError("write path ancestor cannot be group or world writable")
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        if action == "inspect":
            print(json.dumps({"exists": False, "bytes": None, "sha256": None}))
            sys.exit(0)
        if action != "upload" or request.get("previous_hash") is not None:
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
        if action == "read":
            print(json.dumps({"content": base64.b64encode(content).decode(), "sha256": digest}))
            sys.exit(0)
        if action == "inspect":
            print(json.dumps({"exists": True, "bytes": len(content), "sha256": digest}))
            sys.exit(0)
        if request.get("previous_hash") is None:
            raise ValueError("target already exists; read and explicitly confirm its old checksum")
        if digest != request["previous_hash"]:
            raise ValueError("file changed; read and compare again")
    parent = os.fstat(directory)
    if parent.st_mode & 0o022:
        raise ValueError("write directory cannot be group or world writable")
    temporary = ".sinan-" + str(uuid.uuid4())
    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     stat.S_IMODE(metadata.st_mode) if metadata else 0o600, dir_fd=directory)
    try:
        if metadata and os.geteuid() == 0:
            os.fchown(output, metadata.st_uid, metadata.st_gid)
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
    finally:
        os.close(output)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
    print(json.dumps({"sha256": hashlib.sha256(payload).hexdigest(), "created": metadata is None}))
finally:
    if descriptor is not None:
        os.close(descriptor)
    os.close(directory)
