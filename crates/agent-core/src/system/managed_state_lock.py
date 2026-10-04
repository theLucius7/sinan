import fcntl, os, stat, sys

path = sys.argv[1]
parts = path.split("/")
if not path.startswith("/") or any(part in (".", "..") for part in parts):
    raise ValueError("invalid state lock path")
parts = [part for part in parts if part]
directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
try:
    for part in parts[:-1]:
        opened = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        os.close(directory)
        directory = opened
        metadata = os.fstat(directory)
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("lock ancestor must be root-owned and not writable by other accounts")
    descriptor = os.open(parts[-1], os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
        raise ValueError("lock requires private ordinary root-owned inode")
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print("locked", flush=True)
    while os.read(0, 1):
        pass
finally:
    os.close(directory)
