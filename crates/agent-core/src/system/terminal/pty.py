import errno, fcntl, json, os, pwd, select, signal, struct, sys, termios, time

def emit(value):
    sys.stdout.write(json.dumps(value, ensure_ascii=True) + "\n")
    sys.stdout.flush()

account = pwd.getpwnam(sys.argv[1])
if os.geteuid() != 0 and os.geteuid() != account.pw_uid:
    emit({"ready": False, "error": "account switch requires privilege"})
    sys.exit(1)
master, slave = os.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", int(sys.argv[3]), int(sys.argv[2]), 0, 0))
pid = os.fork()
if pid == 0:
    os.close(master)
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    for descriptor in (0, 1, 2): os.dup2(slave, descriptor)
    if slave > 2: os.close(slave)
    if os.geteuid() == 0:
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    os.chdir(account.pw_dir)
    os.execve("/bin/sh", ["/bin/sh", "-i"], {"HOME": account.pw_dir, "PATH": "/usr/local/bin:/usr/bin:/bin", "TERM": "dumb", "SHELL": "/bin/sh"})
os.close(slave)
os.set_blocking(master, False)
emit({"ready": True})
buffer = b""
started = time.monotonic()
last_input = started
try:
    while time.monotonic() - started < 1800 and time.monotonic() - last_input < 300:
        ready, _, _ = select.select([master, 0], [], [], 1)
        if master in ready:
            try: data = os.read(master, 8192)
            except OSError as error:
                if error.errno == errno.EIO: break
                raise
            if not data: break
            emit({"data": data.decode("utf-8", "replace")})
        if 0 in ready:
            data = os.read(0, 32768)
            if not data: break
            buffer += data
            if len(buffer) > 65536: raise ValueError("input budget exceeded")
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                frame = json.loads(line)
                if frame.get("close"): raise EOFError()
                text = frame.get("data", "").encode("utf-8")
                if len(text) > 8192: raise ValueError("input budget exceeded")
                if frame.get("columns") is not None:
                    columns, rows = int(frame["columns"]), int(frame["rows"])
                    if not 20 <= columns <= 300 or not 5 <= rows <= 120: raise ValueError("invalid terminal dimensions")
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
                if text:
                    offset = 0
                    while offset < len(text):
                        _, writable, _ = select.select([], [master], [], 2)
                        if not writable: raise TimeoutError("PTY input stalled")
                        offset += os.write(master, text[offset:])
                last_input = time.monotonic()
except EOFError:
    pass
finally:
    for sig in (signal.SIGHUP, signal.SIGKILL):
        try: os.killpg(pid, sig)
        except ProcessLookupError: pass
    os.close(master)
    os.waitpid(pid, 0)
