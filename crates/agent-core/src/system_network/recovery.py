import hashlib, json, os, resource, stat, subprocess, sys, tempfile
from pathlib import Path

def read_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
            raise ValueError("recovery snapshot is not private ordinary root-owned file")
        with os.fdopen(descriptor, "r", closefd=False) as source:
            return json.load(source)
    finally:
        os.close(descriptor)

def invoke(arguments, pass_fds=()):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = subprocess.run(arguments, stdout=output, stderr=error, pass_fds=pass_fds, timeout=5, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C"})
        output.seek(0)
        error.seek(0)
        stdout, stderr = output.read(65537), error.read(65537)
        if len(stdout) > 65536 or len(stderr) > 65536 or result.returncode:
            raise ValueError("bounded local recovery command failed")
        return stdout.decode()

def command(arguments):
    return invoke(arguments)

def recover(state_dir, kind, identity, snapshot_path):
    marker = Path(state_dir) / "network-recovery" / ("current-" + kind + ".json")
    record = read_json(marker)
    if record != {"id":identity,"kind":kind,"state":"armed"}:
        return "superseded"
    snapshot = read_json(snapshot_path)
    def finish(state):
        temporary = marker.with_name(".recovery-" + identity)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "w", closefd=False) as target:
                json.dump({"id":identity,"kind":kind,"state":state}, target)
                target.flush()
                os.fsync(descriptor)
            os.replace(temporary, marker)
        finally:
            os.close(descriptor)
            temporary.unlink(missing_ok=True)
        if state == "restored":
            completed = Path(snapshot_path).parent / "restored"
            descriptor = os.open(completed, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        return state
    if kind == "sysctl":
        if snapshot.get("id") != identity:
            raise ValueError("recovery snapshot identity mismatch")
        observed = {key:" ".join(command(["/sbin/sysctl","-n",key]).split()) for key in snapshot["before"]}
        if any(observed[key] not in (before, snapshot["desired"][key]) for key, before in snapshot["before"].items()):
            return finish("refused")
        for key, before in snapshot["before"].items():
            if observed[key] != before:
                if " ".join(command(["/sbin/sysctl","-n",key]).split()) != observed[key]:
                    return finish("refused")
                command(["/sbin/sysctl","-w",key + "=" + before])
        if any(" ".join(command(["/sbin/sysctl","-n",key]).split()) != before for key, before in snapshot["before"].items()):
            raise ValueError("recovery could not confirm original parameters")
    elif kind == "firewall":
        table = snapshot["table"]
        if not table.startswith("sinan_") or not all(character in "0123456789abcdef" for character in table[6:]):
            raise ValueError("recovery table identity invalid")
        tables = command(["/usr/sbin/nft","list","tables"])
        actual = command(["/usr/sbin/nft","list","table","inet",table]) if "table inet " + table in tables.splitlines() else None
        if actual == snapshot.get("previous"):
            return finish("restored")
        if actual is None or hashlib.sha256(actual.encode()).hexdigest() != snapshot["observed_hash"]:
            return finish("refused")
        if command(["/usr/sbin/nft","list","table","inet",table]) != actual:
            return finish("refused")
        batch = "delete table inet " + table + "\n" + (snapshot.get("previous") or "")
        with tempfile.TemporaryFile() as rules:
            rules.write(batch.encode())
            rules.flush()
            invoke(["/usr/sbin/nft","-f","/proc/self/fd/"+str(rules.fileno())], pass_fds=(rules.fileno(),))
        tables = command(["/usr/sbin/nft","list","tables"])
        restored = command(["/usr/sbin/nft","list","table","inet",table]) if "table inet " + table in tables.splitlines() else None
        if restored != snapshot.get("previous"):
            raise ValueError("firewall restoration could not be confirmed")
    else:
        raise ValueError("unknown recovery kind")
    return finish("restored")

if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_FSIZE, (131072, 131072))
    print(recover(*sys.argv[1:]))
