"""Prepare the explicit offline NodeQuality artifact without running diagnostics."""
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import nodequality_history as history

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins/nodequality"
CANONICAL_VERSION = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-sinan-native-r1"
VERSION = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-offline-rootfs-r1"
BINARY = "nodequality"
FILES = {BINARY, "rootfs.tar.gz", "rootfs-manifest.json"}
MAX_OUTER_STREAM = 256 * 1024 * 1024
MAX_RUNNER = 4 * 1024 * 1024
MAX_MANIFEST = 8 * 1024 * 1024
ENTRY_SHA256 = "728d15d923ae030b9caf83cfe38b9bdb690800c9e11feb57c75ce99a7623a182"
LOAD_ROOTFS = b'''function load_bench_os(){
    cd $work_dir
    rm -rf BenchOs

    curl "-L#o" BenchOs.tar.gz $bench_os_url
    tar -xzf BenchOs.tar.gz\x20\x20\x20\x20\x20
    cd $work_dir/BenchOs

    mount -t proc /proc proc/
    mount --bind /sys sys/
    mount --rbind /dev dev/
    mount --make-rslave dev

    rm etc/resolv.conf 2>/dev/null
    cp /etc/resolv.conf etc/resolv.conf
}
'''
LOCAL_ROOTFS = b'''function load_bench_os(){
    python3 "$SINAN_ROOTFS_HELPER" extract \\
        --archive "$SINAN_ROOTFS_DIRECTORY/rootfs.tar.gz" \\
        --manifest "$SINAN_ROOTFS_DIRECTORY/rootfs-manifest.json" \\
        --workspace "$work_dir" --arch "$SINAN_ROOTFS_ARCH" \\
        --destination BenchOs || return $?
    cd "$work_dir/BenchOs" || return $?
    mount -t proc /proc proc/ || return $?
    mount --bind /sys sys/ || return $?
    mount -o remount,bind,ro sys/ || return $?
    mount --rbind /dev dev/ || return $?
    mount --make-rslave dev || return $?
    [[ ! -L etc/resolv.conf && -f etc/resolv.conf ]] || return 70
    cp -- /etc/resolv.conf etc/resolv.conf || return $?
}
'''
MARKERS = {
    "NODEQUALITY_SOURCE": "SINAN_NODEQUALITY_SOURCE_A92FCA6",
    "NODEQUALITY_LICENSE": "SINAN_NODEQUALITY_LICENSE_A92FCA6",
    "PINNED_CHAIN": "SINAN_NODEQUALITY_PINNED_CHAIN",
}
HELPERS = {
    "SOURCE_HELPER": "native-source-helper.py", "REPORT_POLICY_HELPER": "report-policy.py",
    "SWAP_POLICY_HELPER": "swap-policy.py", "DEPENDENCY_POLICY_HELPER": "dependency-policy.py",
    "DATA_POLICY_HELPER": "data-policy.py", "LOADER_POLICY_HELPER": "loader-policy.py",
    "RANKING_POLICY_HELPER": "ranking-policy.py", "IP_SCORE_POLICY_HELPER": "ip-score-policy.py",
    "BROWSER_POLICY_HELPER": "native-browser-policy.py",
    "QUERY_POLICY_HELPER": "query-policy.py", "ACCESS_POLICY_HELPER": "access-policy.py",
    "OPENAI_POLICY_HELPER": "openai-policy.py", "NETFLIX_POLICY_HELPER": "native-netflix-policy.py",
    "REPORT_HELPER": "native-report.py", "EXIT_OBSERVER": "exit-observer.sh", "DAILY_HELPER": "daily.py",
    "CURL_SHIM": "curl-shim.sh", "CHROOT_SHIM": "chroot-shim.sh",
    "OFFICIAL_IP_HELPER": "official-ip.py", "EXECUTION_ADMISSION": "execution-admission.json",
}


def ensure(condition, message):
    if not condition:
        raise ValueError(message)


def module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(result)
    return result


def runtime():
    return history.rootfs_module()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        ensure(key not in result, "duplicate offline provenance key")
        result[key] = value
    return result


def replace_once(content, before, after):
    ensure(content.count(before) == 1, "offline runner requires a unique fixed anchor")
    return content.replace(before, after, 1)


def embedded(content, sentinel):
    begin, end = ("<<'" + sentinel + "'\n").encode(), ("\n" + sentinel + "\n").encode()
    ensure(content.count(begin) == 1 and content.count(end) == 1,
           "missing or duplicate embedded source boundary")
    start = content.index(begin) + len(begin)
    stop = content.index(end, start)
    return content[start:stop + 1]


LEGACY_VERSION = CANONICAL_VERSION


def legacy_runner(bundle_bytes):
    return canonical_runner(bundle_bytes)


def canonical_runner(bundle_bytes):
    helper = module("sinan_offline_source_helper", PLUGIN / "native-source-helper.py")
    bundle = helper.decode(bundle_bytes)
    ensure(isinstance(bundle, dict) and set(bundle) == {"schema", "lock", "files"}
           and type(bundle["schema"]) is int and bundle["schema"] == 1,
           "offline runner requires the complete canonical source bundle")
    lock = helper.decode(helper.ordinary(PLUGIN / "source-lock.json", MAX_MANIFEST))
    ensure(bundle.get("lock") == lock, "offline runner requires the canonical source lock")
    rows = helper.validate(lock)
    helper.execution_admission(PLUGIN / "execution-admission.json")
    helper.official_ip_identity()
    ensure(isinstance(bundle, dict) and set(bundle) == {"schema", "lock", "files"}
           and type(bundle["schema"]) is int and bundle["schema"] == 1
           and isinstance(bundle["files"], dict) and set(bundle["files"]) == set(rows),
           "offline runner requires the complete canonical source bundle")
    for name, row in rows.items():
        helper.verified(base64.b64decode(bundle["files"][name], validate=True), row)
    entry = helper.entrypoint(bundle)
    ensure(digest(entry) == ENTRY_SHA256, "offline entrypoint input SHA256 mismatch")
    license_bytes = helper.verified(base64.b64decode(bundle["files"]["LICENSE.nodequality"], validate=True),
                                    rows["LICENSE.nodequality"])
    payloads = {"NODEQUALITY_SOURCE": entry, "NODEQUALITY_LICENSE": license_bytes,
                "PINNED_CHAIN": bundle_bytes}
    payloads.update({name: history.native_source(filename) if name == "REPORT_HELPER" else helper.ordinary(PLUGIN / filename, MAX_RUNNER)
                     for name, filename in HELPERS.items()})
    template = history.native_source("native-runner.sh.tmpl")
    for marker, payload in payloads.items():
        ensure(payload.endswith(b"\n"), "embedded offline payload must end with newline")
        template = replace_once(template, ("@" + marker + "@\n").encode(), payload)
    ensure(len(template) <= MAX_RUNNER, "runner exceeds byte limit")
    return template


def offline_runner(base):
    ensure(isinstance(base, bytes) and 0 < len(base) <= MAX_RUNNER,
           "invalid canonical runner size")
    bundle = embedded(base, MARKERS["PINNED_CHAIN"])
    ensure(base == canonical_runner(bundle), "base runner differs from exact native policy packaged source")
    entry = embedded(base, MARKERS["NODEQUALITY_SOURCE"])
    patched = replace_once(entry, LOAD_ROOTFS, LOCAL_ROOTFS)
    patched = replace_once(patched, b"    load_bench_os\n",
                           b"    load_bench_os || exit $? # Sinan: no online rootfs fallback.\n")
    result = replace_once(base, entry, patched)
    result = replace_once(result, b"New full executions are refused before filesystem changes or upstream tools.",
                          b"This artifact includes a verified offline rootfs preparation.\n"
                          b"New full executions are refused before filesystem changes or upstream tools.")
    result = replace_once(result, ("version=" + CANONICAL_VERSION + "\n").encode(),
                          ("version=" + VERSION + "\n").encode())
    # Preserve the canonical artifact's complete-execution admission unchanged.
    extractor = history.source("rootfs.py")
    ensure(extractor.endswith(b"\n") and b"\nSINAN_NODEQUALITY_ROOTFS_HELPER\n" not in extractor,
           "invalid embedded rootfs helper")
    injection = b'''cat > "$runtime/rootfs.py" <<'SINAN_NODEQUALITY_ROOTFS_HELPER'
''' + extractor + b'''SINAN_NODEQUALITY_ROOTFS_HELPER
export SINAN_ROOTFS_HELPER=$runtime/rootfs.py
SINAN_ROOTFS_DIRECTORY=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
export SINAN_ROOTFS_DIRECTORY
case "$(uname -m)" in
  x86_64) SINAN_ROOTFS_ARCH=amd64 ;;
  aarch64|arm64) SINAN_ROOTFS_ARCH=arm64 ;;
  *) die 'unsupported offline rootfs architecture' ;;
esac
export SINAN_ROOTFS_ARCH
'''
    result = replace_once(result, b"cat > \"$runtime/NodeQuality.sh\" <<'SINAN_NODEQUALITY_SOURCE_A92FCA6'\n",
                          injection + b"cat > \"$runtime/NodeQuality.sh\" <<'SINAN_NODEQUALITY_SOURCE_A92FCA6'\n")
    ensure(len(result) <= MAX_RUNNER, "offline runner exceeds byte limit")
    return result


def validate_files(files, version, arch):
    ensure(version == VERSION and arch in ("amd64", "arm64"), "unsupported offline artifact identity")
    ensure(set(files) == FILES, "offline artifact requires its exact binary and two auxiliary files")
    ensure(0 < len(files[BINARY]) <= MAX_RUNNER and 0 < len(files["rootfs-manifest.json"]) <= MAX_MANIFEST,
           "offline artifact metadata exceeds byte limits")
    ensure(0 < len(files["rootfs.tar.gz"]) < MAX_OUTER_STREAM
           and sum(len(value) for value in files.values()) + 10240 <= MAX_OUTER_STREAM,
           "offline artifact exceeds total outer tar budget")
    helper = runtime()
    manifest = helper.load_manifest(files["rootfs-manifest.json"], arch)
    # Build/release validation may use temporary disk. The Agent runtime reads
    # the signed ordinary archive in place and never copies it into a variable.
    with tempfile.TemporaryDirectory(prefix="sinan-rootfs-intake-") as temporary:
        archive = Path(temporary).resolve(strict=True) / "rootfs.tar.gz"
        with archive.open("xb") as output:
            output.write(files["rootfs.tar.gz"])
        helper.verify_archive(archive, manifest)
        names = ["usr/share/sinan-rootfs/" + name for name in
                 ("provenance.json", "inputs-lock.json", "source-inventory.json", "license-inventory.json")]
        metadata = helper.read_metadata(archive, manifest, names)
    provenance = json.loads(metadata[names[0]], object_pairs_hook=unique_object)
    expected = {"schema", "kind", "arch", "full_ready", "source_authenticated",
                "reproducibility_verified", "source_epoch", "builder", "inputs_lock_sha256",
                "source_inventory_sha256", "license_inventory_sha256", "build_tool_sha256",
                "pending_capabilities"}
    ensure(isinstance(provenance, dict) and set(provenance) == expected
           and type(provenance["schema"]) is int and provenance["schema"] == 1
           and provenance["kind"] == "sinan-nodequality-debian12-preparation"
           and provenance["arch"] == arch and provenance["full_ready"] is False
           and provenance["source_authenticated"] is True
           and provenance["reproducibility_verified"] is False,
           "offline provenance must identify preparation with full mode unavailable")
    ensure(type(provenance["source_epoch"]) is int and 0 < provenance["source_epoch"] < 2**32
           and isinstance(provenance["build_tool_sha256"], str)
           and len(provenance["build_tool_sha256"]) == 64
           and all(value in "0123456789abcdef" for value in provenance["build_tool_sha256"]),
           "offline provenance has an invalid epoch or build-tool digest")
    builder = provenance["builder"]
    ensure(isinstance(builder, dict) and set(builder) == {"image_sha256", "arch", "tools"}
           and builder["arch"] == arch and isinstance(builder["image_sha256"], str)
           and len(builder["image_sha256"]) == 64
           and all(value in "0123456789abcdef" for value in builder["image_sha256"])
           and isinstance(builder["tools"], list), "invalid offline builder declaration")
    for name, field in zip(names[1:], ("inputs_lock_sha256", "source_inventory_sha256", "license_inventory_sha256")):
        ensure(provenance[field] == digest(metadata[name]), "embedded inventory differs from offline provenance")
    ensure(isinstance(provenance["pending_capabilities"], list) and provenance["pending_capabilities"]
           and all(isinstance(value, str) and 0 < len(value) <= 256 for value in provenance["pending_capabilities"]),
           "offline preparation must retain pending capabilities")
    licenses = json.loads(metadata[names[3]], object_pairs_hook=unique_object)
    ensure(isinstance(licenses, dict) and licenses.get("reviewed") is False,
           "offline preparation is not a complete license review")
    inputs = json.loads(metadata[names[1]], object_pairs_hook=unique_object)
    sources = json.loads(metadata[names[2]], object_pairs_hook=unique_object)
    ensure(isinstance(inputs, dict) and type(inputs.get("schema")) is int and inputs["schema"] == 1
           and inputs.get("arch") == arch and inputs.get("source_epoch") == provenance["source_epoch"]
           and inputs.get("builder") == builder, "embedded input declaration differs from provenance")
    ensure(isinstance(sources, dict) and type(sources.get("schema")) is int and sources["schema"] == 1
           and sources.get("arch") == arch, "invalid embedded source inventory identity")
    bundle = embedded(files[BINARY], MARKERS["PINNED_CHAIN"])
    ensure(files[BINARY] == offline_runner(canonical_runner(bundle)),
           "offline runner differs from its exact controlled derivation")
    return manifest


def archive_files(data):
    ensure(isinstance(data, bytes) and 0 < len(data) <= MAX_OUTER_STREAM,
           "offline outer archive size outside permitted range")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        unpacked = compressed.read(MAX_OUTER_STREAM + 1)
    ensure(len(unpacked) <= MAX_OUTER_STREAM, "offline outer archive exceeds decompressed stream limit")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as archive:
        for member in archive:
            ensure(member.name in FILES and member.name not in files and member.isfile()
                   and not member.pax_headers and 0 < member.size <= MAX_OUTER_STREAM,
                   "unsafe offline outer archive member")
            files[member.name] = archive.extractfile(member).read(member.size + 1)
            ensure(len(files[member.name]) == member.size, "offline archive member truncated")
    ensure(set(files) == FILES, "offline artifact file set is incomplete")
    return files


def pack(files):
    ensure(set(files) == FILES and sum(len(value) for value in files.values()) + 10240 <= MAX_OUTER_STREAM,
           "offline artifact exceeds total outer stream budget")
    output = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(files):
                member = tarfile.TarInfo(name)
                member.size = len(files[name])
                member.mode = 0o755 if name == BINARY else 0o644
                archive.addfile(member, io.BytesIO(files[name]))
    data = output.getvalue()
    ensure(len(data) <= MAX_OUTER_STREAM, "offline compressed artifact exceeds total archive byte budget")
    return data
