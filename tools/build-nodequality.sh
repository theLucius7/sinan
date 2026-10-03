#!/usr/bin/env bash
# Package canonical NodeQuality sources, reference data and fixed policies.
set -euo pipefail
umask 022

usage() {
  cat <<'USAGE'
Usage: tools/build-nodequality.sh <amd64|arm64> <ARTIFACT_ROOT>

Build prerequisites: bash, curl, python3. No benchmark runs during packaging.
Output: ARTIFACT_ROOT/nodequality/a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22/<arch>
        ARTIFACT_ROOT/nodequality/a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22/SHA256SUMS

Both targets contain one architecture-independent executable named nodequality.
The canonical entrypoint, five first-level scripts, seven reference files and
four full licenses are retained verbatim. Fixed helpers forbid runtime installs
and swap changes, gate public reports and embed static data without removing
hardware sources. New full runs are refused by the artifact itself. Its signed
execution-admission record declares unresolved rootfs and secondary tools;
source and license retention do not authorize their execution or redistribution.
Existing architecture files are immutable. Packaging verifies and retains the
other architecture's checksum entry. Run architectures sequentially.
USAGE
}
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
[[ $# == 2 ]] || { usage >&2; exit 2; }
arch=$1
case "$arch" in amd64|arm64) ;; *) die 'architecture must be amd64 or arm64' ;; esac
[[ -n $2 ]] || die 'ARTIFACT_ROOT must not be empty'
for tool in curl python3; do command -v "$tool" >/dev/null || die "missing build tool: $tool"; done
upstream_revision=a92fca6c0067df29ddd03fdc2fee6f3000f64545
version=$upstream_revision-r22
output=$2/nodequality/$version
[[ ! -L $output ]] || die 'output version directory must not be a symlink'
mkdir -p "$output"
output=$(cd "$output" && pwd -P)
lock=$output/.build.lock
mkdir "$lock" 2>/dev/null || die "another build owns $lock; remove only after confirming that build has stopped"
scratch=
stage_file=
sums_file=
output_created=0
committed=0
cleanup() {
  if [[ $output_created == 1 && $committed == 0 ]]; then rm -f -- "$output/$arch"; fi
  [[ -z $stage_file ]] || rm -f -- "$stage_file"
  [[ -z $sums_file ]] || rm -f -- "$sums_file"
  [[ -z $scratch ]] || rm -rf -- "$scratch"
  rmdir -- "$lock"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[[ ! -e $output/$arch && ! -L $output/$arch ]] || die "immutable artifact already exists: $output/$arch"
python3 - "$output" <<'PY'
import hashlib
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
manifest = root / "SHA256SUMS"
expected = {}
if manifest.is_symlink() or (manifest.exists() and not manifest.is_file()):
    raise SystemExit("SHA256SUMS must be an ordinary file")
if manifest.exists():
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](amd64|arm64)", line)
        if not match or match[2] in expected:
            raise SystemExit("invalid or duplicate SHA256SUMS entry")
        expected[match[2]] = match[1].lower()
for arch in ("amd64", "arm64"):
    artifact = root / arch
    if artifact.is_symlink() or (artifact.exists() and not artifact.is_file()):
        raise SystemExit(f"{arch} must be an ordinary file")
    if artifact.exists():
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if expected.get(arch) != actual:
            raise SystemExit(f"existing {arch} lacks a matching checksum; refusing to replace the manifest")
    elif arch in expected:
        raise SystemExit(f"SHA256SUMS refers to missing {arch}")
PY
scratch=$(mktemp -d "${TMPDIR:-/tmp}/sinan-nodequality-build.XXXXXX")
script_dir=$(cd "$(dirname "$0")" && pwd -P)
plugin_dir=$script_dir/../plugins/nodequality
python3 "$plugin_dir/source-helper.py" admission "$plugin_dir/execution-admission.json" >/dev/null
python3 "$plugin_dir/source-helper.py" downloads "$plugin_dir/source-lock.json" \
  | while IFS=$'\t' read -r filename source_url; do
      if [[ $filename == NodeQuality.sh ]]; then
        [[ $source_url == "https://raw.githubusercontent.com/LloydAsp/NodeQuality/$upstream_revision/NodeQuality.sh" ]] \
          || die 'entrypoint source commit differs from the artifact version'
      fi
      curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 60 --max-filesize 2097152 \
        "$source_url" \
        | python3 "$plugin_dir/source-helper.py" receive "$scratch/$filename"
    done
python3 "$plugin_dir/source-helper.py" pack "$plugin_dir/source-lock.json" "$scratch" > "$scratch/pinned-chain.json"
python3 "$plugin_dir/source-helper.py" entrypoint "$scratch/pinned-chain.json" > "$scratch/NodeQuality.patched.sh"
python3 - "$scratch" "$plugin_dir" <<'PY'
import pathlib
import sys

scratch, plugin = map(pathlib.Path, sys.argv[1:])
runner = (plugin / "runner.sh.tmpl").read_bytes()
for marker, path in (
    ("NODEQUALITY_SOURCE", scratch / "NodeQuality.patched.sh"),
    ("NODEQUALITY_LICENSE", scratch / "LICENSE.nodequality"),
    ("PINNED_CHAIN", scratch / "pinned-chain.json"),
    ("SOURCE_HELPER", plugin / "source-helper.py"),
    ("REPORT_POLICY_HELPER", plugin / "report-policy.py"),
    ("SWAP_POLICY_HELPER", plugin / "swap-policy.py"),
    ("DEPENDENCY_POLICY_HELPER", plugin / "dependency-policy.py"),
    ("DATA_POLICY_HELPER", plugin / "data-policy.py"),
    ("LOADER_POLICY_HELPER", plugin / "loader-policy.py"),
    ("RANKING_POLICY_HELPER", plugin / "ranking-policy.py"),
    ("IP_SCORE_POLICY_HELPER", plugin / "ip-score-policy.py"),
    ("NETFLIX_POLICY_HELPER", plugin / "netflix-policy.py"),
    ("BROWSER_POLICY_HELPER", plugin / "browser-policy.py"),
    ("PUBLIC_ACCESS_POLICY_HELPER", plugin / "public-access-policy.py"),
    ("REPORT_HELPER", plugin / "report.py"),
    ("EXIT_OBSERVER", plugin / "exit-observer.sh"),
    ("DAILY_HELPER", plugin / "daily.py"),
    ("OFFICIAL_IP_HELPER", plugin / "official-ip.py"),
    ("EXECUTION_ADMISSION", plugin / "execution-admission.json"),
    ("CURL_SHIM", plugin / "runtime-curl.sh"),
    ("CHROOT_SHIM", plugin / "chroot-shim.sh"),
):
    placeholder = ("@" + marker + "@\n").encode()
    if runner.count(placeholder) != 1:
        raise SystemExit("invalid runner template placeholder: " + marker)
    payload = path.read_bytes()
    if not payload.endswith(b"\n"):
        raise SystemExit("embedded source must end with a newline: " + marker)
    runner = runner.replace(placeholder, payload)
target = scratch / "nodequality"
target.write_bytes(runner)
target.chmod(0o755)
PY
bash -n "$scratch/nodequality"
[[ $(bash "$scratch/nodequality" --version) == "nodequality $version" ]] || die 'runner version check failed'
stage_file=$(mktemp "$output/.$arch.XXXXXX")
python3 - "$scratch/nodequality" "$stage_file" <<'PY'
import gzip
import io
import pathlib
import sys
import tarfile

source, target = map(pathlib.Path, sys.argv[1:])
content = source.read_bytes()
entry = tarfile.TarInfo("nodequality")
entry.size = len(content)
entry.mode = 0o755
entry.uid = entry.gid = entry.mtime = 0
with target.open("wb") as destination:
    with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            archive.addfile(entry, io.BytesIO(content))
PY
chmod 0644 "$stage_file"
ln -- "$stage_file" "$output/$arch"
output_created=1
sums_file=$(mktemp "$output/.SHA256SUMS.XXXXXX")
python3 - "$output" "$sums_file" <<'PY'
import hashlib
import pathlib
import sys

root, manifest = map(pathlib.Path, sys.argv[1:])
lines = []
for arch in ("amd64", "arm64"):
    artifact = root / arch
    if artifact.is_file():
        lines.append(hashlib.sha256(artifact.read_bytes()).hexdigest() + "  " + arch + "\n")
manifest.write_text("".join(lines))
manifest.chmod(0o644)
manifest.replace(root / "SHA256SUMS")
PY
committed=1
printf 'Artifact: %s/%s\n' "$output" "$arch"
cat "$output/SHA256SUMS"
