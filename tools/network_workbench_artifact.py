#!/usr/bin/env python3
"""Prepare an offline workbench payload for the existing signed-release pipeline."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text())
    if inventory.get('schema') != 1 or inventory.get('engine_version') != '1.0.0':
        raise ValueError('explicit versioned inventory required')
    interpreter = inventory.get("interpreter", {})
    if interpreter.get("path") != "/usr/bin/python3" or interpreter.get("sha256") != hashlib.sha256(Path("/usr/bin/python3").read_bytes()).hexdigest():
        raise ValueError("explicit approved Python interpreter digest required")
    for name, item in inventory.get('tools', {}).items():
        path = Path(item['path'])
        if not path.is_absolute() or not item.get('licensed') or not item.get('license') or not item.get('source_url', '').startswith('https://'):
            raise ValueError('absolute tool, license confirmation and official source evidence required: ' + name)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if item.get('sha256') != digest:
            raise ValueError('installed tool differs from previously approved source digest: ' + name)
        flag = '-V' if name == 'ping' else '--version'
        version = subprocess.run([str(path), flag], capture_output=True, timeout=3, check=True)
        text = (version.stdout + version.stderr).decode('utf-8', 'replace')
        if item['version'] not in text or len(text) > 4096:
            raise ValueError('tool identity differs: ' + name)
        item['version_output_sha256'] = hashlib.sha256(version.stdout + version.stderr).hexdigest()
    root = Path(__file__).resolve().parents[1]
    files = {'sinan-network-workbench': (root / 'tools/network-workbench.py').read_bytes(),
             'tools-manifest.json': json.dumps(inventory, separators=(',', ':')).encode(),
             'LICENSE': (root / 'LICENSE').read_bytes()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.output, 'w:gz') as archive:
        for name, content in files.items():
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name == 'sinan-network-workbench' else 0o644
            entry.size = len(content)
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(content))
    print(json.dumps({'artifact': str(args.output), 'version': '1.0.0', 'sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      'signed': False, 'release_authorized': False, 'tool_count': len(inventory.get('tools', {}))}))


if __name__ == '__main__':
    main()
