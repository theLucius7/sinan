"""Read exact historical sources used to verify signed NodeQuality identities."""
import hashlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace

DIRECTORY = Path(__file__).resolve().parents[1] / 'plugins/nodequality/historical-r19'
NATIVE_DIRECTORY = DIRECTORY.parent / 'historical-native-r1'
NATIVE_IDENTITIES = {
    'native-runner.sh.tmpl': '9d24b242669b3b6152e294a00e07d8396462c576ed82be5500b479e723f1584f',
    'native-report.py': '5034e8d27f4b91172f06c6149d3e8e9653c67d5116721bc00a56efa2be66320f',
}
MAX_FILE = 128 * 1024
IDENTITIES = {
    'runner.sh.tmpl': 'b2842d48ad9df0c70734500ba80f9cfae269bee89c18c0877f007a43f4aece79',
    'report.py': '60dfa274ef3e0687ee74f0ad4e8bbe7ebab0472628cc671d57d3517fe2c5591f',
    'rootfs.py': '215d2e5367c6640399cfc8954aa5b42c18c159ba341e450af397024b3ae0345e',
}


def _source(directory, identities, name):
    if name not in identities:
        raise ValueError('unsupported historical NodeQuality source')
    descriptor = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE:
            raise ValueError('historical source must be a bounded ordinary file')
        content = stream.read(MAX_FILE + 1)
    if len(content) > MAX_FILE or hashlib.sha256(content).hexdigest() != identities[name]:
        raise ValueError('historical NodeQuality source identity mismatch')
    return content


def source(name):
    return _source(DIRECTORY, IDENTITIES, name)


def native_source(name):
    return _source(NATIVE_DIRECTORY, NATIVE_IDENTITIES, name)


def rootfs_module():
    path = DIRECTORY / 'rootfs.py'
    content = source('rootfs.py')
    namespace = {'__name__': 'sinan_historical_rootfs', '__file__': str(path)}
    # Compile the verified bytes directly; do not reload a mutable path.
    exec(compile(content, str(path), 'exec'), namespace)
    return SimpleNamespace(**namespace)
