#!/usr/bin/env python3
"""Materialize the exact four-source, standalone AGPL IPQuality profile."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_FILE = 2 * 1024 * 1024
MAX_BUNDLE = 2 * 1024 * 1024
COMMIT = '87397e2c3196ec796f5477c83343c2354df601ea'
EXPECTED = {
    'ip.sh': ('ip.sh', 'b30df5a3c2204276c54e99dcc5080b46f8a627667730aee7de63b109b8ecaecf', 108641),
    'LICENSE.ip': ('LICENSE', '8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef', 34523),
    'ip-iso3166.json': ('ref/iso3166.json', 'e1434e42786484b1841082a0a16cf27208691443dc6440d125ad81d49007ea42', 65317),
    'ip-dnsbl.list': ('ref/dnsbl.list', 'a92ca482843310167309c82f05cb7e208d7decc7f8bb7eada0f96af42f1143ad', 8812),
}
POLICIES = {
    'report': '0c66e702084820e399a16b18b51ba331cd8edd406dd96ede7c2ee84f78c30245',
    'dependency': '9424dded5fd6c74ff9888fa6e2e3d9482fe8db144fa4c572682fca3f8cf5b5de',
    'data': '0115f90f8ce521eab1472d8426b8f8dfbf1fefca427ae0fdfd557b346a8fdab3',
    'ip-score': 'f5ae90c823d6b6d993c9254369220f6128ac7169f41b557c603ab00f184f245f',
    'browser': '04de9983ccbe2a7651011e3b05b1092cd0a25af950ff3a97f583536f4c693ef1',
    'query': 'e4ec8e34c9264b25b64d5ec6252f419762493be9b928d96beaba7addffe3aa00',
    'access': '83db5e84f2c2c793eb4eff0d43ba0e439b196ab7a940a2a293d9b513860985b9',
    'netflix': 'b928c6d4ac92b26f72207914d269b5154f09441bad3ca9eb5f036654f20f5eb7',
    'openai': '1def74828e5414ad41f184f45e821fb686ed9898b3ed665663acc978ed191928',
}
REVIEWED_POLICY_FILES = {'browser': 'native-browser-policy.py',
                         'netflix': 'native-netflix-policy.py'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate source manifest field')
        result[key] = value
    return result


def decode(content):
    return json.loads(content, object_pairs_hook=unique)


def ordinary(path, limit=MAX_FILE):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= limit, 'bounded ordinary source file required')
        content = stream.read(limit + 1)
    require(len(content) <= limit, 'source input byte limit exceeded')
    return content


def canonical_lock():
    rows = []
    for name, (path, digest, size) in EXPECTED.items():
        row = dict(name=name, repository='xykt/IPQuality', commit=COMMIT, path=path, sha256=digest, size=size)
        if name != 'LICENSE.ip':
            row['license_file'] = 'LICENSE.ip'
        rows.append(row)
    return dict(schema=1, files=rows)


def validate(lock):
    require(isinstance(lock, dict) and set(lock) == {'schema', 'files'} and type(lock['schema']) is int
            and lock['schema'] == 1 and isinstance(lock['files'], list), 'exact standalone source manifest required')
    require(len(lock['files']) == len(EXPECTED), 'standalone source roles differ')
    rows = {row['name']: row for row in lock['files'] if isinstance(row, dict) and isinstance(row.get('name'), str)}
    require(len(rows) == len(EXPECTED) and rows == {row['name']: row for row in canonical_lock()['files']},
            'source identity, license or immutable input differs from fixed IPQuality')
    return rows


def verify_files(files):
    require(isinstance(files, dict) and set(files) == set(EXPECTED), 'exact four upstream source roles required')
    for name, content in files.items():
        _path, digest, size = EXPECTED[name]
        require(isinstance(content, bytes) and len(content) == size and hashlib.sha256(content).hexdigest() == digest,
                'standalone source checksum or size mismatch: ' + name)
    return files


def policy_bytes():
    here = Path(__file__).resolve().parent
    directory = here / 'policies'
    # Developer builds may reuse the reviewed helpers. The source offer carries
    # independent exact copies under policies/; the runtime script imports none.
    source_offer = directory.is_dir()
    if not source_offer:
        directory = here.parent / 'nodequality'
    result = {}
    for name, digest in POLICIES.items():
        filename = name + '-policy.py' if source_offer else REVIEWED_POLICY_FILES.get(name, name + '-policy.py')
        content = ordinary(directory / filename, 65536)
        require(hashlib.sha256(content).hexdigest() == digest, 'reviewed policy helper identity mismatch: ' + name)
        result[name] = content
    return result


def load_policies():
    result = {}
    for name, content in policy_bytes().items():
        namespace = {'__name__': 'sinan_ipquality_' + name.replace('-', '_')}
        # Only these previously pinned local transforms execute here. They do
        # not execute upstream source, write files or perform provider queries.
        exec(compile(content, name + '-policy.py', 'exec'), namespace)
        result[name] = namespace
    return result


def transform_files(source_directory):
    """Return derived bytes without writing files or executing upstream code."""
    files = verify_files(source_directory)
    here = Path(__file__).resolve().parent
    validate(decode(ordinary(here / 'source-lock.json', 65536)))
    source_policy = ordinary(here / 'source-policy.py', 65536)
    namespace = {'__name__': 'sinan_standalone_ipquality_policy'}
    exec(compile(source_policy, 'source-policy.py', 'exec'), namespace)
    patched = namespace['transform'](files['ip.sh'], load_policies(),
                                      {name: files[name] for name in ('ip-iso3166.json', 'ip-dnsbl.list')})
    return {'patched-ip.sh': patched, 'transport.py': ordinary(here / 'transport.py', 65536),
            'ip-iso3166.json': files['ip-iso3166.json'], 'ip-dnsbl.list': files['ip-dnsbl.list'],
            'LICENSE.ip': files['LICENSE.ip']}


def pack(lock, directory):
    validate(lock)
    require(directory.is_dir() and not directory.is_symlink(), 'ordinary upstream source directory required')
    files = verify_files({name: ordinary(directory / name) for name in EXPECTED})
    result = dict(schema=1, lock=canonical_lock(), files={name: base64.b64encode(content).decode()
                                                     for name, content in files.items()})
    content = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(content) <= MAX_BUNDLE, 'standalone source bundle byte limit exceeded')
    return content


def bundle_files(bundle):
    require(isinstance(bundle, dict) and set(bundle) == {'schema', 'lock', 'files'}
            and type(bundle['schema']) is int and bundle['schema'] == 1, 'unsupported standalone source bundle')
    validate(bundle['lock'])
    require(isinstance(bundle['files'], dict) and set(bundle['files']) == set(EXPECTED), 'exact source bundle roles required')
    return verify_files({name: base64.b64decode(value, validate=True) for name, value in bundle['files'].items()})


def decode_bundle(content):
    require(isinstance(content, bytes) and 0 < len(content) <= MAX_BUNDLE, 'bounded standalone source bundle required')
    result = decode(content)
    bundle_files(result)
    return result


def materialize(bundle, destination):
    files = bundle_files(bundle)
    derived = transform_files(files)
    destination.mkdir(mode=0o700, exist_ok=False)
    for name, content in {**files, **derived, 'source-lock.json': json.dumps(canonical_lock()).encode()}.items():
        with (destination / name).open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['downloads', 'pack', 'materialize', 'transform'])
    parser.add_argument('input', type=Path)
    parser.add_argument('remaining', nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if arguments.operation == 'downloads':
        require(not arguments.remaining, 'downloads accepts only a fixed lock')
        rows = validate(decode(ordinary(arguments.input, 65536)))
        for name, row in sorted(rows.items()):
            print(name + '\thttps://raw.githubusercontent.com/' + row['repository'] + '/' + row['commit'] + '/' + row['path'])
    elif arguments.operation == 'pack':
        require(len(arguments.remaining) == 1, 'pack requires one ordinary source directory')
        sys.stdout.buffer.write(pack(decode(ordinary(arguments.input, 65536)), Path(arguments.remaining[0])))
    elif arguments.operation == 'materialize':
        require(len(arguments.remaining) == 1, 'materialize requires one new private destination')
        materialize(decode(ordinary(arguments.input, MAX_BUNDLE)), Path(arguments.remaining[0]))
    else:
        require(not arguments.remaining, 'transform accepts only a fixed source directory')
        files = {name: ordinary(arguments.input / name) for name in EXPECTED}
        sys.stdout.buffer.write(transform_files(files)['patched-ip.sh'])


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise SystemExit('IPQuality source guard: ' + str(error)) from None
