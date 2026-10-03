#!/usr/bin/env python3
"""Inert standalone bootstrap metadata contracts; no signing or installation."""
import ast
import base64
import importlib.util
import json
import lzma
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import release

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bootstrap_artifact_render", ROOT / "tools/render-bootstrap.py")
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)


class StandaloneMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sinan-bootstrap-artifact-TEST_ONLY-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.stage = self.root / "standalone"
        self.stage.mkdir(mode=0o700)
        # Execute only the generated fixed local-byte materializer. No shell,
        # installer, download path or artifact factory is invoked.
        rendered = RENDER.render(test_installer="#!/bin/sh\nexit 99\n", publication=False,
                                 trusted_keys=ROOT / "crates/protocol/tests/fixtures/public-keys.json")
        begin = '"$PYTHON" -I - "$STAGING" <<\'' + RENDER.PAYLOAD_BEGIN + "'\n"
        self.assertEqual(rendered.count(begin), 1)
        self.program = rendered.split(begin, 1)[1].split("\n" + RENDER.PAYLOAD_BEGIN + "\n", 1)[0] + "\n"
        result = subprocess.run([sys.executable, "-B", "-I", "-", str(self.stage)], input=self.program,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLessEqual(len(rendered.encode()), RENDER.MAX_BOOTSTRAP)
        self.manifest = next(ast.literal_eval(node.value) for node in ast.parse(self.program).body
                             if isinstance(node, ast.Assign) and node.targets[0].id == "manifest")
        self.assertEqual(set(self.manifest),
                         set(RENDER.SOURCES[:-1]) | set(RENDER.PLUGIN_SOURCES)
                         | {"public-keys.json", "tools/trusted-install.sh"})

    def isolated(self, program, *args):
        result = subprocess.run([sys.executable, "-B", "-I", "-c",
                                 "import os,sys;sys.path.insert(0,os.getcwd()+'/tools');" + program, *map(str, args)],
                                cwd=self.stage, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def bundle(self, module, version, auxiliary):
        entry = {"name": module, "version": version, "arch": "amd64", "format": "tar.gz",
                 "binary_name": module, "archive_size": 4, "binary_size": 3,
                 "binary_sha256": "a" * 64,
                 "auxiliary_files": {name: {"sha256": "b" * 64, "size": 1}
                                     for name in auxiliary}}
        entry["asset_name"] = release.asset_name(entry)
        bundle = self.root / (module + "-" + version)
        bundle.mkdir(mode=0o700)
        metadata = {"schema": 1, "source_repo": release.REPOSITORY, "tag": "agent-v0.3.0",
                    "protocol_min": 1, "protocol_max": 1, "artifacts": [entry]}
        encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        installer = b"#!/bin/sh\nexit 99\n"
        (bundle / "release.json").write_bytes(encoded)
        (bundle / "install.sh").write_bytes(installer)
        rows = {"release.json": release.digest(encoded), "install.sh": release.digest(installer),
                release.canonical_path(entry): "c" * 64}
        (bundle / "SHA256SUMS").write_text("".join(f"{rows[path]}  {path}\n" for path in sorted(rows)))
        return bundle

    def test_standalone_metadata_accepts_exact_legacy_and_explicit_native_inventories(self):
        stem = "a92fca6c0067df29ddd03fdc2fee6f3000f64545"
        rootfs = {"rootfs.tar.gz", "rootfs-manifest.json"}
        vectors = [("nodequality", stem + suffix, auxiliary) for suffix, auxiliary in
                   (("-r19", set()), ("-r20", rootfs), ("-r21", set()), ("-r22", set()),
                    ("-sinan-native-r1", set()), ("-sinan-native-r2", set()), ("-offline-rootfs-r1", rootfs))]
        vectors.append(("ipquality", "87397e2c3196ec796f5477c83343c2354df601ea-node-r1",
                        rootfs | {"build-info.json", "LICENSE", "source.tar.gz", "THIRD_PARTY_NOTICES.txt"}))
        for module, version, auxiliary in vectors:
            with self.subTest(module=module, version=version):
                bundle = self.bundle(module, version, auxiliary)
                output = self.isolated("import release;release.validate_manifest(sys.argv[1],'agent-v0.3.0');"
                                       "print('TEST_ONLY metadata, no signature acceptance')", bundle)
                self.assertIn("TEST_ONLY metadata", output)

    def test_standalone_missing_offline_inventory_is_refused(self):
        bundle = self.bundle("nodequality", "a92fca6c0067df29ddd03fdc2fee6f3000f64545-offline-rootfs-r1",
                             {"rootfs.tar.gz"})
        output = self.isolated("import release\ntry:release.validate_manifest(sys.argv[1],'agent-v0.3.0')\n"
                               "except ValueError as error:print(error)\nelse:raise SystemExit(1)", bundle)
        self.assertIn("incomplete offline NodeQuality", output)

    def test_old_asset_limit_never_imports_optional_ipquality_validator(self):
        output = self.isolated("import builtins,release\noriginal=builtins.__import__\n"
                               "def guarded(name,*args,**kwargs):\n"
                               " if name=='ipquality_artifact':raise AssertionError('unexpected optional import')\n"
                               " return original(name,*args,**kwargs)\n"
                               "builtins.__import__=guarded\n"
                               "assert release.source_offer_asset_limit('agent-0.3.0-linux-musl-amd64')==release.MAX_BINARY\n"
                               "assert release.source_offer_asset_limit('nodequality-old-linux-amd64.tar.gz')==release.MAX_BINARY\n"
                               "print('old identity independent')")
        self.assertIn("independent", output)

    def test_isolated_historical_readers_have_exact_original_bytes_and_complete_derivation_inputs(self):
        output = self.isolated("""import hashlib,json,pathlib
import nodequality_history as history
import nodequality_rootfs_artifact as legacy
import nodequality_native_rootfs_artifact as native
import nodequality_node_query_artifact as query
stage=pathlib.Path.cwd()
assert legacy.ROOT==stage and native.ROOT==stage and query.ROOT==stage
for identities,reader in ((history.IDENTITIES,history.source),(history.NATIVE_IDENTITIES,history.native_source)):
 for name,digest in identities.items():
  content=reader(name)
  assert hashlib.sha256(content).hexdigest()==digest and len(content)<=history.MAX_FILE
assert history.rootfs_module().MAX_ENTRIES==100000
for artifact in (legacy,native):
 assert artifact.runtime().MAX_ENTRIES==100000
 helper=artifact.module('TEST_ONLY_isolated_helper',artifact.PLUGIN/artifact.HELPERS['SOURCE_HELPER'])
 for name in artifact.HELPERS.values():
  assert helper.ordinary(artifact.PLUGIN/name,artifact.MAX_RUNNER)
 lock=helper.decode(helper.ordinary(artifact.PLUGIN/'source-lock.json',artifact.MAX_MANIFEST))
 payload=json.dumps({'schema':1,'lock':lock,'files':{}}).encode()
 try:artifact.canonical_runner(payload)
 except ValueError as error:assert 'complete canonical source bundle' in str(error),str(error)
 else:raise AssertionError('incomplete source inventory was accepted')
assert legacy.runtime().ordinary(query.PLUGIN/'node-query.py',128*1024)
print('exact isolated histories and strict derivation closure')
""")
        self.assertIn("strict derivation closure", output)

    def test_isolated_historical_tampering_is_refused_before_compiling_source(self):
        for directory, names in (("historical-r19", ("runner.sh.tmpl", "report.py", "rootfs.py")),
                                 ("historical-native-r1", ("native-runner.sh.tmpl", "native-report.py"))):
            for name in names:
                path = self.stage / "plugins/nodequality" / directory / name
                original = path.read_bytes()
                try:
                    path.write_bytes(b"raise AssertionError('changed historical code executed')\n")
                    reader = "source" if directory == "historical-r19" else "native_source"
                    output = self.isolated(f"import nodequality_history as history\n"
                                           f"try:history.{reader}(sys.argv[1])\n"
                                           "except ValueError as error:print(error)\nelse:raise SystemExit(1)", name)
                    self.assertIn("identity mismatch", output)
                finally:
                    path.write_bytes(original)

    def test_isolated_ipquality_factory_closure_keeps_current_proof_code_and_strict_runner_intake(self):
        output = self.isolated("""import ast,pathlib
import ipquality_artifact as ip
stage=pathlib.Path.cwd()
assert ip.ROOT==stage
build=ip.factory()
derive=build.INPUT_PROFILE
assert derive.build is build and set(derive.commands)==set(build.TOOL_PACKAGES)
inputs=__import__('importlib.util').util.spec_from_file_location('TEST_ONLY_inputs',stage/'tools/ipquality-inputs.py')
module=__import__('importlib.util').util.module_from_spec(inputs)
inputs.loader.exec_module(module)
closure=module.modules()
assert set(closure)=={'profile','build','collect','parent_build','capacity'}
for name in module.CODE_FILES:
 assert ip.runtime().ordinary(stage/name,ip.MAX_SOURCE)
for name in ('plugins/ipquality/source-helper.py','plugins/ipquality/SOURCE.md','tools/build-ipquality.py',
             'plugins/ipquality/source-lock.json','plugins/ipquality/source-policy.py','plugins/ipquality/transport.py','LICENSE'):
 assert ip.runtime().ordinary(stage/name,ip.MAX_SOURCE)
helper=ip.module('TEST_ONLY_ip_sources',ip.PLUGIN/'source-helper.py')
assert set(helper.policy_bytes())==set(helper.POLICIES)
assert helper.validate(helper.decode(helper.ordinary(ip.PLUGIN/'source-lock.json')))
runner=ip.runner()
embedded=[node.value for node in ast.parse(runner.decode('utf-8')).body
          if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name)
          and target.id=='ROOTFS_SOURCE' for target in node.targets)]
assert len(embedded)==1
verifier=ast.literal_eval(embedded[0])
assert isinstance(verifier,str) and verifier.encode('utf-8')==(stage/'plugins/nodequality/rootfs.py').read_bytes()
files={name:b'not a valid artifact' for name in ip.FILES}
files[ip.BINARY]=runner
try:ip.validate_files(files,ip.VERSION,'amd64')
except (ValueError,TypeError):pass
else:raise AssertionError('invalid current source proof was accepted')
print('isolated current IPQuality proof closure remains strict')
""")
        self.assertIn("proof closure remains strict", output)

    def test_corrupt_or_incomplete_embedded_inventory_is_refused_before_any_stage_write(self):
        tree = ast.parse(self.program)
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and node.targets[0].id == "payload")
        original = ast.literal_eval(assignment.value)
        sources = json.loads(lzma.decompress(base64.b85decode(original)))
        for change in ("modified", "missing", "extra"):
            values = dict(sources)
            if change == "modified":
                values["tools/nodequality_history.py"] = "changed"
            elif change == "missing":
                del values["plugins/nodequality/historical-r19/rootfs.py"]
            else:
                values["../outside.py"] = "changed"
            compressed = lzma.compress(json.dumps(values).encode(), format=lzma.FORMAT_XZ,
                                       filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1024 * 1024}])
            encoded = base64.b85encode(compressed).decode()
            program = self.program.replace("payload = " + repr(original), "payload = " + repr(encoded), 1)
            target = self.root / change
            target.mkdir(mode=0o700)
            result = subprocess.run([sys.executable, "-B", "-I", "-", str(target)], input=program,
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(list(target.iterdir()), [])

    def test_directory_swap_during_materialization_never_follows_replacement_link(self):
        target = self.root / "directory-swap"
        target.mkdir(mode=0o700)
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        hook = """original_open = os.open
def replace_open_directory(path, flags, mode=0o777, *, dir_fd=None):
    descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
    if path == 'tools' and flags & os.O_DIRECTORY:
        source = pathlib.Path(sys.argv[1]) / 'tools'
        source.rename(source.with_name('held-tools'))
        source.symlink_to(pathlib.Path(sys.argv[2]), target_is_directory=True)
    return descriptor
os.open = replace_open_directory
"""
        imports, rest = self.program.split("\n", 1)
        program = imports + "\n" + hook + rest
        result = subprocess.run([sys.executable, "-B", "-I", "-", str(target), str(outside)],
                                input=program, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((target / "held-tools/artifact_manifest.py").is_file())


if __name__ == "__main__":
    unittest.main()
