#!/usr/bin/env python3
"""Real minisign interoperability and hostile-release contract tests."""

import argparse
import base64
import contextlib
import gzip
import http.server
import io
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/protocol/tests/fixtures"
if not FIXTURES.is_dir():
    FIXTURES = ROOT / "fixtures"
sys.path.insert(0, str(ROOT / "tools"))
import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sinan-release-test-")
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "artifacts"
        for arch in ("amd64", "arm64"):
            agent = self.source / "agent" / "0.3.0"
            agent.mkdir(parents=True, exist_ok=True)
            (agent / arch).write_bytes(b"TEST ONLY Agent " + arch.encode())
            for name, version in (("sing-box", "1.14.2"),
                                  ("nodequality", release.NODEQUALITY_VERSION)):
                runtime = self.source / name / version
                runtime.mkdir(parents=True, exist_ok=True)
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode="w") as archive:
                    data = b"TEST ONLY " + name.encode() + b" " + arch.encode()
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    member.mode = 0o755
                    archive.addfile(member, io.BytesIO(data))
                (runtime / arch).write_bytes(gzip.compress(output.getvalue(), mtime=0))
        self.installer = self.directory / "installer.sh"
        self.installer.write_text("#!/bin/sh\nexit 0\n")
        self.bundle = self.directory / "release"
        self.arguments = argparse.Namespace(source=str(self.source), output=str(self.bundle),
                                             agent_version="0.3.0", runtime_version="1.14.2",
                                             tag="agent-v0.3.0", installer=str(self.installer))
        release.assemble(self.arguments)
        self.roots = release.load_roots(FIXTURES / "public-keys.json")
        self.sign()

    def tearDown(self):
        self.temporary.cleanup()

    def sign(self):
        result = subprocess.run(["minisign", "-S", "-m", str(self.bundle / "SHA256SUMS"),
                                 "-s", str(FIXTURES / "TEST_ONLY.key"), "-x",
                                 str(self.bundle / "SHA256SUMS.minisig"), "-t",
                                 "Sinan TEST ONLY automated fixture"], capture_output=True)
        self.assertEqual(result.returncode, 0, "fixture signing failed")

    def verify(self):
        return release.verify_bundle(self.bundle, self.roots, "minisign", "agent-v0.3.0")

    def rewrite_metadata(self, operation):
        path = self.bundle / "release.json"
        data = json.loads(path.read_text())
        operation(data)
        path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
        manifest = self.bundle / "SHA256SUMS"
        lines = manifest.read_text().splitlines()
        lines = [release.digest(path.read_bytes()) + "  release.json" if line.endswith("  release.json")
                 else line for line in lines]
        manifest.write_text("\n".join(lines) + "\n")
        self.sign()

    def signed_native_runtime(self, files=None):
        binary, auxiliary = b"TEST ONLY native runtime", b"TEST ONLY native DLL"
        files = files if files is not None else [("sing-box.exe", binary), ("wintun.dll", auxiliary)]
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, content in files:
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mode = 0o755
                archive.addfile(member, io.BytesIO(content))
        data = gzip.compress(output.getvalue(), mtime=0)
        metadata_path = self.bundle / "release.json"
        metadata = json.loads(metadata_path.read_text())
        entry = next(item for item in metadata["artifacts"]
                     if item["name"] == "sing-box" and item["arch"] in ("amd64", "windows-amd64"))
        old_path, old_asset = release.canonical_path(entry), entry["asset_name"]
        entry.update(arch="windows-amd64", binary_name="sing-box.exe", archive_size=len(data),
                     binary_size=len(binary), binary_sha256=release.digest(binary),
                     auxiliary_files={"wintun.dll": {"size": len(auxiliary), "sha256": release.digest(auxiliary)}})
        entry["asset_name"] = release.asset_name(entry)
        (self.bundle / old_asset).unlink()
        (self.bundle / entry["asset_name"]).write_bytes(data)
        metadata_path.write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n")
        sums = dict((path, value) for value, path in
                    (line.split("  ", 1) for line in (self.bundle / "SHA256SUMS").read_text().splitlines()))
        sums.pop(old_path)
        sums[release.canonical_path(entry)] = release.digest(data)
        sums["release.json"] = release.digest(metadata_path.read_bytes())
        (self.bundle / "SHA256SUMS").write_text("".join(f"{sums[path]}  {path}\n" for path in sorted(sums)))
        self.sign()
        return binary, auxiliary

    def test_signed_native_runtime_with_auxiliary_file(self):
        self.signed_native_runtime()
        metadata = self.verify()
        entry = next(item for item in metadata["artifacts"] if item["arch"] == "windows-amd64")
        self.assertIn("wintun.dll", entry["auxiliary_files"])

    def test_signed_native_runtime_rejects_wrong_missing_extra_duplicate_and_unsafe_files(self):
        binary, auxiliary = b"TEST ONLY native runtime", b"TEST ONLY native DLL"
        for files in [
            [("sing-box.exe", binary), ("wintun.dll", b"wrong DLL")],
            [("sing-box.exe", binary)],
            [("sing-box.exe", binary), ("wintun.dll", auxiliary), ("unsigned.dll", auxiliary)],
            [("sing-box.exe", binary), ("wintun.dll", auxiliary), ("wintun.dll", auxiliary)],
            [("sing-box.exe", binary), ("../wintun.dll", auxiliary)],
        ]:
            with self.subTest(files=[name for name, _ in files]):
                self.signed_native_runtime(files)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_signed_auxiliary_metadata_rejects_bad_names_sizes_digests_and_field_sets(self):
        self.signed_native_runtime()
        valid = {"sha256": release.digest(b"TEST ONLY native DLL"), "size": len(b"TEST ONLY native DLL")}
        for auxiliary in [
            {"../wintun.dll": valid}, {"sing-box.exe": valid},
            {"release.json": valid}, {".artifact.json": valid},
            {"wintun.dll": dict(valid, size=0)}, {"wintun.dll": dict(valid, size=True)},
            {"wintun.dll": dict(valid, sha256="g" * 64)},
            {"wintun.dll": dict(valid, unsigned="field")},
            {f"extra-{number}.dll": valid for number in range(8)}, [],
        ]:
            with self.subTest(auxiliary=auxiliary):
                self.rewrite_metadata(lambda metadata: next(item for item in metadata["artifacts"]
                    if item["arch"] == "windows-amd64").update(auxiliary_files=auxiliary))
                with self.assertRaises(ValueError):
                    self.verify()

    def test_signed_runner_only_nodequality_cannot_claim_offline_auxiliary_inventory(self):
        def claim(metadata):
            entry = next(item for item in metadata["artifacts"] if item["name"] == "nodequality")
            entry["auxiliary_files"] = {
                "rootfs.tar.gz": {"sha256": "0" * 64, "size": 1},
                "rootfs-manifest.json": {"sha256": "1" * 64, "size": 1},
            }
        self.rewrite_metadata(claim)
        with self.assertRaisesRegex(ValueError, "runner-only NodeQuality identity"):
            release.verify_manifest(self.bundle, self.roots, "minisign", "agent-v0.3.0")

    def append_ipquality_fixture(self, arch="amd64", mutate_notice=None):
        """Signing alone does not authenticate the fixture's intentionally fake profile."""
        import ipquality_artifact
        files = {name: b"TEST ONLY unapproved IPQuality profile " + name.encode()
                 for name in ipquality_artifact.FILES}
        paired = b"TEST ONLY unapproved corresponding Debian and Sinan sources " + arch.encode()
        asset = f"ipquality-{ipquality_artifact.VERSION}-linux-{arch}-sources.tar.gz"
        notice = {"source_offer": {"asset": asset, "size": len(paired), "sha256": release.digest(paired)},
                  "notice": "TEST ONLY unapproved source closure", "license": "AGPL-3.0-only"}
        if mutate_notice is not None:
            mutate_notice(notice)
        files["THIRD_PARTY_NOTICES.txt"] = (b"Sinan IPQuality node self-query\n"
            + (json.dumps(notice, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
        (self.bundle / asset).write_bytes(paired)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name in sorted(files):
                member = tarfile.TarInfo(name)
                member.size = len(files[name])
                member.mode = 0o755 if name == "ipquality" else 0o644
                archive.addfile(member, io.BytesIO(files[name]))
        data = gzip.compress(output.getvalue(), mtime=0)
        entry = {"name": "ipquality", "version": ipquality_artifact.VERSION,
                 "arch": arch, "format": "tar.gz", "binary_name": "ipquality",
                 "archive_size": len(data), "binary_size": len(files["ipquality"]),
                 "binary_sha256": release.digest(files["ipquality"]),
                 "auxiliary_files": {name: {"size": len(content), "sha256": release.digest(content)}
                                     for name, content in files.items() if name != "ipquality"}}
        entry["asset_name"] = release.asset_name(entry)
        (self.bundle / entry["asset_name"]).write_bytes(data)
        metadata_path = self.bundle / "release.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["artifacts"].append(entry)
        metadata_path.write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n")
        sums = dict((path, value) for value, path in
                    (line.split("  ", 1) for line in (self.bundle / "SHA256SUMS").read_text().splitlines()))
        sums[release.canonical_path(entry)] = release.digest(data)
        sums["release.json"] = release.digest(metadata_path.read_bytes())
        (self.bundle / "SHA256SUMS").write_text("".join(f"{sums[path]}  {path}\n" for path in sorted(sums)))
        self.sign()
        return files

    def test_signed_ipquality_manifest_requires_exact_offline_inventory_and_fixed_identity(self):
        self.append_ipquality_fixture()
        release.verify_manifest(self.bundle, self.roots, "minisign", "agent-v0.3.0")
        for mutation in (
            lambda entry: entry.update(version="main"),
            lambda entry: entry.update(binary_name="nodequality"),
            lambda entry: entry.update(arch="windows-amd64"),
            lambda entry: entry.update(auxiliary_files={}),
            lambda entry: entry["auxiliary_files"].pop("source.tar.gz"),
            lambda entry: entry["auxiliary_files"].update({"unexpected.json": {"size": 1, "sha256": "1" * 64}}),
        ):
            original = json.loads((self.bundle / "release.json").read_text())
            self.rewrite_metadata(lambda metadata: mutation(next(item for item in metadata["artifacts"] if item["name"] == "ipquality")))
            with self.assertRaises(ValueError):
                release.verify_manifest(self.bundle, self.roots, "minisign", "agent-v0.3.0")
            self.rewrite_metadata(lambda metadata: metadata.update(original))

    def test_signed_ipquality_bundle_still_requires_source_license_and_rootfs_profile_validation(self):
        import ipquality_artifact
        files = self.append_ipquality_fixture()
        with patch.object(ipquality_artifact, "validate_files", side_effect=ValueError("unapproved IPQuality closure")) as validate:
            with self.assertRaisesRegex(ValueError, "unapproved IPQuality closure"):
                self.verify()
        validate.assert_called_once_with(files, ipquality_artifact.VERSION, "amd64")

    def test_signed_ipquality_source_offer_requires_the_exact_asset_hash_and_full_inventory_check(self):
        import ipquality_artifact
        files = self.append_ipquality_fixture()
        offer = ipquality_artifact.source_offer(files, ipquality_artifact.VERSION, "amd64")
        paired = self.bundle / offer["asset"]
        original = paired.read_bytes()
        with patch.object(ipquality_artifact, "validate_files"), \
                patch.object(ipquality_artifact, "validate_source_offer") as validate:
            self.verify()
            validate.assert_called_once_with(paired, files, ipquality_artifact.VERSION, "amd64")
            validate.reset_mock()
            paired.write_bytes(original + b"changed source")
            with self.assertRaisesRegex(ValueError, "signed declaration"):
                self.verify()
            validate.assert_not_called()
            paired.unlink()
            with self.assertRaisesRegex(ValueError, "ordinary file"):
                self.verify()
            validate.assert_not_called()
            paired.write_bytes(original)
            (self.bundle / "unlisted-sources.tar.gz").write_bytes(b"unsigned source offer")
            with self.assertRaisesRegex(ValueError, "extra release assets"):
                self.verify()
            (self.bundle / "unlisted-sources.tar.gz").unlink()
        with patch.object(ipquality_artifact, "validate_files"), \
                patch.object(ipquality_artifact, "validate_source_offer", side_effect=ValueError("incomplete Debian source inventory")):
            with self.assertRaisesRegex(ValueError, "incomplete Debian source inventory"):
                self.verify()

    def test_signed_ipquality_source_offer_cannot_change_architecture_version_or_path(self):
        import ipquality_artifact
        for name in ("../untrusted.tar.gz", "ipquality-main-linux-amd64-sources.tar.gz",
                     f"ipquality-{ipquality_artifact.VERSION}-linux-arm64-sources.tar.gz"):
            with self.subTest(name=name):
                files = self.append_ipquality_fixture(mutate_notice=lambda notice: notice["source_offer"].update(asset=name))
                with self.assertRaises(ValueError):
                    ipquality_artifact.source_offer(files, ipquality_artifact.VERSION, "amd64")
                # Keep the next iteration's fixture identities unique.
                self.rewrite_metadata(lambda metadata: metadata.update(artifacts=[
                    entry for entry in metadata["artifacts"] if entry["name"] != "ipquality"]))
                sums = self.bundle / "SHA256SUMS"
                sums.write_text("".join(line for line in sums.read_text().splitlines(keepends=True)
                                        if "  ipquality/" not in line))
                self.sign()

    def test_ipquality_assembly_copies_only_the_signed_paired_source_archive(self):
        import ipquality_artifact
        files = self.append_ipquality_fixture()
        offer = ipquality_artifact.source_offer(files, ipquality_artifact.VERSION, "amd64")
        original = (self.bundle / offer["asset"]).read_bytes()
        entry = next(item for item in json.loads((self.bundle / "release.json").read_text())["artifacts"]
                     if item["name"] == "ipquality")
        directory = self.source / "ipquality" / ipquality_artifact.VERSION
        directory.mkdir(parents=True)
        (directory / "amd64").write_bytes((self.bundle / entry["asset_name"]).read_bytes())
        paired = directory / "amd64.sources.tar.gz"
        paired.write_bytes(original)
        self.arguments.ipquality_version = ipquality_artifact.VERSION
        self.arguments.arch = ["amd64"]
        self.arguments.output = str(self.directory / "paired-ipquality-release")
        with patch.object(ipquality_artifact, "validate_files"), \
                patch.object(ipquality_artifact, "validate_source_offer") as validate:
            release.assemble(self.arguments)
            validate.assert_called_once_with(paired, files, ipquality_artifact.VERSION, "amd64")
            self.assertEqual((Path(self.arguments.output) / offer["asset"]).read_bytes(), original)
            self.assertNotIn(offer["asset"], (Path(self.arguments.output) / "SHA256SUMS").read_text())
            paired.write_bytes(b"different source offer")
            self.arguments.output = str(self.directory / "changed-ipquality-release")
            with self.assertRaisesRegex(ValueError, "signed declaration"):
                release.assemble(self.arguments)
            self.assertFalse((Path(self.arguments.output) / "release.json").exists())

    def test_paired_source_assets_are_streamed_and_reject_unsafe_or_oversized_files(self):
        paired = self.directory / "paired.tar.gz"
        content = b"TEST ONLY streamed source" * 1024
        paired.write_bytes(content)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("source asset must be streamed")):
            self.assertEqual(release.regular_file_proof(paired),
                             {"size": len(content), "sha256": release.digest(content)})
        with self.assertRaises(ValueError):
            release.regular_file_proof(paired, len(content) - 1)
        linked = self.directory / "source-link.tar.gz"
        linked.symlink_to(paired)
        with self.assertRaises(ValueError):
            release.regular_file_proof(linked)
        linked.unlink()
        os.link(paired, linked)
        with self.assertRaises(ValueError):
            release.regular_file_proof(paired)

    def test_ipquality_assembly_is_opt_in_and_refuses_an_unapproved_profile_before_signing(self):
        import ipquality_artifact
        self.assertFalse(any(entry["name"] == "ipquality" for entry in json.loads((self.bundle / "release.json").read_text())["artifacts"]))
        self.arguments.ipquality_version = ipquality_artifact.VERSION
        self.arguments.output = str(self.directory / "unapproved-ipquality-release")
        directory = self.source / "ipquality" / ipquality_artifact.VERSION
        directory.mkdir(parents=True)
        (directory / "amd64").write_bytes(b"TEST ONLY unapproved input")
        with patch.object(ipquality_artifact, "archive_files", return_value={"fixture": b"unapproved"}), \
                patch.object(ipquality_artifact, "validate_files", side_effect=ValueError("unapproved IPQuality closure")) as validate:
            with self.assertRaisesRegex(ValueError, "unapproved IPQuality closure"):
                release.assemble(self.arguments)
        validate.assert_called_once_with({"fixture": b"unapproved"}, ipquality_artifact.VERSION, "amd64")
        self.assertFalse((Path(self.arguments.output) / "release.json").exists())

    def test_raw_artifact_cannot_claim_auxiliary_files(self):
        self.rewrite_metadata(lambda metadata: metadata["artifacts"][0].update(
            auxiliary_files={"extra.dll": {"sha256": "0" * 64, "size": 1}}))
        with self.assertRaises(ValueError):
            self.verify()

    def test_auxiliary_file_cannot_be_a_symbolic_link(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            binary = tarfile.TarInfo("sing-box.exe")
            binary.size = 1
            archive.addfile(binary, io.BytesIO(b"x"))
            auxiliary = tarfile.TarInfo("wintun.dll")
            auxiliary.type = tarfile.SYMTYPE
            auxiliary.linkname = "../../untrusted.dll"
            archive.addfile(auxiliary)
        with self.assertRaises(ValueError):
            release.binary_bytes(gzip.compress(output.getvalue()), "tar.gz", "sing-box.exe",
                                 {"wintun.dll": {"sha256": release.digest(b"x"), "size": 1}})

    def test_concatenated_gzip_cannot_hide_nonzero_tail(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            member = tarfile.TarInfo("sing-box")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        payload = gzip.compress(output.getvalue()) + gzip.compress(b"unlisted trailing payload")
        with self.assertRaisesRegex(ValueError, "trailing data"):
            release.binary_bytes(payload, "tar.gz", "sing-box")

    def test_raw_extension_headers_and_total_unpacked_overflow_are_rejected(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", pax_headers={"comment": "unlisted metadata"}) as archive:
            member = tarfile.TarInfo("sing-box")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "unsafe archive member"):
            release.binary_bytes(gzip.compress(output.getvalue()), "tar.gz", "sing-box")
        self.signed_native_runtime()
        entry = next(item for item in json.loads((self.bundle / "release.json").read_text())["artifacts"]
                     if item["arch"] == "windows-amd64")
        with patch.object(release, "MAX_BINARY", 4096):
            with self.assertRaisesRegex(ValueError, "unpacked size limit"):
                release.binary_bytes((self.bundle / entry["asset_name"]).read_bytes(), "tar.gz",
                                     entry["binary_name"], entry["auxiliary_files"])

    def test_legacy_archive_still_rejects_additional_unsigned_file(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name in ("sing-box", "unsigned.dll"):
                member = tarfile.TarInfo(name)
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(ValueError):
            release.binary_bytes(gzip.compress(output.getvalue()), "tar.gz", "sing-box")

    def test_valid_complete_signature_and_every_asset(self):
        self.assertEqual(len(self.verify()["artifacts"]), 6)

    def test_single_architecture_ci_bundle(self):
        self.arguments.arch = ["amd64"]
        self.arguments.output = str(self.directory / "single")
        release.assemble(self.arguments)
        data = json.loads((Path(self.arguments.output) / "release.json").read_text())
        self.assertEqual({entry["arch"] for entry in data["artifacts"]}, {"amd64"})
        self.assertEqual({entry["name"] for entry in data["artifacts"]},
                         {"agent", "sing-box", "nodequality"})

    def test_deterministic_manifests(self):
        second = self.directory / "second"
        self.arguments.output = str(second)
        release.assemble(self.arguments)
        for name in ("release.json", "SHA256SUMS"):
            self.assertEqual((second / name).read_bytes(), (self.bundle / name).read_bytes())

    def test_tampered_signed_checksum_file(self):
        with (self.bundle / "SHA256SUMS").open("a") as file:
            file.write("0" * 64 + "  extra\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_tampered_trusted_comment(self):
        path = self.bundle / "SHA256SUMS.minisig"
        lines = path.read_text().splitlines()
        lines[2] += " modified"
        path.write_text("\n".join(lines) + "\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_truncated_signature(self):
        path = self.bundle / "SHA256SUMS.minisig"
        path.write_text("\n".join(path.read_text().splitlines()[:3]) + "\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_legacy_signature_refused(self):
        path = self.bundle / "SHA256SUMS.minisig"
        lines = path.read_text().splitlines()
        data = base64.b64decode(lines[1])
        lines[1] = base64.b64encode(b"Ed" + data[2:]).decode()
        path.write_text("\n".join(lines) + "\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_modified_archive(self):
        path = self.bundle / "sing-box-1.14.2-linux-amd64.tar.gz"
        path.write_bytes(path.read_bytes() + b"modified")
        with self.assertRaises(ValueError):
            self.verify()

    def test_signed_wrong_binary_digest(self):
        self.rewrite_metadata(lambda data: data["artifacts"][0].update(binary_sha256="0" * 64))
        with self.assertRaises(ValueError):
            self.verify()

    def test_signed_wrong_asset_name(self):
        self.rewrite_metadata(lambda data: data["artifacts"][0].update(asset_name="../escape"))
        with self.assertRaises(ValueError):
            self.verify()

    def test_signed_wrong_protocol_range(self):
        self.rewrite_metadata(lambda data: data.update(protocol_min=2, protocol_max=2))
        with self.assertRaises(ValueError):
            self.verify()

    def test_signed_protocol_range_that_includes_this_client_is_compatible(self):
        self.rewrite_metadata(lambda data: data.update(protocol_max=2))
        self.assertEqual(self.verify()["protocol_max"], 2)

    def test_signed_unknown_metadata_field(self):
        self.rewrite_metadata(lambda data: data.update(public_keys=self.roots))
        with self.assertRaises(ValueError):
            self.verify()

    def test_extra_asset_refused(self):
        (self.bundle / "unsigned").write_text("unsigned")
        with self.assertRaises(ValueError):
            self.verify()

    def test_duplicate_checksum_refused_even_when_signed(self):
        path = self.bundle / "SHA256SUMS"
        text = path.read_text()
        path.write_text(text + text.splitlines()[0] + "\n")
        self.sign()
        with self.assertRaises(ValueError):
            self.verify()

    def test_test_key_cannot_publish(self):
        with self.assertRaises(ValueError):
            release.load_roots(FIXTURES / "public-keys.json", publication=True)

    def test_duplicate_trust_root_refused(self):
        path = self.directory / "duplicate-public-keys.json"
        path.write_text(json.dumps(self.roots * 2))
        with self.assertRaises(ValueError):
            release.load_roots(path)

    def test_test_key_cannot_publish_with_another_key_id(self):
        material = bytearray(base64.b64decode(self.roots[0]))
        material[2:10] = b"other-id"
        path = self.directory / "renamed-key.json"
        path.write_text(json.dumps([base64.b64encode(material).decode()]))
        with self.assertRaises(ValueError):
            release.load_roots(path, publication=True)

    def test_rotation_key_cannot_publish_with_another_key_id(self):
        material = bytearray(base64.b64decode(release.TEST_ONLY_ROTATION_PUBLIC_KEY))
        material[2:10] = b"other-id"
        path = self.directory / "renamed-rotation-key.json"
        path.write_text(json.dumps([base64.b64encode(material).decode()]))
        with self.assertRaises(ValueError):
            release.load_roots(path, publication=True)

    def test_every_test_public_fixture_is_denied(self):
        material = b"Ed" + b"test-id!" + b"\x42" * 32
        record = base64.b64encode(material).decode()
        fixtures = self.directory / "fixture-pubs"
        fixtures.mkdir()
        (fixtures / "TEST_ONLY_FUTURE.pub").write_text("untrusted comment: TEST ONLY\n" + record + "\n")
        path = self.directory / "new-fixture-key.json"
        path.write_text(json.dumps([record]))
        with patch.object(release, "TEST_PUBLIC_KEY_DIRS", (fixtures,)):
            with self.assertRaises(ValueError):
                release.load_roots(path, publication=True)

    def test_archive_path_traversal_refused(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            member = tarfile.TarInfo("../sing-box")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(ValueError):
            release.binary_bytes(gzip.compress(output.getvalue()), "tar.gz", "sing-box")

    def signed_executable_fixture(self):
        self.installer_architecture = {"x86_64": "amd64", "amd64": "amd64",
                                       "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
        self.installer_asset = "agent-0.3.0-linux-musl-" + self.installer_architecture
        good_marker = self.directory / "trusted-agent-executed"
        bad_marker = self.directory / "untrusted-agent-executed"

        def executable(marker):
            # A fake verifier must reject incorrect role-binding arguments too.
            return ("#!/bin/sh\n"
                    '[ "$#" = 7 ] && [ "$1" = verify-installed ] && [ "$2" = --binary ] && '
                    '[ "$3" = "$0" ] && [ "$4" = --name ] && [ "$5" = agent ] && '
                    '[ "$6" = --format ] && [ "$7" = raw ] || exit 93\n'
                    "printf verified > " + shlex.quote(str(marker)) + "\n").encode()

        good, bad = executable(good_marker), executable(bad_marker)
        size = max(len(good), len(bad)) + 64
        good, bad = good.ljust(size, b"\n"), bad.ljust(size, b"\n")
        (self.bundle / self.installer_asset).write_bytes(good)

        def update(metadata):
            entry = next(item for item in metadata["artifacts"]
                         if item["name"] == "agent" and item["arch"] == self.installer_architecture)
            entry.update(archive_size=size, binary_size=size, binary_sha256=release.digest(good))

        self.rewrite_metadata(update)
        manifest = self.bundle / "SHA256SUMS"
        proof_identity = "  agent/0.3.0/" + self.installer_architecture
        lines = [release.digest(good) + proof_identity if
                 line.endswith(proof_identity) else line
                 for line in manifest.read_text().splitlines()]
        manifest.write_text("\n".join(lines) + "\n")
        self.sign()
        self.verify()
        return good, bad, good_marker, bad_marker

    @contextlib.contextmanager
    def panel_response(self, payload, length=True, redirect=False):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.requests += 1
                self.send_response(302 if redirect else 200)
                if redirect:
                    self.send_header("Location", "/never-follow")
                elif length:
                    self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if not redirect:
                    try:
                        self.wfile.write(payload)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            def log_message(self, format, *arguments):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.requests = 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def installer_prefix(self, panel, forced_optimization=False, payload=None, target=None, core_root=None):
        if payload is not None:
            (self.bundle / self.installer_asset).write_bytes(payload)
        # Execute the actual production path through its first Agent execution.
        text = release.installer_source(ROOT / "deploy/install.sh.tmpl", ROOT / "deploy/sinan-agent.service",
                                        ROOT / "plugins/sing-box/sinan-singbox@.service", source_root=ROOT)
        text = text.split("# Reject unverifiable legacy caches", 1)[0] + "\nexit 0\n"
        if core_root:
            text = text.replace("/opt/sinan/core", str(core_root))
        if forced_optimization:
            proof_verifier = 'python3 -I - "$BUNDLE"'
            self.assertEqual(text.count(proof_verifier), 1, "installer prefix must retain the signed proof verifier")
            text = text.replace(proof_verifier, 'python3 -I -O - "$BUNDLE"', 1)
        script = self.directory / "verified-installer-prefix.sh"
        script.write_text(text)
        token = self.directory / "fixture-token"
        token.write_text("TEST_ONLY_token")
        commands = self.directory / "commands"
        commands.mkdir(exist_ok=True)
        for name in ("systemctl", "useradd"):
            path = commands / name
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
        Path("/run/systemd/system").mkdir(parents=True, exist_ok=True)
        modules = self.directory / "untrusted-python-path"
        modules.mkdir(exist_ok=True)
        environment_marker = self.directory / "python-environment-injected"
        (modules / "json.py").write_text(
            "from pathlib import Path\nPath(" + repr(str(environment_marker)) + ").write_text('injected')\n")
        environment = dict(os.environ, PATH=str(commands) + ":" + os.environ["PATH"],
                           PYTHONOPTIMIZE="1", PYTHONPATH=str(modules),
                           HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9",
                           ALL_PROXY="socks5://127.0.0.1:9", NO_PROXY="", no_proxy="")
        arguments = ["/bin/sh", str(script), "--bundle", str(self.bundle),
                     "--version", "0.3.0", "--panel", panel, "--token-file", str(token)]
        if target:
            arguments.extend(["--target", target])
        result = subprocess.run(arguments, env=environment,
                                capture_output=True, timeout=35)
        self.assertFalse(environment_marker.exists(), "installer imported an untrusted Python module")
        return result

    @unittest.skipUnless(os.getuid() == 0, "real installer prefix requires isolated Linux container root")
    def test_optimized_installer_refuses_tampered_raw_without_execution(self):
        good, bad, good_marker, bad_marker = self.signed_executable_fixture()
        self.assertEqual(len(good), len(bad))
        for forced in (False, True):
            with self.subTest(forced_optimization=forced), self.panel_response(bad) as (server, panel):
                result = self.installer_prefix(panel, forced, bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(server.requests, 0)
                self.assertIn("摘要不匹配".encode(), result.stderr)
                self.assertFalse(bad_marker.exists())
                self.assertFalse(good_marker.exists())

    @unittest.skipUnless(os.getuid() == 0, "real installer prefix requires isolated Linux container root")
    def test_installer_accepts_signed_raw_and_passes_role_binding(self):
        good, _, good_marker, bad_marker = self.signed_executable_fixture()
        with self.panel_response(good) as (server, panel):
            result = self.installer_prefix(panel, True, good)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(server.requests, 0)
            self.assertEqual(good_marker.read_text(), "verified")
            self.assertFalse(bad_marker.exists())

    def signed_abi_fixture(self, abi):
        good, _, marker, _ = self.signed_executable_fixture()
        old_arch, old_asset = self.installer_architecture, self.installer_asset
        target = "linux-" + abi + "-" + old_arch
        self.installer_asset = "agent-0.3.0-" + target
        (self.bundle / old_asset).rename(self.bundle / self.installer_asset)

        def update(metadata):
            entry = next(item for item in metadata["artifacts"]
                         if item["name"] == "agent" and item["arch"] == old_arch)
            entry.update(arch=target, asset_name=self.installer_asset)

        self.rewrite_metadata(update)
        manifest = self.bundle / "SHA256SUMS"
        rows = dict(line.split("  ")[::-1] for line in manifest.read_text().splitlines())
        rows["agent/0.3.0/" + target] = rows.pop("agent/0.3.0/" + old_arch)
        manifest.write_text("".join(f"{rows[path]}  {path}\n" for path in sorted(rows)))
        self.sign()
        self.verify()
        return good, marker, target

    @unittest.skipUnless(os.getuid() == 0, "real installer prefix requires isolated Linux container root")
    def test_installer_accepts_exact_signed_musl_identity(self):
        good, marker, target = self.signed_abi_fixture("musl")
        with self.panel_response(good) as (server, panel):
            result = self.installer_prefix(panel, payload=good, target=target)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(server.requests, 0)
            self.assertEqual(marker.read_text(), "verified")

    @unittest.skipUnless(os.getuid() == 0 and platform.libc_ver()[0] == "glibc",
                         "GNU Agent prefix requires root on a GNU/glibc host")
    def test_installer_accepts_exact_signed_gnu_identity(self):
        good, marker, target = self.signed_abi_fixture("gnu")
        with self.panel_response(good) as (server, panel):
            result = self.installer_prefix(panel, payload=good, target=target)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(server.requests, 0)
            self.assertEqual(marker.read_text(), "verified")

    @unittest.skipUnless(os.getuid() == 0, "protected executable staging test requires root")
    def test_installer_refuses_writable_execution_parent_before_agent_execution(self):
        good, _, marker, _ = self.signed_executable_fixture()
        with tempfile.TemporaryDirectory(prefix="sinan-installer-parent-", dir="/root") as directory:
            unsafe = Path(directory) / "unsafe-core"
            unsafe.mkdir(mode=0o777)
            unsafe.chmod(0o777)
            with self.panel_response(good) as (server, panel):
                result = self.installer_prefix(panel, payload=good, core_root=unsafe)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("root 保护".encode(), result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(server.requests, 0)
            self.assertEqual(list(unsafe.iterdir()), [])

    @unittest.skipUnless(os.getuid() == 0, "real installer prefix requires isolated Linux container root")
    def test_installer_refuses_unbounded_body_at_signed_size(self):
        good, _, good_marker, bad_marker = self.signed_executable_fixture()
        with self.panel_response(good + b"x" * 1048576, length=False) as (server, panel):
            result = self.installer_prefix(panel, payload=good + b"x" * 1048576)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(server.requests, 0)
            self.assertIn("有界普通文件".encode(), result.stderr)
            self.assertFalse(good_marker.exists())
            self.assertFalse(bad_marker.exists())

    @unittest.skipUnless(os.getuid() == 0, "real installer prefix requires isolated Linux container root")
    def test_missing_preloaded_agent_never_falls_back_to_panel(self):
        good, _, good_marker, bad_marker = self.signed_executable_fixture()
        (self.bundle / self.installer_asset).unlink()
        with self.panel_response(good, redirect=True) as (server, panel):
            result = self.installer_prefix(panel)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(server.requests, 0)
            self.assertIn("有界普通文件".encode(), result.stderr)
            self.assertFalse(good_marker.exists())
            self.assertFalse(bad_marker.exists())


if __name__ == "__main__":
    unittest.main()
