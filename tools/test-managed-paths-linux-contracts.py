#!/usr/bin/env python3
"""Tool boundary regressions; these never count as registered-device acceptance."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("managed_paths_driver", Path(__file__).with_name("test-managed-paths-linux.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


def checkpoint(revision=3, instance="instance-1"):
    return {"binding": {"revision": revision, "bundle_sha256": "a" * 64,
                        "deployment_id": "deployment", "binding_digest": "b" * 64},
            "healthy": True, "activation_id": "activation", "instance": {"instance_id": instance}}


def proof_fixture():
    expected = checkpoint()
    vector = [[1, expected], [2, checkpoint(4)]]
    value = {"path_probes": [], "requests": [], "receipts": [], "vectors": []}
    for stage in ("candidate", "switched"):
        request_id = stage + "-request"
        probe_id = stage + "-probe"
        value["path_probes"].append({"chain_id": 8, "generation": 2, "stage": stage,
                                    "state": "verified", "request_id": request_id,
                                    "probe_id": probe_id, "dependency_vector": copy.deepcopy(vector)})
        value["requests"].append({"request_id": request_id, "server_id": 1, "kind": "probe",
                                 "expected": copy.deepcopy(expected), "digest": "d" * 64})
        value["receipts"].append({"request_id": request_id, "outcome": "verified",
                                 "result": {"success": True, "observed": copy.deepcopy(expected),
                                            "request_digest": "d" * 64, "probe_id": probe_id}})
    value["vectors"].append({"chain_id": 8, "generation": 2, "barrier_request_id": "barrier",
                              "barrier_vector": copy.deepcopy(vector), "revision": 3,
                              **{key: expected["binding"][key] for key in ("bundle_sha256", "deployment_id", "binding_digest")}})
    value["requests"].append({"request_id": "barrier", "server_id": 1, "kind": "barrier",
                              "expected": copy.deepcopy(expected), "digest": "e" * 64})
    value["receipts"].append({"request_id": "barrier", "outcome": "verified", "result": {
        "success": True, "observed": copy.deepcopy(expected), "request_digest": "e" * 64,
        "pending_intents_clear": True, "minimum_revision": 3}})
    return value


def manifest_fixture(root):
    """Actual private file shapes for pure binding checks, never live facts."""
    root.chmod(0o700)
    run_id = "ab12640c-270f-4a82-a506-41176e42e19f"
    DRIVER.write_bytes(root / ".sinan-managed-test-run", (run_id + "\n").encode())
    source = {"head": "a" * 40, "file_count": 782, "frozen_inputs_sha256": "b" * 64,
              "functional_sha256": "c" * 64, "cargo_lock_sha256": "d" * 64}
    programs = {}
    for name in ("controller", "fixture"):
        path = root / (name + ".py")
        DRIVER.write_bytes(path, b"# TEST_ONLY pure manifest fixture; do not execute.\n")
        programs[name] = {"path": str(path), "sha256": DRIVER.digest(path.read_bytes())}
    roles = {}
    for index, role in enumerate(("A", "M", "B"), 2):
        config = root / ("agent-" + role + ".toml")
        DRIVER.write_bytes(config, b'panel_url = "https://owned.test"\npanel_ca_file = "/etc/sinan/trust/panel-ca.pem"\n')
        roles[role] = {"address": "10.231.0." + str(index), "sni": "reality.test",
                       "agent_config_file": str(config)}
    ca, admin = root / "panel-ca.pem", root / "administrator.json"
    DRIVER.write_bytes(ca, b"TEST_ONLY CA file; not a cryptographic acceptance fixture\n")
    DRIVER.write_json(admin, {"password": "TEST_ONLY_private_password"})
    binaries = {}
    for name in ("sinan-agent", "sinan-panel"):
        path = root / name
        DRIVER.write_bytes(path, b"TEST_ONLY immutable binary identity, not executable\n")
        binaries[name] = {"path": str(path), "sha256": DRIVER.digest(path.read_bytes()),
                          "size": path.stat().st_size}
    receipt = root / "prepared-artifacts.json"
    DRIVER.write_json(receipt, {"status": "prepared", "test_only": True, "run_id": run_id,
        "source_identity": source, "release": {"official_publication_rejected": True},
        "binaries": {name: {key: row[key] for key in ("sha256", "size")} for name, row in binaries.items()}})
    controller = {"schema": 1, "test_only": True, "dedicated": True, "run_id": run_id,
        "run_root": str(root), "source_identity": copy.deepcopy(source),
        "artifacts": {"test_only": True, "prepared_receipt_file": str(receipt), "binaries": binaries},
        "roles": {role: {"init_pid": index, "starttime": index, "netns_id": index,
            "mountns_id": index, "pidns_id": index, "systemd_id": str(index).zfill(32),
            "filesystem_id": "1:" + str(index), "agent_config": "/etc/sinan/agent.toml",
            "agent_binary": "/opt/sinan/core/current/sinan-agent"}
            for index, role in enumerate(("A", "M", "B"), 2)},
        "panel": {"origin": "https://owned.test", "unit": "sinan-managed-panel-" + run_id + ".service",
            "data_dir": str(root / "panel-data"), "ownership_file": str(root / ".sinan-managed-test-run"),
            "unit_file": str(root / "panel.service"), "unit_sha256": "e" * 64,
            "environment_file": str(root / "panel.env"), "environment_sha256": "f" * 64,
            "postgres": {"socket_dir": str(root / "pg"), "port": 55437,
                         "username": "postgres", "database": "sinan_managed_" + run_id.replace("-", "")}}}
    network_root = root / "network"
    network_root.mkdir(mode=0o700)
    tls = network_root / "tls"
    tls.mkdir(mode=0o700)
    empty_roots = tls / "empty-ca-directory"
    empty_roots.mkdir(mode=0o700)
    tls_files = {"empty_ca_directory": str(empty_roots)}
    for name in ("ca", "cert", "key"):
        path = tls / (name + ".pem")
        DRIVER.write_bytes(path, b"TEST_ONLY bounded TLS identity; not a live certificate\n")
        tls_files[name] = str(path)
    accounts, contents = {}, {}
    for version in ("v1", "v2", "bad", "v3"):
        account = {"username": "TEST_ONLY_X_" + version, "password": "TEST_ONLY_account_" + version}
        accounts[version] = account
        path = network_root / ("source-" + version + ".json")
        DRIVER.write_json(path, {"outbounds": [{"type": "http", "tag": "TEST_ONLY_X",
            "server": "10.231.0.1", "server_port": 21001, **account}]})
        contents[version] = {"path": str(path), "sha256": DRIVER.digest(path.read_bytes())}
    runtime = root / "sing-box"
    DRIVER.write_bytes(runtime, b"TEST_ONLY native runtime identity, not executable\n")
    fixture = {"schema": 1, "test_only": True, "run_id": run_id, "root": str(network_root),
        "native_binary": str(runtime), "native_sha256": DRIVER.digest(runtime.read_bytes()),
        "addresses": {"fixture": "10.231.0.1", "client": "10.231.0.1",
                      **{role: row["address"] for role, row in roles.items()}},
        "ports": {"x": 21001, "handshake": 21002, "tcp_echo": 21003, "udp_echo": 21004, "https": 21005},
        "managed_ports": {"A": [20011, 20012], "M": 20001, "B": 20001},
        "accounts": accounts, "source_contents": contents, "tls": tls_files}
    programs["controller"]["manifest_file"] = str(root / "environment.json")
    programs["fixture"]["manifest_file"] = str(network_root / "manifest.json")
    prepared = {"schema": 1, "run_id": run_id, "source_identity": source,
        "panel": {"origin": "https://owned.test", "ca_file": str(ca), "admin_descriptor_file": str(admin)},
        "roles": roles, **programs,
        "release": {"test_only": True, "agent_version": "0.3.1", "agent_target": "aarch64-unknown-linux-gnu"},
        "evidence_dir": str(root / "evidence")}
    return prepared, controller, fixture


def save_manifests(prepared, controller, fixture):
    DRIVER.write_json(Path(prepared["controller"]["manifest_file"]), controller)
    DRIVER.write_json(Path(prepared["fixture"]["manifest_file"]), fixture)


class DriverContracts(unittest.TestCase):
    def ordered_driver(self, root, ids=None):
        """Real driver methods with a boundary stub, never a product or device."""
        driver = object.__new__(DRIVER.Driver)
        driver.directory = root
        driver.state_file = root / "private-state.json"
        driver.state = {"requests": {}, "ids": ids or {}, "tokens": {}, "prefix": "TEST_ONLY"}
        driver.manifest = {"run_id": "ab12640c-270f-4a82-a506-41176e42e19f",
            "panel": {"origin": "https://owned.test"}, "source_identity": {"frozen": "TEST_ONLY"},
            "roles": {role: {"address": "10.231.0." + str(number), "sni": "reality.test"}
                      for number, role in enumerate(("A", "M", "B"), 2)}}
        driver.panel = mock.Mock()
        driver.control = mock.Mock()
        driver.fixtures = mock.Mock()
        driver.fixtures.manifest = {"addresses": {"fixture": "10.231.0.1"},
                                    "ports": {"handshake": 21002}}
        driver.fixtures.source.side_effect = lambda version: "TEST_ONLY private source " + version
        driver.event = mock.Mock()
        driver.environment_owned = False
        driver.fixture_started = False
        def immediately(label, read, predicate, **options):
            value = read()
            self.assertTrue(predicate(value), label)
            return value
        driver.wait = mock.Mock(side_effect=immediately)
        return driver

    def assert_manifest_rejected_before_business(self, mutation):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            prepared, controller, fixture = manifest_fixture(root)
            mutation(prepared, controller, fixture, root)
            save_manifests(prepared, controller, fixture)
            with mock.patch.object(DRIVER, "Controller") as control, \
                    mock.patch.object(DRIVER, "Panel") as panel, \
                    mock.patch.object(DRIVER, "Fixtures") as helper:
                with self.assertRaises(DRIVER.Rejected):
                    DRIVER.Driver(prepared, ("baseline",))
                control.assert_not_called()
                panel.assert_not_called()
                helper.assert_not_called()
            self.assertFalse((root / "evidence").exists())

    def test_manifest_ids_origins_and_source_mismatch_before_business(self):
        mutations = (
            lambda p, c, f, r: p.update(run_id=p["run_id"].upper()),
            lambda p, c, f, r: p.update(run_id="00000000-0000-0000-0000-000000000000"),
            lambda p, c, f, r: p["panel"].update(origin="https://owned.test/"),
            lambda p, c, f, r: p["panel"].update(origin="https://OWNED.test"),
            lambda p, c, f, r: p["panel"].update(origin="https://operator:TEST_ONLY@owned.test"),
            lambda p, c, f, r: c.update(run_id="ea681d39-1a63-4b48-b4f5-a9e48614ebd0"),
            lambda p, c, f, r: c["source_identity"].update(functional_sha256="e" * 64),
            lambda p, c, f, r: c["panel"].update(origin="https://other.test"),
            lambda p, c, f, r: DRIVER.write_bytes(r / ".sinan-managed-test-run", b"different-owned-run\n"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_manifest_rejected_before_business(mutation)

    def test_evidence_path_is_owned_private_and_never_follows_symlinks(self):
        def public_evidence(p, c, f, root):
            (root / "public-evidence").mkdir(mode=0o755)
            (root / "public-evidence").chmod(0o755)
            p["evidence_dir"] = str(root / "public-evidence")
        def linked_evidence(p, c, f, root):
            (root / "real-evidence").mkdir(mode=0o700)
            (root / "linked-evidence").symlink_to(root / "real-evidence", target_is_directory=True)
            p["evidence_dir"] = str(root / "linked-evidence")
        def linked_parent(p, c, f, root):
            (root / "real-parent").mkdir(mode=0o700)
            (root / "linked-parent").symlink_to(root / "real-parent", target_is_directory=True)
            p["evidence_dir"] = str(root / "linked-parent" / "new-evidence")
        mutations = (
            lambda p, c, f, r: p.update(evidence_dir=str(r.parent / "unowned-evidence")),
            lambda p, c, f, r: p.update(evidence_dir=str(r)),
            lambda p, c, f, r: p.update(evidence_dir=str(r / "missing" / ".." / "escape")),
            public_evidence, linked_evidence, linked_parent,
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_manifest_rejected_before_business(mutation)

    def test_helper_run_addresses_and_exact_ports_bind_before_business(self):
        mutations = (
            lambda p, c, f, r: f.update(run_id="ea681d39-1a63-4b48-b4f5-a9e48614ebd0"),
            lambda p, c, f, r: f.update(test_only=False),
            lambda p, c, f, r: f["addresses"].update(B="10.231.0.99"),
            lambda p, c, f, r: f["addresses"].update(fixture=p["roles"]["A"]["address"]),
            lambda p, c, f, r: f["addresses"].update(client=p["roles"]["M"]["address"]),
            lambda p, c, f, r: f["managed_ports"].update(A=[20011]),
            lambda p, c, f, r: f["managed_ports"].update(A=[20011, 20012, 20013]),
            lambda p, c, f, r: f["managed_ports"].update(M=20002),
            lambda p, c, f, r: f["managed_ports"].update(B=True),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_manifest_rejected_before_business(mutation)

    def test_complete_private_manifest_accepts_new_and_resumed_host_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            prepared, controller, fixture = manifest_fixture(root)
            save_manifests(prepared, controller, fixture)
            self.assertIs(DRIVER.manifest_contract(prepared), prepared)
            self.assertFalse((root / "evidence").exists())
            (root / "evidence").mkdir(mode=0o700)
            fixture["addresses"]["client"] = "10.231.0.10"
            fixture["managed_ports"] = {"A": [20012, 20011], "M": [20001], "B": [20001]}
            save_manifests(prepared, controller, fixture)
            self.assertIs(DRIVER.manifest_contract(prepared), prepared)
            fixture["addresses"]["client"] = "127.0.0.1"
            save_manifests(prepared, controller, fixture)
            self.assertIs(DRIVER.manifest_contract(prepared), prepared)

    def test_isolation_requires_three_actual_distinct_namespaces(self):
        facts = {"dedicated": True, "isolated": True, "test_only": True,
                 "roles": {role: {"filesystem_id": number, "netns_id": number, "systemd_id": str(number)}
                           for number, role in enumerate(("A", "M", "B"), 1)}}
        DRIVER.complete_inspection(facts)
        for field in ("filesystem_id", "netns_id", "systemd_id"):
            broken = copy.deepcopy(facts)
            broken["roles"]["B"][field] = broken["roles"]["M"][field]
            with self.assertRaises(DRIVER.Rejected):
                DRIVER.complete_inspection(broken)
        facts["dedicated"] = False
        with self.assertRaises(DRIVER.Rejected):
            DRIVER.complete_inspection(facts)

    def test_checkpoint_health_does_not_replace_probe_barrier_receipts(self):
        proof = proof_fixture()
        DRIVER.assert_proof_chain(proof, 8, 2)
        mutations = (
            lambda item: item["receipts"][0].update(outcome="superseded"),
            lambda item: item["receipts"][0]["result"].update(request_digest="different"),
            lambda item: item["receipts"][0]["result"].update(observed=checkpoint(instance="new-instance")),
            lambda item: item["path_probes"][0].update(dependency_vector=[]),
            lambda item: item["path_probes"][0]["dependency_vector"][0].__setitem__(1, checkpoint(instance="other")),
            lambda item: item["receipts"][-1]["result"].update(pending_intents_clear=False),
            lambda item: item["receipts"][-1]["result"].update(minimum_revision=2),
            lambda item: item["vectors"][0].update(bundle_sha256="unknown"),
            lambda item: item.update(vectors=[]),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                broken = copy.deepcopy(proof)
                mutate(broken)
                with self.assertRaises(DRIVER.Rejected):
                    DRIVER.assert_proof_chain(broken, 8, 2)

    def test_inspected_panel_and_source_bind_before_login_or_mutation(self):
        prepared = {"panel": {"origin": "https://owned.test"},
                    "source_identity": {"frozen_inputs_sha256": "a" * 64}}
        facts = {"dedicated": True, "isolated": True, "test_only": True,
                 "panel_origin": prepared["panel"]["origin"], "source_identity": prepared["source_identity"],
                 "roles": {role: {"filesystem_id": number, "netns_id": number, "systemd_id": str(number)}
                           for number, role in enumerate(("A", "M", "B"), 1)}}
        DRIVER.bind_inspection(facts, prepared)
        for field, replacement in (("panel_origin", None), ("panel_origin", "https://other.test"),
                                   ("source_identity", None), ("source_identity", {"frozen_inputs_sha256": "b" * 64})):
            broken = copy.deepcopy(facts)
            if replacement is None:
                del broken[field]
            else:
                broken[field] = replacement
            driver = object.__new__(DRIVER.Driver)
            driver.manifest = prepared
            driver.environment_owned = False
            driver.control = mock.Mock()
            driver.control.call.return_value = broken
            driver.panel, driver.fixtures = mock.Mock(), mock.Mock()
            with self.assertRaises(DRIVER.Rejected):
                driver.setup()
            driver.panel.login.assert_not_called()
            driver.fixtures.start.assert_not_called()
            self.assertFalse(driver.environment_owned)
            driver.control.call.assert_called_once_with("inspect")

    def test_batch_retry_persists_and_reuses_exact_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = object.__new__(DRIVER.Driver)
            driver.state_file = Path(temporary).resolve() / "state.json"
            driver.state = {"requests": {}}
            calls = []
            body = {"request_id": "b1697cd3-4c69-4f1c-91a1-6e2734a7a1ef", "items": [{"name": "TEST_ONLY"}]}
            def request(path, method, supplied, expected):
                self.assertEqual(path, "/api/plugins/sing-box/chains/ordered-batch")
                saved = json.loads(driver.state_file.read_bytes())
                self.assertEqual(saved["requests"]["batch"]["body"], body)
                calls.append(copy.deepcopy(supplied))
                if len(calls) == 1:
                    raise DRIVER.Rejected("panel_transport_failed")
                return {"chain_ids": [7]}
            driver.panel = mock.Mock(request=request)
            self.assertEqual(driver.request_once("batch", DRIVER.ORDERED_BATCH, "POST", body), {"chain_ids": [7]})
            self.assertEqual(calls, [body, body])
            with self.assertRaises(DRIVER.Rejected):
                driver.request_once("batch", DRIVER.ORDERED_BATCH, "POST", {**body, "items": []})
            self.assertEqual(len(calls), 2)

    def test_setup_and_atomic_replay_use_ordered_routes_and_keep_numeric_policy_ids(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve())
            source_node = {"id": "c1d62c7f-9b5d-49c0-b382-1c4ff5c4eecc",
                           "version_id": "9ab7aef7-b438-4155-ade3-69c60aacdd0d",
                           "source_revision_id": "76347930-1c2b-4332-970c-6b5e1d937acf",
                           "source_id": 7, "identity_epoch": 1, "selectable": True}
            receipt = {"request_id": None, "chain_ids": [41, 42], "entry_node_ids": [13, 14]}
            calls, named_calls = [], []
            numbered = {"server_A": 1, "server_M": 2, "server_B": 3,
                        "node_M": 11, "node_B": 12, "node_three": 13, "node_four": 14,
                        "user_three": 21, "user_four": 22, "policy_three": 31, "policy_four": 32}
            def named(key, path, fields):
                named_calls.append((key, path, copy.deepcopy(fields)))
                driver.state["ids"][key] = numbered[key]
                return {"id": numbered[key], **fields, "device_public_key": "TEST_ONLY-" + key,
                        "subscription_url": "https://owned.test/sub/TEST_ONLY-" + key,
                        "subscription_token": "TEST_ONLY-" + key}
            driver.named = mock.Mock(side_effect=named)
            driver.credentials_unchanged = mock.Mock()
            driver.control.call.return_value = {"dedicated": True, "isolated": True, "test_only": True,
                "panel_origin": driver.manifest["panel"]["origin"],
                "source_identity": driver.manifest["source_identity"],
                "roles": {role: {"filesystem_id": number, "netns_id": number, "systemd_id": str(number)}
                          for number, role in enumerate(("A", "M", "B"), 1)}}
            def request(path, method="GET", body=None, expected=(200,)):
                calls.append((path, method, copy.deepcopy(body), expected))
                if path.startswith("/api/servers/") and method == "GET":
                    return {"id": int(path.rsplit("/", 1)[1]), "online": True,
                            "device_public_key": "TEST_ONLY-" + path,
                            "capabilities": ["singbox", "artifact:minisign-v1", "runtime:checkpoint-v1",
                                             "runtime:barrier-v1", "runtime:path-probe-v1"]}
                if path.endswith("/enable") and method == "POST":
                    return {}
                if path.endswith("/deployments/check") and method == "POST":
                    return {"ready": True}
                if path == "/api/plugins/sing-box/ordered-subscription-sources":
                    if method == "GET":
                        return []
                    self.assertEqual(method, "POST")
                    self.assertEqual(body["input"], {"kind": "inline", "content": driver.fixtures.source("v1")})
                    return {"source_id": 7, "settings_revision": 1, "identity_epoch": 1,
                            "job_id": "d992c067-893f-4c09-b1b5-1b3e5c8158d4"}
                if path == "/api/plugins/sing-box/ordered-subscription-sources/7/nodes":
                    return {"source_id": 7, "success_revision": {"id": source_node["source_revision_id"],
                            "source_id": 7, "identity_epoch": 1},
                            "nodes": [copy.deepcopy(source_node)]}
                if path == "/api/plugins/sing-box/chains/ordered-batch":
                    if expected == (400,):
                        self.assertEqual(body["items"][1]["hops"][0]["node_id"], 0)
                        return {"error": "TEST_ONLY invalid middle item"}
                    if expected == (409,):
                        self.assertTrue(body["items"][0]["name"].endswith("-changed"))
                        return {"error": "TEST_ONLY request collision"}
                    if receipt["request_id"] is None:
                        receipt["request_id"] = body["request_id"]
                    self.assertEqual(body["request_id"], receipt["request_id"])
                    return copy.deepcopy(receipt)
                if path in ("/api/plugins/sing-box/ordered-proxy-resources/chain/41",
                            "/api/plugins/sing-box/ordered-proxy-resources/chain/42"):
                    return {"id": int(path.rsplit("/", 1)[1]),
                            "path_state": {"phase": "applied", "applied_generation": 1,
                                           "candidate_generation": None}}
                if path in ("/api/plugins/sing-box/users/21/policy-groups",
                            "/api/plugins/sing-box/users/22/policy-groups"):
                    self.assertEqual(method, "PUT")
                    return {}
                if path == "/api/plugins/sing-box/nodes" and method == "GET":
                    return [{"id": number} for number in (11, 12, 13, 14)]
                self.fail("unexpected API contract: " + path)
            driver.panel.request.side_effect = request
            with mock.patch.object(DRIVER, "write_json"):
                driver.setup()
            initial = copy.deepcopy(driver.state["requests"]["create-chains"]["body"])
            self.assertEqual(driver.state["ids"]["source"], 7)
            self.assertEqual(initial["items"][0]["hops"][0], {"kind": "subscription", "source_id": 7,
                "external_node_id": source_node["id"], "node_version_id": source_node["version_id"],
                "update_mode": "follow_node"})
            self.assertEqual([hop["kind"] for hop in initial["items"][1]["hops"]],
                             ["managed", "subscription", "managed"])
            policies = [fields for key, path, fields in named_calls if key.startswith("policy_")]
            self.assertEqual(policies, [{"node_ids": [], "chain_ids": [41]},
                                        {"node_ids": [], "chain_ids": [42]}])
            driver.scenario_atomic_replay()
            batches = [row for row in calls if row[0] == "/api/plugins/sing-box/chains/ordered-batch"]
            self.assertEqual(len(batches), 4)
            self.assertEqual(batches[1][2], initial)
            self.assertEqual(driver.state["initial_batch_receipt"], receipt)
            self.assertTrue(driver.state["requests"]["invalid-batch"]["path"].endswith("/chains/ordered-batch"))

    def test_inline_update_polls_ordered_job_without_reinterpreting_uuid_as_a_source_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_id = 2**63 - 1
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": source_id})
            job_id = "d992c067-893f-4c09-b1b5-1b3e5c8158d4"
            source_path = "/api/plugins/sing-box/ordered-subscription-sources/" + str(source_id)
            calls = []
            def request(path, method="GET", body=None, expected=(200,)):
                calls.append((path, method, copy.deepcopy(body)))
                if path == source_path and method == "GET":
                    return {"id": source_id, "settings_revision": 5, "identity_epoch": 1}
                if path == source_path and method == "PATCH":
                    return {"source_id": source_id, "settings_revision": 6, "identity_epoch": 2, "job_id": job_id}
                if path == "/api/plugins/sing-box/ordered-subscription-source-jobs/" + job_id:
                    return {"id": job_id, "source_id": source_id, "settings_revision": 6,
                            "identity_epoch": 2, "status": "succeeded"}
                self.fail("unexpected API contract: " + path)
            driver.panel.request.side_effect = request
            result = driver.patch_source("v3", "replace")
            self.assertEqual(result["source_id"], source_id)
            self.assertEqual(calls[1][2]["input"], {"kind": "inline", "content": "TEST_ONLY private source v3",
                                                   "identity_action": "replace"})
            self.assertEqual(calls[1][2]["settings_revision"], 5)
            self.assertEqual(driver.state["source_fixture_version"], "v3")
            self.assertEqual(calls[2][0], "/api/plugins/sing-box/ordered-subscription-source-jobs/" + job_id)

    def test_follow_pinned_apply_and_failed_source_keep_ordered_api_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": 7})
            initial = {"id": "c1d62c7f-9b5d-49c0-b382-1c4ff5c4eecc", "identity_epoch": 1,
                       "version_id": "9ab7aef7-b438-4155-ade3-69c60aacdd0d"}
            latest = {**initial, "version_id": "e1132060-107e-4381-ae29-cfd3a2e627ec"}
            replacement = {**latest, "identity_epoch": 2}
            def resource(identifier, generation, version):
                return {"id": identifier, "settings_revision": 3,
                        "path_state": {"applied_generation": generation, "desired_generation": generation},
                        "hops": [{"kind": "subscription", "position": 1, "identity_epoch": 1,
                                  "node_version_id": version}]}
            three_old = resource(41, 1, initial["version_id"])
            four_old = resource(42, 1, initial["version_id"])
            three_new = resource(41, 2, latest["version_id"])
            four_new = resource(42, 2, latest["version_id"])
            driver.source_version = mock.Mock(side_effect=[initial, latest, replacement])
            driver.applied = mock.Mock(side_effect=[three_old, four_old, three_new, four_old,
                                                    four_new, three_new, four_new])
            driver.patch_source = mock.Mock()
            driver.traffic, driver.real_proofs = mock.Mock(), mock.Mock()
            job_id = "d992c067-893f-4c09-b1b5-1b3e5c8158d4"
            successful = {"id": 7, "settings_revision": 5, "identity_epoch": 1,
                          "latest_success": {"id": initial["version_id"]}}
            calls, source_reads = [], 0
            def request(path, method="GET", body=None, expected=(200,)):
                nonlocal source_reads
                calls.append((path, method, copy.deepcopy(body)))
                if path == "/api/plugins/sing-box/ordered-proxy-resources/chain/42/apply-node-versions":
                    self.assertEqual(method, "POST")
                    return {"request_id": body["request_id"], "kind": "chain", "id": 42,
                            "settings_revision": 4, "generation": 2}
                if path == "/api/plugins/sing-box/ordered-subscription-sources/7" and method == "GET":
                    source_reads += 1
                    return {**successful, "settings_revision": 5 if source_reads == 1 else 6,
                            "last_error": None if source_reads == 1 else {"kind": "document"}}
                if path == "/api/plugins/sing-box/ordered-subscription-sources/7" and method == "PATCH":
                    return {"source_id": 7, "settings_revision": 6, "identity_epoch": 1, "job_id": job_id}
                if path == "/api/plugins/sing-box/ordered-subscription-source-jobs/" + job_id:
                    return {"id": job_id, "source_id": 7, "settings_revision": 6, "identity_epoch": 1,
                            "status": "failed", "error": {"kind": "document"}}
                self.fail("unexpected API contract: " + path)
            driver.panel.request.side_effect = request
            driver.scenario_source_versions()
            self.assertEqual(calls[0][2]["versions"], [{"hop_position": 1, "node_version_id": latest["version_id"]}])
            self.assertEqual(calls[0][2]["settings_revision"], 3)
            self.assertEqual(calls[0][2]["generation"], 1)
            self.assertEqual(calls[2][2]["input"]["identity_action"], "update")
            self.assertEqual(driver.patch_source.call_args_list, [mock.call("v2"), mock.call("v3", "replace")])
            self.assertTrue(driver.state["source_replaced"])
            self.assertEqual(source_reads, 2)

    def test_retirement_guards_and_deleted_replay_stay_on_ordered_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            ids = {"source": 7, "chain_three": 41, "chain_four": 42, "node_B": 12, "node_M": 11,
                   "user_three": 21, "user_four": 22, "policy_three": 31, "policy_four": 32}
            driver = self.ordered_driver(Path(temporary).resolve(), ids)
            initial = {"request_id": "b1697cd3-4c69-4f1c-91a1-6e2734a7a1ef",
                       "items": [{"name": "TEST_ONLY_three"}, {"name": "TEST_ONLY_four"}]}
            receipt = {"request_id": initial["request_id"], "chain_ids": [41, 42], "entry_node_ids": [13, 14]}
            driver.state["requests"]["create-chains"] = {"path": DRIVER.ORDERED_BATCH, "method": "POST", "body": initial}
            driver.state["initial_batch_receipt"] = copy.deepcopy(receipt)
            driver.quiet_usage = mock.Mock(return_value={"uplink": 4096, "downlink": 4096})
            driver.subscription, driver.credentials_unchanged = mock.Mock(), mock.Mock()
            def control(operation, role=None, arguments=None):
                if operation == "panel_evidence":
                    return {"chains": [{"id": 41, "phase": "retired"}, {"id": 42, "phase": "retired"}],
                            "current_dependencies": []}
                self.assertEqual(operation, "device_snapshot")
                return {"runtime": {"active": True}}
            driver.control.call.side_effect = control
            calls = []
            def request(path, method="GET", body=None, expected=(200,)):
                calls.append((path, method, copy.deepcopy(body), expected))
                if path == "/api/plugins/sing-box/ordered-subscription-sources/7":
                    if method == "GET":
                        return {"id": 7, "settings_revision": 5, "identity_epoch": 1}
                    self.assertEqual((method, body, expected), ("DELETE", {"settings_revision": 5}, (409,)))
                    return {"error": "TEST_ONLY referenced source"}
                if path.startswith("/api/plugins/sing-box/ordered-proxy-resources/"):
                    self.assertEqual(method, "DELETE")
                    self.assertIn(expected, ((409,), (204,)))
                    return None
                if path == "/api/plugins/sing-box/ordered-proxy-resources":
                    self.assertEqual(method, "GET")
                    return []
                if path == "/api/plugins/sing-box/chains/ordered-batch":
                    self.assertEqual((method, body), ("POST", initial))
                    return copy.deepcopy(receipt)
                if path in ("/api/plugins/sing-box/nodes/11", "/api/plugins/sing-box/nodes/12"):
                    return {"enabled": True}
                if path in ("/api/plugins/sing-box/users/21/policy-groups", "/api/plugins/sing-box/users/22/policy-groups"):
                    self.assertEqual((method, body), ("PUT", {"group_ids": []}))
                    return {}
                if path in ("/api/plugins/sing-box/policy-groups/31", "/api/plugins/sing-box/policy-groups/32"):
                    self.assertEqual((method, expected), ("DELETE", (204,)))
                    return None
                self.fail("unexpected API contract: " + path)
            driver.panel.request.side_effect = request
            driver.scenario_retirement()
            self.assertTrue(driver.state["retired"])
            self.assertEqual(calls[0][:2], ("/api/plugins/sing-box/ordered-proxy-resources/direct/12", "DELETE"))
            self.assertEqual(calls[1][:2], ("/api/plugins/sing-box/ordered-proxy-resources/chain/41", "DELETE"))
            removed = [row[0] for row in calls if row[1] == "DELETE" and row[3] == (204,)]
            self.assertEqual(removed, ["/api/plugins/sing-box/policy-groups/31",
                "/api/plugins/sing-box/ordered-proxy-resources/chain/41",
                "/api/plugins/sing-box/policy-groups/32",
                "/api/plugins/sing-box/ordered-proxy-resources/chain/42"])
            self.assertEqual(driver.state["initial_batch_receipt"], receipt)

    def test_unkeyed_creation_is_not_blindly_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = object.__new__(DRIVER.Driver)
            driver.state_file = Path(temporary).resolve() / "state.json"
            driver.state = {"requests": {}}
            driver.panel = mock.Mock()
            driver.panel.request.side_effect = DRIVER.Rejected("panel_transport_failed")
            with self.assertRaises(DRIVER.Rejected):
                driver.request_once("server", "/api/servers", "POST", {"name": "TEST_ONLY"})
            self.assertEqual(driver.panel.request.call_count, 1)

    def test_source_nodes_bind_bigint_source_and_uuid_version_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_id = 2**63 - 1
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": source_id})
            revision_id = "76347930-1c2b-4332-970c-6b5e1d937acf"
            page = {"source_id": source_id,
                    "success_revision": {"id": revision_id, "source_id": source_id, "identity_epoch": 1},
                    "nodes": [{"id": "c1d62c7f-9b5d-49c0-b382-1c4ff5c4eecc", "source_id": source_id,
                               "version_id": "9ab7aef7-b438-4155-ade3-69c60aacdd0d",
                               "source_revision_id": revision_id, "identity_epoch": 1, "selectable": True}]}
            driver.panel.request.return_value = copy.deepcopy(page)
            self.assertEqual(driver.source_version(), page["nodes"][0])
            driver.panel.request.assert_called_once_with(
                "/api/plugins/sing-box/ordered-subscription-sources/9223372036854775807/nodes")
            mutations = (("page_source", 7), ("node_source", 7), ("revision_source", 7),
                         ("node_epoch", 2), ("node_version", 7), ("node_version", "0" * 32),
                         ("node_revision", "9ab7aef7-b438-4155-ade3-69c60aacdd0d"))
            for field, value in mutations:
                with self.subTest(field=field, value_type=type(value).__name__):
                    broken = copy.deepcopy(page)
                    if field == "page_source":
                        broken["source_id"] = value
                    elif field == "revision_source":
                        broken["success_revision"]["source_id"] = value
                    else:
                        key = {"node_source": "source_id", "node_epoch": "identity_epoch",
                               "node_version": "version_id", "node_revision": "source_revision_id"}[field]
                        broken["nodes"][0][key] = value
                    driver.panel.request.return_value = broken
                    with self.assertRaises(DRIVER.Rejected):
                        driver.source_version()
            for invalid_id in (True, "7", 0, -1, 2**63, revision_id):
                with self.subTest(source_type=type(invalid_id).__name__):
                    driver.state["ids"]["source"] = invalid_id
                    driver.panel.request.reset_mock()
                    with self.assertRaisesRegex(DRIVER.Rejected, "resource_id_invalid"):
                        driver.source_nodes()
                    driver.panel.request.assert_not_called()

    def test_inline_update_rejects_unbound_receipt_or_successful_job(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": 7})
            source_path = "/api/plugins/sing-box/ordered-subscription-sources/7"
            job_id = "d992c067-893f-4c09-b1b5-1b3e5c8158d4"
            receipt = {"source_id": 7, "settings_revision": 6, "identity_epoch": 1, "job_id": job_id}
            job = {"id": job_id, "source_id": 7, "settings_revision": 6,
                   "identity_epoch": 1, "status": "succeeded"}
            mutations = (("receipt", "source_id", True), ("receipt", "source_id", 8),
                         ("receipt", "settings_revision", 5), ("receipt", "identity_epoch", 2),
                         ("receipt", "job_id", 7), ("job", "source_id", 8),
                         ("job", "settings_revision", 5), ("job", "identity_epoch", 2),
                         ("job", "status", "failed"),
                         ("job", "id", "c1d62c7f-9b5d-49c0-b382-1c4ff5c4eecc"))
            for target, field, value in mutations:
                with self.subTest(target=target, field=field):
                    rows = {"receipt": copy.deepcopy(receipt), "job": copy.deepcopy(job)}
                    rows[target][field] = value
                    def request(path, method="GET", body=None, expected=(200,)):
                        if path == source_path and method == "GET":
                            return {"id": 7, "settings_revision": 5, "identity_epoch": 1}
                        if path == source_path and method == "PATCH":
                            return rows["receipt"]
                        if path == "/api/plugins/sing-box/ordered-subscription-source-jobs/" + job_id:
                            return rows["job"]
                        self.fail("unexpected API contract: " + path)
                    driver.panel.request.side_effect = request
                    with self.assertRaises(DRIVER.Rejected):
                        driver.patch_source("v2")
                    self.assertNotIn("source_fixture_version", driver.state)

    def test_deferred_inline_update_waits_for_its_revision_instead_of_old_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": 7})
            source_path = "/api/plugins/sing-box/ordered-subscription-sources/7"
            old_page = {"source_id": 7, "success_revision": {"settings_revision": 5, "identity_epoch": 1}}
            new_page = {"source_id": 7, "success_revision": {"settings_revision": 6, "identity_epoch": 1}}
            observations = iter((old_page, new_page))
            def request(path, method="GET", body=None, expected=(200,)):
                if path == source_path and method == "GET":
                    return {"id": 7, "settings_revision": 5, "identity_epoch": 1}
                if path == source_path and method == "PATCH":
                    return {"source_id": 7, "settings_revision": 6, "identity_epoch": 1, "job_id": None}
                self.assertEqual((path, method), (source_path + "/nodes", "GET"))
                return next(observations)
            def pending_then_finished(label, read, predicate):
                self.assertEqual(label, "source_import")
                self.assertFalse(predicate(read()))
                self.assertNotIn("source_fixture_version", driver.state)
                completed = read()
                self.assertTrue(predicate(completed))
                return completed
            driver.panel.request.side_effect = request
            driver.wait.side_effect = pending_then_finished
            driver.patch_source("v2")
            self.assertEqual(driver.state["source_fixture_version"], "v2")
            calls = [row.args[0] for row in driver.panel.request.call_args_list]
            self.assertEqual(calls, [source_path, source_path, source_path + "/nodes", source_path + "/nodes"])

    def test_deferred_failed_update_ignores_old_cancelling_job_and_binds_new_job(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": 7})
            old_job_id = "c1d62c7f-9b5d-49c0-b382-1c4ff5c4eecc"
            new_job_id = "d992c067-893f-4c09-b1b5-1b3e5c8158d4"
            previous = {"id": 7, "settings_revision": 5, "identity_epoch": 1,
                        "last_attempt_at": 100, "last_error": {"kind": "TEST_ONLY old failure"},
                        "latest_success": {"id": "76347930-1c2b-4332-970c-6b5e1d937acf"}}
            receipt = {"source_id": 7, "settings_revision": 6, "identity_epoch": 1, "job_id": None}
            old = {**previous, "settings_revision": 6,
                   "active_job": {"id": old_job_id, "source_id": 7, "settings_revision": 5,
                                  "identity_epoch": 1, "status": "cancelling"}}
            failed_job = {"id": new_job_id, "source_id": 7, "settings_revision": 6,
                          "identity_epoch": 1, "status": "failed", "error": {"kind": "document"}}
            new = {**previous, "settings_revision": 6, "last_attempt_at": 101,
                   "last_error": failed_job["error"], "active_job": {**failed_job, "status": "running"}}
            observations = iter((old, new))
            def request(path, method="GET", body=None, expected=(200,)):
                self.assertEqual(method, "GET")
                if path == "/api/plugins/sing-box/ordered-subscription-sources/7":
                    return next(observations)
                self.assertEqual(path, "/api/plugins/sing-box/ordered-subscription-source-jobs/" + new_job_id)
                return failed_job
            def pending_then_finished(label, read, predicate):
                self.assertEqual(label, "invalid_source")
                self.assertFalse(predicate(read()))
                self.assertEqual(driver.panel.request.call_count, 1)
                completed = read()
                self.assertTrue(predicate(completed))
                return completed
            driver.panel.request.side_effect = request
            driver.wait.side_effect = pending_then_finished
            self.assertEqual(driver.source_failure(receipt, previous), new)
            paths = [row.args[0] for row in driver.panel.request.call_args_list]
            self.assertEqual(paths, ["/api/plugins/sing-box/ordered-subscription-sources/7"] * 2
                             + ["/api/plugins/sing-box/ordered-subscription-source-jobs/" + new_job_id])

    def test_deferred_failure_can_finish_between_observations_without_a_job_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": 7})
            previous = {"id": 7, "settings_revision": 5, "identity_epoch": 1, "last_attempt_at": 100,
                        "last_error": None, "latest_success": {"id": "76347930-1c2b-4332-970c-6b5e1d937acf"}}
            receipt = {"source_id": 7, "settings_revision": 6, "identity_epoch": 1, "job_id": None}
            current = {**previous, "settings_revision": 6, "last_attempt_at": 101,
                       "last_error": {"kind": "document"}, "active_job": None}
            driver.panel.request.return_value = current
            self.assertEqual(driver.source_failure(receipt, previous), current)
            driver.panel.request.assert_called_once_with("/api/plugins/sing-box/ordered-subscription-sources/7")

    def test_deferred_failure_retained_old_error_and_old_success_are_not_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": 7})
            previous = {"id": 7, "settings_revision": 5, "identity_epoch": 1, "last_attempt_at": 100,
                        "last_error": {"kind": "TEST_ONLY old failure"},
                        "latest_success": {"id": "76347930-1c2b-4332-970c-6b5e1d937acf"}}
            receipt = {"source_id": 7, "settings_revision": 6, "identity_epoch": 1, "job_id": None}
            pending = {**previous, "settings_revision": 6, "active_job": None}
            failed = {**pending, "last_attempt_at": 101, "last_error": {"kind": "document"}}
            driver.panel.request.side_effect = [pending, failed]
            def pending_then_finished(label, read, predicate):
                self.assertFalse(predicate(read()))
                completed = read()
                self.assertTrue(predicate(completed))
                return completed
            driver.wait.side_effect = pending_then_finished
            self.assertEqual(driver.source_failure(receipt, previous), failed)
            self.assertEqual(driver.panel.request.call_count, 2)

    def test_deferred_failure_rejects_changed_source_epoch_or_success_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve(), {"source": 7})
            previous = {"id": 7, "settings_revision": 5, "identity_epoch": 1, "last_attempt_at": 100,
                        "last_error": None, "latest_success": {"id": "76347930-1c2b-4332-970c-6b5e1d937acf"}}
            receipt = {"source_id": 7, "settings_revision": 6, "identity_epoch": 1, "job_id": None}
            failed = {**previous, "settings_revision": 6, "last_attempt_at": 101,
                      "last_error": {"kind": "document"}, "active_job": None}
            for change in ({"id": 8}, {"settings_revision": 7}, {"identity_epoch": 2},
                           {"latest_success": {"id": "d992c067-893f-4c09-b1b5-1b3e5c8158d4"}},
                           {"active_job": {"id": "d992c067-893f-4c09-b1b5-1b3e5c8158d4", "source_id": 8,
                                           "settings_revision": 6, "identity_epoch": 1, "status": "running"}}):
                with self.subTest(changed_fields=list(change)):
                    driver.panel.request.return_value = {**failed, **change}
                    with self.assertRaises(DRIVER.Rejected):
                        driver.source_failure(receipt, previous)

    def test_batch_replay_preserves_bigint_ids_and_rejects_unbound_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            driver = self.ordered_driver(Path(temporary).resolve(), {"server_A": 1})
            body = {"request_id": "b1697cd3-4c69-4f1c-91a1-6e2734a7a1ef",
                    "items": [{"name": "TEST_ONLY_three", "hops": [{"kind": "managed", "node_id": 12}]},
                              {"name": "TEST_ONLY_four", "hops": [{"kind": "managed", "node_id": 12}]}]}
            receipt = {"request_id": body["request_id"], "chain_ids": [2**63 - 1, 2**53 + 1],
                       "entry_node_ids": [13, 14]}
            driver.state["requests"]["create-chains"] = {"path": DRIVER.ORDERED_BATCH,
                                                          "method": "POST", "body": body}
            driver.state["initial_batch_receipt"] = copy.deepcopy(receipt)
            driver.credentials_unchanged = mock.Mock()
            malformed = [{**receipt, "request_id": "c1d62c7f-9b5d-49c0-b382-1c4ff5c4eecc"},
                         {**receipt, "chain_ids": [True, 42]}, {**receipt, "chain_ids": ["41", 42]},
                         {**receipt, "chain_ids": [2**63, 42]}, {**receipt, "chain_ids": [41, 41]},
                         {**receipt, "entry_node_ids": [13]}]
            for broken in malformed:
                driver.panel.request.reset_mock()
                driver.panel.request.return_value = broken
                with self.assertRaises(DRIVER.Rejected):
                    driver.scenario_atomic_replay()
                driver.panel.request.assert_called_once_with(DRIVER.ORDERED_BATCH, "POST", body, expected=(200,))
                driver.credentials_unchanged.assert_not_called()
            def request(path, method="GET", supplied=None, expected=(200,)):
                if path == DRIVER.ORDERED_BATCH:
                    return copy.deepcopy(receipt) if expected == (200,) else {"error": "TEST_ONLY rejected"}
                self.assertEqual(path, "/api/plugins/sing-box/nodes")
                return [{"id": 13}, {"id": 14}]
            driver.panel.request.side_effect = request
            driver.scenario_atomic_replay()
            self.assertEqual(driver.state["initial_batch_receipt"], receipt)
            driver.credentials_unchanged.assert_called_once_with()

    def test_controller_binding_whitelist_and_fixed_manifest_argument(self):
        controller = object.__new__(DRIVER.Controller)
        controller.path = Path("/owned/controller.py")
        controller.manifest_file = Path("/owned/environment.json")
        controller.run_id = "run"
        controller.directory = Path("/owned/evidence")
        controller.deadline = mock.Mock(remaining=lambda maximum: maximum)
        controller.sequence = 0
        with mock.patch.object(DRIVER, "Process") as process:
            process.return_value.result.return_value = {"schema": 1, "run_id": "run",
                                                       "operation": "inspect", "ok": True, "facts": {}}
            controller.call("inspect")
            self.assertEqual(process.call_args.args[0][-2:], ["--manifest", "/owned/environment.json"])
            self.assertEqual(process.call_args.args[3]["operation"], "inspect")
            process.return_value.result.return_value["run_id"] = "other"
            with self.assertRaises(DRIVER.Rejected):
                controller.call("inspect")
            with self.assertRaises(DRIVER.Rejected):
                controller.call("confirm_devices")
            with self.assertRaises(DRIVER.Rejected):
                controller.call("panel_evidence", "production")
            self.assertEqual(process.call_count, 2)

    def test_parent_exit_still_cleans_owned_process_group(self):
        process = object.__new__(DRIVER.Process)
        process.process = mock.Mock(pid=9876)
        process.process.poll.return_value = 0
        process.threads = []
        process.log = Path("/owned/private.stderr")
        process.buffers = [bytearray(), bytearray()]
        with mock.patch.object(DRIVER, "write_bytes"):
            process.stop()
        process.process.stop_group.assert_called_once_with()
        process.process.stdout.close.assert_called_once_with()
        process.process.stderr.close.assert_called_once_with()

    def test_symlink_parent_and_unbounded_controller_source_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real"
            real.mkdir()
            source = real / "controller.py"
            source.write_bytes(b"# TEST_ONLY\n")
            descriptor = {"path": str(source), "sha256": DRIVER.digest(source.read_bytes())}
            self.assertEqual(DRIVER.verified_program(descriptor), source)
            (root / "linked").symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError):
                DRIVER.verified_program({**descriptor, "path": str(root / "linked" / "controller.py")})
            source.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(DRIVER.Rejected):
                DRIVER.verified_program(descriptor)

    def test_graph_cannot_pass_when_a_shortcut_reaches_target(self):
        graph = {"kind": "result", "event": "observation", "socket_edges": [{"protocol": "tcp"}],
                 "edges": [["client", "A"], ["A", "M"], ["M", "X"], ["X", "B"], ["B", "target"]]}
        DRIVER.assert_graph(graph, True)
        graph["edges"].append(["A", "target"])
        with self.assertRaises(DRIVER.Rejected):
            DRIVER.assert_graph(graph, True)

    def test_fault_events_are_not_erased_or_promoted_to_baseline_success(self):
        successful = {"tcp": {"ok": True, "bytes": 4096}, "udp": {"ok": True, "packets": 5, "bytes": 960},
                      "https": {"ok": True}}
        failed = copy.deepcopy(successful)
        failed["tcp"]["ok"] = False
        result = {"events": [successful, failed, successful]}
        DRIVER.assert_traffic(result, all_rounds=False)
        with self.assertRaises(DRIVER.Rejected):
            DRIVER.assert_traffic(result)
        self.assertEqual(len(result["events"]), 3)

    def test_preflight_rejection_does_not_restore_or_stop_unproven_hosts(self):
        driver = object.__new__(DRIVER.Driver)
        driver.state = {"ids": {}, "requests": {}, "run_id": "run"}
        driver.manifest = {"run_id": "run", "source_identity": {"frozen": "digest"}}
        driver.scenarios = ("baseline",)
        driver.environment_owned = False
        driver.accounting_verified = False
        driver.results, driver.cleanup_errors = {}, []
        driver.directory = Path("/owned/evidence")
        driver.control, driver.fixtures = mock.Mock(), mock.Mock()
        driver.setup = mock.Mock(side_effect=DRIVER.Rejected("dedicated_isolation_not_proven"))
        driver.event = mock.Mock()
        driver.evidence = mock.Mock()
        with mock.patch.object(DRIVER, "write_json"):
            result = driver.run()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["full_matrix"])
        driver.control.call.assert_not_called()

    def test_partial_protocol_bypass_cannot_pass_negative_traffic(self):
        failed = {"tcp": {"ok": False}, "udp": {"ok": False}, "https": {"ok": False}}
        DRIVER.assert_all_traffic_failed({"events": [failed]})
        for protocol in ("tcp", "udp", "https"):
            broken = copy.deepcopy(failed)
            broken[protocol]["ok"] = True
            with self.assertRaises(DRIVER.Rejected):
                DRIVER.assert_all_traffic_failed({"events": [broken]})

    def test_native_sparse_counter_response_is_typed_and_cannot_double_count(self):
        observed = {"kind": "result", "event": "stats", "counters": [{"name": "user>>>u1_n2>>>traffic>>>uplink", "value": "9007199254740993"}]}
        self.assertEqual(DRIVER.counter_values(observed), {"user>>>u1_n2>>>traffic>>>uplink": 9007199254740993})
        observed["counters"].append(copy.deepcopy(observed["counters"][0]))
        with self.assertRaises(DRIVER.Rejected):
            DRIVER.counter_values(observed)
        with self.assertRaises(DRIVER.Rejected):
            DRIVER.counter_values({"kind": "result", "event": "stats", "counters": [{"name": "counter", "value": 3}]})

    def test_client_jsonlines_preserve_fault_rows_and_exact_final_history(self):
        fixtures = object.__new__(DRIVER.Fixtures)
        fixtures.run_id = "run"
        fixtures.deadline = mock.Mock(remaining=lambda maximum: maximum)
        event = {"round": 1, "elapsed_ms": 0, "tcp": {"ok": False}, "udp": {"ok": False}, "https": {"ok": False}}
        result = {"kind": "result", "run_id": "run", "cleanup_confirmed": True, "events": [event]}
        for changed in (False, True):
            client = mock.Mock()
            final = copy.deepcopy(result)
            if changed:
                final["events"][0]["tcp"]["ok"] = True
            client.receive.side_effect = [{"kind": "traffic", "event": "client_round", "phase": "fault", **event}, final]
            fixtures.clients = [client]
            if changed:
                with self.assertRaises(DRIVER.Rejected):
                    fixtures.client_result(client)
            else:
                self.assertEqual(fixtures.client_result(client), result)
            client.stop.assert_called_once()
            self.assertEqual(fixtures.clients, [])

    def test_signal_enters_cleanup_once_instead_of_killing_driver(self):
        with mock.patch.object(DRIVER, "CANCELLED", False):
            with self.assertRaisesRegex(DRIVER.Rejected, "^acceptance_cancelled$"):
                DRIVER.interrupted(signal.SIGTERM, None)
            self.assertTrue(DRIVER.CANCELLED)
            DRIVER.interrupted(signal.SIGINT, None)


if __name__ == "__main__":
    unittest.main()
