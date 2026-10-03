#!/usr/bin/env python3
"""Accept registered Linux paths through real panel APIs and bounded controllers.

No panel business function or device-result writer is available to this driver.
The prepared environment owns installation, isolation, and read-only observations.
Ordered paths use the separate mainline ordered API family. Numeric source/path
IDs and UUID request, external-node, version, revision, and job IDs retain their
actual types; the legacy numeric two-hop APIs are not fallback endpoints.
Runtime path proofs use the signed panel /health plan. This driver does not
create periodic ProbeSpec monitoring authorizations or execution leases.
"""

import argparse
import contextlib
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from managed_paths_support import OwnedProcess, write_pipe


PLUGIN = "/api/plugins/sing-box"
ORDERED_SOURCES = PLUGIN + "/ordered-subscription-sources"
ORDERED_SOURCE_JOBS = PLUGIN + "/ordered-subscription-source-jobs"
ORDERED_RESOURCES = PLUGIN + "/ordered-proxy-resources"
ORDERED_BATCH = PLUGIN + "/chains/ordered-batch"
MAX_BYTES = 2 * 1024 * 1024
SCENARIOS = (
    "baseline", "atomic-replay", "source-versions", "candidate-failure",
    "dependency-offline", "agent-restart", "runtime-restart", "panel-disconnect", "external-failure",
    "authorization", "retirement",
)
CONTROL_OPERATIONS = frozenset((
    "inspect", "enroll", "agent_stop", "agent_start", "agent_restart",
    "runtime_restart", "panel_stop", "panel_start", "device_snapshot",
    "panel_evidence", "restore_all", "cleanup",
))
CANCELLED = False


class Rejected(Exception):
    """Only fixed codes and HTTP statuses are exposed outside private evidence."""


def interrupted(signum, frame):
    global CANCELLED
    if not CANCELLED:
        CANCELLED = True
        raise Rejected("acceptance_cancelled")


def require(condition, code):
    if not condition:
        raise Rejected(code)


def positive(value):
    return type(value) is int and value > 0


def resource_id(value):
    """Preserve panel bigint identities without accepting bools or coercion."""
    require(type(value) is int and 0 < value < 2**63, "resource_id_invalid")
    return value


def uuid_id(value):
    require(isinstance(value, str), "uuid_id_invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise Rejected("uuid_id_invalid") from None
    require(str(parsed) == value and parsed.int != 0, "uuid_id_invalid")
    return value


def batch_receipt(value, request):
    require(isinstance(value, dict) and uuid_id(value.get("request_id")) == request["request_id"],
            "batch_receipt_request_changed")
    for field in ("chain_ids", "entry_node_ids"):
        identifiers = value.get(field)
        require(isinstance(identifiers, list) and len(identifiers) == len(request["items"]),
                "batch_receipt_incomplete")
        for identifier in identifiers:
            resource_id(identifier)
        require(len(set(identifiers)) == len(identifiers), "batch_receipt_duplicate_ids")
    return value


def source_receipt(value, identifier=None):
    require(isinstance(value, dict), "source_receipt_invalid")
    actual = resource_id(value.get("source_id"))
    require(identifier is None or actual == identifier, "source_receipt_source_changed")
    resource_id(value.get("settings_revision"))
    resource_id(value.get("identity_epoch"))
    if value.get("job_id") is not None:
        uuid_id(value["job_id"])
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def private_file(value, maximum=MAX_BYTES):
    path = Path(value)
    require(path.is_absolute(), "private_path_not_absolute")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "private_file_not_regular")
    require(metadata.st_mode & 0o077 == 0, "private_file_permissions")
    require(metadata.st_size <= maximum, "private_file_too_large")
    return path


def secure_read(value, maximum=MAX_BYTES, private=False):
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts, "input_path_invalid")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            metadata = os.fstat(descriptor)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= maximum, "input_file_invalid")
            require(not private or metadata.st_mode & 0o077 == 0, "private_file_permissions")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                data = source.read(maximum + 1)
            require(len(data) <= maximum, "input_file_limit")
            return data
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def read_json(path, private=True):
    data = secure_read(path, private=private)
    try:
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise Rejected("json_file_invalid") from None


def write_json(path, value):
    write_bytes(path, canonical(value) + b"\n")


def write_bytes(path, data):
    require(path.parent.is_dir() and not path.parent.is_symlink(), "output_parent_invalid")
    require(not path.is_symlink(), "output_is_symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".managed-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def origin(value, https=False):
    require(isinstance(value, str) and "\\" not in value, "panel_origin_invalid")
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme in (("https",) if https else ("http", "https"))
            and parsed.hostname and not parsed.username and not parsed.password
            and "@" not in parsed.netloc and not parsed.query and not parsed.fragment
            and parsed.path in ("", "/") and parsed.port != 0, "panel_origin_invalid")
    return value.rstrip("/")


def verified_program(description):
    path = Path(description["path"])
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), "controller_path_invalid")
    require(isinstance(description.get("sha256"), str)
            and digest(secure_read(path, 1024 * 1024)) == description["sha256"], "controller_source_changed")
    return path


def private_directory(value, allow_missing=False):
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts, "private_directory_path_invalid")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:
                following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=descriptor)
            except FileNotFoundError:
                require(allow_missing, "private_directory_missing")
                return path
            os.close(descriptor)
            descriptor = following
        require(os.fstat(descriptor).st_mode & 0o077 == 0, "private_directory_permissions")
        return path
    except OSError:
        raise Rejected("private_directory_path_invalid") from None
    finally:
        os.close(descriptor)


def canonical_panel_origin(value):
    origin(value, https=True)
    parsed = urllib.parse.urlsplit(value)
    host = parsed.hostname
    require(host.isascii() and not any(character.isspace() or ord(character) < 32 for character in value),
            "panel_origin_invalid")
    authority = "[" + host + "]" if ":" in host else host
    if parsed.port is not None:
        authority += ":" + str(parsed.port)
    require(value == "https://" + authority, "panel_origin_not_canonical")
    return value


def fixture_bindings(fixture, prepared):
    require(isinstance(fixture, dict) and fixture.get("schema") == 1 and
            fixture.get("test_only") is True and fixture.get("run_id") == prepared["run_id"],
            "fixture_run_binding")
    addresses = fixture.get("addresses")
    require(isinstance(addresses, dict) and set(addresses) == {"fixture", "client", "A", "M", "B"},
            "fixture_addresses_invalid")
    for role in ("A", "M", "B"):
        require(addresses[role] == prepared["roles"][role]["address"], "fixture_role_address_mismatch")
    managed = {addresses[role] for role in ("A", "M", "B")}
    # Both helper processes run in the driver's host network namespace. A
    # distinct client address is allowed only as an assigned host alias; this
    # field never creates or attests another isolated client namespace.
    for role in ("fixture", "client"):
        try:
            address = ipaddress.ip_address(addresses[role])
        except (ValueError, TypeError):
            raise Rejected("fixture_host_address_invalid") from None
        require(address.version == 4 and address.is_private and
                (role == "client" or not address.is_loopback) and not address.is_unspecified and
                not address.is_multicast and str(address) not in managed,
                "fixture_host_address_invalid")
    ports = fixture.get("managed_ports")
    require(isinstance(ports, dict) and set(ports) == {"A", "M", "B"}, "fixture_managed_ports_mismatch")
    for role, expected in (("A", [20011, 20012]), ("M", [20001]), ("B", [20001])):
        actual = ports[role] if isinstance(ports[role], list) else [ports[role]]
        require(all(type(port) is int for port in actual) and sorted(actual) == expected,
                "fixture_managed_ports_mismatch")


def manifest_contract(value):
    require(isinstance(value, dict) and value.get("schema") == 1, "prepared_manifest_schema")
    try:
        run_id = uuid.UUID(value["run_id"])
        require(str(run_id) == value["run_id"] and run_id.int != 0, "prepared_run_id_invalid")
    except (ValueError, TypeError, KeyError):
        raise Rejected("prepared_run_id_invalid") from None
    require(value.get("release", {}).get("test_only") is True, "test_release_required")
    require(isinstance(value.get("source_identity"), dict) and value["source_identity"],
            "frozen_source_identity_required")
    require(set(value.get("roles", {})) == {"A", "M", "B"}, "three_roles_required")
    addresses = []
    for role in ("A", "M", "B"):
        item = value["roles"][role]
        address = ipaddress.ip_address(item["address"])
        require(address.version == 4 and address.is_private and not address.is_loopback and
                not address.is_unspecified and not address.is_multicast and str(address) == item["address"],
                "role_address_not_isolated")
        addresses.append(address)
        require(isinstance(item.get("sni"), str) and item["sni"], "role_sni_required")
        private_file(item["agent_config_file"])
    require(len(set(addresses)) == 3, "role_addresses_not_distinct")
    panel = value["panel"]
    canonical_panel_origin(panel["origin"])
    private_file(panel["ca_file"], 256 * 1024)
    private_file(panel["admin_descriptor_file"])
    verified_program(value["controller"])
    controller = read_json(private_file(value["controller"]["manifest_file"]))
    require(isinstance(controller, dict) and controller.get("schema") == 1 and
            controller.get("test_only") is True and controller.get("dedicated") is True,
            "controller_manifest_invalid")
    require(controller.get("run_id") == value["run_id"], "controller_run_binding")
    require(controller.get("source_identity") == value["source_identity"], "controller_source_binding")
    require(isinstance(controller.get("panel"), dict) and
            controller["panel"].get("origin") == panel["origin"], "controller_panel_origin_mismatch")
    run_root = private_directory(controller["run_root"])
    marker = secure_read(run_root / ".sinan-managed-test-run", 128, private=True)
    require(marker.decode("utf-8").strip() == value["run_id"], "run_ownership_mismatch")
    evidence = Path(value["evidence_dir"])
    require(evidence.is_absolute() and ".." not in evidence.parts and
            evidence != run_root and evidence.is_relative_to(run_root), "evidence_outside_owned_run")
    private_directory(evidence, allow_missing=True)
    verified_program(value["fixture"])
    fixture_bindings(read_json(private_file(value["fixture"]["manifest_file"])), value)
    return value


class Deadline:
    def __init__(self, seconds=1800):
        self.ends = time.monotonic() + seconds

    def remaining(self, maximum):
        remaining = self.ends - time.monotonic()
        require(remaining > 0, "acceptance_deadline")
        return min(maximum, remaining)


class Process:
    """Bound both pipes while retaining only this process group's ownership."""

    def __init__(self, command, directory, label, payload=None):
        self.buffers = [bytearray(), bytearray()]
        self.overflow = threading.Event()
        self.log = directory / (label + ".stderr")
        self.threads = []
        self.process = OwnedProcess(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
        try:
            for index, stream in enumerate((self.process.stdout, self.process.stderr)):
                thread = threading.Thread(target=self._drain, args=(stream, index), daemon=True)
                thread.start()
                self.threads.append(thread)
            if payload is not None:
                write_pipe(self.process.stdin, canonical(payload) + b"\n")
            self.process.stdin.close()
        except BaseException:
            self.stop()
            raise

    def _drain(self, stream, index):
        while True:
            block = stream.read(4096)
            if not block:
                return
            if len(self.buffers[index]) + len(block) > MAX_BYTES:
                self.overflow.set()
                return
            self.buffers[index].extend(block)

    def stop(self):
        self.process.stop_group()
        for thread in self.threads:
            thread.join(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
        write_bytes(self.log, bytes(self.buffers[1]))

    def result(self, timeout):
        try:
            self.process.wait(timeout=timeout)
            for thread in self.threads:
                thread.join(timeout=1)
            require(not self.overflow.is_set(), "helper_output_limit")
            require(not any(thread.is_alive() for thread in self.threads), "helper_inherited_pipe")
            require(self.process.returncode == 0, "helper_process_failed")
            try:
                return json.loads(bytes(self.buffers[0]))
            except (ValueError, UnicodeError):
                raise Rejected("helper_output_invalid") from None
        except subprocess.TimeoutExpired:
            raise Rejected("helper_deadline") from None
        finally:
            self.stop()


class Controller:
    def __init__(self, manifest, directory, deadline):
        self.path = verified_program(manifest["controller"])
        self.manifest_file = private_file(manifest["controller"]["manifest_file"])
        self.run_id = manifest["run_id"]
        self.directory, self.deadline = directory, deadline
        self.sequence = 0

    def call(self, operation, role=None, arguments=None, cleanup=False):
        require(operation in CONTROL_OPERATIONS, "controller_operation_not_allowed")
        require(role is None or role in ("A", "M", "B"), "controller_role_invalid")
        self.sequence += 1
        body = {"schema": 1, "run_id": self.run_id, "operation": operation,
                "arguments": arguments or {}}
        if role is not None:
            body["role"] = role
        timeout = 60 if cleanup else self.deadline.remaining(120 if operation == "enroll" else 30)
        process = Process([sys.executable, str(self.path), "--manifest", str(self.manifest_file)], self.directory,
                          f"control-{self.sequence:04d}", body)
        value = process.result(timeout)
        require(isinstance(value, dict) and value.get("schema") == 1
                and value.get("run_id") == self.run_id and value.get("operation") == operation,
                "controller_response_binding")
        require(value.get("ok") is True and isinstance(value.get("facts"), dict), "controller_action_failed")
        return value["facts"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise Rejected("panel_redirect_rejected")


class Panel:
    def __init__(self, prepared, deadline):
        self.base = origin(prepared["origin"], https=True)
        self.deadline = deadline
        self.context = ssl.create_default_context(cafile=str(private_file(prepared["ca_file"])))
        self.client = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=self.context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.auth = read_json(prepared["admin_descriptor_file"])
        require(isinstance(self.auth, dict) and isinstance(self.auth.get("password"), str), "admin_descriptor_invalid")

    def login(self):
        self.request("/api/login", "POST", self.auth, expected=(200,))

    def request(self, path, method="GET", body=None, expected=(200,), raw=False):
        require(path.startswith("/") and not path.startswith("//"), "api_path_invalid")
        request = urllib.request.Request(self.base + path, method=method,
                                         data=None if body is None else canonical(body),
                                         headers={} if body is None else {"Content-Type": "application/json"})
        try:
            try:
                response = self.client.open(request, timeout=self.deadline.remaining(20))
            except urllib.error.HTTPError as error:
                response = error
            with response:
                code = response.code
                data = response.read(MAX_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Rejected("panel_transport_failed") from None
        require(len(data) <= MAX_BYTES, "panel_response_limit")
        require(code in expected, "panel_http_" + str(code))
        if raw:
            return code, data
        if code == 204:
            return None
        try:
            return json.loads(data)
        except (ValueError, UnicodeError):
            raise Rejected("panel_json_invalid") from None


def complete_inspection(facts):
    require(facts.get("dedicated") is True and facts.get("isolated") is True
            and facts.get("test_only") is True, "dedicated_isolation_not_proven")
    require(set(facts.get("roles", {})) == {"A", "M", "B"}, "isolation_roles_missing")
    for field in ("filesystem_id", "netns_id", "systemd_id"):
        values = [facts["roles"][role].get(field) for role in ("A", "M", "B")]
        require(all(value is not None for value in values) and len(set(values)) == 3,
                "isolation_identity_not_distinct")


def bind_inspection(facts, prepared):
    complete_inspection(facts)
    require(facts.get("panel_origin") == prepared["panel"]["origin"], "inspected_panel_origin_mismatch")
    require(facts.get("source_identity") == prepared["source_identity"], "inspected_source_identity_mismatch")


def assert_proof_chain(evidence, chain_id, generation):
    """Check actual persistent association and receipts; a healthy flag is insufficient."""
    probes = [item for item in evidence.get("path_probes", [])
              if item.get("chain_id") == chain_id and item.get("generation") == generation]
    requests = {item["request_id"]: item for item in evidence.get("requests", [])}
    receipts = {item["request_id"]: item for item in evidence.get("receipts", [])}
    for stage in ("candidate", "switched"):
        matches = [item for item in probes if item.get("stage") == stage and item.get("state") == "verified"]
        require(len(matches) == 1, "verified_probe_stage_missing")
        probe = matches[0]
        request = requests.get(probe.get("request_id"), {})
        receipt = receipts.get(probe.get("request_id"), {})
        result = receipt.get("result", {})
        vector = probe.get("dependency_vector")
        require(request.get("kind") == "probe" and receipt.get("outcome") == "verified"
                and result.get("success") is True and result.get("observed") == request.get("expected")
                and result.get("request_digest") == request.get("digest")
                and result.get("probe_id") == probe.get("probe_id")
                and valid_vector(vector) and [request.get("server_id"), request.get("expected")] in vector,
                "probe_receipt_not_bound")
    barriers = [item for item in evidence.get("vectors", [])
                if item.get("chain_id") == chain_id and item.get("generation") == generation
                and item.get("barrier_request_id")]
    require(barriers, "barrier_binding_missing")
    for binding in barriers:
        request = requests.get(binding["barrier_request_id"], {})
        receipt = receipts.get(binding["barrier_request_id"], {})
        result = receipt.get("result", {})
        vector = binding.get("barrier_vector")
        expected = request.get("expected", {}).get("binding", {})
        require(request.get("kind") == "barrier" and receipt.get("outcome") == "verified"
                and result.get("success") is True and result.get("pending_intents_clear") is True
                and result.get("request_digest") == request.get("digest")
                and result.get("observed") == request.get("expected")
                and type(result.get("minimum_revision")) is int
                and result["minimum_revision"] >= binding["revision"]
                and valid_vector(vector) and [request.get("server_id"), request.get("expected")] in vector
                and expected.get("revision") == binding["revision"]
                and expected.get("bundle_sha256") == binding["bundle_sha256"]
                and expected.get("deployment_id") == binding["deployment_id"]
                and expected.get("binding_digest") == binding["binding_digest"],
                "barrier_receipt_not_bound")


def valid_vector(vector):
    return isinstance(vector, list) and bool(vector) and all(
        isinstance(item, list) and len(item) == 2 and positive(item[0])
        and isinstance(item[1], dict) and isinstance(item[1].get("binding"), dict)
        for item in vector) and len({item[0] for item in vector}) == len(vector)


class Lines:
    """A bounded JSON-lines peer; neither ready nor exit alone means acceptance."""

    def __init__(self, command, directory, label):
        self.pending = bytearray()
        self.stderr = bytearray()
        self.overflow = threading.Event()
        self.log = directory / (label + ".stderr")
        self.reader = None
        self.selector = selectors.DefaultSelector()
        self.process = OwnedProcess(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
        try:
            self.reader = threading.Thread(target=self._stderr, daemon=True)
            self.reader.start()
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
        except BaseException:
            self.stop()
            raise

    def _stderr(self):
        while True:
            block = self.process.stderr.read(4096)
            if not block:
                return
            if len(self.stderr) + len(block) > MAX_BYTES:
                self.overflow.set()
                return
            self.stderr.extend(block)

    def send(self, value):
        require(self.process.poll() is None, "fixture_peer_exited")
        write_pipe(self.process.stdin, canonical(value) + b"\n")

    def receive(self, timeout):
        ends = time.monotonic() + timeout
        while b"\n" not in self.pending:
            require(not self.overflow.is_set(), "fixture_output_limit")
            remaining = ends - time.monotonic()
            require(remaining > 0, "fixture_response_deadline")
            require(self.selector.select(remaining), "fixture_response_deadline")
            block = os.read(self.process.stdout.fileno(), 4096)
            require(block, "fixture_response_eof")
            self.pending.extend(block)
            require(len(self.pending) <= MAX_BYTES, "fixture_response_limit")
        line, _, self.pending = self.pending.partition(b"\n")
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            raise Rejected("fixture_json_invalid") from None
        require(isinstance(value, dict), "fixture_response_invalid")
        return value

    def stop(self):
        self.process.stop_group()
        if self.reader is not None:
            self.reader.join(timeout=1)
        self.selector.close()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
        write_bytes(self.log, bytes(self.stderr))


class Fixtures:
    def __init__(self, prepared, directory, deadline, run_id):
        self.path = verified_program(prepared)
        self.manifest_file = private_file(prepared["manifest_file"])
        self.manifest = read_json(self.manifest_file)
        require(self.manifest.get("schema") == 1 and self.manifest.get("test_only") is True,
                "fixture_manifest_invalid")
        require(self.manifest.get("run_id") == run_id, "fixture_run_binding")
        self.directory, self.deadline, self.run_id = directory, deadline, run_id
        self.serve = None
        self.clients = []
        self.sequence = 0
        self.cursor = 0

    def command(self, operation, *arguments):
        return [sys.executable, str(self.path), operation, "--manifest", str(self.manifest_file), *arguments]

    def start(self):
        self.serve = Lines(self.command("serve"), self.directory, "fixture-serve")
        ready = self.serve.receive(self.deadline.remaining(30))
        require(ready.get("kind") == "ready" and ready.get("run_id") == self.run_id, "fixture_not_ready")
        self.journal = private_file(ready["journal"])
        return ready

    def source(self, version):
        descriptor = self.manifest["source_contents"][version]
        path = private_file(descriptor["path"])
        content = secure_read(path, private=True)
        require(digest(content) == descriptor["sha256"], "fixture_source_changed")
        try:
            return content.decode("utf-8")
        except UnicodeError:
            raise Rejected("fixture_source_encoding") from None

    def service(self, operation, **arguments):
        require(operation in ("snapshot", "stop_x", "start_x", "stop"), "fixture_operation_invalid")
        self.serve.send({"op": operation, **arguments})
        return self.serve.receive(self.deadline.remaining(20))

    def target_events(self):
        events = []
        for _ in range(32):
            snapshot = self.service("snapshot", after=self.cursor)
            rows = snapshot.get("events", [])
            require(isinstance(rows, list) and len(rows) <= 128, "target_event_page_invalid")
            for row in rows:
                require(positive(row.get("seq")) and row["seq"] > self.cursor, "target_event_sequence_invalid")
                self.cursor = row["seq"]
                events.append(row)
            require(snapshot.get("next") == self.cursor, "target_event_cursor_invalid")
            if not snapshot.get("has_more"):
                self.sequence += 1
                write_json(self.directory / f"target-events-{self.sequence:03d}.json", events)
                return events
            require(rows, "target_events_truncated")
        raise Rejected("target_event_page_limit")

    def client(self, config, phase, duration=1):
        self.sequence += 1
        client = Lines(self.command("client", "--config", str(config), "--config-sha256",
                                    digest(config.read_bytes()), "--phase", phase,
                                    "--duration-secs", str(duration), "--interval-ms", "1000"),
                       self.directory, f"client-{self.sequence:03d}")
        self.clients.append(client)
        ready = client.receive(self.deadline.remaining(30))
        require(ready.get("kind") == "ready" and ready.get("run_id") == self.run_id
                and isinstance(ready.get("identity"), dict),
                "client_not_ready")
        return client, ready["identity"]

    def client_result(self, client, timeout=90):
        try:
            ends = time.monotonic() + self.deadline.remaining(timeout)
            observed = []
            while True:
                result = client.receive(max(0.001, ends - time.monotonic()))
                if result.get("kind") == "traffic":
                    observed.append({key: result[key] for key in ("round", "elapsed_ms", "tcp", "udp", "https")})
                    require(len(observed) <= 64, "traffic_event_limit")
                    continue
                break
            require(result.get("kind") == "result" and result.get("run_id") == self.run_id
                    and result.get("cleanup_confirmed") is True,
                    "client_cleanup_unconfirmed")
            require(isinstance(result.get("events"), list) and result["events"], "traffic_events_missing")
            require(observed == result["events"], "traffic_history_changed")
            return result
        finally:
            client.stop()
            self.clients.remove(client)

    def observe(self, identities, seconds=10):
        self.sequence += 1
        identity_file = self.directory / f"identities-{self.sequence:03d}.json"
        write_json(identity_file, identities)
        timeout = self.deadline.remaining(seconds + 15)
        return Process(self.command("observe", "--identities", str(identity_file),
                                    "--seconds", str(seconds)), self.directory,
                       f"observe-{self.sequence:03d}").result(timeout)

    def stats(self, role, identities):
        self.sequence += 1
        identity_file = self.directory / f"stats-identities-{self.sequence:03d}.json"
        write_json(identity_file, identities)
        timeout = self.deadline.remaining(20)
        return Process(self.command("stats", "--role", role, "--identities", str(identity_file)),
                       self.directory, f"stats-{self.sequence:03d}").result(timeout)

    def stop(self):
        for client in list(self.clients):
            client.stop()
            self.clients.remove(client)
        if self.serve is not None:
            try:
                self.serve.send({"op": "stop"})
                result = self.serve.receive(20)
                require(result.get("cleanup_confirmed") is True, "fixture_cleanup_unconfirmed")
                self.process_journal()
            finally:
                self.serve.stop()
                self.serve = None

    def process_journal(self):
        if hasattr(self, "journal"):
            data = secure_read(self.journal, private=True)
            lines = data.splitlines()
            require(all(len(line) <= 16384 for line in lines), "fixture_journal_row_limit")
            write_json(self.directory / "fixture-journal-receipt.json", {
                "sha256": digest(data), "size": len(data), "rows": len(lines), "run_id": self.run_id})


def successful_events(result):
    return [event for event in result["events"]
            if all(event.get(name, {}).get("ok") is True for name in ("tcp", "udp", "https"))]


def assert_all_traffic_failed(result):
    require(isinstance(result.get("events"), list) and result["events"]
            and all(event.get(protocol, {}).get("ok") is False
                    for event in result["events"] for protocol in ("tcp", "udp", "https")),
            "traffic_bypassed_failed_dependency_or_authorization")


def counter_values(stats):
    require(stats.get("kind") == "result" and stats.get("event") == "stats"
            and isinstance(stats.get("counters"), list), "native_stats_not_observed")
    values = {}
    for counter in stats["counters"]:
        name, value = counter.get("name"), counter.get("value")
        require(isinstance(name, str) and name not in values and isinstance(value, str)
                and value.isdecimal(), "native_counter_invalid")
        values[name] = int(value)
    return values


def assert_traffic(result, all_rounds=True):
    successes = successful_events(result)
    require(successes and (not all_rounds or len(successes) == len(result["events"])), "traffic_not_successful")
    for event in successes:
        require(event["tcp"].get("bytes") == 4096 and event["udp"].get("packets") == 5
                and event["udp"].get("bytes") == 960, "traffic_payload_not_bounded")


def assert_graph(observation, four_hops):
    require(observation.get("kind") == "result" and observation.get("event") == "observation"
            and observation.get("socket_edges"), "network_observation_missing")
    edges = {tuple(edge) for edge in observation.get("edges", [])}
    required = {("client", "A"), ("X", "B"), ("B", "target")}
    required |= {("A", "M"), ("M", "X")} if four_hops else {("A", "X")}
    forbidden = {("A", "B"), ("A", "target"), ("M", "B"), ("M", "target"),
                 ("X", "target"), ("client", "target")}
    require(required <= edges and not forbidden.intersection(edges), "ordered_graph_not_observed")


class Driver:
    def __init__(self, manifest, scenarios):
        self.manifest = manifest_contract(manifest)
        self.deadline = Deadline()
        self.scenarios = scenarios
        root = Path(manifest["evidence_dir"])
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not root.is_symlink() and root.stat().st_mode & 0o077 == 0, "evidence_directory_permissions")
        self.state_file = root / "managed-private-state.json"
        self.state = read_json(self.state_file) if self.state_file.exists() else {
            "schema": 1, "run_id": manifest["run_id"], "manifest_sha256": digest(canonical(manifest)),
            "prefix": "managed-" + manifest["run_id"][:8], "ids": {}, "requests": {}, "tokens": {},
        }
        require(self.state.get("run_id") == manifest["run_id"]
                and self.state.get("manifest_sha256") == digest(canonical(manifest)), "resume_environment_changed")
        attempt = root / ("attempt-" + str(uuid.uuid4()))
        attempt.mkdir(mode=0o700)
        self.directory = attempt
        self.control = Controller(manifest, attempt, self.deadline)
        self.panel = Panel(manifest["panel"], self.deadline)
        self.fixtures = Fixtures(manifest["fixture"], attempt, self.deadline, manifest["run_id"])
        self.inspection = None
        self.events = []
        self.results = {}
        self.cleanup_errors = []
        self.fixture_started = False
        self.environment_owned = False
        self.accounting_verified = False

    def save(self):
        write_json(self.state_file, self.state)

    def event(self, code, **facts):
        require(len(self.events) < 1024, "event_budget")
        self.events.append({"at": int(time.time()), "event": code, **facts})
        write_json(self.directory / "events.json", self.events)

    def owned(self):
        ids = self.state["ids"]
        for identifier in ids.values():
            resource_id(identifier)
        return {"servers": [ids[key] for key in ("server_A", "server_M", "server_B") if key in ids],
                "chains": [ids[key] for key in ("chain_three", "chain_four") if key in ids],
                "users": [ids[key] for key in ("user_three", "user_four") if key in ids],
                "node_ids": [value for key, value in ids.items() if key.startswith("node_")]}

    def evidence(self, label):
        facts = self.control.call("panel_evidence", arguments={"owned_ids": self.owned()})
        write_json(self.directory / (label + "-panel.json"), facts)
        devices = {}
        for role in ("A", "M", "B"):
            devices[role] = self.control.call("device_snapshot", role)
        write_json(self.directory / (label + "-devices.json"), devices)
        return facts, devices

    def wait(self, label, read, predicate, seconds=240, permit_failure=False):
        ends = time.monotonic() + self.deadline.remaining(seconds)
        last = None
        while time.monotonic() < ends:
            try:
                value = read()
            except Rejected as error:
                if str(error) not in ("panel_transport_failed", "panel_http_502", "panel_http_503"):
                    raise
                time.sleep(min(1, max(0, ends - time.monotonic())))
                continue
            if predicate(value):
                self.event("wait_complete", label=label)
                return value
            if isinstance(value, dict):
                state = value.get("path_state", value)
                summary = {key: state.get(key) for key in ("phase", "desired_generation", "applied_generation", "status")}
                if summary != last:
                    self.event("wait_observation", label=label, state=summary)
                    last = summary
                if not permit_failure:
                    require(state.get("phase") != "failed", "path_failed_" + label)
            time.sleep(min(1, max(0, ends - time.monotonic())))
        raise Rejected("state_deadline_" + label)

    def request_once(self, key, path, method, body, statuses=(200, 201, 202)):
        record = {"path": path, "method": method, "body": body}
        previous = self.state["requests"].get(key)
        require(previous is None or previous == record, "saved_request_changed")
        self.state["requests"][key] = record
        self.save()
        # Only interfaces carrying request_id are automatically replayed after loss.
        try:
            return self.panel.request(path, method, body, expected=statuses)
        except Rejected as error:
            if str(error) != "panel_transport_failed" or "request_id" not in body:
                raise
            return self.panel.request(path, method, body, expected=statuses)

    def named(self, key, path, fields):
        name = self.state["prefix"] + "-" + key
        items = self.panel.request(path)
        require(isinstance(items, list), "resource_list_invalid")
        matches = [item for item in items if item.get("name") == name]
        require(len(matches) <= 1, "owned_name_ambiguous")
        if key in self.state["ids"]:
            require(matches and matches[0].get("id") == self.state["ids"][key], "owned_resource_changed")
        if not matches:
            item = self.panel.request(path, "POST", {"name": name, **fields}, expected=(201,))
        else:
            item = matches[0]
        resource_id(item.get("id"))
        for field in ("server_id", "public_host", "port", "chain_ids", "node_ids"):
            if field in fields:
                require(item.get(field) == fields[field], "owned_resource_configuration_changed")
        self.state["ids"][key] = item["id"]
        self.save()
        return item

    def resource(self, which):
        identifier = resource_id(self.state["ids"]["chain_" + which])
        value = self.panel.request(ORDERED_RESOURCES + "/chain/" + str(identifier))
        require(isinstance(value, dict) and resource_id(value.get("id")) == identifier,
                "ordered_resource_changed")
        return value

    def applied(self, which, generation=None):
        def ready(item):
            state = item.get("path_state") or {}
            return state.get("phase") == "applied" and positive(state.get("applied_generation")) \
                and state.get("candidate_generation") is None \
                and (generation is None or state["applied_generation"] >= generation)
        return self.wait(which, lambda: self.resource(which), ready)

    def source_nodes(self):
        identifier = resource_id(self.state["ids"]["source"])
        value = self.panel.request(ORDERED_SOURCES + f"/{identifier}/nodes")
        require(isinstance(value, dict) and resource_id(value.get("source_id")) == identifier,
                "source_nodes_source_changed")
        return value

    def source_version(self):
        page = self.wait("source_nodes", self.source_nodes,
                         lambda item: item.get("success_revision") is not None
                         and any(node.get("selectable") for node in item.get("nodes", [])))
        nodes = [node for node in page["nodes"] if node.get("selectable")]
        require(len(nodes) == 1, "fixture_source_identity_ambiguous")
        node = nodes[0]
        revision = page["success_revision"]
        require(resource_id(revision.get("source_id")) == self.state["ids"]["source"]
                and resource_id(node.get("source_id")) == self.state["ids"]["source"],
                "source_version_source_changed")
        uuid_id(node.get("id"))
        uuid_id(node.get("version_id"))
        require(uuid_id(node.get("source_revision_id")) == uuid_id(revision.get("id")),
                "source_version_revision_changed")
        require(resource_id(node.get("identity_epoch")) == resource_id(revision.get("identity_epoch")),
                "source_version_epoch_changed")
        return node

    def source(self):
        identifier = resource_id(self.state["ids"]["source"])
        value = self.panel.request(ORDERED_SOURCES + f"/{identifier}")
        require(isinstance(value, dict) and resource_id(value.get("id")) == identifier,
                "source_identity_changed")
        resource_id(value.get("settings_revision"))
        resource_id(value.get("identity_epoch"))
        return value

    def read_source_job(self, receipt, job_id):
        source_receipt(receipt, resource_id(self.state["ids"]["source"]))
        uuid_id(job_id)
        value = self.panel.request(ORDERED_SOURCE_JOBS + "/" + job_id)
        require(isinstance(value, dict) and uuid_id(value.get("id")) == job_id
                and resource_id(value.get("source_id")) == receipt["source_id"]
                and resource_id(value.get("settings_revision")) == receipt["settings_revision"]
                and resource_id(value.get("identity_epoch")) == receipt["identity_epoch"],
                "source_job_binding_changed")
        if value.get("source_revision_id") is not None:
            uuid_id(value["source_revision_id"])
        return value

    def source_job(self, receipt, label="source_job"):
        job_id = uuid_id(receipt.get("job_id"))
        return self.wait(label, lambda: self.read_source_job(receipt, job_id),
                         lambda item: item.get("status") in ("succeeded", "failed", "cancelled", "superseded"))

    def source_failure(self, receipt, previous):
        source_receipt(receipt, resource_id(self.state["ids"]["source"]))
        require(receipt["settings_revision"] == previous["settings_revision"] + 1
                and receipt["identity_epoch"] == previous["identity_epoch"],
                "source_failure_receipt_changed")
        def bound_source():
            current = self.source()
            require(current["settings_revision"] == receipt["settings_revision"]
                    and current["identity_epoch"] == receipt["identity_epoch"],
                    "source_failure_binding_changed")
            return current
        if receipt.get("job_id") is not None:
            job = self.source_job(receipt, "invalid_source")
            current = bound_source()
        else:
            discovered = None
            def observe():
                nonlocal discovered
                current = bound_source()
                active = current.get("active_job")
                if active is not None:
                    require(isinstance(active, dict) and resource_id(active.get("source_id")) == receipt["source_id"]
                            and resource_id(active.get("identity_epoch")) == receipt["identity_epoch"],
                            "source_job_binding_changed")
                    identifier = uuid_id(active.get("id"))
                    revision = resource_id(active.get("settings_revision"))
                    if revision == receipt["settings_revision"]:
                        require(discovered is None or discovered == identifier, "source_job_binding_changed")
                        discovered = identifier
                    else:
                        require(revision < receipt["settings_revision"] and active.get("status") == "cancelling",
                                "source_job_binding_changed")
                if discovered is not None:
                    return {"source": current, "job": self.read_source_job(receipt, discovered)}
                # A fast new worker may finish between observations. No active
                # job plus a fresh source error proves failure; a retained old
                # error needs a strictly newer attempt, never an old success.
                attempt, old_attempt = current.get("last_attempt_at"), previous.get("last_attempt_at")
                fresh_attempt = type(attempt) is int and (old_attempt is None
                    or type(old_attempt) is int and attempt > old_attempt)
                failed = active is None and current.get("last_error") is not None \
                    and (previous.get("last_error") is None or fresh_attempt)
                return {"source": current, "job": None, "failed": failed}
            result = self.wait("invalid_source", observe, lambda item: item.get("failed") is True
                               or isinstance(item.get("job"), dict)
                               and item["job"].get("status") in ("succeeded", "failed", "cancelled", "superseded"))
            current, job = result["source"], result["job"]
        require((job is None or job.get("status") == "failed" and job.get("error") is not None)
                and current.get("last_error") is not None
                and isinstance(current.get("latest_success"), dict)
                and uuid_id(current["latest_success"].get("id")) == uuid_id(previous["latest_success"].get("id")),
                "source_failure_erased_success")
        return current

    def patch_source(self, version, action="update"):
        identifier = resource_id(self.state["ids"]["source"])
        source = self.source()
        body = {"request_id": str(uuid.uuid4()), "settings_revision": source["settings_revision"],
                "input": {"kind": "inline", "content": self.fixtures.source(version), "identity_action": action}}
        receipt = self.request_once("source-" + body["request_id"], ORDERED_SOURCES + f"/{identifier}",
                                    "PATCH", body)
        source_receipt(receipt, identifier)
        require(receipt["settings_revision"] == source["settings_revision"] + 1,
                "source_receipt_revision_changed")
        require(receipt["identity_epoch"] == source["identity_epoch"] + int(action == "replace"),
                "source_receipt_epoch_changed")
        if receipt.get("job_id"):
            job = self.source_job(receipt)
            require(job.get("status") == "succeeded", "source_job_not_successful")
        else:
            # A superseded job may still be cancelling. The API returns no job
            # until its worker can enqueue the new revision; old success is not
            # evidence that this update has finished.
            self.wait("source_import", self.source_nodes, lambda page: isinstance(page.get("success_revision"), dict)
                      and page["success_revision"].get("settings_revision") == receipt["settings_revision"]
                      and page["success_revision"].get("identity_epoch") == receipt["identity_epoch"])
        self.state["source_fixture_version"] = version
        self.save()
        return receipt

    def credentials_unchanged(self):
        for which in ("three", "four"):
            user = self.panel.request(PLUGIN + "/users/" + str(self.state["ids"]["user_" + which]))
            saved = self.state["tokens"][which]
            require(user["subscription_url"] == saved["url"] and user["subscription_token"] == saved["token"],
                    "subscription_identity_changed")

    def subscription(self, which, blocked=False):
        url = self.state["tokens"][which]["url"]
        parsed = urllib.parse.urlsplit(url)
        require(origin(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")), https=True) == self.panel.base
                and parsed.path.startswith("/sub/") and not parsed.query and not parsed.fragment,
                "subscription_origin_changed")
        code, content = self.panel.request(parsed.path + "?format=singbox", expected=(409,) if blocked else (200,), raw=True)
        if blocked:
            preview = self.panel.request(PLUGIN + "/users/" + str(self.state["ids"]["user_" + which]) + "/subscription?format=singbox")
            require(preview.get("status") in ("empty", "blocked") and preview.get("content") is None,
                    "blocked_preview_not_empty")
            return None
        config = json.loads(content)
        proxies = [item for item in config.get("outbounds", []) if item.get("type") == "vless"]
        require(len(proxies) == 1 and proxies[0].get("server") == self.manifest["roles"]["A"]["address"],
                "subscription_not_entry_only")
        file = self.directory / ("subscription-" + which + "-" + str(uuid.uuid4()) + ".json")
        write_bytes(file, content)
        self.event("subscription_read", which=which, status=code, sha256=digest(content))
        return file

    def subscription_ready(self, which):
        user = self.state["ids"]["user_" + which]
        entry = self.state["ids"]["node_" + which]
        return self.wait("qualified_" + which,
                         lambda: self.panel.request(PLUGIN + f"/users/{user}/subscription?format=singbox"),
                         lambda item: item.get("status") == "ready"
                         and any(node.get("id") == entry for node in item.get("ready_nodes", [])),
                         permit_failure=True)

    def identities(self, client=None):
        roles = {}
        for role in ("A", "M", "B"):
            snapshot = self.control.call("device_snapshot", role)
            runtime = snapshot.get("runtime", {})
            require(runtime.get("active") is True and positive(runtime.get("pid")), "runtime_not_active")
            roles[role] = {"pid": runtime["pid"], "starttime": runtime["starttime"],
                           "netns_inode": runtime.get("netns_inode", runtime.get("netns_id"))}
        self.fixtures.target_events()
        snapshot = self.fixtures.service("snapshot", after=self.fixtures.cursor)
        if snapshot.get("x_identity"):
            roles["X"] = snapshot["x_identity"]
        if client:
            roles["client"] = client
        return {"schema": 1, "run_id": self.manifest["run_id"], "roles": roles}

    def traffic(self, which, observe=False):
        self.subscription_ready(which)
        return self.traffic_config(which, self.subscription(which), observe)

    def traffic_config(self, which, configuration, observe=False):
        identities = self.identities() if observe else None
        self.fixtures.target_events()
        client, identity = self.fixtures.client(configuration, which, 20 if observe else 1)
        if identities:
            identities["roles"]["client"] = identity
        observation = self.fixtures.observe(identities, 10) if observe else None
        result = self.fixtures.client_result(client)
        assert_traffic(result)
        targets = self.fixtures.target_events()
        require(targets and all(event.get("peer_role") == "B" for event in targets)
                and {event.get("kind") for event in targets} >= {"tcp", "udp", "https"},
                "user_traffic_final_egress_not_B")
        if observation:
            assert_graph(observation, which == "four")
            write_json(self.directory / (which + "-graph-" + str(uuid.uuid4()) + ".json"), observation)
        self.event("traffic_passed", which=which, rounds=len(result["events"]))
        write_json(self.directory / (which + "-traffic-" + str(uuid.uuid4()) + ".json"), result)
        return result

    def usage(self, which):
        ids = self.state["ids"]
        user, node = ids["user_" + which], ids["node_" + which]
        return self.panel.request(PLUGIN + f"/usage?user_id={user}&node_id={node}")

    def quiet_usage(self):
        def drained(_):
            return all(self.control.call("device_snapshot", role).get("usage", {}).get("pending_batches") == 0
                       for role in ("A", "M", "B"))
        self.wait("usage_outbox", lambda: {}, drained)
        previous = None
        stable = 0
        def totals():
            return {which: self.usage(which)["total"] for which in ("three", "four")}
        ends = time.monotonic() + self.deadline.remaining(30)
        while time.monotonic() < ends:
            current = totals()
            require(all(isinstance(value, str) and value.isdecimal() for value in current.values()), "usage_integer_invalid")
            stable = stable + 1 if current == previous else 0
            if stable >= 10:
                return current
            previous = current
            time.sleep(1)
        raise Rejected("quiet_usage_not_stable")

    def real_proofs(self, label):
        applied = {which: self.applied(which) for which in ("three", "four")}
        for which in ("three", "four"):
            self.subscription_ready(which)
        evidence, devices = self.evidence(label)
        for which in ("three", "four"):
            item = applied[which]
            assert_proof_chain(evidence, item["id"], item["path_state"]["applied_generation"])
        keys = [devices[role].get("device_public_key") for role in ("A", "M", "B")]
        require(all(isinstance(key, str) and key for key in keys) and len(set(keys)) == 3,
                "registered_devices_not_distinct")
        require(all(devices[role].get("usage", {}).get("pending_bytes", 0) <= MAX_BYTES
                    for role in ("A", "M", "B")), "usage_outbox_budget_exceeded")
        for role in ("A", "M", "B"):
            server = self.panel.request("/api/servers/" + str(self.state["ids"]["server_" + role]))
            require(server.get("online") is True and type(server.get("last_heartbeat_at")) is int
                    and 0 <= time.time() - server["last_heartbeat_at"] <= 45
                    and type(server.get("metrics_sampled_at")) is int
                    and 0 <= time.time() * 1000 - server["metrics_sampled_at"] <= 15000
                    and server.get("metrics_stale") is False, "managed_heartbeat_or_metrics_stale")
        self.credentials_unchanged()
        return evidence, devices

    def setup(self):
        self.inspection = self.control.call("inspect")
        bind_inspection(self.inspection, self.manifest)
        self.environment_owned = True
        write_json(self.directory / "isolation.json", self.inspection)
        self.panel.login()
        self.fixtures.start()
        self.fixture_started = True
        capabilities = {"singbox", "artifact:minisign-v1", "runtime:checkpoint-v1",
                        "runtime:barrier-v1", "runtime:path-probe-v1"}
        for role in ("A", "M", "B"):
            server = self.named("server_" + role, "/api/servers", {
                "agent_settings": {"sample_interval_secs": 1, "upload_interval_secs": 3,
                                   "auto_update": False, "discover_public_ips": False}})
            if not server.get("device_public_key"):
                release = self.manifest["release"]
                query = urllib.parse.urlencode({"agent_version": release["agent_version"],
                                                "agent_target": release["agent_target"]})
                enrollment = self.panel.request(f"/api/servers/{server['id']}/enrollment?{query}")
                descriptor = self.directory / ("enrollment-" + role + ".json")
                write_json(descriptor, {"schema": 1, "run_id": self.manifest["run_id"],
                                        "role": role, "token": enrollment["token"],
                                        "server_id": server["id"], "origin": self.panel.base,
                                        "enrollment": enrollment})
                self.control.call("enroll", role, {"descriptor_file": str(descriptor)})
            else:
                self.control.call("agent_start", role)
            server = self.wait("registration_" + role,
                               lambda identifier=server["id"]: self.panel.request(f"/api/servers/{identifier}"),
                               lambda item: item.get("online") is True and item.get("device_public_key")
                               and capabilities <= set(item.get("capabilities", [])))
            self.state.setdefault("device_keys", {})[role] = server["device_public_key"]
            self.save()
            self.panel.request(PLUGIN + f"/servers/{server['id']}/enable", "POST", expected=(200, 202))
            check = self.panel.request(PLUGIN + f"/servers/{server['id']}/deployments/check", "POST")
            require(check.get("ready") is True, "signed_runtime_preflight_failed")
        require(len(set(self.state["device_keys"].values())) == 3, "device_key_collision")
        settings = {"reality": {"handshake_server": self.fixtures.manifest["addresses"]["fixture"],
                                "handshake_port": self.fixtures.manifest["ports"]["handshake"]}}
        for role, key, port in (("M", "node_M", 20001), ("B", "node_B", 20001),
                                ("A", "node_three", 20011), ("A", "node_four", 20012)):
            require(self.manifest["roles"][role]["sni"] == "reality.test", "fixture_reality_sni_mismatch")
            self.named(key, PLUGIN + "/nodes", {
                "server_id": self.state["ids"]["server_" + role],
                "public_host": self.manifest["roles"][role]["address"],
                "sni": self.manifest["roles"][role]["sni"], "port": port, "settings": settings})
        source_id = self.state["ids"].get("source")
        if source_id is None:
            sources = self.panel.request(ORDERED_SOURCES)
            name = self.state["prefix"] + "-source"
            matches = [item for item in sources if item.get("name") == name]
            require(len(matches) <= 1, "owned_source_ambiguous")
            if matches:
                source_id = resource_id(matches[0].get("id"))
            else:
                body = {"request_id": str(uuid.uuid4()), "name": name,
                        "input": {"kind": "inline", "content": self.fixtures.source("v1")}}
                receipt = self.request_once("create-source", ORDERED_SOURCES, "POST", body)
                source_receipt(receipt)
                source_id = receipt["source_id"]
            self.state["ids"]["source"] = source_id
            self.state["source_fixture_version"] = "v1"
            self.save()
        resource_id(source_id)
        node = self.source_version()
        if "chain_three" not in self.state["ids"]:
            request = self.state["requests"].get("create-chains", {}).get("body")
            if request is None:
                request = {"request_id": str(uuid.uuid4()), "items": []}
                for which, port, mode in (("three", 20011, "follow_node"), ("four", 20012, "pinned")):
                    hops = []
                    if which == "four":
                        hops.append({"kind": "managed", "node_id": self.state["ids"]["node_M"]})
                    hops.extend([{"kind": "subscription", "source_id": source_id,
                                  "external_node_id": node["id"], "node_version_id": node["version_id"],
                                  "update_mode": mode},
                                 {"kind": "managed", "node_id": self.state["ids"]["node_B"]}])
                    request["items"].append({"name": self.state["prefix"] + "-" + which,
                                              "entry": {"mode": "existing", "node_id": self.state["ids"]["node_" + which]},
                                              "hops": hops})
            receipt = self.request_once("create-chains", ORDERED_BATCH, "POST", request)
            batch_receipt(receipt, request)
            for position, which in enumerate(("three", "four")):
                self.state["ids"]["chain_" + which] = receipt["chain_ids"][position]
                self.state["ids"]["node_" + which] = receipt["entry_node_ids"][position]
            self.state["initial_source_node"] = {"id": node["id"], "version_id": node["version_id"],
                                                 "identity_epoch": node["identity_epoch"]}
            self.state["initial_batch_receipt"] = receipt
            self.save()
        if not self.state.get("source_replaced") and any(
                self.resource(which)["path_state"]["phase"] == "failed" for which in ("three", "four")):
            self.patch_source("v1")
        for which in ("three", "four"):
            user = self.named("user_" + which, PLUGIN + "/users", {})
            credentials = {"token": user["subscription_token"], "url": user["subscription_url"]}
            previous = self.state["tokens"].get(which)
            require(previous is None or previous == credentials, "user_identity_changed")
            self.state["tokens"][which] = credentials
            self.save()
            policy = self.named("policy_" + which, PLUGIN + "/policy-groups", {
                "node_ids": [], "chain_ids": [self.state["ids"]["chain_" + which]]})
            self.panel.request(PLUGIN + f"/users/{user['id']}/policy-groups", "PUT", {"group_ids": [policy["id"]]})
        self.applied("three")
        self.applied("four")
        self.event("setup_complete", owned_ids=self.owned())

    def scenario_baseline(self):
        self.quiet_usage()
        before_usage = {which: self.usage(which) for which in ("three", "four")}
        before_identities = self.identities()
        before_stats = self.fixtures.stats("A", before_identities)
        for which in ("three", "four"):
            self.traffic(which, observe=True)
        totals = self.quiet_usage()
        require(all(int(value) > 0 for value in totals.values()), "entry_usage_missing")
        identities = self.identities()
        stats = {role: self.fixtures.stats(role, identities) for role in ("A", "M", "B")}
        require(identities["roles"]["A"] == before_identities["roles"]["A"], "accounting_runtime_changed_during_sample")
        after_usage = {which: self.usage(which) for which in ("three", "four")}
        comparisons = []
        before_counters, after_counters = counter_values(before_stats), counter_values(stats["A"])
        for which in ("three", "four"):
            user, node = self.state["ids"]["user_" + which], self.state["ids"]["node_" + which]
            for direction in ("uplink", "downlink"):
                name = f"user>>>u{user}_n{node}>>>traffic>>>{direction}"
                require(name in after_counters, "native_entry_counter_missing")
                native = after_counters[name] - before_counters.get(name, 0)
                ledger = int(after_usage[which][direction]) - int(before_usage[which][direction])
                require(native > 0 and native == ledger, "native_ledger_delta_mismatch")
                comparisons.append({"user_id": user, "node_id": node, "direction": direction,
                                    "native_delta": str(native), "ledger_delta": str(ledger)})
        write_json(self.directory / "native-ledger-reconciliation.json", {
            "verified": True, "basis": "quiet_native_cumulative_counter_and_ledger_delta",
            "before_runtime_identity": before_identities["roles"]["A"],
            "after_runtime_identity": identities["roles"]["A"], "comparisons": comparisons})
        self.accounting_verified = True
        for role in ("M", "B"):
            require(not any(item["name"].startswith("user>>>") for item in stats[role].get("counters", [])),
                    "internal_relay_user_metered")
        write_json(self.directory / "baseline-native-stats.json", stats)
        evidence, _ = self.real_proofs("baseline")
        records = evidence.get("usage", {}).get("records", [])
        require(records and evidence["usage"].get("duplicate_identities") == 0, "usage_identity_not_unique")
        owned_users = set(self.owned()["users"])
        entries = {self.state["ids"]["node_three"], self.state["ids"]["node_four"]}
        require(all(row.get("node_id") in entries and row.get("server_id") == self.state["ids"]["server_A"]
                    for row in records if row.get("user_id") in owned_users), "ledger_not_entry_only")

    def scenario_atomic_replay(self):
        body = self.state["requests"]["create-chains"]["body"]
        replay = batch_receipt(self.panel.request(ORDERED_BATCH, "POST", body, expected=(200,)), body)
        require(replay == self.state["initial_batch_receipt"], "batch_replay_ids_changed")
        changed = json.loads(canonical(body))
        changed["items"][0]["name"] += "-changed"
        self.panel.request(ORDERED_BATCH, "POST", changed, expected=(409,))
        before = self.panel.request(PLUGIN + "/nodes")
        bad = self.state["requests"].get("invalid-batch", {}).get("body")
        if bad is None:
            bad = json.loads(canonical(body))
            bad["request_id"] = str(uuid.uuid4())
            for index, item in enumerate(bad["items"]):
                item["name"] += "-rollback"
                item["entry"] = {"mode": "new", "server_id": self.state["ids"]["server_A"],
                                  "public_host": self.manifest["roles"]["A"]["address"],
                                  "sni": self.manifest["roles"]["A"]["sni"], "port": 20111 + index}
            bad["items"][1]["hops"][0] = {"kind": "managed", "node_id": 0}
        self.request_once("invalid-batch", ORDERED_BATCH, "POST", bad, statuses=(400,))
        after = self.panel.request(PLUGIN + "/nodes")
        require({item["id"] for item in before} == {item["id"] for item in after}, "atomic_batch_left_nodes")
        self.credentials_unchanged()

    def scenario_source_versions(self):
        require(not self.state.get("source_replaced"), "replacement_already_completed_requires_new_run")
        initial = self.source_version()
        resources = {which: self.applied(which) for which in ("three", "four")}
        before = {which: item["path_state"]["applied_generation"] for which, item in resources.items()}
        pinned_version = next(hop["node_version_id"] for hop in resources["four"]["hops"] if hop["kind"] == "subscription")
        self.patch_source("v3" if self.state.get("source_fixture_version") == "v2" else "v2")
        latest = self.source_version()
        require(latest["id"] == initial["id"] and latest["identity_epoch"] == initial["identity_epoch"]
                and latest["version_id"] != initial["version_id"], "same_identity_version_not_preserved")
        followed = self.applied("three", before["three"] + 1)
        pinned = self.applied("four")
        external = lambda item: next(hop for hop in item["hops"] if hop["kind"] == "subscription")
        require(external(followed)["node_version_id"] == latest["version_id"]
                and external(pinned)["node_version_id"] == pinned_version
                and pinned["path_state"]["applied_generation"] == before["four"], "follow_pinned_conflated")
        body = {"request_id": str(uuid.uuid4()), "settings_revision": pinned["settings_revision"],
                "generation": pinned["path_state"]["desired_generation"],
                "versions": [{"hop_position": external(pinned)["position"], "node_version_id": latest["version_id"]}]}
        identifier = resource_id(pinned["id"])
        uuid_id(latest["version_id"])
        receipt = self.request_once("apply-version-" + body["request_id"],
                                    ORDERED_RESOURCES + f"/chain/{identifier}/apply-node-versions", "POST", body)
        require(isinstance(receipt, dict) and uuid_id(receipt.get("request_id")) == body["request_id"]
                and receipt.get("kind") == "chain" and resource_id(receipt.get("id")) == identifier
                and resource_id(receipt.get("settings_revision")) == body["settings_revision"] + 1
                and resource_id(receipt.get("generation")) > body["generation"],
                "apply_version_receipt_changed")
        self.applied("four", before["four"] + 1)
        source_id = self.state["ids"]["source"]
        source = self.source()
        bad = {"request_id": str(uuid.uuid4()), "settings_revision": source["settings_revision"],
               "input": {"kind": "inline", "content": "<html>TEST_ONLY invalid subscription</html>", "identity_action": "update"}}
        receipt = self.request_once("invalid-source-" + bad["request_id"], ORDERED_SOURCES + f"/{source_id}", "PATCH", bad)
        self.source_failure(receipt, source)
        self.patch_source("v3", "replace")
        replaced = self.source_version()
        require(replaced["identity_epoch"] != latest["identity_epoch"], "source_replacement_epoch_unchanged")
        for which in ("three", "four"):
            kept = self.applied(which)
            require(external(kept)["identity_epoch"] == latest["identity_epoch"], "replacement_rebound_path")
            self.traffic(which)
        # Replacement is a distinct source. Later candidate checks use a fresh
        # TEST_ONLY source, without crossing an applied identity epoch.
        self.state["source_replaced"] = True
        self.save()
        self.real_proofs("source-versions")

    def scenario_candidate_failure(self):
        require(not self.state.get("source_replaced"), "candidate_scenario_requires_original_epoch")
        before = self.applied("three")
        old_generation = before["path_state"]["applied_generation"]
        self.patch_source("bad")
        failed = self.wait("candidate_failure", lambda: self.resource("three"),
                           lambda item: item["path_state"]["phase"] == "failed", permit_failure=True)
        require(failed["path_state"]["applied_generation"] == old_generation
                and failed["path_state"]["last_error"], "failed_candidate_lost_old_generation")
        self.traffic("three")
        self.traffic("four")
        self.evidence("candidate-failure")
        self.patch_source("v3")
        self.applied("three", old_generation + 1)
        self.real_proofs("candidate-restored")

    def scenario_dependency_offline(self):
        require(not self.state.get("source_replaced"), "offline_scenario_requires_original_epoch")
        before = self.applied("three")
        generation = before["path_state"]["applied_generation"]
        configurations = {which: self.subscription(which) for which in ("three", "four")}
        self.control.call("agent_stop", "B")
        try:
            source = "v3" if self.state.get("source_fixture_version") == "v2" else "v2"
            self.patch_source(source)
            latest = self.source_version()
            self.state["offline_last_version"] = latest["version_id"]
            self.save()
            pending = self.wait("offline_candidate", lambda: self.resource("three"),
                                lambda item: item["path_state"]["candidate_generation"] is not None)
            time.sleep(self.deadline.remaining(8))
            pending = self.resource("three")
            require(pending["path_state"]["applied_generation"] == generation
                    and pending["path_state"]["candidate_generation"] is not None
                    and pending["path_state"]["phase"] != "failed", "offline_dependency_not_waiting")
            self.traffic_config("three", configurations["three"])
            self.traffic_config("four", configurations["four"])
            self.evidence("dependency-offline")
        finally:
            self.control.call("agent_start", "B")
        self.applied("three", generation + 1)
        self.real_proofs("dependency-restored")

    def uninterrupted_fault(self, name, stop_operation, start_operation, role=None, seconds=12):
        which = "four"
        before_usage = self.quiet_usage()
        before = self.control.call("device_snapshot", role or "A")
        client, _ = self.fixtures.client(self.subscription(which), name, 35)
        start = time.monotonic()
        self.control.call(stop_operation, role)
        try:
            time.sleep(self.deadline.remaining(seconds))
            during = self.control.call("device_snapshot", role or "A")
            write_json(self.directory / (name + "-during-device.json"), during)
            if stop_operation == "panel_stop":
                require(during.get("usage", {}).get("pending_batches", 0) > 0
                        and during.get("usage", {}).get("pending_bytes", 0) > 0,
                        "disconnect_did_not_exercise_usage_outbox")
        finally:
            self.control.call(start_operation, role)
        result = self.fixtures.client_result(client)
        assert_traffic(result)
        require(time.monotonic() - start >= seconds, "fault_duration_missing")
        self.applied("three")
        self.applied("four")
        after = self.control.call("device_snapshot", role or "A")
        require(before.get("device_public_key") == after.get("device_public_key"), "fault_changed_device_identity")
        require(before.get("runtime", {}).get("pid") == after.get("runtime", {}).get("pid")
                and before.get("runtime", {}).get("starttime") == after.get("runtime", {}).get("starttime"),
                "constant_service_restarted_with_control_plane")
        totals = self.quiet_usage()
        require(int(totals[which]) > int(before_usage[which]), "fault_traffic_not_uploaded")
        once = totals
        time.sleep(self.deadline.remaining(5))
        require(self.quiet_usage() == once, "usage_replay_counted_twice")
        write_json(self.directory / (name + "-traffic.json"), result)
        facts, _ = self.real_proofs(name)
        if stop_operation == "panel_stop":
            counters = during["usage"]["counters"]
            records = facts.get("usage", {}).get("records", [])
            require(counters and all(any(str(row["seq"]) == str(counter["seq"])
                                        and row["epoch"] == counter["epoch"]
                                        and digest(f"u{row['user_id']}_n{row['node_id']}".encode()) == counter["stat_name_sha256"]
                                        and str(row["uplink"]) == str(counter["uplink"])
                                        and str(row["downlink"]) == str(counter["downlink"])
                                        for row in records) for counter in counters),
                    "offline_usage_identity_not_persisted")

    def scenario_agent_restart(self):
        self.uninterrupted_fault("agent-restart", "agent_stop", "agent_start", "A")
        self.control.call("agent_restart", "M")
        self.applied("four")
        self.traffic("four")
        self.real_proofs("internal-agent-restart")

    def scenario_panel_disconnect(self):
        self.uninterrupted_fault("panel-disconnect", "panel_stop", "panel_start", seconds=20)

    def scenario_runtime_restart(self):
        evidence, devices = self.real_proofs("runtime-before")
        previous = devices["M"]["runtime"]
        self.control.call("runtime_restart", "M")
        current = self.wait("runtime_new_instance", lambda: self.control.call("device_snapshot", "M"),
                            lambda item: item.get("runtime", {}).get("active") is True
                            and (item["runtime"].get("pid"), item["runtime"].get("starttime"))
                            != (previous.get("pid"), previous.get("starttime")))
        require(current["device_public_key"] == devices["M"]["device_public_key"], "runtime_restart_changed_identity")
        self.applied("four")
        self.traffic("four")
        after, _ = self.real_proofs("runtime-after")
        chain_id = self.state["ids"]["chain_four"]
        generation = self.resource("four")["path_state"]["applied_generation"]
        probes = lambda value: [item for item in value["path_probes"]
                                if item["chain_id"] == chain_id and item["generation"] == generation
                                and item["stage"] == "switched"]
        require(probes(after)[0]["request_id"] != probes(evidence)[0]["request_id"]
                and probes(after)[0]["dependency_vector"] != probes(evidence)[0]["dependency_vector"],
                "runtime_restart_reused_old_vector_proof")
        original = {item["request_id"]: item for item in evidence["receipts"]}
        kept = {item["request_id"]: item for item in after["receipts"]}
        require(all(kept.get(identifier) == value for identifier, value in original.items()), "old_receipt_relabelled")

    def scenario_external_failure(self):
        self.fixtures.target_events()
        self.fixtures.service("stop_x")
        try:
            client, _ = self.fixtures.client(self.subscription("four"), "external-failure", 1)
            result = self.fixtures.client_result(client)
            assert_all_traffic_failed(result)
            require(not self.fixtures.target_events(), "target_reached_without_external_hop")
            for role in ("A", "M", "B"):
                snapshot = self.control.call("device_snapshot", role)
                require(snapshot["agent"]["active"] is True and snapshot["runtime"]["active"] is True,
                        "external_failure_dragged_managed_service")
            write_json(self.directory / "external-failure-traffic.json", result)
        finally:
            self.fixtures.service("start_x")
        self.traffic("four")
        self.real_proofs("external-restored")

    def scenario_authorization(self):
        user = self.state["ids"]["user_four"]
        stale = self.subscription("four")
        self.panel.request(PLUGIN + f"/users/{user}/policy-groups", "PUT", {"group_ids": []})
        self.wait("authorization_removed", lambda: self.panel.request(PLUGIN + f"/users/{user}/subscription?format=singbox"),
                  lambda item: item.get("status") in ("empty", "blocked") and item.get("content") is None)
        self.subscription("four", blocked=True)
        self.wait("revocation_deployment", lambda: self.panel.request(PLUGIN + f"/servers/{self.state['ids']['server_A']}/deployments"),
                  lambda item: item.get("pending") is False and item.get("status", {}).get("healthy") is True)
        client, _ = self.fixtures.client(stale, "revoked-client", 1)
        result = self.fixtures.client_result(client)
        assert_all_traffic_failed(result)
        self.panel.request(PLUGIN + f"/users/{user}/policy-groups", "PUT",
                           {"group_ids": [self.state["ids"]["policy_four"]]})
        self.applied("four")
        self.traffic("four")
        self.real_proofs("reauthorized")

    def scenario_retirement(self):
        ids = self.state["ids"]
        self.panel.request(ORDERED_RESOURCES + f"/direct/{ids['node_B']}", "DELETE", expected=(409,))
        self.panel.request(ORDERED_RESOURCES + f"/chain/{ids['chain_three']}", "DELETE", expected=(409,))
        source = self.source()
        self.panel.request(ORDERED_SOURCES + f"/{ids['source']}", "DELETE",
                           {"settings_revision": source["settings_revision"]}, expected=(409,))
        before = self.quiet_usage()
        for which in ("three", "four"):
            self.panel.request(PLUGIN + f"/users/{ids['user_' + which]}/policy-groups", "PUT", {"group_ids": []})
            self.panel.request(PLUGIN + f"/policy-groups/{ids['policy_' + which]}", "DELETE", expected=(204,))
            self.panel.request(ORDERED_RESOURCES + f"/chain/{ids['chain_' + which]}", "DELETE", expected=(204,))
        evidence = self.wait("paths_retired", lambda: self.control.call("panel_evidence", arguments={"owned_ids": self.owned()}),
                             lambda item: len([chain for chain in item.get("chains", []) if chain.get("phase") == "retired"]) == 2)
        require(isinstance(evidence.get("current_dependencies"), list)
                and not any(row.get("chain_id") in self.owned()["chains"] for row in evidence["current_dependencies"]),
                "retired_dependencies_not_confirmed_absent")
        for which in ("three", "four"):
            self.subscription(which, blocked=True)
        request = self.state["requests"]["create-chains"]["body"]
        replay = batch_receipt(self.panel.request(ORDERED_BATCH, "POST", request), request)
        require(replay == self.state["initial_batch_receipt"], "deleted_receipt_recreated_resources")
        resources = self.panel.request(ORDERED_RESOURCES)
        require(not any(item["kind"] == "chain" and item["id"] in self.owned()["chains"] for item in resources),
                "receipt_replay_revived_deleted_path")
        for role in ("M", "B"):
            node = self.panel.request(PLUGIN + f"/nodes/{ids['node_' + role]}")
            require(node["enabled"] is True, "shared_internal_node_deleted")
            snapshot = self.control.call("device_snapshot", role)
            require(snapshot["runtime"]["active"] is True, "shared_internal_runtime_stopped")
        require(self.quiet_usage() == before, "retirement_erased_or_recounted_history")
        self.credentials_unchanged()
        self.state["retired"] = True
        self.save()

    def run(self):
        failed = None
        active_scenario = None
        try:
            require(sys.platform.startswith("linux") and os.geteuid() == 0, "dedicated_linux_root_required")
            require(not self.state.get("retired"), "completed_retired_run_requires_new_environment")
            self.setup()
            for scenario in self.scenarios:
                active_scenario = scenario
                started = time.monotonic()
                self.results[scenario] = {"status": "running"}
                write_json(self.directory / "scenario-results.json", self.results)
                self.evidence(scenario + "-before")
                getattr(self, "scenario_" + scenario.replace("-", "_"))()
                self.evidence(scenario + "-after")
                self.results[scenario] = {"status": "passed", "elapsed_ms": int((time.monotonic() - started) * 1000)}
                write_json(self.directory / "scenario-results.json", self.results)
        except Exception as error:
            failed = str(error) if isinstance(error, Rejected) else "unexpected_driver_failure"
            if active_scenario is not None:
                self.results[active_scenario] = {"status": "failed", "failure_code": failed}
                write_json(self.directory / "scenario-results.json", self.results)
            self.event("acceptance_failed", code=failed)
            if self.environment_owned:
                with contextlib.suppress(Exception):
                    self.evidence("failure")
        finally:
            if self.environment_owned:
                try:
                    self.control.call("restore_all", cleanup=True)
                except Exception:
                    self.cleanup_errors.append("restore_all")
            try:
                self.fixtures.stop()
            except Exception:
                self.cleanup_errors.append("fixtures")
            if self.environment_owned:
                try:
                    facts = self.control.call("cleanup", cleanup=True)
                    write_json(self.directory / "cleanup.json", facts)
                    require(facts.get("product_units_stopped") is True
                            and facts.get("pid_and_cgroup_cleanup_confirmed") is True
                            and facts.get("databases_and_evidence_retained") is True,
                            "controller_cleanup_unconfirmed")
                except Exception:
                    self.cleanup_errors.append("controller")
        registered = len(self.state.get("device_keys", {})) == 3 and len(set(self.state.get("device_keys", {}).values())) == 3
        complete = failed is None and not self.cleanup_errors and registered and self.environment_owned \
            and self.accounting_verified \
            and set(self.results) == set(SCENARIOS) and all(item["status"] == "passed" for item in self.results.values())
        receipt = {"schema": 1, "test_only": True, "run_id": self.manifest["run_id"],
                   "source_identity": self.manifest["source_identity"], "manifest_sha256": digest(canonical(self.manifest)),
                   "status": "passed_registered_managed_paths" if complete else "passed_selected_scenarios" if failed is None and not self.cleanup_errors else "failed",
                   "full_matrix": complete, "registered_agents": registered,
                   "client_execution_namespace": "driver_host",
                   "selected_scenarios": list(self.scenarios), "results": self.results,
                   "failure_code": failed, "cleanup_errors": self.cleanup_errors,
                   "native_ledger_reconciliation": "verified" if self.accounting_verified else "not_verified",
                   "ttl_expiry": "not_verified",
                   "signal_cancellation": "verified_cleanup" if CANCELLED and not self.cleanup_errors and self.environment_owned else "not_verified",
                   "formal_release": False, "full_nodequality": False}
        write_json(self.directory / "receipt.json", receipt)
        return receipt


def main():
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-manifest", type=Path, required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, action="append")
    arguments = parser.parse_args()
    selected = tuple(dict.fromkeys(arguments.scenario or SCENARIOS))
    # A failed candidate must be exercised before replacing the source epoch.
    selected = tuple(sorted(selected, key=lambda name: (name == "retirement", name == "source-versions", SCENARIOS.index(name))))
    try:
        result = Driver(read_json(arguments.prepared_manifest), selected).run()
    except Exception as error:
        code = str(error) if isinstance(error, Rejected) else "prepared_environment_invalid"
        print(json.dumps({"status": "rejected", "code": code}), flush=True)
        return 1
    print(json.dumps({key: result[key] for key in ("status", "full_matrix", "failure_code", "cleanup_errors")}), flush=True)
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
