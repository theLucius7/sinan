#!/usr/bin/env python3
"""Collect bounded, allowlisted evidence from this run's disposable fixtures."""

import argparse
import decimal
import errno
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time


PHASES = {"first-traffic", "resumed-traffic"}
DIRECTIONS = {"download", "upload"}
KINDS = {"none", "dns", "connect", "timeout", "tls", "tls_verify", "http", "empty_reply",
         "send", "receive", "proxy", "curl", "signal", "launch", "payload", "not_configured", "other"}
CURL_ERRORS = {6: "dns", 7: "connect", 22: "http", 28: "timeout", 35: "tls", 52: "empty_reply",
               55: "send", 56: "receive", 60: "tls_verify", 97: "proxy"}
NUMBERS = {"curl_exit": 255, "http_status": 599, "download_bytes": 2 ** 63 - 1,
           "upload_bytes": 2 ** 63 - 1, "connect_ms": 90000,
           "local_dns_ms": 90000, "pretransfer_ms": 90000,
           "first_byte_ms": 90000, "elapsed_ms": 100000}
LEGACY_METRICS = "http_status download_bytes upload_bytes connect_ms first_byte_ms elapsed_ms".split()
METRICS = "http_status download_bytes upload_bytes local_dns_ms connect_ms pretransfer_ms first_byte_ms elapsed_ms".split()
STAGES = {"completed", "receiving_response", "request_or_response", "proxy_or_transport", "before_proxy_connect", "unknown"}
EVIDENCE_NAME = "traffic-evidence.json"
REQUEST_SECONDS = 90
PROCESS_GUARD_SECONDS = 92
TRAFFIC_POLICY = {
    "target_scope": "owned_loopback",
    "request_ms": REQUEST_SECONDS * 1000,
    "process_guard_ms": PROCESS_GUARD_SECONDS * 1000,
    "failure_probe_network_ms": 7000,
    "download_bytes": 2 * 1024 * 1024,
    "upload_bytes": 1024 * 1024,
    "retries": 0,
}
TIMEOUT_SOURCES = {"curl_deadline", "process_guard"}


def integer(value, maximum):
    return value if type(value) is int and 0 <= value <= maximum else None


def safe_record(value, transfer=False):
    """Revalidate even locally generated JSON before it becomes a public artifact."""
    if not isinstance(value, dict):
        return {}
    result = {key: integer(value[key], maximum) for key, maximum in NUMBERS.items() if key in value}
    if isinstance(value.get("error_kind"), str) and value["error_kind"] in KINDS:
        result["error_kind"] = value["error_kind"]
    if type(value.get("passed")) is bool:
        result["passed"] = value["passed"]
    if transfer:
        if (not isinstance(value.get("phase"), str) or value["phase"] not in PHASES
                or not isinstance(value.get("direction"), str) or value["direction"] not in DIRECTIONS):
            return {}
        result.update(phase=value["phase"], direction=value["direction"])
        result.pop("passed", None)
        if type(value.get("curl_succeeded")) is bool:
            result["curl_succeeded"] = value["curl_succeeded"]
        if isinstance(value.get("reached_stage"), str) and value["reached_stage"] in STAGES:
            result["reached_stage"] = value["reached_stage"]
        if (result.get("curl_exit") == 28 and result.get("error_kind") == "timeout"
                and isinstance(value.get("timeout_source"), str)
                and value["timeout_source"] in TIMEOUT_SOURCES):
            result["timeout_source"] = value["timeout_source"]
    return result


def safe_summary(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    policy = value.get("policy")
    if (isinstance(policy, dict) and all(type(policy.get(key)) is type(expected)
                                       and policy[key] == expected
                                       for key, expected in TRAFFIC_POLICY.items())):
        result["policy"] = dict(TRAFFIC_POLICY)
    if isinstance(value.get("transfers"), list):
        records = [safe_record(record, True) for record in value["transfers"][:4]]
        result["transfers"] = [record for record in records if record]
    failure = value.get("failure")
    if isinstance(failure, dict):
        result["failure"] = {
            key: safe_record(failure[key]) for key in
            ("http_tcp", "client_tcp", "runtime_tcp", "fixture_http", "fixture_tls") if key in failure
        }
        for key in ("client_present", "http_fixture_present"):
            if type(failure.get(key)) is bool:
                result["failure"][key] = failure[key]
        resources = failure.get("host")
        if isinstance(resources, dict):
            result["failure"]["host"] = {
                key: integer(resources[key], maximum) for key, maximum in
                (("cpu_count", 65536), ("load1_milli", 2 ** 31 - 1), ("mem_available_kib", 2 ** 63 - 1))
                if key in resources
            }
    return result


def load(path):
    try:
        if path.is_symlink() or path.stat().st_size > 16384:
            return {}
        return safe_summary(json.loads(path.read_text()))
    except (OSError, ValueError, RecursionError):
        return {}


def save(path, value):
    if path.is_symlink():
        raise OSError("evidence symlink refused")
    temporary = path.with_suffix(".next")
    # Scratch is created by the acceptance script with umask 077.
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(json.dumps(safe_summary(value)) + "\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def curl_metrics(output):
    if not isinstance(output, str) or len(output) > 256:
        return {}
    values = output.split()
    fields = METRICS if len(values) == len(METRICS) else LEGACY_METRICS
    if len(values) != len(fields):
        return {}
    result = {}
    for index, (key, value) in enumerate(zip(fields, values)):
        if not re.fullmatch(r"[0-9]{1,20}(?:\.[0-9]{1,6})?", value):
            continue
        number = decimal.Decimal(value)
        if index >= 3:
            number *= 1000
        if number != number.to_integral_value() and index < 3:
            continue
        result[key] = integer(int(number), NUMBERS[key])
    return result


def reached_stage(record, status):
    """Describe observations, never attribute a stall to an unobserved remote hop."""
    if status == 0:
        return "completed"
    if ((record.get("first_byte_ms") or 0) > 0
            or (record.get("http_status") or 0) >= 100
            or (record.get("download_bytes") or 0) > 0):
        return "receiving_response"
    if (record.get("pretransfer_ms") or 0) > 0:
        return "request_or_response"
    if (record.get("connect_ms") or 0) > 0:
        return "proxy_or_transport"
    if record.get("connect_ms") == 0 and record.get("elapsed_ms", 0) > 0:
        return "before_proxy_connect"
    return "unknown"


def transfer(scratch, phase, direction):
    # All endpoints and curl options are fixed; no config, environment, or body is emitted.
    output = scratch / ("download.bin" if direction == "download" else "upload-response.txt")
    command = ["curl", "--fail", "--silent", "--max-time", str(REQUEST_SECONDS), "--noproxy", "",
               "--proxy", "socks5h://127.0.0.1:2080"]
    if direction == "upload":
        command += ["-X", "POST", "--data-binary", "@" + str(scratch / "upload.bin")]
    command += ["http://127.0.0.1:18081/" + direction, "-o", str(output), "--write-out",
                "%{http_code} %{size_download} %{size_upload} %{time_namelookup} %{time_connect} %{time_pretransfer} "
                "%{time_starttransfer} %{time_total}\n"]
    started = time.monotonic()
    try:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, timeout=PROCESS_GUARD_SECONDS, check=False)
        status = process.returncode if 0 <= process.returncode <= 255 else (
            128 - process.returncode if -127 <= process.returncode < 0 else 1)
        record = curl_metrics(process.stdout)
        kind = "signal" if process.returncode < 0 else ("none" if status == 0 else CURL_ERRORS.get(status, "curl"))
        if status == 28:
            record["timeout_source"] = "curl_deadline"
    except subprocess.TimeoutExpired:
        status, record, kind = 28, {"timeout_source": "process_guard"}, "timeout"
    except OSError:
        status, record, kind = 127, {}, "launch"
    record.update(phase=phase, direction=direction, curl_exit=status, error_kind=kind,
                  curl_succeeded=status == 0, reached_stage=reached_stage(record, status))
    record.setdefault("elapsed_ms", min(100000, int((time.monotonic() - started) * 1000)))
    path = scratch / EVIDENCE_NAME
    evidence = load(path)
    evidence["policy"] = dict(TRAFFIC_POLICY)
    evidence["transfers"] = [item for item in evidence.get("transfers", [])
                             if (item["phase"], item["direction"]) != (phase, direction)] + [record]
    try:
        save(path, evidence)
    except OSError:
        print("Traffic evidence write failed; transfer status is preserved.", file=sys.stderr)
    if status:
        print(f"Fixture proxy {direction} failed: curl_exit={status} error_kind={kind}.", file=sys.stderr)
    return status


def error_kind(error):
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(error, ssl.SSLCertVerificationError):
        return "tls_verify"
    if isinstance(error, ssl.SSLError):
        return "tls"
    if isinstance(error, OSError) and error.errno in (errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH):
        return "connect"
    return "other"


def probe(action):
    started = time.monotonic()
    try:
        result = action()
        result.setdefault("error_kind", "none")
        result.setdefault("passed", True)
    except (OSError, ValueError, http.client.HTTPException) as error:
        result = {"passed": False, "error_kind": error_kind(error)}
    result["elapsed_ms"] = min(100000, int((time.monotonic() - started) * 1000))
    return safe_record(result)


def tcp_probe(port):
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        return {}


class DeadlineReader(io.RawIOBase):
    """Recheck a single deadline before every socket read, including header reads."""

    def __init__(self, stream, deadline):
        super().__init__()
        self.stream = stream
        self.deadline = deadline
        self.source = stream.makefile("rb", buffering=0)

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.stream.settimeout(remaining)
        return self.source.readinto(buffer)

    def close(self):
        try:
            self.source.close()
        finally:
            super().close()


class DeadlineSocket:
    def __init__(self, stream, deadline):
        self.stream = stream
        self.deadline = deadline

    def makefile(self, mode):
        if mode != "rb":
            raise ValueError()
        return io.BufferedReader(DeadlineReader(self.stream, self.deadline))


def http_probe(port=18081):
    deadline = time.monotonic() + 2
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    connection.response_class = lambda stream, **options: http.client.HTTPResponse(
        DeadlineSocket(stream, deadline), **options)
    try:
        connection.connect()
        stream = connection.sock
        stream.settimeout(max(0.001, deadline - time.monotonic()))
        connection.request("GET", "/download")
        stream.settimeout(max(0.001, deadline - time.monotonic()))
        response = connection.getresponse()
        count = 0
        while count <= 2 * 1024 * 1024:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            stream.settimeout(remaining)
            chunk = response.read(min(65536, 2 * 1024 * 1024 + 1 - count))
            count += len(chunk)
            if not chunk:
                break
        passed = response.status == 200 and count == 2 * 1024 * 1024
        return {"http_status": response.status, "download_bytes": count, "passed": passed,
                "error_kind": "none" if passed else ("http" if response.status != 200 else "payload")}
    finally:
        connection.close()


def bounded_http_probe(scratch):
    # HTTPResponse may perform repeated recv calls despite a socket timeout.
    # A single owned worker gives slow-drip headers and bodies a hard deadline.
    command = [sys.executable, str(Path(__file__).resolve()), "--scratch", str(scratch), "probe-http"]
    try:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, timeout=2, check=False)
        if process.returncode == 0 and len(process.stdout) <= 512:
            result = safe_record(json.loads(process.stdout))
            if type(result.get("passed")) is bool:
                return result
    except subprocess.TimeoutExpired:
        # subprocess.run kills and reaps its own worker before raising.
        return {"passed": False, "error_kind": "timeout"}
    except (OSError, ValueError, RecursionError):
        pass
    return {"passed": False, "error_kind": "other"}


def tls_probe(address, certificate, port=443):
    deadline = time.monotonic() + 2
    context = ssl.create_default_context(cafile=str(certificate))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve("X25519")
    with socket.create_connection((address, port), timeout=max(0.001, deadline - time.monotonic())) as stream:
        stream.settimeout(max(0.001, deadline - time.monotonic()))
        with context.wrap_socket(stream, server_hostname="sinan-e2e.example.test"):
            return {}


def fixture_address(scratch):
    path = scratch / "tls-network.json"
    if path.is_symlink() or path.stat().st_size > 4096:
        raise ValueError()
    networks = json.loads(path.read_text())
    if not isinstance(networks, dict) or len(networks) != 1:
        raise ValueError()
    address = ipaddress.ip_address(next(iter(networks.values()))["IPAddress"])
    bridge_ranges = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                     ipaddress.ip_network("192.168.0.0/16"))
    if address.version != 4 or not any(address in network for network in bridge_ranges):
        raise ValueError()
    return str(address)


def present(pid):
    if pid <= 0:
        return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return None


def host_resources():
    result = {"cpu_count": os.cpu_count()}
    try:
        result["load1_milli"] = int(os.getloadavg()[0] * 1000)
    except OSError:
        pass
    try:
        with Path("/proc/meminfo").open() as source:
            text = source.read(16384)
        values = re.findall(r"^MemAvailable: +([0-9]{1,20}) kB$", text, re.MULTILINE)
        if len(values) == 1:
            result["mem_available_kib"] = int(values[0])
    except OSError:
        pass
    return result


def failure(scratch, client_pid, fixture_pid):
    evidence = load(scratch / EVIDENCE_NAME)
    result = {"client_present": present(client_pid), "http_fixture_present": present(fixture_pid),
              "host": host_resources()}
    for name, port in (("http_tcp", 18081), ("client_tcp", 2080), ("runtime_tcp", 443)):
        result[name] = probe(lambda: tcp_probe(port))
    result["fixture_http"] = probe(lambda: bounded_http_probe(scratch))
    try:
        address = fixture_address(scratch)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        result["fixture_tls"] = {"passed": False, "error_kind": "not_configured"}
    else:
        result["fixture_tls"] = probe(lambda: tls_probe(address, scratch / "camouflage.crt"))
    evidence["failure"] = result
    save(scratch / EVIDENCE_NAME, evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    transfer_command = commands.add_parser("transfer")
    transfer_command.add_argument("--phase", choices=sorted(PHASES), required=True)
    transfer_command.add_argument("--direction", choices=sorted(DIRECTIONS), required=True)
    failure_command = commands.add_parser("failure")
    failure_command.add_argument("--client-pid", type=int, default=0)
    failure_command.add_argument("--fixture-pid", type=int, default=0)
    commands.add_parser("probe-http")
    arguments = parser.parse_args()
    if arguments.command == "transfer":
        return transfer(arguments.scratch, arguments.phase, arguments.direction)
    if arguments.command == "probe-http":
        print(json.dumps(probe(http_probe)))
        return 0
    failure(arguments.scratch, arguments.client_pid, arguments.fixture_pid)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError):
        print("Fixture evidence unavailable.", file=sys.stderr)
        sys.exit(1)
