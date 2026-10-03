#!/usr/bin/python3
"""Offline workbench entrypoint. Supply this executable and its signed manifest.
No downloads, shell, rank uploads, disk devices, or host configuration changes.
"""
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, urljoin

VERSION = "1.0.0"
LIMIT = 64 * 1024
TOOLS = {"route": None, "mtr": "mtr", "throughput": "iperf3", "cpu": "sysbench",
         "memory": "sysbench", "disk": "fio", "stability": "stress-ng", "speedtest": "speedtest",
         "icmp": "ping", "quic": "curl", "hardware_info": "smartctl"}
KINDS = set(TOOLS) | {"tcp", "http", "dns", "tls", "udp", "web_socket", "exit", "mail"}
PROCESS = None
MANIFEST = {}
EXECUTION = {}
WORKSPACE = None
CREATED = []
FILE_FDS = []
LATENCY_SAMPLES = []
IDLE_LATENCY = []
CANCELLED = False


def require(condition, message):
    if not condition:
        raise ValueError(message)


def atomic(path, value):
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    require(len(encoded) <= LIMIT, "structured report exceeds 64 KiB")
    descriptor = os.open(str(path) + ".new", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(path) + ".new", path)
    except BaseException:
        try:
            os.unlink(str(path) + ".new")
        except FileNotFoundError:
            pass
        raise


def section(name, text, complete, revision=1):
    atomic(WORKSPACE / (name + ".json"), {"name": name, "text": json.dumps(text, ensure_ascii=False),
           "complete": complete, "revision": revision, "collected_at": int(time.time())})


def deadline(*_):
    stop()
    raise TimeoutError("workbench duration budget exceeded")


def stop(*_):
    global CANCELLED
    CANCELLED = True
    if PROCESS is not None and PROCESS.poll() is None:
        try:
            os.killpg(PROCESS.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def tool_name(check):
    return check.get("tool") if check["kind"] == "route" else TOOLS.get(check["kind"])


def supplied_tool(name, expected_version=None):
    item = MANIFEST.get("tools", {}).get(name)
    require(isinstance(item, dict) and item.get("licensed") is True,
            "tool license or offline inventory missing: " + name)
    require(item.get("license") and item.get("source_url", "").startswith("https://"),
            "tool license and source evidence required")
    path = Path(item["path"])
    require(path.is_absolute() and path.is_file(), "offline tool is not installed")
    require(path.stat().st_mode & 0o022 == 0, "tool is writable by other accounts")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    require(digest.hexdigest() == item.get("sha256"), "tool does not match signed manifest")
    require(not expected_version or item.get("version") == expected_version, "tool version differs")
    flag = "-V" if name == "ping" else "--version"
    version = subprocess.run([str(path), flag], capture_output=True, timeout=3, check=True)
    require(hashlib.sha256(version.stdout + version.stderr).hexdigest() == item.get("version_output_sha256"), "tool runtime identity differs from signed inventory")
    return str(path)


def family(check):
    require(check.get("family") in ("ipv4", "ipv6"), "address family required")
    return socket.AF_INET if check["family"] == "ipv4" else socket.AF_INET6


def addresses(host, port, check, socktype=socket.SOCK_STREAM):
    results = socket.getaddrinfo(host, port, family(check), socktype)
    require(results, "selected family has no address")
    return [item[4] for item in results]


def target():
    require(isinstance(EXECUTION.get("target"), dict), "authorized target snapshot missing")
    value = EXECUTION["target"]
    require(value.get("authorization"), "target authorization missing")
    require(not value.get("authorized_until") or value["authorized_until"] > time.time(), "target authorization expired")
    return value["host"]


def current_resources():
    memory = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            name, value = line.split(":", 1)
            memory[name] = int(value.split()[0]) * 1024
    except (FileNotFoundError, ValueError):
        pass
    return {"memory_available": memory.get("MemAvailable"), "load_one": os.getloadavg()[0],
            "cpu_count": os.cpu_count(), "frequency_khz": read_optional("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"),
            "temperature": read_optional("/sys/class/thermal/thermal_zone0/temp")}


def read_optional(path):
    try:
        return Path(path).read_text().strip()[:128]
    except OSError:
        return None


def resource_protection():
    data = current_resources()
    require(data["memory_available"] is None or data["memory_available"] >= 128 * 1024 * 1024,
            "business protection: available memory below reserve")
    require(data["load_one"] <= max(data["cpu_count"] or 1, 1) * 1.5,
            "business protection: system load above reserve")
    for pid in MANIFEST.get("protected_processes", []):
        require(isinstance(pid, int) and pid > 0, "invalid protected process identity")
        require(Path("/proc") .joinpath(str(pid)).exists(), "business protection: protected process exited")
    return data


def command(args, seconds):
    global PROCESS
    resource_protection()
    log = tempfile.TemporaryFile(dir=WORKSPACE)
    snapshots = []
    try:
        PROCESS = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                   start_new_session=True, pass_fds=tuple(FILE_FDS), env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        deadline = time.monotonic() + seconds
        while PROCESS.poll() is None:
            if EXECUTION["check"].get("latency_target") and len(LATENCY_SAMPLES) < 32:
                LATENCY_SAMPLES.append(latency(EXECUTION["check"]))
            require(not CANCELLED, "cancellation requested")
            require(time.monotonic() < deadline, "tool timeout")
            require(os.fstat(log.fileno()).st_size <= LIMIT // 2, "tool output exceeds controlled limit")
            snapshots.append(resource_protection())
            snapshots = snapshots[-32:]
            time.sleep(0.25)
        log.seek(0)
        text = log.read(LIMIT // 2).decode("utf-8", errors="replace")
        return PROCESS.returncode, text, snapshots
    finally:
        if PROCESS is not None and PROCESS.poll() is None:
            os.killpg(PROCESS.pid, signal.SIGTERM)
            try:
                PROCESS.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(PROCESS.pid, signal.SIGKILL)
                PROCESS.wait(timeout=2)
        PROCESS = None
        log.close()


def dns_name(value):
    value = value.rstrip(".")
    require(len(value) <= 253, "DNS name too long")
    labels = value.encode("idna").split(b".")
    require(all(0 < len(v) <= 63 for v in labels), "invalid DNS label")
    return b"".join(bytes([len(v)]) + v for v in labels) + b"\0"


def decode_name(packet, offset, depth=0):
    require(depth < 16, "DNS compression recursion")
    labels = []
    while True:
        require(offset < len(packet), "truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        if length & 0xc0 == 0xc0:
            require(offset < len(packet), "truncated DNS pointer")
            pointer = ((length & 0x3f) << 8) | packet[offset]
            suffix, _ = decode_name(packet, pointer, depth + 1)
            labels.append(suffix)
            return ".".join(labels), offset + 1
        require(length <= 63 and offset + length <= len(packet), "truncated DNS label")
        labels.append(packet[offset:offset + length].decode("ascii", "replace"))
        offset += length


def receive_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        require(not CANCELLED, "cancellation requested")
        value = sock.recv(length - len(data))
        require(value, "connection closed during protocol response")
        data.extend(value)
    return bytes(data)


def dns_query(name, resolver, record_type):
    types = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
    require(record_type in types, "unsupported DNS record type")
    transaction = secrets.randbelow(65536)
    payload = struct.pack("!HHHHHH", transaction, 0x100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", types[record_type], 1)
    resolver_ip = ipaddress.ip_address(resolver)
    started = time.monotonic()
    with socket.socket(socket.AF_INET if resolver_ip.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.connect((resolver, 53))
        sock.send(payload)
        packet = sock.recv(4096)
    require(len(packet) >= 12, "truncated DNS response")
    ident, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", packet[:12])
    require(ident == transaction and flags & 0x8000, "DNS response identity mismatch")
    transport = "udp"
    if flags & 0x200:
        transport = "tcp_fallback"
        with socket.socket(socket.AF_INET if resolver_ip.version == 4 else socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((resolver, 53))
            sock.sendall(struct.pack("!H", len(payload)) + payload)
            header = receive_exact(sock, 2)
            size = struct.unpack("!H", header)[0]
            require(12 <= size <= 4096, "DNS TCP response exceeds budget")
            packet = receive_exact(sock, size)
        ident, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", packet[:12])
        require(ident == transaction and flags & 0x8000 and not flags & 0x200, "DNS TCP response invalid")
    offset = 12
    for _ in range(questions):
        _, offset = decode_name(packet, offset)
        offset += 4
    records = []
    for _ in range(min(answers, 64)):
        owner, offset = decode_name(packet, offset)
        require(offset + 10 <= len(packet), "truncated DNS RR")
        rrtype, _, ttl, length = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        data = packet[offset:offset + length]
        require(len(data) == length, "truncated DNS RR data")
        if rrtype == 1 and length == 4:
            value = str(ipaddress.IPv4Address(data))
        elif rrtype == 28 and length == 16:
            value = str(ipaddress.IPv6Address(data))
        elif rrtype in (2, 5, 12):
            value, _ = decode_name(packet, offset)
        elif rrtype == 15 and length >= 3:
            host, _ = decode_name(packet, offset + 2)
            value = str(struct.unpack("!H", data[:2])[0]) + " " + host
        elif rrtype == 16:
            position, chunks = 0, []
            while position < len(data):
                chunk_size = data[position]
                chunks.append(data[position + 1:position + 1 + chunk_size].decode("utf-8", "replace"))
                position += chunk_size + 1
            value = "".join(chunks)
        else:
            value = data.hex()
        records.append({"name": owner, "type": rrtype, "ttl": ttl, "value": value})
        offset += length
    return {"resolver": resolver, "rcode": flags & 0xf, "records": records,
            "response_ms": (time.monotonic() - started) * 1000, "transport": transport}


def tcp(check):
    endpoint = addresses(target(), check["port"], check)[0]
    samples = []
    for _ in range(check["samples"]):
        require(not CANCELLED, "cancellation requested")
        started = time.monotonic()
        try:
            with socket.socket(family(check)) as sock:
                sock.settimeout(3)
                sock.connect(endpoint)
            samples.append({"connected": True, "elapsed_ms": (time.monotonic() - started) * 1000})
        except OSError as error:
            samples.append({"connected": False, "failure": str(error)})
    return {"address": endpoint[0], "port": endpoint[1], "samples": samples}, "", all(s["connected"] for s in samples)


def http_request(check, url, websocket=False):
    parsed = urlsplit(url)
    require(parsed.hostname == (EXECUTION.get("target") or {}).get("host", parsed.hostname), "URL leaves authorized target")
    require(not parsed.username and not parsed.password and not parsed.fragment, "URL contains forbidden credentials")
    secure = parsed.scheme in ("https", "wss")
    require(parsed.scheme in ("http", "https", "ws", "wss"), "unsupported URL scheme")
    port = parsed.port or (443 if secure else 80)
    timings = {}
    started = time.monotonic()
    endpoint = addresses(parsed.hostname, port, check)[0]
    timings["dns_ms"] = (time.monotonic() - started) * 1000
    proxy = urlsplit(check["proxy_url"]) if check.get("route_kind") == "proxy_chain" and check.get("proxy_url") else None
    if proxy:
        require(proxy.scheme == "http" and ipaddress.ip_address(proxy.hostname).is_loopback() and proxy.port and not proxy.username and not proxy.password, "only explicitly configured local HTTP CONNECT proxy is supported")
        proxy_family = socket.AF_INET if ipaddress.ip_address(proxy.hostname).version == 4 else socket.AF_INET6
        sock = socket.socket(proxy_family)
    else:
        sock = socket.socket(family(check))
    sock.settimeout(5)
    try:
        phase = time.monotonic()
        sock.connect((proxy.hostname, proxy.port) if proxy else endpoint)
        timings["connect_ms"] = (time.monotonic() - phase) * 1000
        if proxy:
            destination = ("[" + endpoint[0] + "]" if ":" in endpoint[0] else endpoint[0]) + ":" + str(port)
            sock.sendall(("CONNECT " + destination + " HTTP/1.1\r\nHost: " + destination + "\r\n\r\n").encode("ascii"))
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                require(len(headers) < 4096, "proxy CONNECT headers exceed limit")
                headers.extend(receive_exact(sock, 1))
            require(re.match(br"HTTP/1\.[01] 200(?: |\r)", headers), "local proxy CONNECT rejected")
            timings["proxy_connect_ms"] = (time.monotonic() - phase) * 1000
        if secure:
            phase = time.monotonic()
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
            timings["tls_ms"] = (time.monotonic() - phase) * 1000
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        headers = "Host: " + parsed.netloc + "\r\nUser-Agent: Sinan-Workbench/" + VERSION + "\r\n"
        if websocket:
            headers += "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n"
        else:
            headers += "Connection: close\r\n"
        phase = time.monotonic()
        sock.sendall(("GET " + path + " HTTP/1.1\r\n" + headers + "\r\n").encode("ascii"))
        first = sock.recv(1)
        timings["first_byte_ms"] = (time.monotonic() - phase) * 1000
        require(first, "HTTP peer closed before response")
        response = http.client.HTTPResponse(_PrefixedSocket(sock, first))
        response.begin()
        if websocket:
            expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            valid = response.status == 101 and response.getheader("Sec-WebSocket-Accept") == expected and response.getheader("Upgrade", "").lower() == "websocket"
            result = {"status_code": response.status, "handshake_valid": valid, "held_secs": 0, "disconnect_reason": None, "timings": timings}
            if valid:
                hold_start = time.monotonic()
                sock.settimeout(1)
                while time.monotonic() - hold_start < check["hold_secs"] and not CANCELLED:
                    try:
                        frame = sock.recv(1)
                        if not frame:
                            result["disconnect_reason"] = "peer_closed"
                            break
                        frame += receive_exact(sock, 1)
                        opcode, length = frame[0] & 15, frame[1] & 127
                        if length == 126:
                            length = struct.unpack("!H", receive_exact(sock, 2))[0]
                        elif length == 127:
                            length = struct.unpack("!Q", receive_exact(sock, 8))[0]
                        require(length <= 4096, "WebSocket frame exceeds budget")
                        require(not frame[1] & 128, "server WebSocket frame must not be masked")
                        payload = receive_exact(sock, length)
                        if opcode == 8:
                            result["disconnect_reason"] = "websocket_close_frame"
                            result["close_code"] = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
                            break
                        if opcode == 9:
                            require(len(payload) <= 125, "WebSocket ping exceeds control-frame limit")
                            mask = secrets.token_bytes(4)
                            masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
                            sock.sendall(bytes([0x8a, 0x80 | len(payload)]) + mask + masked)
                    except socket.timeout:
                        pass
                result["held_secs"] = round(time.monotonic() - hold_start, 3)
            return result, "", valid and result["disconnect_reason"] is None
        body = response.read(LIMIT // 4 + 1)
        require(len(body) <= LIMIT // 4, "HTTP body exceeds controlled limit")
        raw = body.decode("utf-8", "replace")
        return {"status_code": response.status, "location": response.getheader("Location"), "timings": timings,
                "content_match": check.get("expected_content") is None or check["expected_content"] in raw}, raw, response.status == check.get("expected_status", 200)
    finally:
        sock.close()


class _PrefixedSocket:
    def __init__(self, sock, first):
        self.sock, self.first = sock, first
    def makefile(self, mode):
        import io
        return io.BufferedReader(_PrefixedReader(self.sock.makefile("rb", buffering=0), self.first), buffer_size=1)


class _PrefixedReader(__import__("io").RawIOBase):
    def __init__(self, stream, first):
        self.stream, self.first = stream, first
    def readable(self):
        return True
    def readinto(self, buffer):
        if self.first:
            buffer[0:1] = self.first
            self.first = b""
            return 1
        return self.stream.readinto(buffer)


def tls(check):
    endpoint = addresses(target(), check["port"], check)[0]
    started = time.monotonic()
    with socket.socket(family(check)) as sock:
        sock.settimeout(5)
        sock.connect(endpoint)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=check["server_name"]) as wrapped:
            cert = wrapped.getpeercert()
            return {"domain_match": True, "trust_chain_valid": True, "certificate": cert,
                    "expires_at": int(ssl.cert_time_to_seconds(cert["notAfter"])), "handshake_ms": (time.monotonic() - started) * 1000,
                    "protocol": wrapped.version(), "cipher": wrapped.cipher(), "chain_details_available": hasattr(wrapped, "get_verified_chain"), "verified_chain": [base64.b64encode(value).decode() for value in wrapped.get_verified_chain()] if hasattr(wrapped, "get_verified_chain") else None}, "", True


def udp(check):
    require(check["protocol"] in ("dns", "echo", "custom_authorized"), "QUIC requires a supplied protocol-aware tool")
    payload, expected = bytes.fromhex(check["request_hex"]), bytes.fromhex(check["expected_hex"])
    require(0 < len(payload) <= 1200 and 0 < len(expected) <= 1200, "valid UDP request and expectation required")
    if check["protocol"] == "dns":
        require(len(payload) >= 12 and not struct.unpack("!H", payload[2:4])[0] & 0x8000 and struct.unpack("!H", payload[4:6])[0] > 0, "DNS service request must be a valid query")
    endpoint = addresses(target(), check["port"], check, socket.SOCK_DGRAM)[0]
    started = time.monotonic()
    try:
        with socket.socket(family(check), socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect(endpoint)
            sock.send(payload)
            result = sock.recv(4096)
        valid = result.startswith(expected)
        if check["protocol"] == "dns":
            valid = valid and len(result) >= 12 and result[:2] == payload[:2] and bool(struct.unpack("!H", result[2:4])[0] & 0x8000)
        elif check["protocol"] == "echo":
            valid = valid and result == payload
        return {"outcome": "valid_response" if valid else "unexpected_response",
                "response_hex": result.hex(), "elapsed_ms": (time.monotonic() - started) * 1000}, "", valid
    except socket.timeout:
        return {"outcome": "unknown", "reason": "no_response_is_not_evidence_of_closed_port"}, "", False


def path_report(text, tool):
    try:
        value = json.loads(text)
    except ValueError:
        value = {"machine_readable": False}
    hops = []
    source = value.get("report", {}).get("hubs", []) if tool == "mtr" else value.get("TraceMap", value.get("hops", []))
    if tool == "traceroute" and not source:
        for line in text.splitlines():
            match = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if match:
                responders = []
                for token in match[2].split():
                    try:
                        responders.append(str(ipaddress.ip_address(token.strip("()"))))
                    except ValueError:
                        pass
                hops.append({"hop": int(match[1]), "ip": responders[0] if responders else None,
                             "responders": sorted(set(responders)), "raw": line, "asn": None,
                             "reverse_dns": None, "geolocation": None, "metadata_source": "traceroute_output", "position_is_estimate": True})
    elif isinstance(source, list):
        for index, hop in enumerate(source[:64]):
            samples = hop if isinstance(hop, list) else [hop]
            first = next((sample for sample in samples if isinstance(sample, dict)), {})
            responders = []
            for sample in samples:
                if isinstance(sample, dict):
                    address = sample.get("host", sample.get("ip", sample.get("IP")))
                    try:
                        responders.append(str(ipaddress.ip_address(address)))
                    except (ValueError, TypeError):
                        pass
            geo = None
            latitude, longitude = first.get("latitude"), first.get("longitude")
            if isinstance(latitude, (int, float)) and isinstance(longitude, (int, float)) and -90 <= latitude <= 90 and -180 <= longitude <= 180:
                geo = {"latitude": latitude, "longitude": longitude, "source": tool, "is_estimate": True}
            hops.append({"hop": index + 1, "raw": hop, "ip": responders[0] if responders else None,
                         "responders": sorted(set(responders)), "asn": first.get("asn", first.get("ASN")),
                         "reverse_dns": first.get("hostname", first.get("Hostname")), "geolocation": geo,
                         "metadata_source": tool + "_output", "position_is_estimate": True})
    return {"tool_output": value, "hops": hops, "external_as_path": None, "direction": EXECUTION["role"], "unanswered_hops_are_not_path_loss": True}


def latency(check):
    started = time.monotonic()
    try:
        endpoint = addresses(check["latency_target"], 443, check)[0]
        with socket.socket(family(check)) as sock:
            sock.settimeout(0.5)
            sock.connect(endpoint)
        return {"method": "tcp_connect", "target": check["latency_target"], "port": 443, "elapsed_ms": (time.monotonic() - started) * 1000, "connected": True}
    except OSError as error:
        return {"method": "tcp_connect", "connected": False, "error": str(error)}


def external(check):
    name = tool_name(check)
    program = supplied_tool(name, check.get("tool_version"))
    kind = check["kind"]
    maximum = EXECUTION["budget"]["duration_secs"]
    if kind == "quic":
        require(urlsplit(check["url"]).hostname == target(), "QUIC URL leaves authorized target")
        args = [program, "--http3-only", "--silent", "--show-error", "--max-time", str(maximum), "--max-filesize", "16384", "--output", "/dev/null", "--write-out", "%{json}", "-4" if family(check) == socket.AF_INET else "-6", check["url"]]
    elif kind == "hardware_info":
        require(check["device"] in MANIFEST.get("allowed_health_devices", []), "hardware-health device is not explicitly authorized")
        args = [program, "--json", "--all", check["device"]]
    elif kind == "icmp":
        args = [program, "-4" if family(check) == socket.AF_INET else "-6", "-n", "-c", str(check["samples"]), "-s", str(check["packet_bytes"]), "-W", "2", "--", target()]
    elif kind == "route":
        host = target()
        if name == "nexttrace":
            args = [program, "--json", "--ipv4" if family(check) == socket.AF_INET else "--ipv6", "--max-hops", str(check["max_hops"]), "--port", str(check["port"])]
            if check["protocol"] != "icmp":
                args += ["--" + check["protocol"]]
            args += [host]
        else:
            args = [program, "-4" if family(check) == socket.AF_INET else "-6", "-n", "-m", str(check["max_hops"]), "-w", "1", "-q", "1"]
            args += ["-I"] if check["protocol"] == "icmp" else (["-T"] if check["protocol"] == "tcp" else [])
            args += ["-p", str(check["port"]), host]
    elif kind == "mtr":
        args = [program, "--json", "--report", "--report-cycles", str(check["samples"]), "--no-dns", "--port", str(check["port"]), "-4" if family(check) == socket.AF_INET else "-6"]
        if check["protocol"] != "icmp":
            args += ["--" + check["protocol"]]
        args += [target()]
    elif kind == "throughput":
        if EXECUTION["role"].startswith("listener:"):
            args = [program, "--server", "--one-off", "--json", "--bind", check["receiver_host"], "--port", str(check["port"]), "--idle-timeout", str(maximum)]
            return listener(args, check, maximum)
        args = [program, "--client", check["receiver_host"], "--port", str(check["port"]), "--json", "--time", str(check["duration_secs"]), "--parallel", str(check["streams"]), "--bitrate", str(check["rate_bps"]), "--connect-timeout", "3000", "-4" if family(check) == socket.AF_INET else "-6"]
        if check["direction"] == "reverse":
            args += ["--reverse"]
        if check["direction"] == "bidirectional":
            args += ["--bidir"]
        if check["protocol"] == "udp":
            args += ["--udp"]
    elif kind == "cpu":
        args = [program, "cpu", "--threads=" + str(check["threads"]), "--time=" + str(check["duration_secs"]), "run"]
    elif kind == "memory":
        args = [program, "memory", "--memory-block-size=" + str(check["block_bytes"]), "--memory-total-size=" + str(check["total_bytes"]), "--memory-oper=" + check["operation"], "--time=" + str(maximum), "run"]
    elif kind == "disk":
        directory = Path(check["directory"])
        require(directory.resolve() == directory and directory.is_dir(), "disk directory must be canonical existing directory")
        allowed = [Path(p).resolve() for p in MANIFEST.get("allowed_test_directories", [])]
        require(any(directory == p or p in directory.parents for p in allowed), "disk test outside configured allowlist")
        free = os.statvfs(directory).f_bavail * os.statvfs(directory).f_frsize
        require(free > check["file_bytes"] + 2 * 1024 * 1024 * 1024, "disk reserve insufficient")
        descriptor, filename = tempfile.mkstemp(prefix="sinan-fio-", dir=directory)
        os.ftruncate(descriptor, check["file_bytes"])
        os.unlink(filename)
        FILE_FDS.append(descriptor)
        CREATED.append(Path(filename))
        args = [program, "--name=sinan-acceptance", "--filename=/proc/self/fd/" + str(descriptor), "--size=" + str(check["file_bytes"]), "--bs=" + str(check["block_bytes"]), "--iodepth=" + str(check["queue_depth"]), "--rw=" + check["mode"], "--rwmixread=" + str(check["read_percent"]), "--runtime=" + str(check["duration_secs"]), "--time_based", "--direct=1", "--ioengine=libaio", "--output-format=json", "--group_reporting"]
    elif kind == "stability":
        args = [program, "--timeout", str(check["duration_secs"]) + "s", "--metrics-brief"]
        if check["cpu_workers"]:
            args += ["--cpu", str(check["cpu_workers"])]
        if check["memory_bytes"]:
            args += ["--vm", "1", "--vm-bytes", str(check["memory_bytes"])]
        if check["io_workers"]:
            args += ["--io", str(check["io_workers"])]
    elif kind == "speedtest":
        require(check["license_acknowledged"] is True, "Speedtest terms not acknowledged")
        args = [program, "--format=json", "--accept-license", "--accept-gdpr"]
        if check.get("server_id"):
            args += ["--server-id=" + str(check["server_id"])]
    else:
        raise ValueError("unsupported fixed tool")
    if kind == "throughput" and check.get("latency_target"):
        IDLE_LATENCY.extend(latency(check) for _ in range(3))
    code, raw, samples = command(args, maximum)
    if kind == "icmp":
        loss = re.search(r"([\d.]+)% packet loss", raw)
        values = re.search(r"(?:rtt|round-trip)[^=]*= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", raw)
        data = {"packet_loss_percent": float(loss[1]) if loss else None, "samples": check["samples"], "packet_bytes": check["packet_bytes"], "rtt_min_avg_max_deviation_ms": [float(v) for v in values.groups()] if values else None}
    elif kind in ("route", "mtr"):
        data = path_report(raw, name)
    else:
        try:
            data = {"tool_output": json.loads(raw)}
        except ValueError:
            data = {"machine_readable": False}
        if kind == "throughput":
            client, server = EXECUTION["source_label"], "服务器 " + str(check["receiver_server"])
            flows = ([{"sender": client, "receiver": server}] if check["direction"] == "forward" else
                     [{"sender": server, "receiver": client}] if check["direction"] == "reverse" else
                     [{"sender": client, "receiver": server}, {"sender": server, "receiver": client}])
            data.update({"sender": flows[0]["sender"] if len(flows) == 1 else None,
                         "receiver": flows[0]["receiver"] if len(flows) == 1 else None,
                         "flows": flows, "direction": check["direction"], "streams": check["streams"],
                         "latency_under_load_available": bool(check.get("latency_target")),
                         "idle_latency": IDLE_LATENCY, "load_latency": LATENCY_SAMPLES,
                         "flow_budget_bytes": EXECUTION["budget"]["traffic_bytes"]})
    if kind == "quic":
        data["protocol_request"] = "HTTP/3 GET over QUIC; no HTTP/2 fallback"
        data["handshake_valid"] = code == 0 and data.get("tool_output", {}).get("http_version") == "3"
        code = 0 if data["handshake_valid"] and data["tool_output"].get("response_code") == check["expected_status"] else 1
    if kind == "cpu":
        value = re.search(r"events per second:\s*([\d.]+)", raw)
        data["events_per_second"] = float(value[1]) if value else None
        data["threads"] = check["threads"]
    if kind == "memory":
        value = re.search(r"([\d.]+) MiB/sec", raw)
        data["throughput_mib_per_second"] = float(value[1]) if value else None
    data["resource_samples"] = samples
    data["effective_arguments"] = args[1:]
    return data, raw, code == 0


def listener(args, check, maximum):
    global PROCESS
    log = tempfile.TemporaryFile(dir=WORKSPACE)
    try:
        PROCESS = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        deadline = time.monotonic() + maximum
        ready = False
        while PROCESS.poll() is None:
            require(not CANCELLED and time.monotonic() < deadline, "listener cancellation or deadline")
            resource_protection()
            # Kernel listening table avoids using a readiness connection that consumes one-off iperf.
            owned = set()
            for descriptor in Path("/proc").joinpath(str(PROCESS.pid), "fd").iterdir():
                try:
                    linked = os.readlink(descriptor)
                    if linked.startswith("socket:["):
                        owned.add(linked[8:-1])
                except OSError:
                    pass
            for path in ("/proc/net/tcp", "/proc/net/tcp6"):
                for line in Path(path).read_text().splitlines()[1:]:
                    fields = line.split()
                    if fields[3] == "0A" and fields[9] in owned and int(fields[1].split(":")[1], 16) == check["port"]:
                        ready = True
            if ready:
                section("workbench_scope", {"execution": EXECUTION, "listener_ready": True,
                        "port": check["port"], "protocol": check["protocol"], "readiness_source": "kernel_listener_table"}, True, 2)
                break
            time.sleep(0.25)
        require(ready, "temporary listener never became ready")
        while PROCESS.poll() is None:
            require(not CANCELLED and time.monotonic() < deadline, "listener cancellation or deadline")
            require(os.fstat(log.fileno()).st_size <= LIMIT // 2, "listener output exceeds limit")
            resource_protection()
            time.sleep(0.25)
        log.seek(0)
        raw = log.read(LIMIT // 2).decode("utf-8", "replace")
        return {"listener_ready": ready, "direction": check["direction"], "tool_output": json.loads(raw), "effective_arguments": args[1:]}, raw, PROCESS.returncode == 0
    finally:
        if PROCESS is not None and PROCESS.poll() is None:
            os.killpg(PROCESS.pid, signal.SIGKILL)
            PROCESS.wait(timeout=2)
        PROCESS = None
        log.close()


def perform(check):
    kind = check["kind"]
    if kind in TOOLS:
        return external(check)
    if kind == "tcp":
        return tcp(check)
    if kind == "tls":
        return tls(check)
    if kind == "udp":
        return udp(check)
    if kind == "web_socket":
        return http_request(check, check["url"], True)
    if kind == "http":
        url, redirects = check["url"], []
        for _ in range(6):
            data, raw, ok = http_request(check, url)
            if check["follow_redirects"] and 300 <= data["status_code"] < 400 and data["location"]:
                url = urljoin(url, data["location"])
                require(urlsplit(url).hostname == target(), "redirect leaves authorized target")
                redirects.append(url)
                continue
            data["redirects"] = redirects
            return data, raw, ok and data["content_match"]
        raise ValueError("redirect limit exceeded")
    if kind == "dns":
        results = []
        for resolver in check["resolvers"]:
            try:
                result = dns_query(target(), resolver, check["record_type"])
                result["expected_match"] = all(v in [r["value"] for r in result["records"]] for v in check["expected"])
                results.append(result)
            except (OSError, ValueError) as error:
                results.append({"resolver": resolver, "status": "unknown", "error": str(error)})
        return {"sources": results, "record_type": check["record_type"]}, "", all(r.get("rcode") == 0 and r.get("expected_match") for r in results)
    if kind == "exit":
        data, raw, ok = http_request(dict(check, expected_status=200), check["discovery_url"])
        try:
            address = str(ipaddress.ip_address(raw.strip()))
        except ValueError:
            value = json.loads(raw)
            address = str(ipaddress.ip_address(value.get("ip", value.get("address", ""))))
        require(ipaddress.ip_address(address).version == (4 if check["family"] == "ipv4" else 6), "exit family differs")
        return {"address": address, "family": check["family"], "route_kind": check["route_kind"], "discovery_source": urlsplit(check["discovery_url"]).hostname,
                "proxy_applied": check["route_kind"] == "proxy_chain", "timings": data["timings"]}, "", ok
    if kind == "mail":
        results = []
        for resolver in check["resolvers"]:
            for name, rr in [(check["domain"], "MX"), (check["domain"], "TXT"), ("_dmarc." + check["domain"], "TXT"), (check["selector"] + "._domainkey." + check["domain"], "TXT")]:
                try:
                    results.append(dict(dns_query(name, resolver, rr), queried_name=name, record_type=rr))
                except (OSError, ValueError) as error:
                    results.append({"queried_name": name, "status": "unknown", "error": str(error)})
        ports = [dict(tcp(dict(check, port=port, samples=1))[0], service_port=port) for port in check["ports"]]
        endpoints = addresses(target(), check["ports"][0], check)
        for endpoint in endpoints[:4]:
            try:
                ptr = dns_query(ipaddress.ip_address(endpoint[0]).reverse_pointer, check["resolvers"][0], "PTR")
                results.append(dict(ptr, record_type="PTR", queried_address=endpoint[0]))
            except (OSError, ValueError) as error:
                results.append({"record_type": "PTR", "status": "unknown", "error": str(error)})
        return {"dns_evidence": results, "ports": ports, "spf_dkim_dmarc_semantics": "raw_configuration_evidence_requires_review"}, "", True
    raise ValueError("unsupported or gated check")


def preflight(execution):
    require(execution.get("schema") == 1 and isinstance(execution.get("check"), dict), "invalid execution schema")
    check, budget = execution["check"], execution["budget"]
    require(check.get("kind") in KINDS, "unregistered check; NodeQuality full execution remains gated")
    require(1 <= budget["duration_secs"] <= 3600 and 16 * 1024 * 1024 <= budget["memory_bytes"] <= 1024 * 1024 * 1024,
            "invalid resource budget")
    require(1 <= budget.get("cpu_percent", 20) <= 80 and 1 <= budget.get("cpu_weight", 20) <= 100,
            "invalid CPU hard cap or contention weight")
    if execution.get("target"):
        target()
    if tool_name(check):
        program = supplied_tool(tool_name(check), check.get("tool_version"))
        if check["kind"] == "quic":
            version = subprocess.run([program, "--version"], capture_output=True, timeout=2, check=True)
            require(b"HTTP3" in version.stdout, "QUIC unavailable: curl was built without HTTP3")
    if check["kind"] == "throughput":
        multiplier = 2 if check["direction"] == "bidirectional" else 1
        require(check["rate_bps"] * check["duration_secs"] * check["streams"] * multiplier // 8 <= budget["traffic_bytes"], "throughput traffic budget exceeded")
        require(check["rate_bps"] <= budget["rate_bps"] and 1 <= check["streams"] <= 8, "throughput rate or parallel budget exceeded")
        require(check["port"] >= 1024, "temporary listener must use unprivileged port")
    if check["kind"] == "speedtest":
        require(check["license_acknowledged"] is True, "Speedtest terms not acknowledged")
        raise ValueError("Speedtest cannot enforce an exact traffic budget; execute externally under license and import")
    if check["kind"] == "exit":
        require(check["route_kind"] == "nat_public" or check.get("proxy_url"), "proxy-chain exit requires explicitly selected local HTTP CONNECT proxy")
    resource_protection()


def main():
    global EXECUTION, WORKSPACE, MANIFEST
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--input")
    parser.add_argument("--workspace")
    parser.add_argument("--manifest")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    if args.version:
        print("sinan-network-workbench " + VERSION)
        return 0
    EXECUTION = json.loads(Path(args.input).read_text())
    MANIFEST = json.loads(Path(args.manifest).read_text())
    require(MANIFEST.get("schema") == 1 and MANIFEST.get("engine_version") == VERSION, "signed manifest version mismatch")
    interpreter = MANIFEST.get("interpreter", {})
    require(interpreter.get("path") == "/usr/bin/python3" and hashlib.sha256(Path("/usr/bin/python3").read_bytes()).hexdigest() == interpreter.get("sha256"), "host Python interpreter differs from signed inventory")
    preflight(EXECUTION)
    if args.preflight:
        print(json.dumps({"ready": True, "version": VERSION, "resources": current_resources()}))
        return 0
    WORKSPACE = Path(args.workspace)
    require(WORKSPACE.resolve() == WORKSPACE and WORKSPACE.is_dir(), "workspace must be canonical private directory")
    require(WORKSPACE.stat().st_mode & 0o077 == 0, "workspace is not private")
    require(not (WORKSPACE / "result.json").exists(), "completed execution cannot rerun")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(EXECUTION["budget"]["duration_secs"])
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT * 4, LIMIT * 4))
    section("workbench_scope", {"execution": EXECUTION, "listener_ready": False}, True)
    check = EXECUTION["check"]
    report = {"schema": 1, "source": EXECUTION["source_label"], "target": (EXECUTION.get("target") or {}).get("host", check.get("receiver_host", "")),
              "method": check["kind"], "tool": tool_name(check) or "sinan-network-workbench", "tool_version": check.get("tool_version", MANIFEST.get("tools", {}).get(tool_name(check), {}).get("version", VERSION)),
              "parameters": check, "collected_at": int(time.time()), "status": "failed", "data": {}, "raw_output": "", "error": None,
              "cleanup": {"process_stopped": False, "files_removed": False, "listeners_closed": False}}
    try:
        data, raw, ok = perform(check)
        report.update(data=data, raw_output=raw, status="succeeded" if ok else "failed")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = str(error)[:4096]
    finally:
        signal.alarm(0)
        if CANCELLED:
            report["status"] = "failed"
            report["error"] = report["error"] or "cancellation requested"
        for descriptor in FILE_FDS:
            os.close(descriptor)
        for path in CREATED:
            path.unlink(missing_ok=True)
        report["cleanup"] = {"process_stopped": PROCESS is None, "files_removed": all(not p.exists() for p in CREATED), "listeners_closed": PROCESS is None}
        report["data"]["environment"] = {"resources": current_resources(), "protected_processes_configured": bool(MANIFEST.get("protected_processes")), "kernel": os.uname().release,
                                                 "hardware_health": {"available": False, "reason": "设备健康资料需独立只读采集能力"}}
        atomic(WORKSPACE / "result.json", report)
        section("workbench_result", report, True)
    return 0 if report["status"] == "succeeded" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=__import__("sys").stderr)
        raise SystemExit(2)
