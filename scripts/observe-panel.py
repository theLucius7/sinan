#!/usr/bin/env python3
"""Submit independently observed panel availability using a scoped API token."""
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, stream, code, message, headers, new_url):
        return None


def main():
    parser = argparse.ArgumentParser(description="Submit an independent panel HTTP observation")
    parser.add_argument("--panel-origin", required=True)
    parser.add_argument("--observer-name", required=True)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()
    origin = args.panel_origin.rstrip("/")
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        parser.error("panel origin must be an HTTPS origin without credentials or path")
    if not 1 <= args.timeout <= 60 or not 1 <= len(args.observer_name) <= 200:
        parser.error("invalid timeout or observer name")
    token = os.environ.get("SINAN_OBSERVER_API_TOKEN", "")
    if not token.startswith("sinan_api_") or not 32 <= len(token) <= 512 or not all(character.isascii() and (character.isalnum() or character in "-_") for character in token):
        parser.error("SINAN_OBSERVER_API_TOKEN must contain a monitoring:write scoped management token")
    opener = urllib.request.build_opener(NoRedirect())
    started = time.monotonic()
    available = None
    evidence = {"probe": "HTTPS GET /healthz", "tls_verification": True}
    try:
        request = urllib.request.Request(origin + "/healthz", headers={"User-Agent": "Sinan-Independent-Observer/1"})
        with opener.open(request, timeout=args.timeout) as response:
            payload = response.read(1024)
            available = response.status == 200 and payload.strip() == b"ok"
            evidence["http_status"] = response.status
            evidence["expected_body_matched"] = payload.strip() == b"ok"
    except urllib.error.HTTPError as exc:
        available = False
        evidence["http_status"] = exc.code
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError):
        available = False
        evidence["failure"] = "HTTPS request failed or timed out"
    report = {"observer_name": args.observer_name, "target_origin": origin,
              "observed_at": int(time.time()), "available": available,
              "elapsed_ms": int((time.monotonic() - started) * 1000), "evidence": evidence}
    body = json.dumps(report, ensure_ascii=False).encode()
    request = urllib.request.Request(origin + "/api/control-center/observers", data=body,
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json"}, method="POST")
    try:
        with opener.open(request, timeout=args.timeout) as response:
            receipt = json.loads(response.read(8192))
        print(json.dumps({"observation": report, "receipt": receipt}, ensure_ascii=False))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        print(json.dumps({"observation": report, "delivery": "failed", "retry_policy": "retain observation locally; no fabricated receipt"}, ensure_ascii=False))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
