#!/usr/bin/env python3
"""Reject proxy business references in core while preserving native account APIs.

Two cores are checked: the Agent core (`crates/agent-core`) and the panel host
(`crates/panel-host`). Crate manifests are also checked so that plugins depend
on the host and never the reverse.
"""
import argparse
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {"user", "users", "subscription", "subscriptions", "quota", "quotas"}
TOKENS = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
CAMEL_PARTS = re.compile(r"_|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# Exact operating-system/SQLite API spellings, scoped to their existing callers.
# Mask only these expressions: a forbidden reference on the same line still fails.
EXCEPTIONS = {
    "src/system/windows.rs": (
        r"\[Security\.Principal\.WindowsIdentity\]::GetCurrent\(\)\.User\b",
    ),
    "src/system/deploy/native/windows.rs": (
        r"\[Security\.Principal\.WindowsIdentity\]::GetCurrent\(\)\.User\b",
        r"\b(?:Get|New|Set|Enable)-LocalUser\b",
        r"(?<![\w-])-(?:UserMayNotChangePassword|UserId|User)\b",
        r"\bUSER_RIGHTS\b",
    ),
    "src/system/deploy/native/unix.rs": (
        r'(?<=")/Users(?=/|")',
        r'"UserShell"',
        r"<key>UserName</key>",
    ),
    "tests/usage.rs": (r"\bPRAGMA user_version\b",),
    "tests/usage_bounds.rs": (
        r"\bPRAGMA user_version\b",
        r'\.pragma_update\(None, "user_version",',
    ),
}

# Panel host: HTTP and Windows API spellings plus URL userinfo test fixtures.
HOST_EXCEPTIONS = {
    "src/config.rs": (r'"https://user:secret@example\.invalid"',),
    "src/diagnostics/tests.rs": (r'"https://user:secret@nodequality\.com/r/x"',),
    "src/exchange/fetch.rs": (r"\.user_agent\(",),
    "src/installation/windows.rs": (
        r"\[Security\.Principal\.WindowsIdentity\]::GetCurrent\(\)\.User\b",
        r"\.DefaultRequestHeaders\.UserAgent\b",
    ),
    "src/ip_quality/providers/tests.rs": (r'contains_key\("user-agent"\)',),
    "src/releases/network.rs": (r"\.user_agent\(", r'"https://user@github\.com/"'),
}

CORES = {
    "crates/agent-core": EXCEPTIONS,
    "crates/panel-host": HOST_EXCEPTIONS,
}

# Workspace crates each layer may depend on (all dependency tables).
AGENT_CORE_DEPENDENCIES = {"sinan-adapter-sdk", "sinan-protocol"}
ADAPTER_DEPENDENCIES = {"sinan-adapter-sdk"}
HOST_DEPENDENCIES = {"sinan-protocol"}
PLUGIN_DEPENDENCIES = {"sinan-panel-host", "sinan-protocol", "sinan-compiler", "sinan-cloud-api"}


def violations(relative, source, exceptions=None):
    exceptions = EXCEPTIONS if exceptions is None else exceptions
    findings = []
    for number, line in enumerate(source.splitlines(), 1):
        if re.search(r"singbox|sing-box", line, re.IGNORECASE):
            findings.append((number, "runtime name"))
        for expression in exceptions.get(relative, ()):
            line = re.sub(expression, "", line)
        for token in TOKENS.findall(line):
            parts = {part.lower() for part in CAMEL_PARTS.split(token)}
            banned = sorted(parts & FORBIDDEN)
            if banned:
                findings.append((number, "/".join(banned)))
    return findings


def check(directory, exceptions=None):
    failed = False
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            print(f"{path}: symlinks are not allowed in core", file=sys.stderr)
            failed = True
        elif path.is_file():
            relative = path.relative_to(directory).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
            except UnicodeError:
                print(f"{path}: unreadable core source", file=sys.stderr)
                failed = True
                continue
            for line, reason in violations(relative, source, exceptions):
                print(f"{path}:{line}: forbidden core reference: {reason}", file=sys.stderr)
                failed = True
    return not failed


def workspace_dependencies(manifest):
    """Returns every `sinan-*` crate named in any dependency table."""
    data = tomllib.loads(manifest)
    tables = [data.get(key, {}) for key in ("dependencies", "dev-dependencies", "build-dependencies")]
    for target in data.get("target", {}).values():
        tables += [target.get(key, {}) for key in ("dependencies", "dev-dependencies", "build-dependencies")]
    return {name for table in tables for name in table if name.startswith("sinan-")}


def layer_rules(root):
    """Maps each layered manifest to the workspace crates it may depend on."""
    rules = {root / "crates/agent-core/Cargo.toml": AGENT_CORE_DEPENDENCIES}
    for manifest in sorted(root.glob("crates/adapter-*/Cargo.toml")):
        if manifest.parent.name != "adapter-sdk":
            rules[manifest] = ADAPTER_DEPENDENCIES
    rules[root / "crates/panel-host/Cargo.toml"] = HOST_DEPENDENCIES
    for manifest in sorted(root.glob("plugins/*/panel/Cargo.toml")):
        rules[manifest] = PLUGIN_DEPENDENCIES
    return rules


def check_dependencies(root):
    failed = False
    for manifest, allowed in layer_rules(root).items():
        if not manifest.is_file():
            print(f"{manifest}: layered manifest is missing", file=sys.stderr)
            failed = True
            continue
        for name in sorted(workspace_dependencies(manifest.read_text(encoding="utf-8")) - allowed):
            print(f"{manifest}: forbidden workspace dependency: {name}", file=sys.stderr)
            failed = True
    return not failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, help="check only this core directory")
    args = parser.parse_args()
    if args.core is not None:
        if not args.core.is_dir():
            parser.error("core directory is missing")
        relative = args.core.resolve().relative_to(ROOT).as_posix() if args.core.resolve().is_relative_to(ROOT) else ""
        return 0 if check(args.core, CORES.get(relative, EXCEPTIONS)) else 1
    passed = all([check(ROOT / core, exceptions) for core, exceptions in CORES.items()])
    return 0 if check_dependencies(ROOT) and passed else 1


if __name__ == "__main__":
    sys.exit(main())
