#!/usr/bin/env python3
"""Exercise the real PowerShell bootstrap functions without native service changes."""
import base64
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'crates/protocol/tests/fixtures'
PWSH = os.environ.get('SINAN_PWSH') or shutil.which('pwsh')
sys.path.insert(0, str(ROOT / 'tools'))
import release


def quote(value):
    return "'" + ''.join(character * 2 if character in "'\u2018\u2019\u201a\u201b" else character for character in str(value)) + "'"


class PowerShellGenerationTests(unittest.TestCase):
    def test_generated_script_embeds_approved_roots_and_utf8_bom(self):
        spec = importlib.util.spec_from_file_location('render_powershell', ROOT / 'tools/render-bootstrap-powershell.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        generated = module.render()
        self.assertEqual((ROOT / 'deploy/bootstrap.ps1').read_bytes(), generated)
        self.assertTrue(generated.startswith(b'\xef\xbb\xbf'))
        self.assertNotIn(release.TEST_ONLY_PUBLIC_KEY.encode(), generated)
        self.assertNotIn(b'@@', generated)


@unittest.skipUnless(PWSH and shutil.which('minisign'), 'requires pwsh and minisign; native service install is separate')
class PowerShellBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sinan-powershell-')
        self.directory = Path(self.temporary.name)
        self.bundle = self.directory / '0.3.0'
        self.bundle.mkdir()
        entries, sums = [], {}
        for target in ('windows-amd64', 'windows-arm64', 'freebsd-amd64', 'macos-arm64'):
            payload = b'TEST ONLY binary, never execute ' + target.encode()
            entry = {'name': 'agent', 'version': '0.3.0', 'arch': target, 'format': 'raw',
                     'binary_name': 'sinan-agent.exe' if target.startswith('windows-') else 'sinan-agent',
                     'archive_size': len(payload), 'binary_size': len(payload),
                     'binary_sha256': release.digest(payload)}
            entry['asset_name'] = release.asset_name(entry)
            sums[release.canonical_path(entry)] = release.digest(payload)
            entries.append(entry)
        metadata = {'schema': 1, 'source_repo': release.REPOSITORY, 'tag': 'agent-v0.3.0',
                    'protocol_min': 1, 'protocol_max': 1, 'artifacts': entries}
        (self.bundle / 'release.json').write_text(json.dumps(metadata, sort_keys=True, separators=(',', ':')) + '\n')
        (self.bundle / 'install.sh').write_text('#!/bin/sh\nexit 0\n')
        for name in ('release.json', 'install.sh'):
            sums[name] = release.digest((self.bundle / name).read_bytes())
        (self.bundle / 'SHA256SUMS').write_text(''.join(f'{sums[path]}  {path}\n' for path in sorted(sums)))
        subprocess.run(['minisign', '-S', '-m', str(self.bundle / 'SHA256SUMS'), '-s', str(FIXTURES / 'TEST_ONLY.key'), '-t', 'Sinan TEST ONLY PowerShell fixture'], check=True, capture_output=True)

    def tearDown(self):
        self.temporary.cleanup()

    def run_ps(self, code):
        script = self.directory / 'test.ps1'
        script.write_text('$ErrorActionPreference=\'Stop\'\n. ' + quote(ROOT / 'deploy/bootstrap.ps1') + ' -Panel https://panel.example.com -Token fixture\n' + code, encoding='utf-8-sig')
        return subprocess.run([PWSH, '-NoProfile', '-File', str(script)], capture_output=True, text=True, timeout=30)

    def assert_ok(self, code):
        result = self.run_ps(code)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_signed_native_manifest_validates_exact_version_and_all_targets(self):
        key = release.load_roots(FIXTURES / 'public-keys.json')[0]
        self.assert_ok(f'$script:Roots=@({quote(key)}); Test-ReleaseSignature {quote(self.bundle)} {quote(shutil.which("minisign"))}; $m=Read-ReleaseManifest {quote(self.bundle)} 0.3.0; Assert-Sinan ($m.artifacts.Count -eq 4) "wrong count"; Assert-Sinan ($m.artifacts[0].binary_name -eq "sinan-agent.exe") "wrong Windows binary"')
        result = self.run_ps(f'Read-ReleaseManifest {quote(self.bundle)} 0.4.0')
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_root_and_modified_signed_bytes_are_rejected(self):
        result = self.run_ps(f'Test-ReleaseSignature {quote(self.bundle)} {quote(shutil.which("minisign"))}')
        self.assertNotEqual(result.returncode, 0)
        key = release.load_roots(FIXTURES / 'public-keys.json')[0]
        (self.bundle / 'SHA256SUMS').write_bytes((self.bundle / 'SHA256SUMS').read_bytes() + b'evil\n')
        result = self.run_ps(f'$script:Roots=@({quote(key)}); Test-ReleaseSignature {quote(self.bundle)} {quote(shutil.which("minisign"))}')
        self.assertNotEqual(result.returncode, 0)

    def test_non_executable_verifier_cannot_reuse_a_previous_success_exit(self):
        blocked = self.directory / 'blocked-minisign.exe'
        blocked.write_bytes(b'TEST ONLY non-executable verifier, never run')
        blocked.chmod(0o600)
        fake = 'untrusted comment: TEST ONLY\n' + base64.b64encode(b'ED' + b'\0' * 72).decode() + '\ntrusted comment: TEST ONLY\n' + base64.b64encode(b'\0' * 64).decode() + '\n'
        (self.bundle / 'SHA256SUMS.minisig').write_text(fake)
        key = release.load_roots(FIXTURES / 'public-keys.json')[0]
        self.assert_ok(f'$script:Roots=@({quote(key)}); $global:LASTEXITCODE=0; $ErrorActionPreference="Continue"; $rejected=$false; try {{ Test-ReleaseSignature {quote(self.bundle)} {quote(blocked)} }} catch {{ $rejected=$true }}; Assert-Sinan $rejected "non-executable verifier accepted fake signature"; Assert-Sinan ($null -eq $global:LASTEXITCODE) "verifier reused stale native success"')

    def test_real_verifier_rejects_bad_signature_and_can_continue_to_the_correct_root(self):
        key = release.load_roots(FIXTURES / 'public-keys.json')[0]
        wrong = release.load_roots(ROOT / 'deploy/release-public-keys.json', publication=True)[0]
        original = (self.bundle / 'SHA256SUMS').read_bytes()
        (self.bundle / 'SHA256SUMS').write_bytes(original + b'TEST ONLY tampering\n')
        result = self.run_ps(f'$script:Roots=@({quote(key)}); $global:LASTEXITCODE=0; Test-ReleaseSignature {quote(self.bundle)} {quote(shutil.which("minisign"))}')
        self.assertNotEqual(result.returncode, 0)
        (self.bundle / 'SHA256SUMS').write_bytes(original)
        self.assert_ok(f'$script:Roots=@({quote(wrong)},{quote(key)}); $global:LASTEXITCODE=7; Test-ReleaseSignature {quote(self.bundle)} {quote(shutil.which("minisign"))}; Assert-Sinan ($global:LASTEXITCODE -eq 0) "correct root was not attempted after wrong signature"')

    def test_agent_native_calls_require_current_success_and_reject_failed_launch(self):
        blocked = self.directory / 'blocked-agent.exe'
        blocked.write_bytes(b'TEST ONLY non-executable Agent, never run')
        blocked.chmod(0o600)
        self.assert_ok(f'$global:LASTEXITCODE=0; $ErrorActionPreference="Continue"; $rejected=$false; try {{ Invoke-CheckedAgent {quote(blocked)} @("fixture") }} catch {{ $rejected=$true }}; Assert-Sinan $rejected "non-executable Agent accepted stale success"; Assert-Sinan ($null -eq $global:LASTEXITCODE) "Agent reused stale native exit"')
        for status in (0, 7):
            code = f'$global:LASTEXITCODE=0; $ErrorActionPreference="Continue"; $rejected=$false; try {{ Invoke-CheckedAgent {quote(PWSH)} @("-NoProfile","-NonInteractive","-Command","[Environment]::Exit({status})") }} catch {{ $rejected=$true }}; Assert-Sinan ($rejected -eq ${"true" if status else "false"}) "wrong current Agent status"; Assert-Sinan ($global:LASTEXITCODE -eq {status}) "wrong current native exit"'
            self.assert_ok(code)
    def test_canonical_manifest_rejects_metadata_installer_and_duplicate_path_tampering(self):
        manifest = self.bundle / 'SHA256SUMS'
        original = manifest.read_bytes()
        for changed in (original.replace(b'\n', b'\r\n'), original + original.splitlines(keepends=True)[0], b''.join(reversed(original.splitlines(keepends=True)))):
            manifest.write_bytes(changed)
            self.assertNotEqual(self.run_ps(f'Read-ReleaseManifest {quote(self.bundle)} 0.3.0').returncode, 0)
        manifest.write_bytes(original)
        (self.bundle / 'install.sh').write_text('tampered installer')
        self.assertNotEqual(self.run_ps(f'Read-ReleaseManifest {quote(self.bundle)} 0.3.0').returncode, 0)
        (self.bundle / 'install.sh').write_text('#!/bin/sh\nexit 0\n')
        (self.bundle / 'release.json').write_text('{}')
        self.assertNotEqual(self.run_ps(f'Read-ReleaseManifest {quote(self.bundle)} 0.3.0').returncode, 0)

    def test_partial_enrollment_reuses_same_key_and_rejects_mismatched_or_activated_identity(self):
        identity = self.directory / 'identity'
        identity.mkdir()
        (identity / 'device.key').write_bytes(b'k' * 32)
        (identity / 'panel_origin').write_text('https://panel.example.com')
        # Linux has no Windows ACL; replace only the ACL checker for these data checks.
        prelude = 'function Assert-ProtectedTree([string]$Path) {}\n'
        self.assert_ok(prelude + f'Assert-PartialIdentity {quote(identity)} https://panel.example.com')
        self.assertEqual((identity / 'device.key').read_bytes(), b'k' * 32)
        self.assertNotEqual(self.run_ps(prelude + f'Assert-PartialIdentity {quote(identity)} https://elsewhere.example.com').returncode, 0)
        (identity / 'device.key').write_bytes(b'bad')
        self.assertNotEqual(self.run_ps(prelude + f'Assert-PartialIdentity {quote(identity)} https://panel.example.com').returncode, 0)
        (identity / 'device.key').unlink()
        self.assert_ok(prelude + f'Assert-PartialIdentity {quote(identity)} https://panel.example.com')
        (identity / 'unexpected').write_bytes(b'unknown')
        self.assertNotEqual(self.run_ps(prelude + f'Assert-PartialIdentity {quote(identity)} https://panel.example.com').returncode, 0)

    def test_native_enrollment_command_preserves_token_with_option_prefix(self):
        template = (ROOT / 'deploy/bootstrap.ps1.tmpl').read_text()
        command = next(line.strip() for line in template.splitlines()
                       if 'Invoke-CheckedAgent' in line and "'enroll'" in line)
        agent = self.directory / 'fixture-agent'
        agent.write_text('#!' + sys.executable + '\n' +
                         'import argparse, json\n'
                         'parser = argparse.ArgumentParser()\n'
                         'parser.add_argument("--config")\n'
                         'parser.add_argument("command")\n'
                         'parser.add_argument("--panel")\n'
                         'parser.add_argument("--token")\n'
                         'print(json.dumps(vars(parser.parse_args())))\n')
        agent.chmod(0o755)
        output = self.assert_ok(f'$agent={quote(agent)}; $configuration={quote(self.directory / "agent.toml")}; $Token="-TEST_ONLY_token"; ' + command)
        self.assertEqual(json.loads(output)['token'], '-TEST_ONLY_token')

    def test_previous_windows_agent_reads_reference_file_and_rejects_path_escape(self):
        core = self.directory / 'core'
        binary = core / '0.2.0' / 'sinan-agent.exe'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'TEST ONLY never execute')
        reference = core / 'current'
        reference.write_text(json.dumps({'sinan_directory_reference': True, 'target': str(binary.parent)}))
        config = self.directory / 'agent.toml'
        prelude = 'function Assert-ProtectedTree([string]$Path) {}\n'
        for value in (json.dumps(str(core)), "'" + str(core) + "'"):
            config.write_text('agent_root = ' + value + '\n')
            self.assert_ok(prelude + f'Assert-Sinan ((Get-PreviousAgent {quote(self.directory)} {quote(config)}) -eq {quote(binary)}) "wrong previous binary"')
        reference.write_text(json.dumps({'sinan_directory_reference': True, 'target': str(self.directory / 'elsewhere/0.2.0')}))
        self.assertNotEqual(self.run_ps(prelude + f'Get-PreviousAgent {quote(self.directory)} {quote(config)}').returncode, 0)

    def test_origin_and_github_redirect_allowlists(self):
        for origin in ('https://panel.example.com', 'http://127.0.0.1:8080', 'http://[::1]:8080', 'http://localhost:8080'):
            self.assert_ok('Assert-Origin ' + quote(origin))
        for origin in ('http://panel.example.com', 'https://user:pass@panel.example.com', 'https://panel.example.com/path', 'https://panel.example.com?evil=1'):
            self.assertNotEqual(self.run_ps('Assert-Origin ' + quote(origin)).returncode, 0)
        for url in ('https://example.com/file', 'http://github.com/file', 'https://github.com:444/file', 'https://github.com.example.com/file'):
            self.assertNotEqual(self.run_ps('Assert-GithubUrl ([Uri]' + quote(url) + ')').returncode, 0)

    def test_github_mirror_never_uses_panel_or_ip_origin(self):
        self.assert_ok("Assert-Mirror https://mirror.example.com/prefix https://panel.example.com; Assert-GithubUrl ([Uri]'https://mirror.example.com/https://github.com/file') mirror.example.com; Assert-Sinan ((Get-ReleaseUrl https://github.com/file https://mirror.example.com/prefix) -eq 'https://mirror.example.com/prefix/https://github.com/file') 'bad mirror URL'")
        for mirror in ('https://panel.example.com/mirror', 'http://mirror.example.com', 'https://127.0.0.1', 'https://localhost', 'https://user:pass@mirror.example.com', 'https://mirror.example.com:444', 'https://mirror.example.com?token=fixture'):
            self.assertNotEqual(self.run_ps('Assert-Mirror ' + quote(mirror) + ' https://panel.example.com').returncode, 0)
        template = (ROOT / 'deploy/bootstrap.ps1.tmpl').read_text()
        self.assertNotIn("'/api/bootstrap/'", template)
        self.assertIn('Receive-SinanFile $url $agent $selected.binary_size $true', template)
        self.assertIn('Windows 服务安装仅支持稳定版本', template)

    def test_windows_architecture_uses_native_os_under_wow64(self):
        self.assert_ok('$env:PROCESSOR_ARCHITECTURE="AMD64"; $env:PROCESSOR_ARCHITEW6432="ARM64"; Assert-Sinan ((Get-HostTarget) -eq "windows-arm64") "wrong native architecture"; $env:PROCESSOR_ARCHITEW6432=""; Assert-Sinan ((Get-HostTarget) -eq "windows-amd64") "wrong native architecture"')
        self.assertNotEqual(self.run_ps('$env:PROCESSOR_ARCHITEW6432=""; $env:PROCESSOR_ARCHITECTURE="X86"; Get-HostTarget').returncode, 0)

    @unittest.skipUnless(shutil.which('rustc'), 'requires rustc to exercise the actual launcher quote function')
    def test_rust_launcher_quote_recovers_all_arguments_without_smart_quote_injection(self):
        source = (ROOT / 'crates/panel-host/src/installation/windows.rs').read_text()
        function = re.search(r'(?ms)^fn quote\(value: &str\) -> String \{.*?^\}', source).group()
        harness = self.directory / 'quote.rs'
        harness.write_text(function + '\nfn main() { for value in std::env::args().skip(1) { for byte in quote(&value).as_bytes() { print!("{byte:02x}"); } println!(); } }\n')
        executable = self.directory / ('quote.exe' if os.name == 'nt' else 'quote')
        subprocess.run(['rustc', '--edition=2024', '-C', 'debuginfo=0', str(harness), '-o', str(executable)], check=True, capture_output=True, timeout=30)

        def rust_quote(values):
            result = subprocess.run([str(executable), *values], check=True, capture_output=True, text=True, timeout=5)
            return [bytes.fromhex(line).decode() for line in result.stdout.splitlines()]

        delimiters = "'\u2018\u2019\u201a\u201b"
        exploit = 'https://mirror.example.com/\u2019;[Environment]::Exit(61);\u2018tail'
        # The original ASCII-only quoting executes the marker before payload dispatch.
        old_payload = "Capture -Mirror '" + exploit.replace("'", "''") + "'"
        old_outer = "'" + old_payload.replace("'", "''") + "'"
        self.assertEqual(self.run_ps('$payload=' + old_outer + '; & ([ScriptBlock]::Create($payload))').returncode, 61)
        mirrors = [f'https://mirror.example.com/{character};[Environment]::Exit(61);{character}tail' for character in delimiters]
        mirrors.append('https://mirror.example.com/' + delimiters + '路径/😀')
        for mirror in mirrors:
            values = ['0.3.1', 'https://panel.example.com', 'fixture' + delimiters + '\n$([Environment]::Exit(61));', 'windows-arm64', mirror]
            literals = rust_quote(values)
            payload = 'Capture ' + ' '.join(f'-{name} {literal}' for name, literal in zip(('Version', 'Panel', 'Token', 'Target', 'Mirror'), literals))
            outer = rust_quote([payload])[0]
            code = 'function Capture { param([string]$Version,[string]$Panel,[string]$Token,[string]$Target,[string]$Mirror); foreach($value in @($Version,$Panel,$Token,$Target,$Mirror)) { [Console]::WriteLine([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($value))) } }\n'
            code += '$payload=' + outer + '; & ([ScriptBlock]::Create($payload))'
            output = self.assert_ok(code)
            recovered = [base64.b64decode(line).decode('utf-16le') for line in output.splitlines()]
            self.assertEqual(recovered, values)
            # These are valid anonymous HTTPS mirror paths; no installation is run.
            self.assert_ok('Assert-Mirror ' + literals[-1] + ' https://panel.example.com')

    def test_download_bounds_and_panel_redirects_and_numeric_version_selection(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                if self.path.startswith('/redirect'):
                    self.send_response(302); self.send_header('Location', '/payload'); self.end_headers(); return
                if self.path.startswith('/api/bootstrap/versions'):
                    content = json.dumps({'versions': [{'version': v, 'tag': 'agent-v' + v} for v in ('0.9.0', '0.10.0', '2.0.0-beta')]}).encode()
                else:
                    content = b'valid'
                self.send_response(200); self.send_header('Content-Length', str(len(content))); self.end_headers(); self.wfile.write(content)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        origin = f'http://127.0.0.1:{server.server_port}'
        try:
            payload = self.directory / 'payload'
            self.assert_ok(f'Receive-SinanFile {quote(origin + "/payload")} {quote(payload)} 5 $false 5')
            self.assertEqual(payload.read_bytes(), b'valid')
            for path, limit, size in (('/payload', 4, 0), ('/payload', 6, 6), ('/redirect', 5, 5)):
                payload.unlink(missing_ok=True)
                self.assertNotEqual(self.run_ps(f'Receive-SinanFile {quote(origin + path)} {quote(payload)} {limit} $false {size}').returncode, 0)
                self.assertFalse(payload.exists())
            self.assert_ok(f'$v=@(Get-ReleaseCandidates {quote(self.directory)} {quote(origin)} fixture windows-amd64 latest); Assert-Sinan ($v[0] -eq "0.10.0" -and $v[1] -eq "0.9.0" -and $v.Count -eq 2) "numeric ordering failed"')
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
