import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tools/check-core-boundary.py"
spec = importlib.util.spec_from_file_location("core_boundary", SCRIPT)
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


class CoreBoundaryTests(unittest.TestCase):
    def test_business_identifiers_sql_routes_and_comments_are_rejected(self):
        for source in (
            "struct ProxyUser { user_id: i64 }", "SELECT users.id FROM users",
            '"/api/users"', "loadSubscription()", "subscription_token",
            "quota_bytes", "AccountQuota", "// user traffic", "USER_ID",
            "SubscriptionURL", "monthly_quotas", "userId",
        ):
            with self.subTest(source=source):
                self.assertTrue(boundary.violations("src/transport.rs", source))

    def test_runtime_name_remains_forbidden_in_every_file(self):
        for relative in ("Cargo.toml", "README.md", "src/system/windows.rs"):
            for source in ("singbox", "SING-BOX"):
                self.assertTrue(boundary.violations(relative, source))

    def test_native_exceptions_are_expression_and_file_scoped(self):
        fixtures = {
            "src/system/services.rs": '"--property=LoadState,MainPID,User,Group,SupplementaryGroups"; properties.get("User")',
            "src/system/jobs.rs": '"--property=CPUQuota=20%"; "--property=CPUQuotaPeriodSec=100ms"',
            "src/system/budgets.rs": '("CPUQuota", format!("{}%", limit)); ("CPUQuotaPeriodSec", "100ms".into())',
            "src/system/tests.rs": '"--property=CPUWeight,CPUQuotaPerSecUSec,IOWeight,OOMScoreAdjust"; ("CPUQuotaPerSecUSec", "1s".into())',
            "src/system_network/firewall.rs": '"WantedBy=multi-user.target\\n"',
            "src/system_network/tunnel.rs": 'format!("UserKnownHostsFile={}",known.display())',
            "src/system/windows.rs": "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            "src/system/deploy/native/windows.rs": "Get-LocalUser -Name $account; -UserId 'SYSTEM'; USER_RIGHTS",
            "src/system/deploy/native/unix.rs": '"/Users/example"; "UserShell"; <key>UserName</key>',
            "tests/usage_bounds.rs": '.pragma_update(None, "user_version", 1); "PRAGMA user_version"',
        }
        for relative, source in fixtures.items():
            with self.subTest(relative=relative):
                self.assertFalse(boundary.violations(relative, source))
                self.assertTrue(boundary.violations("src/transport.rs", source))
                self.assertTrue(boundary.violations(relative, source + "; user_id=1"))

    def test_api_names_and_existing_account_terms_do_not_match_business(self):
        self.assertFalse(boundary.violations("src/config.rs", "url.username(); account_name; usershow; useradd"))

    def test_network_native_exception_cannot_mask_repurposed_business_terms(self):
        for source in ('"multi-user.target"', '"WantedBy=multi-user.target/proxy"',
                       '"WantedBy=multi-user.target\\n"; user_id=1'):
            self.assertTrue(boundary.violations("src/system_network/firewall.rs", source))
        for source in ('UserKnownHostsFile', 'format!("UserKnownHostsFile=proxy-user")',
                       'format!("UserKnownHostsFile={}", user_id)'):
            self.assertTrue(boundary.violations("src/system_network/tunnel.rs", source))

    def test_formatted_native_expression_preserves_lines_and_adjacent_business_rejection(self):
        native = 'let account = properties\n    .get("User")\n    .map(String::as_str);'
        relative = "src/system_network/certificates.rs"
        self.assertFalse(boundary.violations(relative, native))
        self.assertTrue(boundary.violations("src/transport.rs", native))
        findings = boundary.violations(relative, native + '\nlet user_id = 1;')
        self.assertEqual(findings, [(4, 'user')])
        findings = boundary.violations(relative, native.replace('.get("User")', '.get("User"); user_id=1'))
        self.assertEqual(findings, [(2, 'user')])

    def test_certificate_native_account_fixture_exception_is_exact_and_file_scoped(self):
        relative = "src/system_network/certificates.rs"
        for native in ('loaded.insert("User".into(), "operator".into());',
                       'loaded.insert("User".into(), String::new());'):
            with self.subTest(native=native):
                self.assertFalse(boundary.violations(relative, native))
                self.assertTrue(boundary.violations("src/transport.rs", native))
                self.assertEqual(boundary.violations(relative, native + " user_id=1;"),
                                 [(1, 'user')])
        for native in ('other.insert("User".into(), String::new());',
                       'loaded.insert("User", String::new());'):
            self.assertTrue(boundary.violations(relative, native))

    def test_macos_account_path_exception_does_not_hide_business_routes(self):
        relative = "src/system/deploy/native/unix.rs"
        for source in ('"/Users".into()', 'format!("/Users/{name}")'):
            with self.subTest(source=source):
                self.assertFalse(boundary.violations(relative, source))
        for source in ('let route = "/api/Users";', 'let path = "/proxy/Users/example";',
                       'let path = format!("{root}/Users");', 'let path = "/Users/user_id";'):
            with self.subTest(source=source):
                self.assertTrue(boundary.violations(relative, source))

    def test_new_file_is_scanned_and_current_core_passes(self):
        self.assertTrue(boundary.check(SCRIPT.parents[1] / "crates/agent-core"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "new.sql").write_text("SELECT quota FROM state")
            self.assertFalse(boundary.check(root))


if __name__ == "__main__":
    unittest.main()
