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

    def test_panel_host_passes_and_its_exceptions_stay_scoped(self):
        root = SCRIPT.parents[1]
        self.assertTrue(boundary.check(root / "crates/panel-host", boundary.HOST_EXCEPTIONS))
        relative, source = "src/exchange/fetch.rs", '.user_agent("Sinan-exchange-rates/1")'
        self.assertFalse(boundary.violations(relative, source, boundary.HOST_EXCEPTIONS))
        self.assertTrue(boundary.violations(relative, source))
        self.assertTrue(boundary.violations("src/servers.rs", source, boundary.HOST_EXCEPTIONS))
        self.assertTrue(boundary.violations(relative, source + "; user_id", boundary.HOST_EXCEPTIONS))
        self.assertTrue(boundary.violations("src/lib.rs", "pub mod singbox;", boundary.HOST_EXCEPTIONS))

    def test_plugins_depend_on_the_host_and_never_the_reverse(self):
        self.assertTrue(boundary.check_dependencies(SCRIPT.parents[1]))
        manifests = {
            "crates/agent-core/Cargo.toml": "[dependencies]\nsinan-protocol.workspace = true\n",
            "crates/panel-host/Cargo.toml": "[dependencies]\nsinan-protocol.workspace = true\n",
            "plugins/ddns/panel/Cargo.toml": "[dependencies]\nsinan-panel-host.workspace = true\n",
        }
        broken = {
            "crates/panel-host/Cargo.toml": "[dev-dependencies]\nsinan-plugin-singbox.workspace = true\n",
            "plugins/ddns/panel/Cargo.toml": "[dependencies]\nsinan-plugin-singbox.workspace = true\n",
            "crates/agent-core/Cargo.toml": "[target.'cfg(unix)'.dependencies]\nsinan-adapter-singbox.workspace = true\n",
        }
        for path, manifest in broken.items():
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for relative, text in {**manifests, path: manifest}.items():
                    (root / relative).parent.mkdir(parents=True, exist_ok=True)
                    (root / relative).write_text(text)
                self.assertFalse(boundary.check_dependencies(root))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, text in manifests.items():
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                (root / relative).write_text(text)
            self.assertTrue(boundary.check_dependencies(root))


if __name__ == "__main__":
    unittest.main()
