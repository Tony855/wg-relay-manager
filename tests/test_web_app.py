import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_APP_PATH = PROJECT_ROOT / "web" / "app.py"

spec = importlib.util.spec_from_file_location("wg_relay_web_app", WEB_APP_PATH)
web_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web_app)


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_file = Path(self.temp_dir.name) / "config.json"
        self.log_file = Path(self.temp_dir.name) / "wg-relay.log"
        web_app.CONFIG_FILE = str(self.config_file)
        web_app.LOG_FILE = str(self.log_file)
        web_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_config(self, password_hash):
        self.config_file.write_text(
            json.dumps(
                {
                    "relay_name": "Test Relay",
                    "web_user": "admin",
                    "web_pass_hash": password_hash,
                    "public_interface": "eth0",
                    "public_ip": "127.0.0.1",
                    "web_port": 8080,
                    "next_rule_id": 1,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def test_legacy_sha256_login_is_accepted_and_migrated(self):
        password = "LegacyPass!23"
        legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        self.write_config(legacy_hash)

        client = web_app.app.test_client()
        response = client.post(
            "/login",
            data={"username": "admin", "password": password},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        updated_config = json.loads(self.config_file.read_text(encoding="utf-8"))
        self.assertNotEqual(updated_config["web_pass_hash"], legacy_hash)
        self.assertTrue(web_app.check_password_hash(updated_config["web_pass_hash"], password))

    def test_api_status_parses_conntrack_count(self):
        self.write_config(generate_password_hash("admin"))
        client = web_app.app.test_client()
        with client.session_transaction() as session:
            session["logged_in"] = True
            session["username"] = "admin"

        def fake_run_shell_command(command, check=True):
            if command == "grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'":
                return "12.5", ""
            if command == "free | grep Mem":
                return "Mem: 1000 250 750 0 0 0", ""
            if command == "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'":
                return "33", ""
            if command == "cat /proc/net/nf_conntrack 2>/dev/null | wc -l":
                return "15", ""
            if command == "cat /proc/uptime | awk -F. '{print $1}'":
                return "3600", ""
            if command == "systemctl is-active wg-relay-web":
                return "active", ""
            if command == "systemctl is-active nginx":
                return "inactive", ""
            if command == "grep 'eth0:' /proc/net/dev":
                return "eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0", ""
            raise AssertionError(f"未模拟的命令: {command}")

        with patch.object(web_app, "run_shell_command", side_effect=fake_run_shell_command):
            response = client.get("/api/status")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["data"]["connection_stats"], 15)


if __name__ == "__main__":
    unittest.main()
