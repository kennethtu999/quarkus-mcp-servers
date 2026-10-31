"""Run with: python3 -m unittest discover -s jdbc/scripts -p test_onboarding.py"""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from onboarding_check import show_status, verify
from probe_mcp import EXPECTED, probe


FAKE_MCP = '''
import json, sys
mode = sys.argv[1]
names = json.loads(sys.argv[2])
for line in sys.stdin:
    req = json.loads(line)
    if "id" not in req: continue
    method = req["method"]
    if method == "tools/call" and req["params"]["name"] == "db_execute_template":
        print(json.dumps({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32601, "message": "hidden"}}), flush=True)
        continue
    if method == "initialize": result = {"protocolVersion": "2024-11-05"}
    elif method == "tools/list": result = {"tools": [{"name": n} for n in names]}
    elif req["params"]["name"] == "db_list_profiles":
        value = [] if mode == "empty" else [{"profileId": "one", "label": "TEST", "enabled": True,
          "policy": "POLICY_STALE" if mode == "stale" else "ACTIVE", "access": "READ_ONLY"}]
        result = {"content": [{"type": "text", "text": json.dumps(value)}]}
    else:
        result = {"isError": mode == "db-down", "content": [{"type": "text", "text": "{\\"tables\\": []}"}]}
    print(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}), flush=True)
'''


class OnboardingTest(unittest.TestCase):
    def test_initial_status_does_not_create_or_open_an_empty_store(self):
        with tempfile.TemporaryDirectory() as temporary, patch("onboarding_check.config_directory", return_value=Path(temporary)), \
                patch("onboarding_check.subprocess.run") as invoked, contextlib.redirect_stdout(io.StringIO()) as output:
            show_status(Path("/app"), "/java")
        invoked.assert_not_called()
        self.assertIn("尚未建立", output.getvalue())

    def test_initial_status_distinguishes_disabled_failed_and_active_profiles(self):
        from subprocess import CompletedProcess
        def completed(stdout, code=0):
            return CompletedProcess([], code, stdout=stdout, stderr="")
        replies = [completed("LABEL TYPE ENABLED\nDB-A DB2_LUW true\nDB-B ORACLE false\n"),
                   completed("policy: ACTIVE\n"), completed("access: READ_ONLY\n"), completed("FAILED", 1),
                   completed("policy: POLICY_STALE\n"), completed("access: READ_WRITE_WHITELIST\n")]
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "profiles.enc").touch()
            with patch("onboarding_check.config_directory", return_value=Path(temporary)), \
                    patch("onboarding_check.subprocess.run", side_effect=replies) as invoked, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                show_status(Path("/app"), "/java")
        self.assertIn("DB-A | DB2_LUW | true | READ_ONLY | ACTIVE | 失敗", output.getvalue())
        self.assertIn("DB-B | ORACLE | false | READ_WRITE_WHITELIST | POLICY_STALE | 已停用", output.getvalue())
        self.assertEqual(invoked.call_count, 6)

    def wire(self, mode="ok", tools=EXPECTED):
        return probe([sys.executable, "-u", "-c", FAKE_MCP, mode, json.dumps(sorted(tools))])

    def test_real_subprocess_wire_success_and_database_check(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.wire()
        self.assertEqual(result[0]["access"], "READ_ONLY")
        self.assertIn("實際 DB 連線", output.getvalue())

    def test_protocol_success_does_not_hide_bad_db_or_policy(self):
        for mode in ("db-down", "stale", "empty"):
            with self.subTest(mode=mode), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(RuntimeError):
                    self.wire(mode)

    def test_wrong_tools_fail(self):
        with self.assertRaises(RuntimeError):
            self.wire(tools={"arbitrary_sql"})

    def test_verification_never_registers_or_calls_client_tools(self):
        with patch("onboarding_check.probe", return_value=[{"enabled": True, "access": "READ_WRITE_WHITELIST"}]) as checked, \
                patch("onboarding_check.subprocess.run") as cli, contextlib.redirect_stdout(io.StringIO()):
            verify(Path("/app"), "/java")
        cli.assert_not_called()
        self.assertEqual(checked.call_count, 1)
        self.assertNotIn("--mode", checked.call_args.args[0])

    def test_readonly_configuration_only_verifies_read_endpoint(self):
        with patch("onboarding_check.probe", return_value=[{"enabled": True, "access": "READ_ONLY"}]) as checked, \
                contextlib.redirect_stdout(io.StringIO()):
            verify(Path("/app"), "/java")
        self.assertEqual(checked.call_count, 1)


if __name__ == "__main__":
    unittest.main()
