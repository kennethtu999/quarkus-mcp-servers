import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from register_defaults import clean_jsonc, default_env, merge_opencode, write_opencode, register, keep_scope


class DefaultRegistrationTest(unittest.TestCase):
    def test_merging_jsonc_keeps_other_settings_comments_and_existing_mcp(self):
        text = '''{
          // keep provider comment
          "provider": {"url": "https://example/", "literal": ",} /*not a comment*/",},
          "mcp": {"existing": {"type": "remote", "url": "https://mcp/"},},
        }'''
        entries = {"ai-db-read": {"type": "local", "command": ["/path with spaces/java", "-jar", "/x.jar"]}}
        updated = merge_opencode(text, entries)
        decoded = json.loads(clean_jsonc(updated))
        self.assertIn("// keep provider comment", updated)
        self.assertEqual(decoded["provider"]["literal"], ",} /*not a comment*/")
        self.assertEqual(decoded["mcp"]["existing"]["url"], "https://mcp/")
        self.assertEqual(decoded["mcp"]["ai-db-read"], entries["ai-db-read"])
        self.assertEqual(json.loads(clean_jsonc(merge_opencode(updated, entries))), decoded)

    def test_empty_or_missing_mcp_and_duplicate_keys(self):
        for text in ("{}", '{"provider":{},}', '{/*comment*/}'):
            self.assertIn("ai-db-read", json.loads(clean_jsonc(merge_opencode(text, {"ai-db-read": {}})))["mcp"])
        with self.assertRaises(ValueError):
            merge_opencode('{"mcp":{},"mcp":{}}', {})

    def test_default_environment_does_not_follow_custom_client_config(self):
        with patch.dict(os.environ, {"CODEX_HOME": "/custom", "CLAUDE_CONFIG_DIR": "/custom", "OPENCODE_CONFIG": "/custom"}):
            env = default_env()
        for key in ("CODEX_HOME", "CLAUDE_CONFIG_DIR", "OPENCODE_CONFIG"):
            self.assertNotIn(key, env)

    def test_opencode_is_backed_up_and_only_default_paths_are_written(self):
        with tempfile.TemporaryDirectory() as directory, patch("pathlib.Path.home", return_value=Path(directory)):
            path = Path(directory) / ".config/opencode/opencode.jsonc"
            path.parent.mkdir(parents=True)
            original = '{"provider":{"keep":true}}'
            path.write_text(original)
            write_opencode({"ai-db-read": {"type": "local", "command": ["java"]}})
            self.assertEqual(json.loads(clean_jsonc(path.read_text()))["provider"], {"keep": True})
            self.assertEqual(next(path.parent.glob("*.bak")).read_text(), original)

    def test_codex_registers_named_endpoints_and_reads_back_exact_command(self):
        from subprocess import CompletedProcess
        command = ["/java", "-jar", "/app/lib/ai-db-mcp.jar", "start"]
        state = {"ai-db-read": {"command": "/old/java", "args": ["--profiles", "DB-A"]},
                 "ai-db-write": {"command": "/old/java", "args": ["--profiles", "DB-B"]},
                 "other": {"command": "keep", "args": []}}
        def native(name, args, required=True):
            if args[:2] == ["mcp", "get"]:
                entry = state.get(args[2])
                return CompletedProcess([], 0 if entry else 1, stdout=json.dumps({"enabled": True, "transport": entry}) if entry else "")
            if args[:2] == ["mcp", "add"]:
                state[args[2]] = {"command": args[4], "args": args[5:]}
            elif args[:2] == ["mcp", "remove"]:
                state.pop(args[2])
            return CompletedProcess([], 0, stdout="")
        with patch("shutil.which", return_value="/bin/codex"), patch("register_defaults.cli", side_effect=native), \
                patch("register_defaults.probe") as verified:
            register("codex", {"dbmcp": command})
        self.assertEqual(set(state), {"dbmcp", "other"})
        self.assertEqual(state["dbmcp"]["args"][-2:], ["--profiles", "DB-A,DB-B"])
        self.assertEqual(verified.call_args.args[0], command + ["--profiles", "DB-A,DB-B"])

    def test_json_clients_remove_aliases_preserve_scope_and_unrelated_entries(self):
        command = ["/java", "-jar", "/app/lib/ai-db-mcp.jar", "start"]
        from subprocess import CompletedProcess
        for client, relative, section in (("claude", ".claude.json", "mcpServers"),
                                          ("pi", ".pi/agent/mcp.json", "mcpServers"),
                                          ("opencode", ".config/opencode/opencode.json", "mcp")):
            with self.subTest(client=client), tempfile.TemporaryDirectory() as directory, \
                    patch("pathlib.Path.home", return_value=Path(directory)), \
                    patch.dict(os.environ, {"XDG_CONFIG_HOME": str(Path(directory) / ".config")}), \
                    patch("shutil.which", return_value="/client"), patch("register_defaults.probe"), \
                    patch("register_defaults.cli", return_value=CompletedProcess([], 0, stdout="pi mcp <command>")):
                path = Path(directory) / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                original = {"provider": "KEEP", section: {
                    "ai-db-mcp": {"command": "/old/java", "args": ["start", "--mode", "read", "--profiles", "ONLY-DB"]},
                    "ai-db-read": {}, "ai-db-write": {}, "unrelated": {"enabled": False}}}
                path.write_text(json.dumps(original))
                register(client, {"dbmcp": command})
                saved = json.loads(clean_jsonc(path.read_text()))
                self.assertEqual(set(saved[section]), {"dbmcp", "unrelated"})
                self.assertEqual(saved["provider"], "KEEP")
                entry = saved[section]["dbmcp"]
                actual = entry["command"] if isinstance(entry["command"], list) else [entry["command"], *entry["args"]]
                self.assertEqual(actual, command + ["--profiles", "ONLY-DB"])
                self.assertTrue(list(path.parent.glob("*.bak")))

    def test_failed_replacement_probe_leaves_json_configuration_untouched(self):
        with tempfile.TemporaryDirectory() as directory, patch("pathlib.Path.home", return_value=Path(directory)), \
                patch("shutil.which", return_value="/claude"), patch("register_defaults.probe", side_effect=RuntimeError("failed")):
            path = Path(directory) / ".claude.json"
            text = '{"mcpServers":{"ai-db-read":{},"unrelated":{}}}'
            path.write_text(text)
            with self.assertRaises(RuntimeError):
                register("claude", {"dbmcp": ["/java", "-jar", "/x.jar", "start"]})
            self.assertEqual(path.read_text(), text)

    def test_canonical_scope_has_priority_over_legacy_and_missing_scope_is_not_invented(self):
        command = ["java", "start"]
        self.assertEqual(keep_scope(command, {"ai-db-mcp": {"args": ["--profiles", "A"]},
                                              "ai-db-read": {"args": ["--profiles", "B"]}}), command + ["--profiles", "A"])
        self.assertEqual(keep_scope(command, {"ai-db-read": {"args": []}}), command)


if __name__ == "__main__":
    unittest.main()
