#!/usr/bin/env python3
"""Opt-in registration in default user configs only; no custom launcher discovery."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from onboarding_check import config_directory
from probe_mcp import probe

CANONICAL = "dbmcp"
LEGACY = ("ai-db-mcp", "ai-db-read", "ai-db-write")


def keep_scope(command, previous):
    """Do not broaden an existing directory/profile restriction during name migration."""
    if "--profiles" in command:
        return command
    canonical = previous.get(CANONICAL, previous.get("ai-db-mcp"))
    entries = [canonical] if canonical is not None else [previous[name] for name in LEGACY if name in previous]
    labels = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("舊 MCP 設定格式無效，請手動修正")
        args = entry.get("command", []) if isinstance(entry.get("command"), list) else entry.get("args", [])
        if "--profiles" not in args:
            return command
        index = args.index("--profiles")
        if index + 1 >= len(args):
            raise ValueError("舊設定的 --profiles 不完整，請手動修正")
        labels.extend(args[index + 1].split(","))
    return [*command, "--profiles", ",".join(dict.fromkeys(labels))] if labels else command


def default_env():
    env = os.environ.copy()
    for key in ("CODEX_HOME", "CLAUDE_CONFIG_DIR", "PI_CODING_AGENT_DIR", "OPENCODE_CONFIG",
                "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG_CONTENT"):
        env.pop(key, None)
    return env


def cli(name, args, required=True):
    result = subprocess.run([name, *args], env=default_env(), cwd=Path.home(), capture_output=True,
                            text=True, timeout=45)
    if required and result.returncode:
        raise RuntimeError(name + " 註冊／讀回失敗，請手動檢查；未輸出可能含敏感值的 client 訊息")
    return result


def clean_jsonc(text):
    chars = list(text)
    quoted = False
    i = 0
    while i < len(chars):
        if quoted:
            if chars[i] == "\\":
                i += 2
                continue
            if chars[i] == '"':
                quoted = False
        elif chars[i] == '"':
            quoted = True
        elif text.startswith("//", i) or text.startswith("/*", i):
            end = text.find("\n", i) if text.startswith("//", i) else text.find("*/", i + 2)
            if end < 0:
                if text.startswith("/*", i):
                    raise ValueError("JSONC 註解未結束")
                end = len(chars)
            elif text.startswith("/*", i):
                end += 2
            for position in range(i, end):
                if chars[position] not in "\r\n":
                    chars[position] = " "
            i = end
            continue
        i += 1
    quoted = False
    i = 0
    while i < len(chars):
        if quoted:
            if chars[i] == "\\":
                i += 2
                continue
            if chars[i] == '"':
                quoted = False
        elif chars[i] == '"':
            quoted = True
        elif chars[i] == ',':
            end = i + 1
            while end < len(chars) and chars[end].isspace():
                end += 1
            if end < len(chars) and chars[end] in "}]":
                chars[i] = " "
        i += 1
    return "".join(chars)


def merge_opencode(text, entries, section="mcp"):
    clean = clean_jsonc(text)
    def unique(pairs):
        value = {}
        for key, entry in pairs:
            if key in value:
                raise ValueError("JSONC 含重複欄位，請先修正")
            value[key] = entry
        return value
    root = json.loads(clean, object_pairs_hook=unique)
    if not isinstance(root, dict) or not isinstance(root.get(section, {}), dict):
        raise ValueError("Client 設定與 MCP 區塊必須是 object")
    previous = root.get(section, {})
    entries = {name: dict(value) for name, value in entries.items()}
    if CANONICAL in entries:
        entry = entries[CANONICAL]
        if isinstance(entry.get("command"), list):
            entry["command"] = keep_scope(entry["command"], previous)
        else:
            command = keep_scope([entry["command"], *entry.get("args", [])], previous)
            entry["command"], entry["args"] = command[0], command[1:]
    obsolete = LEGACY if CANONICAL in entries else ()
    if all(previous.get(name) == value for name, value in entries.items()) and not any(name in previous for name in obsolete):
        return text
    merged = {**{name: value for name, value in previous.items() if name not in obsolete}, **entries}
    encoded = json.dumps(merged, ensure_ascii=False, indent=2)
    decoder = json.JSONDecoder()
    position = clean.index("{") + 1
    while True:
        while clean[position].isspace() or clean[position] == ',':
            position += 1
        if clean[position] == '}':
            break
        key, position = decoder.raw_decode(clean, position)
        while clean[position].isspace() or clean[position] == ':':
            position += 1
        start = position
        _, position = decoder.raw_decode(clean, position)
        if key == section:
            return text[:start] + encoded + text[position:]
    position = clean.index("{") + 1
    return text[:position] + '\n  ' + json.dumps(section) + ': ' + encoded + ("," if root else "") + text[position:]


def write_json_configs(paths, entries, section):
    saved = None
    for path in paths:
        if path.is_symlink():
            raise RuntimeError("預設 client 設定是 symlink，請手動處理")
        original = path.read_text() if path.exists() else "{}\n"
        updated = merge_opencode(original, entries, section)
        expected = json.loads(clean_jsonc(updated))[section]
        saved = expected[CANONICAL] if CANONICAL in entries else expected
        if CANONICAL in entries:
            actual = saved["command"] if isinstance(saved.get("command"), list) else [saved["command"], *saved.get("args", [])]
            probe(actual, env=default_env(), check_database=False)
        if updated == original and path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = path.with_name(path.name + ".ai-db-" + str(time.time_ns()) + ".bak")
            descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(original)
        descriptor, temporary = tempfile.mkstemp(prefix=".ai-db-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(updated)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        reread = json.loads(clean_jsonc(path.read_text()))
        if reread.get(section) != expected or (CANONICAL in entries and any(name in reread[section] for name in LEGACY)):
            raise RuntimeError("Client 設定讀回或舊名稱清理不符")
    return saved


def write_opencode(entries):
    directory = Path(os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")) / "opencode"
    paths = [directory / name for name in ("opencode.json", "opencode.jsonc") if (directory / name).exists()]
    return write_json_configs(paths or [directory / "opencode.json"], entries, "mcp")


def register(client, commands):
    if set(commands) != {CANONICAL}:
        raise ValueError("只註冊 dbmcp")
    if not shutil.which(client):
        print("[略過] 未安裝 " + client)
        return
    if client == "opencode":
        saved = write_opencode({CANONICAL: {"type": "local", "command": commands[CANONICAL], "enabled": True}})
        actual = saved["command"]
    elif client in ("claude", "pi"):
        if client == "pi" and "mcp" not in cli("pi", ["--help"]).stdout.lower():
            raise RuntimeError("此 Pi 版本尚不支援原生 MCP，請升級")
        path = Path.home() / (".claude.json" if client == "claude" else ".pi/agent/mcp.json")
        command = commands[CANONICAL]
        saved = write_json_configs([path], {CANONICAL: {"type": "stdio", "command": command[0], "args": command[1:]}}, "mcpServers")
        actual = [saved["command"], *saved["args"]]
    elif client == "codex":
        previous = {}
        for name in (CANONICAL, *LEGACY):
            existing = cli(client, ["mcp", "get", name, "--json"], required=False)
            if existing.returncode == 0:
                previous[name] = json.loads(existing.stdout).get("transport", {})
        actual = keep_scope(commands[CANONICAL], previous)
        probe(actual, env=default_env(), check_database=False)
        cli(client, ["mcp", "add", CANONICAL, "--", *actual])
        saved = json.loads(cli(client, ["mcp", "get", CANONICAL, "--json"]).stdout)
        transport = saved.get("transport", {})
        if saved.get("enabled") is False or [transport.get("command"), *transport.get("args", [])] != actual:
            raise RuntimeError("Codex 設定讀回不符")
        # Only retire the old aliases after the replacement starts successfully.
        for name in LEGACY:
            if name in previous:
                cli(client, ["mcp", "remove", name])
                if cli(client, ["mcp", "get", name, "--json"], required=False).returncode == 0:
                    raise RuntimeError("Codex 舊名稱尚未移除：" + name)
    else:
        raise ValueError("不支援此 client")
    print("[完成] " + client + "：dbmcp；已清理 ai-db-mcp／ai-db-read／ai-db-write（重開 client 生效）")


def offer(app, java, profiles):
    print("\n註冊預設 client：1 Codex  2 Claude  3 Pi  4 OpenCode  5 全部  0 略過")
    selected = input("選擇，可逗號分隔 [0]：").strip() or "0"
    options = {"1": "codex", "2": "claude", "3": "pi", "4": "opencode"}
    if selected == "0":
        return
    keys = list(options) if selected == "5" else selected.split(",")
    if any(key.strip() not in options for key in keys):
        raise RuntimeError("無效選項")
    base = [java, "-jar", str(app / "lib/ai-db-mcp.jar"), "start", "--config-dir", str(config_directory())]
    if os.environ.get("AI_DB_MCP_KEY_PROVIDER"):
        base += ["--key-provider", os.environ["AI_DB_MCP_KEY_PROVIDER"]]
    commands = {CANONICAL: base}
    failed = []
    for client in dict.fromkeys(options[key.strip()] for key in keys):
        try:
            register(client, commands)
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            failed.append(client)
            print("[未完成] " + client + "：" + str(error))
    if failed:
        raise RuntimeError("部分 client 註冊失敗：" + ", ".join(failed))
