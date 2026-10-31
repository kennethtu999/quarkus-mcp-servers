#!/usr/bin/env python3
"""Show DB status and verify MCP/DB; offer optional default-client registration afterwards."""
import os
from pathlib import Path
import re
import subprocess
import sys

from probe_mcp import probe


def config_directory():
    if os.environ.get("AI_DB_MCP_CONFIG_DIR"):
        return Path(os.environ["AI_DB_MCP_CONFIG_DIR"]).expanduser().absolute()
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/ai-db-mcp"
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "ai-db-mcp"


def show_status(app, java):
    config = config_directory()
    print("\n設定儲存位置：" + str(config), flush=True)
    print("連線帳密：profiles.enc（加密）；權限：permissions/；操作紀錄：logs/", flush=True)
    if not (config / "profiles.enc").exists():
        print("目前尚未建立 DB 連線。", flush=True)
        return
    base = [java, "-jar", str(app / "lib/ai-db-mcp.jar")]

    def inspect(args):
        try:
            return subprocess.run(base + args, capture_output=True, text=True, timeout=35)
        except subprocess.TimeoutExpired:
            return None

    listed = inspect(["profile", "list"])
    if listed is None or listed.returncode:
        print("[無法讀取設定] 請檢查 master key、OS key store 或設定目錄權限；尚未更動任何設定。", flush=True)
        return
    print("\n目前已設定的 DB（逐組實測連線，逾時會標示失敗）：", flush=True)
    print("LABEL | TYPE | 啟用 | 權限 | POLICY | DB連線", flush=True)
    for line in listed.stdout.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[2] not in {"true", "false"}:
            continue
        label, kind, enabled = parts
        details = inspect(["profile", "show", label])
        policy = inspect(["policy", "show", label])
        state = re.search(r"^policy:\s+(\S+)", details.stdout, re.M) if details and details.returncode == 0 else None
        access = re.search(r"^access:\s+(\S+)", policy.stdout, re.M) if policy and policy.returncode == 0 else None
        connected = inspect(["profile", "test", label]) if enabled == "true" else None
        status = "已停用" if enabled == "false" else ("成功" if connected and connected.returncode == 0 else "失敗／逾時")
        print(" | ".join([label, kind, enabled, access.group(1).strip("\"'") if access else "未知",
                          state.group(1) if state else "未知", status]), flush=True)


def verify(app, java):
    command = [java, "-jar", str(app / "lib/ai-db-mcp.jar"), "start", "--config-dir", str(config_directory())]
    if os.environ.get("AI_DB_MCP_KEY_PROVIDER"):
        command += ["--key-provider", os.environ["AI_DB_MCP_KEY_PROVIDER"]]
    profiles = probe(command)
    print("\nDB／MCP 驗證通過。重開 client 重新載入工具清單。")
    return profiles


if __name__ == "__main__":
    try:
        app = Path(sys.argv[1]).resolve()
        java = sys.argv[2]
        if len(sys.argv) > 3 and sys.argv[3] == "--status":
            show_status(app, java)
        else:
            profiles = verify(app, java)
            from register_defaults import offer
            offer(app, java, profiles)
    except (OSError, RuntimeError, ValueError, KeyError, EOFError, KeyboardInterrupt) as error:
        print("\n[未完成] " + str(error) + "\n設定可能已儲存，但 DB／MCP 尚未全部驗證通過。", file=sys.stderr)
        sys.exit(1)
