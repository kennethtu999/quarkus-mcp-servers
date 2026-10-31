#!/usr/bin/env python3
"""Read-only MCP verification using the user's real configuration, never disposable profiles."""
import json
import queue
import subprocess
import tempfile
import threading
import time

EXPECTED = {"db_list_profiles", "db_list_tables", "db_describe_table", "db_query"}
WRITE_TOOLS = {"db_list_profiles", "db_list_change_rules", "db_execute_template", "db_preview_change", "db_execute_change"}


def probe(command, env=None, check_database=True):
    mode = command[command.index("--mode") + 1] if "--mode" in command else "auto"
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=errors, text=True, bufsize=1, env=env)
        messages = queue.Queue()

        def read():
            for line in process.stdout:
                messages.put(line)
            messages.put(None)

        threading.Thread(target=read, daemon=True).start()
        request_id = 0

        def request(method, params=None):
            nonlocal request_id
            request_id += 1
            payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
            process.stdin.write(json.dumps(payload) + "\n")
            process.stdin.flush()
            deadline = time.monotonic() + 45
            while True:
                try:
                    line = messages.get(timeout=max(0, deadline - time.monotonic()))
                except queue.Empty:
                    raise RuntimeError("MCP 回應逾時（45 秒）") from None
                if line is None:
                    raise RuntimeError("MCP 提前結束；請檢查 Java、master key 與設定目錄")
                result = json.loads(line)
                if result.get("id") == request_id:
                    if "error" in result:
                        raise RuntimeError("MCP 請求失敗：" + method)
                    return result["result"]

        def tool(name, arguments):
            result = request("tools/call", {"name": name, "arguments": arguments})
            if result.get("isError"):
                raise RuntimeError("工具失敗：" + name + "；請執行 profile test 或 policy show 檢查")
            content = result.get("content", [])
            value = json.loads("".join(c.get("text", "") for c in content if c.get("type") == "text"))
            if isinstance(value, dict) and ("error" in value or value.get("decision") == "DENY"):
                raise RuntimeError("工具拒絕操作：" + name)
            return value

        try:
            request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                   "clientInfo": {"name": "onboarding-check", "version": "1.0"}})
            process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
            process.stdin.flush()
            tools = request("tools/list")
            profiles = tool("db_list_profiles", {})
            if not isinstance(profiles, list):
                raise RuntimeError("Profile 回應格式錯誤")
            enabled = [p for p in profiles if p.get("enabled")]
            expected = WRITE_TOOLS if mode == "write" else EXPECTED
            if mode == "auto" and any(p.get("policy") == "ACTIVE" and str(p.get("access", "")).startswith("READ_WRITE") for p in enabled):
                expected = EXPECTED | WRITE_TOOLS
            if {t["name"] for t in tools["tools"]} != expected:
                raise RuntimeError("工具清單與預期的讀／寫模式不符")
            print("[通過] " + mode + " MCP 握手與 " + str(len(expected)) + " 個工具")
            blocked = "db_execute_template" if expected == EXPECTED else ("db_query" if mode == "write" else "unregistered_sql_tool")
            rejected = False
            try:
                blocked_result = request("tools/call", {"name": blocked, "arguments": {}})
                rejected = blocked_result.get("isError") is True
            except RuntimeError:
                rejected = True
            if not rejected:
                raise RuntimeError("MCP 未拒絕另一模式的工具")
            if not enabled:
                raise RuntimeError("沒有已啟用的 DB Profile，尚不能查詢")
            for profile in enabled:
                label = profile["label"]
                if profile.get("policy") != "ACTIVE":
                    raise RuntimeError(label + " 權限尚未生效；請檢查 policy")
                print("[通過] " + label + " 權限：" + str(profile.get("access")))
                if check_database:
                    if mode == "write":
                        value = tool("db_list_change_rules", {"profileId": profile["profileId"]})
                        if not isinstance(value, dict) or "templates" not in value:
                            raise RuntimeError(label + " 無法讀取異動規則")
                        print("[通過] " + label + " 異動規則與 SQL 範本參數 Metadata（未執行寫入）")
                    else:
                        value = tool("db_list_tables", {"profileId": profile["profileId"], "size": 1, "page": 1})
                        if not isinstance(value, dict) or "tables" not in value:
                            raise RuntimeError(label + " 無法讀取資料表清單")
                        print("[通過] " + label + " 實際 DB 連線與唯讀 Metadata 查詢")
                        if mode == "auto" and "db_list_change_rules" in expected and str(profile.get("access", "")).startswith("READ_WRITE"):
                            tool("db_list_change_rules", {"profileId": profile["profileId"]})
                            print("[通過] " + label + " 異動規則與 SQL 範本參數 Metadata（未執行寫入）")
            return profiles
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()


if __name__ == "__main__":
    import sys
    try:
        probe(sys.argv[1:])
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print("[未通過] " + str(error), file=sys.stderr)
        sys.exit(1)
