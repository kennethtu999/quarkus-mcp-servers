# DBMCP

讓 Codex、Claude Code、Pi、OpenCode 透過 MCP 查詢 Db2 LUW、PostgreSQL、Oracle 測試資料庫。預設唯讀，每次查詢最多回傳 500 筆；可另外設定允許更新的資料表與固定 SQL 範本。

## 打包

需要 JDK 17+、Python 3。在 repository 根目錄執行：

```sh
./mvnw -pl jdbc -am verify -Pbundle-db2
python3 -m unittest discover -s jdbc/scripts -p 'test_*.py'
python3 jdbc/scripts/smoke_stdio.py java -jar jdbc/target/mcp-server-jdbc-999-SNAPSHOT.jar
python3 jdbc/scripts/package.py --bundled-db2
```

產出：

```text
jdbc/target/dbmcp-local-db2.zip
jdbc/target/dbmcp-local-db2.zip.sha256
```

ZIP 解壓目錄為 `dbmcp/`，包含 fat JAR、onboarding、範例與使用說明。此版本已包含 Db2 JCC 12.1.5.0、PostgreSQL、Oracle JDBC driver。

## 初次使用

使用者需要 Java 17+、Python 3。將 ZIP 解壓到 HOME：

```sh
unzip dbmcp-local-db2.zip -d "$HOME"
cd "$HOME/dbmcp"
sh onboarding.sh
```

依提示貼上 DB 設定，最後輸入 `END`；程式會驗證 MCP 與實際 DB 連線，再讓你選擇註冊 Codex／Claude／Pi／OpenCode。註冊名稱固定為 `dbmcp`，會清除預設 client 設定中的舊名稱。

唯讀範例（依序為名稱、類型、JDBC URL、帳號、Schema、密碼）：

```text
MY-DEV##DB2_LUW##jdbc:db2://db.example:60000/TESTDB##dbuser##APP##你的密碼
TLS=OFF
ACCESS=READ_ONLY
MAX_ROWS=500
OVERRIDE=NO
END
```

整段貼入 onboarding，勿貼到 shell。`TLS=OFF` 用於沒有 TLS 的測試 DB；預設 `TLS=ON`，需使用啟用 TLS 的 JDBC URL。覆蓋既有連線改為 `OVERRIDE=YES`。
更新權限範例見 [setup-combined.example.txt](jdbc/setup-combined.example.txt)：表白名單需預覽與人工確認；固定 UPDATE SQL 範本設定後預先授權，AI 只填範本名稱與參數。

## 各專案指定 DB

Codex 在專案 `.codex/config.toml` 加入以下設定，保留原有設定：

```toml
[mcp_servers.dbmcp]
command = "/bin/sh"
args = ["-c", 'exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar "$HOME/dbmcp/lib/ai-db-mcp.jar" start --profiles MY-DEV']
startup_timeout_sec = 60

[mcp_servers.dbmcp.tools.db_list_profiles]
approval_mode = "approve"

[mcp_servers.dbmcp.tools.db_list_tables]
approval_mode = "approve"

[mcp_servers.dbmcp.tools.db_describe_table]
approval_mode = "approve"

[mcp_servers.dbmcp.tools.db_query]
approval_mode = "approve"
```

`approve` 表示預先允許該工具。`--profiles MY-DEV,MY-SIT` 可指定多組，不分大小寫；省略時允許所有已設定的 Profile。手動設定也應移除舊的 `ai-db-mcp`、`ai-db-read`、`ai-db-write` entry。
Claude 與其他 client 設定見 [完整使用說明](jdbc/README.md#接入-mcp給其他工具ai-的設定說明)。接入後重開 client，再要求：「使用 dbmcp 列出可用 DB 並查詢資料」。

## 執行與紀錄

- client 自動啟動 JAR，不需另外開服務；多個 client 各有獨立程序與連線池。
- 第一次操作才連 DB，每個程序、每個 Profile 最多 4 條連線；查完歸還池中，程序結束後釋放。
- 純執行只需 fat JAR 與 Java 17+；Python 3 用於 onboarding。
- macOS 設定在 `~/Library/Application Support/ai-db-mcp/`，不在解壓目錄。每人自行初始化，主密鑰預設存於 OS key store。RHEL／Ubuntu 無可用 Secret Service（含預設 collection 不可用導致首次寫入 NPE）時，首次初始化自動存到 `~/.config/dbmcp/master-<設定目錄摘要>.key`，目錄 0700、檔案 0600；之後固定沿用，專案不需設定 key provider。
- 操作紀錄在上述目錄的 `logs/audit.jsonl`，最多保留 7 天；每次寫入時補清過期紀錄。
- 啟動失敗訊息輸出到 stderr。macOS 若無法取得 master key，需檢查啟動環境的 Keychain 存取權。

升級時關閉 client，替換安裝目錄，再執行 onboarding 驗證；保留原本設定目錄。詳細權限與操作見 [jdbc/README.md](jdbc/README.md)。
