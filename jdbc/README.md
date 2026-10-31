# AI Database MCP Gateway

## 中文快速使用

這是本機 stdio MCP，支援 Db2 LUW、PostgreSQL、Oracle 的測試資料庫。安裝包已包含 JDBC driver（Db2 bundled 版）。
準備 Java 17+、Python 3，將完整 ZIP 解壓到固定目錄後執行：

```sh
cd /你的安裝位置/dbmcp
sh onboarding.sh
```

onboarding 先顯示既有 DB 狀態，再顯示兩組 sample（READ、UPDATE＋TABLE＋SQL）供整段貼上，最後驗證 MCP 與實際 DB。
驗證後可選註冊到預設 Codex、Claude、Pi、OpenCode（可複選，`0` 略過）。只使用預設使用者設定，不處理 `~/bin/*.sh` 或自訂設定位置；OpenCode 合併前會備份並保留其他設定。

純查詢 sample（第一行的順序：Label、DB 類型、JDBC URL、帳號、Schema、密碼）：

```text
MY-DEV##DB2_LUW##jdbc:db2://db.example:60000/TESTDB##dbuser##APP##你的密碼
TLS=OFF
ACCESS=READ_ONLY
MAX_ROWS=100
OVERRIDE=NO
END
```

整段貼入程式提示，不要貼到 shell 指令列；內容不回顯。密碼可含 `##`；前五欄不可含 `##`。
省略第一行最後的 `##密碼` 可再隱藏輸入密碼。`END` 結束這一組 DB 的設定。

- `TLS=ON` 是預設，JDBC URL 必須啟用 TLS；無 TLS 的測試 DB 才填 `OFF`。
- `ACCESS=READ_ONLY` 是預設；有更新規則時填 `UPDATE`。
- `MAX_ROWS` 可設 1–500，預設 500；程式強制限制回傳筆數，AI 不能提高上限。
- `OVERRIDE=YES` 整組取代同名 DB 的連線與權限，保留 profileId 與啟用狀態；預設 `NO`，重名即拒絕。驗證失敗不取代舊設定。

多表與固定 SQL 可在同一段設定，後面的設定行例如：

```text
TLS=OFF
ACCESS=UPDATE
MAX_ROWS=500
OVERRIDE=YES
UPDATE=APP.CUSTOMERS,APP.PAYMENTS
SQL=order_status##UPDATE APP.ORDERS SET STATUS=? WHERE ORDER_ID=?
SQL=order_note##UPDATE APP.ORDERS SET NOTE=? WHERE ORDER_ID=? AND VERSION=?
END
```

`UPDATE=` 可有多行，允許指定資料表的結構化 UPDATE，需 preview → 人工 approve → execute。
`SQL=` 可有多行，固定範本在設定成功後即預先授權，**執行免逐次審核**。AI 只能提供範本名稱與參數，不能傳入或更改 SQL。
第一版 SQL 僅支援單表 UPDATE、`SET COL=?`、至少一個 `WHERE KEY=?`，多條件用 AND；不接受函式、JOIN、OR、子查詢、註解、分號或其他 SQL 語法。
若只要固定 SQL 的權限，就不要再對同一張表宣告整表 `UPDATE=`。
異動預設最多 100 筆，超過會拒絕／回滾。查詢上限 500 是回傳上限，DB 可能多讀一筆判斷截斷，不是資料庫掃描量上限。

完整可修改 sample：`setup.example.txt`、`setup-update.example.txt`、`setup-sql.example.txt`、`setup-combined.example.txt`。
權限 YAML 範例：`sample.yaml`。不需要手動複製 sample；onboarding 會產生並啟用真正的權限檔。

## 接入 MCP：給其他工具／AI 的設定說明

使用 **stdio**，由 client 啟動 Java 程序，不需先開 HTTP server。請將範例中的 `/ABS_PATH/ai-db-mcp` 換成這個解壓目錄的實際絕對路徑；
Java 也建議使用完整路徑。不要在 client 設定加入 DB 帳號、密碼或 JDBC URL。保留 client 原有設定，只合併下列 entry。

| 入口名稱 | 啟動參數 | 可用工具 |
|---|---|---|
| `dbmcp`（目前純讀） | `start` | `db_list_profiles`、`db_list_tables`、`db_describe_table`、`db_query` |
| 同一個 `dbmcp`（有允許更新的 DB） | 同一個 `start` | 上述查詢工具，加上 `db_list_change_rules`、`db_execute_template`、`db_preview_change`、`db_execute_change` |

一律只註冊 **`dbmcp`**。`start` 預設 `auto`，依允許的 Profile 權限提供 4 或 8 個工具；停用、無效或範圍外的 Profile 不會啟用異動工具。各次操作仍逐一驗證目標 DB 的政策。
修改 DB 權限後重開／重新連線 MCP 讓 client 更新工具清單，不需要改註冊名稱或重新註冊。
onboarding 註冊會更新 `dbmcp` 並移除該 client 預設設定中的舊別名 `ai-db-mcp`、`ai-db-read`、`ai-db-write`，保留其他 MCP 和既有 `--profiles` 限制；JSON 設定修改前會備份。新設定啟動驗證失敗時不會清除舊別名。
手動專案設定若仍用舊別名，也請改成相同的 `dbmcp` 名稱。進階用途仍可指定 `--mode read` 或 `--mode write`，但一般註冊不固定模式。

Claude Desktop／其他使用 `mcpServers` JSON 的 client：

```json
{
  "mcpServers": {
    "dbmcp": {
      "command": "/ABS_PATH/jdk/bin/java",
      "args": ["-jar", "/ABS_PATH/dbmcp/lib/ai-db-mcp.jar", "start"]
    }
  }
}
```

Codex 使用的 `config.toml`：

```toml
[mcp_servers.dbmcp]
command = "/ABS_PATH/jdk/bin/java"
args = ["-jar", "/ABS_PATH/dbmcp/lib/ai-db-mcp.jar", "start"]
startup_timeout_sec = 30
```

OpenCode 在 `mcp` 下只建立 `dbmcp`，entry 為 `{"type":"local","command":["/ABS_PATH/jdk/bin/java","-jar","/ABS_PATH/dbmcp/lib/ai-db-mcp.jar","start"],"enabled":true}`。
新版 Pi（已核對 1.4.0）支援原生 `pi mcp add`，使用 `~/.pi/agent/mcp.json`；舊版不支援時會提示升級。使用者自訂啟動腳本／設定檔位置由 client 自己處理，onboarding 不介入。
Windows 可使用 `C:/.../java.exe` 與 `C:/.../ai-db-mcp.jar` 路徑。

AI 先呼叫 `db_list_profiles` 查看實際權限；需要異動時，再呼叫 `db_list_change_rules(profileId)`。
規則清單會提供允許的表／SQL、參數順序、JDBC 型別、size、scale、nullable。Metadata 即時讀取，執行時再驗證，商業值限制不會從欄位型別自動推論。

固定 SQL 的呼叫範例：`db_execute_template`，參數為：

```json
{"profileId":"MY-DEV","templateId":"order_status","params":["CANCELLED","ORD001"]}
```

client 接入後重開工作階段，確認工具清單符合上表，再列 Profile／查資料；onboarding 的驗證只證明 Gateway／DB 有效，不能代替 client 本身的接入驗證。

## 不同專案使用不同 DB

DB 帳密仍共用加密儲存；每個專案的 MCP 加上 `--profiles`，只列出並允許指定 DB，直接指定其他 DB 的名稱或 ID 也會拒絕。
多組可用逗號分隔，如 `--profiles MY-DEV,MY-SIT`。省略時允許所有 Profile。

Codex：在專案的 `.codex/config.toml` 放入（需信任該專案）：

```toml
[mcp_servers.dbmcp]
command = "/ABS_PATH/jdk/bin/java"
args = ["-jar", "/ABS_PATH/dbmcp/lib/ai-db-mcp.jar", "start", "--profiles", "PROJECT-A-DEV"]
```

Claude Code：在專案的 `.mcp.json` 放入：

```json
{
  "mcpServers": {
    "dbmcp": {
      "command": "/ABS_PATH/jdk/bin/java",
      "args": ["-jar", "/ABS_PATH/dbmcp/lib/ai-db-mcp.jar", "start", "--profiles", "PROJECT-A-DEV"]
    }
  }
}
```

B 專案改成 `PROJECT-B-DEV`。專案與全域都使用相同的 `dbmcp` 名稱，讓專案設定覆蓋全域 entry；清掉專案中舊的 `ai-db-read`／`ai-db-write` 別名，避免另一入口不受此範圍限制。
如使用非預設 Gateway 設定目錄或 key file，專案 entry 須沿用對應的 `--config-dir`／`--key-provider`。
Pi 可在專案 `.pi/mcp.json` 使用相同 `mcpServers` 格式；OpenCode 用專案 `opencode.json` 的 `mcp` 格式，加上同樣的 `--profiles` 啟動參數。

## 設定放在哪裡

- macOS：`~/Library/Application Support/ai-db-mcp/`
- Linux：`${XDG_CONFIG_HOME:-~/.config}/ai-db-mcp/`
- Windows：`%LOCALAPPDATA%/ai-db-mcp/`

首次建立 key 會寫入後讀回驗證；只有確認 key 不存在才建立。存取失敗或 key 損壞時停止，不覆蓋既有資料。錯誤會在 stderr 保留原因分類、例外類型與堆疊，但不輸出原生訊息中的機敏內容。

`profiles.enc` 是加密連線，`permissions/permissions_<LABEL>.yaml` 是權限，`logs/audit.jsonl` 是紀錄；主密鑰預設放 OS key store。

Audit 紀錄最多保留 7 天，每次寫入時自動刪除過期紀錄（包含目前檔案及輪替檔）；停止使用期間不執行清理，下次操作時補清。單檔達 10 MiB 會輪替，另外最多保留 10 個輪替檔，因此大量使用時可能少於 7 天。
可用 `AI_DB_MCP_CONFIG_DIR` 改位置；RHEL／Ubuntu 無 Secret Service，或預設 collection 不可用而在首次 `createItem` 寫入發生套件 NPE 時，首次初始化會自動將 master key 存到 `~/.config/dbmcp/master-<設定目錄摘要>.key`（目錄 0700、檔案 0600），之後固定沿用；不受解壓位置影響，專案與 client 不需設定環境變數或 `--key-provider`。也可明確指定 `AI_DB_MCP_KEY_PROVIDER=keyfile:/外部安全位置/master.key`。
所有管理命令與 MCP 程序必須使用同一設定目錄、key provider 及可存取密鑰的 OS 使用者；自訂目錄可在每個 MCP 的 `args` 加入 `--config-dir`、`--key-provider`。
設定不在 ZIP 解壓目錄，換程式版本不會清掉連線。每人自己初始化，不共用 master key。Linux 自動 key file 請另行備份；遺失後不能只靠 `profiles.enc` 還原。
DB MCP 本身沒有管理設定的工具；若 AI 另有同帳號的 shell／檔案權限，仍可能改設定，不能視為 OS 權限隔離。

---

A Model Context Protocol (MCP) server that lets an AI assistant query, and in a controlled way modify, **test data** in
IBM Db2 LUW, PostgreSQL and Oracle databases - while the assistant never sees a database password.

**安裝、Codex / Claude 接入與團隊交付： [繁體中文操作步驟](docs/QUICKSTART.zh-TW.md)。**

macOS/Linux：解壓後執行 `sh onboarding.sh`，依提示設定與驗證 DB；client 接入方式見上方。

Create a portable distribution after building: `python3 jdbc/scripts/package.py` (from the repository root).
Extract `jdbc/target/dbmcp-local.zip`, then run `bin/ai-db-mcp` (`bin/ai-db-mcp.cmd` on Windows).
The `ai-db-mcp` commands below refer to this launcher; add its `bin` directory to PATH or use its absolute path.

> **Scope:** DEV / SIT / UAT databases on a single trusted workstation, over stdio. Not for production data and not a
> multi-user service. See [docs/SECURITY.md](docs/SECURITY.md) for exactly what it does and does not protect against, and
> [docs/RISKS.md](docs/RISKS.md) for what has **not yet been verified against real Db2 / PostgreSQL / Oracle servers**.

This module started from the upstream Quarkiverse JDBC MCP server but is a rewrite (see [docs/UPSTREAM.md](docs/UPSTREAM.md)).
The upstream arbitrary-SQL tools (`read_query`, `write_query`, `create_table`) and the launcher that took `-p <password>`
on the command line were removed on purpose.

## What the assistant can do

Register one stable server name, **dbmcp**, with `start` (default mode: `auto`). It exposes four query tools when all
allowed profiles are read-only, or eight tools when an enabled, active, in-scope profile permits writes. Each operation
still enforces its own profile policy. Reconnect after policy changes to refresh the client's tool catalog; no rename
or re-registration is needed. Explicit `--mode read` and `--mode write` remain supported for advanced restrictions.
`ToolSurfaceTest` checks the eight approved tools; runtime filtering and write entry-point checks enforce availability.

| Tool | Purpose |
|---|---|
| `db_list_profiles` | Profiles with label, type, connection and policy status, access mode. Never URLs or credentials. |
| `db_list_tables` | Tables and views (system schemas hidden), paged. |
| `db_describe_table` | Columns of one table. |
| `db_query` | **One** read-only `SELECT`. **At most 500 rows per call - this cannot be raised.** |
| `db_preview_change` | Structured single-table `INSERT` / `UPDATE` / `DELETE`. Changes nothing; returns what would change. |
| `db_execute_change` | Runs a previewed change, only with a one-time token that **you** obtained. |
| `db_list_change_rules` | Write endpoint: lists table rules, SQL template IDs and live parameter metadata. |
| `db_execute_template` | Write endpoint: runs a pre-approved fixed UPDATE template by ID and bound parameters, without per-run approval. |

There is no tool that accepts SQL for writing, no DDL, no stored procedures, and no tool to change profiles or policies.
SQL templates are declared only by the administrator during onboarding (`SQL=id##UPDATE ...`). They allow a restricted
single-table UPDATE with parameterized assignments and mandatory equality conditions joined by AND. They do not grant
generic table write access. Parameters are validated against current JDBC metadata and bound to prepared statements;
template executions roll back on errors or affected-row overflow (default 100), and are never automatically retried.

Use `sh onboarding.sh` to paste a complete connection/policy block. It displays existing DB status, supports explicit
`OVERRIDE=YES` and enforces `MAX_ROWS=1..500`. Default client registration is optional; project-specific examples are above.
See `setup.example.txt`, `setup-update.example.txt`, `setup-sql.example.txt` and `setup-combined.example.txt` in the ZIP.

## Install and build

```shell
./mvnw -pl jdbc -am verify          # unit + service tests (H2 based, no external database needed)
java -jar jdbc/target/mcp-server-jdbc-999-SNAPSHOT.jar --help
```

Requires Java 17 or newer. The PostgreSQL and Oracle JDBC drivers are bundled. **IBM Db2 JCC is not** (its licence restricts
redistribution): download it yourself and see [Db2](#db2) below.

For an internal distribution permitted to include IBM JCC, build a fat JAR with both Db2 JCC and the existing
PostgreSQL / Oracle drivers:

```shell
./mvnw -pl jdbc -am verify -Pbundle-db2
python3 jdbc/scripts/package.py --bundled-db2
```

The Db2 profile declares `com.ibm.db2:jcc:12.1.5.0` through Maven; no Gradle cache path or manual driver pin is needed
at runtime. Oracle continues to use the BOM-managed `ojdbc11` dependency for Java 17 compatibility.
Confirm IBM driver redistribution rights before sharing this bundled build.

## First-time setup

```shell
ai-db-mcp init
```

Asks for a label (for example `DB2-DEV`), the database type (`DB2_LUW`, `POSTGRESQL` or `ORACLE`), the JDBC URL, username and
password (typed without echo), tests the connection, and stores everything encrypted. Repeat with `ai-db-mcp profile add`.

Where things live (override with `--config-dir <path>` or `AI_DB_MCP_CONFIG_DIR`):

| OS | Default |
|---|---|
| macOS | `~/Library/Application Support/ai-db-mcp/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/ai-db-mcp/` |
| Windows | `%LOCALAPPDATA%\ai-db-mcp\` |

```text
profiles.enc                      all connections, AES-256-GCM encrypted
permissions/permissions_<LABEL>.yaml   one policy per profile (you edit these)
policy-manifest.json              which policy version you activated (signed)
settings.yaml                     pinned external driver digests (no secrets)
approvals/                        pending / granted / used change approvals
logs/audit.jsonl                  audit log (hash chained, no secrets)
backups/                          previous profiles.enc generations
drivers/                          external JDBC jars, e.g. IBM JCC
```

The master key that decrypts `profiles.enc` is kept in the **OS key store** (macOS Keychain, Windows Credential Manager, Linux
Secret Service). On RHEL/Ubuntu without an available Secret Service, first initialization automatically creates an owner-only key file in `~/.config/dbmcp/`. Its filename includes the configuration directory digest; subsequent runs keep using that file even if Secret Service becomes available. Existing ciphertext with a lost key, access denied, or malformed keys never triggers replacement. An explicit external key file remains available:

```shell
ai-db-mcp init --key-provider keyfile:/safe/place/outside/config/master.key
```

Every command that opens the store needs the same `--config-dir` / `--key-provider` options. There is **no option anywhere to
pass a password, token or key on the command line**; passwords are read from the terminal, or one line at a time from stdin with
`--password-stdin` for automation.

### JDBC URLs

TLS with certificate verification is required by default, and only a strict set of URL forms and properties is accepted:

| Database | Accepted form |
|---|---|
| PostgreSQL | `jdbc:postgresql://host:5432/db?sslmode=verify-full` |
| Db2 LUW | `jdbc:db2://host:50000/DB:sslConnection=true;` |
| Oracle | `jdbc:oracle:thin:@tcps://host:1521/service` |

URLs may not contain credentials, driver class names, socket factories, trace files or TNS descriptors. A cleartext URL needs
the explicit administrator flag `--allow-insecure-tls`.

### Db2

Place the IBM `jcc` jar in `<config-dir>/drivers/` (create it with mode 0700), then trust it by recording its digest:

```shell
ai-db-mcp driver pin db2jcc4.jar      # prints the SHA-256; compare it with the checksum IBM publishes
ai-db-mcp driver list
```

A jar is only ever loaded if its SHA-256 matches a pin, so a swapped or newly dropped-in jar is ignored. Internal builds licensed
to redistribute JCC can bundle it with `-Pbundle-db2` instead.

## Permissions

Every profile starts as `READ_ONLY`. Edit `permissions/permissions_<LABEL>.yaml`, then:

```shell
ai-db-mcp policy validate DB2-DEV     # checks the file (and, online, that the tables exist)
ai-db-mcp policy reload DB2-DEV       # makes it the active policy
```

**Editing a file does nothing by itself.** Until you `reload`, that profile refuses *every* operation (`POLICY_STALE`) - it never
falls back to the old policy or to a more permissive one. A missing, unparsable or mismatching file has the same effect.

| `access` | `SELECT` | `INSERT` / `UPDATE` / `DELETE` |
|---|---|---|
| `READ_ONLY` | up to 500 rows | refused |
| `READ_WRITE` | up to 500 rows | in `allowedSchemas`, for the listed `operations` |
| `READ_WRITE_WHITELIST` | up to 500 rows | only listed `schema` + `table` + `operations` |

```yaml
version: 1
profile: ORA-SIT
profileId: c3d4e5f6-1234-4567-89ab-333333333333   # printed by `ai-db-mcp profile show ORA-SIT`
access: READ_WRITE_WHITELIST
read:
  maxRows: 500          # 1-500, can only be lowered
  timeoutSeconds: 30
write:
  maxAffectedRows: 100  # most rows one change may touch
  whitelist:
    - { schema: APP, table: ORDERS,    operations: [INSERT, UPDATE] }
    - { schema: APP, table: CUSTOMERS, operations: [UPDATE] }
```

Unknown keys, wildcards, duplicate entries, YAML anchors/aliases/tags, a `profile`/`profileId` that does not match, and
`requireConfirmation: false` are all rejected. A policy only ever **narrows** what the database account itself may do; it
cannot grant anything the database does not.

## Changing data (the approval step)

1. The assistant calls `db_preview_change`. Nothing changes; it gets the affected row count, the current values and a `previewId`.
2. **You** run, in a terminal: `ai-db-mcp approve <previewId>`. It shows the change and asks you to type a short code. It refuses
   to run from a script or a pipe.
3. It prints a one-time token. Give it to the assistant.
4. The assistant calls `db_execute_change` with the token. The gateway re-checks the policy, locks the rows, verifies the data
   has not changed since the preview and that the row count is the one you approved, applies the change in one transaction, and
   commits - or rolls everything back. Writes are never retried.

A token works once, expires after 2 minutes, is bound to that exact change, policy version and data, and five wrong guesses
revoke the preview. The assistant cannot create or forge one: it has no key and no access to the approval files.

This token flow applies to **table rules and structured changes**. Explicit SQL templates with `autoExecute: true`
are approved once when configured; `db_execute_template` needs no approval token. `db_list_change_rules` reports the
distinction and parameter order, JDBC type, size, scale and nullability. Metadata is read live during discovery and
checked again during execution; it is not a stale startup cache. Business value allowlists are not inferred from JDBC.

## Use it from an MCP client

```json
{
  "mcpServers": {
    "dbmcp": {
      "command": "java",
      "args": ["-jar", "/path/to/mcp-server-jdbc-999-SNAPSHOT.jar", "start"]
    }
  }
}
```

Add `"--config-dir", "/your/dir"` (and `"--key-provider", "keyfile:..."` if used) to `args`. The client configuration contains no
URL, user name or password. `start` refuses to run - and changes no file - if the master key is missing or `profiles.enc` does
not decrypt.

## Maintenance

| Task | Command |
|---|---|
| List / inspect | `ai-db-mcp profile list`, `profile show <L>`, `policy show <L>` |
| Test a connection | `ai-db-mcp profile test <L>` |
| Change a password | `ai-db-mcp profile rotate-password <L>` (the new one is tested before the old one is replaced) |
| Rename | `ai-db-mcp profile rename <OLD> <NEW>` (policy file moves with it; the immutable `profileId` does not change) |
| Disable / enable / remove | `profile disable <L>`, `profile enable <L>`, `profile remove <L>` (the policy file is kept) |

**Changes take effect in a running server immediately.** `profile disable`, `rotate-password`, `rename`, `remove` and `add` rewrite
`profiles.enc`; a running `start` notices before its next tool call and rebuilds the affected connection pools. If `profiles.enc`
cannot be read at that moment (key gone, file damaged) the server refuses everything until it can, rather than continuing with the
last copy it had - a profile you just disabled must not keep working.

Administrative commands that change state (`init`, `profile add/rotate-password/rename/enable/disable/remove`, `policy reload`,
`key rotate`, `backup restore`, `driver pin/unpin`, `approve`) are recorded in `logs/audit.jsonl`, together with the tool calls.
Only the command and its first argument (a label) are recorded - never an option value.
| Trust a Db2 driver jar | `ai-db-mcp driver pin <jar>`, `driver list`, `driver unpin <jar>` |
| Rotate the master key | `ai-db-mcp key rotate` (re-encrypts, then reloads all policies; pending approvals become invalid) |
| Back up | `ai-db-mcp backup create <dir>` - **back up the master key separately** |
| Restore | `ai-db-mcp backup restore <dir> [--dry-run]` into an empty configuration directory |

Run `backup restore --dry-run` on a spare machine once, with the key, to prove your backup actually opens.

## Troubleshooting

| Symptom | Cause / action |
|---|---|
| `Cannot start: Master key is not available` | The key store entry or key file is gone. Restore the key. **Nothing was modified.** |
| `Cannot start: Decryption failed` | Wrong key, or `profiles.enc` was altered. Restore the key or `backups/profiles.enc.bak`. |
| `no usable policy (POLICY_STALE)` | You edited the YAML; run `policy validate` then `policy reload`. |
| `no usable policy (POLICY_INVALID)` | The YAML is missing, unreadable, group/world accessible, or wrong; `policy validate` explains. |
| `PROFILE_UNAVAILABLE` | The database could not be connected; other profiles keep working. Retries back off up to 2 minutes. |
| `JDBC driver ... is not available` | Db2: put the JCC jar in `drivers/` (see above). |
| `approve needs an interactive terminal` | By design. Run it yourself in a terminal. |
| `The preview has expired` | Previews live 2 minutes. Ask the assistant to preview again. |

Key failures always print a diagnostic reason (`NOT_FOUND`, `ACCESS_FAILED`, `BACKEND_UNAVAILABLE`, `INVALID_KEY`) and cause/stack trace to stderr. Native exception messages are omitted to avoid exposing secrets. `AI_DB_MCP_DEBUG=1` enables the same sanitized trace for other command failures.
