# AI Database MCP Gateway

A Model Context Protocol (MCP) server that lets an AI assistant query, and in a controlled way modify, **test data** in
IBM Db2 LUW, PostgreSQL and Oracle databases - while the assistant never sees a database password.

> **Scope:** DEV / SIT / UAT databases on a single trusted workstation, over stdio. Not for production data and not a
> multi-user service. See [docs/SECURITY.md](docs/SECURITY.md) for exactly what it does and does not protect against, and
> [docs/RISKS.md](docs/RISKS.md) for what has **not yet been verified against real Db2 / PostgreSQL / Oracle servers**.

This module started from the upstream Quarkiverse JDBC MCP server but is a rewrite (see [docs/UPSTREAM.md](docs/UPSTREAM.md)).
The upstream arbitrary-SQL tools (`read_query`, `write_query`, `create_table`) and the launcher that took `-p <password>`
on the command line were removed on purpose.

## What the assistant can do

The assistant is given exactly six tools. `ToolSurfaceTest` fails the build if any other tool or prompt is compiled in.

| Tool | Purpose |
|---|---|
| `db_list_profiles` | Profiles with label, type, connection and policy status, access mode. Never URLs or credentials. |
| `db_list_tables` | Tables and views (system schemas hidden), paged. |
| `db_describe_table` | Columns of one table. |
| `db_query` | **One** read-only `SELECT`. **At most 500 rows per call - this cannot be raised.** |
| `db_preview_change` | Structured single-table `INSERT` / `UPDATE` / `DELETE`. Changes nothing; returns what would change. |
| `db_execute_change` | Runs a previewed change, only with a one-time token that **you** obtained. |

There is no tool that accepts SQL for writing, no DDL, no stored procedures, and no tool to change profiles or policies.

## Install and build

```shell
./mvnw -pl jdbc -am verify          # unit + service tests (H2 based, no external database needed)
java -jar jdbc/target/mcp-server-jdbc-999-SNAPSHOT.jar --help
```

Requires Java 17 or newer. The PostgreSQL and Oracle JDBC drivers are bundled. **IBM Db2 JCC is not** (its licence restricts
redistribution): download it yourself and see [Db2](#db2) below.

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
Secret Service). Where none exists (headless Linux) use an explicit key file - never created silently:

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

## Use it from an MCP client

```json
{
  "mcpServers": {
    "ai-db-mcp": {
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

Set `AI_DB_MCP_DEBUG=1` to print stack traces (they can quote driver text; do not share them blindly).
