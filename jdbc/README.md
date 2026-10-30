# AI Database MCP Gateway

A Model Context Protocol (MCP) server that lets an AI agent query and (in a controlled way) modify test data in
IBM Db2 LUW, PostgreSQL and Oracle databases, with credentials that the AI never sees.

> **Status: under development.** Only the skeleton exists so far. The design and work breakdown are in
> `AI_Database_MCP_Gateway_Execution_Plan_v2.3.md`; see also [docs/UPSTREAM.md](docs/UPSTREAM.md) and
> [docs/RISKS.md](docs/RISKS.md).

This module started from the upstream Quarkiverse JDBC MCP server but is a rewrite. The upstream arbitrary-SQL tools
(`read_query`, `write_query`, `create_table`) and the launcher that accepted `-p <password>` on the command line have
been removed on purpose.

## Approved tool surface

| Tool | Purpose |
|---|---|
| `db_list_profiles` | List configured profiles (label, type, status). Never returns URLs or credentials. |
| `db_list_tables` | Tables the profile's policy allows (planned) |
| `db_describe_table` | Columns of an allowed table (planned) |
| `db_query` | Single read-only SELECT, at most 500 rows per call (planned) |
| `db_preview_change` | Structured single-table INSERT/UPDATE/DELETE preview (planned) |
| `db_execute_change` | Execute a previewed change with a one-time token (planned) |

`ToolSurfaceTest` fails the build if any other tool or any prompt is compiled into this module.

## Running

```shell
java -jar target/mcp-server-jdbc-999-SNAPSHOT.jar start
```

Credentials are never passed as command line arguments, JVM properties or environment variables.
