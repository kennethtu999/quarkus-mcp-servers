# Upstream tracking

The `jdbc` module is a security-focused rewrite of the upstream
[quarkiverse/quarkus-mcp-servers](https://github.com/quarkiverse/quarkus-mcp-servers) JDBC server.
It is developed against `AI_Database_MCP_Gateway_Execution_Plan_v2.3.md`.

| Item | Value |
|---|---|
| Upstream remote | `https://github.com/quarkiverse/quarkus-mcp-servers` (add as `upstream`) |
| Baseline commit | `96be32eba2b94ae597c6121bfb6b1619488182dc` (`chore(deps): bump Quarkus to 3.35.0.CR1 and MCP server to 1.11.1 (#92)`) |
| License | Apache-2.0 (root `LICENSE` is retained unchanged) |

## What was removed from upstream

`read_query`, `write_query`, `create_table`, `database_info`, the `er_diagram` / `sample_data` prompts, the
`.scripts/mcpjdbc.java` JBang launcher (it passed `-p` passwords on a child process command line) and
`.scripts/mcpservernodriver.java`.

## Merging upstream

Because `jdbc/` is rewritten, upstream changes to it will conflict. When merging:

1. Never accept a hunk that re-adds an arbitrary-SQL tool or a launcher that passes credentials as arguments.
2. Run `ToolSurfaceTest`; it fails if any tool outside the approved `db_*` list (or any prompt) is compiled in.
3. Re-run the full security test suite before tagging a release.
4. Update the baseline commit in this file.
