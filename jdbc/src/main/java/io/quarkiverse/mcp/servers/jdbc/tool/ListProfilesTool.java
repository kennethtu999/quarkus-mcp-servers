package io.quarkiverse.mcp.servers.jdbc.tool;

import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkiverse.mcp.server.Tool;
import io.quarkiverse.mcp.server.ToolArg;

/**
 * The approved read-side MCP tools. They only forward to {@link QueryService}; every decision lives there so tests do not
 * need Quarkus. The write tools live in {@code ChangeTools}.
 */
@ApplicationScoped
public class ListProfilesTool {

    @Inject
    GatewayServices services;

    private QueryService service() {
        return services.queries();
    }

    @Tool(name = "db_list_profiles", description = "List the configured database profiles with their label, type, connection status and access mode. Never returns connection details or credentials.")
    String db_list_profiles() {
        return service().listProfiles();
    }

    @Tool(name = "db_list_tables", description = "List tables and views of a profile (system schemas are hidden), paged. Use profileId from db_list_profiles.")
    String db_list_tables(
            @ToolArg(description = "Profile id or label") String profileId,
            @ToolArg(description = "Schema name to filter on", required = false) String schema,
            @ToolArg(description = "Page number starting at 1", required = false) Integer page,
            @ToolArg(description = "Tables per page (max 200, default 50)", required = false) Integer size) {
        return service().listTables(profileId, schema, page, size);
    }

    @Tool(name = "db_describe_table", description = "Describe the columns of one table.")
    String db_describe_table(
            @ToolArg(description = "Profile id or label") String profileId,
            @ToolArg(description = "Schema name") String schema,
            @ToolArg(description = "Table name") String table) {
        return service().describeTable(profileId, schema, table);
    }

    @Tool(name = "db_query", description = "Run ONE read-only SELECT. At most 500 rows are ever returned per call; this limit cannot be raised. "
            + "Use ? placeholders and pass values in params. No comments, no multiple statements, no locking clauses.")
    String db_query(
            @ToolArg(description = "Profile id or label") String profileId,
            @ToolArg(description = "A single SELECT statement") String sql,
            @ToolArg(description = "Values for ? placeholders, in order", required = false) List<Object> params,
            @ToolArg(description = "Maximum rows to return (1-500; larger values are reduced to 500)", required = false) Integer maxRows) {
        return service().query(profileId, sql, params, maxRows);
    }
}
