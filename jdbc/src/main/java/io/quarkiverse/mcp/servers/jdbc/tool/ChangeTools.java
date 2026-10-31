package io.quarkiverse.mcp.servers.jdbc.tool;

import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkiverse.mcp.server.Tool;
import io.quarkiverse.mcp.server.ToolArg;
import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.change.ChangeRequest;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;

/** The two approved write tools. Structured single-table changes only; there is no tool that accepts SQL for writing. */
@ApplicationScoped
public class ChangeTools {

    @Inject
    GatewayServices services;

    @Tool(name = "db_preview_change", description = "Preview ONE structured INSERT, UPDATE or DELETE on a single table. Nothing is changed. "
            + "UPDATE and DELETE need at least one condition (equality on column values, combined with AND). "
            + "The result lists the affected rows and a previewId. A person must then approve it with 'ai-db-mcp approve <previewId>' "
            + "in a terminal; you cannot approve it yourself.")
    String db_preview_change(
            @ToolArg(description = "Profile id or label") String profileId,
            @ToolArg(description = "INSERT, UPDATE or DELETE") String operation,
            @ToolArg(description = "Schema name") String schema,
            @ToolArg(description = "Table name") String table,
            @ToolArg(description = "Column to new value (INSERT and UPDATE)", required = false) Map<String, Object> values,
            @ToolArg(description = "Column to required value, all must match (UPDATE and DELETE)", required = false) Map<String, Object> conditions) {
        io.quarkiverse.mcp.servers.jdbc.app.ToolMode.requireWrite();
        Operation op;
        try {
            op = Operation.valueOf(operation == null ? "" : operation.strip().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ToolCallException("operation must be INSERT, UPDATE or DELETE", null);
        }
        return services.changes().preview(new ChangeRequest(profileId, op, schema, table, values, conditions));
    }

    @Tool(name = "db_execute_change", description = "Execute a previewed change. Requires the one-time confirmationToken that the USER obtained by running "
            + "'ai-db-mcp approve <previewId>'. Never invent a token; without a real one the change is refused.")
    String db_execute_change(
            @ToolArg(description = "Profile id or label") String profileId,
            @ToolArg(description = "previewId returned by db_preview_change") String previewId,
            @ToolArg(description = "One-time token given to you by the user") String confirmationToken) {
        io.quarkiverse.mcp.servers.jdbc.app.ToolMode.requireWrite();
        return services.changes().execute(profileId, previewId, confirmationToken);
    }
}
