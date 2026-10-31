package io.quarkiverse.mcp.servers.jdbc.tool;

import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkiverse.mcp.server.Tool;
import io.quarkiverse.mcp.server.ToolArg;
import io.quarkiverse.mcp.servers.jdbc.app.ToolMode;

@ApplicationScoped
public class TemplateTools {
    @Inject
    GatewayServices services;

    @Tool(name = "db_list_change_rules", description = "WRITE MCP: call first to discover allowed tables and fixed SQL templates, parameter order/types, and affected-row limits. Table rules require approval; pre-approved SQL templates do not.")
    String rules(@ToolArg(description = "Profile id or label") String profileId) {
        ToolMode.requireWrite();
        return services.templates().rules(profileId);
    }

    @Tool(name = "db_execute_template", description = "WRITE MCP: execute an administrator-preapproved fixed UPDATE template. Supply only templateId and params in the order from db_list_change_rules; never supply SQL. No per-run approval required. Transaction rolls back if validation or affected-row limits fail. Do not retry writes automatically.")
    String execute(@ToolArg(description = "Profile id or label") String profileId,
            @ToolArg(description = "Exact templateId from db_list_change_rules") String templateId,
            @ToolArg(description = "Scalar values in placeholder order") List<Object> params) {
        ToolMode.requireWrite();
        return services.templates().execute(profileId, templateId, params);
    }
}
