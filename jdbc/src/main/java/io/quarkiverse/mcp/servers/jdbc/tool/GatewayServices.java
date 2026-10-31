package io.quarkiverse.mcp.servers.jdbc.tool;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.app.GatewayRuntime;
import io.quarkiverse.mcp.servers.jdbc.audit.AuditService;
import io.quarkiverse.mcp.servers.jdbc.change.ChangeService;

/**
 * Builds the tool services once, from the context that {@code start} validated. If the runtime was not initialised, every
 * tool refuses rather than running with defaults.
 */
@ApplicationScoped
public class GatewayServices {

    private volatile QueryService queries;
    private volatile ChangeService changes;
    private volatile io.quarkiverse.mcp.servers.jdbc.change.TemplateService templates;

    private synchronized void init() {
        if (queries != null) {
            return;
        }
        if (!GatewayRuntime.isReady()) {
            throw new ToolCallException("The gateway is not initialised", null);
        }
        var ctx = GatewayRuntime.get();
        ToolGateway gateway = new ToolGateway(ctx, new AuditService(ctx.paths.logsDir()));
        changes = new ChangeService(gateway, ctx.approvals);
        templates = new io.quarkiverse.mcp.servers.jdbc.change.TemplateService(gateway);
        queries = new QueryService(gateway);
    }

    public QueryService queries() {
        if (queries == null) {
            init();
        }
        return queries;
    }

    public ChangeService changes() {
        if (changes == null) {
            init();
        }
        return changes;
    }

    public io.quarkiverse.mcp.servers.jdbc.change.TemplateService templates() {
        if (templates == null) {
            init();
        }
        return templates;
    }
}
