package io.quarkiverse.mcp.servers.jdbc.app;

import java.util.Set;

import jakarta.inject.Singleton;

import io.quarkiverse.mcp.server.FilterContext;
import io.quarkiverse.mcp.server.ToolFilter;
import io.quarkiverse.mcp.server.ToolManager.ToolInfo;

/** Enforced for both tools/list and tools/call, including calls to names hidden from discovery. */
@Singleton
public class ToolMode implements ToolFilter {
    public static final Set<String> READ = Set.of("db_list_profiles", "db_list_tables", "db_describe_table", "db_query");
    public static final Set<String> WRITE = Set.of("db_list_profiles", "db_list_change_rules", "db_execute_template",
            "db_preview_change", "db_execute_change");

    public static boolean allows(String mode, String name) {
        if ("auto".equals(mode)) {
            return READ.contains(name) || (writeEnabled() && WRITE.contains(name));
        }
        return ("write".equals(mode) ? WRITE : READ).contains(name);
    }

    public static boolean writeEnabled() {
        if ("write".equals(GatewayRuntime.mode())) {
            return true;
        }
        if (!"auto".equals(GatewayRuntime.mode()) || !GatewayRuntime.isReady()) {
            return false;
        }
        var ctx = GatewayRuntime.get();
        if (ctx.sync.refresh() != null) {
            return false;
        }
        for (var profile : ctx.registry.all()) {
            if (profile.enabled() && GatewayRuntime.allowsProfile(profile.label())) {
                var snapshot = ctx.policies.current(profile);
                if (snapshot.active() && snapshot.policy().access().allowsWrite()) {
                    return true;
                }
            }
        }
        return false;
    }

    public static void requireWrite() {
        if (!writeEnabled()) {
            throw new io.quarkiverse.mcp.server.ToolCallException(
                    "This MCP is currently READ ONLY. Configure an allowed write policy to enable modifications.",
                    null);
        }
    }

    @Override
    public boolean test(ToolInfo tool, FilterContext context) {
        return allows(GatewayRuntime.mode(), tool.name());
    }
}
