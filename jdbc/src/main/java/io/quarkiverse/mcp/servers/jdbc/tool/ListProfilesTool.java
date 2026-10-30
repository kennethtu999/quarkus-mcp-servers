package io.quarkiverse.mcp.servers.jdbc.tool;

import io.quarkiverse.mcp.server.Tool;

public class ListProfilesTool {

    @Tool(name = "db_list_profiles", description = "List the configured database profiles (label, type and status). Never returns connection details or credentials.")
    String db_list_profiles() {
        // Placeholder until the profile registry exists (WP2.1); an empty list is the only safe answer.
        return "[]";
    }
}
