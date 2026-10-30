package io.quarkiverse.mcp.servers.jdbc.cli;

import java.util.concurrent.Callable;

import io.quarkiverse.mcp.servers.jdbc.app.GatewayApp;
import io.quarkus.runtime.Quarkus;
import picocli.CommandLine.Command;

/**
 * Starts the stdio MCP server. Later work packages add config-dir resolution, master-key loading and policy
 * validation here, all of which must complete before Quarkus is started so that a failure never leaves a half
 * initialised server answering tool calls.
 */
@Command(name = "start", description = "Start the MCP server on stdio")
public class StartCommand implements Callable<Integer> {

    @Override
    public Integer call() {
        Quarkus.run(GatewayApp.class);
        return 0;
    }
}
