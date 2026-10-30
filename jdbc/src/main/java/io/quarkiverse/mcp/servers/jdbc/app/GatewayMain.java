package io.quarkiverse.mcp.servers.jdbc.app;

import io.quarkiverse.mcp.servers.jdbc.cli.RootCommand;
import io.quarkus.runtime.annotations.QuarkusMain;
import picocli.CommandLine;

/**
 * Entry point of the AI Database MCP Gateway.
 * <p>
 * Arguments are parsed by picocli, not by the shared {@code McpCliConfigSource}, so values containing {@code =} are
 * handled correctly and nothing on the command line is ever turned into configuration. Only {@code start} boots
 * Quarkus; administrative commands run as a plain JVM process and never touch stdout used by the MCP transport.
 */
@QuarkusMain(name = "ai-db-mcp")
public class GatewayMain {

    public static void main(String[] args) {
        System.exit(new CommandLine(new RootCommand()).execute(args));
    }
}
