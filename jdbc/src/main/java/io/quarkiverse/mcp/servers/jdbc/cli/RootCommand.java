package io.quarkiverse.mcp.servers.jdbc.cli;

import picocli.CommandLine.Command;

@Command(name = "ai-db-mcp", mixinStandardHelpOptions = true, description = "AI Database MCP Gateway", subcommands = {
        StartCommand.class })
public class RootCommand implements Runnable {

    @Override
    public void run() {
        new picocli.CommandLine(this).usage(System.err);
    }
}
