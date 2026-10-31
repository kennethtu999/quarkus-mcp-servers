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

    static {
        // This must precede picocli, keyring/JNA and any JUL logger, including plain `init`.
        System.setProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager");
    }

    public static void main(String[] args) {
        System.exit(commandLine().execute(args));
    }

    /**
     * Failures are reported as one line on stderr. A stack trace can quote driver or file content, so it is only printed
     * when the operator explicitly sets {@code AI_DB_MCP_DEBUG}.
     */
    public static CommandLine commandLine() {
        CommandLine cmd = new CommandLine(new RootCommand());
        enableHelp(cmd);
        cmd.setExecutionStrategy(new io.quarkiverse.mcp.servers.jdbc.cli.AdminAudit());
        cmd.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            System.err.println("Error: " + ex.getMessage());
            if (SafeDiagnostics.isKeyFailure(ex) || System.getenv("AI_DB_MCP_DEBUG") != null) {
                SafeDiagnostics.print("Diagnostic trace (native messages omitted):", ex);
            }
            return 1;
        });
        return cmd;
    }

    /** Every command at every depth answers {@code --help}, not just the root. */
    private static void enableHelp(CommandLine cmd) {
        cmd.getCommandSpec().mixinStandardHelpOptions(true);
        cmd.getSubcommands().values().forEach(GatewayMain::enableHelp);
    }
}
