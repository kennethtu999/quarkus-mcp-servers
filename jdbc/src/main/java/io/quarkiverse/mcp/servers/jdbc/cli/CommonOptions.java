package io.quarkiverse.mcp.servers.jdbc.cli;

import java.nio.file.Path;

import io.quarkiverse.mcp.servers.jdbc.profile.ConfigPaths;
import picocli.CommandLine.Option;

/** Options every command accepts. Deliberately no option for a password, a JDBC URL secret or a key value. */
public class CommonOptions implements GatewayContext.RootOptions {

    @Option(names = "--config-dir", description = "Configuration directory (default: AI_DB_MCP_CONFIG_DIR, then the OS default).")
    String configDir;

    @Option(names = "--key-provider", paramLabel = "keyfile:<path>", description = "Where the master key lives. Default is the OS key store. "
            + "Use keyfile:<path> only on machines without one; the file must be owner-only and outside the config directory.")
    String keyProvider;

    @Option(names = "--allow-insecure-tls", description = "Administrator override: accept JDBC URLs that do not request TLS with certificate verification. Not for production-like data.")
    boolean allowInsecureTls;

    private ConfigPaths cached;

    @Override
    public ConfigPaths paths() {
        if (cached == null) {
            cached = GatewayContext.resolvePaths(configDir);
        }
        return cached;
    }

    @Override
    public Path keyFile() {
        if (keyProvider == null || keyProvider.isBlank()) {
            return null;
        }
        if (!keyProvider.startsWith("keyfile:") || keyProvider.length() == "keyfile:".length()) {
            throw new IllegalArgumentException("--key-provider must be of the form keyfile:<path>");
        }
        return Path.of(keyProvider.substring("keyfile:".length()));
    }

    @Override
    public boolean requireTls() {
        return !allowInsecureTls;
    }
}
