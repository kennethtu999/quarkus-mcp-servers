package io.quarkiverse.mcp.servers.jdbc.cli;

import java.nio.file.Path;

import io.quarkiverse.mcp.servers.jdbc.profile.ConfigPaths;
import picocli.CommandLine.Option;

/** Options every command accepts. Deliberately no option for a password, a JDBC URL secret or a key value. */
public class CommonOptions implements GatewayContext.RootOptions {

    @Option(names = "--config-dir", description = "Configuration directory (default: AI_DB_MCP_CONFIG_DIR, then the OS default).")
    String configDir;

    @Option(names = "--key-provider", paramLabel = "keyfile:<path>", description = "Where the master key lives. Default: AI_DB_MCP_KEY_PROVIDER, "
            + "then the OS key store (Linux: automatic ~/.config/dbmcp key file if unavailable on first init). An explicit keyfile:<path> must be owner-only "
            + "and outside the config directory.")
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

    /** Environment variable holding the same {@code keyfile:<path>} value; it names a location, never a key. */
    public static final String KEY_PROVIDER_ENV = "AI_DB_MCP_KEY_PROVIDER";

    @Override
    public Path keyFile() {
        String value = keyProvider;
        if (value == null || value.isBlank()) {
            value = System.getenv(KEY_PROVIDER_ENV);
        }
        return parseKeyProvider(value);
    }

    static Path parseKeyProvider(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        if (!value.startsWith("keyfile:") || value.length() == "keyfile:".length()) {
            throw new IllegalArgumentException("The key provider must be of the form keyfile:<path>");
        }
        return Path.of(value.substring("keyfile:".length()));
    }

    @Override
    public boolean requireTls() {
        return !allowInsecureTls;
    }
}
