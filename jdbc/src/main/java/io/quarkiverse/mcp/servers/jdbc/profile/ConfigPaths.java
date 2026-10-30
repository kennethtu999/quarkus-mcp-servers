package io.quarkiverse.mcp.servers.jdbc.profile;

import java.nio.file.Path;
import java.util.Locale;
import java.util.function.Function;

/**
 * Locations inside the configuration directory, and how that directory is chosen: an explicit {@code --config-dir}
 * wins, then {@code AI_DB_MCP_CONFIG_DIR}, then the per-OS default.
 */
public final class ConfigPaths {

    public static final String ENV_VAR = "AI_DB_MCP_CONFIG_DIR";

    private final Path root;

    public ConfigPaths(Path root) {
        this.root = root.toAbsolutePath().normalize();
    }

    public static ConfigPaths resolve(String cliValue, Function<String, String> env, String osName, String userHome) {
        if (cliValue != null && !cliValue.isBlank()) {
            return new ConfigPaths(Path.of(cliValue));
        }
        String fromEnv = env.apply(ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return new ConfigPaths(Path.of(fromEnv));
        }
        return new ConfigPaths(defaultDir(env, osName, userHome));
    }

    static Path defaultDir(Function<String, String> env, String osName, String userHome) {
        String os = osName.toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            String local = env.apply("LOCALAPPDATA");
            Path base = local != null && !local.isBlank() ? Path.of(local) : Path.of(userHome, "AppData", "Local");
            return base.resolve("ai-db-mcp");
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return Path.of(userHome, "Library", "Application Support", "ai-db-mcp");
        }
        String xdg = env.apply("XDG_CONFIG_HOME");
        Path base = xdg != null && !xdg.isBlank() ? Path.of(xdg) : Path.of(userHome, ".config");
        return base.resolve("ai-db-mcp");
    }

    public Path root() {
        return root;
    }

    public Path profilesFile() {
        return root.resolve("profiles.enc");
    }

    public Path settingsFile() {
        return root.resolve("settings.yaml");
    }

    public Path permissionsDir() {
        return root.resolve("permissions");
    }

    public Path logsDir() {
        return root.resolve("logs");
    }

    public Path backupsDir() {
        return root.resolve("backups");
    }

    public Path approvalsDir() {
        return root.resolve("approvals");
    }

    public Path driversDir() {
        return root.resolve("drivers");
    }
}
