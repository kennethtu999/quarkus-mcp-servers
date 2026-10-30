package io.quarkiverse.mcp.servers.jdbc.profile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

/**
 * Non-secret gateway settings in {@code settings.yaml}. For now only the pinned external JDBC driver jars:
 * file name to SHA-256. The file is written by {@code ai-db-mcp driver pin}; anything in it that is malformed is ignored
 * (so a damaged file can only ever mean "no external driver is trusted", never "any driver is trusted").
 */
public final class Settings {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());
    private static final Pattern FILE_NAME = Pattern.compile("[A-Za-z0-9._-]{1,100}\\.jar");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

    private final Path file;

    public Settings(Path file) {
        this.file = file;
    }

    /** Pinned drivers; invalid entries are dropped. */
    public Map<String, String> pinnedDrivers() {
        try {
            if (!Files.isRegularFile(file) || Files.isSymbolicLink(file) || Files.size(file) > 64 * 1024) {
                return Map.of();
            }
            FilePerms.verifyFile(file);
            var drivers = YAML.readTree(file.toFile()).path("drivers");
            Map<String, String> out = new TreeMap<>();
            drivers.fields().forEachRemaining(e -> {
                String sha = e.getValue().asText("").toLowerCase();
                if (FILE_NAME.matcher(e.getKey()).matches() && SHA256.matcher(sha).matches()) {
                    out.put(e.getKey(), sha);
                }
            });
            return Map.copyOf(out);
        } catch (IOException | RuntimeException e) {
            return Map.of();
        }
    }

    public void pinDriver(String jarName, String sha256) throws IOException {
        if (!FILE_NAME.matcher(jarName).matches() || !SHA256.matcher(sha256).matches()) {
            throw new IllegalArgumentException("Invalid driver file name or digest");
        }
        Map<String, String> all = new TreeMap<>(pinnedDrivers());
        all.put(jarName, sha256);
        write(all);
    }

    public void unpinDriver(String jarName) throws IOException {
        Map<String, String> all = new TreeMap<>(pinnedDrivers());
        if (all.remove(jarName) != null) {
            write(all);
        }
    }

    private void write(Map<String, String> drivers) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        FilePerms.ensureSecureDir(dir);
        Path tmp = Files.createTempFile(dir, "settings", ".tmp");
        try {
            FilePerms.restrictFile(tmp);
            Files.writeString(tmp, YAML.writeValueAsString(Map.of("drivers", drivers)));
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
