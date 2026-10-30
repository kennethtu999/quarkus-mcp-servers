package io.quarkiverse.mcp.servers.jdbc.database;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Driver;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads JDBC drivers that are not bundled in the application jar (IBM JCC cannot be redistributed by default).
 * <p>
 * A driver jar is only loaded if its SHA-256 matches a digest the administrator pinned, so dropping a different jar
 * into the drivers directory cannot change which code runs. Loading is per jar and never touches {@code DriverManager},
 * which avoids both its class loader restrictions and cross-profile driver confusion.
 */
public final class DriverLoader {

    private final Path driversDir;
    private final Map<String, String> pinnedSha256;
    private final Map<String, Class<? extends Driver>> cache = new ConcurrentHashMap<>();

    /**
     * @param driversDir directory holding driver jars, may not exist
     * @param pinnedSha256 jar file name to lower-case hex SHA-256
     */
    public DriverLoader(Path driversDir, Map<String, String> pinnedSha256) {
        this.driversDir = driversDir;
        this.pinnedSha256 = Map.copyOf(pinnedSha256);
    }

    /** Returns a driver for a type that is available on the application class path (PostgreSQL, Oracle, H2 in tests). */
    public static Class<? extends Driver> bundled(String className) {
        try {
            return Class.forName(className).asSubclass(Driver.class);
        } catch (ReflectiveOperationException | LinkageError e) {
            throw new DriverUnavailableException("JDBC driver " + className + " is not available", e);
        }
    }

    /**
     * Resolves the driver class for a dialect: first the application class path, then a pinned jar from the drivers
     * directory. Failure affects only the profiles that need this driver.
     */
    public Class<? extends Driver> load(DbDialect dialect) {
        return cache.computeIfAbsent(dialect.driverClassName(), name -> {
            try {
                return bundled(name);
            } catch (DriverUnavailableException notBundled) {
                return loadExternal(name);
            }
        });
    }

    private Class<? extends Driver> loadExternal(String className) {
        if (pinnedSha256.isEmpty() || !Files.isDirectory(driversDir)) {
            throw new DriverUnavailableException(
                    "JDBC driver " + className + " is not bundled and no pinned driver jar is configured");
        }
        for (Map.Entry<String, String> pin : pinnedSha256.entrySet()) {
            String fileName = pin.getKey();
            if (fileName.contains("/") || fileName.contains("\\") || fileName.contains("..")) {
                throw new DriverUnavailableException("Invalid pinned driver file name");
            }
            Path jar = driversDir.resolve(fileName).normalize();
            if (!jar.startsWith(driversDir.normalize()) || !Files.isRegularFile(jar)) {
                continue;
            }
            String actual = sha256(jar);
            if (!actual.equalsIgnoreCase(pin.getValue())) {
                throw new DriverUnavailableException("Driver jar " + fileName + " does not match its pinned SHA-256");
            }
            try {
                URLClassLoader loader = new URLClassLoader(new URL[] { jar.toUri().toURL() },
                        DriverLoader.class.getClassLoader());
                return Class.forName(className, true, loader).asSubclass(Driver.class);
            } catch (ClassNotFoundException | ClassCastException | IOException | LinkageError e) {
                // keep trying other pinned jars; remember nothing about this one
            }
        }
        throw new DriverUnavailableException("No pinned driver jar provides " + className);
    }

    /** SHA-256 of a file as lower-case hex; used both to verify a pin and to create one. */
    public static String sha256Of(Path file) {
        return sha256(file);
    }

    static String sha256(Path file) {
        try (InputStream in = Files.newInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new DriverUnavailableException("Cannot read driver jar " + file.getFileName(), e);
        }
    }

    public static final class DriverUnavailableException extends RuntimeException {
        public DriverUnavailableException(String message) {
            super(message);
        }

        public DriverUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
