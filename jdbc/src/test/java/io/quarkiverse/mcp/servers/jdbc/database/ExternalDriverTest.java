package io.quarkiverse.mcp.servers.jdbc.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.profile.Settings;

/**
 * Proves the external-driver path really works end to end, which is how IBM JCC reaches the gateway: a jar that is NOT on the
 * application class path, dropped into {@code drivers/} and pinned by digest, is loaded and used to open connections - and
 * a different jar under the same name is refused.
 * <p>
 * The driver is a tiny real JDBC driver compiled here (class {@code com.ibm.db2.jcc.DB2Driver}, the name the Db2 dialect
 * looks for) that delegates to H2, so no network and no real Db2 jar are needed.
 */
class ExternalDriverTest {

    @TempDir
    Path tmp;

    /** Builds a jar containing a DB2Driver that accepts jdbc:db2: URLs and opens an in-memory H2 database. */
    private Path buildDriverJar(Path dir, String marker) throws Exception {
        Path src = Files.createDirectories(tmp.resolve("src-" + UUID.randomUUID()));
        Path pkg = Files.createDirectories(src.resolve("com/ibm/db2/jcc"));
        Files.writeString(pkg.resolve("DB2Driver.java"), """
                package com.ibm.db2.jcc;
                import java.sql.*;
                import java.util.Properties;
                import java.util.logging.Logger;
                public class DB2Driver implements Driver {
                    public static final String MARKER = "%s";
                    public Connection connect(String url, Properties p) throws SQLException {
                        if (!acceptsURL(url)) return null;
                        return new org.h2.Driver().connect("jdbc:h2:mem:ext;DB_CLOSE_DELAY=-1", p);
                    }
                    public boolean acceptsURL(String url) { return url != null && url.startsWith("jdbc:db2:"); }
                    public DriverPropertyInfo[] getPropertyInfo(String u, Properties p) { return new DriverPropertyInfo[0]; }
                    public int getMajorVersion() { return 1; }
                    public int getMinorVersion() { return 0; }
                    public boolean jdbcCompliant() { return false; }
                    public Logger getParentLogger() { return Logger.getAnonymousLogger(); }
                }
                """.formatted(marker));
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        String cp = System.getProperty("java.class.path");
        int rc = compiler.run(null, null, null, "-cp", cp, "-d", src.toString(), pkg.resolve("DB2Driver.java").toString());
        assertThat(rc).as("test driver must compile").isZero();

        Path jar = dir.resolve("db2jcc4.jar");
        Files.createDirectories(dir);
        try (OutputStream out = Files.newOutputStream(jar); JarOutputStream jos = new JarOutputStream(out)) {
            jos.putNextEntry(new JarEntry("com/ibm/db2/jcc/DB2Driver.class"));
            jos.write(Files.readAllBytes(src.resolve("com/ibm/db2/jcc/DB2Driver.class")));
            jos.closeEntry();
        }
        return jar;
    }

    private static DbProfile db2Profile() {
        return new DbProfile(UUID.randomUUID().toString(), "DB2-DEV", DbType.DB2_LUW,
                "jdbc:db2://db2.example.internal:50000/TESTDB:sslConnection=true;", "sa", "".toCharArray(), null, true);
    }

    @Test
    void aPinnedExternalJarLoadsAndOpensConnections() throws Exception {
        Path drivers = tmp.resolve("drivers");
        Path jar = buildDriverJar(drivers, "v1");
        String sha = DriverLoader.sha256Of(jar);

        DriverLoader loader = new DriverLoader(drivers, Map.of("db2jcc4.jar", sha));
        Class<? extends Driver> cls = loader.load(DbDialect.of(DbType.DB2_LUW));
        assertThat(cls.getName()).isEqualTo("com.ibm.db2.jcc.DB2Driver");
        assertThat(cls.getClassLoader()).as("loaded from the jar, not from the application class path")
                .isNotSameAs(getClass().getClassLoader());

        try (ConnectionManager cm = new ConnectionManager(loader, 2); Connection c = cm.getConnection(db2Profile())) {
            assertThat(c.isValid(2)).isTrue();
            assertThat(c.createStatement().executeQuery("SELECT 41 + 1").next()).isTrue();
        }
    }

    @Test
    void aJarThatDoesNotMatchItsPinIsRefusedAndNeverLoaded() throws Exception {
        Path drivers = tmp.resolve("drivers");
        Path genuine = buildDriverJar(drivers, "genuine");
        String pinnedSha = DriverLoader.sha256Of(genuine);

        // someone replaces the jar with different code under the same name
        buildDriverJar(drivers, "SWAPPED-BY-ATTACKER");
        assertThat(DriverLoader.sha256Of(drivers.resolve("db2jcc4.jar"))).isNotEqualTo(pinnedSha);

        DriverLoader loader = new DriverLoader(drivers, Map.of("db2jcc4.jar", pinnedSha));
        assertThatThrownBy(() -> loader.load(DbDialect.of(DbType.DB2_LUW)))
                .isInstanceOf(DriverLoader.DriverUnavailableException.class).hasMessageContaining("pinned SHA-256");

        try (ConnectionManager cm = new ConnectionManager(loader, 2)) {
            assertThatThrownBy(() -> cm.getConnection(db2Profile()))
                    .isInstanceOf(ConnectionManager.ProfileUnavailableException.class);
        }
    }

    @Test
    void anUnpinnedJarInTheDriversDirectoryIsNeverLoaded() throws Exception {
        Path drivers = tmp.resolve("drivers");
        buildDriverJar(drivers, "v1");
        DriverLoader loader = new DriverLoader(drivers, Map.of());
        assertThatThrownBy(() -> loader.load(DbDialect.of(DbType.DB2_LUW)))
                .isInstanceOf(DriverLoader.DriverUnavailableException.class);
    }

    @Test
    void theRealWiringReadsPinsFromSettingsYaml() throws Exception {
        Path cfg = tmp.resolve("cfg");
        io.quarkiverse.mcp.servers.jdbc.secret.FilePerms.ensureSecureDir(cfg); // as `init` creates it
        Path drivers = cfg.resolve("drivers");
        Path jar = buildDriverJar(drivers, "v1");
        Settings settings = new Settings(cfg.resolve("settings.yaml"));
        assertThat(settings.pinnedDrivers()).isEmpty();

        settings.pinDriver("db2jcc4.jar", DriverLoader.sha256Of(jar));
        Map<String, String> pins = new Settings(cfg.resolve("settings.yaml")).pinnedDrivers();
        assertThat(pins).containsOnlyKeys("db2jcc4.jar");

        try (ConnectionManager cm = new ConnectionManager(new DriverLoader(drivers, pins), 2);
                Connection c = cm.getConnection(db2Profile())) {
            assertThat(c.isValid(2)).isTrue();
        }
        io.quarkiverse.mcp.servers.jdbc.secret.FilePerms.verifyFile(cfg.resolve("settings.yaml"));
    }

    @Test
    void aDamagedOrForgedSettingsFileTrustsNothing() throws Exception {
        Path cfg = Files.createDirectories(tmp.resolve("cfg2"));
        Path f = cfg.resolve("settings.yaml");
        for (String content : List.of("not: [valid", "drivers: [a, b]", "drivers:\n  ../evil.jar: " + "a".repeat(64),
                "drivers:\n  x.jar: not-a-digest", "drivers:\n  x.txt: " + "a".repeat(64), "")) {
            Files.writeString(f, content, StandardCharsets.UTF_8);
            io.quarkiverse.mcp.servers.jdbc.secret.FilePerms.restrictFile(f);
            assertThat(new Settings(f).pinnedDrivers()).as(content).isEmpty();
        }
        // a world-writable settings file is not trusted at all
        Files.writeString(f, "drivers:\n  x.jar: " + "a".repeat(64) + "\n");
        Files.setPosixFilePermissions(f, java.nio.file.attribute.PosixFilePermissions.fromString("rw-rw-rw-"));
        assertThat(new Settings(f).pinnedDrivers()).isEmpty();
    }

    @Test
    void pinRejectsPathsAndBadDigests() throws IOException {
        Settings s = new Settings(tmp.resolve("s.yaml"));
        assertThatThrownBy(() -> s.pinDriver("../x.jar", "a".repeat(64))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> s.pinDriver("x.jar", "zz")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> s.pinDriver("x.exe", "a".repeat(64))).isInstanceOf(IllegalArgumentException.class);
    }
}
