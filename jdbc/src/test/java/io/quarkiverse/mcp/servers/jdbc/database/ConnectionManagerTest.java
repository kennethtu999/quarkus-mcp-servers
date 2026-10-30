package io.quarkiverse.mcp.servers.jdbc.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager.ProfileUnavailableException;
import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager.Status;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

class ConnectionManagerTest {

    // A refused local port: fails fast and never leaves the machine.
    private static final String UNREACHABLE_PG = "jdbc:postgresql://127.0.0.1:1/x";

    @TempDir
    Path tmp;

    private ConnectionManager manager;

    /** PostgreSQL profiles use the real (bundled) PG driver; Oracle profiles are redirected to in-memory H2. */
    private static final Function<DbDialect, Class<? extends Driver>> DRIVERS = d -> d.type() == DbType.ORACLE
            ? org.h2.Driver.class
            : DriverLoader.bundled(d.driverClassName());

    @BeforeEach
    void setUp() {
        manager = new ConnectionManager(DRIVERS, 2);
    }

    @AfterEach
    void tearDown() {
        manager.close();
    }

    private static DbProfile profile(String label, DbType type, String url, boolean enabled) {
        return new DbProfile(UUID.randomUUID().toString(), label, type, url, "sa", "TOPSECRET99".toCharArray(), null,
                enabled);
    }

    /** A healthy profile: H2 in memory, standing in for any reachable database. */
    private static DbProfile healthy(String label) {
        return profile(label, DbType.ORACLE, "jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", true);
    }

    private static DbProfile dead(String label) {
        return profile(label, DbType.POSTGRESQL, UNREACHABLE_PG, true);
    }

    @Test
    void healthyProfileHandsOutWorkingConnectionsFromARealPool() throws Exception {
        DbProfile p = healthy("OK");
        try (Connection c = manager.getConnection(p); var st = c.createStatement(); var rs = st.executeQuery("SELECT 1")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getInt(1)).isEqualTo(1);
            assertThat(c.getAutoCommit()).as("pools hand out manual-commit connections").isFalse();
        }
        assertThat(manager.status(p)).isEqualTo(Status.AVAILABLE);
    }

    @Test
    void oneUnreachableDatabaseDoesNotAffectAWorkingOne() throws Exception {
        DbProfile broken = dead("PG-DEAD");
        DbProfile ok = healthy("OK");

        // the working profile is connected first and kept open while the other one fails
        try (Connection c = manager.getConnection(ok)) {
            assertThatThrownBy(() -> manager.getConnection(broken)).isInstanceOf(ProfileUnavailableException.class)
                    .satisfies(e -> assertThat(((ProfileUnavailableException) e).status()).isEqualTo(Status.UNAVAILABLE));

            assertThat(manager.status(broken)).isEqualTo(Status.UNAVAILABLE);
            assertThat(manager.status(ok)).isEqualTo(Status.AVAILABLE);
            assertThat(c.isValid(2)).isTrue();
        }
        // and it keeps serving after the other one has failed
        try (Connection again = manager.getConnection(ok); var rs = again.createStatement().executeQuery("SELECT 2")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getInt(1)).isEqualTo(2);
        }
    }

    @Test
    void failedProfileIsRateLimitedByBackoff() {
        DbProfile broken = dead("PG-DEAD");

        assertThatThrownBy(() -> manager.getConnection(broken)).hasMessageContaining("Cannot connect");
        long start = System.nanoTime();
        assertThatThrownBy(() -> manager.getConnection(broken)).hasMessageContaining("back-off");
        // answered from state, not by trying the network again
        assertThat((System.nanoTime() - start) / 1_000_000).isLessThan(200);
    }

    @Test
    void disabledProfileIsNeverConnected() {
        DbProfile disabled = profile("PG-OFF", DbType.POSTGRESQL, UNREACHABLE_PG, false);
        assertThatThrownBy(() -> manager.getConnection(disabled)).isInstanceOf(ProfileUnavailableException.class)
                .hasMessageContaining("disabled");
        assertThat(manager.status(disabled)).isEqualTo(Status.DISABLED);
    }

    @Test
    void errorsNeverContainThePasswordOrHost() {
        DbProfile broken = dead("PG-DEAD");
        assertThatThrownBy(() -> manager.getConnection(broken)).satisfies(e -> {
            for (Throwable t = e; t != null; t = t.getCause()) {
                assertThat(String.valueOf(t.getMessage())).doesNotContain("TOPSECRET99").doesNotContain("127.0.0.1");
            }
        });
    }

    @Test
    void invalidateClearsBackoffSoARotatedPasswordIsTriedImmediately() {
        DbProfile broken = dead("PG-DEAD");
        assertThatThrownBy(() -> manager.getConnection(broken)).hasMessageContaining("Cannot connect");
        assertThatThrownBy(() -> manager.getConnection(broken)).hasMessageContaining("back-off");

        manager.invalidate(broken.profileId());

        // back-off state is gone: this is a fresh network attempt, not "back-off"
        assertThatThrownBy(() -> manager.getConnection(broken)).hasMessageContaining("Cannot connect");
    }

    @Test
    void invalidateClosesTheOldPoolAndAFreshOneIsCreated() throws Exception {
        DbProfile p = healthy("OK");
        Connection first = manager.getConnection(p);
        first.close();

        manager.invalidate(p.profileId());

        try (Connection second = manager.getConnection(p)) {
            assertThat(second.isValid(2)).isTrue();
        }
    }

    @Test
    void missingExternalDriverFailsOnlyThatProfile() throws Exception {
        // Production wiring: Db2 JCC is not on the class path and no jar is pinned.
        try (ConnectionManager prod = new ConnectionManager(new DriverLoader(tmp.resolve("drivers"), Map.of()), 2)) {
            DbProfile db2 = profile("DB2-DEV", DbType.DB2_LUW, "jdbc:db2://127.0.0.1:50000/X:sslConnection=true;", true);
            assertThatThrownBy(() -> prod.getConnection(db2)).isInstanceOf(ProfileUnavailableException.class);
            assertThat(prod.status(db2)).isEqualTo(Status.UNAVAILABLE);
        }
    }

    @Test
    void driverJarWithWrongDigestIsRefused() throws Exception {
        Path drivers = Files.createDirectories(tmp.resolve("drivers"));
        Files.writeString(drivers.resolve("jcc.jar"), "not really a jar");
        DriverLoader loader = new DriverLoader(drivers, Map.of("jcc.jar", "0".repeat(64)));

        assertThatThrownBy(() -> loader.load(DbDialect.of(DbType.DB2_LUW)))
                .isInstanceOf(DriverLoader.DriverUnavailableException.class)
                .hasMessageContaining("pinned SHA-256");
    }

    @Test
    void pinnedFileNamesCannotEscapeTheDriversDirectory() throws Exception {
        Path drivers = Files.createDirectories(tmp.resolve("drivers"));
        Files.writeString(tmp.resolve("outside.jar"), "x");
        DriverLoader loader = new DriverLoader(drivers, Map.of("../outside.jar", "0".repeat(64)));

        assertThatThrownBy(() -> loader.load(DbDialect.of(DbType.DB2_LUW)))
                .isInstanceOf(DriverLoader.DriverUnavailableException.class).hasMessageContaining("Invalid pinned");
    }

    @Test
    void testDoesNotLeaveBackoffStateBehind() {
        DbProfile broken = dead("PG-DEAD");
        assertThatThrownBy(() -> manager.test(broken)).isInstanceOf(java.sql.SQLException.class);
        assertThat(manager.status(broken)).isEqualTo(Status.AVAILABLE);
    }
}
