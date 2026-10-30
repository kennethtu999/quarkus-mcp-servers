package io.quarkiverse.mcp.servers.jdbc.database;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.agroal.api.AgroalDataSource;
import io.agroal.api.configuration.supplier.AgroalDataSourceConfigurationSupplier;
import io.agroal.api.security.NamePrincipal;
import io.agroal.api.security.SimplePassword;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

/**
 * One lazily created connection pool per {@code profileId}. A failing database only marks its own profile
 * {@link Status#UNAVAILABLE} (with exponential back-off); other profiles are untouched.
 */
public final class ConnectionManager implements AutoCloseable {

    public enum Status {
        /** Never connected, or last attempt succeeded. */
        AVAILABLE,
        /** Last connection attempt failed; retries are rate limited. */
        UNAVAILABLE,
        /** Profile is disabled or has no usable driver. */
        DISABLED
    }

    public static final int DEFAULT_MAX_CONNECTIONS = 4;
    private static final Duration ACQUISITION_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration LOGIN_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration MIN_BACKOFF = Duration.ofSeconds(2);
    private static final Duration MAX_BACKOFF = Duration.ofMinutes(2);

    private final java.util.function.Function<DbDialect, Class<? extends java.sql.Driver>> drivers;
    private final int maxConnections;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    public ConnectionManager(DriverLoader drivers) {
        this(drivers, DEFAULT_MAX_CONNECTIONS);
    }

    public ConnectionManager(DriverLoader drivers, int maxConnections) {
        this(drivers::load, maxConnections);
    }

    /** Lets tests substitute the driver lookup; production code uses {@link DriverLoader}. */
    ConnectionManager(java.util.function.Function<DbDialect, Class<? extends java.sql.Driver>> drivers, int maxConnections) {
        if (maxConnections < 1 || maxConnections > 10) {
            throw new IllegalArgumentException("maxConnections must be between 1 and 10");
        }
        this.drivers = drivers;
        this.maxConnections = maxConnections;
    }

    /**
     * Borrows a connection. The caller must close it (returning it to the pool).
     *
     * @throws ProfileUnavailableException if the profile is disabled, has no driver, or recently failed
     */
    public Connection getConnection(DbProfile profile) throws ProfileUnavailableException {
        if (!profile.enabled()) {
            throw new ProfileUnavailableException(profile.label(), Status.DISABLED, "Profile is disabled");
        }
        Entry entry = entries.computeIfAbsent(profile.profileId(), id -> new Entry());
        synchronized (entry) {
            if (entry.retryAt != null && Instant.now().isBefore(entry.retryAt)) {
                throw new ProfileUnavailableException(profile.label(), Status.UNAVAILABLE,
                        "Database is unavailable; retrying after back-off");
            }
            try {
                if (entry.pool == null) {
                    entry.pool = createPool(profile);
                }
                Connection c = entry.pool.getConnection();
                entry.failures = 0;
                entry.retryAt = null;
                entry.status = Status.AVAILABLE;
                return c;
            } catch (SQLException | RuntimeException e) {
                closeQuietly(entry);
                entry.failures++;
                entry.status = Status.UNAVAILABLE;
                Duration backoff = MIN_BACKOFF.multipliedBy(1L << Math.min(entry.failures - 1, 6));
                entry.retryAt = Instant.now().plus(backoff.compareTo(MAX_BACKOFF) > 0 ? MAX_BACKOFF : backoff);
                // Do not chain the cause: driver messages can contain host names or, with some drivers, parts of the URL.
                throw new ProfileUnavailableException(profile.label(), Status.UNAVAILABLE,
                        "Cannot connect to database (" + e.getClass().getSimpleName() + ")");
            }
        }
    }

    /**
     * Verifies a profile can connect, bypassing back-off and without keeping a pool. Used by {@code profile test}.
     */
    public void test(DbProfile profile) throws SQLException {
        AgroalDataSource ds = createPool(profile);
        try (ds; Connection c = ds.getConnection(); var st = c.createStatement()) {
            st.setQueryTimeout(10);
            st.execute(DbDialect.of(profile.dbType()).validationQuery());
        }
    }

    public Status status(DbProfile profile) {
        if (!profile.enabled()) {
            return Status.DISABLED;
        }
        Entry e = entries.get(profile.profileId());
        return e == null ? Status.AVAILABLE : e.status;
    }

    /** Atomically forgets the pool of a profile (credentials rotated, profile edited or removed) and closes it. */
    public void invalidate(String profileId) {
        Entry e = entries.remove(profileId);
        if (e != null) {
            synchronized (e) {
                closeQuietly(e);
            }
        }
    }

    @Override
    public void close() {
        entries.keySet().forEach(this::invalidate);
    }

    private AgroalDataSource createPool(DbProfile profile) throws SQLException {
        DbDialect dialect = DbDialect.of(profile.dbType());
        Class<? extends java.sql.Driver> driver;
        try {
            driver = drivers.apply(dialect);
        } catch (DriverLoader.DriverUnavailableException e) {
            throw new IllegalStateException(e.getMessage());
        }
        char[] pw = profile.passwordCopy();
        try {
            var cfg = new AgroalDataSourceConfigurationSupplier()
                    .connectionPoolConfiguration(p -> p
                            .minSize(0)
                            .initialSize(0)
                            .maxSize(maxConnections)
                            .acquisitionTimeout(ACQUISITION_TIMEOUT)
                            .connectionFactoryConfiguration(f -> f
                                    .jdbcUrl(profile.jdbcUrl())
                                    .connectionProviderClass(driver)
                                    .loginTimeout(LOGIN_TIMEOUT)
                                    .autoCommit(false)
                                    .principal(new NamePrincipal(profile.username()))
                                    .credential(new SimplePassword(new String(pw)))));
            return AgroalDataSource.from(cfg);
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
    }

    private static void closeQuietly(Entry e) {
        if (e.pool != null) {
            try {
                e.pool.close();
            } catch (RuntimeException ignored) {
                // nothing useful to do
            }
            e.pool = null;
        }
    }

    private static final class Entry {
        AgroalDataSource pool;
        Status status = Status.AVAILABLE;
        int failures;
        Instant retryAt;
    }

    public static final class ProfileUnavailableException extends Exception {
        private final Status status;

        ProfileUnavailableException(String label, Status status, String message) {
            super(label + ": " + message);
            this.status = status;
        }

        public Status status() {
            return status;
        }
    }
}
