package io.quarkiverse.mcp.servers.jdbc.tool;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import io.quarkiverse.mcp.servers.jdbc.audit.AuditService;
import io.quarkiverse.mcp.servers.jdbc.cli.GatewayContext;
import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager;
import io.quarkiverse.mcp.servers.jdbc.database.DbDialect;
import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import io.quarkiverse.mcp.servers.jdbc.profile.ConfigPaths;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;
import io.quarkiverse.mcp.servers.jdbc.secret.SecretTestSupport.MemoryKeys;

/**
 * Builds a complete, real gateway (encrypted store, policy files, signed manifest, audit log) whose ORACLE profiles are
 * backed by in-memory H2, so end-to-end behaviour can be tested without an external database.
 */
public final class GatewayFixture implements AutoCloseable {

    public static final String PASSWORD = "FIXTURE-SENTINEL-pw-4417";

    public final Path root;
    public final ConfigPaths paths;
    public final GatewayContext ctx;
    public final ToolGateway gateway;
    public final QueryService queries;
    public final AuditService audit;
    private final Connection keepAlive;
    public final String h2Url;

    public GatewayFixture(Path root) throws Exception {
        this.root = root;
        this.paths = new ConfigPaths(root.resolve("cfg"));
        FilePerms.ensureSecureDir(paths.root());
        this.h2Url = "jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1";
        this.keepAlive = DriverManager.getConnection(h2Url, "sa", PASSWORD);

        Function<DbDialect, Class<? extends Driver>> drivers = d -> d.type() == DbType.ORACLE ? org.h2.Driver.class
                : io.quarkiverse.mcp.servers.jdbc.database.DriverLoader.bundled(d.driverClassName());
        this.ctx = GatewayContext.forTesting(paths, MemoryKeys.random(), connectionManager(drivers));
        this.audit = new AuditService(paths.logsDir());
        this.gateway = new ToolGateway(ctx, audit);
        // H2 stands in for Oracle but does not understand Oracle's SET TRANSACTION READ ONLY (covered by OracleDialectTest).
        this.queries = new QueryService(gateway, t -> null);
        seed();
    }

    private static ConnectionManager connectionManager(Function<DbDialect, Class<? extends Driver>> drivers) throws Exception {
        var ctor = ConnectionManager.class.getDeclaredConstructor(Function.class, int.class);
        ctor.setAccessible(true);
        return ctor.newInstance(drivers, 3);
    }

    private void seed() throws Exception {
        try (Statement st = keepAlive.createStatement()) {
            st.execute("CREATE SCHEMA APP");
            st.execute("CREATE SCHEMA SYS");
            st.execute("CREATE TABLE SYS.USER$ (NAME VARCHAR(30))");
            st.execute("INSERT INTO SYS.USER$ VALUES ('SYS')");
            st.execute("CREATE TABLE APP.ORDERS (ID INT PRIMARY KEY, STATUS VARCHAR(20), VERSION INT DEFAULT 1)");
            st.execute("INSERT INTO APP.ORDERS SELECT X, 'OPEN', 1 FROM SYSTEM_RANGE(1, 1000)");
            st.execute("CREATE TABLE APP.CUSTOMERS (ID INT PRIMARY KEY, NAME VARCHAR(50))");
            st.execute("INSERT INTO APP.CUSTOMERS VALUES (1, 'ann'), (2, 'bob')");
            st.execute("CREATE TABLE APP.USERS (ID INT PRIMARY KEY, EMAIL VARCHAR(50))");
            st.execute("INSERT INTO APP.USERS VALUES (1, 'a@x')");
        }
    }

    /** Registers an H2-backed profile and writes its policy (activated unless {@code activate} is false). */
    public DbProfile profile(String label, String policyBody, boolean activate) throws Exception {
        DbProfile p = new DbProfile(UUID.randomUUID().toString(), label, DbType.ORACLE, h2Url, "sa", PASSWORD.toCharArray(),
                "APP", true);
        List<DbProfile> all = new java.util.ArrayList<>(ctx.registry.all());
        all.add(p);
        ctx.registry.replaceAll(all);
        if (policyBody != null) {
            writePolicy(p, policyBody);
            if (activate) {
                ctx.policies.activate(p);
            }
        }
        return p;
    }

    public void writePolicy(DbProfile p, String body) throws Exception {
        FilePerms.ensureSecureDir(paths.permissionsDir());
        Path f = paths.permissionsDir().resolve("permissions_" + p.label() + ".yaml");
        Files.writeString(f, "version: 1\nprofile: " + p.label() + "\nprofileId: " + p.profileId() + "\n" + body);
        FilePerms.restrictFile(f);
    }

    public List<String> auditLines() throws Exception {
        return Files.exists(audit.file()) ? Files.readAllLines(audit.file()) : List.of();
    }

    public String auditText() throws Exception {
        return String.join("\n", auditLines());
    }

    public Connection direct() throws Exception {
        return DriverManager.getConnection(h2Url, "sa", PASSWORD);
    }

    @Override
    public void close() throws Exception {
        ctx.connections.close();
        keepAlive.close();
    }
}
