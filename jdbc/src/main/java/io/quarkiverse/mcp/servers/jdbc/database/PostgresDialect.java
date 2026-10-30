package io.quarkiverse.mcp.servers.jdbc.database;

import java.util.Locale;
import java.util.Set;

public final class PostgresDialect implements DbDialect {

    static final PostgresDialect INSTANCE = new PostgresDialect();

    // socketFactory, sslfactory, loggerFile, authenticationPluginClassName, sslpasswordcallback ... load classes or
    // write files, so they are not allowed.
    private static final Set<String> ALLOWED = Set.of("ssl", "sslmode", "sslrootcert", "currentschema",
            "connecttimeout", "logintimeout", "sockettimeout", "applicationname", "targetservertype");

    private PostgresDialect() {
    }

    @Override
    public DbType type() {
        return DbType.POSTGRESQL;
    }

    @Override
    public String driverClassName() {
        return "org.postgresql.Driver";
    }

    @Override
    public String urlPrefix() {
        return "jdbc:postgresql:";
    }

    @Override
    public Set<String> allowedUrlProperties() {
        return ALLOWED;
    }

    @Override
    public boolean urlRequestsTls(String url) {
        String u = url.toLowerCase(Locale.ROOT);
        return u.contains("sslmode=verify-full") || u.contains("sslmode=verify-ca");
    }

    @Override
    public String validationQuery() {
        return "SELECT 1";
    }

    @Override
    public String defaultSchemaStatement(String schema) {
        return null;
    }

    @Override
    public Set<String> systemSchemas() {
        return Set.of("pg_catalog", "information_schema", "pg_toast");
    }

    @Override
    public String normalizeIdentifier(String identifier) {
        return identifier.toLowerCase(Locale.ROOT);
    }
}
