package io.quarkiverse.mcp.servers.jdbc.database;

import java.util.Locale;
import java.util.Set;

/**
 * Per-database differences only. A dialect never decides whether SQL is allowed; that is {@code SqlGuard}'s job.
 */
public interface DbDialect {

    DbType type();

    String driverClassName();

    /** JDBC URL prefix, e.g. {@code jdbc:postgresql:}. */
    String urlPrefix();

    /** Connection properties that may appear in the JDBC URL. Everything else is rejected. */
    Set<String> allowedUrlProperties();

    /** Properties that must be present for the connection to be considered TLS-protected, if any. */
    boolean urlRequestsTls(String url);

    /** Cheap query used to validate a pooled connection. */
    String validationQuery();

    /** Statement that switches the session to the given schema, or {@code null} to use {@code Connection.setSchema}. */
    String defaultSchemaStatement(String schema);

    /** Schemas that hold system catalogs and must never be readable through the gateway. */
    Set<String> systemSchemas();

    /** Normalises an unquoted identifier the way the database stores it. */
    String normalizeIdentifier(String identifier);

    /** Quotes an identifier that was already validated against JDBC metadata. */
    default String quote(String identifier) {
        if (identifier.indexOf('"') >= 0 || identifier.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Illegal identifier");
        }
        return '"' + identifier + '"';
    }

    static DbDialect of(DbType type) {
        return switch (type) {
            case DB2_LUW -> Db2Dialect.INSTANCE;
            case POSTGRESQL -> PostgresDialect.INSTANCE;
            case ORACLE -> OracleDialect.INSTANCE;
        };
    }

    static String lower(String s) {
        return s.toLowerCase(Locale.ROOT);
    }
}
