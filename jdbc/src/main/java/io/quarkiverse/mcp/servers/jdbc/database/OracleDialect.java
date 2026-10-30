package io.quarkiverse.mcp.servers.jdbc.database;

import java.util.Locale;
import java.util.Set;

public final class OracleDialect implements DbDialect {

    static final OracleDialect INSTANCE = new OracleDialect();

    // TNS_ADMIN, javax.net.ssl.* (file paths), oracle.net.wallet_location etc. read local files and are not allowed.
    private static final Set<String> ALLOWED = Set.of("oracle.net.connect_timeout", "oracle.jdbc.readtimeout",
            "oracle.net.ssl_server_dn_match", "oracle.net.ssl_version");

    private OracleDialect() {
    }

    @Override
    public DbType type() {
        return DbType.ORACLE;
    }

    @Override
    public String driverClassName() {
        return "oracle.jdbc.OracleDriver";
    }

    @Override
    public String urlPrefix() {
        return "jdbc:oracle:thin:";
    }

    @Override
    public Set<String> allowedUrlProperties() {
        return ALLOWED;
    }

    @Override
    public boolean urlRequestsTls(String url) {
        return url.toLowerCase(Locale.ROOT).startsWith("jdbc:oracle:thin:@tcps://");
    }

    @Override
    public String validationQuery() {
        return "SELECT 1 FROM DUAL";
    }

    @Override
    public String defaultSchemaStatement(String schema) {
        return null;
    }

    @Override
    public Set<String> systemSchemas() {
        return Set.of("SYS", "SYSTEM", "SYSAUX", "XDB", "CTXSYS", "MDSYS", "DBSNMP", "OUTLN", "WMSYS", "ORDSYS");
    }

    @Override
    public String normalizeIdentifier(String identifier) {
        return identifier.toUpperCase(Locale.ROOT);
    }
}
