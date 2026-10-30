package io.quarkiverse.mcp.servers.jdbc.database;

import java.util.Locale;
import java.util.Set;

public final class Db2Dialect implements DbDialect {

    static final Db2Dialect INSTANCE = new Db2Dialect();

    // traceFile / traceDirectory / pluginName etc. are deliberately absent: they write to disk or load code.
    private static final Set<String> ALLOWED = Set.of("currentschema", "sslconnection", "sslcertlocation",
            "sslservercertificate", "logintimeout", "connecttimeout", "sockettimeout", "querytimeout",
            "securitymechanism", "applicationname", "clientapplicationinformation");

    private Db2Dialect() {
    }

    @Override
    public DbType type() {
        return DbType.DB2_LUW;
    }

    @Override
    public String driverClassName() {
        return "com.ibm.db2.jcc.DB2Driver";
    }

    @Override
    public String urlPrefix() {
        return "jdbc:db2:";
    }

    @Override
    public Set<String> allowedUrlProperties() {
        return ALLOWED;
    }

    @Override
    public boolean urlRequestsTls(String url) {
        return url.toLowerCase(Locale.ROOT).contains("sslconnection=true");
    }

    @Override
    public String validationQuery() {
        return "SELECT 1 FROM SYSIBM.SYSDUMMY1";
    }

    @Override
    public String defaultSchemaStatement(String schema) {
        return null;
    }

    @Override
    public Set<String> systemSchemas() {
        return Set.of("SYSCAT", "SYSIBM", "SYSIBMADM", "SYSSTAT", "SYSTOOLS", "SYSPROC", "SYSFUN", "SYSPUBLIC");
    }

    @Override
    public String normalizeIdentifier(String identifier) {
        return identifier.toUpperCase(Locale.ROOT);
    }
}
