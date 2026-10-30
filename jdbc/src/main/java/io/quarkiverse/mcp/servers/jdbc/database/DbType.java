package io.quarkiverse.mcp.servers.jdbc.database;

import java.util.Locale;

public enum DbType {
    DB2_LUW,
    POSTGRESQL,
    ORACLE;

    public static DbType parse(String value) {
        if (value == null) {
            throw new IllegalArgumentException("DB type is required");
        }
        try {
            return valueOf(value.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unsupported DB type '" + value + "' (expected DB2_LUW, POSTGRESQL or ORACLE)");
        }
    }
}
