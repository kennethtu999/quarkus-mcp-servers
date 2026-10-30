package io.quarkiverse.mcp.servers.jdbc.security;

import java.util.Locale;
import java.util.Set;

import io.quarkiverse.mcp.servers.jdbc.database.DbType;

/**
 * The only functions an AI-supplied SELECT may call. Anything not listed is rejected, which is what keeps
 * side-effecting or file/network-touching functions (pg_sleep, pg_read_file, dblink, lo_import, DBMS_*, UTL_*,
 * nextval, XMLQUERY, ...) out without having to enumerate them.
 * <p>
 * The lists are deliberately boring: aggregates, null handling, simple string, numeric and date helpers.
 */
final class FunctionAllowlists {

    private static final Set<String> COMMON = Set.of(
            // aggregates
            "COUNT", "SUM", "AVG", "MIN", "MAX",
            // null handling / conditionals
            "COALESCE", "NULLIF",
            // strings
            "UPPER", "LOWER", "LENGTH", "SUBSTR", "SUBSTRING", "TRIM", "LTRIM", "RTRIM", "REPLACE", "CONCAT",
            "LPAD", "RPAD", "INSTR", "POSITION",
            // numbers
            "ABS", "ROUND", "TRUNC", "TRUNCATE", "FLOOR", "CEIL", "CEILING", "MOD", "POWER", "SQRT", "SIGN",
            // dates (no clock-dependent writes, only reads)
            "EXTRACT", "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND", "DATE",
            // ranking, used with OVER
            "ROW_NUMBER", "RANK", "DENSE_RANK");

    private static final Set<String> DB2 = Set.of("VALUE", "CHAR", "VARCHAR", "INTEGER", "DECIMAL", "TIMESTAMP",
            "DAYS", "LCASE", "UCASE", "LOCATE", "DIGITS", "STRIP");

    private static final Set<String> POSTGRES = Set.of("TO_CHAR", "TO_DATE", "TO_NUMBER", "TO_TIMESTAMP", "DATE_TRUNC",
            "DATE_PART", "AGE", "LEFT", "RIGHT", "INITCAP", "CONCAT_WS", "STRING_AGG");

    private static final Set<String> ORACLE = Set.of("NVL", "NVL2", "TO_CHAR", "TO_DATE", "TO_NUMBER", "TO_TIMESTAMP",
            "DECODE", "ADD_MONTHS", "MONTHS_BETWEEN", "LAST_DAY", "INITCAP", "LISTAGG");

    private FunctionAllowlists() {
    }

    static boolean allowed(DbType type, String functionName) {
        if (functionName == null || functionName.contains(".")) {
            // schema-qualified calls are user-defined functions or package members (DBMS_OUTPUT.PUT, myschema.fn)
            return false;
        }
        String name = functionName.toUpperCase(Locale.ROOT);
        if (COMMON.contains(name)) {
            return true;
        }
        return switch (type) {
            case DB2_LUW -> DB2.contains(name);
            case POSTGRESQL -> POSTGRES.contains(name);
            case ORACLE -> ORACLE.contains(name);
        };
    }
}
