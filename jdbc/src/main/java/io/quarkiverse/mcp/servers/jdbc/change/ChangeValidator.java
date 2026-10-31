package io.quarkiverse.mcp.servers.jdbc.change;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Types;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.mcp.servers.jdbc.database.DbDialect;
import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import io.quarkiverse.mcp.servers.jdbc.database.MetadataService;
import io.quarkiverse.mcp.servers.jdbc.database.MetadataService.Column;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;

/**
 * Turns an AI-supplied {@link ChangeRequest} into a {@link ValidatedChange}, or refuses it.
 * <p>
 * Everything here is deny-by-default: the table must exist and be unambiguous, every column must exist, generated and
 * identity columns cannot be written, the operation must have the right shape (an UPDATE or DELETE without a condition is
 * refused), and every value must convert cleanly to its column's type. There is no "best effort" conversion.
 */
public final class ChangeValidator {

    public static final int MAX_COLUMNS = 100;
    public static final int MAX_STRING = 10_000;
    /** Names (upper-cased) that conventionally hold an optimistic-lock version. */
    static final Set<String> VERSION_NAMES = Set.of("VERSION", "ROW_VERSION", "VERSION_NO", "LOCK_VERSION", "REV", "REVISION");

    public static final class Invalid extends Exception {
        public Invalid(String message) {
            super(message);
        }
    }

    private ChangeValidator() {
    }

    /**
     * Phase 1: resolve the target table's real spelling. Nothing about columns, values or the shape of the request is
     * examined or reported here, so the caller can check permission on the resolved name <em>before</em> a profile that
     * may not write learns anything about the table's columns or about how to build a valid request.
     *
     * @return {@code [schema, table]} exactly as the database spells them
     */
    public static String[] resolveTarget(Connection conn, DbType type, ChangeRequest req) throws SQLException, Invalid {
        if (req.operation() == null) {
            throw new Invalid("operation must be INSERT, UPDATE or DELETE");
        }
        try {
            MetadataService.requireName(req.schema(), "schema");
            MetadataService.requireName(req.table(), "table");
        } catch (IllegalArgumentException e) {
            throw new Invalid(e.getMessage());
        }
        DbDialect dialect = DbDialect.of(type);
        if (dialect.systemSchemas().contains(req.schema().toUpperCase(Locale.ROOT))
                || dialect.systemSchemas().contains(req.schema())) {
            throw new Invalid("System schemas cannot be modified");
        }
        String[] resolved = MetadataService.resolveTable(conn, type, req.schema(), req.table());
        if (resolved == null) {
            throw new Invalid("No such table (or the name is ambiguous)");
        }
        return resolved;
    }

    /** Phase 2, after permission was granted on {@code resolved}: shape, columns and value conversion. */
    public static ValidatedChange validate(Connection conn, DbType type, ChangeRequest req, String[] resolved)
            throws SQLException, Invalid {
        shape(req);
        Map<String, Column> columns = MetadataService.columns(conn, type, resolved[0], resolved[1]);
        if (columns.isEmpty()) {
            throw new Invalid("The table has no accessible columns");
        }

        Map<String, Object> values = new LinkedHashMap<>();
        Map<String, Object> conditions = new LinkedHashMap<>();
        Map<String, Integer> types = new LinkedHashMap<>();

        for (Map.Entry<String, Object> e : req.values().entrySet()) {
            Column c = column(columns, e.getKey());
            if (c.autoIncrement() || c.generated()) {
                throw new Invalid("Column " + c.name() + " is generated and cannot be written");
            }
            if (values.containsKey(c.name())) {
                throw new Invalid("Column " + c.name() + " is given more than once");
            }
            Object v = coerce(c, e.getValue());
            if (v == null && !c.nullable()) {
                throw new Invalid("Column " + c.name() + " cannot be null");
            }
            values.put(c.name(), v);
            types.put(c.name(), c.sqlType());
        }
        for (Map.Entry<String, Object> e : req.conditions().entrySet()) {
            Column c = column(columns, e.getKey());
            if (e.getValue() == null) {
                // "col = NULL" never matches anything; accepting it would turn a typo into a silent no-op that looks fine.
                throw new Invalid("Condition on " + c.name() + " cannot be null");
            }
            if (conditions.containsKey(c.name())) {
                throw new Invalid("Condition on " + c.name() + " is given more than once");
            }
            conditions.put(c.name(), coerce(c, e.getValue()));
            types.put(c.name(), c.sqlType());
        }

        if (req.operation() == Operation.UPDATE) {
            for (String col : values.keySet()) {
                if (conditions.containsKey(col)) {
                    throw new Invalid("Column " + col + " is both updated and used as a condition; use a different key");
                }
            }
        }

        List<String> versions = new ArrayList<>();
        for (Column c : columns.values()) {
            if (VERSION_NAMES.contains(c.name().toUpperCase(Locale.ROOT))) {
                versions.add(c.name());
            }
        }
        return new ValidatedChange(type, req.operation(), resolved[0], resolved[1], values, conditions, types, versions);
    }

    private static void shape(ChangeRequest req) throws Invalid {
        int vals = req.values().size();
        int conds = req.conditions().size();
        if (vals > MAX_COLUMNS || conds > MAX_COLUMNS) {
            throw new Invalid("Too many columns");
        }
        switch (req.operation()) {
            case INSERT -> {
                if (vals == 0) {
                    throw new Invalid("INSERT needs at least one value");
                }
                if (conds != 0) {
                    throw new Invalid("INSERT does not take conditions");
                }
            }
            case UPDATE -> {
                if (vals == 0) {
                    throw new Invalid("UPDATE needs at least one value to set");
                }
                if (conds == 0) {
                    throw new Invalid("UPDATE without a condition would change every row and is not allowed");
                }
            }
            case DELETE -> {
                if (conds == 0) {
                    throw new Invalid("DELETE without a condition would remove every row and is not allowed");
                }
                if (vals != 0) {
                    throw new Invalid("DELETE does not take values");
                }
            }
        }
    }

    private static Column column(Map<String, Column> columns, String name) throws Invalid {
        if (name == null || name.isBlank() || name.length() > 128) {
            throw new Invalid("Invalid column name");
        }
        Column c = columns.get(name.toUpperCase(Locale.ROOT));
        if (c == null) {
            throw new Invalid("No such column: " + abbreviate(name));
        }
        return c;
    }

    /**
     * Strict conversion of a JSON scalar to the column's type. Strings are not silently turned into numbers or dates by
     * the database: they must parse here first.
     */
    static Object coerce(Column c, Object v) throws Invalid {
        if (v == null) {
            return null;
        }
        if (v instanceof Map || v instanceof Iterable || v.getClass().isArray()) {
            throw new Invalid("Column " + c.name() + " only accepts a single value");
        }
        try {
            switch (c.sqlType()) {
                case Types.TINYINT, Types.SMALLINT, Types.INTEGER:
                    return exactInt(v, Integer.MIN_VALUE, Integer.MAX_VALUE).intValueExact();
                case Types.BIGINT:
                    return exactInt(v, Long.MIN_VALUE, Long.MAX_VALUE).longValueExact();
                case Types.DECIMAL, Types.NUMERIC, Types.FLOAT, Types.REAL, Types.DOUBLE:
                    return new BigDecimal(v.toString().strip());
                case Types.BOOLEAN, Types.BIT:
                    if (v instanceof Boolean b) {
                        return b;
                    }
                    String s = v.toString().strip().toLowerCase(Locale.ROOT);
                    if (s.equals("true") || s.equals("1")) {
                        return true;
                    }
                    if (s.equals("false") || s.equals("0")) {
                        return false;
                    }
                    throw new Invalid("Column " + c.name() + " expects true or false");
                case Types.DATE:
                    return java.sql.Date.valueOf(LocalDate.parse(v.toString().strip()));
                case Types.TIMESTAMP, Types.TIMESTAMP_WITH_TIMEZONE:
                    return parseTimestamp(v.toString().strip());
                case Types.CHAR, Types.VARCHAR, Types.NCHAR, Types.NVARCHAR, Types.LONGVARCHAR, Types.LONGNVARCHAR, Types.CLOB,
                        Types.NCLOB:
                    String str = v.toString();
                    if (str.length() > MAX_STRING || (c.size() > 0 && str.codePointCount(0, str.length()) > c.size())) {
                        throw new Invalid("Value for " + c.name() + " is too long");
                    }
                    if (str.indexOf('\0') >= 0) {
                        throw new Invalid("Value for " + c.name() + " contains a NUL character");
                    }
                    return str;
                default:
                    throw new Invalid("Column " + c.name() + " has type " + c.typeName() + ", which cannot be modified here");
            }
        } catch (NumberFormatException | ArithmeticException | DateTimeParseException e) {
            throw new Invalid("Value for " + c.name() + " does not fit the column type " + c.typeName());
        }
    }

    private static BigDecimal exactInt(Object v, long min, long max) throws Invalid {
        if (v instanceof Boolean) {
            throw new Invalid("A number is required");
        }
        BigDecimal d = new BigDecimal(v.toString().strip());
        if (d.stripTrailingZeros().scale() > 0) {
            throw new Invalid("A whole number is required");
        }
        if (d.compareTo(BigDecimal.valueOf(min)) < 0 || d.compareTo(BigDecimal.valueOf(max)) > 0) {
            throw new Invalid("Number out of range");
        }
        return d.setScale(0);
    }

    private static java.sql.Timestamp parseTimestamp(String s) {
        try {
            return java.sql.Timestamp.valueOf(LocalDateTime.parse(s.replace(' ', 'T')));
        } catch (DateTimeParseException first) {
            return java.sql.Timestamp.from(OffsetDateTime.parse(s.replace(' ', 'T')).toInstant());
        }
    }

    private static String abbreviate(String s) {
        return s.length() <= 40 ? s : s.substring(0, 40) + "...";
    }
}
