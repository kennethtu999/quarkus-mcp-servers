package io.quarkiverse.mcp.servers.jdbc.change;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import io.quarkiverse.mcp.servers.jdbc.database.DbDialect;

/**
 * Builds the SQL for a {@link ValidatedChange}. The only text that reaches the SQL string is quoted identifiers that came
 * from JDBC metadata and fixed keywords; every value is a {@code ?} placeholder bound by the caller.
 */
public final class DmlBuilder {

    /** SQL text plus the values to bind, in placeholder order. */
    public record Statement(String sql, List<Object> params, List<Integer> types) {
    }

    private DmlBuilder() {
    }

    private static String table(DbDialect d, ValidatedChange c) {
        return d.quote(c.schema()) + "." + d.quote(c.table());
    }

    private static String where(DbDialect d, ValidatedChange c, List<Object> params, List<Integer> types) {
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, Object> e : c.conditions().entrySet()) {
            parts.add(d.quote(e.getKey()) + " = ?");
            params.add(e.getValue());
            types.add(c.columnTypes().get(e.getKey()));
        }
        return String.join(" AND ", parts);
    }

    /** The statement that applies the change. */
    public static Statement apply(ValidatedChange c) {
        DbDialect d = DbDialect.of(c.dbType());
        List<Object> params = new ArrayList<>();
        List<Integer> types = new ArrayList<>();
        switch (c.operation()) {
            case INSERT: {
                String cols = c.values().keySet().stream().map(d::quote).collect(Collectors.joining(", "));
                String marks = c.values().keySet().stream().map(k -> "?").collect(Collectors.joining(", "));
                for (Map.Entry<String, Object> e : c.values().entrySet()) {
                    params.add(e.getValue());
                    types.add(c.columnTypes().get(e.getKey()));
                }
                return new Statement("INSERT INTO " + table(d, c) + " (" + cols + ") VALUES (" + marks + ")", params, types);
            }
            case UPDATE: {
                List<String> sets = new ArrayList<>();
                for (Map.Entry<String, Object> e : c.values().entrySet()) {
                    sets.add(d.quote(e.getKey()) + " = ?");
                    params.add(e.getValue());
                    types.add(c.columnTypes().get(e.getKey()));
                }
                String w = where(d, c, params, types);
                return new Statement("UPDATE " + table(d, c) + " SET " + String.join(", ", sets) + " WHERE " + w, params,
                        types);
            }
            case DELETE: {
                String w = where(d, c, params, types);
                return new Statement("DELETE FROM " + table(d, c) + " WHERE " + w, params, types);
            }
            default:
                throw new IllegalStateException("Unsupported operation");
        }
    }

    /** How many rows the change would touch; {@code null} for INSERT, which always adds exactly one row. */
    public static Statement count(ValidatedChange c) {
        if (c.operation() == io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation.INSERT) {
            return null;
        }
        DbDialect d = DbDialect.of(c.dbType());
        List<Object> params = new ArrayList<>();
        List<Integer> types = new ArrayList<>();
        return new Statement("SELECT COUNT(*) FROM " + table(d, c) + " WHERE " + where(d, c, params, types), params, types);
    }

    /**
     * Selects the rows the change would touch, locking them for the rest of the transaction. {@code columns} are the
     * columns whose before-values matter (those being set, plus any version column).
     * <p>
     * There is deliberately no row-limit clause: engines disagree about combining {@code FETCH FIRST}/{@code LIMIT} with
     * {@code FOR UPDATE} (Oracle and possibly Db2 refuse it) and that cannot be tested without those servers. The caller
     * has already verified, with {@link #count}, that the condition matches no more than {@code maxAffectedRows} rows, so
     * the set being locked is bounded; it re-checks the row count after locking.
     */
    public static Statement lockAndRead(ValidatedChange c, List<String> columns) {
        DbDialect d = DbDialect.of(c.dbType());
        List<Object> params = new ArrayList<>();
        List<Integer> types = new ArrayList<>();
        String cols = columns.isEmpty() ? "1" : columns.stream().map(d::quote).collect(Collectors.joining(", "));
        String w = where(d, c, params, types);
        return new Statement("SELECT " + cols + " FROM " + table(d, c) + " WHERE " + w + " FOR UPDATE", params, types);
    }
}
