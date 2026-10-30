package io.quarkiverse.mcp.servers.jdbc.database;

import java.math.BigDecimal;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs an already-validated SELECT and returns at most {@code limit} rows.
 * <p>
 * Defence in depth, in addition to {@code SqlGuard}: the connection is switched to read-only, the statement has a
 * timeout, and the transaction is always rolled back, so even a SELECT that somehow had a side effect cannot commit.
 * <p>
 * The row limit is applied three times: {@code setMaxRows}, the read loop, and the size cap. {@code limit + 1} rows are
 * requested so that {@code truncated} is accurate, but the extra row is only counted - it is never read into the result.
 */
public final class QueryExecutor {

    /** Cap on the serialised size of one result, independent of the row count (plan section 11.2). */
    public static final int MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
    /** Longest text value returned in one cell; longer values are cut and marked. */
    public static final int MAX_CELL_CHARS = 4_096;
    public static final int MAX_COLUMNS = 200;

    public record Result(List<String> columns, List<Map<String, Object>> rows, boolean truncated, String truncationReason) {
        public int rowCount() {
            return rows.size();
        }
    }

    private QueryExecutor() {
    }

    /**
     * @param params values for {@code ?} placeholders, bound as parameters (never concatenated into the SQL)
     * @param limit already clamped by the policy; re-clamped here so this class is safe on its own
     */
    public static Result run(Connection conn, DbType type, String sql, List<Object> params, int limit, int timeoutSeconds)
            throws SQLException {
        return run(conn, DbDialect.of(type).readOnlyTransactionStatement(), sql, params, limit, timeoutSeconds);
    }

    /**
     * @param readOnlyStatement dialect specific statement that starts a read-only transaction, or {@code null}
     */
    public static Result run(Connection conn, String readOnlyStatement, String sql, List<Object> params, int limit,
            int timeoutSeconds) throws SQLException {
        int effective = Math.max(1, Math.min(limit, 500));
        boolean wasReadOnly = conn.isReadOnly();
        boolean wasAutoCommit = conn.getAutoCommit();
        try {
            conn.setAutoCommit(false);
            conn.setReadOnly(true);
            if (readOnlyStatement != null) {
                try (var st = conn.createStatement()) {
                    st.execute(readOnlyStatement);
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(sql, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
                ps.setQueryTimeout(Math.max(1, timeoutSeconds));
                ps.setMaxRows(effective + 1);
                ps.setFetchSize(Math.min(effective + 1, 500));
                for (int i = 0; i < params.size(); i++) {
                    bind(ps, i + 1, params.get(i));
                }
                try (ResultSet rs = ps.executeQuery()) {
                    return read(rs, effective);
                }
            }
        } finally {
            try {
                conn.rollback();
            } catch (SQLException ignored) {
                // the connection is returned to the pool and validated there
            }
            try {
                conn.setReadOnly(wasReadOnly);
                conn.setAutoCommit(wasAutoCommit);
            } catch (SQLException ignored) {
                // see above
            }
        }
    }

    private static Result read(ResultSet rs, int limit) throws SQLException {
        ResultSetMetaData md = rs.getMetaData();
        int n = md.getColumnCount();
        if (n > MAX_COLUMNS) {
            throw new SQLException("Too many columns in the result");
        }
        List<String> columns = new ArrayList<>(n);
        for (int i = 1; i <= n; i++) {
            String label = md.getColumnLabel(i);
            columns.add(uniqueName(columns, label == null ? "COLUMN" + i : label));
        }

        List<Map<String, Object>> rows = new ArrayList<>();
        long bytes = 0;
        boolean truncated = false;
        String reason = null;
        while (rs.next()) {
            if (rows.size() >= limit) {
                // The (limit+1)th row exists. Count it, do not read it.
                truncated = true;
                reason = "ROW_LIMIT";
                break;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            long rowBytes = 0;
            for (int i = 1; i <= n; i++) {
                Object v = cell(rs, i, md.getColumnType(i));
                row.put(columns.get(i - 1), v);
                rowBytes += columns.get(i - 1).length() + (v == null ? 4 : String.valueOf(v).length()) + 6;
            }
            if (bytes + rowBytes > MAX_OUTPUT_BYTES) {
                truncated = true;
                reason = "SIZE_LIMIT";
                break;
            }
            bytes += rowBytes;
            rows.add(row);
        }
        return new Result(List.copyOf(columns), List.copyOf(rows), truncated, reason);
    }

    private static Object cell(ResultSet rs, int i, int sqlType) throws SQLException {
        switch (sqlType) {
            case Types.BLOB, Types.BINARY, Types.VARBINARY, Types.LONGVARBINARY: {
                // Binary content is never sent to the AI; only its presence and size.
                Object o = rs.getObject(i);
                if (o == null) {
                    return null;
                }
                if (o instanceof byte[] b) {
                    return "<binary " + b.length + " bytes>";
                }
                if (o instanceof Blob blob) {
                    return "<binary " + blob.length() + " bytes>";
                }
                return "<binary>";
            }
            case Types.CLOB, Types.NCLOB: {
                Clob c = rs.getClob(i);
                if (c == null) {
                    return null;
                }
                long len = c.length();
                String head = c.getSubString(1, (int) Math.min(len, MAX_CELL_CHARS));
                return len > MAX_CELL_CHARS ? head + "…[truncated, " + len + " chars]" : head;
            }
            case Types.ARRAY, Types.STRUCT, Types.SQLXML, Types.JAVA_OBJECT, Types.OTHER, Types.REF, Types.DATALINK:
                return rs.getObject(i) == null ? null : "<" + typeName(sqlType) + ">";
            default:
                break;
        }
        Object o = rs.getObject(i);
        if (o == null) {
            return null;
        }
        if (o instanceof Number || o instanceof Boolean) {
            return o instanceof BigDecimal bd ? bd.toPlainString() : o;
        }
        String s = o.toString();
        return s.length() > MAX_CELL_CHARS ? s.substring(0, MAX_CELL_CHARS) + "…[truncated, " + s.length() + " chars]" : s;
    }

    private static String typeName(int t) {
        return switch (t) {
            case Types.ARRAY -> "array";
            case Types.STRUCT -> "struct";
            case Types.SQLXML -> "xml";
            default -> "object";
        };
    }

    private static void bind(PreparedStatement ps, int idx, Object v) throws SQLException {
        if (v == null) {
            ps.setObject(idx, null);
        } else if (v instanceof String s) {
            ps.setString(idx, s);
        } else if (v instanceof Integer i) {
            ps.setInt(idx, i);
        } else if (v instanceof Long l) {
            ps.setLong(idx, l);
        } else if (v instanceof Double d) {
            ps.setDouble(idx, d);
        } else if (v instanceof Boolean b) {
            ps.setBoolean(idx, b);
        } else if (v instanceof BigDecimal bd) {
            ps.setBigDecimal(idx, bd);
        } else {
            throw new SQLException("Unsupported parameter type");
        }
    }

    private static String uniqueName(List<String> existing, String name) {
        if (!existing.contains(name)) {
            return name;
        }
        int k = 2;
        while (existing.contains(name + "_" + k)) {
            k++;
        }
        return name + "_" + k;
    }
}
