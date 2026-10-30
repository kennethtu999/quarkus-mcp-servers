package io.quarkiverse.mcp.servers.jdbc.database;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Reads table and column metadata through JDBC {@link DatabaseMetaData}. System schemas are filtered out, and caller
 * supplied names are only ever used as metadata <em>patterns</em> after being validated, never concatenated into SQL.
 */
public final class MetadataService {

    public static final int DEFAULT_PAGE_SIZE = 50;
    public static final int MAX_PAGE_SIZE = 200;
    private static final Pattern NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_$#]{0,127}");

    public record TablePage(int total, int page, int pageSize, List<Map<String, String>> tables) {
    }

    private MetadataService() {
    }

    /**
     * Turns a literal identifier into a JDBC metadata pattern that matches only itself. In these patterns {@code _} and
     * {@code %} are wildcards, and {@code _} is common in real names, so they must be escaped with the driver's escape
     * character; otherwise asking for {@code A_P} would also return tables of {@code APP} and {@code A1P}.
     */
    static String exact(DatabaseMetaData md, String literal) throws SQLException {
        String esc = md.getSearchStringEscape();
        if (esc == null || esc.isEmpty()) {
            // A driver with no escape character cannot express an exact match; refuse names that contain wildcards.
            if (literal.indexOf('_') >= 0 || literal.indexOf('%') >= 0) {
                throw new SQLException("Driver cannot match names containing '_' exactly");
            }
            return literal;
        }
        return literal.replace(esc, esc + esc).replace("_", esc + "_").replace("%", esc + "%");
    }

    /** Validates a schema or table name supplied by the AI. Wildcards are rejected so a name cannot match more than itself. */
    public static String requireName(String value, String what) {
        if (value == null || !NAME.matcher(value).matches()) {
            throw new IllegalArgumentException(what + " must be a plain identifier");
        }
        return value;
    }

    public static TablePage listTables(Connection conn, DbType type, String schema, Integer page, Integer size)
            throws SQLException {
        DbDialect dialect = DbDialect.of(type);
        int pageSize = size == null ? DEFAULT_PAGE_SIZE : Math.max(1, Math.min(size, MAX_PAGE_SIZE));
        int pageNo = page == null ? 1 : Math.max(1, page);
        DatabaseMetaData md = conn.getMetaData();
        String wanted = schema == null || schema.isBlank() ? null
                : dialect.normalizeIdentifier(requireName(schema, "schema"));
        String schemaPattern = wanted == null ? null : exact(md, wanted);
        Set<String> system = dialect.systemSchemas();

        List<Map<String, String>> all = new ArrayList<>();
        try (ResultSet rs = md.getTables(null, schemaPattern, "%", new String[] { "TABLE", "VIEW" })) {
            while (rs.next()) {
                String s = rs.getString("TABLE_SCHEM");
                if (wanted != null && (s == null || !s.equalsIgnoreCase(wanted))) {
                    continue; // second guard in case a driver mishandled the escape
                }
                if (s != null && system.contains(s.toUpperCase(Locale.ROOT)) || s != null && system.contains(s)) {
                    continue;
                }
                Map<String, String> t = new LinkedHashMap<>();
                t.put("schema", s);
                t.put("name", rs.getString("TABLE_NAME"));
                t.put("type", rs.getString("TABLE_TYPE"));
                String remarks = rs.getString("REMARKS");
                if (remarks != null && !remarks.isBlank()) {
                    t.put("remarks", remarks.length() > 200 ? remarks.substring(0, 200) : remarks);
                }
                all.add(t);
            }
        }
        all.sort((a, b) -> (a.get("schema") + "." + a.get("name")).compareTo(b.get("schema") + "." + b.get("name")));
        int from = Math.min((pageNo - 1) * pageSize, all.size());
        int to = Math.min(from + pageSize, all.size());
        return new TablePage(all.size(), pageNo, pageSize, List.copyOf(all.subList(from, to)));
    }

    /** Returns the columns of one table, or an empty list if it does not exist or is in a system schema. */
    public static List<Map<String, Object>> describeTable(Connection conn, DbType type, String schema, String table)
            throws SQLException {
        DbDialect dialect = DbDialect.of(type);
        requireName(schema, "schema");
        requireName(table, "table");
        if (dialect.systemSchemas().contains(schema.toUpperCase(Locale.ROOT)) || dialect.systemSchemas().contains(schema)) {
            return List.of();
        }
        List<Map<String, Object>> columns = new ArrayList<>();
        DatabaseMetaData md = conn.getMetaData();
        String wantedSchema = dialect.normalizeIdentifier(schema);
        String wantedTable = dialect.normalizeIdentifier(table);
        try (ResultSet rs = md.getColumns(null, exact(md, wantedSchema), exact(md, wantedTable), "%")) {
            while (rs.next()) {
                if (!wantedSchema.equalsIgnoreCase(rs.getString("TABLE_SCHEM"))
                        || !wantedTable.equalsIgnoreCase(rs.getString("TABLE_NAME"))) {
                    continue; // second guard in case a driver mishandled the escape
                }
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("name", rs.getString("COLUMN_NAME"));
                c.put("type", rs.getString("TYPE_NAME"));
                c.put("size", rs.getInt("COLUMN_SIZE"));
                c.put("nullable", "YES".equalsIgnoreCase(rs.getString("IS_NULLABLE")));
                columns.add(c);
            }
        }
        return columns;
    }

    /**
     * Resolves the exact spelling of a table in the database (case differs between engines) so that a write can be
     * checked against, and built from, names that came from metadata rather than from the AI.
     *
     * @return {@code [schema, table]} as the database spells them, or {@code null} if no such table
     */
    public static String[] resolveTable(Connection conn, DbType type, String schema, String table) throws SQLException {
        DbDialect dialect = DbDialect.of(type);
        requireName(schema, "schema");
        requireName(table, "table");
        DatabaseMetaData md = conn.getMetaData();
        String wantedSchema = dialect.normalizeIdentifier(schema);
        String wantedTable = dialect.normalizeIdentifier(table);
        try (ResultSet rs = md.getTables(null, exact(md, wantedSchema), exact(md, wantedTable), new String[] { "TABLE" })) {
            String[] found = null;
            while (rs.next()) {
                if (!wantedSchema.equalsIgnoreCase(rs.getString("TABLE_SCHEM"))
                        || !wantedTable.equalsIgnoreCase(rs.getString("TABLE_NAME"))) {
                    continue;
                }
                if (found != null) {
                    return null; // ambiguous: refuse rather than guess
                }
                found = new String[] { rs.getString("TABLE_SCHEM"), rs.getString("TABLE_NAME") };
            }
            return found;
        }
    }
}
