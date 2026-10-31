package io.quarkiverse.mcp.servers.jdbc.policy;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager;
import io.quarkiverse.mcp.servers.jdbc.database.DbDialect;
import io.quarkiverse.mcp.servers.jdbc.database.MetadataService;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.WhitelistEntry;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

/**
 * Compares a policy with what the database really contains (plan item A13: a whitelist entry for a table that does not
 * exist, or for a system schema, must fail validation instead of silently never matching - or worse, matching something
 * unexpected later).
 */
public final class PolicyMetadataCheck {

    private PolicyMetadataCheck() {
    }

    /** Returns human-readable problems; empty means the policy agrees with the database. */
    public static List<String> check(PermissionPolicy policy, DbProfile profile, ConnectionManager connections)
            throws ConnectionManager.ProfileUnavailableException, SQLException {
        List<String> problems = new ArrayList<>();
        DbDialect dialect = DbDialect.of(profile.dbType());
        if (policy.write() == null) {
            return problems;
        }
        try (Connection c = connections.getConnection(profile)) {
            DatabaseMetaData md = c.getMetaData();
            for (String schema : policy.write().allowedSchemas()) {
                if (PermissionService.isReservedSchema(dialect.systemSchemas(), schema)) {
                    problems.add("Schema " + schema + " is a system schema and cannot be writable");
                } else if (!schemaExists(md, dialect, schema)) {
                    problems.add("Schema " + schema + " does not exist");
                }
            }
            for (WhitelistEntry e : policy.write().whitelist()) {
                if (PermissionService.isReservedSchema(dialect.systemSchemas(), e.schema())) {
                    problems.add(e.schema() + "." + e.table() + " is in a system schema and cannot be writable");
                } else if (!tableExists(md, dialect, e.schema(), e.table())) {
                    problems.add("Table " + e.schema() + "." + e.table() + " does not exist");
                }
            }
            for (var template : policy.write().templates()) {
                var shape = template.shape();
                if (PermissionService.isReservedSchema(dialect.systemSchemas(), shape.schema())
                        || !tableExists(md, dialect, shape.schema(), shape.table())) {
                    problems.add("SQL template target is missing or reserved: " + template.id());
                    continue;
                }
                var target = MetadataService.resolveTable(c, profile.dbType(), shape.schema(), shape.table());
                if (target == null) {
                    problems.add("SQL template target is ambiguous: " + template.id());
                    continue;
                }
                var columns = MetadataService.columns(c, profile.dbType(), target[0], target[1]);
                for (String name : shape.parameterColumns()) {
                    var column = columns.get(name.toUpperCase(Locale.ROOT));
                    if (column == null || (shape.values().contains(name) && (column.generated() || column.autoIncrement()))) {
                        problems.add("SQL template column is missing or generated: " + template.id());
                    }
                }
            }
            c.rollback();
        }
        return problems;
    }

    private static boolean schemaExists(DatabaseMetaData md, DbDialect dialect, String schema) throws SQLException {
        try (ResultSet rs = md.getSchemas()) {
            while (rs.next()) {
                if (rs.getString("TABLE_SCHEM").equalsIgnoreCase(schema)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean tableExists(DatabaseMetaData md, DbDialect dialect, String schema, String table)
            throws SQLException {
        // Ask with the dialect's own folding first, then fall back to a case-insensitive scan of that schema.
        try (ResultSet rs = md.getTables(null, dialect.normalizeIdentifier(schema), dialect.normalizeIdentifier(table),
                new String[] { "TABLE" })) {
            if (rs.next()) {
                return true;
            }
        }
        try (ResultSet rs = md.getTables(null, null, "%", new String[] { "TABLE" })) {
            while (rs.next()) {
                String s = rs.getString("TABLE_SCHEM");
                String t = rs.getString("TABLE_NAME");
                if (s != null && s.toUpperCase(Locale.ROOT).equals(schema.toUpperCase(Locale.ROOT))
                        && t.toUpperCase(Locale.ROOT).equals(table.toUpperCase(Locale.ROOT))) {
                    return true;
                }
            }
        }
        return false;
    }
}
