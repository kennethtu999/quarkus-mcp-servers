package io.quarkiverse.mcp.servers.jdbc.change;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;

/**
 * A change whose schema, table and column names were resolved from JDBC metadata (never taken from the AI's text) and whose
 * values were coerced to the column types. Only this type can be turned into SQL.
 *
 * @param schema schema exactly as the database spells it
 * @param table table exactly as the database spells it
 * @param values column (database spelling) to typed value, in the order given
 * @param conditions column (database spelling) to typed value; combined with AND using equality only
 * @param columnTypes JDBC type of every column that appears in values or conditions
 */
public record ValidatedChange(
        DbType dbType,
        Operation operation,
        String schema,
        String table,
        Map<String, Object> values,
        Map<String, Object> conditions,
        Map<String, Integer> columnTypes,
        List<String> versionColumns) {

    public ValidatedChange {
        values = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(values));
        conditions = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(conditions));
        columnTypes = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(columnTypes));
        versionColumns = List.copyOf(versionColumns);
    }

    public String target() {
        return schema + "." + table;
    }
}
