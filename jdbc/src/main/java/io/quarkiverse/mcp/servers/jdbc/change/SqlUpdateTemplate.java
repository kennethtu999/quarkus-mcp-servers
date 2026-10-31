package io.quarkiverse.mcp.servers.jdbc.change;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;

/** Strict grammar for administrator-approved parameterized single-table UPDATE templates. */
public record SqlUpdateTemplate(String id, String sql) {

    private static final String NAME = "[A-Za-z_][A-Za-z0-9_$#]{0,127}";
    private static final Pattern UPDATE = Pattern.compile(
            "(?is)^UPDATE\\s+(" + NAME + ")\\.(" + NAME + ")\\s+SET\\s+(.+?)\\s+WHERE\\s+(.+)$");
    private static final Pattern TERM = Pattern.compile("^(" + NAME + ")\\s*=\\s*\\?$", Pattern.CASE_INSENSITIVE);

    public record Shape(String schema, String table, List<String> values, List<String> conditions) {
        public List<String> parameterColumns() {
            List<String> result = new ArrayList<>(values);
            result.addAll(conditions);
            return List.copyOf(result);
        }
    }

    public SqlUpdateTemplate {
        if (id == null || !id.matches("[A-Za-z][A-Za-z0-9_-]{0,63}")) {
            throw new IllegalArgumentException("SQL 範本 ID 必須是英數字、底線或連字號，且以英文字母開頭");
        }
        shape(sql);
    }

    public Shape shape() {
        return shape(sql);
    }

    private static Shape shape(String sql) {
        if (sql == null || sql.length() > 8192) {
            throw new IllegalArgumentException("SQL 範本長度無效");
        }
        var match = UPDATE.matcher(sql.strip());
        if (!match.matches()) {
            throw new IllegalArgumentException("只接受 UPDATE SCHEMA.TABLE SET COL=? WHERE KEY=? 的參數化範本");
        }
        List<String> values = columns(match.group(3), "\\s*,\\s*");
        List<String> conditions = columns(match.group(4), "(?i)\\s+AND\\s+");
        var seen = new HashSet<String>();
        for (String name : values) {
            seen.add(name.toUpperCase(Locale.ROOT));
        }
        if (conditions.stream().anyMatch(c -> seen.contains(c.toUpperCase(Locale.ROOT)))) {
            throw new IllegalArgumentException("SET 欄位不可同時作為 WHERE 條件");
        }
        return new Shape(match.group(1), match.group(2), values, conditions);
    }

    private static List<String> columns(String text, String separator) {
        List<String> columns = new ArrayList<>();
        var seen = new HashSet<String>();
        for (String term : text.split(separator, -1)) {
            var match = TERM.matcher(term.strip());
            if (!match.matches() || !seen.add(match.group(1).toUpperCase(Locale.ROOT))) {
                throw new IllegalArgumentException("SQL 範本僅接受不重複的 COL=?；WHERE 條件用 AND 連接，不接受其他 SQL 語法");
            }
            columns.add(match.group(1));
        }
        if (columns.isEmpty() || columns.size() > 100) {
            throw new IllegalArgumentException("SQL 範本欄位數無效");
        }
        return List.copyOf(columns);
    }

    public ChangeRequest bind(String profileRef, List<Object> parameters) {
        Shape shape = shape();
        if (parameters == null || parameters.size() != shape.parameterColumns().size()) {
            throw new IllegalArgumentException("SQL 範本參數數量不符");
        }
        var values = new LinkedHashMap<String, Object>();
        var conditions = new LinkedHashMap<String, Object>();
        int index = 0;
        for (String column : shape.values()) {
            values.put(column, parameters.get(index++));
        }
        for (String column : shape.conditions()) {
            conditions.put(column, parameters.get(index++));
        }
        return new ChangeRequest(profileRef, Operation.UPDATE, shape.schema(), shape.table(), values, conditions);
    }
}
