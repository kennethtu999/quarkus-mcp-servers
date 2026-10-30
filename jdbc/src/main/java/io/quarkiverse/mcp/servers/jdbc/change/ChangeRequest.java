package io.quarkiverse.mcp.servers.jdbc.change;

import java.util.LinkedHashMap;
import java.util.Map;

import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;

/**
 * What the AI asked for, before anything has been checked. Names are the AI's spelling; the validated form is a
 * {@link ValidatedChange}, which only {@link ChangeValidator} can produce.
 */
public record ChangeRequest(
        String profileRef,
        Operation operation,
        String schema,
        String table,
        Map<String, Object> values,
        Map<String, Object> conditions) {

    public ChangeRequest {
        values = values == null ? Map.of() : new LinkedHashMap<>(values);
        conditions = conditions == null ? Map.of() : new LinkedHashMap<>(conditions);
    }
}
