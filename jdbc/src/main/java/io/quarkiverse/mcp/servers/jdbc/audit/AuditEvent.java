package io.quarkiverse.mcp.servers.jdbc.audit;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One audit record. Only fields listed here can be written, and none of them carries a password, key, JDBC URL or SQL
 * text: SQL is represented by a hash and a short normalised shape, parameters by their count.
 */
public final class AuditEvent {

    private final Map<String, Object> fields = new LinkedHashMap<>();

    private AuditEvent(String tool) {
        fields.put("tool", tool);
    }

    public static AuditEvent of(String tool) {
        return new AuditEvent(tool);
    }

    public AuditEvent requestId(String v) {
        return put("requestId", v);
    }

    public AuditEvent actor(String v) {
        return put("actorId", v);
    }

    public AuditEvent profile(String profileId, String label) {
        put("profileId", profileId);
        return put("profileLabel", label);
    }

    public AuditEvent operation(String v) {
        return put("operation", v);
    }

    public AuditEvent target(String v) {
        return put("target", v);
    }

    public AuditEvent policyVersion(String v) {
        return put("policyVersion", v);
    }

    /** {@code ALLOW} or {@code DENY}. */
    public AuditEvent decision(String v) {
        return put("decision", v);
    }

    public AuditEvent code(String v) {
        return put("code", v);
    }

    /** For example {@code OK}, {@code COMMITTED}, {@code ROLLED_BACK}, {@code ERROR}. */
    public AuditEvent result(String v) {
        return put("result", v);
    }

    public AuditEvent rows(long v) {
        return put("rowCount", v);
    }

    public AuditEvent affectedRows(long v) {
        return put("affectedRows", v);
    }

    public AuditEvent durationMs(long v) {
        return put("durationMs", v);
    }

    public AuditEvent sqlHash(String v) {
        return put("sqlHash", v);
    }

    public AuditEvent detail(String v) {
        return put("detail", v);
    }

    private AuditEvent put(String key, Object value) {
        if (value != null) {
            fields.put(key, value);
        }
        return this;
    }

    /** True once a tool body has set its own result (for example {@code COMMITTED}); the gateway then keeps it. */
    public boolean hasResult() {
        return fields.containsKey("result");
    }

    Map<String, Object> fields() {
        return fields;
    }
}
