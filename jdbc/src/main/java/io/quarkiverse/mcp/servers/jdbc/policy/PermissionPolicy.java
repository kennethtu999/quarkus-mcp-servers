package io.quarkiverse.mcp.servers.jdbc.policy;

import java.util.List;
import java.util.Set;

/**
 * A validated, immutable per-profile policy. Instances are only produced by {@link PolicyValidator}, so holding one
 * means every rule in section 8.4 of the plan has already been checked.
 */
public record PermissionPolicy(
        int version,
        String profile,
        String profileId,
        AccessMode access,
        int readMaxRows,
        int readTimeoutSeconds,
        Write write,
        String hash) {

    /** Hard ceiling for rows returned to the AI. Not configurable: neither YAML nor a tool argument can raise it. */
    public static final int MAX_READ_ROWS_HARD_LIMIT = 500;
    public static final int DEFAULT_READ_TIMEOUT_SECONDS = 30;
    public static final int MAX_READ_TIMEOUT_SECONDS = 120;
    /** Ceiling for {@code maxAffectedRows}; YAML may set a lower value. */
    public static final int MAX_AFFECTED_ROWS_HARD_LIMIT = 1000;
    public static final int DEFAULT_MAX_AFFECTED_ROWS = 100;

    public enum Operation {
        INSERT,
        UPDATE,
        DELETE
    }

    /** One whitelist entry. Schema and table are stored exactly as written; matching is done by {@link PermissionService}. */
    public record WhitelistEntry(String schema, String table, Set<Operation> operations) {
    }

    public record Write(
            List<String> allowedSchemas,
            Set<Operation> operations,
            List<WhitelistEntry> whitelist,
            int maxAffectedRows,
            boolean requireConfirmation) {
    }

    public PermissionPolicy {
        if (readMaxRows < 1 || readMaxRows > MAX_READ_ROWS_HARD_LIMIT) {
            throw new IllegalArgumentException("read.maxRows out of range");
        }
    }

    /** The read limit that actually applies: never above the hard limit, never above the policy value. */
    public int effectiveReadLimit(Integer requested) {
        int limit = Math.min(readMaxRows, MAX_READ_ROWS_HARD_LIMIT);
        return requested == null ? limit : Math.max(1, Math.min(requested, limit));
    }
}
