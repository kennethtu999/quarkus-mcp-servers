package io.quarkiverse.mcp.servers.jdbc.policy;

import java.util.Locale;
import java.util.Set;

import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.WhitelistEntry;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyRepository.Snapshot;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

/**
 * The single place that turns "profile + request" into allow or deny. Tools never reason about modes, schemas or tables
 * themselves; they ask here, so every tool applies exactly the same rules.
 * <p>
 * Everything is deny-by-default: an unusable policy, a disabled profile, an unlisted schema/table or an operation outside
 * the allowed set all yield a denial with a stable code that goes into the audit log.
 */
public final class PermissionService {

    public static final String PROFILE_DISABLED = "PROFILE_DISABLED";
    public static final String POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE";
    public static final String WRITE_NOT_PERMITTED = "WRITE_NOT_PERMITTED";
    public static final String SCHEMA_NOT_ALLOWED = "SCHEMA_NOT_ALLOWED";
    public static final String TABLE_NOT_ALLOWED = "TABLE_NOT_ALLOWED";
    public static final String OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED";

    private final PolicyRepository policies;

    public PermissionService(PolicyRepository policies) {
        this.policies = policies;
    }

    /** May the AI read from this profile at all? Table-level read limits are enforced by the database's own grants. */
    public Decision checkRead(DbProfile profile) {
        Decision usable = usable(profile);
        return usable.allowed() ? Decision.allow() : usable;
    }

    /**
     * May this exact write be performed? Schema and table must already be the names resolved from JDBC metadata, not the
     * raw strings the AI sent; comparison is case-insensitive because the metadata spelling depends on the database.
     */
    public Decision checkWrite(DbProfile profile, Operation operation, String schema, String table) {
        Snapshot snap = policies.current(profile);
        Decision usable = usable(profile, snap);
        if (!usable.allowed()) {
            return usable;
        }
        PermissionPolicy policy = snap.policy();
        if (!policy.access().allowsWrite() || policy.write() == null) {
            return Decision.deny(WRITE_NOT_PERMITTED, "This profile is read-only");
        }
        if (schema == null || table == null) {
            return Decision.deny(TABLE_NOT_ALLOWED, "Schema and table are required");
        }
        PermissionPolicy.Write w = policy.write();
        return switch (policy.access()) {
            case READ_WRITE -> {
                boolean schemaOk = w.allowedSchemas().stream().anyMatch(s -> s.equalsIgnoreCase(schema));
                if (!schemaOk) {
                    yield Decision.deny(SCHEMA_NOT_ALLOWED, "Writes to schema " + schema + " are not permitted");
                }
                yield w.operations().contains(operation) ? Decision.allow()
                        : Decision.deny(OPERATION_NOT_ALLOWED, operation + " is not permitted on this profile");
            }
            case READ_WRITE_WHITELIST -> {
                WhitelistEntry entry = w.whitelist().stream()
                        .filter(e -> e.schema().equalsIgnoreCase(schema) && e.table().equalsIgnoreCase(table))
                        .findFirst().orElse(null);
                if (entry == null) {
                    yield Decision.deny(TABLE_NOT_ALLOWED, schema + "." + table + " is not on the write whitelist");
                }
                yield entry.operations().contains(operation) ? Decision.allow()
                        : Decision.deny(OPERATION_NOT_ALLOWED,
                                operation + " is not permitted on " + schema + "." + table);
            }
            default -> Decision.deny(WRITE_NOT_PERMITTED, "This profile is read-only");
        };
    }

    /** The row limit for a query: the stricter of the policy value, the caller's request and the hard limit of 500. */
    public int readLimit(DbProfile profile, Integer requested) {
        Snapshot snap = policies.current(profile);
        int policyMax = snap.active() ? snap.policy().readMaxRows() : PermissionPolicy.MAX_READ_ROWS_HARD_LIMIT;
        int limit = Math.min(policyMax, PermissionPolicy.MAX_READ_ROWS_HARD_LIMIT);
        return requested == null ? limit : Math.max(1, Math.min(requested, limit));
    }

    public int readTimeoutSeconds(DbProfile profile) {
        Snapshot snap = policies.current(profile);
        return snap.active() ? snap.policy().readTimeoutSeconds() : PermissionPolicy.DEFAULT_READ_TIMEOUT_SECONDS;
    }

    public Snapshot snapshot(DbProfile profile) {
        return policies.current(profile);
    }

    /** Identifiers that may never be written, whatever a policy says. */
    public static boolean isReservedSchema(Set<String> systemSchemas, String schema) {
        return schema != null && systemSchemas.contains(schema.toUpperCase(Locale.ROOT));
    }

    private Decision usable(DbProfile profile) {
        return usable(profile, policies.current(profile));
    }

    private static Decision usable(DbProfile profile, Snapshot snap) {
        if (!profile.enabled()) {
            return Decision.deny(PROFILE_DISABLED, "Profile " + profile.label() + " is disabled");
        }
        if (!snap.active()) {
            return Decision.deny(POLICY_UNAVAILABLE,
                    "Profile " + profile.label() + " has no usable policy (" + snap.state() + "): " + snap.reason());
        }
        return Decision.allow();
    }
}
