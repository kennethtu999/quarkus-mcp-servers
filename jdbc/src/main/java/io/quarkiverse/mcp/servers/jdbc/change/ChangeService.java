package io.quarkiverse.mcp.servers.jdbc.change;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.mcp.servers.jdbc.change.ApprovalService.Pending;
import io.quarkiverse.mcp.servers.jdbc.change.ApprovalService.Refused;
import io.quarkiverse.mcp.servers.jdbc.change.DmlBuilder.Statement;
import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager;
import io.quarkiverse.mcp.servers.jdbc.policy.Decision;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyRepository;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.tool.ToolGateway;

/**
 * Preview and execution of structured single-table changes.
 * <p>
 * Safety properties (each covered by tests):
 * <ul>
 * <li>No SQL from the AI: names come from metadata, values are bound parameters.</li>
 * <li>Preview changes nothing (its transaction is always rolled back).</li>
 * <li>Execution needs a one-time token that only a person on a terminal can obtain, bound to the exact change, policy
 * version and data fingerprint.</li>
 * <li>Execution re-checks policy, locks the rows, re-checks the fingerprint and the row count, and commits only if the number
 * of rows changed equals the number previewed. Anything else rolls back. Writes are never retried.</li>
 * </ul>
 */
public final class ChangeService {

    private static final ObjectMapper JSON = new ObjectMapper();
    /** Rows shown in a preview; the preview is for a human to read, not a data export. */
    static final int MAX_PREVIEW_ROWS = 10;

    private final ToolGateway gateway;
    private final ApprovalService approvals;

    public ChangeService(ToolGateway gateway, ApprovalService approvals) {
        this.gateway = gateway;
        this.approvals = approvals;
    }

    public String preview(ChangeRequest req) {
        return gateway.run("db_preview_change", String.valueOf(req.operation()), req.profileRef(), call -> {
            DbProfile profile = call.profile;
            var ctx = gateway.context();
            try (Connection c = connection(call)) {
                c.setAutoCommit(false);
                try {
                    ValidatedChange change = validateAndAuthorise(c, profile, req);
                    call.audit().target(change.target());

                    PolicyRepository.Snapshot snap = ctx.policies.current(profile);
                    int max = snap.policy().write().maxAffectedRows();
                    Observed seen = observe(c, change, max);
                    call.audit().affectedRows(seen.count);

                    String digest = digest(profile, change);
                    String id = ApprovalService.newPreviewId();
                    long expires = approvals.clock().millis() / 1000 + ApprovalService.TTL.toSeconds();
                    String summary = summary(profile, change, seen);
                    approvals.createPending(new Pending(id, profile.profileId(), profile.label(), "local-user", digest,
                            snap.policy().hash(), seen.fingerprint, seen.count, expires, summary, requestJson(req)));

                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("previewId", id);
                    out.put("requestId", call.requestId);
                    out.put("operation", change.operation().name());
                    out.put("target", change.target());
                    out.put("affectedRows", seen.count);
                    out.put("maxAffectedRows", max);
                    out.put("before", seen.sample);
                    out.put("after", change.values());
                    out.put("expiresInSeconds", ApprovalService.TTL.toSeconds());
                    out.put("nextStep", "Ask the user to run: ai-db-mcp approve " + id
                            + "  then call db_execute_change with the token it prints.");
                    call.audit().result("PREVIEWED");
                    return json(out);
                } finally {
                    c.rollback(); // a preview never changes data
                }
            }
        });
    }

    public String execute(String profileRef, String previewId, String token) {
        return gateway.run("db_execute_change", "EXECUTE", profileRef, call -> {
            DbProfile profile = call.profile;
            var ctx = gateway.context();
            Pending pending = approvals.readPending(previewId)
                    .orElseThrow(() -> new ToolGateway.Denied("PREVIEW_NOT_FOUND", "Unknown or expired preview"));
            if (!pending.profileId().equals(profile.profileId())) {
                throw new ToolGateway.Denied("PREVIEW_MISMATCH", "The preview belongs to another profile");
            }
            // The change to run is the one stored (and signed) at preview time; nothing sent now can alter it.
            ChangeRequest stored = parseRequest(pending.request(), profile);

            try (Connection c = connection(call)) {
                c.setAutoCommit(false);
                boolean committed = false;
                try {
                    ValidatedChange change = validateAndAuthorise(c, profile, stored);
                    call.audit().target(change.target());

                    PolicyRepository.Snapshot snap = ctx.policies.current(profile);
                    // The expected binding is rebuilt from the repeated request and current state, not read from the
                    // pending file, so a token granted for a different change or an older policy cannot be used here.
                    String digest = digest(profile, change);
                    int max = snap.policy().write().maxAffectedRows();

                    Observed locked = observeForUpdate(c, change, max);
                    Pending expected = new Pending(previewId, profile.profileId(), profile.label(), "local-user", digest,
                            snap.policy().hash(), locked.fingerprint, locked.count, pending.expiresAt(), pending.summary(),
                            pending.request());
                    try {
                        approvals.verifyAndConsume(expected, token);
                    } catch (Refused r) {
                        throw new ToolGateway.Denied(r.code(), r.getMessage());
                    }

                    call.audit().affectedRows(locked.count);
                    long changed = applyChange(c, change);
                    if (changed != locked.count || changed > max) {
                        throw new ToolGateway.Denied("ROW_COUNT_CHANGED",
                                "The number of affected rows differs from the preview");
                    }
                    c.commit();
                    committed = true;
                    call.audit().result("COMMITTED").affectedRows(changed);

                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("committedRows", changed);
                    out.put("target", change.target());
                    out.put("requestId", call.requestId);
                    return json(out);
                } finally {
                    if (!committed) {
                        try {
                            c.rollback();
                        } catch (SQLException ignored) {
                            // the pooled connection is validated before reuse
                        }
                        if (!call.audit().hasResult()) {
                            call.audit().result("ROLLED_BACK");
                        }
                    }
                }
            }
        });
    }

    // ---- steps ----

    /**
     * Resolves the table, checks permission on the resolved names, and only then validates columns and values. A profile
     * that may not perform the operation therefore never learns anything about the table's columns.
     */
    private ValidatedChange validateAndAuthorise(Connection c, DbProfile profile, ChangeRequest req) throws Exception {
        try {
            String[] target = ChangeValidator.resolveTarget(c, profile.dbType(), req);
            Decision d = gateway.context().permissions.checkWrite(profile, req.operation(), target[0], target[1]);
            if (!d.allowed()) {
                throw new ToolGateway.Denied(d);
            }
            return ChangeValidator.validate(c, profile.dbType(), req, target);
        } catch (ChangeValidator.Invalid e) {
            throw new ToolGateway.Denied("INVALID_CHANGE", e.getMessage());
        }
    }

    private record Observed(int count, String fingerprint, List<Map<String, Object>> sample) {
    }

    /** Counts the affected rows without locking (preview). */
    private Observed observe(Connection c, ValidatedChange change, int max) throws SQLException {
        if (change.operation() == PermissionPolicy.Operation.INSERT) {
            return new Observed(1, fingerprintOf(List.of()), List.of());
        }
        Statement count = DmlBuilder.count(change);
        int n = scalarInt(c, count);
        if (n == 0) {
            throw new ToolGateway.Denied("NO_MATCH", "No row matches the condition");
        }
        if (n > max) {
            throw new ToolGateway.Denied("TOO_MANY_ROWS", n + " rows match; the limit for this profile is " + max);
        }
        return readRows(c, change, DmlBuilder.lockAndRead(change, watched(change)), n, false);
    }

    /** Locks and re-reads the affected rows (execute). */
    private Observed observeForUpdate(Connection c, ValidatedChange change, int max) throws SQLException {
        if (change.operation() == PermissionPolicy.Operation.INSERT) {
            return new Observed(1, fingerprintOf(List.of()), List.of());
        }
        int n = scalarInt(c, DmlBuilder.count(change));
        if (n == 0) {
            throw new ToolGateway.Denied("NO_MATCH", "No row matches the condition");
        }
        if (n > max) {
            throw new ToolGateway.Denied("TOO_MANY_ROWS", n + " rows match; the limit for this profile is " + max);
        }
        return readRows(c, change, DmlBuilder.lockAndRead(change, watched(change)), n, true);
    }

    /** Columns whose before-values go into the fingerprint: everything being changed, plus any version column. */
    private static List<String> watched(ValidatedChange change) {
        List<String> cols = new ArrayList<>(change.conditions().keySet());
        for (String v : change.values().keySet()) {
            if (!cols.contains(v)) {
                cols.add(v);
            }
        }
        for (String v : change.versionColumns()) {
            if (!cols.contains(v)) {
                cols.add(v);
            }
        }
        return cols;
    }

    private Observed readRows(Connection c, ValidatedChange change, Statement st, int expected, boolean locked)
            throws SQLException {
        List<Map<String, Object>> rows = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(locked ? st.sql() : st.sql().replace(" FOR UPDATE", ""))) {
            ps.setQueryTimeout(30);
            bind(ps, st);
            try (ResultSet rs = ps.executeQuery()) {
                int cols = rs.getMetaData().getColumnCount();
                while (rs.next() && rows.size() <= expected) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    for (int i = 1; i <= cols; i++) {
                        Object v = rs.getObject(i);
                        row.put(rs.getMetaData().getColumnLabel(i), v == null ? null : v.toString());
                    }
                    rows.add(row);
                }
            }
        }
        if (rows.size() != expected) {
            throw new ToolGateway.Denied("ROW_COUNT_CHANGED", "The data changed while the change was being prepared");
        }
        List<Map<String, Object>> sample = rows.size() <= MAX_PREVIEW_ROWS ? rows : rows.subList(0, MAX_PREVIEW_ROWS);
        return new Observed(rows.size(), fingerprintOf(rows), List.copyOf(sample));
    }

    private long applyChange(Connection c, ValidatedChange change) throws SQLException {
        Statement st = DmlBuilder.apply(change);
        try (PreparedStatement ps = c.prepareStatement(st.sql())) {
            ps.setQueryTimeout(30);
            bind(ps, st);
            return ps.executeUpdate();
        }
    }

    private static int scalarInt(Connection c, Statement st) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(st.sql())) {
            ps.setQueryTimeout(30);
            bind(ps, st);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private static void bind(PreparedStatement ps, Statement st) throws SQLException {
        for (int i = 0; i < st.params().size(); i++) {
            Object v = st.params().get(i);
            int type = st.types().get(i);
            if (v == null) {
                ps.setNull(i + 1, type);
            } else {
                ps.setObject(i + 1, v, type);
            }
        }
    }

    // ---- stored request ----

    private static String requestJson(ChangeRequest req) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("operation", req.operation().name());
        m.put("schema", req.schema());
        m.put("table", req.table());
        m.put("values", req.values());
        m.put("conditions", req.conditions());
        return json(m);
    }

    @SuppressWarnings("unchecked")
    private static ChangeRequest parseRequest(String json, DbProfile profile) {
        try {
            Map<String, Object> m = JSON.readValue(json, Map.class);
            return new ChangeRequest(profile.profileId(), PermissionPolicy.Operation.valueOf((String) m.get("operation")),
                    (String) m.get("schema"), (String) m.get("table"), (Map<String, Object>) m.get("values"),
                    (Map<String, Object>) m.get("conditions"));
        } catch (Exception e) {
            throw new ToolGateway.Denied("PREVIEW_NOT_FOUND", "The stored preview is unreadable");
        }
    }

    // ---- digests ----

    /** Identifies exactly what is being asked: profile, operation, target, and every value and condition. */
    static String digest(DbProfile profile, ValidatedChange c) {
        StringBuilder sb = new StringBuilder();
        sb.append(profile.profileId()).append('|').append(c.operation()).append('|').append(c.schema()).append('.')
                .append(c.table());
        c.values().forEach((k, v) -> sb.append("|v:").append(k).append('=').append(canonical(v)));
        c.conditions().forEach((k, v) -> sb.append("|c:").append(k).append('=').append(canonical(v)));
        return sha256(sb.toString());
    }

    private static String fingerprintOf(List<Map<String, Object>> rows) {
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> r : rows) {
            r.forEach((k, v) -> sb.append(k).append('=').append(canonical(v)).append(';'));
            sb.append('\n');
        }
        return sha256(sb.toString());
    }

    private static String canonical(Object v) {
        // length-prefixed so "ab","c" and "a","bc" cannot collide
        String s = v == null ? "\u0000null" : v.toString();
        return s.length() + ":" + s;
    }

    private static String summary(DbProfile p, ValidatedChange c, Observed seen) {
        StringBuilder sb = new StringBuilder();
        sb.append(c.operation()).append(' ').append(c.target()).append(" on ").append(p.label()).append(": ")
                .append(seen.count).append(" row(s)");
        if (!c.values().isEmpty()) {
            sb.append("; set ").append(c.values().keySet());
        }
        if (!c.conditions().isEmpty()) {
            sb.append("; where ").append(c.conditions().keySet());
        }
        return sb.toString();
    }

    private Connection connection(ToolGateway.Call call) throws Exception {
        try {
            return gateway.context().connections.getConnection(call.profile);
        } catch (ConnectionManager.ProfileUnavailableException e) {
            throw new ToolGateway.Denied("PROFILE_" + e.status().name(), e.getMessage());
        }
    }

    private static String json(Object o) {
        try {
            return JSON.writeValueAsString(o);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialise result");
        }
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
