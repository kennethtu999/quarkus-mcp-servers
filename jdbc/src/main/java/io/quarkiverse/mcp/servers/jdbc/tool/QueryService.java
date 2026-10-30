package io.quarkiverse.mcp.servers.jdbc.tool;

import java.sql.Connection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.mcp.servers.jdbc.audit.AuditService;
import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager;
import io.quarkiverse.mcp.servers.jdbc.database.MetadataService;
import io.quarkiverse.mcp.servers.jdbc.database.QueryExecutor;
import io.quarkiverse.mcp.servers.jdbc.policy.Decision;
import io.quarkiverse.mcp.servers.jdbc.security.SqlGuard;

/**
 * The read-side tools as plain methods returning JSON strings, so they can be exercised without starting Quarkus. The
 * {@code @Tool} beans only forward to this class.
 */
public final class QueryService {

    private static final ObjectMapper JSON = new ObjectMapper();
    static final int MAX_PARAMS = 50;

    private final ToolGateway gateway;
    /** When set, replaces the dialect's read-only statement. Only tests use this (to stand H2 in for Oracle). */
    private final java.util.function.Function<io.quarkiverse.mcp.servers.jdbc.database.DbType, String> readOnlyStatement;

    public QueryService(ToolGateway gateway) {
        this(gateway, t -> io.quarkiverse.mcp.servers.jdbc.database.DbDialect.of(t).readOnlyTransactionStatement());
    }

    QueryService(ToolGateway gateway,
            java.util.function.Function<io.quarkiverse.mcp.servers.jdbc.database.DbType, String> readOnlyStatement) {
        this.gateway = gateway;
        this.readOnlyStatement = readOnlyStatement;
    }

    public String listProfiles() {
        // No profile reference here, so this does not go through run(); it is still audited.
        var ctx = gateway.context();
        String unavailable = ctx.sync.refresh();
        if (unavailable != null) {
            gateway.audit().record(io.quarkiverse.mcp.servers.jdbc.audit.AuditEvent.of("db_list_profiles").actor("local-user")
                    .operation("LIST").decision("DENY").code("PROFILES_UNAVAILABLE").result("DENIED"));
            throw new io.quarkiverse.mcp.server.ToolCallException(
                    "Profiles cannot be read right now; ask the administrator to check the gateway", null);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (var p : ctx.registry.all()) {
            var snap = ctx.policies.current(p);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("profileId", p.profileId());
            m.put("label", p.label());
            m.put("dbType", p.dbType().name());
            m.put("enabled", p.enabled());
            m.put("connection", p.enabled() ? ctx.connections.status(p).name() : "DISABLED");
            m.put("policy", snap.state().name());
            m.put("access", snap.active() ? snap.policy().access().name() : null);
            m.put("maxRows", snap.active() ? snap.policy().readMaxRows() : null);
            out.add(m);
        }
        gateway.audit().record(io.quarkiverse.mcp.servers.jdbc.audit.AuditEvent.of("db_list_profiles").actor("local-user")
                .operation("LIST").decision("ALLOW").result("OK").rows(out.size()));
        return json(out);
    }

    public String listTables(String profileRef, String schema, Integer page, Integer size) {
        return gateway.run("db_list_tables", "METADATA", profileRef, call -> {
            requireRead(call);
            try (Connection c = connection(call)) {
                var result = MetadataService.listTables(c, call.profile.dbType(), schema, page, size);
                call.audit().rows(result.tables().size());
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("totalCount", result.total());
                out.put("page", result.page());
                out.put("pageSize", result.pageSize());
                out.put("tables", result.tables());
                return json(out);
            }
        });
    }

    public String describeTable(String profileRef, String schema, String table) {
        return gateway.run("db_describe_table", "METADATA", profileRef, call -> {
            requireRead(call);
            call.audit().target(schema + "." + table);
            try (Connection c = connection(call)) {
                var columns = MetadataService.describeTable(c, call.profile.dbType(), schema, table);
                if (columns.isEmpty()) {
                    throw new ToolGateway.Denied("NOT_FOUND", "No such table, or it is not accessible");
                }
                call.audit().rows(columns.size());
                return json(columns);
            }
        });
    }

    public String query(String profileRef, String sql, List<Object> params, Integer maxRows) {
        return gateway.run("db_query", "SELECT", profileRef, call -> {
            requireRead(call);
            call.audit().sqlHash(AuditService.hashSql(sql));
            List<Object> bound = params == null ? List.of() : params;
            if (bound.size() > MAX_PARAMS) {
                throw new ToolGateway.Denied("TOO_MANY_PARAMS", "At most " + MAX_PARAMS + " parameters are allowed");
            }
            try {
                new SqlGuard(call.profile.dbType()).check(sql);
            } catch (SqlGuard.Rejected r) {
                throw new ToolGateway.Denied("SQL_REJECTED", r.getMessage());
            }
            var perms = gateway.context().permissions;
            int limit = perms.readLimit(call.profile, maxRows);
            boolean clamped = maxRows != null && maxRows > limit;
            int timeout = perms.readTimeoutSeconds(call.profile);

            QueryExecutor.Result r;
            try (Connection c = connection(call)) {
                r = QueryExecutor.run(c, readOnlyStatement.apply(call.profile.dbType()), sql, bound, limit, timeout);
            }
            call.audit().rows(r.rowCount());
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("requestId", call.requestId);
            out.put("columns", r.columns());
            out.put("rows", r.rows());
            out.put("rowCount", r.rowCount());
            out.put("truncated", r.truncated());
            if (r.truncated()) {
                out.put("truncationReason", r.truncationReason());
            }
            if (clamped) {
                out.put("maxRowsClamped", true);
                out.put("maxRowsApplied", limit);
            }
            return json(out);
        });
    }

    private void requireRead(ToolGateway.Call call) {
        Decision d = gateway.context().permissions.checkRead(call.profile);
        if (!d.allowed()) {
            throw new ToolGateway.Denied(d);
        }
    }

    private Connection connection(ToolGateway.Call call) throws Exception {
        try {
            return gateway.context().connections.getConnection(call.profile);
        } catch (ConnectionManager.ProfileUnavailableException e) {
            throw new ToolGateway.Denied("PROFILE_" + e.status().name(), e.getMessage());
        }
    }

    static String json(Object o) {
        try {
            return JSON.writeValueAsString(o);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialise result");
        }
    }
}
