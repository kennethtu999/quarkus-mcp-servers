package io.quarkiverse.mcp.servers.jdbc.change;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.mcp.servers.jdbc.database.MetadataService;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy;
import io.quarkiverse.mcp.servers.jdbc.tool.ToolGateway;

/** Exact pre-approved UPDATE templates: no caller SQL and no per-execution approval token. */
public final class TemplateService {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ToolGateway gateway;

    public TemplateService(ToolGateway gateway) {
        this.gateway = gateway;
    }

    public String rules(String profileRef) {
        return gateway.run("db_list_change_rules", "RULES", profileRef, call -> {
            var ctx = gateway.context();
            var allowed = ctx.permissions.checkRead(call.profile);
            if (!allowed.allowed()) {
                throw new ToolGateway.Denied(allowed);
            }
            PermissionPolicy policy = ctx.policies.current(call.profile).policy();
            var result = new LinkedHashMap<String, Object>();
            result.put("profileId", call.profile.profileId());
            result.put("access", policy.access());
            result.put("tableRulesRequireApproval", true);
            result.put("tables", policy.write() == null ? List.of() : policy.write().whitelist());
            List<Map<String, Object>> templates = new ArrayList<>();
            if (policy.write() != null && !policy.write().templates().isEmpty()) {
                try (Connection connection = ctx.connections.getConnection(call.profile)) {
                    for (var template : policy.write().templates()) {
                        var shape = template.shape();
                        var request = new ChangeRequest(profileRef, PermissionPolicy.Operation.UPDATE, shape.schema(),
                                shape.table(),
                                Map.of(), Map.of());
                        String[] target = ChangeValidator.resolveTarget(connection, call.profile.dbType(), request);
                        var columns = MetadataService.columns(connection, call.profile.dbType(), target[0], target[1]);
                        List<Map<String, Object>> parameters = new ArrayList<>();
                        int position = 0;
                        for (String name : shape.parameterColumns()) {
                            var column = columns.get(name.toUpperCase(java.util.Locale.ROOT));
                            if (column == null) {
                                throw new IllegalArgumentException("Template metadata changed; reconfigure the template");
                            }
                            var parameter = new LinkedHashMap<String, Object>();
                            parameter.put("position", ++position);
                            parameter.put("column", column.name());
                            parameter.put("jdbcType", column.sqlType());
                            parameter.put("type", column.typeName());
                            parameter.put("size", column.size());
                            parameter.put("scale", column.scale());
                            parameter.put("nullable", shape.values().contains(name) && column.nullable());
                            parameters.add(parameter);
                        }
                        templates.add(Map.of("templateId", template.id(), "sql", template.sql(), "params", parameters,
                                "requiresApproval", false, "maxAffectedRows", policy.write().maxAffectedRows()));
                    }
                    connection.rollback();
                }
            }
            result.put("templates", templates);
            return JSON.writeValueAsString(result);
        });
    }

    public String execute(String profileRef, String templateId, List<Object> parameters) {
        return gateway.run("db_execute_template", "UPDATE_TEMPLATE", profileRef, call -> {
            var ctx = gateway.context();
            var allowed = ctx.permissions.checkRead(call.profile);
            if (!allowed.allowed()) {
                throw new ToolGateway.Denied(allowed);
            }
            var snap = ctx.policies.current(call.profile);
            if (!snap.active() || snap.policy().write() == null) {
                throw new ToolGateway.Denied("TEMPLATE_NOT_ALLOWED", "No SQL templates are enabled for this profile");
            }
            var template = snap.policy().write().templates().stream()
                    .filter(t -> t.id().equals(templateId)).findFirst()
                    .orElseThrow(() -> new ToolGateway.Denied("TEMPLATE_NOT_ALLOWED", "Unknown SQL template"));
            var request = template.bind(profileRef, parameters);
            call.audit().sqlHash(io.quarkiverse.mcp.servers.jdbc.audit.AuditService.hashSql(template.sql()));
            int limit = snap.policy().write().maxAffectedRows();
            try (Connection connection = ctx.connections.getConnection(call.profile)) {
                connection.setAutoCommit(false);
                connection.setReadOnly(false);
                try {
                    String[] target = ChangeValidator.resolveTarget(connection, call.profile.dbType(), request);
                    var validated = ChangeValidator.validate(connection, call.profile.dbType(), request, target);
                    call.audit().target(target[0] + "." + target[1]);
                    try (var count = prepare(connection, DmlBuilder.count(validated)); var rows = count.executeQuery()) {
                        if (!rows.next() || rows.getLong(1) > limit) {
                            throw new ToolGateway.Denied("ROW_LIMIT", "Template would exceed the affected-row limit");
                        }
                    }
                    int affected;
                    try (var statement = prepare(connection, DmlBuilder.apply(validated))) {
                        affected = statement.executeUpdate();
                    }
                    if (affected < 0 || affected > limit) {
                        throw new ToolGateway.Denied("ROW_LIMIT", "Affected-row limit exceeded; rolled back");
                    }
                    if (ctx.sync.refresh() != null) {
                        throw new ToolGateway.Denied("PROFILES_UNAVAILABLE", "Profile state changed; rolled back");
                    }
                    var current = ctx.registry.byId(call.profile.profileId()).orElse(null);
                    if (current == null || !current.enabled() || !current.jdbcUrl().equals(call.profile.jdbcUrl())
                            || !current.username().equals(call.profile.username()) || current.dbType() != call.profile.dbType()
                            || !ctx.policies.current(current).active()
                            || !snap.policy().hash().equals(ctx.policies.current(current).policy().hash())) {
                        throw new ToolGateway.Denied("POLICY_CHANGED", "Permissions changed; rolled back");
                    }
                    connection.commit();
                    call.audit().affectedRows(affected).result("COMMITTED");
                    return JSON.writeValueAsString(Map.of("templateId", templateId, "affectedRows", affected,
                            "committed", true, "requiresApproval", false));
                } catch (Exception failed) {
                    connection.rollback();
                    call.audit().result("ROLLED_BACK");
                    throw failed;
                }
            }
        });
    }

    private static PreparedStatement prepare(Connection connection, DmlBuilder.Statement sql) throws Exception {
        var statement = connection.prepareStatement(sql.sql());
        try {
            statement.setQueryTimeout(30);
            for (int i = 0; i < sql.params().size(); i++) {
                statement.setObject(i + 1, sql.params().get(i), sql.types().get(i));
            }
            return statement;
        } catch (Exception failed) {
            statement.close();
            throw failed;
        }
    }
}
