package io.quarkiverse.mcp.servers.jdbc.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.change.TemplateService;

class TemplateServiceTest {
    @TempDir
    Path tmp;

    private static final String POLICY = """
            access: READ_WRITE_WHITELIST
            write:
              maxAffectedRows: 1
              whitelist: []
              templates:
                - id: order_status
                  sql: UPDATE APP.ORDERS SET STATUS=? WHERE ID=?
                  autoExecute: true
                - id: tag_label
                  sql: UPDATE APP.TAGS SET LABEL=? WHERE GRP=?
                  autoExecute: true
            """;

    @Test
    void fixedTemplateCommitsWithoutAnApprovalAndValuesCannotBecomeSql() throws Exception {
        try (var fixture = new GatewayFixture(tmp)) {
            var profile = fixture.profile("TEMPLATE", POLICY, true);
            var service = new TemplateService(fixture.gateway);
            String value = "X'; DELETE FROM APP.ORDERS; --";
            String result = service.execute(profile.label(), "order_status", List.of(value, 1));
            assertThat(result).contains("\"committed\":true").contains("\"affectedRows\":1");
            try (var c = fixture.direct();
                    var rs = c.createStatement().executeQuery("SELECT STATUS FROM APP.ORDERS WHERE ID=1")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getString(1)).isEqualTo(value);
            }
            // A template does not grant the generic table-wide write permission.
            assertThat(fixture.ctx.permissions.checkWrite(profile,
                    io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation.UPDATE, "APP", "ORDERS").allowed())
                    .isFalse();
            assertThat(fixture.auditText()).doesNotContain(value).contains("db_execute_template");
        }
    }

    @Test
    void rowLimitBadTypesUnknownTemplatesAndStalePolicyNeverModifyData() throws Exception {
        try (var fixture = new GatewayFixture(tmp)) {
            var profile = fixture.profile("TEMPLATE", POLICY, true);
            var service = new TemplateService(fixture.gateway);
            assertThatThrownBy(() -> service.execute(profile.label(), "tag_label", List.of("CHANGED", "g1")))
                    .isInstanceOf(ToolCallException.class);
            assertThatThrownBy(() -> service.execute(profile.label(), "order_status", List.of("CLOSED", "1 OR 1=1")))
                    .isInstanceOf(ToolCallException.class);
            assertThatThrownBy(() -> service.execute(profile.label(), "order_status", List.of("x".repeat(101), 1)))
                    .isInstanceOf(ToolCallException.class);
            assertThatThrownBy(() -> service.execute(profile.label(), "not_configured", List.of("CLOSED", 1)))
                    .isInstanceOf(ToolCallException.class);
            fixture.writePolicy(profile, POLICY + "# edited without reload\n");
            assertThatThrownBy(() -> service.execute(profile.label(), "order_status", List.of("CLOSED", 1)))
                    .isInstanceOf(ToolCallException.class);
            try (var c = fixture.direct();
                    var rs = c.createStatement().executeQuery("SELECT COUNT(*) FROM APP.ORDERS WHERE STATUS='OPEN'")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getInt(1)).isEqualTo(1000);
            }
            try (var c = fixture.direct();
                    var rs = c.createStatement().executeQuery("SELECT COUNT(*) FROM APP.TAGS WHERE LABEL='CHANGED'")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getInt(1)).isZero();
            }
        }
    }

    @Test
    void discoveryIncludesLiveColumnTypesAndOrderAndReadOnlyCannotExecute() throws Exception {
        try (var fixture = new GatewayFixture(tmp)) {
            var profile = fixture.profile("TEMPLATE", POLICY, true);
            var service = new TemplateService(fixture.gateway);
            var result = new ObjectMapper().readTree(service.rules(profile.label()));
            var params = result.get("templates").get(0).get("params");
            assertThat(params.get(0).get("column").asText()).isEqualTo("STATUS");
            assertThat(params.get(0).get("size").asInt()).isEqualTo(100);
            assertThat(params.get(1).get("column").asText()).isEqualTo("ID");
            assertThat(params.get(1).get("nullable").asBoolean()).isFalse();
            assertThat(result.get("templates").get(0).get("requiresApproval").asBoolean()).isFalse();
            var readonly = fixture.profile("READONLY", "access: READ_ONLY\n", true);
            assertThatThrownBy(() -> service.execute(readonly.label(), "order_status", List.of("CLOSED", 1)))
                    .isInstanceOf(ToolCallException.class);
            fixture.otherProcess().setEnabled(profile.label(), false);
            assertThatThrownBy(() -> service.rules(profile.label())).isInstanceOf(ToolCallException.class);
        }
    }
}
