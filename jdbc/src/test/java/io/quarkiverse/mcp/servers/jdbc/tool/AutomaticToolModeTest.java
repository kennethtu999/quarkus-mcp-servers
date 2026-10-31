package io.quarkiverse.mcp.servers.jdbc.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.app.GatewayRuntime;
import io.quarkiverse.mcp.servers.jdbc.app.ToolMode;

class AutomaticToolModeTest {
    @TempDir
    Path tmp;

    @Test
    void sameAutomaticEndpointFollowsActivePoliciesAndProfileScopeWithoutChangingRegistration() throws Exception {
        try (var fixture = new GatewayFixture(tmp)) {
            var readonly = fixture.profile("READ-DB", "access: READ_ONLY\n", true);
            var writable = fixture.profile("WRITE-DB", """
                    access: READ_WRITE_WHITELIST
                    write:
                      whitelist:
                        - {schema: APP, table: ORDERS, operations: [UPDATE]}
                    """, true);
            GatewayRuntime.set(fixture.ctx);
            GatewayRuntime.mode("auto");
            try {
                assertThat(ToolMode.writeEnabled()).isTrue();
                assertThat(ToolMode.allows("auto", "db_query")).isTrue();
                assertThat(ToolMode.allows("auto", "db_execute_template")).isTrue();
                GatewayRuntime.profiles(Set.of(readonly.label()));
                assertThat(ToolMode.writeEnabled()).isFalse();
                assertThat(ToolMode.allows("auto", "db_execute_template")).isFalse();
                assertThatThrownBy(ToolMode::requireWrite).isInstanceOf(ToolCallException.class);
                GatewayRuntime.profiles(Set.of(writable.label()));
                assertThat(ToolMode.writeEnabled()).isTrue();
                fixture.writePolicy(writable, "access: READ_ONLY\n");
                assertThat(ToolMode.writeEnabled()).isFalse(); // stale policies never enable writes
                fixture.ctx.policies.activate(writable);
                assertThat(ToolMode.writeEnabled()).isFalse();
                assertThat(fixture.queries.listProfiles()).contains("\"gatewayReadOnly\":true");
            } finally {
                GatewayRuntime.profiles(Set.of());
                GatewayRuntime.mode("auto");
                GatewayRuntime.set(null);
            }
        }
    }
}
