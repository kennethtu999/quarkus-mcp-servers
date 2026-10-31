package io.quarkiverse.mcp.servers.jdbc.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

import io.quarkiverse.mcp.servers.jdbc.app.ToolMode;
import io.quarkiverse.mcp.servers.jdbc.change.SqlUpdateTemplate;

class SqlUpdateTemplateTest {
    @Test
    void setupCombinesTablesAndMultipleTemplatesWithoutBroadeningSqlIntoTableGrants() {
        var settings = ProfileSetup.parse(List.of("ACCESS=UPDATE", "UPDATE=APP.OTHER",
                "SQL=order_status##UPDATE APP.ORDERS SET STATUS=? WHERE ID=?",
                "SQL=email##UPDATE APP.USERS SET EMAIL=? WHERE ID=? AND VERSION=?"));
        assertThat(settings.tables).hasSize(1);
        assertThat(settings.templates).hasSize(2);
        var request = settings.templates.get(1).bind("DEV", List.of("a@b", 1, 2));
        assertThat(request.values()).containsEntry("EMAIL", "a@b");
        assertThat(request.conditions()).containsEntry("ID", 1).containsEntry("VERSION", 2);
    }

    @Test
    void arbitrarySqlExpressionsAndMissingConditionsAreRejected() {
        for (String sql : List.of("UPDATE APP.T SET A=?", "DELETE FROM APP.T WHERE ID=?",
                "UPDATE APP.T SET A=1 WHERE ID=?", "UPDATE APP.T SET A=? WHERE ID=? OR X=?",
                "UPDATE APP.T SET A=? WHERE ID=?; DROP TABLE APP.T", "UPDATE APP.T SET A=(SELECT 1) WHERE ID=?",
                "UPDATE APP.T SET A=? WHERE ID=? --comment", "UPDATE APP.T SET A=? WHERE A=?")) {
            assertThatThrownBy(() -> new SqlUpdateTemplate("one", sql)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> ProfileSetup.parse(List.of("ACCESS=READ_ONLY",
                "SQL=one##UPDATE APP.T SET A=? WHERE ID=?"))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void readAndWriteSurfacesAreSeparatedAndUnknownModeCannotAllowWrites() {
        assertThat(ToolMode.allows("read", "db_query")).isTrue();
        assertThat(ToolMode.allows("read", "db_execute_template")).isFalse();
        assertThat(ToolMode.allows("write", "db_execute_template")).isTrue();
        assertThat(ToolMode.allows("write", "db_query")).isFalse();
        assertThat(ToolMode.allows("bad", "db_execute_change")).isFalse();
    }
}
