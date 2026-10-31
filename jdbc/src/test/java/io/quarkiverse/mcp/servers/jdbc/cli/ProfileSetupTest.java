package io.quarkiverse.mcp.servers.jdbc.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

class ProfileSetupTest {
    @Test
    void defaultsAreTlsReadOnlyAndNoOverrideWith500RowLimit() {
        var settings = ProfileSetup.parse(List.of());
        assertThat(settings.tls).isTrue();
        assertThat(settings.update).isFalse();
        assertThat(settings.override).isFalse();
        assertThat(settings.maxRows).isEqualTo(500);
    }

    @Test
    void multipleTablesAndLinesKeepExactNamesAndRequireExplicitUpdateMode() {
        var settings = ProfileSetup.parse(List.of("TLS=OFF", "ACCESS=UPDATE", "MAX_ROWS=10", "OVERRIDE=YES",
                "UPDATE=APP.ONE,APP.TWO", "UPDATE=APP.THREE"));
        assertThat(settings.tables).hasSize(3);
        assertThat(settings.tables.get(2)).containsExactly("APP", "THREE");
        assertThat(settings.maxRows).isEqualTo(10);
        assertThat(settings.tls).isFalse();
        assertThat(settings.override).isTrue();
    }

    @Test
    void badLimitsAmbiguousSettingsAndSqlDoNotCreateBroaderPermissions() {
        for (List<String> invalid : List.of(List.of("MAX_ROWS=501"), List.of("MAX_ROWS=0"), List.of("MAX_ROWS=-1"),
                List.of("ACCESS=UPDATE"), List.of("UPDATE=APP.ONE"), List.of("TLS=MAYBE"),
                List.of("ACCESS=READ_ONLY", "ACCESS=UPDATE"), List.of("ACCESS=UPDATE", "UPDATE=APP.*"),
                List.of("ACCESS=UPDATE", "UPDATE=APP.ONE,app.one"),
                List.of("ACCESS=UPDATE", "UPDATE=UPDATE APP.ONE SET VALUE=1 WHERE ID=1"))) {
            assertThatThrownBy(() -> ProfileSetup.parse(invalid)).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
