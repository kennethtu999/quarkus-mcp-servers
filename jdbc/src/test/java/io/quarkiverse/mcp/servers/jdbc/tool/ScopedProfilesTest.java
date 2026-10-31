package io.quarkiverse.mcp.servers.jdbc.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.app.GatewayRuntime;

class ScopedProfilesTest {
    @TempDir
    Path tmp;

    @Test
    void scopedProcessHidesOtherProfilesAndRejectsTheirLabelsAndIdsAfterLiveReload() throws Exception {
        try (var fixture = new GatewayFixture(tmp)) {
            var allowed = fixture.profile("PROJECT-A", "access: READ_ONLY\n", true);
            var other = fixture.profile("PROJECT-B", "access: READ_ONLY\n", true);
            GatewayRuntime.profiles(Set.of(allowed.label()));
            try {
                assertThat(fixture.queries.listProfiles()).contains("PROJECT-A").doesNotContain("PROJECT-B");
                for (String ref : new String[] { other.label(), other.profileId() }) {
                    assertThatThrownBy(() -> fixture.queries.listTables(ref, "APP", 1, 1))
                            .isInstanceOf(ToolCallException.class).hasMessageContaining("No such profile");
                }
                fixture.otherProcessReplaces(p -> p.withEnabled(true));
                assertThat(fixture.queries.listProfiles()).contains("PROJECT-A").doesNotContain("PROJECT-B");
                assertThat(fixture.queries.listTables(allowed.label(), "APP", 1, 1)).contains("tables");
            } finally {
                GatewayRuntime.profiles(Set.of());
            }
        }
    }
}
