package io.quarkiverse.mcp.servers.jdbc.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PastedProfileTest {
    @Test
    void splitsMetadataButPreservesPasswordSpacesHashesAndShellCharacters() {
        char[] secret;
        try (PastedProfile parsed = PastedProfile.parse(
                " DEV ## DB2_LUW ## jdbc:db2://host:60000/DB ## user ## APP ##  p##$'\\!  ".toCharArray())) {
            assertThat(parsed.fields).containsExactly("DEV", "DB2_LUW", "jdbc:db2://host:60000/DB", "user", "APP");
            assertThat(parsed.password).isEqualTo("  p##$'\\!  ".toCharArray());
            secret = parsed.password;
        }
        assertThat(secret).containsOnly('\0');
    }

    @Test
    void emptySchemaAndOmittedOrEmptyPasswordAreSupported() {
        for (String line : new String[] { "DEV##POSTGRESQL##jdbc:postgresql://host/db##user##",
                "DEV##POSTGRESQL##jdbc:postgresql://host/db##user####" }) {
            try (PastedProfile parsed = PastedProfile.parse(line.toCharArray())) {
                assertThat(parsed.fields[4]).isEmpty();
                assertThat(parsed.password).isNull();
            }
        }
    }

    @Test
    void missingMetadataFailsWithoutQuotingTheInput() {
        for (String input : new String[] { "SECRET-SENTINEL", "DEV##DB2_LUW##host##user", "##DB2_LUW##host##user##APP" }) {
            assertThatThrownBy(() -> PastedProfile.parse(input.toCharArray()))
                    .isInstanceOf(IllegalArgumentException.class).hasMessageNotContaining("SECRET-SENTINEL");
        }
    }
}
