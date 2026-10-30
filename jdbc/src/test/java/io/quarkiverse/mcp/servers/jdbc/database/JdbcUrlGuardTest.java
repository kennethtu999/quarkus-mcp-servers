package io.quarkiverse.mcp.servers.jdbc.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JdbcUrlGuardTest {

    private final JdbcUrlGuard strict = JdbcUrlGuard.strict();
    private final JdbcUrlGuard lax = new JdbcUrlGuard(Set.of(), false);

    @Test
    void acceptsTlsUrlsForEachDatabase() {
        assertThatCode(() -> strict.validate(DbType.POSTGRESQL,
                "jdbc:postgresql://pg-dev.example.internal:5432/testdb?sslmode=verify-full&currentSchema=public"))
                .doesNotThrowAnyException();
        assertThatCode(() -> strict.validate(DbType.DB2_LUW,
                "jdbc:db2://db2-dev.example.internal:50000/TESTDB:sslConnection=true;currentSchema=APP;"))
                .doesNotThrowAnyException();
        assertThatCode(() -> strict.validate(DbType.ORACLE,
                "jdbc:oracle:thin:@tcps://ora-sit.example.internal:1521/TESTPDB")).doesNotThrowAnyException();
    }

    @Test
    void acceptsCleartextUrlsOnlyWhenTlsIsNotRequired() {
        assertThatCode(() -> lax.validate(DbType.POSTGRESQL, "jdbc:postgresql://pg-dev:5432/testdb"))
                .doesNotThrowAnyException();
        assertThatCode(() -> lax.validate(DbType.DB2_LUW, "jdbc:db2://db2-dev:50000/TESTDB")).doesNotThrowAnyException();
        assertThatCode(() -> lax.validate(DbType.ORACLE, "jdbc:oracle:thin:@//ora-sit:1521/TESTPDB"))
                .doesNotThrowAnyException();
    }

    @Test
    void strictRejectsCleartextUrls() {
        assertThatThrownBy(() -> strict.validate(DbType.POSTGRESQL, "jdbc:postgresql://pg-dev:5432/testdb"))
                .hasMessageContaining("TLS");
        assertThatThrownBy(() -> strict.validate(DbType.POSTGRESQL, "jdbc:postgresql://pg-dev:5432/testdb?sslmode=require"))
                .hasMessageContaining("TLS");
        assertThatThrownBy(() -> strict.validate(DbType.DB2_LUW, "jdbc:db2://db2-dev:50000/TESTDB"))
                .hasMessageContaining("TLS");
        assertThatThrownBy(() -> strict.validate(DbType.ORACLE, "jdbc:oracle:thin:@//ora-sit:1521/TESTPDB"))
                .hasMessageContaining("TLS");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "jdbc:postgresql://h/db?sslmode=verify-full&socketFactory=com.evil.Factory",
            "jdbc:postgresql://h/db?sslmode=verify-full&sslfactory=com.evil.Factory",
            "jdbc:postgresql://h/db?sslmode=verify-full&loggerFile=/tmp/x",
            "jdbc:postgresql://h/db?sslmode=verify-full&authenticationPluginClassName=com.evil.P",
            "jdbc:postgresql://h/db?sslmode=verify-full&user=admin",
            "jdbc:postgresql://h/db?sslmode=verify-full&password=secret",
            "jdbc:postgresql://h/db?sslmode=verify-full&options=-c%20search_path=x"
    })
    void rejectsDangerousPostgresProperties(String url) {
        assertThatThrownBy(() -> strict.validate(DbType.POSTGRESQL, url)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not allowed");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "jdbc:db2://h:50000/DB:sslConnection=true;traceFile=/tmp/t;",
            "jdbc:db2://h:50000/DB:sslConnection=true;traceDirectory=/tmp;",
            "jdbc:db2://h:50000/DB:sslConnection=true;pluginName=Evil;",
            "jdbc:db2://h:50000/DB:sslConnection=true;user=x;password=y;"
    })
    void rejectsDangerousDb2Properties(String url) {
        assertThatThrownBy(() -> strict.validate(DbType.DB2_LUW, url)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not allowed");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=h)(PORT=1)))",
            "jdbc:oracle:thin:@tnsalias",
            "jdbc:oracle:thin:@tcps://h:1521/svc?TNS_ADMIN=/tmp",
            "jdbc:oracle:thin:@tcps://h:1521/svc;TNS_ADMIN=/tmp",
            "jdbc:oracle:thin:user/pass@tcps://h:1521/svc"
    })
    void rejectsOracleDescriptorsAndAliases(String url) {
        assertThatThrownBy(() -> strict.validate(DbType.ORACLE, url)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "   ",
            "jdbc:mysql://h:3306/db",
            "jdbc:h2:mem:test",
            "postgresql://h/db",
            "jdbc:postgresql:db",
            "jdbc:postgresql://h:5432",
            "jdbc:postgresql://h:99999/db?sslmode=verify-full",
            "jdbc:postgresql://h:abc/db?sslmode=verify-full",
            "jdbc:postgresql://h/db name?sslmode=verify-full",
            "jdbc:postgresql://h/db\n?sslmode=verify-full",
            "jdbc:postgresql://h/db?sslmode=verify-full&&",
            "jdbc:postgresql://h/../etc?sslmode=verify-full",
            "jdbc:postgresql://user:pass@h/db?sslmode=verify-full",
            "jdbc:postgresql://h_x!/db?sslmode=verify-full"
    })
    void rejectsMalformedOrForeignUrls(String url) {
        assertThatThrownBy(() -> strict.validate(DbType.POSTGRESQL, url)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsCredentialsEmbeddedInTheUrl() {
        assertThatThrownBy(() -> strict.validate(DbType.POSTGRESQL,
                "jdbc:postgresql://user:pass@h/db?sslmode=verify-full")).hasMessageContaining("embed credentials");
        assertThatThrownBy(() -> strict.validate(DbType.DB2_LUW,
                "jdbc:db2://user:pass@h:50000/DB:sslConnection=true;")).hasMessageContaining("embed credentials");
        assertThatThrownBy(() -> strict.validate(DbType.ORACLE, "jdbc:oracle:thin:@tcps://user:pass@h:1521/svc"))
                .hasMessageContaining("embed credentials");
    }

    @Test
    void urlDoesNotMatchADifferentDbType() {
        assertThatThrownBy(() -> strict.validate(DbType.ORACLE, "jdbc:postgresql://h/db?sslmode=verify-full"))
                .hasMessageContaining("does not match DB type");
    }

    @Test
    void enforcesHostAllowList() {
        JdbcUrlGuard guard = new JdbcUrlGuard(Set.of("pg-dev.example.internal"), true);
        assertThatCode(() -> guard.validate(DbType.POSTGRESQL,
                "jdbc:postgresql://PG-DEV.example.internal:5432/db?sslmode=verify-full")).doesNotThrowAnyException();
        assertThatThrownBy(() -> guard.validate(DbType.POSTGRESQL,
                "jdbc:postgresql://evil.example.com:5432/db?sslmode=verify-full"))
                .hasMessageContaining("allowed host list");
        assertThatThrownBy(() -> guard.validate(DbType.POSTGRESQL,
                "jdbc:postgresql://pg-dev.example.internal,evil.example.com/db?sslmode=verify-full"))
                .hasMessageContaining("allowed host list");
    }

    @Test
    void errorMessagesNeverEchoTheUrl() {
        String secretUrl = "jdbc:postgresql://h/db?sslmode=verify-full&password=hunter2";
        assertThatThrownBy(() -> strict.validate(DbType.POSTGRESQL, secretUrl)).satisfies(e -> {
            assertThat(e.getMessage()).doesNotContain("hunter2");
            assertThat(e.getMessage()).doesNotContain(secretUrl);
        });
    }

    @Test
    void dbTypeParsingIsStrict() {
        assertThat(DbType.parse(" postgresql ")).isEqualTo(DbType.POSTGRESQL);
        assertThatThrownBy(() -> DbType.parse("mysql")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> DbType.parse(null)).isInstanceOf(IllegalArgumentException.class);
    }
}
