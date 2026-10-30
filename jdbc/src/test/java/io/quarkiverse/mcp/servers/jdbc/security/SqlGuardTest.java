package io.quarkiverse.mcp.servers.jdbc.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import io.quarkiverse.mcp.servers.jdbc.database.DbType;

class SqlGuardTest {

    private static List<String> corpus(String name) throws IOException {
        try (InputStream in = SqlGuardTest.class.getResourceAsStream("/sqlguard/" + name)) {
            assertThat(in).as("corpus " + name).isNotNull();
            List<String> out = new ArrayList<>();
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                if (!line.isBlank()) {
                    out.add(line);
                }
            }
            return out;
        }
    }

    private static String verdict(DbType type, String sql) {
        try {
            new SqlGuard(type).check(sql);
            return null;
        } catch (SqlGuard.Rejected r) {
            return r.getMessage();
        }
    }

    @ParameterizedTest
    @EnumSource(DbType.class)
    void everyAllowedStatementIsAccepted(DbType type) throws IOException {
        List<String> wrongly = new ArrayList<>();
        for (String sql : corpus("common-allow.sql")) {
            String v = verdict(type, sql);
            if (v != null) {
                wrongly.add(sql + "   <- rejected: " + v);
            }
        }
        assertThat(wrongly).as("statements that should have been accepted on " + type).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(DbType.class)
    void everyCommonDenyStatementIsRejected(DbType type) throws IOException {
        List<String> wrongly = new ArrayList<>();
        for (String sql : corpus("common-deny.sql")) {
            if (verdict(type, sql) == null) {
                wrongly.add(sql);
            }
        }
        assertThat(wrongly).as("statements that were wrongly ACCEPTED on " + type).isEmpty();
    }

    @Test
    void everyPostgresDenyStatementIsRejected() throws IOException {
        assertNoneAccepted(DbType.POSTGRESQL, "pg-deny.sql");
    }

    @Test
    void everyOracleDenyStatementIsRejected() throws IOException {
        assertNoneAccepted(DbType.ORACLE, "oracle-deny.sql");
    }

    @Test
    void everyDb2DenyStatementIsRejected() throws IOException {
        assertNoneAccepted(DbType.DB2_LUW, "db2-deny.sql");
    }

    private static void assertNoneAccepted(DbType type, String file) throws IOException {
        List<String> wrongly = new ArrayList<>();
        for (String sql : corpus(file)) {
            if (verdict(type, sql) == null) {
                wrongly.add(sql);
            }
        }
        assertThat(wrongly).as("statements that were wrongly ACCEPTED on " + type).isEmpty();
    }

    @Test
    void rejectionMessagesNeverEchoTheSql() {
        String secret = "SELECT * FROM APP.ORDERS WHERE TOKEN = 'SUPERSECRETVALUE' FOR UPDATE";
        for (DbType t : DbType.values()) {
            assertThat(verdict(t, secret)).isNotNull().doesNotContain("SUPERSECRETVALUE");
            assertThat(verdict(t, "SELECT SUPERSECRETVALUE(1) FROM APP.T")).doesNotContain("SELECT");
        }
    }

    @Test
    void guardsAgainstDegenerateInput() {
        for (DbType t : DbType.values()) {
            assertThat(verdict(t, null)).isNotNull();
            assertThat(verdict(t, "")).isNotNull();
            assertThat(verdict(t, "   \n\t ")).isNotNull();
            assertThat(verdict(t, "SELECT 1\u0000")).isNotNull();
            assertThat(verdict(t, "SELECT * FROM T WHERE X = " + "(".repeat(500) + "1" + ")".repeat(500))).isNotNull();
            assertThat(verdict(t, "SELECT * FROM APP.T WHERE " + "A = 1 AND ".repeat(3000) + "A = 1")).isNotNull();
            assertThat(verdict(t, "SELECT " + "x".repeat(9000) + " FROM APP.T")).isNotNull();
            assertThat(verdict(t, "SELECT * FROM " + "(SELECT * FROM ".repeat(60) + "APP.T" + ")".repeat(60))).isNotNull();
        }
    }

    @Test
    void caseAndWhitespaceTricksDoNotChangeTheVerdict() {
        for (DbType t : DbType.values()) {
            assertThat(verdict(t, "sElEcT * fRoM APP.ORDERS fOr UpDaTe")).isNotNull();
            assertThat(verdict(t, "SELECT\t*\nFROM\r\nAPP.ORDERS\tFOR\nUPDATE")).isNotNull();
            assertThat(verdict(t, "  select * from APP.ORDERS  ")).isNull();
            assertThat(verdict(t, "DeLeTe FROM APP.ORDERS")).isNotNull();
        }
    }

    @Test
    void systemSchemasAreBlockedRegardlessOfQuotingOrCase() {
        assertThat(verdict(DbType.DB2_LUW, "SELECT * FROM syscat.tables")).isNotNull();
        assertThat(verdict(DbType.DB2_LUW, "SELECT * FROM \"SYSCAT\".\"TABLES\"")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT * FROM \"pg_catalog\".\"pg_user\"")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT * FROM PG_CATALOG.pg_user")).isNotNull();
        assertThat(verdict(DbType.ORACLE, "SELECT * FROM sys.user$")).isNotNull();
        assertThat(verdict(DbType.ORACLE, "SELECT * FROM \"SYS\".\"USER$\"")).isNotNull();
        assertThat(verdict(DbType.ORACLE, "SELECT t.* FROM sys.obj$ t")).isNotNull();
        // a column that merely contains the word is fine
        assertThat(verdict(DbType.POSTGRESQL, "SELECT pg_note FROM public.memos")).isNull();
    }

    @Test
    void systemSchemaInsideNestedConstructsIsStillBlocked() {
        assertThat(verdict(DbType.POSTGRESQL, "SELECT * FROM public.t WHERE id IN (SELECT oid FROM pg_catalog.pg_class)"))
                .isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT (SELECT 1 FROM pg_catalog.pg_user LIMIT 1) FROM public.t")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "WITH x AS (SELECT * FROM pg_catalog.pg_user) SELECT * FROM x")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT * FROM public.t JOIN pg_catalog.pg_user u ON true")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT id FROM public.t UNION SELECT usename FROM pg_catalog.pg_user"))
                .isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT * FROM public.t WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_user)"))
                .isNotNull();
    }

    @Test
    void lockingInsideNestedConstructsIsStillBlocked() {
        assertThat(verdict(DbType.POSTGRESQL, "SELECT * FROM (SELECT * FROM public.t FOR UPDATE) x")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "WITH x AS (SELECT * FROM public.t FOR UPDATE) SELECT * FROM x")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT id FROM public.t UNION SELECT id FROM public.u FOR UPDATE")).isNotNull();
    }

    @Test
    void functionsInsideEveryClauseAreChecked() {
        for (String where : List.of("WHERE x = badfn(1)", "GROUP BY badfn(x)", "HAVING badfn(x) > 1", "ORDER BY badfn(x)",
                "WHERE x IN (badfn(1))", "WHERE EXISTS (SELECT badfn(1) FROM APP.U)")) {
            assertThat(verdict(DbType.POSTGRESQL, "SELECT x FROM APP.T " + where)).as(where).isNotNull();
        }
        assertThat(verdict(DbType.POSTGRESQL, "SELECT x FROM APP.T JOIN APP.U ON badfn(U.id) = T.id")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT CASE WHEN badfn(1) = 1 THEN 1 END FROM APP.T")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT CAST(badfn(1) AS INT) FROM APP.T")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT COALESCE(x, badfn(1)) FROM APP.T")).isNotNull();
        assertThat(verdict(DbType.POSTGRESQL, "SELECT SUM(badfn(x)) FROM APP.T")).isNotNull();
    }
}
