package io.quarkiverse.mcp.servers.jdbc.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.audit.AuditService;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

class QueryServiceTest {

    static final ObjectMapper JSON = new ObjectMapper();

    @TempDir
    Path tmp;

    GatewayFixture fx;
    DbProfile ro;

    @BeforeEach
    void setUp() throws Exception {
        fx = new GatewayFixture(tmp);
        ro = fx.profile("ORA-RO", "access: READ_ONLY\nread:\n  maxRows: 500\n  timeoutSeconds: 30\n", true);
    }

    @AfterEach
    void tearDown() throws Exception {
        fx.close();
    }

    private JsonNode query(String ref, String sql, Integer maxRows) throws Exception {
        return JSON.readTree(fx.queries.query(ref, sql, null, maxRows));
    }

    // ---- A09 / A10: the 500 cap through the whole path ----

    @Test
    void aThousandRowTableReturnsExactlyFiveHundredToTheAi() throws Exception {
        JsonNode r = query(ro.label(), "SELECT ID FROM APP.ORDERS ORDER BY ID", null);
        assertThat(r.get("rows")).hasSize(500);
        assertThat(r.get("rowCount").asInt()).isEqualTo(500);
        assertThat(r.get("truncated").asBoolean()).isTrue();
        assertThat(r.get("rows").get(499).get("ID").asInt()).isEqualTo(500);
    }

    @Test
    void askingForAThousandIsReducedToFiveHundredAndSaysSo() throws Exception {
        JsonNode r = query(ro.profileId(), "SELECT ID FROM APP.ORDERS ORDER BY ID", 1000);
        assertThat(r.get("rows")).hasSize(500);
        assertThat(r.get("maxRowsClamped").asBoolean()).isTrue();
        assertThat(r.get("maxRowsApplied").asInt()).isEqualTo(500);
    }

    @Test
    void aSmallerRequestIsHonouredAndNotMarkedClamped() throws Exception {
        JsonNode r = query(ro.label(), "SELECT ID FROM APP.ORDERS ORDER BY ID", 25);
        assertThat(r.get("rows")).hasSize(25);
        assertThat(r.has("maxRowsClamped")).isFalse();
    }

    @Test
    void aPolicyLowerThanFiveHundredWins() throws Exception {
        DbProfile low = fx.profile("ORA-LOW", "access: READ_ONLY\nread:\n  maxRows: 40\n", true);
        JsonNode r = query(low.label(), "SELECT ID FROM APP.ORDERS ORDER BY ID", 400);
        assertThat(r.get("rows")).hasSize(40);
        assertThat(r.get("maxRowsClamped").asBoolean()).isTrue();
        assertThat(r.get("maxRowsApplied").asInt()).isEqualTo(40);
    }

    @Test
    void profilesCanBeAddressedByIdOrByCaseInsensitiveLabel() throws Exception {
        assertThat(query(ro.profileId(), "SELECT COUNT(*) AS N FROM APP.CUSTOMERS", null).get("rows").get(0).get("N").asInt())
                .isEqualTo(2);
        assertThat(query("ora-ro", "SELECT COUNT(*) AS N FROM APP.CUSTOMERS", null).get("rows").get(0).get("N").asInt())
                .isEqualTo(2);
    }

    @Test
    void parametersAreBoundByTheFullPath() throws Exception {
        JsonNode r = JSON
                .readTree(fx.queries.query(ro.label(), "SELECT NAME FROM APP.CUSTOMERS WHERE ID = ?", List.of(2), null));
        assertThat(r.get("rows").get(0).get("NAME").asText()).isEqualTo("bob");
        JsonNode inj = JSON.readTree(
                fx.queries.query(ro.label(), "SELECT NAME FROM APP.CUSTOMERS WHERE NAME = ?", List.of("x' OR '1'='1"), null));
        assertThat(inj.get("rows")).isEmpty();
    }

    // ---- A11 / A19: unsafe SQL never reaches the database ----

    @Test
    void ddlDmlProceduresAndMergeAreDeniedAndNothingChanges() throws Exception {
        for (String sql : List.of("DROP TABLE APP.ORDERS", "ALTER TABLE APP.ORDERS ADD X INT", "TRUNCATE TABLE APP.ORDERS",
                "DELETE FROM APP.ORDERS", "UPDATE APP.ORDERS SET STATUS = 'X'", "INSERT INTO APP.ORDERS (ID) VALUES (5000)",
                "MERGE INTO APP.ORDERS t USING APP.CUSTOMERS c ON t.ID = c.ID WHEN MATCHED THEN DELETE", "CALL SOMEPROC()",
                "SELECT * FROM APP.ORDERS; DROP TABLE APP.ORDERS", "SELECT * FROM APP.ORDERS FOR UPDATE",
                "WITH d AS (DELETE FROM APP.ORDERS RETURNING *) SELECT * FROM d")) {
            assertThatThrownBy(() -> fx.queries.query(ro.label(), sql, null, null)).as(sql)
                    .isInstanceOf(ToolCallException.class);
        }
        try (var c = fx.direct(); var rs = c.createStatement().executeQuery("SELECT COUNT(*) FROM APP.ORDERS")) {
            rs.next();
            assertThat(rs.getInt(1)).isEqualTo(1000);
        }
    }

    @Test
    void theRefusalToTheAiDoesNotEchoTheSql() throws Exception {
        assertThatThrownBy(
                () -> fx.queries.query(ro.label(), "SELECT * FROM APP.ORDERS WHERE X = 'TOPSECRETVALUE' FOR UPDATE", null,
                        null))
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("TOPSECRETVALUE"));
    }

    // ---- A12: no usable policy, no access at all ----

    @Test
    void aProfileWithoutAPolicyFileIsFullyRefused() throws Exception {
        DbProfile none = fx.profile("ORA-NOPOL", null, false);
        assertThatThrownBy(() -> fx.queries.query(none.label(), "SELECT 1 FROM APP.CUSTOMERS", null, null))
                .isInstanceOf(ToolCallException.class).hasMessageContaining("no usable policy");
        assertThatThrownBy(() -> fx.queries.listTables(none.label(), null, null, null)).isInstanceOf(ToolCallException.class);
        assertThatThrownBy(() -> fx.queries.describeTable(none.label(), "APP", "ORDERS")).isInstanceOf(ToolCallException.class);
    }

    @Test
    void anUnknownPermissionValueRefusesEverythingOnThatProfile() throws Exception {
        DbProfile bad = fx.profile("ORA-BAD", "access: READ_WRITE_EVERYTHING\n", false);
        assertThatThrownBy(() -> fx.queries.query(bad.label(), "SELECT 1 FROM APP.CUSTOMERS", null, null))
                .isInstanceOf(ToolCallException.class);
        // and a healthy profile next to it is unaffected
        assertThat(query(ro.label(), "SELECT COUNT(*) AS N FROM APP.CUSTOMERS", null).get("rows")).hasSize(1);
    }

    @Test
    void aProfileWhosePolicyWasEditedButNotReloadedIsRefusedUntilReloaded() throws Exception {
        fx.writePolicy(ro, "access: READ_ONLY\nread:\n  maxRows: 500\n# edited\n");
        assertThatThrownBy(() -> fx.queries.query(ro.label(), "SELECT 1 FROM APP.CUSTOMERS", null, null))
                .hasMessageContaining("POLICY_STALE");
        fx.ctx.policies.activate(ro);
        assertThat(query(ro.label(), "SELECT COUNT(*) AS N FROM APP.CUSTOMERS", null).get("rows")).hasSize(1);
    }

    @Test
    void unknownAndDisabledProfilesAreRefused() throws Exception {
        assertThatThrownBy(() -> fx.queries.query("nope", "SELECT 1 FROM APP.CUSTOMERS", null, null))
                .hasMessage("No such profile");
        assertThatThrownBy(() -> fx.queries.query(null, "SELECT 1 FROM APP.CUSTOMERS", null, null))
                .hasMessage("No such profile");
        fx.ctx.registry.replaceAll(List.of(ro.withEnabled(false)));
        assertThatThrownBy(() -> fx.queries.query(ro.label(), "SELECT 1 FROM APP.CUSTOMERS", null, null))
                .hasMessageContaining("disabled");
    }

    // ---- metadata tools ----

    @Test
    void listTablesIsPagedAndHidesSystemSchemas() throws Exception {
        JsonNode all = JSON.readTree(fx.queries.listTables(ro.label(), "APP", null, null));
        assertThat(all.get("totalCount").asInt()).isEqualTo(4);
        assertThat(all.get("tables")).extracting(n -> n.get("name").asText()).containsExactly("CUSTOMERS", "ORDERS", "TAGS",
                "USERS");

        JsonNode page = JSON.readTree(fx.queries.listTables(ro.label(), "APP", 2, 3));
        assertThat(page.get("tables")).hasSize(1);
        assertThat(page.get("tables").get(0).get("name").asText()).isEqualTo("USERS");
        assertThat(page.get("page").asInt()).isEqualTo(2);

        // SYS is Oracle's system schema and exists in the stand-in database; it must never be listed.
        JsonNode everything = JSON.readTree(fx.queries.listTables(ro.label(), null, 1, 200));
        assertThat(everything.get("tables")).extracting(n -> n.get("schema").asText()).contains("APP").doesNotContain("SYS");
        assertThat(everything.toString()).doesNotContain("USER$");
    }

    @Test
    void metadataNamesAreValidatedSoWildcardsCannotEnumerateOtherSchemas() throws Exception {
        // Names that cannot be made to match only themselves are rejected outright.
        for (String bad : List.of("%", "AP%", "APP;DROP", "a b", "../x", "A'B")) {
            assertThatThrownBy(() -> fx.queries.listTables(ro.label(), bad, null, null)).as(bad)
                    .isInstanceOf(ToolCallException.class);
        }
        // An underscore is a legitimate identifier character. It is accepted, but escaped, so it matches only itself:
        // asking for "A_P" must not also return the tables of "APP" (see MetadataServiceTest for the database-level check).
        JsonNode underscore = JSON.readTree(fx.queries.listTables(ro.label(), "A_P", null, null));
        assertThat(underscore.get("tables")).isEmpty();
        assertThat(underscore.toString()).doesNotContain("ORDERS").doesNotContain("CUSTOMERS");
        assertThatThrownBy(() -> fx.queries.describeTable(ro.label(), "APP", "%")).isInstanceOf(ToolCallException.class);
        assertThatThrownBy(() -> fx.queries.describeTable(ro.label(), "%", "ORDERS")).isInstanceOf(ToolCallException.class);
    }

    @Test
    void describeTableReturnsColumnsAndNothingForMissingOrSystemTables() throws Exception {
        JsonNode cols = JSON.readTree(fx.queries.describeTable(ro.label(), "APP", "ORDERS"));
        assertThat(cols).extracting(n -> n.get("name").asText()).containsExactly("ID", "STATUS", "VERSION");
        assertThatThrownBy(() -> fx.queries.describeTable(ro.label(), "APP", "NOPE")).hasMessageContaining("No such table");
        assertThatThrownBy(() -> fx.queries.describeTable(ro.label(), "SYS", "USER$")).isInstanceOf(ToolCallException.class);
        assertThatThrownBy(() -> fx.queries.describeTable(ro.label(), "sys", "USER")).isInstanceOf(ToolCallException.class);
    }

    @Test
    void listProfilesShowsStatusButNeverConnectionDetails() throws Exception {
        String out = fx.queries.listProfiles();
        assertThat(out).contains("ORA-RO").contains(ro.profileId()).contains("READ_ONLY");
        assertThat(out).doesNotContain(fx.h2Url).doesNotContain("jdbc:").doesNotContain(GatewayFixture.PASSWORD)
                .doesNotContain("\"sa\"").doesNotContain("username");
    }

    // ---- A03 / audit: every call recorded, allow and deny, without secrets ----

    @Test
    void everyCallIsAuditedIncludingDenialsAndTheLogHoldsNoSecretsOrSql() throws Exception {
        query(ro.label(), "SELECT COUNT(*) AS N FROM APP.CUSTOMERS WHERE NAME = 'private-name-123'", null);
        assertThatThrownBy(
                () -> fx.queries.query(ro.label(), "DELETE FROM APP.ORDERS WHERE NOTE = 'private-note-456'", null, null))
                .isInstanceOf(ToolCallException.class);
        assertThatThrownBy(() -> fx.queries.query("nope", "SELECT 1", null, null)).isInstanceOf(ToolCallException.class);
        fx.queries.listTables(ro.label(), "APP", null, null);

        List<JsonNode> events = fx.auditLines().stream().map(l -> {
            try {
                return JSON.readTree(l);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }).toList();
        assertThat(events).hasSize(4);
        assertThat(events.get(0).get("decision").asText()).isEqualTo("ALLOW");
        assertThat(events.get(0).get("result").asText()).isEqualTo("OK");
        assertThat(events.get(0).get("rowCount").asInt()).isEqualTo(1);
        assertThat(events.get(1).get("decision").asText()).isEqualTo("DENY");
        assertThat(events.get(1).get("code").asText()).isEqualTo("SQL_REJECTED");
        assertThat(events.get(2).get("decision").asText()).isEqualTo("DENY");
        assertThat(events.get(2).get("code").asText()).isEqualTo("UNKNOWN_PROFILE");
        assertThat(events.get(3).get("tool").asText()).isEqualTo("db_list_tables");
        events.forEach(e -> assertThat(e.get("requestId").asText()).startsWith("req-"));
        assertThat(events.get(0).get("profileLabel").asText()).isEqualTo("ORA-RO");
        assertThat(events.get(0).has("policyVersion")).isTrue();

        String raw = fx.auditText();
        // The operation kind ("SELECT") is a required audit field; the SQL text and its literals must not be present.
        assertThat(raw).doesNotContain("private-name-123").doesNotContain("private-note-456")
                .doesNotContain("FROM APP").doesNotContain("WHERE").doesNotContain("COUNT(*)")
                .doesNotContain(GatewayFixture.PASSWORD).doesNotContain(fx.h2Url).doesNotContain("jdbc:");
        assertThat(raw).contains("\"operation\":\"SELECT\"").contains("sqlHash");
        assertThat(AuditService.verify(fx.audit.file())).isZero();
    }

    // ---- A17: one profile down, the others keep working ----

    @Test
    void aBrokenDatabaseOnlyAffectsItsOwnProfile() throws Exception {
        DbProfile dead = new DbProfile("dead-id", "ORA-DEAD", io.quarkiverse.mcp.servers.jdbc.database.DbType.ORACLE,
                "jdbc:h2:tcp://127.0.0.1:1/none", "sa", "x".toCharArray(), null, true);
        List<DbProfile> all = new java.util.ArrayList<>(fx.ctx.registry.all());
        all.add(dead);
        fx.ctx.registry.replaceAll(all);
        fx.writePolicy(dead, "access: READ_ONLY\n");
        fx.ctx.policies.activate(dead);

        assertThatThrownBy(() -> fx.queries.query(dead.label(), "SELECT 1 FROM APP.CUSTOMERS", null, null))
                .isInstanceOf(ToolCallException.class);
        assertThat(query(ro.label(), "SELECT COUNT(*) AS N FROM APP.CUSTOMERS", null).get("rows").get(0).get("N").asInt())
                .isEqualTo(2);
        assertThat(fx.queries.listProfiles()).contains("ORA-DEAD").contains("UNAVAILABLE");
    }

    @Test
    void failureMessagesToTheAiNeverLeakDriverText() throws Exception {
        assertThatThrownBy(() -> fx.queries.query(ro.label(), "SELECT NOPE_COLUMN FROM APP.CUSTOMERS", null, null))
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("NOPE_COLUMN").doesNotContain("jdbc")
                        .doesNotContain("H2").doesNotContain("org.h2"));
    }

    @SuppressWarnings("unused")
    private static void unused() throws Exception {
        Files.exists(Path.of("."));
    }
}
