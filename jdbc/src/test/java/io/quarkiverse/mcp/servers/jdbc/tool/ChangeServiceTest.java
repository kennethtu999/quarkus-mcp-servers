package io.quarkiverse.mcp.servers.jdbc.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.audit.AuditService;
import io.quarkiverse.mcp.servers.jdbc.change.ChangeRequest;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

class ChangeServiceTest {

    static final ObjectMapper JSON = new ObjectMapper();

    static final String WHITELIST = """
            access: READ_WRITE_WHITELIST
            write:
              maxAffectedRows: 5
              whitelist:
                - {schema: APP, table: ORDERS, operations: [INSERT, UPDATE]}
                - {schema: APP, table: CUSTOMERS, operations: [UPDATE]}
            """;

    @TempDir
    Path tmp;

    GatewayFixture fx;
    DbProfile wl;

    @BeforeEach
    void setUp() throws Exception {
        fx = new GatewayFixture(tmp);
        wl = fx.profile("ORA-SIT", WHITELIST, true);
    }

    @AfterEach
    void tearDown() throws Exception {
        fx.close();
    }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    private ChangeRequest update(DbProfile p, String schema, String table, Map<String, Object> values,
            Map<String, Object> cond) {
        return new ChangeRequest(p.label(), Operation.UPDATE, schema, table, values, cond);
    }

    private JsonNode preview(ChangeRequest r) throws Exception {
        return JSON.readTree(fx.changes.preview(r));
    }

    private String approve(String previewId) throws Exception {
        return fx.ctx.approvals.grant(previewId);
    }

    private String status(int id) throws Exception {
        try (Connection c = fx.direct();
                var rs = c.createStatement().executeQuery("SELECT STATUS FROM APP.ORDERS WHERE ID = " + id)) {
            rs.next();
            return rs.getString(1);
        }
    }

    private int count(String sql) throws Exception {
        try (Connection c = fx.direct(); var rs = c.createStatement().executeQuery(sql)) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private JsonNode runToCommit(ChangeRequest r) throws Exception {
        JsonNode p = preview(r);
        String token = approve(p.get("previewId").asText());
        return JSON.readTree(fx.changes.execute(r.profileRef(), p.get("previewId").asText(), token));
    }

    // ---- A06 / A07: the happy path ----

    @Test
    void previewApproveExecuteCommitsExactlyTheApprovedChange() throws Exception {
        ChangeRequest r = update(wl, "APP", "ORDERS", map("STATUS", "CANCELLED"), map("ID", 7));
        JsonNode p = preview(r);
        assertThat(p.get("affectedRows").asInt()).isEqualTo(1);
        assertThat(p.get("before").get(0).get("STATUS").asText()).isEqualTo("OPEN");
        assertThat(p.get("after").get("STATUS").asText()).isEqualTo("CANCELLED");
        assertThat(status(7)).as("a preview changes nothing").isEqualTo("OPEN");

        String token = approve(p.get("previewId").asText());
        JsonNode done = JSON.readTree(fx.changes.execute(wl.label(), p.get("previewId").asText(), token));

        assertThat(done.get("committedRows").asInt()).isEqualTo(1);
        assertThat(status(7)).isEqualTo("CANCELLED");
        assertThat(status(8)).as("other rows untouched").isEqualTo("OPEN");
    }

    @Test
    void insertWorksAndIsBoundNotConcatenated() throws Exception {
        String nasty = "x'); DROP TABLE APP.ORDERS; --";
        ChangeRequest r = new ChangeRequest(wl.label(), Operation.INSERT, "APP", "ORDERS", map("ID", 9001, "STATUS", nasty),
                null);
        assertThat(runToCommit(r).get("committedRows").asInt()).isEqualTo(1);
        assertThat(status(9001)).isEqualTo(nasty);
        assertThat(count("SELECT COUNT(*) FROM APP.ORDERS")).isEqualTo(1001);
    }

    @Test
    void namesAreResolvedFromMetadataSoCaseDoesNotMatter() throws Exception {
        ChangeRequest r = update(wl, "app", "orders", map("status", "DONE"), map("id", 3));
        assertThat(runToCommit(r).get("target").asText()).isEqualTo("APP.ORDERS");
        assertThat(status(3)).isEqualTo("DONE");
    }

    // ---- A05 / A07 / A08: permissions ----

    @Test
    void readOnlyProfilesCannotPreviewAnyWrite() throws Exception {
        DbProfile ro = fx.profile("ORA-RO", "access: READ_ONLY\n", true);
        for (Operation op : Operation.values()) {
            assertThatThrownBy(() -> fx.changes
                    .preview(new ChangeRequest(ro.label(), op, "APP", "ORDERS", map("STATUS", "X"), map("ID", 1))))
                    .isInstanceOf(ToolCallException.class).hasMessageContaining("read-only");
        }
        assertThat(status(1)).isEqualTo("OPEN");
    }

    @Test
    void whitelistAllowsListedOperationsAndRefusesTheRest() throws Exception {
        // DELETE is not whitelisted for ORDERS
        assertThatThrownBy(
                () -> fx.changes.preview(new ChangeRequest(wl.label(), Operation.DELETE, "APP", "ORDERS", null, map("ID", 1))))
                .hasMessageContaining("not permitted");
        // INSERT is not whitelisted for CUSTOMERS
        assertThatThrownBy(() -> fx.changes
                .preview(new ChangeRequest(wl.label(), Operation.INSERT, "APP", "CUSTOMERS", map("ID", 9, "NAME", "z"), null)))
                .isInstanceOf(ToolCallException.class);
        // APP.USERS is not on the list at all
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "USERS", map("EMAIL", "x"), map("ID", 1))))
                .hasMessageContaining("whitelist");
        assertThat(count("SELECT COUNT(*) FROM APP.ORDERS")).isEqualTo(1000);
        assertThat(count("SELECT COUNT(*) FROM APP.USERS WHERE EMAIL = 'x'")).isZero();
    }

    @Test
    void systemSchemasAreNeverWritableEvenIfAPolicyNamedThem() throws Exception {
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "SYS", "USER$", map("NAME", "x"), map("NAME", "SYS"))))
                .isInstanceOf(ToolCallException.class);
        assertThat(count("SELECT COUNT(*) FROM SYS.USER$ WHERE NAME = 'x'")).isZero();
    }

    @Test
    void aDeniedProfileLearnsNothingAboutColumnsOrRequestShape() throws Exception {
        DbProfile ro = fx.profile("ORA-RO2", "access: READ_ONLY\n", true);
        // a column that does not exist, a malformed shape and a bad value all produce the SAME answer: "read-only"
        String[] answers = new String[3];
        answers[0] = refusal(
                new ChangeRequest(ro.label(), Operation.UPDATE, "APP", "ORDERS", map("NO_SUCH_COLUMN", 1), map("ID", 1)));
        answers[1] = refusal(new ChangeRequest(ro.label(), Operation.UPDATE, "APP", "ORDERS", map("STATUS", "x"), null));
        answers[2] = refusal(
                new ChangeRequest(ro.label(), Operation.INSERT, "APP", "ORDERS", map("VERSION", "not-a-number"), map("ID", 1)));
        assertThat(answers)
                .allSatisfy(a -> assertThat(a).contains("read-only").doesNotContain("column").doesNotContain("condition"));
        assertThat(answers[0]).isEqualTo(answers[1]).isEqualTo(answers[2]);
        assertThat(lastAudit().get("code").asText()).isEqualTo("WRITE_NOT_PERMITTED");
    }

    private String refusal(ChangeRequest r) {
        try {
            fx.changes.preview(r);
            throw new AssertionError("expected a refusal");
        } catch (ToolCallException e) {
            return e.getMessage();
        }
    }

    // ---- shape rules ----

    @Test
    void updateAndDeleteWithoutAConditionAreRefused() throws Exception {
        DbProfile rw = fx.profile("ORA-RW",
                "access: READ_WRITE\nwrite:\n  allowedSchemas: [APP]\n  operations: [INSERT, UPDATE, DELETE]\n", true);
        assertThatThrownBy(() -> fx.changes
                .preview(new ChangeRequest(rw.label(), Operation.UPDATE, "APP", "ORDERS", map("STATUS", "X"), null)))
                .hasMessageContaining("without a condition");
        assertThatThrownBy(
                () -> fx.changes.preview(new ChangeRequest(rw.label(), Operation.DELETE, "APP", "ORDERS", null, Map.of())))
                .hasMessageContaining("without a condition");
        assertThat(count("SELECT COUNT(*) FROM APP.ORDERS")).isEqualTo(1000);
    }

    @Test
    void invalidShapesAndColumnsAreRefused() throws Exception {
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("NOPE", 1), map("ID", 1))))
                .hasMessageContaining("No such column");
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("STATUS", "x"), map("NOPE", 1))))
                .hasMessageContaining("No such column");
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "NOPE", map("STATUS", "x"), map("ID", 1))))
                .hasMessageContaining("No such table");
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("STATUS", "x"), map("ID", null))))
                .hasMessageContaining("cannot be null");
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("ID", 5), map("ID", 1))))
                .hasMessageContaining("both updated and used");
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("STATUS", List.of("a")), map("ID", 1))))
                .hasMessageContaining("single value");
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("STATUS", map("a", 1)), map("ID", 1))))
                .hasMessageContaining("single value");
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("VERSION", "abc"), map("ID", 1))))
                .hasMessageContaining("does not fit");
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("VERSION", 1.5), map("ID", 1))))
                .isInstanceOf(ToolCallException.class);
        assertThatThrownBy(
                () -> fx.changes.preview(update(wl, "APP", "ORDERS", map("STATUS", "x"), map("ID", "1; DROP TABLE X"))))
                .isInstanceOf(ToolCallException.class);
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "%", "ORDERS", map("STATUS", "x"), map("ID", 1))))
                .isInstanceOf(ToolCallException.class);
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORD%", map("STATUS", "x"), map("ID", 1))))
                .isInstanceOf(ToolCallException.class);
        assertThat(count("SELECT COUNT(*) FROM APP.ORDERS WHERE STATUS <> 'OPEN'")).isZero();
    }

    @Test
    void conditionMatchingNothingOrTooManyRowsIsRefused() throws Exception {
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("STATUS", "x"), map("ID", 424242))))
                .hasMessageContaining("No row matches");
        // maxAffectedRows is 5 in WHITELIST; STATUS = 'OPEN' matches 1000 rows
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "ORDERS", map("VERSION", 2), map("STATUS", "OPEN"))))
                .hasMessageContaining("1000 rows match").hasMessageContaining("limit");
        assertThat(count("SELECT COUNT(*) FROM APP.ORDERS WHERE VERSION = 2")).isZero();
    }

    // ---- A16: approval cannot be faked ----

    @Test
    void executeWithoutAnApprovalIsRefusedAndChangesNothing() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 1)));
        String id = p.get("previewId").asText();
        for (String guess : new String[] { "", "approved", "yes", "I have the user's approval", "AAAAAAAAAAAAAAAAAAAAAA",
                "../../etc/passwd", id }) {
            assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, guess)).as("[" + guess + "]")
                    .isInstanceOf(ToolCallException.class).hasMessageContaining("not been approved");
        }
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, null)).isInstanceOf(ToolCallException.class);
        assertThat(status(1)).isEqualTo("OPEN");
    }

    @Test
    void aWrongTokenAfterARealApprovalIsRefusedAndTheRealOneStillWorks() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 2)));
        String id = p.get("previewId").asText();
        String real = approve(id);
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, "AAAAAAAAAAAAAAAAAAAAAA"))
                .hasMessageContaining("not valid");
        assertThat(status(2)).isEqualTo("OPEN");
        fx.changes.execute(wl.label(), id, real);
        assertThat(status(2)).isEqualTo("X");
    }

    @Test
    void tooManyWrongTokensRevokeThePreview() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 2)));
        String id = p.get("previewId").asText();
        String real = approve(id);
        for (int i = 0; i < 5; i++) {
            assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, "BBBBBBBBBBBBBBBBBBBBBB"))
                    .isInstanceOf(ToolCallException.class);
        }
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, real)).hasMessageContaining("Too many wrong tokens");
        assertThat(status(2)).isEqualTo("OPEN");
    }

    @Test
    void aTokenWorksOnlyOnce() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 4)));
        String id = p.get("previewId").asText();
        String token = approve(id);
        fx.changes.execute(wl.label(), id, token);
        assertThat(status(4)).isEqualTo("X");

        // put the row back and try to replay the same token
        try (Connection c = fx.direct()) {
            c.createStatement().execute("UPDATE APP.ORDERS SET STATUS = 'OPEN' WHERE ID = 4");
        }
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).isInstanceOf(ToolCallException.class);
        assertThat(status(4)).isEqualTo("OPEN");
    }

    @Test
    void aPreviewCannotBeApprovedTwice() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 4)));
        String id = p.get("previewId").asText();
        approve(id);
        assertThatThrownBy(() -> approve(id)).hasMessageContaining("already approved");
    }

    @Test
    void aTokenForOnePreviewDoesNotWorkForAnother() throws Exception {
        String idA = preview(update(wl, "APP", "ORDERS", map("STATUS", "A"), map("ID", 10))).get("previewId").asText();
        String idB = preview(update(wl, "APP", "ORDERS", map("STATUS", "B"), map("ID", 11))).get("previewId").asText();
        String tokenA = approve(idA);
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), idB, tokenA)).isInstanceOf(ToolCallException.class);
        assertThat(status(11)).isEqualTo("OPEN");
        assertThat(status(10)).isEqualTo("OPEN");
    }

    @Test
    void aGrantFileForgedWithoutTheKeyIsIgnored() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 5)));
        String id = p.get("previewId").asText();
        Path pending = fx.paths.approvalsDir().resolve("pending").resolve(id + ".json");
        Path granted = fx.paths.approvalsDir().resolve("granted");
        Files.createDirectories(granted);
        // copy the pending record into granted/ with a token hash the attacker chose, without being able to sign it
        String forged = Files.readString(pending).replaceFirst("\\}$",
                ",\"tokenHash\":\"" + sha256Hex("FORGEDTOKEN0000000000") + "\"}");
        Files.writeString(granted.resolve(id + ".json"), forged);
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, "FORGEDTOKEN0000000000"))
                .isInstanceOf(ToolCallException.class);
        assertThat(status(5)).isEqualTo("OPEN");
    }

    @Test
    void aTamperedPendingRecordIsIgnored() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 5)));
        String id = p.get("previewId").asText();
        String token = approve(id);
        Path pending = fx.paths.approvalsDir().resolve("pending").resolve(id + ".json");
        Files.writeString(pending, Files.readString(pending).replace("\"affectedRows\":1", "\"affectedRows\":2"));
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).isInstanceOf(ToolCallException.class);
        assertThat(status(5)).isEqualTo("OPEN");
    }

    @Test
    void aPreviewForAnotherProfileCannotBeExecutedHere() throws Exception {
        DbProfile other = fx.profile("ORA-OTHER", WHITELIST, true);
        String id = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 6))).get("previewId").asText();
        String token = approve(id);
        assertThatThrownBy(() -> fx.changes.execute(other.label(), id, token)).hasMessageContaining("another profile");
        assertThat(status(6)).isEqualTo("OPEN");
    }

    @Test
    void unknownAndMalformedPreviewIdsAreRefused() throws Exception {
        for (String bad : new String[] { "nope", "", "../../x", "0".repeat(32), "G".repeat(32), null }) {
            assertThatThrownBy(() -> fx.changes.execute(wl.label(), bad, "AAAAAAAAAAAAAAAAAAAAAA")).as("[" + bad + "]")
                    .isInstanceOf(ToolCallException.class);
        }
    }

    // ---- A14: policy change invalidates the preview ----

    @Test
    void reloadingADifferentPolicyInvalidatesAnOutstandingApproval() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 2)));
        String id = p.get("previewId").asText();
        String token = approve(id);

        fx.writePolicy(wl, WHITELIST.replace("maxAffectedRows: 5", "maxAffectedRows: 6"));
        fx.ctx.policies.activate(wl);

        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).isInstanceOf(ToolCallException.class)
                .hasMessageContaining("does not match");
        assertThat(status(2)).isEqualTo("OPEN");
    }

    @Test
    void anEditedButNotReloadedPolicyBlocksExecution() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 2)));
        String id = p.get("previewId").asText();
        String token = approve(id);
        fx.writePolicy(wl, WHITELIST + "# edited\n");
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).hasMessageContaining("POLICY_STALE");
        assertThat(status(2)).isEqualTo("OPEN");
    }

    @Test
    void permissionIsRecheckedAtExecuteTime() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 2)));
        String id = p.get("previewId").asText();
        String token = approve(id);
        fx.writePolicy(wl, "access: READ_ONLY\n");
        fx.ctx.policies.activate(wl);
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).hasMessageContaining("read-only");
        assertThat(status(2)).isEqualTo("OPEN");
    }

    // ---- A15: data changed after the preview ----

    @Test
    void ifTheRowChangedAfterThePreviewExecutionIsRefused() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 3)));
        String id = p.get("previewId").asText();
        String token = approve(id);
        try (Connection c = fx.direct()) {
            c.createStatement().execute("UPDATE APP.ORDERS SET STATUS = 'CHANGED-BY-SOMEONE-ELSE', VERSION = 2 WHERE ID = 3");
        }
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).isInstanceOf(ToolCallException.class)
                .hasMessageContaining("does not match");
        assertThat(status(3)).isEqualTo("CHANGED-BY-SOMEONE-ELSE");
    }

    @Test
    void aStaleRefusalDoesNotConsumeTheApprovalSoTheUserCanSeeItWasRefusedNotUsed() throws Exception {
        JsonNode p = preview(update(wl, "APP", "ORDERS", map("STATUS", "X"), map("ID", 3)));
        String id = p.get("previewId").asText();
        String token = approve(id);
        try (Connection c = fx.direct()) {
            c.createStatement().execute("UPDATE APP.ORDERS SET VERSION = 9 WHERE ID = 3");
        }
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).isInstanceOf(ToolCallException.class);
        // putting the data back makes the same approved preview valid again: nothing was consumed by the refusal
        try (Connection c = fx.direct()) {
            c.createStatement().execute("UPDATE APP.ORDERS SET VERSION = 1 WHERE ID = 3");
        }
        fx.changes.execute(wl.label(), id, token);
        assertThat(status(3)).isEqualTo("X");
    }

    @Test
    void ifNewMatchingRowsAppearTheCountCheckStopsExecution() throws Exception {
        fx.writePolicy(wl, WHITELIST.replace("- {schema: APP, table: CUSTOMERS, operations: [UPDATE]}",
                "- {schema: APP, table: TAGS, operations: [UPDATE]}"));
        fx.ctx.policies.activate(wl);

        // two rows match GRP = 'g1' at preview time
        JsonNode p = preview(update(wl, "APP", "TAGS", map("LABEL", "z"), map("GRP", "g1")));
        assertThat(p.get("affectedRows").asInt()).isEqualTo(2);
        String id = p.get("previewId").asText();
        String token = approve(id);
        try (Connection c = fx.direct()) {
            c.createStatement().execute("INSERT INTO APP.TAGS VALUES (3, 'g1', 'c')");
        }
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).isInstanceOf(ToolCallException.class);
        assertThat(count("SELECT COUNT(*) FROM APP.TAGS WHERE LABEL = 'z'")).isZero();
    }

    @Test
    void aMultiRowChangeCommitsAllRowsOrNone() throws Exception {
        fx.writePolicy(wl, WHITELIST.replace("- {schema: APP, table: CUSTOMERS, operations: [UPDATE]}",
                "- {schema: APP, table: TAGS, operations: [UPDATE]}"));
        fx.ctx.policies.activate(wl);
        JsonNode done = runToCommit(update(wl, "APP", "TAGS", map("LABEL", "z"), map("GRP", "g1")));
        assertThat(done.get("committedRows").asInt()).isEqualTo(2);
        assertThat(count("SELECT COUNT(*) FROM APP.TAGS WHERE LABEL = 'z'")).isEqualTo(2);
    }

    // ---- A21: a failure rolls back and is audited ----

    @Test
    void aFailureInsideTheTransactionRollsBackEverything() throws Exception {
        // violates the primary key on the second statement of the batch: the first-row change must not survive
        try (Connection c = fx.direct()) {
            c.createStatement().execute("ALTER TABLE APP.CUSTOMERS ADD CONSTRAINT UQ_NAME UNIQUE (NAME)");
        }
        JsonNode p = preview(update(wl, "APP", "CUSTOMERS", map("NAME", "bob"), map("ID", 1)));
        String id = p.get("previewId").asText();
        String token = approve(id);
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), id, token)).isInstanceOf(ToolCallException.class);
        assertThat(count("SELECT COUNT(*) FROM APP.CUSTOMERS WHERE NAME = 'ann'")).isEqualTo(1);

        JsonNode last = lastAudit();
        assertThat(last.get("tool").asText()).isEqualTo("db_execute_change");
        assertThat(last.get("result").asText()).isEqualTo("ERROR");
    }

    // ---- audit ----

    @Test
    void everyStepIsAuditedWithoutValuesOrSecrets() throws Exception {
        String secretValue = "VERY-PRIVATE-VALUE-7731";
        ChangeRequest r = update(wl, "APP", "ORDERS", map("STATUS", secretValue), map("ID", 12));
        JsonNode p = preview(r);
        assertThatThrownBy(() -> fx.changes.execute(wl.label(), p.get("previewId").asText(), "AAAAAAAAAAAAAAAAAAAAAA"))
                .isInstanceOf(ToolCallException.class);
        String id = p.get("previewId").asText();
        fx.changes.execute(wl.label(), id, approve(id));

        List<String> lines = fx.auditLines();
        assertThat(lines).hasSize(3);
        assertThat(lines.get(0)).contains("\"tool\":\"db_preview_change\"").contains("\"result\":\"PREVIEWED\"")
                .contains("APP.ORDERS");
        assertThat(lines.get(1)).contains("\"decision\":\"DENY\"").contains("NOT_APPROVED");
        assertThat(lines.get(2)).contains("\"result\":\"COMMITTED\"").contains("\"affectedRows\":1");
        String all = String.join("\n", lines);
        assertThat(all).doesNotContain(secretValue).doesNotContain(GatewayFixture.PASSWORD).doesNotContain("jdbc:");
        assertThat(AuditService.verify(fx.audit.file())).isZero();
    }

    @Test
    void deniedPreviewsAreAuditedAsDeny() throws Exception {
        assertThatThrownBy(() -> fx.changes.preview(update(wl, "APP", "USERS", map("EMAIL", "x"), map("ID", 1))))
                .isInstanceOf(ToolCallException.class);
        JsonNode last = lastAudit();
        assertThat(last.get("decision").asText()).isEqualTo("DENY");
        assertThat(last.get("code").asText()).isEqualTo("TABLE_NOT_ALLOWED");
    }

    private static String sha256Hex(String s) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    private JsonNode lastAudit() throws Exception {
        List<String> lines = fx.auditLines();
        return JSON.readTree(lines.get(lines.size() - 1));
    }
}
