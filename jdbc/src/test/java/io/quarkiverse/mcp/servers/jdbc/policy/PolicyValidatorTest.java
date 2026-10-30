package io.quarkiverse.mcp.servers.jdbc.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.PolicyException;

class PolicyValidatorTest {

    static final String ID = "c3d4e5f6-1234-4567-89ab-333333333333";

    private static PermissionPolicy ok(String yaml) throws Exception {
        return PolicyValidator.validate(PolicyLoader.parse(yaml.getBytes(StandardCharsets.UTF_8)), "ORA-SIT", ID);
    }

    private static void rejects(String yaml, String messagePart) {
        assertThatThrownBy(() -> ok(yaml)).isInstanceOf(PolicyException.class).hasMessageContaining(messagePart);
    }

    private static final String HEAD = "version: 1\nprofile: ORA-SIT\nprofileId: " + ID + "\n";

    // ---- the three plan examples (section 8) ----

    @Test
    void readOnlyExampleFromThePlan() throws Exception {
        PermissionPolicy p = ok(HEAD + "access: READ_ONLY\nread:\n  maxRows: 500\n  timeoutSeconds: 30\n");
        assertThat(p.access()).isEqualTo(AccessMode.READ_ONLY);
        assertThat(p.write()).isNull();
        assertThat(p.readMaxRows()).isEqualTo(500);
        assertThat(p.hash()).startsWith("sha256:");
    }

    @Test
    void readWriteExampleFromThePlan() throws Exception {
        PermissionPolicy p = ok(HEAD + """
                access: READ_WRITE
                read:
                  maxRows: 500
                  timeoutSeconds: 30
                write:
                  allowedSchemas:
                    - public
                  operations: [INSERT, UPDATE, DELETE]
                  maxAffectedRows: 100
                  requireConfirmation: true
                """);
        assertThat(p.write().allowedSchemas()).containsExactly("public");
        assertThat(p.write().operations()).containsExactlyInAnyOrder(Operation.values());
        assertThat(p.write().maxAffectedRows()).isEqualTo(100);
    }

    @Test
    void whitelistExampleFromThePlan() throws Exception {
        PermissionPolicy p = ok(HEAD + """
                access: READ_WRITE_WHITELIST
                write:
                  maxAffectedRows: 100
                  requireConfirmation: true
                  whitelist:
                    - schema: APP
                      table: ORDERS
                      operations: [INSERT, UPDATE]
                    - schema: APP
                      table: CUSTOMERS
                      operations: [UPDATE]
                    - schema: TEST
                      table: TEMP_DATA
                      operations: [INSERT, UPDATE, DELETE]
                """);
        assertThat(p.write().whitelist()).hasSize(3);
        assertThat(p.write().whitelist().get(0).operations()).containsExactlyInAnyOrder(Operation.INSERT, Operation.UPDATE);
    }

    @Test
    void emptyWhitelistIsValidAndMeansNoWrites() throws Exception {
        PermissionPolicy p = ok(HEAD + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist: []\n");
        assertThat(p.write().whitelist()).isEmpty();
    }

    // ---- rule 1: version and unknown fields ----

    @Test
    void rejectsUnknownOrMissingVersion() {
        rejects(HEAD.replace("version: 1", "version: 2") + "access: READ_ONLY\n", "Unsupported policy version");
        rejects("profile: ORA-SIT\nprofileId: " + ID + "\naccess: READ_ONLY\n", "'version' is required");
    }

    @Test
    void rejectsUnknownFieldsAtEveryLevelSoTyposCannotWeakenRules() {
        rejects(HEAD + "access: READ_ONLY\nacces: READ_WRITE\n", "Unknown field 'acces'");
        rejects(HEAD + "access: READ_ONLY\nread:\n  maxRow: 5\n", "Unknown field 'read.maxRow'");
        rejects(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: [A]\n  operations: [INSERT]\n  maxAffectedRow: 5\n",
                "Unknown field 'write.maxAffectedRow'");
        rejects(HEAD + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist:\n    - schema: A\n      table: T\n"
                + "      operations: [INSERT]\n      extra: x\n", "Unknown field 'write.whitelist[0].extra'");
    }

    // ---- rule 2: profile / profileId binding ----

    @Test
    void rejectsAPolicyThatBelongsToAnotherProfile() {
        rejects(HEAD.replace("ORA-SIT", "ORA-UAT") + "access: READ_ONLY\n", "'profile' does not match");
        rejects(HEAD.replace(ID, "00000000-0000-0000-0000-000000000000") + "access: READ_ONLY\n",
                "'profileId' does not match");
        rejects("version: 1\nprofile: ORA-SIT\naccess: READ_ONLY\n", "'profileId' is required");
    }

    @Test
    void profileLabelComparisonIsCaseInsensitive() throws Exception {
        assertThat(ok(HEAD.replace("ORA-SIT", "ora-sit") + "access: READ_ONLY\n").profile()).isEqualTo("ORA-SIT");
    }

    // ---- rule 3: access ----

    @Test
    void accessIsMandatoryAndMustBeOneOfTheThreeModes() {
        rejects(HEAD, "'access' is required");
        rejects(HEAD + "access: READ_WRITE_ALL\n", "'access' must be");
        rejects(HEAD + "access: read_only\n", "'access' must be");
        rejects(HEAD + "access: 7\n", "'access' must be a non-empty string");
    }

    @Test
    void readOnlyMustNotCarryAWriteSection() {
        rejects(HEAD + "access: READ_ONLY\nwrite:\n  allowedSchemas: [A]\n  operations: [INSERT]\n",
                "must not contain a 'write'");
    }

    // ---- rule 4: read.maxRows ----

    @ParameterizedTest
    @CsvSource({ "0", "-1", "501", "1000", "99999999999" })
    void rejectsOutOfRangeMaxRows(String value) {
        assertThatThrownBy(() -> ok(HEAD + "access: READ_ONLY\nread:\n  maxRows: " + value + "\n"))
                .isInstanceOf(PolicyException.class);
    }

    @Test
    void acceptsLowerMaxRowsAndRejectsNonIntegers() throws Exception {
        assertThat(ok(HEAD + "access: READ_ONLY\nread:\n  maxRows: 1\n").readMaxRows()).isEqualTo(1);
        assertThat(ok(HEAD + "access: READ_ONLY\nread:\n  maxRows: 250\n").readMaxRows()).isEqualTo(250);
        rejects(HEAD + "access: READ_ONLY\nread:\n  maxRows: 10.5\n", "must be an integer");
        rejects(HEAD + "access: READ_ONLY\nread:\n  maxRows: \"10\"\n", "must be an integer");
        rejects(HEAD + "access: READ_ONLY\nread:\n  maxRows: ten\n", "must be an integer");
    }

    @Test
    void missingReadSectionDefaultsToTheHardLimitNeverAboveIt() throws Exception {
        PermissionPolicy p = ok(HEAD + "access: READ_ONLY\n");
        assertThat(p.readMaxRows()).isEqualTo(PermissionPolicy.MAX_READ_ROWS_HARD_LIMIT).isEqualTo(500);
    }

    @Test
    void effectiveReadLimitCanNeverExceedFiveHundred() throws Exception {
        PermissionPolicy p = ok(HEAD + "access: READ_ONLY\nread:\n  maxRows: 200\n");
        assertThat(p.effectiveReadLimit(null)).isEqualTo(200);
        assertThat(p.effectiveReadLimit(100)).isEqualTo(100);
        assertThat(p.effectiveReadLimit(1000)).isEqualTo(200);
        assertThat(p.effectiveReadLimit(Integer.MAX_VALUE)).isEqualTo(200);
        assertThat(p.effectiveReadLimit(0)).isEqualTo(1);
        assertThat(p.effectiveReadLimit(-5)).isEqualTo(1);
        assertThat(ok(HEAD + "access: READ_ONLY\n").effectiveReadLimit(1000)).isEqualTo(500);
    }

    @Test
    void timeoutIsBounded() {
        rejects(HEAD + "access: READ_ONLY\nread:\n  timeoutSeconds: 0\n", "timeoutSeconds");
        rejects(HEAD + "access: READ_ONLY\nread:\n  timeoutSeconds: 3600\n", "timeoutSeconds");
    }

    // ---- rule 5: maxAffectedRows and confirmation ----

    @ParameterizedTest
    @CsvSource({ "0", "-1", "1001", "100000" })
    void rejectsOutOfRangeMaxAffectedRows(String value) {
        assertThatThrownBy(() -> ok(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: [A]\n  operations: [UPDATE]\n"
                + "  maxAffectedRows: " + value + "\n")).isInstanceOf(PolicyException.class);
    }

    @Test
    void maxAffectedRowsDefaultsToOneHundred() throws Exception {
        assertThat(ok(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: [A]\n  operations: [UPDATE]\n").write()
                .maxAffectedRows()).isEqualTo(100);
    }

    @Test
    void confirmationCannotBeSwitchedOff() throws Exception {
        rejects(HEAD
                + "access: READ_WRITE\nwrite:\n  allowedSchemas: [A]\n  operations: [UPDATE]\n  requireConfirmation: false\n",
                "cannot be disabled");
        assertThat(ok(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: [A]\n  operations: [UPDATE]\n").write()
                .requireConfirmation()).isTrue();
    }

    // ---- rule 6: whitelist is explicit, no wildcards ----

    @ParameterizedTest
    @CsvSource({ "*,ORDERS", "APP,*", "AP%,ORDERS", "APP,ORD?RS", "APP,ORDERS;DROP", "'APP.X',ORDERS", "'A B',ORDERS" })
    void rejectsWildcardsAndBadIdentifiersInTheWhitelist(String schema, String table) {
        assertThatThrownBy(() -> ok(HEAD + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist:\n    - schema: \"" + schema
                + "\"\n      table: \"" + table + "\"\n      operations: [UPDATE]\n")).isInstanceOf(PolicyException.class);
    }

    @Test
    void whitelistEntriesNeedOperationsAndOperationsMustBeKnown() {
        rejects(HEAD + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist:\n    - schema: A\n      table: T\n",
                "operations is required");
        rejects(HEAD
                + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist:\n    - schema: A\n      table: T\n      operations: []\n",
                "must not be empty");
        rejects(HEAD
                + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist:\n    - schema: A\n      table: T\n      operations: [MERGE]\n",
                "INSERT, UPDATE or DELETE");
        rejects(HEAD
                + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist:\n    - schema: A\n      table: T\n      operations: [TRUNCATE]\n",
                "INSERT, UPDATE or DELETE");
        rejects(HEAD
                + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist:\n    - schema: A\n      table: T\n      operations: [UPDATE, UPDATE]\n",
                "duplicate operation");
    }

    // ---- rule 9: duplicates ----

    @Test
    void rejectsDuplicateTablesEvenWithDifferentCase() {
        rejects(HEAD + """
                access: READ_WRITE_WHITELIST
                write:
                  whitelist:
                    - {schema: APP, table: ORDERS, operations: [INSERT]}
                    - {schema: app, table: orders, operations: [UPDATE]}
                """, "more than once");
    }

    @Test
    void readWriteNeedsAtLeastOneSchemaAndOneOperation() {
        rejects(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: []\n  operations: [UPDATE]\n", "must not be empty");
        rejects(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: [A]\n  operations: []\n", "must not be empty");
        rejects(HEAD + "access: READ_WRITE\nwrite:\n  operations: [UPDATE]\n", "allowedSchemas is required");
        rejects(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: [A, a]\n  operations: [UPDATE]\n", "duplicate schema");
        rejects(HEAD + "access: READ_WRITE\n", "'write' section is required");
    }

    @Test
    void modeSpecificSectionsCannotBeMixed() {
        rejects(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: [A]\n  operations: [UPDATE]\n  whitelist: []\n",
                "only valid with READ_WRITE_WHITELIST");
        rejects(HEAD + "access: READ_WRITE_WHITELIST\nwrite:\n  allowedSchemas: [A]\n  whitelist: []\n", "not valid with");
        rejects(HEAD + "access: READ_WRITE_WHITELIST\nwrite:\n  maxAffectedRows: 5\n", "whitelist is required");
    }

    @Test
    void typeConfusionIsRejected() {
        rejects(HEAD + "access: READ_ONLY\nread: yes\n", "'read' must be a mapping");
        rejects(HEAD + "access: READ_WRITE\nwrite: [a]\n", "'write' must be a mapping");
        rejects(HEAD + "access: READ_WRITE_WHITELIST\nwrite:\n  whitelist: {a: b}\n", "must be a list");
        rejects(HEAD + "access: READ_WRITE\nwrite:\n  allowedSchemas: A\n  operations: [UPDATE]\n", "must be a list");
    }

    // ---- rule 8: YAML hazards ----

    @Test
    void rejectsAnchorsAliasesTagsMergeKeysAndExtraDocuments() {
        rejects(HEAD + "access: &a READ_ONLY\n", "anchors and aliases");
        rejects(HEAD + "access: READ_ONLY\nread: &r {maxRows: 5}\nx: *r\n", "anchors and aliases");
        rejects(HEAD + "access: !!str READ_ONLY\n", "tags are not allowed");
        rejects(HEAD + "access: !java.lang.Object READ_ONLY\n", "tags are not allowed");
        rejects(HEAD + "access: READ_ONLY\nread:\n  <<: {maxRows: 5}\n", "merge keys");
        rejects(HEAD + "access: READ_ONLY\n---\naccess: READ_WRITE\n", "Multiple documents");
        rejects("%YAML 1.1\n" + HEAD + "access: READ_ONLY\n", "directives");
    }

    @Test
    void ordinaryTextContainingTheseCharactersInsideStringsOrCommentsIsFine() throws Exception {
        PermissionPolicy p = ok(HEAD + "access: READ_ONLY # not & an * alias ! tag\n");
        assertThat(p.access()).isEqualTo(AccessMode.READ_ONLY);
        assertThat(ok("---\n" + HEAD + "access: READ_ONLY\n").access()).isEqualTo(AccessMode.READ_ONLY);
    }

    @Test
    void rejectsDuplicateKeysSoALaterValueCannotOverrideAnEarlierOne() {
        rejects(HEAD + "access: READ_ONLY\naccess: READ_WRITE\n", "not valid YAML");
    }

    @Test
    void rejectsOversizedAndNonUtf8AndNonMappingDocuments() {
        assertThatThrownBy(() -> PolicyLoader.parse(new byte[PolicyLoader.MAX_BYTES + 1])).hasMessageContaining("larger than");
        assertThatThrownBy(() -> PolicyLoader.parse(new byte[] { (byte) 0xff, (byte) 0xfe, 0x41 }))
                .hasMessageContaining("UTF-8");
        assertThatThrownBy(() -> PolicyLoader.parse("- a\n- b\n".getBytes())).hasMessageContaining("must be a YAML mapping");
        assertThatThrownBy(() -> PolicyLoader.parse("just text".getBytes())).hasMessageContaining("must be a YAML mapping");
        assertThatThrownBy(() -> PolicyLoader.parse(new byte[0])).isInstanceOf(PolicyException.class);
    }

    @Test
    void rejectsDeeplyNestedDocuments() {
        String deep = "a: " + "[".repeat(30) + "]".repeat(30) + "\n";
        assertThatThrownBy(() -> PolicyLoader.parse(deep.getBytes())).isInstanceOf(PolicyException.class);
    }

    @Test
    void parseErrorsDoNotEchoFileContent() {
        assertThatThrownBy(() -> PolicyLoader.parse("access: [unclosed SECRETVALUE\n".getBytes()))
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("SECRETVALUE"));
    }

    // ---- file level ----

    @Test
    void loadRejectsMissingFilesAndSymlinks(@TempDir Path tmp) throws Exception {
        assertThatThrownBy(() -> PolicyLoader.load(tmp.resolve("nope.yaml"))).hasMessageContaining("missing");

        Path real = tmp.resolve("real.yaml");
        Files.writeString(real, HEAD + "access: READ_ONLY\n");
        Path link = tmp.resolve("link.yaml");
        Files.createSymbolicLink(link, real);
        assertThatThrownBy(() -> PolicyLoader.load(link)).hasMessageContaining("not a regular file");
        assertThat(PolicyLoader.load(real).tree().get("access").asText()).isEqualTo("READ_ONLY");
    }

    @Test
    void hashChangesWhenTheFileChanges() throws Exception {
        String a = PolicyLoader.parse((HEAD + "access: READ_ONLY\n").getBytes()).hash();
        String b = PolicyLoader.parse((HEAD + "access: READ_ONLY\n# x\n").getBytes()).hash();
        assertThat(a).isNotEqualTo(b);
        assertThat(a).isEqualTo(PolicyLoader.parse((HEAD + "access: READ_ONLY\n").getBytes()).hash());
    }
}
