package io.quarkiverse.mcp.servers.jdbc.policy;

import static io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation.DELETE;
import static io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation.INSERT;
import static io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation.UPDATE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.PolicyException;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyRepository.State;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

class PermissionServiceTest {

    static final String ID = "c3d4e5f6-1234-4567-89ab-333333333333";
    static final String HEAD = "version: 1\nprofile: ORA-SIT\nprofileId: " + ID + "\n";

    @TempDir
    Path tmp;

    Path permissions;
    byte[] macKey = new byte[32];
    PolicyManifest manifest;
    PolicyRepository repo;
    PermissionService service;
    DbProfile profile;

    @BeforeEach
    void setUp() throws Exception {
        Arrays.fill(macKey, (byte) 7);
        permissions = tmp.resolve("permissions");
        FilePerms.ensureSecureDir(permissions);
        manifest = new PolicyManifest(tmp.resolve("policy-manifest.json"), macKey);
        repo = new PolicyRepository(permissions, manifest);
        service = new PermissionService(repo);
        profile = new DbProfile(ID, "ORA-SIT", DbType.ORACLE, "jdbc:oracle:thin:@tcps://h:1521/s", "u", "p".toCharArray(),
                "APP", true);
    }

    private void writePolicy(String body) throws Exception {
        Path f = permissions.resolve("permissions_ORA-SIT.yaml");
        Files.writeString(f, HEAD + body);
        FilePerms.restrictFile(f);
    }

    private void activate(String body) throws Exception {
        writePolicy(body);
        repo.activate(profile);
    }

    private static final String WHITELIST = """
            access: READ_WRITE_WHITELIST
            write:
              whitelist:
                - {schema: APP, table: ORDERS, operations: [INSERT, UPDATE]}
                - {schema: APP, table: CUSTOMERS, operations: [UPDATE]}
                - {schema: TEST, table: TEMP_DATA, operations: [INSERT, UPDATE, DELETE]}
            """;

    // ---- A05: READ_ONLY denies writes ----

    @Test
    void readOnlyAllowsReadsAndDeniesEveryWrite() throws Exception {
        activate("access: READ_ONLY\n");
        assertThat(service.checkRead(profile).allowed()).isTrue();
        for (var op : PermissionPolicy.Operation.values()) {
            Decision d = service.checkWrite(profile, op, "APP", "ORDERS");
            assertThat(d.allowed()).as(op.toString()).isFalse();
            assertThat(d.code()).isEqualTo(PermissionService.WRITE_NOT_PERMITTED);
        }
    }

    // ---- A07 / A08: whitelist ----

    @Test
    void whitelistAllowsOnlyListedTableAndOperation() throws Exception {
        activate(WHITELIST);
        assertThat(service.checkWrite(profile, UPDATE, "APP", "ORDERS").allowed()).isTrue();
        assertThat(service.checkWrite(profile, INSERT, "APP", "ORDERS").allowed()).isTrue();
        assertThat(service.checkWrite(profile, DELETE, "TEST", "TEMP_DATA").allowed()).isTrue();

        Decision del = service.checkWrite(profile, DELETE, "APP", "ORDERS");
        assertThat(del.allowed()).isFalse();
        assertThat(del.code()).isEqualTo(PermissionService.OPERATION_NOT_ALLOWED);

        Decision users = service.checkWrite(profile, UPDATE, "APP", "USERS");
        assertThat(users.allowed()).isFalse();
        assertThat(users.code()).isEqualTo(PermissionService.TABLE_NOT_ALLOWED);

        assertThat(service.checkWrite(profile, INSERT, "APP", "CUSTOMERS").allowed()).isFalse();
        assertThat(service.checkWrite(profile, UPDATE, "OTHER", "ORDERS").allowed()).isFalse();
    }

    @Test
    void whitelistMatchingIsCaseInsensitiveButExactOtherwise() throws Exception {
        activate(WHITELIST);
        assertThat(service.checkWrite(profile, UPDATE, "app", "orders").allowed()).isTrue();
        assertThat(service.checkWrite(profile, UPDATE, "APP", "ORDERS2").allowed()).isFalse();
        assertThat(service.checkWrite(profile, UPDATE, "APP", "ORDER").allowed()).isFalse();
        assertThat(service.checkWrite(profile, UPDATE, "APP2", "ORDERS").allowed()).isFalse();
        assertThat(service.checkWrite(profile, UPDATE, "APP", null).allowed()).isFalse();
        assertThat(service.checkWrite(profile, UPDATE, null, "ORDERS").allowed()).isFalse();
    }

    @Test
    void emptyWhitelistDeniesAllWrites() throws Exception {
        activate("access: READ_WRITE_WHITELIST\nwrite:\n  whitelist: []\n");
        assertThat(service.checkRead(profile).allowed()).isTrue();
        assertThat(service.checkWrite(profile, INSERT, "APP", "ORDERS").allowed()).isFalse();
    }

    @Test
    void readWriteIsLimitedToItsSchemasAndOperations() throws Exception {
        activate("access: READ_WRITE\nwrite:\n  allowedSchemas: [public]\n  operations: [INSERT, UPDATE]\n");
        assertThat(service.checkWrite(profile, UPDATE, "PUBLIC", "ANYTHING").allowed()).isTrue();
        assertThat(service.checkWrite(profile, DELETE, "public", "ANYTHING").code())
                .isEqualTo(PermissionService.OPERATION_NOT_ALLOWED);
        assertThat(service.checkWrite(profile, UPDATE, "secret", "T").code()).isEqualTo(PermissionService.SCHEMA_NOT_ALLOWED);
    }

    // ---- A12: missing / invalid policy fails closed ----

    @Test
    void missingPolicyFileDeniesEverythingIncludingReads() {
        assertThat(repo.current(profile).state()).isEqualTo(State.POLICY_INVALID);
        assertThat(service.checkRead(profile).code()).isEqualTo(PermissionService.POLICY_UNAVAILABLE);
        assertThat(service.checkWrite(profile, UPDATE, "APP", "ORDERS").allowed()).isFalse();
    }

    @Test
    void unknownPermissionValueDeniesEverything() throws Exception {
        writePolicy("access: READ_WRITE_EVERYTHING\n");
        assertThat(repo.current(profile).state()).isEqualTo(State.POLICY_INVALID);
        assertThat(service.checkRead(profile).allowed()).isFalse();
        assertThatThrownBy(() -> repo.activate(profile)).isInstanceOf(PolicyException.class);
    }

    @Test
    void policyMustBeActivatedBeforeItTakesEffect() throws Exception {
        writePolicy("access: READ_ONLY\n");
        Snapshot s = new Snapshot(repo.current(profile));
        assertThat(s.state).isEqualTo(State.POLICY_STALE);
        assertThat(service.checkRead(profile).allowed()).isFalse();
    }

    // ---- A13: policy for the wrong profile ----

    @Test
    void policyForAnotherProfileIdIsRejected() throws Exception {
        Path f = permissions.resolve("permissions_ORA-SIT.yaml");
        Files.writeString(f,
                "version: 1\nprofile: ORA-SIT\nprofileId: 00000000-0000-0000-0000-000000000000\naccess: READ_WRITE_WHITELIST\n"
                        + "write:\n  whitelist: [{schema: A, table: T, operations: [DELETE]}]\n");
        FilePerms.restrictFile(f);
        assertThatThrownBy(() -> repo.activate(profile)).hasMessageContaining("'profileId' does not match");
        assertThat(service.checkRead(profile).allowed()).isFalse();
    }

    // ---- A14: editing a file does nothing until reload ----

    @Test
    void editingThePolicyFileRevokesAccessUntilReloaded() throws Exception {
        activate("access: READ_ONLY\n");
        assertThat(service.checkRead(profile).allowed()).isTrue();

        // someone (or something) escalates the file directly
        writePolicy(WHITELIST);

        assertThat(repo.current(profile).state()).isEqualTo(State.POLICY_STALE);
        assertThat(service.checkRead(profile).allowed()).as("stale policy must not fall back to the old one").isFalse();
        assertThat(service.checkWrite(profile, UPDATE, "APP", "ORDERS").allowed()).isFalse();

        repo.activate(profile); // administrator validates and reloads
        assertThat(service.checkWrite(profile, UPDATE, "APP", "ORDERS").allowed()).isTrue();
    }

    @Test
    void aFailedReloadLeavesTheProfileStaleNotOpen() throws Exception {
        activate("access: READ_ONLY\n");
        writePolicy("access: BROKEN\n");
        assertThatThrownBy(() -> repo.activate(profile)).isInstanceOf(PolicyException.class);
        assertThat(service.checkRead(profile).allowed()).isFalse();
    }

    @Test
    void reloadInAnotherProcessIsSeenByARunningServer() throws Exception {
        activate("access: READ_ONLY\n");
        PermissionService runningServer = new PermissionService(
                new PolicyRepository(permissions, new PolicyManifest(tmp.resolve("policy-manifest.json"), macKey)));
        assertThat(runningServer.checkWrite(profile, UPDATE, "APP", "ORDERS").allowed()).isFalse();

        // the CLI process edits the file and reloads, using its own repository instance
        writePolicy(WHITELIST);
        assertThat(runningServer.checkWrite(profile, UPDATE, "APP", "ORDERS").allowed()).isFalse(); // stale until reload
        new PolicyRepository(permissions, new PolicyManifest(tmp.resolve("policy-manifest.json"), macKey)).activate(profile);

        assertThat(runningServer.checkWrite(profile, UPDATE, "APP", "ORDERS").allowed()).isTrue();
    }

    // ---- manifest integrity ----

    @Test
    void aForgedManifestActivatesNothing() throws Exception {
        writePolicy(WHITELIST);
        String hash = PolicyLoader.load(permissions.resolve("permissions_ORA-SIT.yaml")).hash();

        // an attacker without the key writes a manifest claiming this hash is activated
        PolicyManifest forger = new PolicyManifest(tmp.resolve("policy-manifest.json"), new byte[32]);
        forger.put(ID, hash);

        assertThat(repo.current(profile).state()).isEqualTo(State.POLICY_STALE);
        assertThat(service.checkWrite(profile, UPDATE, "APP", "ORDERS").allowed()).isFalse();
    }

    @Test
    void aTamperedManifestIsIgnored() throws Exception {
        activate("access: READ_ONLY\n");
        Path m = tmp.resolve("policy-manifest.json");
        String original = Files.readString(m);
        Files.writeString(m, original.replace(ID, "11111111-1111-1111-1111-111111111111"));
        assertThat(repo.current(profile).state()).isEqualTo(State.POLICY_STALE);

        Files.writeString(m, "not json");
        assertThat(manifest.read()).isEmpty();
        Files.delete(m);
        assertThat(manifest.read()).isEmpty();
    }

    @Test
    void manifestKeepsOtherProfilesWhenOneIsUpdatedOrRemoved() throws Exception {
        manifest.put("a", "sha256:1");
        manifest.put("b", "sha256:2");
        manifest.put("a", "sha256:3");
        assertThat(manifest.read()).containsEntry("a", "sha256:3").containsEntry("b", "sha256:2");
        manifest.remove("a");
        assertThat(manifest.read()).doesNotContainKey("a").containsEntry("b", "sha256:2");
        FilePerms.verifyFile(tmp.resolve("policy-manifest.json"));
    }

    // ---- file level hazards ----

    @Test
    void policyFilesReadableByOthersAreRefused() throws Exception {
        activate("access: READ_ONLY\n");
        Files.setPosixFilePermissions(permissions.resolve("permissions_ORA-SIT.yaml"),
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-rw-rw-"));
        assertThat(repo.current(profile).state()).isEqualTo(State.POLICY_INVALID);
        assertThat(service.checkRead(profile).allowed()).isFalse();
    }

    @Test
    void symlinkedPolicyFileIsRefused() throws Exception {
        Path real = tmp.resolve("elsewhere.yaml");
        Files.writeString(real, HEAD + "access: READ_ONLY\n");
        FilePerms.restrictFile(real);
        Files.createSymbolicLink(permissions.resolve("permissions_ORA-SIT.yaml"), real);
        assertThat(repo.current(profile).state()).isEqualTo(State.POLICY_INVALID);
    }

    @Test
    void disabledProfileIsDeniedEvenWithAValidPolicy() throws Exception {
        activate(WHITELIST);
        DbProfile off = profile.withEnabled(false);
        assertThat(service.checkRead(off).code()).isEqualTo(PermissionService.PROFILE_DISABLED);
        assertThat(service.checkWrite(off, UPDATE, "APP", "ORDERS").code()).isEqualTo(PermissionService.PROFILE_DISABLED);
    }

    // ---- row limit: A09 / A10 groundwork ----

    @Test
    void readLimitIsTheStrictestOfPolicyRequestAndFiveHundred() throws Exception {
        activate("access: READ_ONLY\nread:\n  maxRows: 300\n");
        assertThat(service.readLimit(profile, null)).isEqualTo(300);
        assertThat(service.readLimit(profile, 100)).isEqualTo(100);
        assertThat(service.readLimit(profile, 1000)).isEqualTo(300);
        assertThat(service.readLimit(profile, Integer.MAX_VALUE)).isEqualTo(300);
        assertThat(service.readLimit(profile, 0)).isEqualTo(1);

        activate("access: READ_ONLY\n");
        assertThat(service.readLimit(profile, 1000)).isEqualTo(500);
        assertThat(service.readLimit(profile, null)).isEqualTo(500);
    }

    @Test
    void readLimitIsNeverAboveFiveHundredEvenWithoutAUsablePolicy() {
        assertThat(service.readLimit(profile, 100000)).isLessThanOrEqualTo(500);
        assertThat(service.readLimit(profile, null)).isLessThanOrEqualTo(500);
    }

    /** Tiny helper so the assertion above reads naturally. */
    private record Snapshot(State state) {
        Snapshot(PolicyRepository.Snapshot s) {
            this(s.state());
        }
    }
}
