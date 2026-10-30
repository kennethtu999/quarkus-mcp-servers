package io.quarkiverse.mcp.servers.jdbc.profile;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager;
import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import io.quarkiverse.mcp.servers.jdbc.database.DriverLoader;
import io.quarkiverse.mcp.servers.jdbc.database.JdbcUrlGuard;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionService;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyManifest;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyRepository;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore;
import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;
import io.quarkiverse.mcp.servers.jdbc.secret.SecretTestSupport.MemoryKeys;

class ProfileManagerTest {

    static final String PW = "R0tat3-Me-pa55-SENTINEL";
    static final String PG_URL = "jdbc:postgresql://pg.example.internal:5432/testdb?sslmode=verify-full";
    static final String DB2_URL = "jdbc:db2://db2.example.internal:50000/TESTDB:sslConnection=true;";
    static final String ORA_URL = "jdbc:oracle:thin:@tcps://ora.example.internal:1521/TESTPDB";

    @TempDir
    Path tmp;

    ConfigPaths paths;
    MemoryKeys keys;
    ProfileRegistry registry;
    PolicyRepository policies;
    PermissionService permissions;
    ProfileManager manager;
    EncryptedProfileStore store;

    @BeforeEach
    void setUp() throws Exception {
        paths = new ConfigPaths(tmp.resolve("cfg"));
        FilePerms.ensureSecureDir(paths.root());
        keys = MemoryKeys.random();
        store = new EncryptedProfileStore(paths.root(), keys);
        registry = new ProfileRegistry();
        policies = new PolicyRepository(paths.permissionsDir(), new PolicyManifest(paths.root().resolve("policy-manifest.json"),
                new byte[32]));
        permissions = new PermissionService(policies);
        ConnectionManager connections = new ConnectionManager(new DriverLoader(paths.driversDir(), Map.of()), 2);
        manager = new ProfileManager(paths, store, registry, new ProfileValidator(JdbcUrlGuard.strict()), connections,
                policies);
    }

    private DbProfile add(String label, DbType type, String url) throws Exception {
        return manager.add(label, type, url, "ai_user", PW.toCharArray(), null, true);
    }

    // ---- A01: five profiles, labels unique ----

    @Test
    void fiveProfilesCanCoexistAndLabelsAreUniqueIgnoringCase() throws Exception {
        add("DB2-DEV", DbType.DB2_LUW, DB2_URL);
        add("DB2-SIT", DbType.DB2_LUW, DB2_URL);
        add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        add("PG-SIT", DbType.POSTGRESQL, PG_URL);
        add("ORA-SIT", DbType.ORACLE, ORA_URL);

        assertThat(manager.list()).hasSize(5);
        assertThat(manager.list().stream().map(DbProfile::profileId).collect(Collectors.toSet())).hasSize(5);
        assertThatThrownBy(() -> add("pg-dev", DbType.POSTGRESQL, PG_URL)).hasMessageContaining("already exists");
        assertThat(manager.list()).hasSize(5);
    }

    @Test
    void everyNewProfileGetsAReadOnlyPolicyThatIsImmediatelyActive() throws Exception {
        DbProfile p = add("PG-DEV", DbType.POSTGRESQL, PG_URL);

        Path policy = paths.permissionsDir().resolve("permissions_PG-DEV.yaml");
        assertThat(policy).exists();
        assertThat(Files.readString(policy)).contains("access: READ_ONLY").contains("profileId: " + p.profileId());
        FilePerms.verifyFile(policy);
        assertThat(permissions.checkRead(p).allowed()).isTrue();
        assertThat(permissions
                .checkWrite(p, io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation.UPDATE, "public", "t")
                .allowed()).isFalse();
    }

    // ---- A02: restart ----

    @Test
    void aFreshProcessReloadsEverythingWithoutAskingForPasswordsAgain() throws Exception {
        add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        add("ORA-SIT", DbType.ORACLE, ORA_URL);

        ProfileRegistry restarted = new ProfileRegistry();
        ProfileManager second = new ProfileManager(paths, new EncryptedProfileStore(paths.root(), keys), restarted,
                new ProfileValidator(JdbcUrlGuard.strict()),
                new ConnectionManager(new DriverLoader(paths.driversDir(), Map.of())),
                policies);
        second.load();

        assertThat(second.list()).extracting(DbProfile::label).containsExactlyInAnyOrder("PG-DEV", "ORA-SIT");
        assertThat(new String(restarted.byLabel("pg-dev").orElseThrow().passwordCopy())).isEqualTo(PW);
    }

    // ---- A03: nothing on disk contains the secret ----

    @Test
    void noFileUnderTheConfigDirectoryContainsThePasswordUrlOrUsername() throws Exception {
        add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        manager.rotatePassword("PG-DEV", "Another-SENTINEL-pw".toCharArray(), true);
        manager.rename("PG-DEV", "PG-DEV2");

        try (Stream<Path> files = Files.walk(paths.root())) {
            for (Path f : (Iterable<Path>) files.filter(Files::isRegularFile)::iterator) {
                String content = new String(Files.readAllBytes(f), java.nio.charset.StandardCharsets.ISO_8859_1);
                assertThat(content).as(f.toString()).doesNotContain(PW).doesNotContain("Another-SENTINEL-pw")
                        .doesNotContain("pg.example.internal").doesNotContain("ai_user");
            }
        }
    }

    // ---- password rotation ----

    @Test
    void rotatingThePasswordReplacesItDurably() throws Exception {
        add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        manager.rotatePassword("PG-DEV", "brand-new-pw".toCharArray(), true);

        assertThat(new String(store.read().get(0).passwordCopy())).isEqualTo("brand-new-pw");
        assertThat(new String(manager.list().get(0).passwordCopy())).isEqualTo("brand-new-pw");
    }

    @Test
    void rotationWithBrokenNewCredentialsKeepsTheOldOnes() throws Exception {
        add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        // test connection is on (skipTest=false) and the host does not exist, so the new password is not accepted
        assertThatThrownBy(() -> manager.rotatePassword("PG-DEV", "nope".toCharArray(), false))
                .isInstanceOf(java.sql.SQLException.class);
        assertThat(new String(store.read().get(0).passwordCopy())).isEqualTo(PW);
    }

    @Test
    void addWithConnectionTestFailsCleanlyWhenTheDatabaseIsUnreachable() {
        assertThatThrownBy(() -> manager.add("PG-DEV", DbType.POSTGRESQL, PG_URL, "u", "p".toCharArray(), null, false))
                .isInstanceOf(java.sql.SQLException.class);
        assertThat(manager.list()).isEmpty();
        assertThat(paths.permissionsDir().resolve("permissions_PG-DEV.yaml")).doesNotExist();
        assertThat(store.exists()).isFalse();
    }

    // ---- validation ----

    @Test
    void rejectsBadLabelsUrlsAndFieldsBeforeTouchingDisk() {
        for (String bad : List.of("../x", "a/b", "a b", "", "-start", ".hidden", "a.b", "x".repeat(65))) {
            assertThatThrownBy(() -> add(bad, DbType.POSTGRESQL, PG_URL)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> add("X", DbType.POSTGRESQL, "jdbc:postgresql://h/db")).hasMessageContaining("TLS");
        assertThatThrownBy(() -> manager.add("X", DbType.POSTGRESQL, PG_URL, "", PW.toCharArray(), null, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> manager.add("X", DbType.POSTGRESQL, PG_URL, "u", new char[0], null, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> manager.add("X", DbType.POSTGRESQL, PG_URL, "u", PW.toCharArray(), "bad schema;", true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(manager.list()).isEmpty();
        assertThat(store.exists()).isFalse();
    }

    @Test
    void anExistingPolicyFileIsNeverAdoptedOrOverwritten() throws Exception {
        FilePerms.ensureSecureDir(paths.permissionsDir());
        Path leftover = paths.permissionsDir().resolve("permissions_PG-DEV.yaml");
        Files.writeString(leftover, "someone else's file");
        FilePerms.restrictFile(leftover);

        assertThatThrownBy(() -> add("PG-DEV", DbType.POSTGRESQL, PG_URL)).hasMessageContaining("already exists");
        assertThat(Files.readString(leftover)).isEqualTo("someone else's file");
        assertThat(manager.list()).isEmpty();
    }

    // ---- enable / disable / remove ----

    @Test
    void disabledProfilesAreDeniedAndCanBeReEnabled() throws Exception {
        DbProfile p = add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        manager.setEnabled("PG-DEV", false);
        assertThat(permissions.checkRead(registry.byLabel("pg-dev").orElseThrow()).code())
                .isEqualTo(PermissionService.PROFILE_DISABLED);
        assertThat(store.read().get(0).enabled()).isFalse();

        manager.setEnabled("PG-DEV", true);
        assertThat(permissions.checkRead(registry.byId(p.profileId()).orElseThrow()).allowed()).isTrue();
    }

    @Test
    void removeDropsTheProfileButKeepsTheAdministratorsPolicyFile() throws Exception {
        add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        add("ORA-SIT", DbType.ORACLE, ORA_URL);
        manager.remove("PG-DEV");

        assertThat(manager.list()).extracting(DbProfile::label).containsExactly("ORA-SIT");
        assertThat(store.read()).hasSize(1);
        assertThat(paths.permissionsDir().resolve("permissions_PG-DEV.yaml")).exists();
        assertThatThrownBy(() -> manager.remove("PG-DEV")).hasMessageContaining("No such profile");
    }

    // ---- A23: rename ----

    @Test
    void renameMovesThePolicyAndKeepsTheProfileId() throws Exception {
        DbProfile before = add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        manager.rename("PG-DEV", "pg-test");

        DbProfile after = registry.byLabel("PG-TEST").orElseThrow();
        assertThat(after.profileId()).isEqualTo(before.profileId());
        assertThat(registry.byLabel("PG-DEV")).isEmpty();
        assertThat(paths.permissionsDir().resolve("permissions_PG-DEV.yaml")).doesNotExist();
        Path moved = paths.permissionsDir().resolve("permissions_PG-TEST.yaml");
        assertThat(Files.readString(moved)).contains("profile: PG-TEST").contains("profileId: " + before.profileId())
                .doesNotContain("profile: PG-DEV");
        assertThat(permissions.checkRead(after).allowed()).isTrue();
        assertThat(store.read().get(0).label()).isEqualTo("PG-TEST");
    }

    @Test
    void renameDoesNotLeakOneProfilesPolicyOntoAnother() throws Exception {
        DbProfile a = add("PG-A", DbType.POSTGRESQL, PG_URL);
        DbProfile b = add("PG-B", DbType.POSTGRESQL, PG_URL);
        // give A a wider policy than B
        Path aFile = paths.permissionsDir().resolve("permissions_PG-A.yaml");
        Files.writeString(aFile, "version: 1\nprofile: PG-A\nprofileId: " + a.profileId()
                + "\naccess: READ_WRITE\nwrite:\n  allowedSchemas: [public]\n  operations: [UPDATE]\n");
        FilePerms.restrictFile(aFile);
        policies.activate(a);

        manager.rename("PG-A", "PG-C");

        DbProfile c = registry.byLabel("PG-C").orElseThrow();
        var update = io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation.UPDATE;
        assertThat(permissions.checkWrite(c, update, "public", "t").allowed()).isTrue();
        assertThat(permissions.checkWrite(registry.byId(b.profileId()).orElseThrow(), update, "public", "t").allowed())
                .isFalse();
    }

    @Test
    void renameFailuresLeaveTheOldStateUntouched() throws Exception {
        add("PG-A", DbType.POSTGRESQL, PG_URL);
        add("PG-B", DbType.POSTGRESQL, PG_URL);

        assertThatThrownBy(() -> manager.rename("PG-A", "pg-b")).hasMessageContaining("already exists");
        assertThatThrownBy(() -> manager.rename("PG-A", "../evil")).isInstanceOf(IllegalArgumentException.class);

        // a stray file at the destination blocks the rename
        Path blocker = paths.permissionsDir().resolve("permissions_PG-Z.yaml");
        Files.writeString(blocker, "x");
        FilePerms.restrictFile(blocker);
        assertThatThrownBy(() -> manager.rename("PG-A", "PG-Z")).hasMessageContaining("already exists");

        // a missing source policy blocks the rename
        Files.delete(paths.permissionsDir().resolve("permissions_PG-A.yaml"));
        assertThatThrownBy(() -> manager.rename("PG-A", "PG-Y")).hasMessageContaining("missing");

        assertThat(registry.byLabel("PG-A")).isPresent();
        assertThat(store.read()).extracting(DbProfile::label).containsExactlyInAnyOrder("PG-A", "PG-B");
        assertThat(Files.readString(blocker)).isEqualTo("x");
    }

    @Test
    void renameToTheSameLabelIsANoOp() throws Exception {
        add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        manager.rename("PG-DEV", "pg-dev");
        assertThat(paths.permissionsDir().resolve("permissions_PG-DEV.yaml")).exists();
        assertThat(manager.list()).hasSize(1);
    }

    // ---- registry / paths ----

    @Test
    void registryResolvesByImmutableIdOrCaseInsensitiveLabel() throws Exception {
        DbProfile p = add("PG-DEV", DbType.POSTGRESQL, PG_URL);
        assertThat(registry.resolve(p.profileId())).isPresent();
        assertThat(registry.resolve("pg-dev")).isPresent();
        assertThat(registry.resolve("nope")).isEmpty();
        assertThat(registry.resolve(null)).isEmpty();
        assertThat(registry.resolve(" ")).isEmpty();
    }

    @Test
    void policyPathsCannotEscapeThePermissionsDirectory() {
        for (String evil : List.of("../x", "..", "a/../../b", "/etc/passwd", "a\\b", "x\0y")) {
            assertThatThrownBy(() -> LabelRules.policyPath(paths.permissionsDir(), evil)).as(evil)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ---- A04: config dir resolution ----

    @Test
    void configDirPriorityIsCliThenEnvironmentThenOsDefault() {
        java.util.function.Function<String, String> env = k -> k.equals("AI_DB_MCP_CONFIG_DIR") ? "/from/env" : null;
        assertThat(ConfigPaths.resolve("/from/cli", env, "Mac OS X", "/home/u").root()).isEqualTo(Path.of("/from/cli"));
        assertThat(ConfigPaths.resolve(null, env, "Mac OS X", "/home/u").root()).isEqualTo(Path.of("/from/env"));
        assertThat(ConfigPaths.resolve(" ", env, "Mac OS X", "/home/u").root()).isEqualTo(Path.of("/from/env"));
        java.util.function.Function<String, String> none = k -> null;
        assertThat(ConfigPaths.resolve(null, none, "Mac OS X", "/Users/u").root())
                .isEqualTo(Path.of("/Users/u/Library/Application Support/ai-db-mcp"));
        assertThat(ConfigPaths.resolve(null, none, "Linux", "/home/u").root()).isEqualTo(Path.of("/home/u/.config/ai-db-mcp"));
        assertThat(ConfigPaths.resolve(null, k -> k.equals("XDG_CONFIG_HOME") ? "/xdg" : null, "Linux", "/home/u").root())
                .isEqualTo(Path.of("/xdg/ai-db-mcp"));
        assertThat(
                ConfigPaths.resolve(null, k -> k.equals("LOCALAPPDATA") ? "C:\\Users\\u\\AppData\\Local" : null, "Windows 11",
                        "C:\\Users\\u").root().getFileName().toString())
                .isEqualTo("ai-db-mcp");
    }
}
