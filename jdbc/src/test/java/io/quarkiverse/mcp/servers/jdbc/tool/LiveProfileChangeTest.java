package io.quarkiverse.mcp.servers.jdbc.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

/**
 * A running server must follow what administrative commands do to {@code profiles.enc} from other processes (plan A22, and
 * the point of {@code profile disable}). Here "the server" is the fixture's context, and every administrative action goes
 * through an independent {@link ProfileManager} that shares only the files - the same relationship as two real processes.
 */
class LiveProfileChangeTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final String SQL = "SELECT COUNT(*) AS N FROM APP.CUSTOMERS";

    @TempDir
    Path tmp;

    GatewayFixture fx;
    DbProfile p;

    @BeforeEach
    void setUp() throws Exception {
        fx = new GatewayFixture(tmp);
        p = fx.profile("ORA-SIT", "access: READ_ONLY\n", true);
    }

    @AfterEach
    void tearDown() throws Exception {
        fx.close();
    }

    private int count(String ref) throws Exception {
        return JSON.readTree(fx.queries.query(ref, SQL, null, null)).get("rows").get(0).get("N").asInt();
    }

    @Test
    void theServerWorksBeforeAnyChange() throws Exception {
        assertThat(count("ORA-SIT")).isEqualTo(2);
        assertThat(fx.ctx.sync.healthy()).isTrue();
    }

    // ---- profile disable: the headline case ----

    @Test
    void disablingAProfileFromAnotherProcessStopsItImmediately() throws Exception {
        assertThat(count("ORA-SIT")).isEqualTo(2); // pool is open and warm
        fx.otherProcess().setEnabled("ORA-SIT", false);

        assertThatThrownBy(() -> count("ORA-SIT")).isInstanceOf(ToolCallException.class).hasMessageContaining("disabled");
        assertThat(fx.queries.listProfiles()).contains("\"enabled\":false");
    }

    @Test
    void reEnablingBringsItBackWithoutARestart() throws Exception {
        fx.otherProcess().setEnabled("ORA-SIT", false);
        assertThatThrownBy(() -> count("ORA-SIT")).isInstanceOf(ToolCallException.class);

        fx.otherProcess().setEnabled("ORA-SIT", true);
        assertThat(count("ORA-SIT")).isEqualTo(2);
    }

    // ---- remove / add / rename ----

    @Test
    void aRemovedProfileDisappearsAndItsPoolIsClosed() throws Exception {
        assertThat(count("ORA-SIT")).isEqualTo(2);
        fx.otherProcess().remove("ORA-SIT");

        assertThatThrownBy(() -> count("ORA-SIT")).hasMessage("No such profile");
        assertThatThrownBy(() -> count(p.profileId())).hasMessage("No such profile");
        assertThat(fx.queries.listProfiles()).doesNotContain("ORA-SIT");
    }

    @Test
    void aProfileAddedElsewhereBecomesUsable() throws Exception {
        DbProfile added = new DbProfile("11111111-aaaa-bbbb-cccc-222222222222", "ORA-NEW",
                io.quarkiverse.mcp.servers.jdbc.database.DbType.ORACLE, fx.h2Url, "sa", GatewayFixture.PASSWORD.toCharArray(),
                "APP", true);
        fx.otherProcessAdds(added);
        fx.writePolicy(added, "access: READ_ONLY\n");
        fx.ctx.policies.activate(added); // the administrator's `policy reload`

        assertThat(count("ORA-NEW")).isEqualTo(2);
        assertThat(fx.queries.listProfiles()).contains("ORA-NEW").contains("ORA-SIT");
    }

    @Test
    void aRenameIsFollowedAndTheOldLabelStopsWorking() throws Exception {
        fx.otherProcess().rename("ORA-SIT", "ORA-UAT");
        assertThat(count("ORA-UAT")).isEqualTo(2);
        assertThat(count(p.profileId())).as("the immutable id still resolves").isEqualTo(2);
        assertThatThrownBy(() -> count("ORA-SIT")).hasMessage("No such profile");
    }

    // ---- password rotation: A22 ----

    @Test
    void aRotatedPasswordReplacesTheOldPoolAndTheOldPasswordStopsWorking() throws Exception {
        assertThat(count("ORA-SIT")).isEqualTo(2); // warm pool using the old password

        // the database account's password is changed, and the gateway is told
        try (Connection c = fx.direct()) {
            c.createStatement().execute("ALTER USER SA SET PASSWORD 'rotated-pw-1'");
        }
        fx.otherProcessReplaces(x -> x.withPassword("rotated-pw-1".toCharArray()));

        assertThat(count("ORA-SIT")).as("new pool, new credentials").isEqualTo(2);
        assertThat(fx.ctx.registry.byLabel("ORA-SIT").orElseThrow().passwordCopy()).isEqualTo("rotated-pw-1".toCharArray());
    }

    @Test
    void connectionsOpenedBeforeAPasswordChangeSurviveUntilTheServerLearnsOfIt() throws Exception {
        // Already-authenticated connections keep working after the database password changes. That is the database's
        // behaviour, and it is why the server must rebuild the pool when profiles.enc changes.
        assertThat(count("ORA-SIT")).isEqualTo(2);
        try (Connection c = fx.direct()) {
            c.createStatement().execute("ALTER USER SA SET PASSWORD 'rotated-pw-2'");
        }
        assertThat(count("ORA-SIT")).as("warm pool, nothing told it anything").isEqualTo(2);
    }

    @Test
    void aChangeSeenByTheServerRebuildsThePoolSoNewCredentialsAreReallyUsed() throws Exception {
        assertThat(count("ORA-SIT")).isEqualTo(2);
        try (Connection c = fx.direct()) {
            c.createStatement().execute("ALTER USER SA SET PASSWORD 'rotated-pw-3'");
        }
        // The administrator disables the profile; the server sees that on its next call (the pool is dropped) ...
        fx.otherProcess().setEnabled("ORA-SIT", false);
        assertThatThrownBy(() -> count("ORA-SIT")).isInstanceOf(ToolCallException.class);
        // ... and when it is enabled again the stored password is still the OLD one, so a genuinely new connection fails.
        // A pool that had been kept alive would wrongly succeed here.
        fx.otherProcess().setEnabled("ORA-SIT", true);
        assertThatThrownBy(() -> count("ORA-SIT")).isInstanceOf(ToolCallException.class);

        // Supplying the new password fixes it, again without restarting anything.
        fx.otherProcessReplaces(x -> x.withPassword("rotated-pw-3".toCharArray()));
        assertThat(count("ORA-SIT")).isEqualTo(2);
    }

    // ---- fail closed ----

    @Test
    void aDamagedStoreRefusesEverythingInsteadOfUsingTheLastGoodCopy() throws Exception {
        assertThat(count("ORA-SIT")).isEqualTo(2);
        Path store = fx.paths.profilesFile();
        byte[] good = Files.readAllBytes(store);

        byte[] bad = good.clone();
        bad[bad.length / 2] ^= 0x01;
        Files.write(store, bad);

        assertThatThrownBy(() -> count("ORA-SIT")).isInstanceOf(ToolCallException.class).hasMessageContaining("cannot be read");
        assertThatThrownBy(() -> fx.queries.listProfiles()).isInstanceOf(ToolCallException.class);
        assertThat(fx.ctx.sync.healthy()).isFalse();
        assertThat(fx.ctx.registry.all()).as("nothing is kept from before").isEmpty();
    }

    @Test
    void theServerRecoversByItselfWhenTheStoreIsGoodAgain() throws Exception {
        Path store = fx.paths.profilesFile();
        byte[] good = Files.readAllBytes(store);
        assertThat(count("ORA-SIT")).isEqualTo(2);

        Files.write(store, new byte[] { 1, 2, 3 });
        assertThatThrownBy(() -> count("ORA-SIT")).isInstanceOf(ToolCallException.class);

        Path restore = Files.createTempFile(store.getParent(), "restore", ".tmp");
        Files.write(restore, good);
        Files.move(restore, store, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        assertThat(count("ORA-SIT")).isEqualTo(2);
        assertThat(fx.ctx.sync.healthy()).isTrue();
    }

    @Test
    void aMissingKeyRefusesEverything() throws Exception {
        assertThat(count("ORA-SIT")).isEqualTo(2);
        ((io.quarkiverse.mcp.servers.jdbc.secret.SecretTestSupport.MemoryKeys) fx.ctx.keys).available = false;
        // the fingerprint is unchanged, so the file is not re-read: the server keeps working with what it already decrypted.
        assertThat(count("ORA-SIT")).isEqualTo(2);

        // but as soon as the file changes it must be re-read, and without the key that is impossible
        Path store = fx.paths.profilesFile();
        byte[] content = Files.readAllBytes(store);
        Path replacement = Files.createTempFile(store.getParent(), "rewrite", ".tmp");
        Files.write(replacement, content); // same bytes, new file: the fingerprint (inode) changes
        Files.move(replacement, store, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertThatThrownBy(() -> count("ORA-SIT")).isInstanceOf(ToolCallException.class);
        assertThat(fx.ctx.registry.all()).isEmpty();
    }

    @Test
    void theRefusalNeverRevealsWhyOrWhere() throws Exception {
        Files.write(fx.paths.profilesFile(), new byte[] { 9, 9, 9 });
        assertThatThrownBy(() -> count("ORA-SIT")).satisfies(e -> assertThat(e.getMessage()).doesNotContain("profiles.enc")
                .doesNotContain(fx.paths.root().toString()).doesNotContain("Decryption").doesNotContain("key"));
    }

    @Test
    void refreshIsCheapWhenNothingChanged() throws Exception {
        assertThat(count("ORA-SIT")).isEqualTo(2);
        int before = fx.ctx.registry.all().hashCode();
        for (int i = 0; i < 200; i++) {
            assertThat(fx.ctx.sync.refresh()).isNull();
        }
        assertThat(fx.ctx.registry.all().hashCode()).as("no reload happened").isEqualTo(before);
    }

    @Test
    void everyChangeIsAuditedWithItsEffectOnTheNextCall() throws Exception {
        count("ORA-SIT");
        fx.otherProcess().setEnabled("ORA-SIT", false);
        assertThatThrownBy(() -> count("ORA-SIT")).isInstanceOf(ToolCallException.class);

        String log = fx.auditText();
        assertThat(log).contains("\"decision\":\"ALLOW\"").contains("\"decision\":\"DENY\"").contains("PROFILE_DISABLED");
        JsonNode last = JSON.readTree(fx.auditLines().get(fx.auditLines().size() - 1));
        assertThat(last.get("code").asText()).isEqualTo("PROFILE_DISABLED");
    }
}
