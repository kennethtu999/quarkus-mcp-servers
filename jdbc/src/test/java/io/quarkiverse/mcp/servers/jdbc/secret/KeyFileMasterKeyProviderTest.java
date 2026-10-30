package io.quarkiverse.mcp.servers.jdbc.secret;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.servers.jdbc.secret.MasterKeyProvider.KeyUnavailableException;

class KeyFileMasterKeyProviderTest {

    @TempDir
    Path tmp;

    private KeyFileMasterKeyProvider provider(Path keyFile, Path configDir) {
        return new KeyFileMasterKeyProvider(keyFile, configDir, "kid");
    }

    @Test
    void createsAndReloadsAnOwnerOnlyKey() throws Exception {
        Path cfg = tmp.resolve("cfg");
        Path keyFile = tmp.resolve("keys").resolve("master.key");
        KeyFileMasterKeyProvider p = provider(keyFile, cfg);

        byte[] created = p.loadOrCreate();
        assertThat(created).hasSize(32);
        FilePerms.verifyFile(keyFile);
        assertThat(p.load()).isEqualTo(created);
        assertThat(p.loadOrCreate()).isEqualTo(created);
    }

    @Test
    void loadNeverCreatesAKey() {
        KeyFileMasterKeyProvider p = provider(tmp.resolve("missing.key"), tmp.resolve("cfg"));
        assertThatThrownBy(p::load).isInstanceOf(KeyUnavailableException.class);
        assertThat(Files.exists(tmp.resolve("missing.key"))).isFalse();
    }

    @Test
    void refusesAKeyFileInsideTheConfigDirectory() {
        Path cfg = tmp.resolve("cfg");
        KeyFileMasterKeyProvider p = provider(cfg.resolve("master.key"), cfg);
        assertThatThrownBy(p::loadOrCreate).hasMessageContaining("outside the configuration directory");
        assertThatThrownBy(p::load).hasMessageContaining("outside the configuration directory");
    }

    @Test
    void refusesAKeyFileThatOthersCanRead() throws Exception {
        Path keyFile = tmp.resolve("master.key");
        KeyFileMasterKeyProvider p = provider(keyFile, tmp.resolve("cfg"));
        p.loadOrCreate();
        Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("rw-r--r--"));
        assertThatThrownBy(p::load).isInstanceOf(KeyUnavailableException.class).hasMessageContaining("owner only");
    }

    @Test
    void refusesMalformedOrWrongLengthKeys() throws Exception {
        Path keyFile = tmp.resolve("master.key");
        KeyFileMasterKeyProvider p = provider(keyFile, tmp.resolve("cfg"));
        p.loadOrCreate();
        Files.writeString(keyFile, "not base64 !!!\n");
        FilePerms.restrictFile(keyFile);
        assertThatThrownBy(p::load).isInstanceOf(KeyUnavailableException.class);

        Files.writeString(keyFile, java.util.Base64.getEncoder().encodeToString(new byte[16]));
        FilePerms.restrictFile(keyFile);
        assertThatThrownBy(p::load).hasMessageContaining("32-byte");
    }
}
