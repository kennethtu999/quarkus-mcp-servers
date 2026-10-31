package io.quarkiverse.mcp.servers.jdbc.secret;

import static org.assertj.core.api.Assertions.*;

import java.nio.file.*;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.servers.jdbc.secret.MasterKeyProvider.KeyUnavailableException;
import io.quarkiverse.mcp.servers.jdbc.secret.MasterKeyProvider.KeyUnavailableException.Reason;

class LinuxMasterKeyProviderTest {
    @TempDir
    Path tmp;

    static class OsStore implements MasterKeyProvider {
        Reason reason = Reason.BACKEND_UNAVAILABLE;
        byte[] value;
        int calls;

        public String keyId() {
            return "kid";
        }

        public byte[] load() throws KeyUnavailableException {
            calls++;
            if (value != null)
                return value.clone();
            throw new KeyUnavailableException(reason, "OS store unavailable", null);
        }

        public byte[] loadOrCreate() throws KeyUnavailableException {
            return load();
        }

        public void store(byte[] key) {
            value = key.clone();
        }

        public String describe() {
            return "OS key store";
        }
    }

    LinuxMasterKeyProvider provider(Path cfg, OsStore os) {
        return new LinuxMasterKeyProvider(cfg, "kid", tmp, os);
    }

    List<Path> keyFiles() throws Exception {
        Path directory = tmp.resolve(".config/dbmcp");
        if (!Files.exists(directory))
            return List.of();
        try (var files = Files.list(directory)) {
            return files.filter(p -> p.toString().endsWith(".key")).toList();
        }
    }

    @Test
    void headlessInitCreatesPrivatePersistentKeyAndReusesItAfterServiceReturns() throws Exception {
        Path cfg = tmp.resolve("cfg");
        OsStore os = new OsStore();
        byte[] key = provider(cfg, os).loadOrCreate();
        assertThat(keyFiles()).hasSize(1);
        FilePerms.verifyDir(tmp.resolve(".config/dbmcp"));
        FilePerms.verifyFile(keyFiles().get(0));
        os.value = new byte[32];
        assertThat(provider(cfg, os).load()).isEqualTo(key);
        assertThat(os.calls).isEqualTo(1);
    }

    @Test
    void availableServiceKeepsExistingOsKey() throws Exception {
        OsStore os = new OsStore();
        os.value = new byte[32];
        assertThat(provider(tmp.resolve("cfg"), os).loadOrCreate()).isEqualTo(os.value);
        assertThat(keyFiles()).isEmpty();
    }

    @Test
    void accessDeniedCorruptionAndMissingKeyDoNotTriggerFallback() throws Exception {
        for (Reason reason : List.of(Reason.ACCESS_FAILED, Reason.INVALID_KEY, Reason.NOT_FOUND)) {
            OsStore os = new OsStore();
            os.reason = reason;
            assertThatThrownBy(provider(tmp.resolve("cfg"), os)::loadOrCreate)
                    .isInstanceOfSatisfying(KeyUnavailableException.class,
                            failure -> assertThat(failure.reason()).isEqualTo(reason));
        }
        assertThat(keyFiles()).isEmpty();
    }

    @Test
    void loadAndInitWithExistingCiphertextNeverInventReplacementKey() throws Exception {
        Path cfg = tmp.resolve("cfg");
        Files.createDirectory(cfg);
        Files.writeString(cfg.resolve("profiles.enc"), "unchanged");
        OsStore os = new OsStore();
        assertThatThrownBy(provider(cfg, os)::load).isInstanceOf(KeyUnavailableException.class);
        assertThatThrownBy(provider(cfg, os)::loadOrCreate).isInstanceOf(KeyUnavailableException.class);
        assertThat(keyFiles()).isEmpty();
        assertThat(Files.readString(cfg.resolve("profiles.enc"))).isEqualTo("unchanged");
    }

    @Test
    void differentConfigurationDirectoriesNeverShareFallbackKeys() throws Exception {
        OsStore os = new OsStore();
        byte[] a = provider(tmp.resolve("a"), os).loadOrCreate();
        byte[] b = provider(tmp.resolve("b"), os).loadOrCreate();
        assertThat(a).isNotEqualTo(b);
        assertThat(keyFiles()).hasSize(2);
    }

    @Test
    void corruptFallbackNeverSwitchesToOsStore() throws Exception {
        Path cfg = tmp.resolve("cfg");
        OsStore os = new OsStore();
        provider(cfg, os).loadOrCreate();
        Files.writeString(keyFiles().get(0), "broken!");
        os.value = new byte[32];
        assertThatThrownBy(provider(cfg, os)::loadOrCreate).isInstanceOf(KeyUnavailableException.class);
        assertThat(os.calls).isEqualTo(1);
    }

    @Test
    void fallbackRotationPersistsAndLostFileDoesNotCreateNewKey() throws Exception {
        Path cfg = tmp.resolve("cfg");
        OsStore os = new OsStore();
        var p = provider(cfg, os);
        p.loadOrCreate();
        byte[] replacement = new byte[32];
        replacement[0] = 42;
        p.store(replacement);
        assertThat(provider(cfg, os).load()).isEqualTo(replacement);
        Files.delete(keyFiles().get(0));
        assertThatThrownBy(provider(cfg, os)::load).isInstanceOf(KeyUnavailableException.class);
    }
}
