package io.quarkiverse.mcp.servers.jdbc.secret;

import static io.quarkiverse.mcp.servers.jdbc.secret.SecretTestSupport.SENTINEL_PASSWORD;
import static io.quarkiverse.mcp.servers.jdbc.secret.SecretTestSupport.profile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore.StoreException;
import io.quarkiverse.mcp.servers.jdbc.secret.SecretTestSupport.MemoryKeys;

class EncryptedProfileStoreTest {

    @TempDir
    Path tmp;

    Path config;
    MemoryKeys keys;
    EncryptedProfileStore store;

    @BeforeEach
    void setUp() throws Exception {
        config = tmp.resolve("cfg");
        FilePerms.ensureSecureDir(config);
        keys = MemoryKeys.random();
        store = new EncryptedProfileStore(config, keys);
    }

    private static List<DbProfile> two() {
        return List.of(profile("11111111-1111-1111-1111-111111111111", "DB2-DEV"),
                profile("22222222-2222-2222-2222-222222222222", "PG-DEV"));
    }

    @Test
    void roundTripsProfilesIncludingPasswords() throws Exception {
        store.write(two());
        List<DbProfile> back = store.read();
        assertThat(back).extracting(DbProfile::label).containsExactly("DB2-DEV", "PG-DEV");
        assertThat(new String(back.get(0).passwordCopy())).isEqualTo(SENTINEL_PASSWORD);
    }

    @Test
    void passwordNeverAppearsInAnyFileOnDisk() throws Exception {
        store.write(two());
        store.write(two()); // second write also produces a backup
        try (Stream<Path> files = Files.walk(config)) {
            for (Path f : (Iterable<Path>) files.filter(Files::isRegularFile)::iterator) {
                String content = new String(Files.readAllBytes(f), java.nio.charset.StandardCharsets.ISO_8859_1);
                assertThat(content).as(f.getFileName().toString()).doesNotContain(SENTINEL_PASSWORD)
                        .doesNotContain("ai_user").doesNotContain("jdbc:postgresql");
            }
        }
    }

    @Test
    void filesAreOwnerOnlyAndNoTempFilesRemain() throws Exception {
        store.write(two());
        store.write(two());
        FilePerms.verifyFile(config.resolve("profiles.enc"));
        FilePerms.verifyFile(config.resolve("backups").resolve("profiles.enc.bak"));
        FilePerms.verifyDir(config.resolve("backups"));
        try (Stream<Path> files = Files.list(config)) {
            assertThat(files.map(p -> p.getFileName().toString())).noneMatch(n -> n.endsWith(".tmp"));
        }
    }

    @Test
    void missingKeyRefusesToReadAndDoesNotTouchTheFile() throws Exception {
        store.write(two());
        byte[] before = Files.readAllBytes(config.resolve("profiles.enc"));

        keys.available = false;
        assertThatThrownBy(store::read).isInstanceOf(StoreException.class).hasMessageContaining("Master key");
        assertThatThrownBy(() -> store.write(List.of())).isInstanceOf(StoreException.class);

        assertThat(Files.readAllBytes(config.resolve("profiles.enc"))).isEqualTo(before);
    }

    @Test
    void wrongKeyNeverOverwritesTheExistingCiphertext() throws Exception {
        store.write(two());
        byte[] before = Files.readAllBytes(config.resolve("profiles.enc"));

        // e.g. the keychain entry was lost and a new random key would be generated: that must not destroy the data
        EncryptedProfileStore other = new EncryptedProfileStore(config, MemoryKeys.random());
        assertThatThrownBy(() -> other.write(List.of(profile("33333333-3333-3333-3333-333333333333", "NEW"))))
                .isInstanceOf(StoreException.class);

        assertThat(Files.readAllBytes(config.resolve("profiles.enc"))).isEqualTo(before);
        assertThat(store.read()).hasSize(2);
    }

    @Test
    void tamperedFileIsRejectedAndLeftAlone() throws Exception {
        store.write(two());
        Path f = config.resolve("profiles.enc");
        byte[] bytes = Files.readAllBytes(f);
        bytes[bytes.length / 2] ^= 0x01;
        Files.write(f, bytes);

        assertThatThrownBy(store::read).isInstanceOf(StoreException.class);
        assertThat(Files.readAllBytes(f)).isEqualTo(bytes);
    }

    @Test
    void truncatedOrGarbageFileIsRejected() throws Exception {
        Files.write(config.resolve("profiles.enc"), new byte[] { 1, 2, 3 });
        assertThatThrownBy(store::read).isInstanceOf(StoreException.class);
        assertThatThrownBy(() -> store.write(two())).isInstanceOf(StoreException.class);
        assertThat(Files.readAllBytes(config.resolve("profiles.enc"))).containsExactly(1, 2, 3);
    }

    @Test
    void keepsThePreviousGenerationAsBackup() throws Exception {
        store.write(List.of(profile("11111111-1111-1111-1111-111111111111", "FIRST")));
        store.write(two());

        Path bak = config.resolve("backups").resolve("profiles.enc.bak");
        EncryptedProfileStore backupAsMain = new EncryptedProfileStore(tmp.resolve("restore"), keys);
        Files.createDirectories(tmp.resolve("restore"));
        Files.copy(bak, tmp.resolve("restore").resolve("profiles.enc"));
        assertThat(backupAsMain.read()).extracting(DbProfile::label).containsExactly("FIRST");
    }

    @Test
    void rejectsDuplicateIdsAndCaseInsensitiveDuplicateLabels() {
        assertThatThrownBy(() -> store.write(List.of(profile("1", "PG-DEV"), profile("2", "pg-dev"))))
                .hasMessageContaining("Duplicate profile label");
        assertThatThrownBy(() -> store.write(List.of(profile("1", "A"), profile("1", "B"))))
                .hasMessageContaining("Duplicate profile id");
    }

    @Test
    void firstWriteCreatesTheMasterKeyAndLaterReadsReuseIt() throws Exception {
        MemoryKeys fresh = new MemoryKeys(null);
        EncryptedProfileStore s = new EncryptedProfileStore(config, fresh);
        assertThatThrownBy(s::read).isInstanceOf(StoreException.class); // no file, no key
        s.write(two());
        assertThat(fresh.key).hasSize(32);
        assertThat(s.read()).hasSize(2);
    }

    @Test
    void profileToStringNeverShowsSecrets() {
        String s = profile("1", "PG-DEV").toString();
        assertThat(s).doesNotContain(SENTINEL_PASSWORD).doesNotContain("jdbc:").doesNotContain("ai_user");
    }

    @Test
    void secureDirRefusesWorldReadableDirectoriesAndSymlinks() throws Exception {
        Path loose = tmp.resolve("loose");
        Files.createDirectory(loose);
        Files.setPosixFilePermissions(loose, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        assertThatThrownBy(() -> FilePerms.ensureSecureDir(loose)).isInstanceOf(FilePerms.InsecurePermissionsException.class);

        Path link = tmp.resolve("link");
        Files.createSymbolicLink(link, config);
        assertThatThrownBy(() -> FilePerms.verifyDir(link)).isInstanceOf(FilePerms.InsecurePermissionsException.class);
    }
}
