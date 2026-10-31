package io.quarkiverse.mcp.servers.jdbc.secret;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Linux Secret Service with the user-authorized, owner-only ~/.config/dbmcp fallback. */
public final class LinuxMasterKeyProvider implements MasterKeyProvider {
    private final MasterKeyProvider osStore;
    private final KeyFileMasterKeyProvider fileStore;
    private final Path keyFile;
    private final Path configDir;
    private boolean usingFile;

    public LinuxMasterKeyProvider(Path configDir, String keyId) {
        this(configDir, keyId, Path.of(System.getProperty("user.home")),
                new KeyringMasterKeyProvider(configDir, keyId));
    }

    LinuxMasterKeyProvider(Path configDir, String keyId, Path home, MasterKeyProvider osStore) {
        this.configDir = configDir;
        this.osStore = osStore;
        try {
            String scope = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(configDir.toAbsolutePath().normalize().toString().getBytes(StandardCharsets.UTF_8)))
                    .substring(0, 16);
            keyFile = home.resolve(".config/dbmcp/master-" + scope + ".key");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
        fileStore = new KeyFileMasterKeyProvider(keyFile, configDir, keyId, true);
    }

    public String keyId() {
        return osStore.keyId();
    }

    public byte[] load() throws KeyUnavailableException {
        return read(false);
    }

    public byte[] loadOrCreate() throws KeyUnavailableException {
        return read(true);
    }

    private byte[] read(boolean create) throws KeyUnavailableException {
        // Once a fallback exists, later desktop/DBus changes must not select another key.
        if (Files.exists(keyFile, LinkOption.NOFOLLOW_LINKS)) {
            usingFile = true;
            return create ? fileStore.loadOrCreate() : fileStore.load();
        }
        try {
            return create ? osStore.loadOrCreate() : osStore.load();
        } catch (KeyUnavailableException failure) {
            if (failure.reason() != KeyUnavailableException.Reason.BACKEND_UNAVAILABLE || !create) {
                throw failure;
            }
            // Never create a replacement for an encrypted store whose key has disappeared.
            if (Files.exists(configDir.resolve("profiles.enc"))) {
                throw failure;
            }
            io.quarkiverse.mcp.servers.jdbc.app.SafeDiagnostics
                    .print("OS key store unavailable; using ~/.config/dbmcp key file", failure);
            usingFile = true;
            return fileStore.loadOrCreate();
        }
    }

    public void store(byte[] key) throws KeyUnavailableException {
        if (Files.exists(keyFile, LinkOption.NOFOLLOW_LINKS)) {
            usingFile = true;
            fileStore.store(key);
        } else {
            osStore.store(key);
        }
    }

    public String describe() {
        return usingFile ? "Linux key file (~/.config/dbmcp/" + keyFile.getFileName() + ")" : osStore.describe();
    }
}
