package io.quarkiverse.mcp.servers.jdbc.secret;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Explicit external key file, also used for the authorized Linux automatic fallback. The key lives in a
 * file that must be owner-only and must <em>not</em> be inside the configuration directory, because a key stored next to
 * the ciphertext protects nothing.
 */
public final class KeyFileMasterKeyProvider implements MasterKeyProvider {

    private final Path keyFile;
    private final Path configDir;
    private final String keyId;
    private final boolean allowInsideConfig;

    public KeyFileMasterKeyProvider(Path keyFile, Path configDir, String keyId) {
        this(keyFile, configDir, keyId, false);
    }

    KeyFileMasterKeyProvider(Path keyFile, Path configDir, String keyId, boolean allowInsideConfig) {
        this.keyFile = keyFile.toAbsolutePath().normalize();
        this.configDir = configDir.toAbsolutePath().normalize();
        this.keyId = keyId;
        this.allowInsideConfig = allowInsideConfig;
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public byte[] load() throws KeyUnavailableException {
        checkLocation();
        if (!Files.exists(keyFile)) {
            throw new KeyUnavailableException(KeyUnavailableException.Reason.NOT_FOUND, "Key file does not exist [NOT_FOUND]",
                    null);
        }
        try {
            FilePerms.verifyFile(keyFile);
            byte[] key = Base64.getDecoder().decode(Files.readString(keyFile, StandardCharsets.US_ASCII).strip());
            if (key.length != 32) {
                java.util.Arrays.fill(key, (byte) 0);
                throw new KeyUnavailableException(KeyUnavailableException.Reason.INVALID_KEY,
                        "Key file does not contain a 32-byte key [INVALID_KEY]", null);
            }
            return key;
        } catch (FilePerms.InsecurePermissionsException e) {
            throw new KeyUnavailableException("Key file must be a regular file, readable by its owner only [ACCESS_FAILED]", e);
        } catch (IllegalArgumentException e) {
            throw new KeyUnavailableException(KeyUnavailableException.Reason.INVALID_KEY,
                    "Key file is malformed [INVALID_KEY]", e);
        } catch (IOException e) {
            throw new KeyUnavailableException("Key file is unreadable [ACCESS_FAILED]", e);
        }
    }

    @Override
    public byte[] loadOrCreate() throws KeyUnavailableException {
        checkLocation();
        try {
            FilePerms.ensureSecureDir(keyFile.getParent());
            Path lockFile = keyFile.resolveSibling("." + keyFile.getFileName() + ".lock");
            if (Files.isSymbolicLink(lockFile)) {
                throw new IOException("Invalid lock file");
            }
            try (var channel = java.nio.channels.FileChannel.open(lockFile, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE); var ignored = channel.lock()) {
                FilePerms.restrictFile(lockFile);
                if (Files.exists(keyFile, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    return load();
                }
                byte[] key = new byte[32];
                new SecureRandom().nextBytes(key);
                try {
                    store(key);
                    return key.clone();
                } finally {
                    java.util.Arrays.fill(key, (byte) 0);
                }
            }
        } catch (IOException failure) {
            throw new KeyUnavailableException("Cannot create master key file [ACCESS_FAILED]", failure);
        }
    }

    @Override
    public void store(byte[] key) throws KeyUnavailableException {
        checkLocation();
        if (key == null || key.length != 32) {
            throw new KeyUnavailableException(KeyUnavailableException.Reason.INVALID_KEY,
                    "A 32-byte master key is required [INVALID_KEY]", null);
        }
        try {
            Path parent = keyFile.getParent();
            if (parent != null) {
                FilePerms.ensureSecureDir(parent);
            }
            Path tmp = Files.createTempFile(parent, "key", ".tmp");
            try {
                FilePerms.restrictFile(tmp);
                Files.writeString(tmp, Base64.getEncoder().encodeToString(key) + "\n", StandardCharsets.US_ASCII,
                        StandardOpenOption.TRUNCATE_EXISTING);
                Files.move(tmp, keyFile, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new KeyUnavailableException("Cannot write key file: " + e.getClass().getSimpleName(), e);
        }
    }

    private void checkLocation() throws KeyUnavailableException {
        if (!allowInsideConfig && keyFile.startsWith(configDir)) {
            throw new KeyUnavailableException("The key file must be outside the configuration directory");
        }
    }

    @Override
    public String describe() {
        return "key file (" + keyFile.getFileName() + ")";
    }
}
