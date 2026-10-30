package io.quarkiverse.mcp.servers.jdbc.secret;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Explicit, opt-in fallback for machines without a usable OS key store (typically headless Linux). The key lives in a
 * file that must be owner-only and must <em>not</em> be inside the configuration directory, because a key stored next to
 * the ciphertext protects nothing.
 */
public final class KeyFileMasterKeyProvider implements MasterKeyProvider {

    private final Path keyFile;
    private final Path configDir;
    private final String keyId;

    public KeyFileMasterKeyProvider(Path keyFile, Path configDir, String keyId) {
        this.keyFile = keyFile.toAbsolutePath().normalize();
        this.configDir = configDir.toAbsolutePath().normalize();
        this.keyId = keyId;
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public byte[] load() throws KeyUnavailableException {
        checkLocation();
        if (!Files.exists(keyFile)) {
            throw new KeyUnavailableException("Key file does not exist");
        }
        try {
            FilePerms.verifyFile(keyFile);
            byte[] key = Base64.getDecoder().decode(Files.readString(keyFile, StandardCharsets.US_ASCII).strip());
            if (key.length != 32) {
                throw new KeyUnavailableException("Key file does not contain a 32-byte key");
            }
            return key;
        } catch (FilePerms.InsecurePermissionsException e) {
            throw new KeyUnavailableException(e.getMessage());
        } catch (IOException | IllegalArgumentException e) {
            throw new KeyUnavailableException("Key file is unreadable or malformed");
        }
    }

    @Override
    public byte[] loadOrCreate() throws KeyUnavailableException {
        checkLocation();
        if (Files.exists(keyFile)) {
            return load();
        }
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        store(key);
        return key;
    }

    @Override
    public void store(byte[] key) throws KeyUnavailableException {
        checkLocation();
        try {
            Path parent = keyFile.getParent();
            if (parent != null && !Files.exists(parent)) {
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
            throw new KeyUnavailableException("Cannot write key file: " + e.getClass().getSimpleName());
        }
    }

    private void checkLocation() throws KeyUnavailableException {
        if (keyFile.startsWith(configDir)) {
            throw new KeyUnavailableException("The key file must be outside the configuration directory");
        }
    }

    @Override
    public String describe() {
        return "key file (" + keyFile.getFileName() + ")";
    }
}
