package io.quarkiverse.mcp.servers.jdbc.secret;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

/**
 * Reads and writes {@code profiles.enc}.
 * <p>
 * Safety rules, all covered by tests:
 * <ul>
 * <li>A missing key or a failed decryption never causes the file to be rewritten (a damaged store is never replaced with
 * an empty one).</li>
 * <li>Writes go to a temp file in the same directory, are fsynced and then atomically moved over the old file, so a crash
 * leaves either the old or the new content.</li>
 * <li>The previous generation is kept in {@code backups/profiles.enc.bak}.</li>
 * <li>Decrypted content is size limited, schema checked and must have unique ids and case-insensitive unique labels.</li>
 * </ul>
 */
public final class EncryptedProfileStore {

    static final int FORMAT_VERSION = 1;
    static final int MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024;
    static final int MAX_PROFILES = 200;

    private static final ObjectMapper JSON = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true)
            .configure(SerializationFeature.INDENT_OUTPUT, false);

    private final Path file;
    private final Path backupFile;
    private final MasterKeyProvider keys;

    public EncryptedProfileStore(Path configDir, MasterKeyProvider keys) {
        this.file = configDir.resolve("profiles.enc");
        this.backupFile = configDir.resolve("backups").resolve("profiles.enc.bak");
        this.keys = keys;
    }

    public boolean exists() {
        return Files.exists(file);
    }

    /**
     * Decrypts and validates the store.
     *
     * @throws StoreException if the file is damaged, the key is missing or wrong; the file is left untouched
     */
    public List<DbProfile> read() throws StoreException {
        byte[] envelope;
        try {
            envelope = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new StoreException("Cannot read profiles.enc");
        }
        byte[] masterKey = null;
        byte[] storeKey = null;
        try {
            masterKey = keys.load();
            storeKey = Hkdf.derive(masterKey, "ai-db-mcp/profile-store", 32);
            byte[] plain = AesGcmEnvelope.open(storeKey, envelope);
            try {
                return parse(plain);
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
        } catch (MasterKeyProvider.KeyUnavailableException e) {
            throw new StoreException("Master key is not available: " + e.getMessage());
        } catch (AesGcmEnvelope.EnvelopeException e) {
            throw new StoreException(e.getMessage());
        } finally {
            wipe(masterKey);
            wipe(storeKey);
        }
    }

    /** Validates and atomically replaces the store. The master key must already exist. */
    public void write(List<DbProfile> profiles) throws StoreException {
        validate(profiles);
        byte[] masterKey = null;
        byte[] storeKey = null;
        byte[] plain = null;
        try {
            // An existing store must be readable with the current key before we overwrite it; otherwise a wrong or
            // missing key would silently destroy the only copy of the data.
            if (exists()) {
                read().forEach(DbProfile::wipe);
            }
            masterKey = keys.loadOrCreate();
            storeKey = Hkdf.derive(masterKey, "ai-db-mcp/profile-store", 32);
            plain = serialize(profiles);
            byte[] sealed = AesGcmEnvelope.seal(storeKey, keys.keyId(), plain);

            Path dir = file.toAbsolutePath().getParent();
            FilePerms.ensureSecureDir(dir);
            try (FileChannel lockCh = FileChannel.open(dir.resolve(".profiles.lock"), StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE); FileLock ignored = lockCh.lock()) {
                backupCurrent();
                Path tmp = Files.createTempFile(dir, "profiles", ".tmp");
                try {
                    FilePerms.restrictFile(tmp);
                    try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                        ch.write(ByteBuffer.wrap(sealed));
                        ch.force(true);
                    }
                    try {
                        Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                    } catch (AtomicMoveNotSupportedException e) {
                        throw new StoreException("This file system does not support atomic replacement");
                    }
                } finally {
                    Files.deleteIfExists(tmp);
                }
            }
        } catch (MasterKeyProvider.KeyUnavailableException e) {
            throw new StoreException("Master key is not available: " + e.getMessage());
        } catch (IOException e) {
            throw new StoreException("Cannot write profiles.enc: " + e.getClass().getSimpleName());
        } finally {
            wipe(masterKey);
            wipe(storeKey);
            wipe(plain);
        }
    }

    /**
     * Re-encrypts the store under {@code newMasterKey} and makes it the provider's key.
     * <p>
     * Order matters so that no step can lose data: the current store is decrypted with the current key first (proving it is
     * readable), the new ciphertext is written to a temp file, and only then is the new key stored and the file swapped in.
     * If swapping fails the previous key is put back. The previous ciphertext is kept as {@code profiles.enc.pre-rotation};
     * it can only be opened with the OLD key, so keep a copy of that key until the rotation is confirmed.
     */
    public void rotateKey(byte[] newMasterKey) throws StoreException {
        if (newMasterKey == null || newMasterKey.length != 32) {
            throw new StoreException("A 32-byte key is required");
        }
        byte[] oldMaster = null;
        byte[] newStoreKey = null;
        byte[] plain = null;
        try {
            List<DbProfile> profiles = read();
            oldMaster = keys.load();
            plain = serialize(profiles);
            profiles.forEach(DbProfile::wipe);
            newStoreKey = Hkdf.derive(newMasterKey, "ai-db-mcp/profile-store", 32);
            byte[] sealed = AesGcmEnvelope.seal(newStoreKey, keys.keyId(), plain);

            Path dir = file.toAbsolutePath().getParent();
            Path tmp = Files.createTempFile(dir, "profiles", ".tmp");
            try {
                FilePerms.restrictFile(tmp);
                try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                    ch.write(ByteBuffer.wrap(sealed));
                    ch.force(true);
                }
                Path pre = dir.resolve("backups").resolve("profiles.enc.pre-rotation");
                FilePerms.ensureSecureDir(pre.getParent());
                Files.copy(file, pre, StandardCopyOption.REPLACE_EXISTING);
                FilePerms.restrictFile(pre);

                keys.store(newMasterKey);
                try {
                    Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                    // The file still holds the old ciphertext, so the old key must stay current.
                    try {
                        keys.store(oldMaster);
                    } catch (MasterKeyProvider.KeyUnavailableException restoreFailed) {
                        throw new StoreException("Rotation failed AND the previous key could not be restored. "
                                + "profiles.enc is still encrypted with the OLD key; put that key back before doing anything else.");
                    }
                    throw new StoreException("Could not replace profiles.enc; the previous key was restored");
                }
            } finally {
                // Best effort only: a failure here must never replace the real outcome of the rotation.
                try {
                    Files.deleteIfExists(tmp);
                } catch (IOException ignored) {
                    // a leftover temp file is harmless; it is encrypted and owner-only
                }
            }
        } catch (MasterKeyProvider.KeyUnavailableException e) {
            throw new StoreException("Master key is not available: " + e.getMessage());
        } catch (IOException e) {
            throw new StoreException("Cannot rotate: " + e.getClass().getSimpleName());
        } finally {
            wipe(oldMaster);
            wipe(newStoreKey);
            wipe(plain);
        }
    }

    private void backupCurrent() throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        Path dir = backupFile.getParent();
        FilePerms.ensureSecureDir(dir);
        Path tmp = Files.createTempFile(dir, "bak", ".tmp");
        try {
            FilePerms.restrictFile(tmp);
            Files.copy(file, tmp, StandardCopyOption.REPLACE_EXISTING);
            FilePerms.restrictFile(tmp);
            Files.move(tmp, backupFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    static void validate(List<DbProfile> profiles) throws StoreException {
        if (profiles.size() > MAX_PROFILES) {
            throw new StoreException("Too many profiles");
        }
        Set<String> ids = new HashSet<>();
        Set<String> labels = new HashSet<>();
        for (DbProfile p : profiles) {
            if (!ids.add(p.profileId())) {
                throw new StoreException("Duplicate profile id");
            }
            if (!labels.add(p.label().toUpperCase(Locale.ROOT))) {
                throw new StoreException("Duplicate profile label");
            }
        }
    }

    private static byte[] serialize(List<DbProfile> profiles) throws StoreException {
        try {
            var root = JSON.createObjectNode();
            root.put("formatVersion", FORMAT_VERSION);
            root.set("profiles", JSON.valueToTree(profiles));
            byte[] out = JSON.writeValueAsBytes(root);
            if (out.length > MAX_PLAINTEXT_BYTES) {
                throw new StoreException("Profile data too large");
            }
            return out;
        } catch (JsonProcessingException e) {
            throw new StoreException("Cannot serialise profiles");
        }
    }

    private static List<DbProfile> parse(byte[] plain) throws StoreException {
        if (plain.length > MAX_PLAINTEXT_BYTES) {
            throw new StoreException("Profile data too large");
        }
        try {
            var root = JSON.readTree(plain);
            if (root.path("formatVersion").asInt(-1) != FORMAT_VERSION) {
                throw new StoreException("Unsupported profile data version");
            }
            var node = root.path("profiles");
            if (!node.isArray()) {
                throw new StoreException("Malformed profile data");
            }
            List<DbProfile> profiles = new java.util.ArrayList<>();
            for (var n : node) {
                profiles.add(JSON.treeToValue(n, DbProfile.class));
            }
            validate(profiles);
            return List.copyOf(profiles);
        } catch (JsonProcessingException | IllegalArgumentException | NullPointerException e) {
            throw new StoreException("Malformed profile data");
        } catch (IOException e) {
            throw new StoreException("Cannot parse profile data");
        }
    }

    private static void wipe(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }

    public static final class StoreException extends Exception {
        public StoreException(String message) {
            super(message);
        }
    }
}
