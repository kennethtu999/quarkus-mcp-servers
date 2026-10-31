package io.quarkiverse.mcp.servers.jdbc.secret;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

import com.github.javakeyring.BackendNotSupportedException;
import com.github.javakeyring.Keyring;
import com.github.javakeyring.PasswordAccessException;

/**
 * Stores the master key in the operating system credential store: macOS Keychain, Windows Credential Manager or the
 * Linux Secret Service. The account name includes a digest of the configuration directory so that two config
 * directories never share (or overwrite) a key.
 * <p>
 * If the OS store is unavailable this fails; it never falls back to a file on its own.
 */
public final class KeyringMasterKeyProvider implements MasterKeyProvider {

    static final String SERVICE = "ai-db-mcp";

    private final String keyId;
    private final String account;

    public KeyringMasterKeyProvider(Path configDir, String keyId) {
        this.keyId = keyId;
        this.account = "master-key/v1:" + digest(configDir.toAbsolutePath().normalize().toString());
    }

    @Override
    public String keyId() {
        return keyId;
    }

    /** Narrow adapter makes native failures testable without touching the user's key store. */
    interface Access extends AutoCloseable {
        String read(String service, String account) throws Exception;

        void write(String service, String account, String value) throws Exception;
    }

    interface Opener {
        Access open() throws Exception;
    }

    private Opener opener = KeyringMasterKeyProvider::openNative;

    KeyringMasterKeyProvider(Path configDir, String keyId, Opener opener) {
        this(configDir, keyId);
        this.opener = opener;
    }

    @Override
    public byte[] load() throws KeyUnavailableException {
        return read(false);
    }

    @Override
    public byte[] loadOrCreate() throws KeyUnavailableException {
        return read(true);
    }

    private byte[] read(boolean create) throws KeyUnavailableException {
        String phase = "open";
        try (Access access = opener.open()) {
            phase = "read";
            String value;
            Throwable missingCause = null;
            try {
                value = access.read(SERVICE, account);
            } catch (PasswordAccessException failure) {
                // java-keyring 1.0.4 uses the same exception for absence and access errors.
                // Only its exact, known absence result permits creating a key.
                if (!isMissing(failure, account)) {
                    throw failure;
                }
                value = null;
                missingCause = failure;
            }
            if (value != null) {
                return decode(value);
            }
            if (!create) {
                throw new KeyUnavailableException(KeyUnavailableException.Reason.NOT_FOUND,
                        "No master key in the OS key store for this configuration directory [NOT_FOUND]", missingCause);
            }
            phase = "write";
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            try {
                access.write(SERVICE, account, Base64.getEncoder().encodeToString(key));
                phase = "verify";
                byte[] persisted = decode(access.read(SERVICE, account));
                try {
                    if (!MessageDigest.isEqual(key, persisted)) {
                        throw new KeyUnavailableException("OS key store did not persist the created key [ACCESS_FAILED]");
                    }
                } finally {
                    java.util.Arrays.fill(persisted, (byte) 0);
                }
                return key.clone();
            } finally {
                java.util.Arrays.fill(key, (byte) 0);
            }
        } catch (KeyUnavailableException failure) {
            throw failure;
        } catch (Exception | LinkageError failure) {
            throw failure(phase, failure);
        }
    }

    @Override
    public void store(byte[] key) throws KeyUnavailableException {
        if (key == null || key.length != 32) {
            throw new KeyUnavailableException(KeyUnavailableException.Reason.INVALID_KEY,
                    "A 32-byte master key is required [INVALID_KEY]", null);
        }
        try (Access access = opener.open()) {
            access.write(SERVICE, account, Base64.getEncoder().encodeToString(key));
        } catch (KeyUnavailableException failure) {
            throw failure;
        } catch (Exception | LinkageError failure) {
            throw failure("store", failure);
        }
    }

    private static KeyUnavailableException failure(String phase, Throwable cause) {
        boolean unavailable = phase.equals("open") && cause instanceof BackendNotSupportedException;
        // 1.0.4 can open Secret Service and report no key, then throw in createItem
        // when the default collection is unavailable. "write" is reached only after
        // confirmed absence in loadOrCreate; rotations use the separate "store" phase.
        if (phase.equals("write") && cause instanceof NullPointerException
                && java.util.Arrays.stream(cause.getStackTrace()).anyMatch(
                        frame -> frame.getClassName().equals("com.github.javakeyring.internal.freedesktop.SimpleCollection")
                                && frame.getMethodName().equals("createItem"))) {
            unavailable = true;
        }
        for (Throwable item = cause; item != null; item = item.getCause()) {
            if (item instanceof SecurityException || item.getClass().getSimpleName().contains("AccessDenied")) {
                unavailable = false;
                break;
            }
        }
        var reason = unavailable ? KeyUnavailableException.Reason.BACKEND_UNAVAILABLE
                : KeyUnavailableException.Reason.ACCESS_FAILED;
        // Never copy native exception messages: they may contain credentials or connection details.
        return new KeyUnavailableException(reason, "OS key store " + phase + " failed [" + reason + "] ("
                + cause.getClass().getSimpleName() + ")", cause);
    }

    static boolean isMissing(PasswordAccessException failure, String account) {
        if (failure.getCause() != null) {
            return false;
        }
        return ("No stored credentials match " + SERVICE + " account: " + account).equals(failure.getMessage())
                || "Password not Found".equals(failure.getMessage())
                || "Error code 1168".equals(failure.getMessage())
                || "Password is not in wallet".equals(failure.getMessage());
    }

    private static Access openNative() throws BackendNotSupportedException {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        // Explicit selection keeps backend initialization causes; Keyring.create() discards them.
        var type = os.contains("mac") ? com.github.javakeyring.KeyringStorageType.OSX_KEYCHAIN
                : os.contains("win") ? com.github.javakeyring.KeyringStorageType.WINDOWS_CREDENTIAL_STORE
                        : com.github.javakeyring.KeyringStorageType.GNOME_KEYRING;
        Keyring nativeStore = Keyring.create(type);
        return new Access() {
            public String read(String service, String account) throws Exception {
                return nativeStore.getPassword(service, account);
            }

            public void write(String service, String account, String value) throws Exception {
                nativeStore.setPassword(service, account, value);
            }

            public void close() throws Exception {
                nativeStore.close();
            }
        };
    }

    private static byte[] decode(String value) throws KeyUnavailableException {
        if (value == null) {
            throw new KeyUnavailableException(KeyUnavailableException.Reason.ACCESS_FAILED,
                    "OS key store returned no key after write [ACCESS_FAILED]", null);
        }
        try {
            byte[] key = Base64.getDecoder().decode(value);
            if (key.length != 32) {
                java.util.Arrays.fill(key, (byte) 0);
                throw new KeyUnavailableException(KeyUnavailableException.Reason.INVALID_KEY,
                        "Stored master key has the wrong length [INVALID_KEY]", null);
            }
            return key;
        } catch (IllegalArgumentException failure) {
            throw new KeyUnavailableException(KeyUnavailableException.Reason.INVALID_KEY,
                    "Stored master key is malformed [INVALID_KEY]", failure);
        }
    }

    private static String digest(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)))
                    .substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String describe() {
        return "OS key store";
    }
}
