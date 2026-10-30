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

    @Override
    public byte[] load() throws KeyUnavailableException {
        try (Keyring keyring = open()) {
            String value;
            try {
                value = keyring.getPassword(SERVICE, account);
            } catch (PasswordAccessException e) {
                throw new KeyUnavailableException("No master key in the OS key store for this configuration directory", e);
            }
            return decode(value);
        } catch (KeyUnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyUnavailableException("OS key store error: " + e.getClass().getSimpleName(), e);
        }
    }

    @Override
    public byte[] loadOrCreate() throws KeyUnavailableException {
        try (Keyring keyring = open()) {
            try {
                return decode(keyring.getPassword(SERVICE, account));
            } catch (PasswordAccessException notFound) {
                byte[] key = new byte[32];
                new SecureRandom().nextBytes(key);
                keyring.setPassword(SERVICE, account, Base64.getEncoder().encodeToString(key));
                return key;
            }
        } catch (KeyUnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyUnavailableException("OS key store error: " + e.getClass().getSimpleName(), e);
        }
    }

    @Override
    public void store(byte[] key) throws KeyUnavailableException {
        try (Keyring keyring = open()) {
            keyring.setPassword(SERVICE, account, Base64.getEncoder().encodeToString(key));
        } catch (KeyUnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyUnavailableException("OS key store error: " + e.getClass().getSimpleName(), e);
        }
    }

    private static Keyring open() throws KeyUnavailableException {
        try {
            return Keyring.create();
        } catch (BackendNotSupportedException e) {
            throw new KeyUnavailableException("No supported OS key store is available. On a headless machine use an "
                    + "explicit --key-provider=keyfile:<path> (stored outside the config directory).", e);
        }
    }

    private static byte[] decode(String value) throws KeyUnavailableException {
        try {
            byte[] key = Base64.getDecoder().decode(value);
            if (key.length != 32) {
                throw new KeyUnavailableException("Stored master key has the wrong length");
            }
            return key;
        } catch (IllegalArgumentException e) {
            throw new KeyUnavailableException("Stored master key is malformed");
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
