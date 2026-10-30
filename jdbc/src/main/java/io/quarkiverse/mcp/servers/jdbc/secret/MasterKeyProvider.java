package io.quarkiverse.mcp.servers.jdbc.secret;

/**
 * Source of the 32-byte master key that protects {@code profiles.enc}. Implementations must fail with
 * {@link KeyUnavailableException} rather than invent, downgrade or silently store a key somewhere weaker.
 */
public interface MasterKeyProvider {

    /** Identifier recorded in the envelope, e.g. {@code ai-db-mcp/master-key/v1}. */
    String keyId();

    /** Returns the existing key, or fails if there is none. Never creates one. */
    byte[] load() throws KeyUnavailableException;

    /** Returns the existing key, creating and persisting a new random one only if none exists yet. */
    byte[] loadOrCreate() throws KeyUnavailableException;

    /** Replaces the stored key (used by key rotation). */
    void store(byte[] key) throws KeyUnavailableException;

    String describe();

    class KeyUnavailableException extends Exception {
        public KeyUnavailableException(String message) {
            super(message);
        }

        public KeyUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
