package io.quarkiverse.mcp.servers.jdbc.secret;

import java.util.Arrays;

import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

public final class SecretTestSupport {

    public static final String SENTINEL_PASSWORD = "S3NTINEL-pa55w0rd-DO-NOT-LEAK";

    private SecretTestSupport() {
    }

    public static DbProfile profile(String id, String label) {
        return new DbProfile(id, label, DbType.POSTGRESQL, "jdbc:postgresql://h:5432/db?sslmode=verify-full", "ai_user",
                SENTINEL_PASSWORD.toCharArray(), "public", true);
    }

    /** In-memory key provider so crypto tests do not depend on the OS keychain. */
    public static final class MemoryKeys implements MasterKeyProvider {
        public byte[] key;
        public boolean available = true;

        public MemoryKeys(byte[] key) {
            this.key = key;
        }

        public static MemoryKeys random() {
            byte[] k = new byte[32];
            new java.security.SecureRandom().nextBytes(k);
            return new MemoryKeys(k);
        }

        @Override
        public String keyId() {
            return "ai-db-mcp/master-key/v1";
        }

        @Override
        public byte[] load() throws KeyUnavailableException {
            if (!available || key == null) {
                throw new KeyUnavailableException("simulated: key store unavailable");
            }
            return Arrays.copyOf(key, key.length);
        }

        @Override
        public byte[] loadOrCreate() throws KeyUnavailableException {
            if (!available) {
                throw new KeyUnavailableException("simulated: key store unavailable");
            }
            if (key == null) {
                key = random().key;
            }
            return Arrays.copyOf(key, key.length);
        }

        @Override
        public void store(byte[] newKey) {
            key = Arrays.copyOf(newKey, newKey.length);
        }

        @Override
        public String describe() {
            return "memory";
        }
    }
}
