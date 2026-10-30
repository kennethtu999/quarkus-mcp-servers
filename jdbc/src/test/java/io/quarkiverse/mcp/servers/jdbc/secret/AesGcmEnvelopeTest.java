package io.quarkiverse.mcp.servers.jdbc.secret;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkiverse.mcp.servers.jdbc.secret.AesGcmEnvelope.EnvelopeException;

class AesGcmEnvelopeTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] PLAIN = "hello profiles".getBytes(StandardCharsets.UTF_8);

    private static byte[] key() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        return k;
    }

    private static ObjectNode parse(byte[] env) throws Exception {
        return (ObjectNode) JSON.readTree(env);
    }

    @Test
    void roundTrips() throws Exception {
        byte[] k = key();
        byte[] env = AesGcmEnvelope.seal(k, "kid", PLAIN);
        assertThat(AesGcmEnvelope.open(k, env)).isEqualTo(PLAIN);
        assertThat(AesGcmEnvelope.keyId(env)).isEqualTo("kid");
    }

    @Test
    void envelopeHasTheDocumentedShapeAndNoPlaintext() throws Exception {
        byte[] env = AesGcmEnvelope.seal(key(), "ai-db-mcp/master-key/v1", PLAIN);
        ObjectNode n = parse(env);
        assertThat(n.get("formatVersion").asInt()).isEqualTo(1);
        assertThat(n.get("cipher").asText()).isEqualTo("AES-256-GCM");
        assertThat(n.get("keyId").asText()).isEqualTo("ai-db-mcp/master-key/v1");
        assertThat(Base64.getDecoder().decode(n.get("nonce").asText())).hasSize(12);
        assertThat(new String(env, StandardCharsets.UTF_8)).doesNotContain("hello profiles");
    }

    @Test
    void everyEncryptionUsesAFreshNonce() throws Exception {
        byte[] k = key();
        Set<String> nonces = new HashSet<>();
        for (int i = 0; i < 2000; i++) {
            nonces.add(parse(AesGcmEnvelope.seal(k, "kid", PLAIN)).get("nonce").asText());
        }
        assertThat(nonces).hasSize(2000);
    }

    @Test
    void wrongKeyFails() {
        byte[] env = AesGcmEnvelope.seal(key(), "kid", PLAIN);
        assertThatThrownBy(() -> AesGcmEnvelope.open(key(), env)).isInstanceOf(EnvelopeException.class)
                .hasMessageContaining("Decryption failed");
    }

    @Test
    void flippingAnyCiphertextBitIsDetected() throws Exception {
        byte[] k = key();
        ObjectNode n = parse(AesGcmEnvelope.seal(k, "kid", PLAIN));
        byte[] ct = Base64.getDecoder().decode(n.get("ciphertext").asText());
        for (int i = 0; i < ct.length; i++) {
            byte[] bad = ct.clone();
            bad[i] ^= 0x01;
            n.put("ciphertext", Base64.getEncoder().encodeToString(bad));
            byte[] tampered = JSON.writeValueAsBytes(n);
            assertThatThrownBy(() -> AesGcmEnvelope.open(k, tampered)).as("byte %d", i)
                    .isInstanceOf(EnvelopeException.class);
        }
    }

    @Test
    void changingTheKeyIdIsDetectedBecauseHeaderIsAuthenticated() throws Exception {
        byte[] k = key();
        ObjectNode n = parse(AesGcmEnvelope.seal(k, "kid-A", PLAIN));
        n.put("keyId", "kid-B");
        byte[] tampered = JSON.writeValueAsBytes(n);
        assertThatThrownBy(() -> AesGcmEnvelope.open(k, tampered)).hasMessageContaining("Decryption failed");
    }

    @Test
    void downgradedVersionOrCipherIsRefused() throws Exception {
        byte[] k = key();
        ObjectNode v = parse(AesGcmEnvelope.seal(k, "kid", PLAIN));
        v.put("formatVersion", 0);
        assertThatThrownBy(() -> AesGcmEnvelope.open(k, JSON.writeValueAsBytes(v))).hasMessageContaining("version");

        ObjectNode c = parse(AesGcmEnvelope.seal(k, "kid", PLAIN));
        c.put("cipher", "AES-128-CBC");
        assertThatThrownBy(() -> AesGcmEnvelope.open(k, JSON.writeValueAsBytes(c))).hasMessageContaining("cipher");
    }

    @Test
    void malformedInputsAreRejectedWithoutCrashing() throws Exception {
        byte[] k = key();
        byte[][] bad = { new byte[0], "not json".getBytes(), "[]".getBytes(), "{}".getBytes(),
                "{\"formatVersion\":1,\"cipher\":\"AES-256-GCM\",\"keyId\":\"k\",\"nonce\":\"AAAA\",\"ciphertext\":\"AAAA\"}"
                        .getBytes(),
                "{\"formatVersion\":1,\"cipher\":\"AES-256-GCM\",\"keyId\":\"k\",\"nonce\":\"!!\",\"ciphertext\":\"!!\"}"
                        .getBytes() };
        for (byte[] b : bad) {
            assertThatThrownBy(() -> AesGcmEnvelope.open(k, b)).isInstanceOf(EnvelopeException.class);
        }
    }

    @Test
    void rejectsTrailingGarbageAfterTheJsonDocument() {
        byte[] k = key();
        byte[] env = AesGcmEnvelope.seal(k, "kid", PLAIN);
        byte[] withTrailer = (new String(env, StandardCharsets.UTF_8) + "{}").getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> AesGcmEnvelope.open(k, withTrailer)).isInstanceOf(EnvelopeException.class);
    }

    @Test
    void requiresA32ByteKey() {
        assertThatThrownBy(() -> AesGcmEnvelope.seal(new byte[16], "kid", PLAIN))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void hkdfDerivesIndependentKeysPerPurpose() {
        byte[] master = key();
        byte[] a = Hkdf.derive(master, "ai-db-mcp/profile-store", 32);
        byte[] b = Hkdf.derive(master, "ai-db-mcp/approvals", 32);
        assertThat(a).hasSize(32).isNotEqualTo(b).isEqualTo(Hkdf.derive(master, "ai-db-mcp/profile-store", 32));
    }

    @Test
    void hkdfMatchesRfc5869TestCase1StructureForSha256() {
        // RFC 5869 A.1 uses a non-empty salt; we use an empty salt by design, so verify against an independent
        // computation of the same construction (HKDF-Extract with a zero salt, then Expand).
        byte[] ikm = new byte[22];
        java.util.Arrays.fill(ikm, (byte) 0x0b);
        byte[] okm = Hkdf.derive(ikm, "", 42);
        assertThat(okm).hasSize(42);
        // known-answer for HKDF-SHA256, IKM=0x0b*22, salt=(none -> 32 zero bytes), info="", L=42 (RFC 5869 A.3)
        assertThat(java.util.HexFormat.of().formatHex(okm)).isEqualTo(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }
}
