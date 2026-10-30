package io.quarkiverse.mcp.servers.jdbc.secret;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * AES-256-GCM envelope for {@code profiles.enc}.
 * <p>
 * The clear-text header fields ({@code formatVersion}, {@code cipher}, {@code keyId}) are bound to the ciphertext as
 * additional authenticated data, so they cannot be swapped or downgraded without failing authentication. A fresh random
 * 96-bit nonce is generated for every encryption.
 */
public final class AesGcmEnvelope {

    public static final int FORMAT_VERSION = 1;
    public static final String CIPHER = "AES-256-GCM";
    static final int NONCE_BYTES = 12;
    static final int TAG_BITS = 128;
    /** Upper bound on the ciphertext we are willing to parse, so a hostile file cannot exhaust memory. */
    static final int MAX_CIPHERTEXT_BYTES = 8 * 1024 * 1024;

    private static final ObjectMapper JSON = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcmEnvelope() {
    }

    public static byte[] seal(byte[] key, String keyId, byte[] plaintext) {
        requireKey(key);
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(FORMAT_VERSION, CIPHER, keyId));
            byte[] ct = cipher.doFinal(plaintext);

            ObjectNode node = JSON.createObjectNode();
            node.put("formatVersion", FORMAT_VERSION);
            node.put("cipher", CIPHER);
            node.put("keyId", keyId);
            node.put("nonce", Base64.getEncoder().encodeToString(nonce));
            node.put("ciphertext", Base64.getEncoder().encodeToString(ct));
            return JSON.writeValueAsBytes(node);
        } catch (GeneralSecurityException | JsonProcessingException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /** The key id recorded in the envelope, without decrypting. Used to pick the right master key. */
    public static String keyId(byte[] envelope) throws EnvelopeException {
        return parse(envelope).keyId;
    }

    public static byte[] open(byte[] key, byte[] envelope) throws EnvelopeException {
        requireKey(key);
        Parsed p = parse(envelope);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, p.nonce));
            cipher.updateAAD(aad(p.formatVersion, p.cipher, p.keyId));
            return cipher.doFinal(p.ciphertext);
        } catch (GeneralSecurityException e) {
            // Wrong key, tampered header or tampered ciphertext are deliberately indistinguishable.
            throw new EnvelopeException("Decryption failed: wrong key or the file was modified");
        }
    }

    private static Parsed parse(byte[] envelope) throws EnvelopeException {
        try {
            var node = JSON.readTree(envelope);
            if (node == null || !node.isObject()) {
                throw new EnvelopeException("Not an encrypted profile file");
            }
            Parsed p = new Parsed();
            p.formatVersion = node.path("formatVersion").asInt(-1);
            p.cipher = node.path("cipher").asText(null);
            p.keyId = node.path("keyId").asText(null);
            if (p.formatVersion != FORMAT_VERSION) {
                throw new EnvelopeException("Unsupported format version " + p.formatVersion);
            }
            if (!CIPHER.equals(p.cipher)) {
                throw new EnvelopeException("Unsupported cipher");
            }
            if (p.keyId == null || p.keyId.isBlank() || p.keyId.length() > 256) {
                throw new EnvelopeException("Missing key id");
            }
            String nonce = node.path("nonce").asText(null);
            String ct = node.path("ciphertext").asText(null);
            if (nonce == null || ct == null || ct.length() > MAX_CIPHERTEXT_BYTES * 2) {
                throw new EnvelopeException("Malformed encrypted profile file");
            }
            p.nonce = Base64.getDecoder().decode(nonce);
            p.ciphertext = Base64.getDecoder().decode(ct);
            if (p.nonce.length != NONCE_BYTES || p.ciphertext.length < TAG_BITS / 8
                    || p.ciphertext.length > MAX_CIPHERTEXT_BYTES) {
                throw new EnvelopeException("Malformed encrypted profile file");
            }
            return p;
        } catch (JsonProcessingException | IllegalArgumentException e) {
            throw new EnvelopeException("Not an encrypted profile file");
        } catch (java.io.IOException e) {
            throw new EnvelopeException("Cannot read encrypted profile file");
        }
    }

    private static byte[] aad(int formatVersion, String cipher, String keyId) {
        return (formatVersion + "|" + cipher + "|" + keyId).getBytes(StandardCharsets.UTF_8);
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("A 32-byte key is required");
        }
    }

    private static final class Parsed {
        int formatVersion;
        String cipher;
        String keyId;
        byte[] nonce;
        byte[] ciphertext;
    }

    public static final class EnvelopeException extends Exception {
        public EnvelopeException(String message) {
            super(message);
        }
    }
}
