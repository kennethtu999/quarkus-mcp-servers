package io.quarkiverse.mcp.servers.jdbc.policy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

/**
 * Records, per {@code profileId}, which policy hash an administrator has validated and activated, signed with a key
 * derived from the master key.
 * <p>
 * {@code policy reload} runs in a different process from the stdio server. This file is how it tells the server "this
 * exact policy is now approved". Because the signature needs the master key, the AI (which has no key and no file
 * access) cannot create or alter an entry; an unsigned or mismatching manifest is treated as if nothing was activated.
 */
public final class PolicyManifest {

    private static final ObjectMapper JSON = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);

    private final Path file;
    private final byte[] macKey;

    public PolicyManifest(Path file, byte[] macKey) {
        this.file = file;
        this.macKey = macKey.clone();
    }

    /** Hash per profileId, or an empty map if the file is missing, unsigned or tampered with. */
    public Map<String, String> read() {
        try {
            if (!Files.isRegularFile(file) || Files.isSymbolicLink(file)) {
                return Map.of();
            }
            ObjectNode root = (ObjectNode) JSON.readTree(Files.readAllBytes(file));
            Map<String, String> entries = JSON.convertValue(root.get("entries"), new TypeReference<TreeMap<String, String>>() {
            });
            String mac = root.path("mac").asText("");
            if (entries == null || !constantTimeEquals(mac, sign(entries))) {
                return Map.of();
            }
            return Map.copyOf(entries);
        } catch (IOException | RuntimeException e) {
            return Map.of();
        }
    }

    /** Sets the activated hash of one profile, keeping the others. Written atomically with owner-only permissions. */
    public synchronized void put(String profileId, String hash) throws IOException {
        Map<String, String> entries = new TreeMap<>(read());
        entries.put(profileId, hash);
        write(entries);
    }

    public synchronized void remove(String profileId) throws IOException {
        Map<String, String> entries = new TreeMap<>(read());
        if (entries.remove(profileId) != null) {
            write(entries);
        }
    }

    private void write(Map<String, String> entries) throws IOException {
        ObjectNode root = JSON.createObjectNode();
        root.put("formatVersion", 1);
        root.set("entries", JSON.valueToTree(new TreeMap<>(entries)));
        root.put("mac", sign(entries));
        Path dir = file.toAbsolutePath().getParent();
        FilePerms.ensureSecureDir(dir);
        Path tmp = Files.createTempFile(dir, "manifest", ".tmp");
        try {
            FilePerms.restrictFile(tmp);
            Files.write(tmp, JSON.writeValueAsBytes(root));
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private String sign(Map<String, String> entries) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            for (Map.Entry<String, String> e : new TreeMap<>(entries).entrySet()) {
                // length-prefix so ("ab","c") and ("a","bc") cannot collide
                mac.update((e.getKey().length() + ":" + e.getKey() + e.getValue().length() + ":" + e.getValue() + "\n")
                        .getBytes(StandardCharsets.UTF_8));
            }
            return Base64.getEncoder().encodeToString(mac.doFinal());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
