package io.quarkiverse.mcp.servers.jdbc.change;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

/**
 * Out-of-band approval of a previewed change.
 * <p>
 * The MCP server writes a signed <em>pending</em> record when a preview is made. Only the {@code approve} command, run by a
 * person on a terminal, can turn it into a <em>granted</em> record containing the hash of a fresh one-time token, and it
 * prints the token for the person to hand to the AI. Records are signed with a key derived from the master key, which the
 * AI does not have, so it can neither create a grant nor forge a token (plan item A16).
 * <p>
 * A token is bound to profile, actor, operation digest, policy version, data fingerprint and expiry, is valid once (the
 * granted file is atomically moved away when used) and expires after {@link #TTL}.
 */
public final class ApprovalService {

    public static final Duration TTL = Duration.ofMinutes(2);
    static final int MAX_WRONG_TOKENS = 5;
    private static final Pattern ID = Pattern.compile("[a-f0-9]{32}");
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_-]{22}");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    /** The facts a grant is bound to. {@code summary} is the human readable text the approver reads. */
    public record Pending(String previewId, String profileId, String profileLabel, String actor, String operationDigest,
            String policyVersion, String fingerprint, int affectedRows, long expiresAt, String summary, String request) {

        boolean sameBinding(Pending o) {
            return previewId.equals(o.previewId) && profileId.equals(o.profileId) && actor.equals(o.actor)
                    && operationDigest.equals(o.operationDigest) && policyVersion.equals(o.policyVersion)
                    && fingerprint.equals(o.fingerprint) && affectedRows == o.affectedRows && expiresAt == o.expiresAt
                    && request.equals(o.request);
        }

        /** Short code the approver must type, so a blind "yes" is not enough. */
        public String confirmationCode() {
            return operationDigest.substring(0, 4).toUpperCase();
        }
    }

    public static final class Refused extends Exception {
        private final String code;

        public Refused(String code, String message) {
            super(message);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    private final Path pendingDir;
    private final Path grantedDir;
    private final Path usedDir;
    private final byte[] key;
    private final Clock clock;
    private final Map<String, Integer> wrongTokens = new ConcurrentHashMap<>();

    public ApprovalService(Path approvalsDir, byte[] macKey, Clock clock) {
        this.pendingDir = approvalsDir.resolve("pending");
        this.grantedDir = approvalsDir.resolve("granted");
        this.usedDir = approvalsDir.resolve("used");
        this.key = macKey.clone();
        this.clock = clock;
    }

    public Clock clock() {
        return clock;
    }

    public static String newPreviewId() {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    // ---- server side ----

    public void createPending(Pending p) throws IOException {
        checkId(p.previewId());
        ensureDirs();
        ObjectNode n = JSON.createObjectNode();
        putPending(n, p);
        n.put("mac", mac(pendingParts(p)));
        writeNew(pendingDir.resolve(p.previewId() + ".json"), n);
    }

    public Optional<Pending> readPending(String previewId) {
        if (!validId(previewId)) {
            return Optional.empty();
        }
        try {
            Path f = pendingDir.resolve(previewId + ".json");
            if (!Files.isRegularFile(f) || Files.isSymbolicLink(f)) {
                return Optional.empty();
            }
            ObjectNode n = (ObjectNode) JSON.readTree(Files.readAllBytes(f));
            Pending p = new Pending(n.path("previewId").asText(), n.path("profileId").asText(), n.path("profileLabel").asText(),
                    n.path("actor").asText(), n.path("operationDigest").asText(), n.path("policyVersion").asText(),
                    n.path("fingerprint").asText(), n.path("affectedRows").asInt(), n.path("expiresAt").asLong(),
                    n.path("summary").asText(), n.path("request").asText());
            if (!p.previewId().equals(previewId) || !constantTimeEquals(n.path("mac").asText(""), mac(pendingParts(p)))) {
                return Optional.empty();
            }
            return Optional.of(p);
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    /**
     * Checks everything about a token and, if it all holds, consumes it. The check order puts cheap and
     * non-revealing refusals first; all refusals use the same wording for "no grant" and "wrong token".
     */
    public void verifyAndConsume(Pending expected, String token) throws Refused {
        String id = expected.previewId();
        if (!validId(id)) {
            throw new Refused("PREVIEW_NOT_FOUND", "Unknown preview");
        }
        if (wrongTokens.getOrDefault(id, 0) >= MAX_WRONG_TOKENS) {
            revoke(id);
            throw new Refused("APPROVAL_REVOKED", "Too many wrong tokens; make a new preview");
        }
        if (clock.millis() / 1000 >= expected.expiresAt()) {
            throw new Refused("PREVIEW_EXPIRED", "The preview has expired; make a new preview");
        }
        Pending onDisk = readPending(id).orElseThrow(() -> new Refused("PREVIEW_NOT_FOUND", "Unknown or tampered preview"));
        if (!onDisk.sameBinding(expected)) {
            throw new Refused("PREVIEW_MISMATCH", "The preview does not match");
        }

        Granted g = readGranted(id)
                .orElseThrow(() -> new Refused("NOT_APPROVED", "This change has not been approved by the user"));
        boolean tokenOk = token != null && TOKEN.matcher(token.strip()).matches()
                && constantTimeEquals(g.tokenHash, sha256(token.strip()));
        if (!tokenOk) {
            wrongTokens.merge(id, 1, Integer::sum);
            throw new Refused("NOT_APPROVED", "The confirmation token is not valid");
        }
        if (!g.pendingBinding.sameBinding(expected)) {
            throw new Refused("PREVIEW_MISMATCH", "The approval does not match this preview");
        }
        try {
            Files.createDirectories(usedDir);
            // The atomic move is the single-use gate: only one caller can make it succeed.
            Files.move(grantedDir.resolve(id + ".json"), usedDir.resolve(id + ".json"), StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new Refused("NOT_APPROVED", "The approval was already used");
        }
        try {
            Files.deleteIfExists(pendingDir.resolve(id + ".json"));
        } catch (IOException ignored) {
            // the grant is already consumed, so a leftover pending file cannot be used again
        }
        wrongTokens.remove(id);
    }

    // ---- approver side (CLI) ----

    public List<Pending> listPending() {
        List<Pending> out = new ArrayList<>();
        try (var files = Files.list(pendingDir)) {
            for (Path f : (Iterable<Path>) files::iterator) {
                String name = f.getFileName().toString();
                if (name.endsWith(".json")) {
                    readPending(name.substring(0, name.length() - 5)).filter(p -> clock.millis() / 1000 < p.expiresAt())
                            .filter(p -> !Files.exists(grantedDir.resolve(p.previewId() + ".json"))).ifPresent(out::add);
                }
            }
        } catch (IOException e) {
            return List.of();
        }
        return out;
    }

    /** Records the approval and returns the one-time token. Fails if the preview is unknown, expired or already granted. */
    public String grant(String previewId) throws Refused {
        Pending p = readPending(previewId).orElseThrow(() -> new Refused("PREVIEW_NOT_FOUND", "No such preview"));
        if (clock.millis() / 1000 >= p.expiresAt()) {
            throw new Refused("PREVIEW_EXPIRED", "The preview has expired");
        }
        byte[] raw = new byte[16];
        RANDOM.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        try {
            ensureDirs();
            ObjectNode n = JSON.createObjectNode();
            putPending(n, p);
            n.put("tokenHash", sha256(token));
            n.put("mac", mac(grantedParts(p, sha256(token))));
            writeNew(grantedDir.resolve(previewId + ".json"), n);
        } catch (java.nio.file.FileAlreadyExistsException e) {
            throw new Refused("ALREADY_GRANTED", "This preview was already approved");
        } catch (IOException e) {
            throw new Refused("GRANT_FAILED", "Could not record the approval");
        }
        return token;
    }

    // ---- internals ----

    private record Granted(Pending pendingBinding, String tokenHash) {
    }

    private Optional<Granted> readGranted(String id) {
        try {
            Path f = grantedDir.resolve(id + ".json");
            if (!Files.isRegularFile(f) || Files.isSymbolicLink(f)) {
                return Optional.empty();
            }
            ObjectNode n = (ObjectNode) JSON.readTree(Files.readAllBytes(f));
            Pending p = new Pending(n.path("previewId").asText(), n.path("profileId").asText(), n.path("profileLabel").asText(),
                    n.path("actor").asText(), n.path("operationDigest").asText(), n.path("policyVersion").asText(),
                    n.path("fingerprint").asText(), n.path("affectedRows").asInt(), n.path("expiresAt").asLong(),
                    n.path("summary").asText(), n.path("request").asText());
            String tokenHash = n.path("tokenHash").asText("");
            if (!p.previewId().equals(id) || !constantTimeEquals(n.path("mac").asText(""), mac(grantedParts(p, tokenHash)))) {
                return Optional.empty();
            }
            return Optional.of(new Granted(p, tokenHash));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private void revoke(String id) {
        try {
            Files.deleteIfExists(grantedDir.resolve(id + ".json"));
            Files.deleteIfExists(pendingDir.resolve(id + ".json"));
        } catch (IOException ignored) {
            // the failure counter keeps refusing anyway
        }
    }

    private void ensureDirs() throws IOException {
        FilePerms.ensureSecureDir(pendingDir.getParent());
        FilePerms.ensureSecureDir(pendingDir);
        FilePerms.ensureSecureDir(grantedDir);
        FilePerms.ensureSecureDir(usedDir);
    }

    private static void writeNew(Path file, ObjectNode node) throws IOException {
        // CREATE_NEW: an existing record is never overwritten.
        try (var ch = java.nio.channels.FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            FilePerms.restrictFile(file);
            ch.write(java.nio.ByteBuffer.wrap(JSON.writeValueAsBytes(node)));
            ch.force(true);
        }
    }

    private static void putPending(ObjectNode n, Pending p) {
        n.put("previewId", p.previewId());
        n.put("profileId", p.profileId());
        n.put("profileLabel", p.profileLabel());
        n.put("actor", p.actor());
        n.put("operationDigest", p.operationDigest());
        n.put("policyVersion", p.policyVersion());
        n.put("fingerprint", p.fingerprint());
        n.put("affectedRows", p.affectedRows());
        n.put("expiresAt", p.expiresAt());
        n.put("summary", p.summary());
        n.put("request", p.request());
    }

    private static String[] pendingParts(Pending p) {
        return new String[] { "pending", p.previewId(), p.profileId(), p.profileLabel(), p.actor(), p.operationDigest(),
                p.policyVersion(), p.fingerprint(), String.valueOf(p.affectedRows()), String.valueOf(p.expiresAt()),
                p.summary(), p.request() };
    }

    private static String[] grantedParts(Pending p, String tokenHash) {
        String[] base = pendingParts(p);
        base[0] = "granted";
        String[] out = java.util.Arrays.copyOf(base, base.length + 1);
        out[base.length] = tokenHash;
        return out;
    }

    private String mac(String... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (String s : parts) {
                // length-prefixed so field boundaries cannot be shifted
                mac.update((s.length() + ":" + s + "\n").getBytes(StandardCharsets.UTF_8));
            }
            return Base64.getEncoder().encodeToString(mac.doFinal());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean validId(String id) {
        return id != null && ID.matcher(id).matches();
    }

    private static void checkId(String id) {
        if (!validId(id)) {
            throw new IllegalArgumentException("Invalid preview id");
        }
    }
}
