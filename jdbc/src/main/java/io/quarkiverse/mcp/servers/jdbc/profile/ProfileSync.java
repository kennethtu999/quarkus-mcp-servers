package io.quarkiverse.mcp.servers.jdbc.profile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore.StoreException;

/**
 * Keeps a running server consistent with {@code profiles.enc}, which administrative commands rewrite from other processes
 * ({@code profile disable}, {@code rotate-password}, {@code rename}, {@code remove}, ...).
 * <p>
 * Before every tool call {@link #refresh()} compares a cheap fingerprint of the file; only when it changed is the file
 * decrypted again. Connection pools of profiles whose connection details, credentials, label or enabled flag changed - and of
 * removed profiles - are closed, so the next call reconnects with the new settings.
 * <p>
 * <strong>Fail closed:</strong> if the file cannot be re-read (key gone, file damaged), {@code refresh} reports a failure and
 * the registry is emptied rather than left on the last good copy. Silently continuing with a profile an administrator just
 * disabled or whose password was just rotated is exactly what this class exists to prevent. The state recovers on the first
 * call after the file is readable again.
 */
public final class ProfileSync {

    private final Path file;
    private final EncryptedProfileStore store;
    private final ProfileRegistry registry;
    private final ConnectionManager connections;
    private String fingerprint;
    private boolean healthy = true;
    private String failure;

    public ProfileSync(Path file, EncryptedProfileStore store, ProfileRegistry registry, ConnectionManager connections) {
        this.file = file;
        this.store = store;
        this.registry = registry;
        this.connections = connections;
    }

    /** Records the state the server started with, so that only later changes trigger a reload. */
    public synchronized void markCurrent() {
        this.fingerprint = fingerprintOrNull();
        this.healthy = true;
        this.failure = null;
    }

    /**
     * Applies any change made since the last call.
     *
     * @return {@code null} if the registry is current, otherwise a short reason why profiles are unavailable
     */
    public synchronized String refresh() {
        String now = fingerprintOrNull();
        if (healthy && Objects.equals(now, fingerprint)) {
            return null;
        }
        if (now == null) {
            return fail("profiles.enc is missing");
        }
        try {
            List<DbProfile> next = store.read();
            apply(next);
            fingerprint = now;
            healthy = true;
            failure = null;
            return null;
        } catch (StoreException e) {
            return fail(e.getMessage());
        }
    }

    private String fail(String reason) {
        for (DbProfile p : registry.all()) {
            connections.invalidate(p.profileId());
        }
        registry.replaceAll(List.of());
        healthy = false;
        failure = reason;
        fingerprint = null;
        return reason;
    }

    private void apply(List<DbProfile> next) {
        Map<String, DbProfile> old = new HashMap<>();
        registry.all().forEach(p -> old.put(p.profileId(), p));
        Map<String, DbProfile> fresh = new HashMap<>();
        next.forEach(p -> fresh.put(p.profileId(), p));

        for (DbProfile o : old.values()) {
            DbProfile n = fresh.get(o.profileId());
            if (n == null || changed(o, n)) {
                connections.invalidate(o.profileId());
            }
        }
        registry.replaceAll(next);
    }

    /** Anything that affects how or whether a connection is made, or which policy applies. */
    static boolean changed(DbProfile a, DbProfile b) {
        return a.enabled() != b.enabled() || !a.label().equals(b.label()) || !a.jdbcUrl().equals(b.jdbcUrl())
                || !a.username().equals(b.username()) || !java.util.Arrays.equals(a.passwordCopy(), b.passwordCopy())
                || a.dbType() != b.dbType() || !Objects.equals(a.defaultSchema(), b.defaultSchema());
    }

    public synchronized boolean healthy() {
        return healthy;
    }

    public synchronized String failure() {
        return failure;
    }

    /** Device+inode (changes on every atomic replace), size and modification time; falls back to a content hash. */
    private String fingerprintOrNull() {
        try {
            BasicFileAttributes a = Files.readAttributes(file, BasicFileAttributes.class);
            Object key = a.fileKey();
            if (key != null) {
                return key + "|" + a.size() + "|" + a.lastModifiedTime().toMillis();
            }
            return "sha:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
        } catch (IOException | NoSuchAlgorithmException e) {
            return null;
        }
    }
}
