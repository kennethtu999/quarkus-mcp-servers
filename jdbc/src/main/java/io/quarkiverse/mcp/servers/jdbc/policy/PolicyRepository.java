package io.quarkiverse.mcp.servers.jdbc.policy;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.Loaded;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.PolicyException;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.profile.LabelRules;
import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

/**
 * Decides, on every call, which policy applies to a profile - or that none does.
 * <p>
 * A policy is {@link State#ACTIVE} only if (a) the signed {@link PolicyManifest} says an administrator activated exactly
 * the hash of the file currently on disk, and (b) that file still validates against its profile. Editing the YAML does
 * not take effect by itself: the profile becomes {@link State#POLICY_STALE} and refuses all operations until
 * {@code policy reload} records the new hash. The previous policy is never used as a fallback, and no state degrades to
 * a more permissive mode.
 * <p>
 * The manifest is re-read on every call, so a {@code policy reload} run in another process (the CLI) is picked up by a
 * running stdio server without a restart.
 */
public final class PolicyRepository {

    public enum State {
        ACTIVE,
        /** File missing, unreadable, invalid, or not matching its profile. */
        POLICY_INVALID,
        /** File differs from what was activated (or nothing was activated); needs {@code policy reload}. */
        POLICY_STALE
    }

    /** Immutable result of a lookup. {@code policy} is non-null only when {@code state} is ACTIVE. */
    public record Snapshot(State state, PermissionPolicy policy, String reason) {
        public boolean active() {
            return state == State.ACTIVE;
        }
    }

    private final Path permissionsDir;
    private final PolicyManifest manifest;

    public PolicyRepository(Path permissionsDir, PolicyManifest manifest) {
        this.permissionsDir = permissionsDir;
        this.manifest = manifest;
    }

    /** Validates the file of a profile without activating it. Used by {@code policy validate}. */
    public PermissionPolicy validate(DbProfile profile) throws PolicyException {
        Path file;
        try {
            file = LabelRules.policyPath(permissionsDir, profile.label());
            FilePerms.verifyDir(permissionsDir);
        } catch (IOException e) {
            throw new PolicyException(e.getMessage());
        }
        verifyFilePermissions(file);
        Loaded loaded = PolicyLoader.load(file);
        return PolicyValidator.validate(loaded, profile.label(), profile.profileId());
    }

    /**
     * Validates and, only if valid, records the hash as activated. On any failure the manifest is untouched, so the
     * previously activated hash stays in force (and will itself go stale if the file has changed).
     */
    public PermissionPolicy activate(DbProfile profile) throws PolicyException {
        PermissionPolicy policy = validate(profile);
        try {
            manifest.put(profile.profileId(), policy.hash());
        } catch (IOException e) {
            throw new PolicyException("Cannot record the activated policy");
        }
        return policy;
    }

    public void forget(String profileId) {
        try {
            manifest.remove(profileId);
        } catch (IOException ignored) {
            // an entry that cannot be removed only ever matches a policy file that no longer exists
        }
    }

    /** The policy to apply right now; reads the file and the manifest fresh each time. */
    public Snapshot current(DbProfile profile) {
        PermissionPolicy onDisk;
        try {
            onDisk = validate(profile);
        } catch (PolicyException e) {
            return new Snapshot(State.POLICY_INVALID, null, e.getMessage());
        }
        Map<String, String> activated = manifest.read();
        String activeHash = activated.get(profile.profileId());
        if (activeHash == null) {
            return new Snapshot(State.POLICY_STALE, null, "Policy has not been activated; run 'policy reload'");
        }
        if (!activeHash.equals(onDisk.hash())) {
            return new Snapshot(State.POLICY_STALE, null,
                    "Policy file changed since it was activated; run 'policy validate' then 'policy reload'");
        }
        return new Snapshot(State.ACTIVE, onDisk, "active");
    }

    private static void verifyFilePermissions(Path file) throws PolicyException {
        try {
            FilePerms.verifyFile(file);
        } catch (FilePerms.InsecurePermissionsException e) {
            throw new PolicyException(e.getMessage());
        } catch (IOException e) {
            throw new PolicyException("Policy file cannot be read");
        }
    }
}
