package io.quarkiverse.mcp.servers.jdbc.profile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyRepository;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore.StoreException;
import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

/**
 * Profile administration used by the CLI: add, edit, rename, rotate the password, enable/disable, remove, test.
 * <p>
 * Every change is validated first, written to the encrypted store, and only then published to the in-memory registry and
 * the connection pools, so a failure at any step leaves the previous state intact. Policy files are created as
 * {@code READ_ONLY}; nothing here can create a policy with write access.
 */
public final class ProfileManager {

    private final ConfigPaths paths;
    private final EncryptedProfileStore store;
    private final ProfileRegistry registry;
    private final ProfileValidator validator;
    private final ConnectionManager connections;
    private final PolicyRepository policies;

    public ProfileManager(ConfigPaths paths, EncryptedProfileStore store, ProfileRegistry registry,
            ProfileValidator validator, ConnectionManager connections, PolicyRepository policies) {
        this.paths = paths;
        this.store = store;
        this.registry = registry;
        this.validator = validator;
        this.connections = connections;
        this.policies = policies;
    }

    /** Loads the encrypted store into the registry. Fails (and changes nothing) if the store cannot be decrypted. */
    public void load() throws StoreException {
        registry.replaceAll(store.exists() ? store.read() : List.of());
    }

    public List<DbProfile> list() {
        return registry.all();
    }

    /**
     * Adds a profile and creates its {@code READ_ONLY} policy file. The connection is tested first unless
     * {@code skipTest} is set.
     *
     * @return the stored profile, including its newly generated immutable id
     */
    public DbProfile add(String label, io.quarkiverse.mcp.servers.jdbc.database.DbType type, String jdbcUrl, String username,
            char[] password, String defaultSchema, boolean skipTest) throws IOException, StoreException, SQLException {
        DbProfile candidate = new DbProfile(UUID.randomUUID().toString(), LabelRules.normalize(label), type, jdbcUrl, username,
                password, defaultSchema, true);
        validator.validate(candidate);
        if (registry.byLabel(candidate.label()).isPresent()) {
            throw new IllegalArgumentException("A profile with label " + candidate.label() + " already exists");
        }
        if (!skipTest) {
            connections.test(candidate);
        }

        Path policyFile = LabelRules.policyPath(paths.permissionsDir(), candidate.label());
        FilePerms.ensureSecureDir(paths.permissionsDir());
        if (Files.exists(policyFile)) {
            // A leftover file may belong to something else; never adopt or overwrite it silently.
            throw new IllegalStateException(
                    "A policy file for " + candidate.label() + " already exists; remove or move it first");
        }

        List<DbProfile> next = new ArrayList<>(registry.all());
        next.add(candidate);
        store.write(next);
        try {
            writeDefaultPolicy(policyFile, candidate);
            policies.activate(candidate);
        } catch (IOException | io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.PolicyException e) {
            // keep store and policy consistent: roll the new profile back out
            store.write(registry.all());
            Files.deleteIfExists(policyFile);
            throw new IOException("Could not create the default policy; profile was not added");
        }
        registry.replaceAll(next);
        return candidate;
    }

    public void rotatePassword(String label, char[] newPassword, boolean skipTest)
            throws StoreException, SQLException {
        DbProfile old = require(label);
        DbProfile updated = old.withPassword(newPassword);
        validator.validate(updated);
        if (!skipTest) {
            connections.test(updated); // the new credentials must work before the old ones are replaced
        }
        replace(old, updated);
        connections.invalidate(old.profileId());
    }

    public void setEnabled(String label, boolean enabled) throws StoreException {
        DbProfile old = require(label);
        replace(old, old.withEnabled(enabled));
        connections.invalidate(old.profileId());
    }

    /**
     * Changes the label. The policy file is copied to its new name (with the {@code profile} field updated) before the
     * store is switched, and the old file is only removed after the new state is durable. On any failure the old label,
     * the old file and the old store contents remain.
     */
    public void rename(String oldLabel, String newLabel) throws IOException, StoreException {
        DbProfile old = require(oldLabel);
        String normalized = LabelRules.normalize(newLabel);
        if (normalized.equals(old.label().toUpperCase(Locale.ROOT))) {
            return;
        }
        if (registry.byLabel(normalized).isPresent()) {
            throw new IllegalArgumentException("A profile with label " + normalized + " already exists");
        }
        Path oldFile = LabelRules.policyPath(paths.permissionsDir(), old.label());
        Path newFile = LabelRules.policyPath(paths.permissionsDir(), normalized);
        if (Files.exists(newFile)) {
            throw new IllegalStateException("A policy file for " + normalized + " already exists; remove or move it first");
        }
        if (!Files.isRegularFile(oldFile)) {
            throw new IllegalStateException("The current policy file is missing; fix it before renaming");
        }

        String content = Files.readString(oldFile, StandardCharsets.UTF_8);
        String rewritten = rewriteProfileField(content, old.label(), normalized);
        writeOwnerOnly(newFile, rewritten);

        DbProfile renamed = old.withLabel(normalized);
        try {
            replace(old, renamed);
        } catch (StoreException e) {
            Files.deleteIfExists(newFile);
            throw e;
        }
        try {
            policies.activate(renamed);
        } catch (io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.PolicyException e) {
            // The copied policy did not validate: put everything back.
            replace(renamed, old);
            Files.deleteIfExists(newFile);
            throw new IOException("The policy file could not be carried over to the new label; rename was undone");
        }
        Files.deleteIfExists(oldFile);
    }

    public void remove(String label) throws StoreException {
        DbProfile old = require(label);
        List<DbProfile> next = new ArrayList<>(registry.all());
        next.removeIf(p -> p.profileId().equals(old.profileId()));
        store.write(next);
        registry.replaceAll(next);
        connections.invalidate(old.profileId());
        policies.forget(old.profileId());
        // The policy file is deliberately kept: deleting an administrator's file is not this command's decision.
    }

    public void test(String label) throws SQLException {
        connections.test(require(label));
    }

    private void replace(DbProfile old, DbProfile updated) throws StoreException {
        List<DbProfile> next = new ArrayList<>();
        for (DbProfile p : registry.all()) {
            next.add(p.profileId().equals(old.profileId()) ? updated : p);
        }
        store.write(next);
        registry.replaceAll(next);
    }

    private DbProfile require(String label) {
        return registry.byLabel(label).orElseThrow(() -> new IllegalArgumentException("No such profile: " + label));
    }

    static String rewriteProfileField(String yaml, String oldLabel, String newLabel) {
        StringBuilder out = new StringBuilder();
        boolean done = false;
        for (String line : yaml.split("(?<=\n)")) {
            if (!done && line.matches("(?i)^profile:\\s*" + java.util.regex.Pattern.quote(oldLabel) + "\\s*(#.*)?\\r?\\n?$")) {
                out.append("profile: ").append(newLabel).append(line.endsWith("\n") ? "\n" : "");
                done = true;
            } else {
                out.append(line);
            }
        }
        if (!done) {
            throw new IllegalStateException("Could not find the 'profile:' line in the policy file");
        }
        return out.toString();
    }

    private void writeDefaultPolicy(Path file, DbProfile profile) throws IOException {
        writeOwnerOnly(file, "version: 1\nprofile: " + profile.label() + "\nprofileId: " + profile.profileId()
                + "\naccess: READ_ONLY\nread:\n  maxRows: 500\n  timeoutSeconds: 30\n");
    }

    private void writeOwnerOnly(Path file, String content) throws IOException {
        Path tmp = Files.createTempFile(file.getParent(), "policy", ".tmp");
        try {
            FilePerms.restrictFile(tmp);
            Files.writeString(tmp, content, StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
