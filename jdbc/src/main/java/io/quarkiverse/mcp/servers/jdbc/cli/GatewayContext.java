package io.quarkiverse.mcp.servers.jdbc.cli;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.function.Function;

import io.quarkiverse.mcp.servers.jdbc.database.ConnectionManager;
import io.quarkiverse.mcp.servers.jdbc.database.DriverLoader;
import io.quarkiverse.mcp.servers.jdbc.database.JdbcUrlGuard;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionService;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyManifest;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyRepository;
import io.quarkiverse.mcp.servers.jdbc.profile.ConfigPaths;
import io.quarkiverse.mcp.servers.jdbc.profile.ProfileManager;
import io.quarkiverse.mcp.servers.jdbc.profile.ProfileRegistry;
import io.quarkiverse.mcp.servers.jdbc.profile.ProfileValidator;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore;
import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;
import io.quarkiverse.mcp.servers.jdbc.secret.Hkdf;
import io.quarkiverse.mcp.servers.jdbc.secret.KeyFileMasterKeyProvider;
import io.quarkiverse.mcp.servers.jdbc.secret.KeyringMasterKeyProvider;
import io.quarkiverse.mcp.servers.jdbc.secret.MasterKeyProvider;

/**
 * Wires every service for one configuration directory. Built identically by the admin CLI and by {@code start}, so both
 * see the same files, keys and rules.
 */
public final class GatewayContext {

    public static final String KEY_ID = "ai-db-mcp/master-key/v1";

    public final ConfigPaths paths;
    public final MasterKeyProvider keys;
    public final EncryptedProfileStore store;
    public final ProfileRegistry registry = new ProfileRegistry();
    public final ConnectionManager connections;
    public final PolicyRepository policies;
    public final PermissionService permissions;
    public final ProfileManager profiles;
    public final io.quarkiverse.mcp.servers.jdbc.change.ApprovalService approvals;

    private GatewayContext(ConfigPaths paths, MasterKeyProvider keys, boolean requireTls, boolean createKey,
            ConnectionManager connectionsOverride) throws IOException {
        this.paths = paths;
        this.keys = keys;
        this.store = new EncryptedProfileStore(paths.root(), keys);

        byte[] master = null;
        byte[] manifestKey;
        byte[] approvalKey;
        try {
            master = createKey ? keys.loadOrCreate() : keys.load();
            manifestKey = Hkdf.derive(master, "ai-db-mcp/policy-manifest", 32);
            approvalKey = Hkdf.derive(master, "ai-db-mcp/approvals", 32);
        } catch (MasterKeyProvider.KeyUnavailableException e) {
            throw new IOException("Master key is not available: " + e.getMessage(), e);
        } finally {
            if (master != null) {
                Arrays.fill(master, (byte) 0);
            }
        }

        this.connections = connectionsOverride != null ? connectionsOverride
                : new ConnectionManager(new DriverLoader(paths.driversDir(),
                        new io.quarkiverse.mcp.servers.jdbc.profile.Settings(paths.settingsFile()).pinnedDrivers()));
        PolicyManifest manifest = new PolicyManifest(paths.root().resolve("policy-manifest.json"), manifestKey);
        Arrays.fill(manifestKey, (byte) 0);
        this.approvals = new io.quarkiverse.mcp.servers.jdbc.change.ApprovalService(paths.approvalsDir(), approvalKey,
                java.time.Clock.systemUTC());
        Arrays.fill(approvalKey, (byte) 0);
        this.policies = new PolicyRepository(paths.permissionsDir(), manifest);
        this.permissions = new PermissionService(policies);
        this.profiles = new ProfileManager(paths, store, registry,
                new ProfileValidator(new JdbcUrlGuard(java.util.Set.of(), requireTls)),
                connections, policies);
    }

    /**
     * Opens an existing configuration. The master key must already exist; this never creates one, so a lost key can never
     * turn into a silently different empty store.
     */
    public static GatewayContext open(RootOptions opts) throws IOException {
        ConfigPaths paths = opts.paths();
        FilePerms.verifyDir(paths.root());
        return new GatewayContext(paths, opts.keyProvider(paths), opts.requireTls(), false, null);
    }

    /** For {@code init}: creates the directory, and the master key if none exists yet. */
    public static GatewayContext create(RootOptions opts) throws IOException {
        ConfigPaths paths = opts.paths();
        FilePerms.ensureSecureDir(paths.root());
        return new GatewayContext(paths, opts.keyProvider(paths), opts.requireTls(), true, null);
    }

    /**
     * Wiring hook for tests: opens a configuration with a caller supplied {@link ConnectionManager}, so the real policy,
     * store, audit and permission code can run against an in-memory database. Production code never calls this.
     */
    public static GatewayContext forTesting(ConfigPaths paths, MasterKeyProvider keys, ConnectionManager connections)
            throws IOException {
        FilePerms.ensureSecureDir(paths.root());
        return new GatewayContext(paths, keys, true, true, connections);
    }

    /** Options shared by every command. */
    public interface RootOptions {
        ConfigPaths paths();

        /** {@code null} selects the OS key store; otherwise a key file path. */
        Path keyFile();

        boolean requireTls();

        default MasterKeyProvider keyProvider(ConfigPaths paths) {
            return keyFile() == null ? new KeyringMasterKeyProvider(paths.root(), KEY_ID)
                    : new KeyFileMasterKeyProvider(keyFile(), paths.root(), KEY_ID);
        }
    }

    public static ConfigPaths resolvePaths(String cliValue) {
        Function<String, String> env = System::getenv;
        return ConfigPaths.resolve(cliValue, env, System.getProperty("os.name", ""), System.getProperty("user.home", "."));
    }
}
