package io.quarkiverse.mcp.servers.jdbc.cli;

import java.io.IOException;
import java.util.concurrent.Callable;

import io.quarkiverse.mcp.servers.jdbc.app.GatewayApp;
import io.quarkiverse.mcp.servers.jdbc.app.GatewayRuntime;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyRepository;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore.StoreException;
import io.quarkus.runtime.Quarkus;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/**
 * Starts the stdio MCP server.
 * <p>
 * Everything that can fail is done <em>before</em> Quarkus starts, so a failure never leaves a half-initialised server
 * answering tool calls, and never touches {@code profiles.enc}: if the master key is missing or the file does not decrypt,
 * the process exits with an error and nothing is rewritten (plan item A18).
 * <p>
 * stdout carries the MCP protocol, so every message here goes to stderr.
 */
@Command(name = "start", description = "Start the MCP server on stdio")
public class StartCommand implements Callable<Integer> {

    @Mixin
    CommonOptions common;

    @Option(names = "--mode", defaultValue = "auto", description = "auto (default): tools follow allowed profile policies; read/write: explicit restricted tool modes.")
    String mode;

    @Option(names = "--profiles", description = "Restrict this MCP process to these profile labels (comma separated); omitted means all profiles.")
    String profiles;

    @Override
    public Integer call() {
        try {
            GatewayRuntime.mode(mode.toLowerCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException invalid) {
            System.err.println(invalid.getMessage());
            return 2;
        }
        GatewayContext ctx;
        try {
            ctx = GatewayContext.open(common);
            ctx.profiles.load();
        } catch (StoreException | IOException e) {
            System.err.println("Cannot start: " + e.getMessage());
            System.err.println("No file was modified. Restore the master key or the backup in backups/, then retry.");
            return 3;
        } catch (IllegalArgumentException e) {
            System.err.println("Cannot start: " + e.getMessage());
            return 2;
        }

        java.util.Set<String> allowed = new java.util.LinkedHashSet<>();
        if (profiles != null) {
            try {
                for (String label : profiles.split(",", -1)) {
                    String normalized = io.quarkiverse.mcp.servers.jdbc.profile.LabelRules.normalize(label.strip());
                    if (ctx.registry.byLabel(normalized).isEmpty()) {
                        throw new IllegalArgumentException("Unknown profile in --profiles: " + normalized);
                    }
                    allowed.add(normalized);
                }
            } catch (IllegalArgumentException invalid) {
                System.err.println(invalid.getMessage());
                return 2;
            }
        }
        GatewayRuntime.profiles(allowed);

        // A bad policy disables only its own profile (every call is refused); it does not stop the server.
        for (DbProfile p : ctx.profiles.list()) {
            if (!GatewayRuntime.allowsProfile(p.label())) {
                continue;
            }
            PolicyRepository.Snapshot snap = ctx.policies.current(p);
            if (!snap.active()) {
                System.err.println("Profile " + p.label() + ": " + snap.state() + " - " + snap.reason());
            }
        }
        System.err.println("ai-db-mcp: " + ctx.profiles.list().size() + " profile(s) loaded from " + ctx.paths.root());

        ctx.sync.markCurrent();
        GatewayRuntime.set(ctx);
        Quarkus.run(GatewayApp.class);
        return 0;
    }
}
