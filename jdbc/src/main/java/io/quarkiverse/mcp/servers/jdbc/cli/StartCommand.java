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

    @Override
    public Integer call() {
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

        // A bad policy disables only its own profile (every call is refused); it does not stop the server.
        for (DbProfile p : ctx.profiles.list()) {
            PolicyRepository.Snapshot snap = ctx.policies.current(p);
            if (!snap.active()) {
                System.err.println("Profile " + p.label() + ": " + snap.state() + " - " + snap.reason());
            }
        }
        System.err.println("ai-db-mcp: " + ctx.profiles.list().size() + " profile(s) loaded from " + ctx.paths.root());

        GatewayRuntime.set(ctx);
        Quarkus.run(GatewayApp.class);
        return 0;
    }
}
