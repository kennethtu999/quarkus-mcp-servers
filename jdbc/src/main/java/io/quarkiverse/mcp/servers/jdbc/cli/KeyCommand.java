package io.quarkiverse.mcp.servers.jdbc.cli;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.Callable;

import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;

@Command(name = "key", description = "Master key maintenance", subcommands = { KeyCommand.Rotate.class })
public class KeyCommand implements Runnable {

    @Override
    public void run() {
        new picocli.CommandLine(this).usage(System.err);
    }

    @Command(name = "rotate", description = "Generate a new master key and re-encrypt profiles.enc. Policies must be reloaded afterwards.")
    static class Rotate implements Callable<Integer> {
        @Mixin
        CommonOptions common;

        @Override
        public Integer call() throws Exception {
            GatewayContext ctx = GatewayContext.open(common);
            ctx.profiles.load();
            byte[] fresh = new byte[32];
            new SecureRandom().nextBytes(fresh);
            try {
                ctx.store.rotateKey(fresh);
            } finally {
                Arrays.fill(fresh, (byte) 0);
            }
            System.err.println("Master key rotated and profiles.enc re-encrypted.");
            System.err.println("The policy manifest and all pending approvals were signed with the old key, so every profile");
            System.err.println("is now POLICY_STALE until you run: ai-db-mcp policy reload --all");

            // Reopen with the new key and reload the policies right away, so the gateway is usable again.
            GatewayContext after = GatewayContext.open(common);
            after.profiles.load();
            int ok = 0;
            for (DbProfile p : after.profiles.list()) {
                try {
                    after.policies.activate(p);
                    ok++;
                } catch (Exception e) {
                    System.err.println("  " + p.label() + ": policy NOT reloaded (" + e.getMessage() + ")");
                }
            }
            System.err.println("Reloaded " + ok + " of " + after.profiles.list().size() + " policies.");
            System.err.println(
                    "backups/profiles.enc.pre-rotation can only be opened with the OLD key; delete it once you have confirmed the new setup.");
            return ok == after.profiles.list().size() ? 0 : 1;
        }
    }
}
