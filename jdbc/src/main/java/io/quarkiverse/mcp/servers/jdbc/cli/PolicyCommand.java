package io.quarkiverse.mcp.servers.jdbc.cli;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.PolicyException;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyMetadataCheck;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.profile.LabelRules;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "policy", description = "Validate, inspect and activate per-profile policy files", subcommands = {
        PolicyCommand.Validate.class, PolicyCommand.Show.class, PolicyCommand.Reload.class })
public class PolicyCommand implements Runnable {

    @Override
    public void run() {
        new picocli.CommandLine(this).usage(System.err);
    }

    abstract static class Base implements Callable<Integer> {
        @Mixin
        CommonOptions common;

        @Parameters(arity = "0..1", paramLabel = "LABEL", description = "Profile label; omit with --all")
        String label;

        @Option(names = "--all", description = "Apply to every profile")
        boolean all;

        @Option(names = "--offline", description = "Skip the check against the live database (the YAML is still fully validated)")
        boolean offline;

        abstract boolean perProfile(GatewayContext ctx, DbProfile p);

        @Override
        public Integer call() throws Exception {
            if (all == (label != null)) {
                System.err.println("Give either a LABEL or --all.");
                return 2;
            }
            GatewayContext ctx = GatewayContext.open(common);
            ctx.profiles.load();
            List<DbProfile> targets = new ArrayList<>();
            if (all) {
                targets.addAll(ctx.profiles.list());
            } else {
                targets.add(ctx.registry.byLabel(label)
                        .orElseThrow(() -> new IllegalArgumentException("No such profile: " + label)));
            }
            boolean ok = true;
            for (DbProfile p : targets) {
                ok &= perProfile(ctx, p);
            }
            return ok ? 0 : 1;
        }

        /** Full YAML validation plus, unless {@code --offline}, a comparison with the live database. */
        PermissionPolicy validate(GatewayContext ctx, DbProfile p) throws Exception {
            PermissionPolicy policy = ctx.policies.validate(p);
            if (!offline && policy.write() != null) {
                List<String> problems;
                try {
                    problems = PolicyMetadataCheck.check(policy, p, ctx.connections);
                } catch (Exception e) {
                    throw new PolicyException("Cannot check the policy against the database (" + e.getClass().getSimpleName()
                            + "). Fix the connection, or use --offline to skip this check.");
                }
                if (!problems.isEmpty()) {
                    throw new PolicyException(String.join("; ", problems));
                }
            }
            return policy;
        }
    }

    @Command(name = "validate", description = "Check a policy file without activating it")
    static class Validate extends Base {
        @Override
        boolean perProfile(GatewayContext ctx, DbProfile p) {
            try {
                PermissionPolicy policy = validate(ctx, p);
                System.out.println("OK      " + p.label() + "  " + policy.access() + "  " + policy.hash());
                return true;
            } catch (Exception e) {
                System.out.println("INVALID " + p.label() + "  " + e.getMessage());
                return false;
            }
        }
    }

    @Command(name = "show", description = "Show the effective policy of a profile")
    static class Show extends Base {
        @Override
        boolean perProfile(GatewayContext ctx, DbProfile p) {
            var snap = ctx.policies.current(p);
            System.out.println(p.label() + ": " + snap.state() + (snap.active() ? "" : " - " + snap.reason()));
            try {
                Path file = LabelRules.policyPath(ctx.paths.permissionsDir(), p.label());
                if (Files.isRegularFile(file)) {
                    System.out.println(Files.readString(file));
                }
            } catch (Exception e) {
                System.out.println("(policy file cannot be shown)");
            }
            return true;
        }
    }

    @Command(name = "reload", description = "Validate a policy and make it the active one")
    static class Reload extends Base {
        @Override
        boolean perProfile(GatewayContext ctx, DbProfile p) {
            try {
                validate(ctx, p); // everything, every time
                PermissionPolicy policy = ctx.policies.activate(p);
                System.out.println("RELOADED " + p.label() + "  " + policy.access() + "  " + policy.hash());
                return true;
            } catch (Exception e) {
                System.out.println("NOT RELOADED " + p.label() + "  " + e.getMessage()
                        + "  (if the file was edited, this profile refuses all operations until a reload succeeds)");
                return false;
            }
        }
    }
}
