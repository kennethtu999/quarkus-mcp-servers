package io.quarkiverse.mcp.servers.jdbc.cli;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;

import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "profile", description = "Manage database profiles", subcommands = {
        ProfileCommand.Add.class, ProfileCommand.ListCmd.class, ProfileCommand.Show.class, ProfileCommand.Test.class,
        ProfileCommand.RotatePassword.class, ProfileCommand.Rename.class, ProfileCommand.Enable.class,
        ProfileCommand.Disable.class, ProfileCommand.Remove.class })
public class ProfileCommand implements Runnable {

    @Override
    public void run() {
        new picocli.CommandLine(this).usage(System.err);
    }

    static void promptAndAdd(GatewayContext ctx, BufferedReader in, boolean passwordStdin, boolean skipTest) throws Exception {
        String label = PasswordPrompt.line("DB label (e.g. DB2-DEV)", null, passwordStdin, in);
        DbType type = DbType.parse(PasswordPrompt.line("DB type (DB2_LUW, POSTGRESQL, ORACLE)", null, passwordStdin, in));
        String url = PasswordPrompt.line("JDBC URL", null, passwordStdin, in);
        String user = PasswordPrompt.line("Username", null, passwordStdin, in);
        String schema = PasswordPrompt.line("Default schema (optional)", "", passwordStdin, in);
        char[] pw = PasswordPrompt.password("Password", passwordStdin, in);
        try {
            DbProfile p = ctx.profiles.add(label, type, url, user, pw, schema.isEmpty() ? null : schema, skipTest);
            System.err.println("Added " + p.label() + " (READ_ONLY). Edit permissions/permissions_" + p.label()
                    + ".yaml, then run: ai-db-mcp policy validate " + p.label() + " && ai-db-mcp policy reload " + p.label());
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
    }

    static void printSummary(GatewayContext ctx) {
        System.out.printf("%-24s %-12s %-9s%n", "LABEL", "TYPE", "ENABLED");
        for (DbProfile p : ctx.profiles.list()) {
            System.out.printf("%-24s %-12s %-9s%n", p.label(), p.dbType(), p.enabled());
        }
    }

    /** Base for subcommands that need an opened configuration. */
    abstract static class Base implements Callable<Integer> {
        @Mixin
        CommonOptions common;

        abstract int run(GatewayContext ctx) throws Exception;

        @Override
        public Integer call() throws Exception {
            GatewayContext ctx = GatewayContext.open(common);
            ctx.profiles.load();
            return run(ctx);
        }
    }

    @Command(name = "add", description = "Add a database profile")
    static class Add extends Base {
        @Option(names = "--password-stdin", description = "Read all answers, including the password, from standard input (one per line).")
        boolean passwordStdin;

        @Option(names = "--skip-connection-test")
        boolean skipTest;

        @Override
        int run(GatewayContext ctx) throws Exception {
            promptAndAdd(ctx, new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)), passwordStdin,
                    skipTest);
            return 0;
        }
    }

    @Command(name = "list", description = "List profiles (no secrets are shown)")
    static class ListCmd extends Base {
        @Override
        int run(GatewayContext ctx) {
            printSummary(ctx);
            return 0;
        }
    }

    @Command(name = "show", description = "Show one profile (no URL, username or password)")
    static class Show extends Base {
        @Parameters(index = "0", paramLabel = "LABEL")
        String label;

        @Override
        int run(GatewayContext ctx) {
            DbProfile p = ctx.registry.byLabel(label)
                    .orElseThrow(() -> new IllegalArgumentException("No such profile: " + label));
            System.out.println("label:     " + p.label());
            System.out.println("profileId: " + p.profileId());
            System.out.println("type:      " + p.dbType());
            System.out.println("schema:    " + (p.defaultSchema() == null ? "-" : p.defaultSchema()));
            System.out.println("enabled:   " + p.enabled());
            System.out.println("policy:    " + ctx.permissions.snapshot(p).state());
            return 0;
        }
    }

    @Command(name = "test", description = "Test that a profile can connect")
    static class Test extends Base {
        @Parameters(index = "0", paramLabel = "LABEL")
        String label;

        @Override
        int run(GatewayContext ctx) {
            try {
                ctx.profiles.test(label);
                System.out.println("OK: connected to " + label);
                return 0;
            } catch (java.sql.SQLException | RuntimeException e) {
                System.err.println("FAILED: " + e.getClass().getSimpleName());
                return 1;
            }
        }
    }

    @Command(name = "rotate-password", description = "Replace the stored password of a profile")
    static class RotatePassword extends Base {
        @Parameters(index = "0", paramLabel = "LABEL")
        String label;

        @Option(names = "--password-stdin")
        boolean passwordStdin;

        @Option(names = "--skip-connection-test")
        boolean skipTest;

        @Override
        int run(GatewayContext ctx) throws Exception {
            char[] pw = PasswordPrompt.password("New password", passwordStdin,
                    new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)));
            try {
                ctx.profiles.rotatePassword(label, pw, skipTest);
            } finally {
                java.util.Arrays.fill(pw, '\0');
            }
            System.err.println("Password for " + label + " was rotated.");
            return 0;
        }
    }

    @Command(name = "rename", description = "Change a profile's label, carrying its policy file along")
    static class Rename extends Base {
        @Parameters(index = "0", paramLabel = "OLD_LABEL")
        String oldLabel;

        @Parameters(index = "1", paramLabel = "NEW_LABEL")
        String newLabel;

        @Override
        int run(GatewayContext ctx) throws Exception {
            ctx.profiles.rename(oldLabel, newLabel);
            System.err.println("Renamed " + oldLabel + " to " + newLabel.toUpperCase(java.util.Locale.ROOT));
            return 0;
        }
    }

    @Command(name = "enable", description = "Enable a profile")
    static class Enable extends Base {
        @Parameters(index = "0", paramLabel = "LABEL")
        String label;

        @Override
        int run(GatewayContext ctx) throws Exception {
            ctx.profiles.setEnabled(label, true);
            return 0;
        }
    }

    @Command(name = "disable", description = "Disable a profile (all operations are refused)")
    static class Disable extends Base {
        @Parameters(index = "0", paramLabel = "LABEL")
        String label;

        @Override
        int run(GatewayContext ctx) throws Exception {
            ctx.profiles.setEnabled(label, false);
            return 0;
        }
    }

    @Command(name = "remove", description = "Remove a profile; its policy file is kept")
    static class Remove extends Base {
        @Parameters(index = "0", paramLabel = "LABEL")
        String label;

        @Override
        int run(GatewayContext ctx) throws Exception {
            ctx.profiles.remove(label);
            return 0;
        }
    }
}
