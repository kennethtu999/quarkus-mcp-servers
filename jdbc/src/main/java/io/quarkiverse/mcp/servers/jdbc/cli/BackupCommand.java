package io.quarkiverse.mcp.servers.jdbc.cli;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.secret.EncryptedProfileStore;
import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * Backup and restore of {@code profiles.enc} and the policy files.
 * <p>
 * A backup is only as useful as the key that opens it: {@code profiles.enc} is encrypted with the master key, and a copy of
 * the file on another machine cannot be read without it. Back the master key up separately (and elsewhere), and run
 * {@code restore --dry-run} on the target to prove the pair works before you need it.
 */
@Command(name = "backup", description = "Back up and restore profiles.enc and the policy files", subcommands = {
        BackupCommand.Create.class, BackupCommand.Restore.class })
public class BackupCommand implements Runnable {

    // `backup` is only a group. `create` and `restore` are siblings: if `backup` itself took the directory argument, picocli
    // would read `backup restore <dir>` as "back up into a directory called restore".
    @Override
    public void run() {
        new picocli.CommandLine(this).usage(System.err);
    }

    @Command(name = "create", description = "Copy profiles.enc and the policy files into a directory")
    static class Create implements Callable<Integer> {
        @Mixin
        CommonOptions common;

        @Parameters(index = "0", paramLabel = "TARGET_DIR", description = "Directory to write the backup to (created, owner-only)")
        Path target;

        @Override
        public Integer call() throws Exception {
            GatewayContext ctx = GatewayContext.open(common);
            ctx.profiles.load(); // proves the store opens with the current key before it is copied
            FilePerms.ensureSecureDir(target);
            Files.copy(ctx.paths.profilesFile(), target.resolve("profiles.enc"), StandardCopyOption.REPLACE_EXISTING);
            FilePerms.restrictFile(target.resolve("profiles.enc"));
            int n = copyPolicies(ctx.paths.permissionsDir(), target.resolve("permissions"));
            System.err.println("Backed up profiles.enc and " + n + " policy file(s) to " + target);
            System.err
                    .println("The master key is NOT included. Back it up separately; without it this backup cannot be opened.");
            return 0;
        }
    }

    static int copyPolicies(Path from, Path to) throws IOException {
        if (!Files.isDirectory(from)) {
            return 0;
        }
        FilePerms.ensureSecureDir(to);
        int n = 0;
        try (Stream<Path> files = Files.list(from)) {
            for (Path f : (Iterable<Path>) files
                    .filter(p -> p.getFileName().toString().matches("permissions_[A-Za-z0-9_-]+\\.yaml"))::iterator) {
                if (Files.isRegularFile(f) && !Files.isSymbolicLink(f)) {
                    Files.copy(f, to.resolve(f.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                    FilePerms.restrictFile(to.resolve(f.getFileName()));
                    n++;
                }
            }
        }
        return n;
    }

    @Command(name = "restore", description = "Restore a backup into an EMPTY configuration directory")
    static class Restore implements Callable<Integer> {
        @Mixin
        CommonOptions common;

        @Parameters(index = "0", paramLabel = "BACKUP_DIR")
        Path source;

        @Option(names = "--dry-run", description = "Only check that the backup opens with the current master key")
        boolean dryRun;

        @Override
        public Integer call() throws Exception {
            Path backupStore = source.resolve("profiles.enc");
            if (!Files.isRegularFile(backupStore)) {
                System.err.println("No profiles.enc in " + source);
                return 1;
            }
            // Open the backup with the current key BEFORE touching anything.
            GatewayContext probe = GatewayContext.open(common);
            List<DbProfile> profiles = new EncryptedProfileStore(source, probe.keys).read();
            System.err.println("Backup opens with the current master key: " + profiles.size() + " profile(s).");
            if (dryRun) {
                return 0;
            }
            if (Files.exists(probe.paths.profilesFile())) {
                System.err
                        .println("Refusing to overwrite an existing profiles.enc. Move it away first (it is your only copy).");
                return 1;
            }
            Files.copy(backupStore, probe.paths.profilesFile());
            FilePerms.restrictFile(probe.paths.profilesFile());
            int n = copyPolicies(source.resolve("permissions"), probe.paths.permissionsDir());
            GatewayContext after = GatewayContext.open(common);
            after.profiles.load();
            int ok = 0;
            for (DbProfile p : after.profiles.list()) {
                try {
                    after.policies.activate(p);
                    ok++;
                } catch (Exception e) {
                    System.err.println("  " + p.label() + ": policy NOT activated (" + e.getMessage() + ")");
                }
            }
            System.err.println("Restored " + after.profiles.list().size() + " profile(s) and " + n + " policy file(s); "
                    + ok + " policy(ies) activated.");
            return ok == after.profiles.list().size() ? 0 : 1;
        }
    }
}
