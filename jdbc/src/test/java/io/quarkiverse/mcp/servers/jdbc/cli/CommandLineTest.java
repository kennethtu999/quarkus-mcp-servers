package io.quarkiverse.mcp.servers.jdbc.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.mcp.servers.jdbc.app.GatewayMain;
import picocli.CommandLine;

class CommandLineTest {

    @TempDir
    Path tmp;

    private record Run(int exit, String out, String err) {
    }

    /** Runs the real command line in-process with the given stdin; stdin is not a terminal, like a script or an AI tool. */
    private Run run(String stdin, String... args) {
        PrintStream oldOut = System.out, oldErr = System.err;
        java.io.InputStream oldIn = System.in;
        ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
            System.setIn(new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8)));
            int exit = GatewayMain.commandLine().execute(args);
            return new Run(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(oldOut);
            System.setErr(oldErr);
            System.setIn(oldIn);
        }
    }

    private String[] common(Path cfg, Path key, String... more) {
        java.util.List<String> a = new java.util.ArrayList<>(java.util.List.of(more));
        a.add("--config-dir");
        a.add(cfg.toString());
        a.add("--key-provider");
        a.add("keyfile:" + key);
        return a.toArray(String[]::new);
    }

    private static final String ANSWERS = String.join("\n", "PG-DEV", "POSTGRESQL",
            "jdbc:postgresql://pg.example.internal:5432/db?sslmode=verify-full", "ai_user", "", "CLI-TEST-SENTINEL-pw") + "\n";

    private void init(Path cfg, Path key) {
        Run r = run(ANSWERS, concat(new String[] { "init", "--password-stdin", "--skip-connection-test" }, common(cfg, key)));
        assertThat(r.exit).as(r.err).isZero();
    }

    private static String[] concat(String[] a, String[] b) {
        String[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @Test
    void everyDocumentedCommandIsReachableFromTheRoot() {
        CommandLine root = GatewayMain.commandLine();
        Set<String> top = root.getSubcommands().keySet();
        assertThat(top).contains("init", "profile", "policy", "approve", "key", "backup", "start");
        assertThat(root.getSubcommands().get("profile").getSubcommands().keySet()).containsExactlyInAnyOrder("add", "list",
                "show",
                "test", "rotate-password", "rename", "enable", "disable", "remove");
        assertThat(root.getSubcommands().get("policy").getSubcommands().keySet()).containsExactlyInAnyOrder("validate", "show",
                "reload");
        assertThat(root.getSubcommands().get("key").getSubcommands().keySet()).contains("rotate");
        assertThat(root.getSubcommands().get("backup").getSubcommands().keySet()).containsExactlyInAnyOrder("create",
                "restore");
    }

    @Test
    void everyCommandAtEveryDepthAnswersHelp() {
        for (CommandLine c : collect(GatewayMain.commandLine())) {
            String[] path = c.getCommandSpec().qualifiedName(" ").split(" ");
            String[] args = java.util.Arrays.copyOfRange(path, 1, path.length + 1);
            args[args.length - 1] = "--help";
            Run r = run("", args);
            assertThat(r.exit).as(String.join(" ", args) + ": " + r.err).isZero();
            assertThat(r.out).as(String.join(" ", args)).contains("Usage:");
        }
    }

    @Test
    void noCommandOffersAnOptionThatTakesASecret() {
        Set<String> bad = Set.of("--password", "--pass", "-p", "--secret", "--token", "--key", "--jdbc-url", "--url", "--user");
        collect(GatewayMain.commandLine()).forEach(cmd -> cmd.getCommandSpec().options().forEach(o -> {
            for (String name : o.names()) {
                assertThat(bad).as(cmd.getCommandName() + " " + name).doesNotContain(name);
            }
        }));
    }

    private static java.util.List<CommandLine> collect(CommandLine c) {
        java.util.List<CommandLine> all = new java.util.ArrayList<>();
        all.add(c);
        c.getSubcommands().values().forEach(s -> all.addAll(collect(s)));
        return all;
    }

    @Test
    void approveRefusesToRunWithoutATerminal() {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        init(cfg, key);
        Run r = run("yes\nyes\n", concat(new String[] { "approve", "0".repeat(32) }, common(cfg, key)));
        assertThat(r.exit).isEqualTo(2);
        assertThat(r.err).contains("interactive terminal");
        assertThat(Files.exists(cfg.resolve("approvals").resolve("granted"))).isFalse();
    }

    @Test
    void initCreatesAReadOnlyPolicyAndNoSecretsAreEverPrinted() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        Run r = run(ANSWERS, concat(new String[] { "init", "--password-stdin", "--skip-connection-test" }, common(cfg, key)));
        assertThat(r.exit).isZero();
        assertThat(r.out + r.err).doesNotContain("CLI-TEST-SENTINEL-pw").doesNotContain("pg.example.internal");
        assertThat(Files.readString(cfg.resolve("permissions").resolve("permissions_PG-DEV.yaml")))
                .contains("access: READ_ONLY");

        java.util.Map<String, String[]> inspect = new java.util.LinkedHashMap<>();
        inspect.put("profile list", new String[] { "profile", "list" });
        inspect.put("profile show", new String[] { "profile", "show", "PG-DEV" });
        inspect.put("policy show", new String[] { "policy", "show", "PG-DEV" });
        inspect.put("policy validate", new String[] { "policy", "validate", "PG-DEV", "--offline" });
        inspect.forEach((name, a) -> {
            Run x = run("", concat(a, common(cfg, key)));
            assertThat(x.exit).as(name + ": " + x.err).isZero();
            assertThat(x.out + x.err).as(name).doesNotContain("CLI-TEST-SENTINEL-pw").doesNotContain("pg.example.internal")
                    .doesNotContain("ai_user");
        });
    }

    // ---- restore drill (definition of done) ----

    @Test
    void backupThenRestoreIntoAnEmptyDirectoryBringsEverythingBack() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key"), backup = tmp.resolve("bak");
        init(cfg, key);
        assertThat(run("", concat(new String[] { "backup", "create", backup.toString() }, common(cfg, key))).exit).isZero();
        assertThat(backup.resolve("profiles.enc")).exists();
        assertThat(backup.resolve("permissions").resolve("permissions_PG-DEV.yaml")).exists();

        // the machine is lost: new empty config directory, same master key
        Path fresh = tmp.resolve("fresh");
        Files.createDirectories(fresh);
        Files.setPosixFilePermissions(fresh, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        Run r = run("", concat(new String[] { "backup", "restore", backup.toString() }, common(fresh, key)));
        assertThat(r.exit).as(r.err).isZero();
        assertThat(r.err).contains("1 profile(s)").contains("1 policy(ies) activated");

        Run list = run("", concat(new String[] { "policy", "show", "PG-DEV" }, common(fresh, key)));
        assertThat(list.out).contains("PG-DEV: ACTIVE");
    }

    @Test
    void restoreNeedsTheRightKeyAndNeverOverwritesAnExistingStore() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key"), backup = tmp.resolve("bak");
        init(cfg, key);
        run("", concat(new String[] { "backup", "create", backup.toString() }, common(cfg, key)));

        // a different master key cannot open the backup, and nothing is written
        Path otherCfg = tmp.resolve("other"), otherKey = tmp.resolve("k2").resolve("master.key");
        init(otherCfg, otherKey);
        byte[] before = Files.readAllBytes(otherCfg.resolve("profiles.enc"));
        Run wrong = run("", concat(new String[] { "backup", "restore", backup.toString() }, common(otherCfg, otherKey)));
        assertThat(wrong.exit).isNotZero();
        assertThat(Files.readAllBytes(otherCfg.resolve("profiles.enc"))).isEqualTo(before);

        // even with the right key, an existing profiles.enc is never overwritten
        byte[] existing = Files.readAllBytes(cfg.resolve("profiles.enc"));
        Run again = run("", concat(new String[] { "backup", "restore", backup.toString() }, common(cfg, key)));
        assertThat(again.exit).isNotZero();
        assertThat(again.err).contains("Refusing to overwrite");
        assertThat(Files.readAllBytes(cfg.resolve("profiles.enc"))).isEqualTo(existing);

        // dry run only checks
        assertThat(run("", concat(new String[] { "backup", "restore", backup.toString(), "--dry-run" }, common(cfg, key))).exit)
                .isZero();
    }

    // ---- key rotation through the CLI ----

    @Test
    void keyRotationKeepsTheGatewayUsableAndInvalidatesTheOldKey() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        init(cfg, key);
        String oldKeyText = Files.readString(key);

        Run r = run("", concat(new String[] { "key", "rotate" }, common(cfg, key)));
        assertThat(r.exit).as(r.err).isZero();
        assertThat(r.err).contains("Reloaded 1 of 1 policies");

        assertThat(Files.readString(key)).isNotEqualTo(oldKeyText);
        assertThat(run("", concat(new String[] { "policy", "show", "PG-DEV" }, common(cfg, key))).out)
                .contains("PG-DEV: ACTIVE");
        assertThat(cfg.resolve("backups").resolve("profiles.enc.pre-rotation")).exists();

        // putting the old key back must fail: the store is now encrypted with the new one
        Path oldKey = tmp.resolve("oldkey").resolve("master.key");
        Files.createDirectories(oldKey.getParent());
        Files.setPosixFilePermissions(oldKey.getParent(), java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        Files.writeString(oldKey, oldKeyText);
        Files.setPosixFilePermissions(oldKey, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        Run stale = run("", concat(new String[] { "profile", "list" }, common(cfg, oldKey)));
        assertThat(stale.exit).isNotZero();
    }

    @Test
    void keyProviderValueIsParsedStrictly() {
        assertThat(CommonOptions.parseKeyProvider(null)).isNull();
        assertThat(CommonOptions.parseKeyProvider("  ")).isNull();
        assertThat(CommonOptions.parseKeyProvider("keyfile:/etc/ai-db-mcp/master.key"))
                .isEqualTo(Path.of("/etc/ai-db-mcp/master.key"));
        for (String bad : new String[] { "keyfile:", "/etc/key", "file:/x", "KEYFILE:/x", "vault:x", "env:SECRET" }) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> CommonOptions.parseKeyProvider(bad)).as(bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void theKeyProviderOptionTakesAPathNeverTheKeyItself() {
        // the option's declared form documents that only a location is accepted
        var opt = GatewayMain.commandLine().getSubcommands().get("start").getCommandSpec().findOption("--key-provider");
        assertThat(opt.paramLabel()).isEqualTo("keyfile:<path>");
    }

    // ---- administrative audit ----

    private java.util.List<com.fasterxml.jackson.databind.JsonNode> auditEvents(Path cfg) throws Exception {
        Path log = cfg.resolve("logs").resolve("audit.jsonl");
        if (!Files.exists(log)) {
            return java.util.List.of();
        }
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        java.util.List<com.fasterxml.jackson.databind.JsonNode> out = new java.util.ArrayList<>();
        for (String l : Files.readAllLines(log)) {
            out.add(mapper.readTree(l));
        }
        return out;
    }

    @Test
    void stateChangingCommandsAreAuditedAndReadOnlyOnesAreNot() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        init(cfg, key);
        run("", concat(new String[] { "profile", "list" }, common(cfg, key)));
        run("", concat(new String[] { "profile", "show", "PG-DEV" }, common(cfg, key)));
        run("", concat(new String[] { "policy", "show", "PG-DEV" }, common(cfg, key)));
        run("", concat(new String[] { "policy", "validate", "PG-DEV", "--offline" }, common(cfg, key)));
        run("", concat(new String[] { "profile", "disable", "PG-DEV" }, common(cfg, key)));
        run("", concat(new String[] { "profile", "enable", "PG-DEV" }, common(cfg, key)));
        run("", concat(new String[] { "policy", "reload", "PG-DEV", "--offline" }, common(cfg, key)));
        run("", concat(new String[] { "profile", "rename", "PG-DEV", "PG-NEW" }, common(cfg, key)));
        run("", concat(new String[] { "key", "rotate" }, common(cfg, key)));

        var events = auditEvents(cfg);
        assertThat(events).extracting(e -> e.get("tool").asText()).containsExactly("cli:init", "cli:profile.disable",
                "cli:profile.enable", "cli:policy.reload", "cli:profile.rename", "cli:key.rotate");
        assertThat(events).allSatisfy(e -> {
            assertThat(e.get("result").asText()).isEqualTo("OK");
            assertThat(e.get("actorId").asText()).isEqualTo("local-admin");
        });
        assertThat(events.get(1).get("target").asText()).isEqualTo("PG-DEV");
        assertThat(events.get(4).get("target").asText()).isEqualTo("PG-DEV");
        assertThat(io.quarkiverse.mcp.servers.jdbc.audit.AuditService.verify(cfg.resolve("logs").resolve("audit.jsonl")))
                .as("the chain stays valid across many short-lived processes").isZero();
    }

    @Test
    void failedAdminCommandsAreAuditedToo() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        init(cfg, key);
        Run r = run("", concat(new String[] { "profile", "disable", "NO-SUCH" }, common(cfg, key)));
        assertThat(r.exit).isNotZero();
        var last = auditEvents(cfg).get(auditEvents(cfg).size() - 1);
        assertThat(last.get("tool").asText()).isEqualTo("cli:profile.disable");
        assertThat(last.get("result").asText()).isIn("ERROR", "FAILED");
        assertThat(last.get("target").asText()).isEqualTo("NO-SUCH");
    }

    @Test
    void theAdminAuditNeverContainsASecretOrAnOptionValue() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        init(cfg, key);
        run("CLI-ROTATED-SENTINEL\n", concat(new String[] { "profile", "rotate-password", "PG-DEV", "--password-stdin",
                "--skip-connection-test" }, common(cfg, key)));
        run("", concat(new String[] { "driver", "pin", "x.jar" }, common(cfg, key)));
        String log = Files.readString(cfg.resolve("logs").resolve("audit.jsonl"));
        assertThat(log).contains("cli:profile.rotate-password").doesNotContain("CLI-ROTATED-SENTINEL")
                .doesNotContain("CLI-TEST-SENTINEL-pw").doesNotContain("pg.example.internal").doesNotContain("ai_user")
                .doesNotContain(cfg.toString()).doesNotContain(key.toString()).doesNotContain("keyfile");
    }

    @Test
    void helpRequestsAreNotAudited() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        init(cfg, key);
        int before = auditEvents(cfg).size();
        run("", "profile", "disable", "--help");
        assertThat(auditEvents(cfg)).hasSize(before);
    }

    @Test
    void everyCommandThatChangesStateIsOnTheAuditedList() {
        // Guards the list in AdminAudit: a new mutating command must be added there. Read-only commands are listed explicitly
        // so that adding any other command makes this test fail until someone decides which kind it is.
        Set<String> readOnly = Set.of("profile list", "profile show", "profile test", "policy validate", "policy show",
                "backup create", "driver list", "start");
        Set<String> groups = Set.of("profile", "policy", "key", "backup", "driver");
        for (CommandLine c : collect(GatewayMain.commandLine())) {
            String path = c.getCommandSpec().qualifiedName(" ").replaceFirst("^ai-db-mcp ?", "");
            if (path.isEmpty() || groups.contains(path)) {
                continue;
            }
            assertThat(AdminAudit.AUDITED.contains(path) || readOnly.contains(path))
                    .as("command '" + path + "' must be classified as audited or read-only").isTrue();
        }
    }

    @Test
    void failuresArePrintedAsOneLineWithoutAStackTrace() {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        Run r = run("", concat(new String[] { "profile", "list" }, common(cfg, key)));
        assertThat(r.exit).isNotZero();
        assertThat(r.err).doesNotContain("\tat ").doesNotContain("Exception in thread");
    }

    @Test
    void startRefusesWithoutAKeyAndModifiesNothing() throws Exception {
        Path cfg = tmp.resolve("cfg"), key = tmp.resolve("k").resolve("master.key");
        init(cfg, key);
        byte[] before = Files.readAllBytes(cfg.resolve("profiles.enc"));
        Files.delete(key);
        Run r = run("", concat(new String[] { "start" }, common(cfg, key)));
        assertThat(r.exit).isEqualTo(3);
        assertThat(r.err).contains("No file was modified");
        assertThat(Files.readAllBytes(cfg.resolve("profiles.enc"))).isEqualTo(before);
        assertThat(Files.exists(key)).as("a missing key is never silently re-created").isFalse();
    }
}
