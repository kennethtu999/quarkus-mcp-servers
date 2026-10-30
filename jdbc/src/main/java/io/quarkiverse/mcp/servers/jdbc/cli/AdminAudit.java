package io.quarkiverse.mcp.servers.jdbc.cli;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import io.quarkiverse.mcp.servers.jdbc.audit.AuditEvent;
import io.quarkiverse.mcp.servers.jdbc.audit.AuditService;
import picocli.CommandLine;
import picocli.CommandLine.ParseResult;

/**
 * Records administrative commands in the same audit log the MCP tools use (plan section 12: profile changes, policy reloads,
 * key and approval events).
 * <p>
 * It hooks the one place every command passes through, so a new command cannot forget to be audited. Only commands that change
 * state or grant authority are recorded - read-only commands would just flood the log. Only the command path and its first
 * positional argument (a label, a preview id) are written: <em>no option value is ever logged</em>, so a secret cannot reach
 * the
 * log even if an option that carries one were added later.
 */
public final class AdminAudit implements CommandLine.IExecutionStrategy {

    /** Command paths that change state or grant authority. */
    static final Set<String> AUDITED = Set.of(
            "init", "profile add", "profile rotate-password", "profile rename", "profile enable", "profile disable",
            "profile remove", "policy reload", "key rotate", "backup restore", "driver pin", "driver unpin", "approve");

    private final CommandLine.IExecutionStrategy next = new CommandLine.RunLast();

    @Override
    public int execute(ParseResult parseResult) throws CommandLine.ExecutionException, CommandLine.ParameterException {
        ParseResult leaf = parseResult;
        while (leaf.hasSubcommand()) {
            leaf = leaf.subcommand();
        }
        String path = leaf.commandSpec().qualifiedName(" ").replaceFirst("^ai-db-mcp ?", "");
        boolean audited = AUDITED.contains(path) && !leaf.isUsageHelpRequested() && !leaf.isVersionHelpRequested();
        long start = System.nanoTime();
        int exit;
        try {
            exit = next.execute(parseResult);
        } catch (RuntimeException e) {
            if (audited) {
                record(leaf, path, "ERROR", e.getClass().getSimpleName(), start);
            }
            throw e;
        }
        if (audited) {
            record(leaf, path, exit == 0 ? "OK" : "FAILED", "exit=" + exit, start);
        }
        return exit;
    }

    private static void record(ParseResult leaf, String path, String result, String detail, long start) {
        try {
            Path logs = logsDir(leaf);
            if (logs == null) {
                return;
            }
            String target = null;
            List<String> positional = leaf.matchedPositionals().isEmpty() ? List.of()
                    : leaf.matchedPositionals().get(0).stringValues();
            if (!positional.isEmpty()) {
                target = positional.get(0);
            }
            new AuditService(logs).record(AuditEvent.of("cli:" + path.replace(' ', '.')).actor("local-admin").operation("ADMIN")
                    .target(target).decision("ALLOW").result(result).detail(detail)
                    .durationMs((System.nanoTime() - start) / 1_000_000));
        } catch (RuntimeException ignored) {
            // auditing must never change the outcome of the command it describes
        }
    }

    /** Every command carries the shared options as a mixin; its config directory decides where the log lives. */
    private static Path logsDir(ParseResult leaf) {
        for (var mixin : leaf.commandSpec().mixins().values()) {
            if (mixin.userObject() instanceof CommonOptions options) {
                return options.paths().logsDir();
            }
        }
        return null;
    }
}
