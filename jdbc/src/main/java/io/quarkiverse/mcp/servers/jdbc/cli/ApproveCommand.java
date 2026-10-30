package io.quarkiverse.mcp.servers.jdbc.cli;

import java.io.Console;
import java.util.concurrent.Callable;

import io.quarkiverse.mcp.servers.jdbc.change.ApprovalService;
import io.quarkiverse.mcp.servers.jdbc.change.ApprovalService.Pending;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Parameters;

/**
 * The only way to obtain a confirmation token. It refuses to run unless a person is at an interactive terminal, so a script
 * or an AI tool cannot answer the prompt for them, and it requires typing a short code taken from the change itself, so a
 * reflexive "yes" is not enough.
 */
@Command(name = "approve", description = "Review a previewed change and, if you agree, get the one-time confirmation token")
public class ApproveCommand implements Callable<Integer> {

    @Mixin
    CommonOptions common;

    @Parameters(index = "0", arity = "0..1", paramLabel = "PREVIEW_ID", description = "Preview to approve; omit to list pending previews")
    String previewId;

    @Override
    public Integer call() throws Exception {
        Console console = System.console();
        if (console == null) {
            System.err.println("approve needs an interactive terminal. It cannot be run from a script or piped input.");
            return 2;
        }
        GatewayContext ctx = GatewayContext.open(common);
        ApprovalService approvals = ctx.approvals;

        if (previewId == null) {
            var pending = approvals.listPending();
            if (pending.isEmpty()) {
                System.out.println("No pending previews.");
            }
            for (Pending p : pending) {
                System.out.println(p.previewId() + "  " + p.summary());
            }
            return 0;
        }

        Pending p = approvals.readPending(previewId.strip()).orElse(null);
        if (p == null) {
            System.err.println("No such preview (it may have expired).");
            return 1;
        }
        System.out.println();
        System.out.println("  Profile:   " + p.profileLabel());
        System.out.println("  Change:    " + p.summary());
        System.out.println("  Rows:      " + p.affectedRows());
        System.out.println("  Expires:   in " + Math.max(0, p.expiresAt() - java.time.Instant.now().getEpochSecond()) + " s");
        System.out.println();
        String typed = console.readLine("Type the code %s to approve, anything else to cancel: ", p.confirmationCode());
        if (typed == null || !typed.strip().equalsIgnoreCase(p.confirmationCode())) {
            System.err.println("Cancelled. Nothing was approved.");
            return 1;
        }
        try {
            String token = approvals.grant(p.previewId());
            System.out.println();
            System.out.println("Approved. Give this one-time token to the assistant (valid for a few minutes, usable once):");
            System.out.println();
            System.out.println("  " + token);
            System.out.println();
            return 0;
        } catch (ApprovalService.Refused r) {
            System.err.println("Not approved: " + r.getMessage());
            return 1;
        }
    }
}
