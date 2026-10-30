package io.quarkiverse.mcp.servers.jdbc.cli;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;

import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(name = "init", description = "First-time setup: create the config directory and master key, then add the first profile")
public class InitCommand implements Callable<Integer> {

    @Mixin
    CommonOptions common;

    @Option(names = "--password-stdin", description = "Read every answer, including the password, from standard input (one per line).")
    boolean passwordStdin;

    @Option(names = "--skip-connection-test", description = "Do not test the connection before saving.")
    boolean skipTest;

    @Override
    public Integer call() throws Exception {
        if (common.allowInsecureTls) {
            System.err.println("WARNING: TLS verification is not being enforced for this profile.");
        }
        GatewayContext ctx = GatewayContext.create(common);
        ctx.profiles.load();
        System.err.println("Configuration directory: " + ctx.paths.root());
        System.err.println("Master key: " + ctx.keys.describe());

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        do {
            ProfileCommand.promptAndAdd(ctx, in, passwordStdin, skipTest);
            if (passwordStdin) {
                break;
            }
            System.err.print("Add another database? [y/N]: ");
            System.err.flush();
        } while ("y".equalsIgnoreCase(String.valueOf(in.readLine()).strip()));

        ProfileCommand.printSummary(ctx);
        return 0;
    }
}
