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

    @Option(names = "--paste", description = "Paste Label##DB_TYPE##JDBC_URL##USERNAME##SCHEMA[##PASSWORD] as one hidden input line.")
    boolean paste;

    @Option(names = "--setup", description = "Paste one connection line followed by TLS/ACCESS/MAX_ROWS/OVERRIDE/UPDATE settings and END.")
    boolean setup;

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
        if (setup) {
            if (paste) {
                throw new IllegalArgumentException("--setup 與 --paste 請擇一使用");
            }
            ProfileSetup.prompt(ctx, in, passwordStdin, skipTest);
            ProfileCommand.printSummary(ctx);
            return 0;
        }
        do {
            ProfileCommand.promptAndAdd(ctx, in, passwordStdin, skipTest, paste);
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
