package io.quarkiverse.mcp.servers.jdbc.cli;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;

/**
 * Reads answers and secrets without ever placing them in process arguments, environment variables or shell history: from
 * the terminal with echo disabled for passwords, or (for automation and tests) one answer per line from standard input.
 */
public final class PasswordPrompt {

    private PasswordPrompt() {
    }

    /** Reads a password. With {@code fromStdin} the next line of {@code in} is used; otherwise the terminal, without echo. */
    public static char[] password(String label, boolean fromStdin, BufferedReader in) throws IOException {
        if (fromStdin) {
            String line = in.readLine();
            if (line == null || line.isEmpty()) {
                throw new IOException("No password was provided on standard input");
            }
            return line.toCharArray();
        }
        Console console = System.console();
        if (console == null) {
            throw new IOException("No interactive terminal is available. Run this in a terminal, or pass --password-stdin.");
        }
        char[] pw = label.isEmpty() ? console.readPassword("") : console.readPassword("%s: ", label);
        if (pw == null || pw.length == 0) {
            throw new IOException("A password is required");
        }
        return pw;
    }

    /** Reads a non-secret answer, optionally with a default. */
    public static String line(String label, String defaultValue, boolean fromStdin, BufferedReader in) throws IOException {
        String suffix = defaultValue == null || defaultValue.isEmpty() ? "" : " [" + defaultValue + "]";
        Console console = System.console();
        String value;
        if (console != null && !fromStdin) {
            value = console.readLine("%s%s: ", label, suffix);
        } else {
            System.err.print(label + suffix + ": ");
            System.err.flush();
            value = in.readLine();
        }
        if (value == null) {
            throw new IOException("Input ended unexpectedly");
        }
        value = value.strip();
        return value.isEmpty() && defaultValue != null ? defaultValue : value;
    }
}
