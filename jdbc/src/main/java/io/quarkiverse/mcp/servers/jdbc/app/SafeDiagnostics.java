package io.quarkiverse.mcp.servers.jdbc.app;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

import io.quarkiverse.mcp.servers.jdbc.secret.MasterKeyProvider.KeyUnavailableException;

/** Retains cause types and stack frames without printing native messages, SQL, keys or suppressed secrets. */
public final class SafeDiagnostics {
    private SafeDiagnostics() {
    }

    public static boolean isKeyFailure(Throwable failure) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            if (cause instanceof KeyUnavailableException) {
                return true;
            }
        }
        return false;
    }

    public static void print(String summary, Throwable failure) {
        System.err.println(summary);
        print(failure, "", Collections.newSetFromMap(new IdentityHashMap<>()));
    }

    private static void print(Throwable failure, String prefix, Set<Throwable> seen) {
        if (failure == null || !seen.add(failure)) {
            return;
        }
        System.err.println(prefix + failure.getClass().getName()
                + (failure instanceof KeyUnavailableException key ? " [" + key.reason() + "]" : ""));
        for (StackTraceElement frame : failure.getStackTrace()) {
            System.err.println("\tat " + frame);
        }
        for (Throwable suppressed : failure.getSuppressed()) {
            print(suppressed, "Suppressed: ", seen);
        }
        print(failure.getCause(), "Caused by: ", seen);
    }
}
