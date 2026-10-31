package io.quarkiverse.mcp.servers.jdbc.app;

import static org.assertj.core.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.Test;

import io.quarkiverse.mcp.servers.jdbc.secret.MasterKeyProvider.KeyUnavailableException;

class SafeDiagnosticsTest {
    @Test
    void preservesTypesCausesSuppressedFramesWithoutAnyExceptionMessages() {
        var cause = new NullPointerException("password=SECRET-SENTINEL jdbc:postgresql://secret");
        cause.addSuppressed(new IllegalStateException("SECRET-SENTINEL"));
        var failure = new KeyUnavailableException("controlled summary", cause);
        PrintStream original = System.err;
        var output = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(output));
            SafeDiagnostics.print("Key operation failed", failure);
        } finally {
            System.setErr(original);
        }
        assertThat(output.toString()).contains("ACCESS_FAILED", "Caused by: java.lang.NullPointerException",
                "Suppressed: java.lang.IllegalStateException", "SafeDiagnosticsTest.java")
                .doesNotContain("SECRET-SENTINEL", "jdbc:postgresql", "password=");
        assertThat(SafeDiagnostics.isKeyFailure(new RuntimeException(failure))).isTrue();
    }
}
