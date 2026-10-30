package io.quarkiverse.mcp.servers.jdbc.app;

import java.util.concurrent.atomic.AtomicReference;

import io.quarkiverse.mcp.servers.jdbc.cli.GatewayContext;

/**
 * Hands the fully validated context from {@code start} to the MCP tool beans. It is set before Quarkus starts, so a tool
 * call can never observe a half-initialised gateway; if it is somehow unset, tools refuse to run.
 */
public final class GatewayRuntime {

    private static final AtomicReference<GatewayContext> CONTEXT = new AtomicReference<>();

    private GatewayRuntime() {
    }

    public static void set(GatewayContext context) {
        CONTEXT.set(context);
    }

    public static GatewayContext get() {
        GatewayContext c = CONTEXT.get();
        if (c == null) {
            throw new IllegalStateException("The gateway is not initialised");
        }
        return c;
    }

    public static boolean isReady() {
        return CONTEXT.get() != null;
    }
}
