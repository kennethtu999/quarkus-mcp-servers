package io.quarkiverse.mcp.servers.jdbc.app;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;

/**
 * The Quarkus application that serves MCP over stdio. It only exists to keep the process alive until the MCP client
 * closes the transport; all start-up validation happens in the CLI before this class is run.
 */
public class GatewayApp implements QuarkusApplication {

    @Override
    public int run(String... args) {
        Quarkus.waitForExit();
        return 0;
    }
}
