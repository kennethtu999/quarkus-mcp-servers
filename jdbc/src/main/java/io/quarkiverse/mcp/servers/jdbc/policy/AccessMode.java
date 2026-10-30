package io.quarkiverse.mcp.servers.jdbc.policy;

public enum AccessMode {
    READ_ONLY,
    READ_WRITE,
    READ_WRITE_WHITELIST;

    public boolean allowsWrite() {
        return this != READ_ONLY;
    }
}
