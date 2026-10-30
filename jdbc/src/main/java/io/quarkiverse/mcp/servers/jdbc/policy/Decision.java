package io.quarkiverse.mcp.servers.jdbc.policy;

/** Outcome of a permission check: allowed, or denied with a stable machine-readable code. */
public record Decision(boolean allowed, String code, String message) {

    private static final Decision ALLOW = new Decision(true, "ALLOW", "allowed");

    public static Decision allow() {
        return ALLOW;
    }

    public static Decision deny(String code, String message) {
        return new Decision(false, code, message);
    }
}
