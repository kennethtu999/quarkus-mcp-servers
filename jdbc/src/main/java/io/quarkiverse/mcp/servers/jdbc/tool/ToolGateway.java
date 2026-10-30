package io.quarkiverse.mcp.servers.jdbc.tool;

import java.util.UUID;

import io.quarkiverse.mcp.server.ToolCallException;
import io.quarkiverse.mcp.servers.jdbc.audit.AuditEvent;
import io.quarkiverse.mcp.servers.jdbc.audit.AuditService;
import io.quarkiverse.mcp.servers.jdbc.cli.GatewayContext;
import io.quarkiverse.mcp.servers.jdbc.policy.Decision;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyRepository;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;

/**
 * The single path every tool call takes. It resolves the profile, records the outcome (allow <em>and</em> deny, success
 * <em>and</em> failure) and turns every failure into a short, safe {@link ToolCallException}.
 * <p>
 * Using one wrapper instead of a CDI interceptor is deliberate: a denial thrown before the interceptor would run is exactly
 * the case that must never go unrecorded.
 * <p>
 * Error messages returned to the AI never contain stack traces, SQL, JDBC URLs, host names or driver messages. The detail
 * stays in the (scrubbed) audit log.
 */
public final class ToolGateway {

    private static final String ACTOR = "local-user";

    private final GatewayContext ctx;
    private final AuditService audit;

    public ToolGateway(GatewayContext ctx, AuditService audit) {
        this.ctx = ctx;
        this.audit = audit;
    }

    public GatewayContext context() {
        return ctx;
    }

    public AuditService audit() {
        return audit;
    }

    /** What a tool body receives: the resolved profile and a place to add details to the audit record. */
    public static final class Call {
        public final String requestId = "req-" + UUID.randomUUID().toString().substring(0, 8);
        public final DbProfile profile;
        final AuditEvent event;

        Call(DbProfile profile, AuditEvent event) {
            this.profile = profile;
            this.event = event;
        }

        public AuditEvent audit() {
            return event;
        }
    }

    public interface Body<T> {
        T run(Call call) throws Exception;
    }

    /** Thrown by tool bodies for expected refusals; the message is safe to show to the AI. */
    public static final class Denied extends RuntimeException {
        private final String code;

        public Denied(String code, String message) {
            super(message);
            this.code = code;
        }

        public Denied(Decision d) {
            this(d.code(), d.message());
        }

        public String code() {
            return code;
        }
    }

    /**
     * Runs {@code body} for the profile named by {@code profileRef} (an immutable id or a label).
     *
     * @param operation short operation name for the audit record, e.g. {@code SELECT}
     */
    public <T> T run(String tool, String operation, String profileRef, Body<T> body) {
        long start = System.nanoTime();
        AuditEvent event = AuditEvent.of(tool).actor(ACTOR).operation(operation);
        String unavailable = ctx.sync.refresh();
        DbProfile profile = unavailable != null ? null : ctx.registry.resolve(profileRef).orElse(null);
        Call call = new Call(profile, event);
        event.requestId(call.requestId);
        try {
            if (unavailable != null) {
                throw new Denied("PROFILES_UNAVAILABLE",
                        "Profiles cannot be read right now; ask the administrator to check the gateway");
            }
            if (profile == null) {
                throw new Denied("UNKNOWN_PROFILE", "No such profile");
            }
            event.profile(profile.profileId(), profile.label());
            PolicyRepository.Snapshot snap = ctx.policies.current(profile);
            if (snap.active()) {
                event.policyVersion(snap.policy().hash());
            }
            T result = body.run(call);
            event.decision("ALLOW");
            if (!event.hasResult()) {
                event.result("OK");
            }
            return result;
        } catch (Denied d) {
            event.decision("DENY").code(d.code()).result("DENIED").detail(d.getMessage());
            throw new ToolCallException(d.getMessage(), null);
        } catch (ToolCallException e) {
            event.decision("ALLOW").result("ERROR").detail(e.getMessage());
            throw e;
        } catch (Exception e) {
            event.decision("ALLOW").result("ERROR").code(e.getClass().getSimpleName());
            throw new ToolCallException("The operation failed (" + e.getClass().getSimpleName()
                    + "). Details are in the audit log.", null);
        } finally {
            event.durationMs((System.nanoTime() - start) / 1_000_000);
            audit.record(event);
        }
    }
}
