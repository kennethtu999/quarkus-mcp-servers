package io.quarkiverse.mcp.servers.jdbc.profile;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Immutable snapshot of the known profiles, swapped atomically, so a tool call always sees one consistent view and never
 * a half-applied edit.
 */
public final class ProfileRegistry {

    private final AtomicReference<List<DbProfile>> snapshot = new AtomicReference<>(List.of());

    public void replaceAll(List<DbProfile> profiles) {
        snapshot.set(List.copyOf(profiles));
    }

    public List<DbProfile> all() {
        return snapshot.get();
    }

    public Optional<DbProfile> byId(String profileId) {
        return snapshot.get().stream().filter(p -> p.profileId().equals(profileId)).findFirst();
    }

    public Optional<DbProfile> byLabel(String label) {
        if (label == null) {
            return Optional.empty();
        }
        String wanted = label.toUpperCase(Locale.ROOT);
        return snapshot.get().stream().filter(p -> p.label().toUpperCase(Locale.ROOT).equals(wanted)).findFirst();
    }

    /** Resolves what the AI sent: an immutable profileId first, then a label. */
    public Optional<DbProfile> resolve(String idOrLabel) {
        if (idOrLabel == null || idOrLabel.isBlank()) {
            return Optional.empty();
        }
        Optional<DbProfile> byId = byId(idOrLabel);
        return byId.isPresent() ? byId : byLabel(idOrLabel);
    }
}
