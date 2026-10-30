package io.quarkiverse.mcp.servers.jdbc.profile;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Label syntax and the mapping from a label to a policy file name. Labels are compared case-insensitively and always
 * stored upper-case. Because a label becomes part of a file name, it is restricted to a safe alphabet and the resulting
 * path is checked once more after it has been resolved.
 */
public final class LabelRules {

    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_-]{0,63}");

    private LabelRules() {
    }

    public static boolean isValid(String label) {
        return label != null && VALID.matcher(label).matches();
    }

    /** Returns the canonical upper-case label or throws. */
    public static String normalize(String label) {
        if (!isValid(label)) {
            throw new IllegalArgumentException(
                    "Label must match [A-Za-z0-9][A-Za-z0-9_-]{0,63} (letters, digits, '_' and '-', at most 64 characters)");
        }
        return label.toUpperCase(Locale.ROOT);
    }

    public static String policyFileName(String label) {
        return "permissions_" + normalize(label) + ".yaml";
    }

    /** Resolves the policy file for a label and proves it stays inside {@code permissionsDir}. */
    public static Path policyPath(Path permissionsDir, String label) throws IOException {
        Path base = permissionsDir.toAbsolutePath().normalize();
        Path resolved = base.resolve(policyFileName(label)).normalize();
        if (!resolved.getParent().equals(base)) {
            throw new IOException("Policy path escapes the permissions directory");
        }
        return resolved;
    }
}
