package io.quarkiverse.mcp.servers.jdbc.policy;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;

import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.Operation;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy.WhitelistEntry;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.Loaded;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader.PolicyException;
import io.quarkiverse.mcp.servers.jdbc.profile.LabelRules;

/**
 * Turns a parsed YAML tree into a {@link PermissionPolicy}, enforcing plan section 8.4: known version, no unknown keys,
 * the file must belong to the profile it is loaded for, {@code access} is mandatory, limits are in range, no wildcards,
 * no duplicate or conflicting entries. Anything doubtful is an error; nothing is defaulted towards more permission.
 */
public final class PolicyValidator {

    static final int SUPPORTED_VERSION = 1;
    /** Plain SQL identifiers only; quoting and case folding are resolved against JDBC metadata later. */
    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_$#]{0,127}");

    private static final Set<String> TOP = Set.of("version", "profile", "profileId", "access", "read", "write");
    private static final Set<String> READ = Set.of("maxRows", "timeoutSeconds");
    private static final Set<String> WRITE = Set.of("allowedSchemas", "operations", "maxAffectedRows",
            "requireConfirmation", "whitelist");
    private static final Set<String> WHITELIST_ENTRY = Set.of("schema", "table", "operations");

    private PolicyValidator() {
    }

    /**
     * @param expectedLabel the profile label this file is being loaded for
     * @param expectedProfileId the immutable id of that profile
     */
    public static PermissionPolicy validate(Loaded loaded, String expectedLabel, String expectedProfileId)
            throws PolicyException {
        JsonNode root = loaded.tree();
        unknownKeys(root, TOP, "");

        int version = intValue(root, "version", true, "");
        if (version != SUPPORTED_VERSION) {
            throw new PolicyException("Unsupported policy version " + version);
        }

        String profile = text(root, "profile", true);
        if (!LabelRules.isValid(profile) || !LabelRules.normalize(profile).equals(LabelRules.normalize(expectedLabel))) {
            throw new PolicyException("'profile' does not match the profile this file belongs to");
        }
        String profileId = text(root, "profileId", true);
        if (!profileId.equals(expectedProfileId)) {
            throw new PolicyException("'profileId' does not match the profile this file belongs to");
        }

        String accessText = text(root, "access", true);
        AccessMode access;
        try {
            access = AccessMode.valueOf(accessText);
        } catch (IllegalArgumentException e) {
            throw new PolicyException("'access' must be READ_ONLY, READ_WRITE or READ_WRITE_WHITELIST");
        }

        int maxRows = PermissionPolicy.MAX_READ_ROWS_HARD_LIMIT;
        int timeout = PermissionPolicy.DEFAULT_READ_TIMEOUT_SECONDS;
        if (root.has("read")) {
            JsonNode read = object(root, "read");
            unknownKeys(read, READ, "read.");
            if (read.has("maxRows")) {
                maxRows = intValue(read, "maxRows", true, "read.");
                if (maxRows < 1 || maxRows > PermissionPolicy.MAX_READ_ROWS_HARD_LIMIT) {
                    throw new PolicyException(
                            "read.maxRows must be between 1 and " + PermissionPolicy.MAX_READ_ROWS_HARD_LIMIT);
                }
            }
            if (read.has("timeoutSeconds")) {
                timeout = intValue(read, "timeoutSeconds", true, "read.");
                if (timeout < 1 || timeout > PermissionPolicy.MAX_READ_TIMEOUT_SECONDS) {
                    throw new PolicyException(
                            "read.timeoutSeconds must be between 1 and " + PermissionPolicy.MAX_READ_TIMEOUT_SECONDS);
                }
            }
        }

        PermissionPolicy.Write write = null;
        if (access == AccessMode.READ_ONLY) {
            if (root.has("write")) {
                throw new PolicyException("A READ_ONLY policy must not contain a 'write' section");
            }
        } else {
            write = validateWrite(root, access);
        }

        return new PermissionPolicy(version, LabelRules.normalize(profile), profileId, access, maxRows, timeout, write,
                loaded.hash());
    }

    private static PermissionPolicy.Write validateWrite(JsonNode root, AccessMode access) throws PolicyException {
        if (!root.has("write")) {
            throw new PolicyException("'write' section is required for " + access);
        }
        JsonNode w = object(root, "write");
        unknownKeys(w, WRITE, "write.");

        int maxAffected = PermissionPolicy.DEFAULT_MAX_AFFECTED_ROWS;
        if (w.has("maxAffectedRows")) {
            maxAffected = intValue(w, "maxAffectedRows", true, "write.");
            if (maxAffected < 1 || maxAffected > PermissionPolicy.MAX_AFFECTED_ROWS_HARD_LIMIT) {
                throw new PolicyException(
                        "write.maxAffectedRows must be between 1 and " + PermissionPolicy.MAX_AFFECTED_ROWS_HARD_LIMIT);
            }
        }

        // The plan makes Preview/Confirm mandatory for every write. A policy may state it, but may not turn it off.
        boolean requireConfirmation = true;
        if (w.has("requireConfirmation")) {
            JsonNode rc = w.get("requireConfirmation");
            if (!rc.isBoolean()) {
                throw new PolicyException("write.requireConfirmation must be a boolean");
            }
            if (!rc.asBoolean()) {
                throw new PolicyException("write.requireConfirmation cannot be disabled");
            }
        }

        List<String> schemas = new ArrayList<>();
        Set<Operation> operations = EnumSet.noneOf(Operation.class);
        List<WhitelistEntry> whitelist = new ArrayList<>();

        if (access == AccessMode.READ_WRITE) {
            if (w.has("whitelist")) {
                throw new PolicyException("write.whitelist is only valid with READ_WRITE_WHITELIST");
            }
            if (!w.has("allowedSchemas")) {
                throw new PolicyException("write.allowedSchemas is required for READ_WRITE");
            }
            Set<String> seen = new HashSet<>();
            for (String s : stringList(w, "allowedSchemas", "write.")) {
                identifier(s, "write.allowedSchemas");
                if (!seen.add(s.toUpperCase(Locale.ROOT))) {
                    throw new PolicyException("write.allowedSchemas contains a duplicate schema");
                }
                schemas.add(s);
            }
            if (schemas.isEmpty()) {
                throw new PolicyException("write.allowedSchemas must not be empty (an empty list would allow nothing)");
            }
            operations = operations(w, "operations", "write.", true);
        } else {
            if (w.has("allowedSchemas") || w.has("operations")) {
                throw new PolicyException("write.allowedSchemas and write.operations are not valid with READ_WRITE_WHITELIST");
            }
            if (!w.has("whitelist")) {
                throw new PolicyException("write.whitelist is required for READ_WRITE_WHITELIST");
            }
            JsonNode list = w.get("whitelist");
            if (!list.isArray()) {
                throw new PolicyException("write.whitelist must be a list");
            }
            Set<String> seen = new HashSet<>();
            int i = 0;
            for (JsonNode entry : list) {
                String where = "write.whitelist[" + i++ + "].";
                if (!entry.isObject()) {
                    throw new PolicyException("write.whitelist entries must be mappings");
                }
                unknownKeys(entry, WHITELIST_ENTRY, where);
                String schema = text(entry, "schema", true);
                String table = text(entry, "table", true);
                identifier(schema, where + "schema");
                identifier(table, where + "table");
                if (!seen.add(schema.toUpperCase(Locale.ROOT) + "." + table.toUpperCase(Locale.ROOT))) {
                    throw new PolicyException("write.whitelist defines " + schema + "." + table + " more than once");
                }
                whitelist.add(new WhitelistEntry(schema, table, operations(entry, "operations", where, true)));
            }
            // An empty whitelist is valid and means "no writes at all".
        }

        return new PermissionPolicy.Write(List.copyOf(schemas), Set.copyOf(operations), List.copyOf(whitelist),
                maxAffected, requireConfirmation);
    }

    private static Set<Operation> operations(JsonNode parent, String key, String where, boolean required)
            throws PolicyException {
        if (!parent.has(key)) {
            if (required) {
                throw new PolicyException(where + key + " is required");
            }
            return EnumSet.noneOf(Operation.class);
        }
        Set<Operation> ops = EnumSet.noneOf(Operation.class);
        for (String s : stringList(parent, key, where)) {
            Operation op;
            try {
                op = Operation.valueOf(s);
            } catch (IllegalArgumentException e) {
                throw new PolicyException(where + key + " may only contain INSERT, UPDATE or DELETE");
            }
            if (!ops.add(op)) {
                throw new PolicyException(where + key + " contains a duplicate operation");
            }
        }
        if (ops.isEmpty()) {
            throw new PolicyException(where + key + " must not be empty");
        }
        return ops;
    }

    private static void identifier(String value, String where) throws PolicyException {
        if (value.contains("*") || value.contains("%") || value.contains("?")) {
            throw new PolicyException(where + " must not contain wildcards");
        }
        if (!IDENTIFIER.matcher(value).matches()) {
            throw new PolicyException(where + " is not a valid identifier");
        }
    }

    private static void unknownKeys(JsonNode node, Set<String> allowed, String prefix) throws PolicyException {
        for (Iterator<String> it = node.fieldNames(); it.hasNext();) {
            String name = it.next();
            if (!allowed.contains(name)) {
                throw new PolicyException("Unknown field '" + prefix + abbreviate(name) + "'");
            }
        }
    }

    private static JsonNode object(JsonNode parent, String key) throws PolicyException {
        JsonNode n = parent.get(key);
        if (n == null || !n.isObject()) {
            throw new PolicyException("'" + key + "' must be a mapping");
        }
        return n;
    }

    private static String text(JsonNode parent, String key, boolean required) throws PolicyException {
        JsonNode n = parent.get(key);
        if (n == null || n.isNull()) {
            if (required) {
                throw new PolicyException("'" + key + "' is required");
            }
            return null;
        }
        if (!n.isTextual() || n.asText().isBlank()) {
            throw new PolicyException("'" + key + "' must be a non-empty string");
        }
        return n.asText();
    }

    private static int intValue(JsonNode parent, String key, boolean required, String prefix) throws PolicyException {
        JsonNode n = parent.get(key);
        if (n == null || n.isNull()) {
            if (required) {
                throw new PolicyException("'" + prefix + key + "' is required");
            }
            return 0;
        }
        if (!n.isIntegralNumber() || !n.canConvertToInt()) {
            throw new PolicyException("'" + prefix + key + "' must be an integer");
        }
        return n.asInt();
    }

    private static List<String> stringList(JsonNode parent, String key, String where) throws PolicyException {
        JsonNode n = parent.get(key);
        if (n == null || !n.isArray()) {
            throw new PolicyException(where + key + " must be a list");
        }
        List<String> out = new ArrayList<>();
        for (JsonNode item : n) {
            if (!item.isTextual() || item.asText().isBlank()) {
                throw new PolicyException(where + key + " must contain non-empty strings only");
            }
            out.add(item.asText());
        }
        return out;
    }

    private static String abbreviate(String s) {
        return s.length() <= 40 ? s : s.substring(0, 40) + "...";
    }
}
