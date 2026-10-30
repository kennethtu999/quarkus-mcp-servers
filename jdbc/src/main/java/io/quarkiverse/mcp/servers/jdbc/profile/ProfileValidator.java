package io.quarkiverse.mcp.servers.jdbc.profile;

import java.util.regex.Pattern;

import io.quarkiverse.mcp.servers.jdbc.database.JdbcUrlGuard;

/** Validates the fields an administrator typed in before a profile is stored. */
public final class ProfileValidator {

    private static final Pattern SCHEMA = Pattern.compile("[A-Za-z_][A-Za-z0-9_$#]{0,127}");
    private static final int MAX_USERNAME = 128;
    private static final int MAX_PASSWORD = 512;

    private final JdbcUrlGuard urlGuard;

    public ProfileValidator(JdbcUrlGuard urlGuard) {
        this.urlGuard = urlGuard;
    }

    public void validate(DbProfile p) {
        LabelRules.normalize(p.label());
        urlGuard.validate(p.dbType(), p.jdbcUrl());
        if (p.username().isBlank() || p.username().length() > MAX_USERNAME || hasControl(p.username())) {
            throw new IllegalArgumentException("Username is required and must not contain control characters");
        }
        char[] pw = p.passwordCopy();
        try {
            if (pw.length == 0 || pw.length > MAX_PASSWORD) {
                throw new IllegalArgumentException("Password is required (at most " + MAX_PASSWORD + " characters)");
            }
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
        if (p.defaultSchema() != null && !SCHEMA.matcher(p.defaultSchema()).matches()) {
            throw new IllegalArgumentException("Default schema is not a valid identifier");
        }
    }

    private static boolean hasControl(String s) {
        return s.chars().anyMatch(c -> c < 0x20 || c == 0x7f);
    }
}
