package io.quarkiverse.mcp.servers.jdbc.profile;

import java.util.Arrays;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import io.quarkiverse.mcp.servers.jdbc.database.DbType;

/**
 * A decrypted database profile. Lives only in process memory; on disk it exists solely inside {@code profiles.enc}.
 * <p>
 * The password is held as a {@code char[]} so it can be wiped, and {@link #toString()} never prints it or the URL.
 */
public final class DbProfile {

    private final String profileId;
    private final String label;
    private final DbType dbType;
    private final String jdbcUrl;
    private final String username;
    private final char[] password;
    private final String defaultSchema;
    private final boolean enabled;

    @JsonCreator
    public DbProfile(@JsonProperty("profileId") String profileId, @JsonProperty("label") String label,
            @JsonProperty("dbType") DbType dbType, @JsonProperty("jdbcUrl") String jdbcUrl,
            @JsonProperty("username") String username, @JsonProperty("password") String password,
            @JsonProperty("defaultSchema") String defaultSchema, @JsonProperty("enabled") boolean enabled) {
        this(profileId, label, dbType, jdbcUrl, username, password == null ? null : password.toCharArray(), defaultSchema,
                enabled);
    }

    public DbProfile(String profileId, String label, DbType dbType, String jdbcUrl, String username, char[] password,
            String defaultSchema, boolean enabled) {
        this.profileId = Objects.requireNonNull(profileId, "profileId");
        this.label = Objects.requireNonNull(label, "label");
        this.dbType = Objects.requireNonNull(dbType, "dbType");
        this.jdbcUrl = Objects.requireNonNull(jdbcUrl, "jdbcUrl");
        this.username = Objects.requireNonNull(username, "username");
        this.password = password == null ? new char[0] : password.clone();
        this.defaultSchema = defaultSchema;
        this.enabled = enabled;
    }

    @JsonProperty("profileId")
    public String profileId() {
        return profileId;
    }

    @JsonProperty("label")
    public String label() {
        return label;
    }

    @JsonProperty("dbType")
    public DbType dbType() {
        return dbType;
    }

    @JsonProperty("jdbcUrl")
    public String jdbcUrl() {
        return jdbcUrl;
    }

    @JsonProperty("username")
    public String username() {
        return username;
    }

    @JsonProperty("password")
    String passwordForSerialization() {
        return new String(password);
    }

    /** A copy; the caller owns it and should {@link Arrays#fill(char[], char)} it after use. */
    @JsonIgnore
    public char[] passwordCopy() {
        return password.clone();
    }

    @JsonProperty("defaultSchema")
    public String defaultSchema() {
        return defaultSchema;
    }

    @JsonProperty("enabled")
    public boolean enabled() {
        return enabled;
    }

    public DbProfile withPassword(char[] newPassword) {
        return new DbProfile(profileId, label, dbType, jdbcUrl, username, newPassword, defaultSchema, enabled);
    }

    public DbProfile withLabel(String newLabel) {
        return new DbProfile(profileId, newLabel, dbType, jdbcUrl, username, password, defaultSchema, enabled);
    }

    public DbProfile withEnabled(boolean newEnabled) {
        return new DbProfile(profileId, label, dbType, jdbcUrl, username, password, defaultSchema, newEnabled);
    }

    public void wipe() {
        Arrays.fill(password, '\0');
    }

    /** Never includes the URL, username or password. */
    @Override
    public String toString() {
        return "DbProfile[label=" + label + ", dbType=" + dbType + ", enabled=" + enabled + "]";
    }
}
