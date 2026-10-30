package io.quarkiverse.mcp.servers.jdbc.database;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates an administrator supplied JDBC URL before it is stored or used. Only a strict subset of each driver's URL
 * syntax is accepted: the host form, a connection property allowlist, and (by default) a TLS setting that verifies the
 * server certificate. Anything unrecognised is rejected rather than passed to the driver.
 * <p>
 * Error messages never echo the URL, because a URL may contain a secret that was pasted by mistake.
 */
public final class JdbcUrlGuard {

    private static final int MAX_LENGTH = 1024;
    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\\[[0-9A-Fa-f:]+]");
    private static final Pattern DB_NAME = Pattern.compile("[A-Za-z0-9_.-]{1,128}");
    private static final Pattern PROP_NAME = Pattern.compile("[A-Za-z0-9_.]{1,64}");

    private final Set<String> allowedHosts;
    private final boolean requireTls;

    /**
     * @param allowedHosts lower-case host names that may be connected to; empty means any host
     * @param requireTls whether the URL must request an encrypted connection with certificate verification
     */
    public JdbcUrlGuard(Set<String> allowedHosts, boolean requireTls) {
        this.allowedHosts = allowedHosts;
        this.requireTls = requireTls;
    }

    public static JdbcUrlGuard strict() {
        return new JdbcUrlGuard(Set.of(), true);
    }

    public void validate(DbType type, String url) {
        DbDialect dialect = DbDialect.of(type);
        if (url == null || url.isBlank()) {
            throw reject("JDBC URL is required");
        }
        if (url.length() > MAX_LENGTH) {
            throw reject("JDBC URL is too long");
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c < 0x20 || c == 0x7f || Character.isWhitespace(c)) {
                throw reject("JDBC URL contains whitespace or control characters");
            }
        }
        if (!url.startsWith(dialect.urlPrefix())) {
            throw reject("JDBC URL does not match DB type " + type);
        }
        String rest = url.substring(dialect.urlPrefix().length());

        switch (type) {
            case POSTGRESQL -> validatePostgres(dialect, rest, url);
            case DB2_LUW -> validateDb2(dialect, rest, url);
            case ORACLE -> validateOracle(dialect, rest, url);
        }
    }

    private void validatePostgres(DbDialect dialect, String rest, String url) {
        if (!rest.startsWith("//")) {
            throw reject("PostgreSQL URL must use the //host:port/database form");
        }
        String authorityAndPath = rest.substring(2);
        String query = null;
        int q = authorityAndPath.indexOf('?');
        if (q >= 0) {
            query = authorityAndPath.substring(q + 1);
            authorityAndPath = authorityAndPath.substring(0, q);
        }
        int slash = authorityAndPath.indexOf('/');
        if (slash < 0) {
            throw reject("PostgreSQL URL must name a database");
        }
        checkHosts(authorityAndPath.substring(0, slash));
        checkDbName(authorityAndPath.substring(slash + 1));
        checkProperties(dialect, query == null ? List.of() : List.of(query.split("&", -1)), "=");
        checkTls(dialect, url);
    }

    private void validateDb2(DbDialect dialect, String rest, String url) {
        if (!rest.startsWith("//")) {
            throw reject("Db2 URL must use the //host:port/database form");
        }
        String authorityAndPath = rest.substring(2);
        String props = null;
        int colon = authorityAndPath.indexOf(':', authorityAndPath.indexOf('/') + 1);
        if (colon >= 0) {
            props = authorityAndPath.substring(colon + 1);
            authorityAndPath = authorityAndPath.substring(0, colon);
        }
        int slash = authorityAndPath.indexOf('/');
        if (slash < 0) {
            throw reject("Db2 URL must name a database");
        }
        checkHosts(authorityAndPath.substring(0, slash));
        checkDbName(authorityAndPath.substring(slash + 1));
        List<String> pairs = new ArrayList<>();
        if (props != null) {
            for (String p : props.split(";", -1)) {
                if (!p.isEmpty()) {
                    pairs.add(p);
                }
            }
        }
        checkProperties(dialect, pairs, "=");
        checkTls(dialect, url);
    }

    private void validateOracle(DbDialect dialect, String rest, String url) {
        // Only the EZConnect forms @//host:port/service (cleartext) and @tcps://host:port/service (TLS). TNS
        // descriptors and tnsnames aliases would pull in TNS_ADMIN files and arbitrary address lists.
        boolean tcps = rest.startsWith("@tcps://");
        if (!tcps && !rest.startsWith("@//")) {
            throw reject("Oracle URL must use the @//host:port/service or @tcps://host:port/service form");
        }
        if (rest.indexOf('(') >= 0 || rest.indexOf('?') >= 0 || rest.indexOf(';') >= 0) {
            throw reject("Oracle URL must not contain a descriptor or connection properties");
        }
        String authorityAndPath = rest.substring(tcps ? "@tcps://".length() : "@//".length());
        int slash = authorityAndPath.indexOf('/');
        if (slash < 0) {
            throw reject("Oracle URL must name a service");
        }
        checkHosts(authorityAndPath.substring(0, slash));
        checkDbName(authorityAndPath.substring(slash + 1));
        checkTls(dialect, url);
    }

    private void checkHosts(String hostList) {
        if (hostList.isEmpty()) {
            throw reject("JDBC URL must name a host");
        }
        if (hostList.indexOf('@') >= 0) {
            throw reject("JDBC URL must not embed credentials; the username and password are stored separately");
        }
        for (String hostPort : hostList.split(",", -1)) {
            String host = hostPort;
            if (hostPort.startsWith("[")) {
                int end = hostPort.indexOf(']');
                if (end < 0) {
                    throw reject("Invalid IPv6 host");
                }
                host = hostPort.substring(0, end + 1);
                String port = hostPort.substring(end + 1);
                checkPort(port.startsWith(":") ? port.substring(1) : port.isEmpty() ? null : "x");
            } else {
                int colon = hostPort.lastIndexOf(':');
                if (colon >= 0) {
                    host = hostPort.substring(0, colon);
                    checkPort(hostPort.substring(colon + 1));
                }
            }
            Matcher m = HOST.matcher(host);
            if (!m.matches()) {
                throw reject("Invalid host name");
            }
            if (!allowedHosts.isEmpty() && !allowedHosts.contains(host.toLowerCase(Locale.ROOT))) {
                throw reject("Host is not in the allowed host list");
            }
        }
    }

    private static void checkPort(String port) {
        if (port == null) {
            return;
        }
        try {
            int p = Integer.parseInt(port);
            if (p < 1 || p > 65535) {
                throw reject("Port out of range");
            }
        } catch (NumberFormatException e) {
            throw reject("Invalid port");
        }
    }

    private static void checkDbName(String name) {
        if (!DB_NAME.matcher(name).matches()) {
            throw reject("Invalid database name");
        }
    }

    private static void checkProperties(DbDialect dialect, List<String> pairs, String separator) {
        for (String pair : pairs) {
            int eq = pair.indexOf(separator);
            if (eq <= 0) {
                throw reject("Malformed connection property");
            }
            String name = pair.substring(0, eq);
            if (!PROP_NAME.matcher(name).matches()) {
                throw reject("Malformed connection property name");
            }
            if (!dialect.allowedUrlProperties().contains(name.toLowerCase(Locale.ROOT))) {
                throw reject("Connection property '" + name + "' is not allowed");
            }
        }
    }

    private void checkTls(DbDialect dialect, String url) {
        if (requireTls && !dialect.urlRequestsTls(url)) {
            throw reject("TLS with certificate verification is required for this profile");
        }
    }

    private static JdbcUrlRejectedException reject(String message) {
        return new JdbcUrlRejectedException(message);
    }

    public static final class JdbcUrlRejectedException extends IllegalArgumentException {
        JdbcUrlRejectedException(String message) {
            super(message);
        }
    }
}
