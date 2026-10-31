package io.quarkiverse.mcp.servers.jdbc.audit;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

/**
 * Append-only JSON Lines audit log in {@code logs/audit.jsonl}.
 * <p>
 * Each line carries {@code prev}, the SHA-256 of the previous line, so removing or editing a line in the middle breaks the
 * chain and is detectable by {@link #verify}. A local file cannot stop someone who can rewrite the whole file; for formal
 * auditing the log should be shipped to an immutable central store (plan section 12).
 * <p>
 * Audit failures never block or change the outcome of the operation being audited, but they are reported on stderr so they
 * are not silent. Every free-text value is scrubbed for anything that looks like a secret before it is written.
 */
public final class AuditService {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_FIELD = 300;
    /** Rotate when the active file passes this size. */
    private static final long DEFAULT_MAX_BYTES = 10L * 1024 * 1024;
    private static final int DEFAULT_KEEP = 10;

    private static final Pattern URL_LIKE = Pattern.compile("(?i)jdbc:[a-z0-9]+:[^\\s\"']*");
    private static final Pattern SECRET_ASSIGNMENT = Pattern
            .compile("(?i)(password|passwd|pwd|secret|token|apikey|api_key|authorization)\\s*[=:]\\s*[^\\s,;\"']+");

    private final Path file;
    private final Clock clock;
    private final long maxBytes;
    private final int keep;
    private final Object lock = new Object();

    public AuditService(Path logsDir) {
        this(logsDir, Clock.systemDefaultZone(), DEFAULT_MAX_BYTES, DEFAULT_KEEP);
    }

    AuditService(Path logsDir, Clock clock, long maxBytes, int keep) {
        this.file = logsDir.resolve("audit.jsonl");
        this.clock = clock;
        this.maxBytes = maxBytes;
        this.keep = keep;
    }

    public Path file() {
        return file;
    }

    public void record(AuditEvent event) {
        try {
            write(event);
        } catch (IOException | RuntimeException e) {
            // Never throw into the caller, never include the event: report the failure class only.
            System.err.println("ai-db-mcp: audit write failed (" + e.getClass().getSimpleName() + ")");
        }
    }

    private void write(AuditEvent event) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        synchronized (lock) {
            FilePerms.ensureSecureDir(dir);
            try (FileChannel lockCh = FileChannel.open(dir.resolve(".audit.lock"), StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE); FileLock ignored = lockCh.lock()) {
                rotateIfNeeded();
                removeExpiredRecords();
                String prev = hashOfLastLine(); // always from the file: another process may have written since we last did

                ObjectNode node = JSON.createObjectNode();
                node.put("timestamp", OffsetDateTime.now(clock).toString());
                for (Map.Entry<String, Object> e : event.fields().entrySet()) {
                    Object v = e.getValue();
                    if (v instanceof String s) {
                        node.put(e.getKey(), scrub(s));
                    } else if (v instanceof Long l) {
                        node.put(e.getKey(), l);
                    } else {
                        node.put(e.getKey(), scrub(String.valueOf(v)));
                    }
                }
                node.put("prev", prev);
                String line = JSON.writeValueAsString(node);

                boolean isNew = !Files.exists(file);
                Files.write(file, (line + "\n").getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND);
                if (isNew) {
                    FilePerms.restrictFile(file);
                }
            }
        }
    }

    /** Removes anything that looks like a connection string or credential, and bounds the length. */
    static String scrub(String s) {
        if (s == null) {
            return null;
        }
        String out = URL_LIKE.matcher(s).replaceAll("[jdbc-url-removed]");
        out = SECRET_ASSIGNMENT.matcher(out).replaceAll("$1=[removed]");
        out = out.replaceAll("[\\p{Cntrl}&&[^ ]]", " ");
        return out.length() <= MAX_FIELD ? out : out.substring(0, MAX_FIELD) + "...";
    }

    public static String hashSql(String sql) {
        return "sha256:" + sha256(sql == null ? "" : sql.strip().replaceAll("\\s+", " "));
    }

    private static final Pattern ROTATED = Pattern.compile("audit-(\\d{12})-\\d+\\.jsonl");

    /** Run under the shared file lock; retain original lines so the remaining hash chain stays intact. */
    private void removeExpiredRecords() throws IOException {
        Instant cutoff = clock.instant().minus(Duration.ofDays(7));
        java.util.ArrayList<Path> sources = new java.util.ArrayList<>(rotatedFiles());
        if (Files.exists(file)) {
            sources.add(file);
        }
        for (Path source : sources) {
            try (var reader = Files.newBufferedReader(source, StandardCharsets.UTF_8)) {
                String first = reader.readLine();
                if (first == null || !expired(first, cutoff)) {
                    continue;
                }
            }
            List<String> lines = Files.readAllLines(source, StandardCharsets.UTF_8);
            int start = 0;
            while (start < lines.size() && expired(lines.get(start), cutoff)) {
                start++;
            }
            if (start == lines.size()) {
                Files.deleteIfExists(source);
            } else {
                Path temporary = Files.createTempFile(source.getParent(), ".audit-retention-", ".tmp");
                try {
                    FilePerms.restrictFile(temporary);
                    Files.write(temporary, lines.subList(start, lines.size()), StandardCharsets.UTF_8);
                    Files.move(temporary, source, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } finally {
                    Files.deleteIfExists(temporary);
                }
            }
        }
    }

    private static boolean expired(String line, Instant cutoff) throws IOException {
        return OffsetDateTime.parse(JSON.readTree(line).path("timestamp").asText()).toInstant().isBefore(cutoff);
    }

    private void rotateIfNeeded() throws IOException {
        if (!Files.exists(file) || Files.size(file) < maxBytes) {
            return;
        }
        // The sequence number, not the clock, orders the files: clocks can repeat or go backwards.
        String stamp = OffsetDateTime.now(clock).toString().replaceAll("[^0-9]", "");
        Path rotated = file.resolveSibling(String.format("audit-%012d-%s.jsonl", nextSequence(), stamp));
        // The chain continues across the rotation: the first line of the new file points at the last of the old one.
        Files.move(file, rotated, StandardCopyOption.ATOMIC_MOVE);
        List<Path> all = rotatedFiles();
        for (int i = 0; i < all.size() - keep; i++) {
            Files.deleteIfExists(all.get(i));
            System.err.println("ai-db-mcp: audit retention removed " + all.get(i).getFileName());
        }
    }

    private long nextSequence() throws IOException {
        List<Path> all = rotatedFiles();
        if (all.isEmpty()) {
            return 1;
        }
        Matcher m = ROTATED.matcher(all.get(all.size() - 1).getFileName().toString());
        return m.matches() ? Long.parseLong(m.group(1)) + 1 : all.size() + 1;
    }

    /** Rotated files, oldest first. */
    private List<Path> rotatedFiles() throws IOException {
        try (var files = Files.list(file.getParent())) {
            return files.filter(p -> ROTATED.matcher(p.getFileName().toString()).matches()).sorted().toList();
        }
    }

    /**
     * Hash of the newest line, read from disk under the file lock. After a rotation the active file does not exist yet, so
     * the chain continues from the newest rotated file.
     */
    private String hashOfLastLine() throws IOException {
        if (Files.exists(file) && Files.size(file) > 0) {
            return lastLineHash(file);
        }
        Path rotated = latestRotated();
        return rotated == null ? "genesis" : lastLineHash(rotated);
    }

    private static String lastLineHash(Path source) throws IOException {
        // A line is at most a few KB; reading the last 64 KB is enough and avoids re-reading a 10 MB log on every write.
        try (java.io.RandomAccessFile f = new java.io.RandomAccessFile(source.toFile(), "r")) {
            long len = f.length();
            long start = Math.max(0, len - 64 * 1024);
            byte[] buf = new byte[(int) (len - start)];
            f.seek(start);
            f.readFully(buf);
            String tail = new String(buf, StandardCharsets.UTF_8);
            String[] lines = tail.split("\n");
            for (int i = lines.length - 1; i >= 0; i--) {
                // when the window starts mid-file, the first line may be cut; it is never the last non-blank line
                if (!lines[i].isBlank() && (i > 0 || start == 0)) {
                    return sha256(lines[i]);
                }
            }
        }
        return "genesis";
    }

    private Path latestRotated() throws IOException {
        List<Path> all = rotatedFiles();
        return all.isEmpty() ? null : all.get(all.size() - 1);
    }

    /**
     * Checks the hash chain of one log file.
     * <p>
     * Detects an edited, removed or reordered line after the first one. It cannot detect lines removed from the very start
     * or end of a file, nor a complete rewrite of the file: that needs an external, immutable copy.
     *
     * @return the 1-based number of the first line whose {@code prev} does not match, or {@code 0} if intact
     */
    public static int verify(Path logFile) throws IOException {
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        String expected = null;
        int n = 0;
        for (String line : lines) {
            if (line.isBlank()) {
                continue;
            }
            n++;
            try {
                String prev = JSON.readTree(line).path("prev").asText(null);
                if (prev == null || (expected != null && !prev.equals(expected))) {
                    return n;
                }
            } catch (JsonProcessingException e) {
                return n;
            }
            expected = sha256(line);
        }
        return 0;
    }

    private static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
