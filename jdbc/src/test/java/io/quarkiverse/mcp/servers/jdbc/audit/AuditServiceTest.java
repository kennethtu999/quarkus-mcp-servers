package io.quarkiverse.mcp.servers.jdbc.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

class AuditServiceTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final String SENTINEL = "AUDIT-SENTINEL-pw-9981";

    @TempDir
    Path tmp;

    Path logs;
    AuditService audit;

    @BeforeEach
    void setUp() {
        logs = tmp.resolve("logs");
        audit = new AuditService(logs);
    }

    private List<JsonNode> read(Path f) throws Exception {
        return Files.readAllLines(f).stream().filter(l -> !l.isBlank()).map(l -> {
            try {
                return JSON.readTree(l);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }).toList();
    }

    private AuditEvent sample(String tool) {
        return AuditEvent.of(tool).requestId("req-1").actor("local-user").profile("c3d4e5f6", "ORA-SIT").operation("UPDATE")
                .target("APP.ORDERS").policyVersion("sha256:abc").decision("ALLOW").result("COMMITTED").affectedRows(1)
                .durationMs(12);
    }

    @Test
    void writesTheFieldsFromThePlanAsOneJsonObjectPerLine() throws Exception {
        audit.record(sample("db_execute_change"));
        List<JsonNode> lines = read(audit.file());
        assertThat(lines).hasSize(1);
        JsonNode n = lines.get(0);
        assertThat(n.get("tool").asText()).isEqualTo("db_execute_change");
        assertThat(n.get("profileLabel").asText()).isEqualTo("ORA-SIT");
        assertThat(n.get("decision").asText()).isEqualTo("ALLOW");
        assertThat(n.get("affectedRows").asLong()).isEqualTo(1);
        assertThat(n.get("timestamp").asText()).isNotBlank();
        assertThat(n.get("prev").asText()).isEqualTo("genesis");
    }

    @Test
    void theFileAndDirectoryAreOwnerOnly() throws Exception {
        audit.record(sample("db_query"));
        FilePerms.verifyDir(logs);
        FilePerms.verifyFile(audit.file());
    }

    // ---- A03: no secrets in the log ----

    @Test
    void secretsAndConnectionStringsInFreeTextNeverReachTheFile() throws Exception {
        audit.record(
                sample("db_query").detail("failed: jdbc:postgresql://pg.example.internal:5432/db?user=u&password=" + SENTINEL));
        audit.record(sample("db_query").detail("password=" + SENTINEL + " and token: " + SENTINEL));
        audit.record(sample("db_query").detail("Authorization: " + SENTINEL));
        audit.record(sample("db_query").target("jdbc:oracle:thin:@//ora:1521/svc").detail("pwd=" + SENTINEL));

        String all = Files.readString(audit.file());
        assertThat(all).doesNotContain(SENTINEL).doesNotContain("pg.example.internal").doesNotContain("jdbc:postgresql")
                .doesNotContain("jdbc:oracle").doesNotContain("ora:1521");
        assertThat(all).contains("[jdbc-url-removed]").contains("[removed]");
    }

    @Test
    void sqlIsRecordedAsAHashNeverAsText() throws Exception {
        String sql = "SELECT * FROM APP.ORDERS WHERE SSN = '123-45-6789'";
        audit.record(sample("db_query").sqlHash(AuditService.hashSql(sql)));
        String all = Files.readString(audit.file());
        assertThat(all).doesNotContain("123-45-6789").doesNotContain("SELECT").contains("sqlHash");
        assertThat(AuditService.hashSql(sql))
                .isEqualTo(AuditService.hashSql("  SELECT   *\nFROM APP.ORDERS WHERE SSN = '123-45-6789' "));
        assertThat(AuditService.hashSql(sql)).isNotEqualTo(AuditService.hashSql(sql + " " + "AND 1=1"));
    }

    @Test
    void controlCharactersCannotForgeAnExtraLogLine() throws Exception {
        audit.record(sample("db_query").detail("ok\n{\"tool\":\"forged\",\"decision\":\"ALLOW\"}\r\ndone"));
        List<String> raw = Files.readAllLines(audit.file());
        assertThat(raw).hasSize(1);
        assertThat(read(audit.file())).hasSize(1);
        assertThat(read(audit.file()).get(0).get("tool").asText()).isEqualTo("db_query");
    }

    @Test
    void longValuesAreBounded() throws Exception {
        audit.record(sample("db_query").detail("x".repeat(100_000)));
        assertThat(Files.size(audit.file())).isLessThan(2_000);
    }

    // ---- tamper evidence ----

    @Test
    void anIntactChainVerifies() throws Exception {
        for (int i = 0; i < 20; i++) {
            audit.record(sample("db_query").detail("n" + i));
        }
        assertThat(AuditService.verify(audit.file())).isZero();
    }

    @Test
    void editingAMiddleLineIsDetectedAtTheFollowingLine() throws Exception {
        for (int i = 0; i < 10; i++) {
            audit.record(sample("db_query").detail("n" + i));
        }
        List<String> lines = Files.readAllLines(audit.file());
        lines.set(4, lines.get(4).replace("ALLOW", "DENY "));
        Files.write(audit.file(), lines);
        assertThat(AuditService.verify(audit.file())).isEqualTo(6);
    }

    @Test
    void removingAMiddleLineIsDetected() throws Exception {
        for (int i = 0; i < 10; i++) {
            audit.record(sample("db_query").detail("n" + i));
        }
        List<String> lines = new java.util.ArrayList<>(Files.readAllLines(audit.file()));
        lines.remove(5);
        Files.write(audit.file(), lines);
        assertThat(AuditService.verify(audit.file())).isEqualTo(6);
    }

    @Test
    void reorderingLinesIsDetected() throws Exception {
        for (int i = 0; i < 6; i++) {
            audit.record(sample("db_query").detail("n" + i));
        }
        List<String> lines = new java.util.ArrayList<>(Files.readAllLines(audit.file()));
        java.util.Collections.swap(lines, 2, 3);
        Files.write(audit.file(), lines);
        assertThat(AuditService.verify(audit.file())).isGreaterThan(0);
    }

    @Test
    void aNewInstanceContinuesTheChainAcrossRestarts() throws Exception {
        audit.record(sample("db_query").detail("before"));
        new AuditService(logs).record(sample("db_query").detail("after restart"));
        assertThat(AuditService.verify(audit.file())).isZero();
        assertThat(read(audit.file())).hasSize(2);
    }

    // ---- rotation ----

    @Test
    void rotationKeepsTheChainContinuousAndLimitsHowManyFilesRemain() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-10-30T10:00:00Z"), ZoneId.of("UTC"));
        AuditService small = new AuditService(logs, clock, 600, 3);
        for (int i = 0; i < 60; i++) {
            small.record(sample("db_query").detail("entry-" + i));
        }
        List<Path> rotated;
        try (Stream<Path> s = Files.list(logs)) {
            rotated = s.filter(p -> p.getFileName().toString().startsWith("audit-")).sorted().toList();
        }
        assertThat(rotated).hasSizeLessThanOrEqualTo(3);
        assertThat(rotated).isNotEmpty();
        for (Path p : rotated) {
            assertThat(AuditService.verify(p)).as(p.getFileName().toString()).isZero();
            FilePerms.verifyFile(p);
        }
        assertThat(AuditService.verify(small.file())).isZero();

        // the first line of the active file points at the last line of the newest rotated file
        String firstPrev = read(small.file()).get(0).get("prev").asText();
        assertThat(firstPrev).isNotEqualTo("genesis").hasSize(64);
    }

    @Test
    void retentionDeletesTheOldestFilesNeverTheNewestEvenWhenTheClockRepeats() throws Exception {
        // A pinned clock makes every rotated file carry the same timestamp; ordering must not depend on it.
        Clock clock = Clock.fixed(Instant.parse("2026-10-30T10:00:00Z"), ZoneId.of("UTC"));
        AuditService small = new AuditService(logs, clock, 600, 3);
        int total = 80;
        for (int i = 0; i < total; i++) {
            small.record(sample("db_query").detail("entry-" + i));
        }
        List<Path> rotated;
        try (Stream<Path> s = Files.list(logs)) {
            rotated = s.filter(p -> p.getFileName().toString().startsWith("audit-")).sorted().toList();
        }
        assertThat(rotated).hasSize(3);

        // every surviving entry number, in file order
        java.util.ArrayList<Integer> kept = new java.util.ArrayList<>();
        for (Path p : rotated) {
            for (JsonNode n : read(p)) {
                kept.add(Integer.parseInt(n.get("detail").asText().substring("entry-".length())));
            }
        }
        for (JsonNode n : read(small.file())) {
            kept.add(Integer.parseInt(n.get("detail").asText().substring("entry-".length())));
        }
        assertThat(kept).as("surviving entries are strictly increasing, i.e. in creation order").isSorted();
        assertThat(kept).as("the newest entry is always kept").contains(total - 1);
        assertThat(kept.get(kept.size() - 1)).isEqualTo(total - 1);
        // what survives is one contiguous run ending at the newest entry: nothing newer was deleted in favour of older
        for (int i = 1; i < kept.size(); i++) {
            assertThat(kept.get(i)).isEqualTo(kept.get(i - 1) + 1);
        }

        // and the chain is unbroken from the oldest kept file through the active one
        for (int i = 1; i < rotated.size(); i++) {
            String prevFirst = read(rotated.get(i)).get(0).get("prev").asText();
            List<String> lines = Files.readAllLines(rotated.get(i - 1));
            String lastOfPrevious = AuditServiceTest.sha256(lines.get(lines.size() - 1));
            assertThat(prevFirst).isEqualTo(lastOfPrevious);
        }
    }

    static String sha256(String s) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- failure behaviour ----

    @Test
    void anUnwritableLogDirectoryNeverThrowsIntoTheCaller() throws Exception {
        Files.createDirectories(logs);
        Files.setPosixFilePermissions(logs, PosixFilePermissions.fromString("r-x------"));
        try {
            assertThatCode(() -> audit.record(sample("db_query"))).doesNotThrowAnyException();
        } finally {
            Files.setPosixFilePermissions(logs, PosixFilePermissions.fromString("rwx------"));
        }
    }

    @Test
    void concurrentWritersProduceAValidChain() throws Exception {
        Thread[] threads = new Thread[8];
        for (int t = 0; t < threads.length; t++) {
            int id = t;
            threads[t] = new Thread(() -> {
                for (int i = 0; i < 25; i++) {
                    audit.record(sample("db_query").detail("t" + id + "-" + i));
                }
            });
            threads[t].start();
        }
        for (Thread t : threads) {
            t.join();
        }
        assertThat(read(audit.file())).hasSize(200);
        assertThat(AuditService.verify(audit.file())).isZero();
    }
}
