package io.quarkiverse.mcp.servers.jdbc.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.mcp.servers.jdbc.database.QueryExecutor.Result;

class QueryExecutorTest {

    Connection conn;

    @BeforeEach
    void setUp() throws Exception {
        conn = DriverManager.getConnection("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE ORDERS (ID INT PRIMARY KEY, STATUS VARCHAR(20), NOTE VARCHAR(100000), DATA BLOB)");
            st.execute("INSERT INTO ORDERS SELECT X, CASE WHEN MOD(X, 2) = 0 THEN 'EVEN' ELSE 'ODD' END, NULL, NULL "
                    + "FROM SYSTEM_RANGE(1, 1000)");
            st.execute("CREATE TABLE BIG (ID INT, NOTE VARCHAR(100000))");
            st.execute("INSERT INTO BIG SELECT X, REPEAT('x', 50000) FROM SYSTEM_RANGE(1, 200)");
        }
        conn.setAutoCommit(false);
        conn.commit();
    }

    @AfterEach
    void tearDown() throws Exception {
        conn.close();
    }

    private Result run(String sql, int limit) throws SQLException {
        return QueryExecutor.run(conn, DbType.POSTGRESQL, sql, List.of(), limit, 10);
    }

    // ---- A09: a 1,000 row result delivers at most 500 ----

    @Test
    void aThousandRowResultDeliversExactlyFiveHundredAndSaysTruncated() throws Exception {
        Result r = run("SELECT ID FROM ORDERS ORDER BY ID", 500);
        assertThat(r.rows()).hasSize(500);
        assertThat(r.truncated()).isTrue();
        assertThat(r.truncationReason()).isEqualTo("ROW_LIMIT");
        assertThat(r.rows().get(0).get("ID")).isEqualTo(1);
        assertThat(r.rows().get(499).get("ID")).isEqualTo(500);
    }

    @Test
    void theExtraRowUsedToDetectTruncationIsNeverReturned() throws Exception {
        Result r = run("SELECT ID FROM ORDERS ORDER BY ID", 500);
        assertThat(r.rows()).extracting(m -> m.get("ID")).doesNotContain(501);
        assertThat(r.rows()).extracting(m -> m.get("ID")).doesNotHaveDuplicates();
    }

    // ---- A10: asking for more than 500 never gets more than 500 ----

    @Test
    void aLimitAboveFiveHundredIsClampedInsideTheExecutorToo() throws Exception {
        for (int huge : new int[] { 501, 1000, 100_000, Integer.MAX_VALUE }) {
            Result r = run("SELECT ID FROM ORDERS ORDER BY ID", huge);
            assertThat(r.rows()).as("limit " + huge).hasSize(500);
            assertThat(r.truncated()).isTrue();
        }
    }

    @Test
    void zeroOrNegativeLimitsStillReturnAtLeastOneRowNeverEverything() throws Exception {
        for (int bad : new int[] { 0, -1, Integer.MIN_VALUE }) {
            Result r = run("SELECT ID FROM ORDERS ORDER BY ID", bad);
            assertThat(r.rows()).as("limit " + bad).hasSize(1);
        }
    }

    @Test
    void truncatedIsFalseWhenTheResultFitsExactly() throws Exception {
        Result exact = run("SELECT ID FROM ORDERS WHERE ID <= 500 ORDER BY ID", 500);
        assertThat(exact.rows()).hasSize(500);
        assertThat(exact.truncated()).as("exactly 500 rows is not truncated").isFalse();

        Result fewer = run("SELECT ID FROM ORDERS WHERE ID <= 10", 500);
        assertThat(fewer.rows()).hasSize(10);
        assertThat(fewer.truncated()).isFalse();

        assertThat(run("SELECT ID FROM ORDERS WHERE ID < 0", 500).rows()).isEmpty();
    }

    @Test
    void aSmallerRequestedLimitIsHonoured() throws Exception {
        Result r = run("SELECT ID FROM ORDERS ORDER BY ID", 7);
        assertThat(r.rows()).hasSize(7);
        assertThat(r.truncated()).isTrue();
    }

    // ---- A24: large values and output size ----

    @Test
    void hugeCellsAreCutAndMarked() throws Exception {
        Result r = run("SELECT NOTE FROM BIG WHERE ID = 1", 10);
        String note = (String) r.rows().get(0).get("NOTE");
        assertThat(note.length()).isLessThan(QueryExecutor.MAX_CELL_CHARS + 100);
        assertThat(note).contains("truncated");
    }

    @Test
    void totalOutputIsCappedEvenWhenTheRowCountIsSmall() throws Exception {
        // 12*12*12 = 1728 candidate rows of ~12 KB each: the 2 MiB size cap, not the 500 row cap, must be what stops it.
        Result r = run(
                "SELECT a.NOTE AS A, b.NOTE AS B, c.NOTE AS C FROM BIG a, BIG b, BIG c WHERE a.ID <= 12 AND b.ID <= 12 AND c.ID <= 12",
                500);
        long approx = r.rows().stream().mapToLong(m -> m.values().stream().mapToLong(v -> String.valueOf(v).length()).sum())
                .sum();
        assertThat(r.truncated()).isTrue();
        assertThat(r.truncationReason()).isEqualTo("SIZE_LIMIT");
        assertThat(r.rows().size()).isLessThan(500);
        assertThat(approx).isLessThanOrEqualTo(QueryExecutor.MAX_OUTPUT_BYTES);
    }

    @Test
    void binaryContentIsReportedByLengthNotSent() throws Exception {
        try (Statement st = conn.createStatement()) {
            st.execute("UPDATE ORDERS SET DATA = X'DEADBEEF' WHERE ID = 1");
            conn.commit();
        }
        Result r = run("SELECT DATA FROM ORDERS WHERE ID = 1", 10);
        assertThat(r.rows().get(0).get("DATA")).isEqualTo("<binary 4 bytes>");
    }

    @Test
    void duplicateColumnLabelsDoNotOverwriteEachOther() throws Exception {
        Result r = run("SELECT ID, ID, STATUS FROM ORDERS WHERE ID = 1", 10);
        assertThat(r.columns()).containsExactly("ID", "ID_2", "STATUS");
        assertThat(r.rows().get(0)).hasSize(3);
    }

    // ---- parameters ----

    @Test
    void parametersAreBoundNotConcatenated() throws Exception {
        Result r = QueryExecutor.run(conn, DbType.POSTGRESQL, "SELECT ID FROM ORDERS WHERE STATUS = ? AND ID < ? ORDER BY ID",
                List.of("EVEN", 10), 100, 10);
        assertThat(r.rows()).extracting(m -> m.get("ID")).containsExactly(2, 4, 6, 8);

        // a classic injection string is just a value that matches nothing
        Result inj = QueryExecutor.run(conn, DbType.POSTGRESQL, "SELECT ID FROM ORDERS WHERE STATUS = ?",
                List.of("x' OR '1'='1"), 100, 10);
        assertThat(inj.rows()).isEmpty();
        assertThat(run("SELECT COUNT(*) AS N FROM ORDERS", 1).rows().get(0).get("N")).isEqualTo(1000L);
    }

    @Test
    void unsupportedParameterTypesAreRejected() {
        assertThatThrownBy(() -> QueryExecutor.run(conn, DbType.POSTGRESQL, "SELECT ID FROM ORDERS WHERE ID = ?",
                List.of(new Object()), 10, 10)).isInstanceOf(SQLException.class);
    }

    // ---- read-only and rollback behaviour ----

    @Test
    void theConnectionStateIsRestoredAndNothingIsCommitted() throws Exception {
        assertThat(conn.isReadOnly()).isFalse();
        assertThat(conn.getAutoCommit()).isFalse();
        run("SELECT ID FROM ORDERS WHERE ID = 1", 10);
        assertThat(conn.isReadOnly()).isFalse();
        assertThat(conn.getAutoCommit()).isFalse();
    }

    @Test
    void aWriteSmuggledPastTheGuardIsStoppedByTheReadOnlyConnection() throws Exception {
        // H2 enforces read-only connections for DML; this is the second layer if SqlGuard were ever bypassed.
        assertThatThrownBy(() -> run("UPDATE ORDERS SET STATUS = 'HACKED'", 10)).isInstanceOf(SQLException.class);
        conn.setAutoCommit(false);
        try (Statement st = conn.createStatement();
                var rs = st.executeQuery("SELECT COUNT(*) FROM ORDERS WHERE STATUS = 'HACKED'")) {
            rs.next();
            assertThat(rs.getInt(1)).isZero();
        }
    }

    @Test
    void failuresStillLeaveTheConnectionUsable() throws Exception {
        assertThatThrownBy(() -> run("SELECT NOPE FROM ORDERS", 10)).isInstanceOf(SQLException.class);
        assertThat(run("SELECT ID FROM ORDERS WHERE ID = 3", 10).rows()).hasSize(1);
    }

    @Test
    void timeoutAbortsALongQuery() throws Exception {
        long start = System.nanoTime();
        assertThatThrownBy(() -> QueryExecutor.run(conn, DbType.POSTGRESQL,
                "SELECT COUNT(*) FROM SYSTEM_RANGE(1, 2000000000) a, SYSTEM_RANGE(1, 2000000000) b", List.of(), 10, 1))
                .isInstanceOf(SQLException.class);
        assertThat((System.nanoTime() - start) / 1_000_000_000L).isLessThan(15);
    }
}
