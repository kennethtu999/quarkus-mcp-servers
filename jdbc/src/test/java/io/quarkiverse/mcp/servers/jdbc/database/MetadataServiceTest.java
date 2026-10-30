package io.quarkiverse.mcp.servers.jdbc.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MetadataServiceTest {

    Connection conn;

    @BeforeEach
    void setUp() throws Exception {
        conn = DriverManager.getConnection("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
        try (Statement st = conn.createStatement()) {
            // names chosen so that "_" in one of them is a wildcard that matches the others
            st.execute("CREATE SCHEMA APP");
            st.execute("CREATE SCHEMA A1P");
            st.execute("CREATE SCHEMA A_P");
            st.execute("CREATE TABLE APP.T1 (X INT)");
            st.execute("CREATE TABLE A1P.T2 (X INT)");
            st.execute("CREATE TABLE A_P.T3 (X INT)");
            st.execute("CREATE TABLE APP.ORDER_LINES (X INT)");
            st.execute("CREATE TABLE APP.ORDERXLINES (X INT)");
            st.execute("CREATE TABLE APP.ORDERS_ARCHIVE (Y INT)");
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        conn.close();
    }

    @Test
    void anUnderscoreInASchemaNameMatchesOnlyThatSchema() throws Exception {
        var page = MetadataService.listTables(conn, DbType.ORACLE, "A_P", null, null);
        assertThat(page.tables()).extracting(t -> t.get("schema") + "." + t.get("name")).containsExactly("A_P.T3");
    }

    @Test
    void anUnderscoreInATableNameMatchesOnlyThatTable() throws Exception {
        List<Map<String, Object>> cols = MetadataService.describeTable(conn, DbType.ORACLE, "APP", "ORDER_LINES");
        assertThat(cols).extracting(c -> c.get("name")).containsExactly("X");

        // a table that only matches because "_" was treated as a wildcard must not be reachable
        assertThat(MetadataService.describeTable(conn, DbType.ORACLE, "APP", "ORDER_LINE")).isEmpty();
        assertThat(MetadataService.describeTable(conn, DbType.ORACLE, "APP", "ORDER_LINES").size()).isEqualTo(1);
    }

    @Test
    void resolveTableIsExactNotAmbiguousBecauseOfWildcards() throws Exception {
        assertThat(MetadataService.resolveTable(conn, DbType.ORACLE, "APP", "ORDER_LINES")).containsExactly("APP",
                "ORDER_LINES");
        assertThat(MetadataService.resolveTable(conn, DbType.ORACLE, "A_P", "T3")).containsExactly("A_P", "T3");
        assertThat(MetadataService.resolveTable(conn, DbType.ORACLE, "APP", "NOPE")).isNull();
        assertThat(MetadataService.resolveTable(conn, DbType.ORACLE, "A_P", "T1")).as("T1 lives in APP, not A_P").isNull();
    }

    @Test
    void listTablesWithoutASchemaStillWorksAndPaginates() throws Exception {
        var all = MetadataService.listTables(conn, DbType.ORACLE, null, 1, 200);
        assertThat(all.tables()).extracting(t -> t.get("name")).contains("T1", "T2", "T3", "ORDER_LINES");
        var paged = MetadataService.listTables(conn, DbType.ORACLE, "APP", 2, 2);
        assertThat(paged.page()).isEqualTo(2);
        assertThat(paged.tables()).hasSize(2);
        assertThat(paged.total()).isEqualTo(4);
        assertThat(MetadataService.listTables(conn, DbType.ORACLE, "APP", 99, 2).tables()).isEmpty();
    }

    @Test
    void pageSizeAndPageNumberAreClamped() throws Exception {
        assertThat(MetadataService.listTables(conn, DbType.ORACLE, "APP", -5, -5).pageSize()).isEqualTo(1);
        assertThat(MetadataService.listTables(conn, DbType.ORACLE, "APP", -5, -5).page()).isEqualTo(1);
        assertThat(MetadataService.listTables(conn, DbType.ORACLE, "APP", 1, 100_000).pageSize())
                .isEqualTo(MetadataService.MAX_PAGE_SIZE);
    }

    @Test
    void wildcardAndInjectionShapedNamesAreRejectedBeforeAnyMetadataCall() {
        for (String bad : new String[] { "%", "A%", "A B", "A;B", "A'B", "A\"B", "../x", "A-B", "" }) {
            assertThatThrownBy(() -> MetadataService.requireName(bad, "schema")).as("[" + bad + "]")
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> MetadataService.listTables(conn, DbType.ORACLE, "%", null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void escapeBuildsExactPatterns() throws Exception {
        var md = conn.getMetaData();
        assertThat(MetadataService.exact(md, "ORDER_LINES")).isEqualTo("ORDER\\_LINES");
        assertThat(MetadataService.exact(md, "PLAIN")).isEqualTo("PLAIN");
        assertThat(MetadataService.exact(md, "A_B_C")).isEqualTo("A\\_B\\_C");
    }
}
