package io.quarkiverse.mcp.servers.jdbc.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Pins the dialect facts that cannot be exercised against the in-memory H2 used elsewhere in the unit tests. These must
 * also be confirmed against real Db2 / PostgreSQL / Oracle instances (see docs/RISKS.md, WP1.2).
 */
class DialectTest {

    @Test
    void onlyOracleNeedsAnExplicitReadOnlyTransactionStatement() {
        assertThat(DbDialect.of(DbType.ORACLE).readOnlyTransactionStatement()).isEqualTo("SET TRANSACTION READ ONLY");
        assertThat(DbDialect.of(DbType.POSTGRESQL).readOnlyTransactionStatement()).isNull();
        assertThat(DbDialect.of(DbType.DB2_LUW).readOnlyTransactionStatement()).isNull();
    }

    @Test
    void driverClassNamesAndUrlPrefixesMatchTheDrivers() {
        assertThat(DbDialect.of(DbType.POSTGRESQL).driverClassName()).isEqualTo("org.postgresql.Driver");
        assertThat(DbDialect.of(DbType.ORACLE).driverClassName()).isEqualTo("oracle.jdbc.OracleDriver");
        assertThat(DbDialect.of(DbType.DB2_LUW).driverClassName()).isEqualTo("com.ibm.db2.jcc.DB2Driver");
        assertThat(DbDialect.of(DbType.POSTGRESQL).urlPrefix()).isEqualTo("jdbc:postgresql:");
        assertThat(DbDialect.of(DbType.ORACLE).urlPrefix()).isEqualTo("jdbc:oracle:thin:");
        assertThat(DbDialect.of(DbType.DB2_LUW).urlPrefix()).isEqualTo("jdbc:db2:");
    }

    @Test
    void bundledDriversAreOnTheClassPathButDb2IsNot() {
        assertThat(DriverLoader.bundled("org.postgresql.Driver")).isNotNull();
        assertThat(DriverLoader.bundled("oracle.jdbc.OracleDriver")).isNotNull();
        // IBM JCC is licensed and not redistributed by default (docs: -Pbundle-db2).
        assertThatThrownBy(() -> DriverLoader.bundled("com.ibm.db2.jcc.DB2Driver"))
                .isInstanceOf(DriverLoader.DriverUnavailableException.class);
    }

    @Test
    void identifiersFoldTheWayEachDatabaseStoresThem() {
        assertThat(DbDialect.of(DbType.POSTGRESQL).normalizeIdentifier("Orders")).isEqualTo("orders");
        assertThat(DbDialect.of(DbType.ORACLE).normalizeIdentifier("Orders")).isEqualTo("ORDERS");
        assertThat(DbDialect.of(DbType.DB2_LUW).normalizeIdentifier("Orders")).isEqualTo("ORDERS");
    }

    @Test
    void quotingRefusesIdentifiersThatCouldEscapeTheQuotes() {
        for (DbType t : DbType.values()) {
            DbDialect d = DbDialect.of(t);
            assertThat(d.quote("ORDERS")).isEqualTo("\"ORDERS\"");
            assertThatThrownBy(() -> d.quote("A\"B")).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> d.quote("A\0B")).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void everyDialectHidesItsSystemSchemas() {
        assertThat(DbDialect.of(DbType.DB2_LUW).systemSchemas()).contains("SYSCAT", "SYSIBM", "SYSSTAT");
        assertThat(DbDialect.of(DbType.POSTGRESQL).systemSchemas()).contains("pg_catalog", "information_schema");
        assertThat(DbDialect.of(DbType.ORACLE).systemSchemas()).contains("SYS", "SYSTEM");
    }
}
