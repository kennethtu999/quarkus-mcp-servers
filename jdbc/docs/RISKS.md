# Risks and open items (plan v2.3, section 17)

| Risk / open item | Impact | Mitigation | Owner work package |
|---|---|---|---|
| Db2 LUW version / JCC compatibility unknown | Driver mismatch or SQL dialect differences | Live PoC first; JCC is only bundled by the internal `-Pbundle-db2` build, never by default | WP1.2 |
| Oracle / Db2 identifier case and synonyms | Whitelist misjudgement | JDBC metadata + dialect tests; unknown means deny | WP4.2, WP6.1 |
| OS key store availability | Profiles cannot be decrypted | macOS first; Linux without a keyring requires an explicit key file; never silently downgrade | WP3.2 |
| macOS Keychain prompts for an unsigned JVM | Unusable start-up | Verify on day one of the secret work | WP3.2 |
| Local user can edit policy YAML | Not suitable for multi-user isolation | Phase 1 is single trusted local user; shared mode needs central policy | out of scope |
| SQL parser does not cover every dialect | Unsafe SQL judged safe | Default-deny AST walker, restricted subset, read-only transaction, least-privilege DB grants | WP5.1 |
| 500 rows can still be expensive to compute | DB load | Query timeout, read-only grants, output size cap | WP5.2 |
| Data changes between preview and execute | Unintended rows modified | Row lock, fingerprint re-check, row-count re-check | WP6.3 |
| Unsafe JDBC URL parameters | Redirect to other hosts, weakened TLS | Per-dialect property allowlist, TLS verification on by default | WP1.1 |
| Profile rename leaves YAML inconsistent | Wrong policy applied | Immutable `profileId`, atomic move with rollback | WP2.1 |
| AI has other filesystem tools | AI could edit policy files | OS ACLs; do not expose the config directory to AI tools | operations |
| Upstream merge re-enables dangerous tools | Policy bypass | `ToolSurfaceTest` | WP0.1 |
| Pre-release dependencies (Quarkus 3.35.0.CR1) | Instability | Pin versions; revisit at GA | WP0.1 |

## Items that need a real Db2 / Oracle / PostgreSQL to confirm

These are implemented but could only be unit-tested against H2 on the development machine (no container runtime was
available). Each must be run once against the real engines before the gateway is used with real data (plan P1/P7).

| Item | What to confirm | Where |
|---|---|---|
| Oracle `SET TRANSACTION READ ONLY` | Accepted, and a write inside the transaction is refused | `OracleDialect.readOnlyTransactionStatement`, `QueryExecutor` |
| `SELECT ... FOR UPDATE` for locking | Works on all three engines without a row-limit clause, inside a manual-commit transaction | `DmlBuilder.lockAndRead` |
| Db2 `jdbc:db2://host:port/DB:sslConnection=true;` | Connects and verifies the server certificate | `Db2Dialect`, `JdbcUrlGuard` |
| Oracle `jdbc:oracle:thin:@tcps://host:port/service` | TLS connects with the wallet/truststore the JVM is configured with | `OracleDialect`, `JdbcUrlGuard` |
| `DatabaseMetaData.getSearchStringEscape()` | Returns the escape character on each driver, so `A_P` matches only itself | `MetadataService.exact` |
| IBM JCC loaded from `drivers/` | Pinned jar loads and connects (`DriverLoader`) | `DriverLoader` |
| Function allow-lists | Each listed function exists with the expected semantics in that engine | `FunctionAllowlists` |
| `IS_AUTOINCREMENT` / `IS_GENERATEDCOLUMN` | Reported by each driver so generated columns are refused | `MetadataService.columns` |
| macOS Keychain with an unsigned JVM | Whether a prompt appears and how it behaves headless | `KeyringMasterKeyProvider` |
| Profile change detection on a shared/network file system | A running server notices `profiles.enc` changes by inode+size+mtime (content hash if the file system has no file key); verify on the file system you use | `ProfileSync` |

