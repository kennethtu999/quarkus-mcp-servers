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
