# Security model

This document states what the gateway protects against, how, and - just as importantly - what it does **not** protect against.

## Threat model

The assistant (an LLM, possibly manipulated by text it reads, i.e. prompt injection) is **untrusted**. The person running the
gateway on their own workstation is **trusted**. The database account is the final authority.

### What the gateway enforces

| Property | Mechanism |
|---|---|
| The assistant never sees credentials | Profiles are decrypted only inside the server process; no tool returns URLs, users or passwords; error messages never echo driver text, SQL or hosts; the audit log scrubs `jdbc:` strings and `password=` style values. |
| No secret in process arguments | No CLI option takes a password, token or key; passwords come from the terminal or stdin. A test fails if such an option is ever added. |
| At most 500 rows returned | `MAX_READ_ROWS_HARD_LIMIT` is a code constant. A policy can only lower it; a request for more is reduced and reported. The executor clamps again on its own. The 501st row is used only to set `truncated`, never returned. A 2 MiB output cap and per-cell truncation apply as well. |
| Only plain `SELECT` is run | `SqlGuard` is a default-deny allow-list over the parsed statement: one statement, no comments or hints, no locking clauses, no `INTO`, no DML in CTEs, functions only from a per-database list, system schemas and database links refused, nested sub-selects checked the same way. Anything unrecognised is rejected. |
| Reads cannot change data even if the guard were wrong | Read-only transaction (and Oracle `SET TRANSACTION READ ONLY`), query timeout, always rolled back. |
| Writes are structured | Table and column names are resolved from JDBC metadata, values are bound parameters, conditions are typed equality. UPDATE/DELETE need a condition. Generated columns cannot be written. |
| Writes need a human | A one-time token only `ai-db-mcp approve` can mint (needs a real terminal and a typed code). Records are HMAC-signed with a key derived from the master key. The token is bound to profile, operation, policy version, data fingerprint and expiry, is single-use, and is revoked after five wrong guesses. |
| Data cannot change between preview and execute unnoticed | Rows are locked, a fingerprint of the affected rows and the row count are re-verified, and the change commits only if the number of rows changed equals the number previewed. |
| Fail closed | Missing/invalid/stale policy, disabled profile, unknown profile, unavailable driver: the operation is refused. Nothing falls back to a more permissive state. |
| One database down does not affect others | One connection pool per profile, with isolated back-off. |
| Secrets at rest | `profiles.enc` is AES-256-GCM with the header authenticated; the master key lives in the OS key store (or an explicit owner-only key file outside the config directory). A wrong or missing key never causes the file to be rewritten. Files are 0600, directories 0700. |
| Tamper evidence | The audit log is hash-chained; policy activations and approvals are HMAC-signed. |

### What the gateway does NOT protect against

* **A compromised workstation or user account.** Anything running as you can read your files and key store, and can edit the
  policy YAML (it will then be `POLICY_STALE` until *you* reload, which protects against the assistant, not against malware that
  also runs `policy reload`). Encryption at rest does not help against a process with your privileges.
* **An assistant that also has file or shell tools.** If the same assistant can read your config directory, run commands, or
  edit `permissions/*.yaml`, the controls above are bypassed. **Do not give the assistant filesystem or shell access to the
  config directory, or to the machine's key store.** The gateway cannot enforce this for you.
* **An overpowered database account.** The policy only *narrows* what the account may do. Give the account the minimum grants
  (ideally SELECT only for read-only profiles, no DDL, no admin, no cross-environment access). `SELECT` can still call
  side-effecting functions that are not on the allow-list only if the parser disagrees with the database; the read-only
  transaction and the account's grants are the backstop for that.
* **Expensive queries.** 500 rows is a *return* limit, not a scan limit. The timeout and database-side resource limits bound the load.
* **Sensitive data in permitted tables.** Whatever the assistant is allowed to read goes to the model provider. Restrict
  visible schemas/views/columns in the database, or mask data there.
* **Multiple users or a shared server.** This is a single-user, local, stdio design. Sharing it needs per-user authentication
  and a policy service this does not have.
* **Audit log forgery by someone who can rewrite the whole file.** The hash chain detects edits to individual lines, not
  deletion from the very start or end of a file or a complete rewrite. Ship the log to an immutable store for formal audit.
* **Production.** Not designed, reviewed or tested for production data.

## Assumptions to verify in your environment

The following were implemented from documentation and unit-tested against H2 only; see `RISKS.md` for the full list. Confirm
them against your real servers before trusting the gateway with anything that matters.

* Oracle `SET TRANSACTION READ ONLY`, `SELECT ... FOR UPDATE` locking, and the per-database function allow-lists.
* TLS URL forms for Db2 (`sslConnection=true`) and Oracle (`@tcps://`).
* That your JDBC drivers report generated/identity columns, so they are refused.
* macOS Keychain behaviour with an unsigned JVM.

## Reporting

If you find a way for the assistant to read a credential, exceed 500 rows, run a statement other than a single `SELECT` through
`db_query`, change data without a human-issued token, or write outside the policy, treat it as a security bug.
