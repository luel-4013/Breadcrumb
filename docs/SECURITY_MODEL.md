# Breadcrumb security model

**Status:** current for the Leadline merge (Phases 0–8, 2026-11-08).
**Deployment assumption:** one user, one machine, loopback only, no login.

This document states what Breadcrumb protects, what it does not protect, and
which controls must remain true. It is the reference for the release checklist
and the rollback plan.

---

## 1. Assets and trust boundaries

| Asset | Location | Protection |
|---|---|---|
| Evidence captures | `paste` rows in SQLite | SHA-256 content seal + linear hash chain |
| Programs, targets, entities, findings | SQLite | Local file permissions; backups |
| Header-profile secrets | `headerprofile.headers`, `.proxy` | Fernet encryption at rest (`enc:v1:`) |
| Encryption key | `<BREADCRUMB_DB_PATH>.key` or `BREADCRUMB_KEY_FILE` | Mode `0600`; never in the DB |
| NVD cache | `breadcrumb.nvd.json` by default | Local file; no credentials |
| Import manifest | `<BREADCRUMB_DB_PATH>.leadline-import.json` | Mode `0600`; contains IDs and source path, not header values |
| Leadline source DB | User-controlled path | Opened read-only; never written |

Trust boundary: the local OS user and the loopback HTTP port. Breadcrumb does
not provide multi-user isolation, roles, audit logs or network authentication.

---

## 2. Local-only HTTP boundary

Defaults:

- `BREADCRUMB_HOST=127.0.0.1`, `BREADCRUMB_PORT=8787`.
- Host allowlist: `127.0.0.1`, `localhost`, `::1`, plus
  `BREADCRUMB_ALLOWED_HOSTS` (comma-separated).
- Cross-origin writes rejected via `Origin` and `Sec-Fetch-Site` checks.
- HTML form posts require a CSRF token (`bc_csrf` cookie + hidden field or
  `x-csrf-token` header).
- SQLite runs with WAL, `busy_timeout=30000`, `foreign_keys=ON` and
  `secure_delete=ON`.

**Not protected:** DNS rebinding that resolves an allowed hostname to a
non-loopback address, a compromised local browser, a malicious local process,
or anyone who can reach the port if you bind to `0.0.0.0`. Keep the default
bind and do not port-forward it.

---

## 3. Scope guard (SSRF controls)

Every native collector and adapter calls the same `ScopeGuard` before opening a
connection or spawning a process.

Rules:

- Unknown, out-of-scope and excluded targets **fail closed**.
- Private and loopback targets are **allowed with a visible warning**
  (`BREADCRUMB_ALLOW_PRIVATE_TARGETS` defaults on, per owner decision Q2).
- Metadata, link-local, multicast, unspecified and reserved addresses are
  **always hard-blocked**, even if a scope rule would include them.
  This includes `169.254.0.0/16`, `fe80::/10` and cloud metadata hostnames.
- DNS resolution is pinned for native HTTP collectors; all resolved addresses
  are checked before the request.
- Redirects are re-checked against scope; an out-of-scope redirect is a
  permanent failure, not a retry.
- Configured proxies are treated as a scope bypass for native collectors and
  fail permanently.
- CIDR targets must be wholly contained in scope; overlap with a blocked or
  excluded range fails closed.

Residual risk: an external tool resolves names itself. Preflight and pinned
`-resolve` options reduce but cannot eliminate the gap between the guard’s
decision and the tool’s socket. `BREADCRUMB_STRICT_MODE=1` disables adapters
that cannot be pinned. The deployment control is an egress firewall or
network namespace.

---

## 4. Executor and external tools

- Executor default: **off** (`BREADCRUMB_EXECUTOR=off`).
- Durable worker claims native collectors only, unless
  `BREADCRUMB_EXTERNAL_TOOLS=1`.
- Adapter jobs can still be run explicitly with **Run now**,
  `breadcrumb collect --run-now`, or the API run endpoint.
- External tools run with:
  - argv lists only (`shell=False`);
  - a fixed option schema, never a passthrough;
  - a fresh process group;
  - SIGTERM then SIGKILL on cancel, timeout or output overflow;
  - a per-run timeout and output cap;
  - a temporary `cwd`/`HOME`;
  - an environment allowlist that excludes proxies and application secrets.
- Header profiles, cookies, authorization headers and proxy settings are
  **never** passed to an external tool. Authenticated scanning remains an
  external-runner workflow.
- Missing binaries are reported as “not installed”, not as an empty success.

Adapters are not sandboxed beyond these process/environment controls. Run the
worker as an unprivileged user on a dedicated host when scanning untrusted
targets.

---

## 5. Evidence integrity

- Every sealed capture stores `content_sha256` and
  `chain_hash = sha256(f"{prev_chain or 'genesis'}:{content}")`.
- `chain_seq` is 1-based and unique; the `evidencechain` singleton stores the
  head and length.
- Writes use `BEGIN IMMEDIATE` to prevent chain forks.
- `/api/v1/verify` recomputes the chain offline and reports broken links,
  forks, gaps from deleted programs, and unsealed legacy captures.
- Deleting a program removes its captures and is reported as a gap, not as
  tampering.
- The importer does not create captures. Imported findings/entities are marked
  with their Leadline source IDs; they are not presented as Breadcrumb-sealed
  network evidence.

---

## 6. Secrets at rest

- Header profiles use `EncryptedJSON`; the DB stores only `enc:v1:<token>`.
- Key resolution order:
  1. `BREADCRUMB_SECRET_KEYS` (comma-separated, newest first);
  2. `BREADCRUMB_SECRET_KEY`;
  3. `BREADCRUMB_KEY_FILE`;
  4. `<BREADCRUMB_DB_PATH>.key` (generated on first use, mode `0600`).
- If ciphertext exists and the key is missing, decryption raises a clear error;
  the key is never regenerated over existing ciphertext.
- Startup migrates legacy plaintext profiles, scrubs the pre-migration backup,
  and compacts the file/WAL.
- `breadcrumb secrets rotate` uses `MultiFernet` and archives previous keys at
  `<key>.old`.
- Backups must include the key file separately. Losing the key makes encrypted
  header values unrecoverable.
- Logs, errors, exports and AI prompts redact secret values.

**Residual risk:** the local UI/API intentionally shows decrypted header values
for the curl-copy workflow. Anyone with local UI access can read them.

---

## 7. Leadline import controls

- Source opened with SQLite `mode=ro` and `PRAGMA query_only=ON`.
- Source fingerprint (main file + WAL) checked before and after reading; a
  concurrent change aborts with instructions.
- `--dry-run` writes no rows and no manifest.
- Real import backs up the destination, enables maintenance mode, and commits
  in one transaction.
- Header profiles are written only through `EncryptedJSON`. If encryption is
  unavailable, the import aborts rather than storing plaintext.
- Malformed targets/scans/findings/graph nodes are reported and skipped; the
  rest of the import continues.
- Imported scans are terminal history rows (`runner=leadline.imported`,
  `attempts=1`, `max_attempts=1`). They cannot be claimed, retried or re-run.
- The imported program’s scope is empty, so new scans fail closed until the
  operator configures scope.
- The source database is never archived, deleted or rewritten by Breadcrumb.

---

## 8. What Breadcrumb does not protect

- Multi-user access control, SSO, roles or per-user audit.
- Encryption of the whole database, evidence captures or findings at rest.
- A compromised OS account, browser, editor, shell history or backup target.
- A malicious or backdoored external tool binary.
- Supply-chain compromise of Python dependencies.
- Legal authorization. Private-target mode is a capability, not permission.
  Only scan systems you are authorized to test.
- Denial of service from a local process or an enormous scan target.

---

## 9. Required deployment controls

1. Keep `BREADCRUMB_HOST=127.0.0.1`; do not expose the port.
2. Back up the DB **and** key separately; restrict backup permissions.
3. Run the worker as an unprivileged user.
4. Keep `BREADCRUMB_EXECUTOR=off` unless actively scanning.
5. Keep `BREADCRUMB_EXTERNAL_TOOLS` off unless adapters are needed.
6. Use `BREADCRUMB_STRICT_MODE=1` when adapters are enabled on an untrusted
   network.
7. Use an egress firewall/network namespace for untrusted targets.
8. Rotate keys after suspected exposure; restore from a known-good backup if
   ciphertext integrity is in doubt.
9. Run `/api/v1/verify` after restores and before sign-off.
10. Keep the Leadline folder read-only as a fallback until parity sign-off.

---

## 10. Reporting a security issue

This is a local, single-user project. If you find a vulnerability, do not
publish exploit details before the owner has a chance to fix it. Include the
affected version/commit, reproduction steps, and whether the issue requires
local access, a malicious target, or an external tool. Until a private channel
is configured, use the repository’s private security-advisory mechanism.
