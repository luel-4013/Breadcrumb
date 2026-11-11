# Adapter safety model

External tool adapters are optional. Breadcrumb can import output from any tool
without running it; adapters only exist for users who explicitly opt in to
execution. The default executor is **off**, and the default install needs no
external binary.

## Enablement

- `BREADCRUMB_EXECUTOR=inline` starts the in-process worker for the web app.
- Without that variable, run `breadcrumb worker` yourself.
- Adapter execution additionally requires `BREADCRUMB_EXTERNAL_TOOLS=1`.
  Native collectors do not require it.
- `BREADCRUMB_STRICT_MODE=1` tightens adapter scope policy. A tool whose
  `strict_policy` is `never` is reported as `strict_disabled` and is not a
  candidate for strict execution.

Nothing is downloaded, installed or auto-updated. A missing binary is a normal
diagnostic, not a crash.

## What an adapter may do

- Receive an argv list. **No shell**, no `shell=True`, no string interpolation
  into a command line.
- Receive one target that passed scope preflight. Targets beginning with `-`,
  containing control characters, or resolving outside scope are rejected.
- Run in a fresh temporary working directory.
- Read an allowlisted environment. Proxy variables, `BREADCRUMB_SECRET_KEY`,
  notification tokens and application secrets are **not** passed.
- Produce bounded stdout/stderr. Output beyond the adapter cap is truncated and
  marked as truncated.
- Be cancelled as a process group, so child processes do not survive.
- Be killed at the timeout. A timeout is reported as a failed/partial phase, not
  as a successful empty scan.

## Scope modes

| Mode | Meaning |
|---|---|
| `preflight_only` | Resolve and check the target once, then pass the original target |
| `resolve_override` | Pass the resolved in-scope IP instead of the hostname |
| `ip_literal` | Adapter only accepts a literal IP/CIDR target |
| `passive` | Tool is treated as passive; still subject to target validation |

Scope never becomes "trust the tool". Redirects, DNS changes and output that
mentions out-of-scope hosts are parsed as evidence but do not grant permission
to scan those hosts.

## Diagnostics

```bash
breadcrumb tools                 # table: installed, scope mode, strict, version
breadcrumb tools --json          # machine-readable
curl http://127.0.0.1:8787/api/v1/tools
breadcrumb doctor                # also reports optional tool availability
```

`/api/v1/tools` reports for each adapter:

- `installed`, `path`, `version`, `version_status`
- `scope_mode`, `strict_policy`
- `strict_disabled` when strict mode is on and the adapter cannot comply

A version string is **informational**. Breadcrumb does not enforce semver ranges
for external binaries: flags and output contracts change between releases, and a
hard version gate would turn a working local install into a support incident.
If an adapter's expected output changes, the parser reports malformed/zero
entities instead of silently claiming success.

## Trust boundary

Adapters execute a **local binary chosen by the operator** with the operator's
permissions. There is no sandbox, container, seccomp profile or network
namespace. A malicious binary is equivalent to running it in a shell. Breadcrumb
protects against accidental scope mistakes, argument injection, runaway output
and orphaned processes; it does not protect you from a compromised tool.

Similarly, **local parser plugins are imported Python** and run in-process. Only
install parsers you trust. Plugin load errors are contained and shown at
`/parsers` and in `breadcrumb parsers --json`, but a plugin that loads has full
process access.

## Operator checklist

1. Verify the binary path and version (`breadcrumb tools --json`).
2. Keep `BREADCRUMB_STRICT_MODE=1` for production recon.
3. Use a header profile or proxy only when the program allows it.
4. Review scope before the first run; out-of-scope targets fail closed.
5. Keep output caps and timeouts at their defaults unless you have measured a
   need.
6. Treat all tool output as untrusted text. Reports escape it; do not paste it
   into a shell.
7. Store the SQLite database and artifact directory together; both are local
   evidence.

## Failure behavior

| Failure | Result |
|---|---|
| Binary missing | Adapter unavailable; job/phase error states "not installed" |
| Version probe fails | `version_status: unknown`; execution is not blocked |
| Target out of scope | Fail closed; no process starts |
| Target begins with `-` | Rejected as unsafe before execution |
| Timeout | Process group killed; truncated output retained as evidence |
| Output cap exceeded | Truncation flag set; parser sees bounded text |
| Worker crash | Lease expires and the durable queue recovers the job |
| Maintenance mode | Workers stop claiming; running work is not silently rewritten |

## Deliberate non-goals

- No remote plugin or adapter marketplace.
- No automatic tool installation.
- No exploitation, brute force or credential attacks.
- No cloud/distributed scanning.
- No claim that a clean adapter run proves a target is secure.
