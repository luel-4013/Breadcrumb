# Scope decision reference

Scope is deterministic and explainable. `app.scope.Scope.explain()` returns a
`ScopeDecision` with a status (`in`, `out`, `unknown`), a stable reason code,
the exact rule line that decided it, the rule kind, the observed status code and
structured detail.

## Rule shapes

```text
example.com                  apex + every subdomain
*.example.com                subdomains only (not the apex)
.example.com                 explicit suffix
api.example.com              suffix match (apex + subdomains)
10.0.0.0/24                  CIDR range
10.0.0.5                     single IP
https://app.example.com/login  URL; its host is used
example.com/admin/*          URL path prefix (path rule)
https://api.example.com/v2   host + path prefix
!internal.example.com        negation (out of scope)
-example.com/private         negation with a path
example.com status:200,204   host-wide observed-status filter
example.com/admin status:200 path rule plus observed-status filter
```

A bare domain matches subdomains on purpose: recon data is overwhelmingly
subdomains, and over-inclusive scope is easy to correct. A path rule only
matches URLs/paths under the prefix; it does not scope the whole host.

## Precedence

1. Positive out-of-scope rules (`scope_out`, no `!`).
2. Negated in-scope rules (`scope_in` line beginning `!` or `-`).
3. Re-includes in the out list (`scope_out` line beginning `!` or `-`).
4. Positive in-scope rules.
5. No match → `unknown`.

Explicit exclusions always win. Out-list negation is the escape hatch for a
broad out-of-scope entry that contains a specific asset you may test.

## Stable reason codes

| Reason | Status | Meaning |
|---|---|---|
| `in_rule` | in | a positive in-scope rule matched |
| `out_rule` | out | a positive out-of-scope rule matched |
| `in_negated` | out | an in-scope line was negated (`!`) |
| `re_included` | in | an out-of-scope line was negated (`!`) |
| `status_filter` | out | the rule matched but the observed status is not allowed |
| `status_unknown` | unknown | the rule has a status filter and no status was observed |
| `no_match` | unknown | no rule matched |
| `no_scope` | unknown | the program has no scope rules |
| `no_host` | unknown | the value has no host (for example a bare path) |

`scope_reason` is persisted on every entity at rebuild time, so ledger filters,
the program page and the scope page agree without re-parsing.

## Status filters

Status filters only decide entities whose HTTP status is known. The status is
taken from parser metadata (`status_code`, `status`, `http_status`, `code`) or
from an `http_status` entity value. It is **never** parsed out of a URL path:
`/404` is a page, not evidence of an HTTP 404 response.

If a status-filtered rule matches the host/path but no status is known, the
decision is `unknown` with reason `status_unknown`. It is not silently dropped.
This is deliberate: a missing status means “probe it”, not “out of scope”.

## Per-rule severity overrides

Programs can map a parser rule to a severity:

```text
tech-detect=info
CVE-2024-1234=critical
```

The key is the nuclei template id or the BBOT finding name. Overrides are
applied during ingest and on *Save & rebuild*. The original severity is stored
in `Finding.meta.parser_severity`; when an override changes the value,
`Finding.meta.severity_override` records `{rule_id, from, to}`. Removing the
override and saving reverts to the parser value. Overrides never rewrite the
finding title, evidence or fingerprint.

## Bulk re-scope

The Scope page (`/programs/<id>/scope`) shows every entity with its decision.
Selected assets can be appended to the program's in-scope or out-of-scope text.
This is the only bulk action that persists: it writes durable rule lines and
rebuilds attribution. A plain rebuild recomputes decisions without changing
rules. Duplicate lines are skipped, so repeated bulk actions are idempotent.

## Import-time classification

`rebuild_program()` runs after every ingest (browser, API, worker, CLI, ledger
import). It consolidates duplicate entities, recomputes scope and persists
`scope_status`/`scope_reason`, attributes targets, and rebuilds derived graph
edges. The rebuild summary includes `scope_reasons` counts, which the program
page and import report expose. There is no separate “scope later” path that can
leave stale decisions behind.
