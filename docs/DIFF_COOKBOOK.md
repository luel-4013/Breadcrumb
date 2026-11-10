# Diff cookbook

Diff v2 compares any two **selectors**. A selector is explicit so a typo cannot
silently compare the wrong things:

| Selector | State used | Best for |
|---|---|---|
| `paste:<id>` | entities/findings from one capture | “what did this tool run add?” |
| `target:<id>` | live state attributed to one target | “what does this host look like now?” |
| `program:<id>` | live state for the whole program | “what does this engagement look like?” |
| `job:<id>` | sealed history snapshot | “what changed between two scans?” |

Job selectors use `app.history.ensure_snapshot()`, which is the only state that
correctly represents a point-in-time scan. Capture, target and program
selectors use live evidence state. Entity-level comparison is unavailable when
either side is a job snapshot; the other categories still work.

## Categories

- **Findings**: new, disappeared, changed (severity/title/status/verdict/triage/
  verified), still open. False positives are excluded.
- **Entities**: added, removed, changed (scope status/reason, status code,
  verdict, tags, notes). Capture/target/program selectors only.
- **Ports**: opened, closed, changed service/version/banner.
- **DNS records**: added and removed, keyed by record type/name/value.
- **Endpoints**: added and removed URL/path/endpoint entities.
- **Technologies**: added and removed product/version labels.
- **Security headers**: added, removed, changed values (extracted from sealed
  header/HTTP captures).
- **Risk**: explainable 0–100 score before/after, delta and direction. False
  positives and unverified CVE candidates are excluded, matching the rest of
  the product.

## Recipes

### Two tool runs on one host

```bash
breadcrumb diff paste:41 paste:57
```

Use this after re-running httpx or nuclei. Ports that closed and endpoints that
disappeared are as important as new ones.

### Two engagements

```bash
breadcrumb diff program:1 program:2 --format md -o engagement-diff.md
```

Cross-program diff is intentionally not a “which is better” score; it shows
shared surface, unique surface, and risk movement. Combine it with
`/ledger?q=seen:other-program` for the memory view.

### Two scans of one target

```bash
breadcrumb diff job:9 job:14
```

Job selectors require a ready snapshot. If a job has no snapshot, run
`breadcrumb history <target> --diff` or let the worker finish; the API returns a
clear error instead of an empty diff.

### Alert on change

```bash
breadcrumb diff job:9 job:14 --notify
```

The alert uses the existing notification channels and the
`on_scope_changes` toggle. Diff alerts respect the configured severity floor
only for finding creation; a diff is sent when at least one category changed.

### API and CI

```bash
curl '/api/v1/diff?left=program:1&right=program:2'
curl '/api/v1/diff?left=job:9&right=job:14' | jq '.summary.has_changes'
```

`has_changes` is a single boolean for a CI step; individual counts remain
available for gates and dashboards.

## Accuracy rules

- Findings are keyed like history snapshots: CVE id first, then the stored
  dedup fingerprint, then tool/evidence/title.
- A finding that exists on both sides but changed is reported as changed, not as
  removed+new.
- Ignored entities are excluded. Entities with a `false-positive` verdict remain
  visible in entity diffs so the analyst can see the annotation change; finding
  diffs exclude false positives.
- Lists are capped at 2,000 items per category; the summary counts are always
  exact.
- Diff output contains evidence values. Treat exported Markdown/JSON as
  sensitive; it does not automatically mask secrets (use the report redaction
  path for submissions).
