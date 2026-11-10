# Cross-program memory (the Ledger)

Breadcrumb is built around one question that single-engagement scanners cannot
answer: **have I seen this asset before?** The Ledger is the local memory that
answers it. It is not a second findings table and it is not a cloud asset
inventory; it is a deterministic projection over the evidence already in the
capture chain.

## What the Ledger aggregates

For every `(type, normalized)` pair across every program, the Ledger reports:

- first and last sighting, total occurrences, and highest confidence;
- every program, target and capture that observed the asset;
- scope status and the stable reason code from the scope engine;
- observed HTTP status codes (never guessed from a URL path);
- analyst verdicts, tags and private notes;
- `seen_before`, true when more than one program has the asset.

The canonical access path is `app.ledger.ledger_assets()`. The web UI
(`/ledger`), JSON API (`GET /api/v1/ledger`) and CLI (`breadcrumb ledger list`)
all use that function, so filters and totals cannot drift between surfaces.

## Filter language

| Token | Meaning |
|---|---|
| `type:port` | one or more entity types (`type:subdomain,domain`) |
| `scope:in` | `in`, `out`, or `unknown` |
| `tag:needs-auth` | entity tag (case-insensitive, repeatable) |
| `verdict:confirmed` | analyst verdict |
| `program:acme` | program name substring or numeric id (repeatable) |
| `status:200,204` | observed HTTP status codes |
| `seen:other-program` | assets present in more than one program |
| `seen:single` | assets present in exactly one program |
| `sort:last_seen` | `last_seen`, `first_seen`, `value`, `programs`, `occurrences` |
| `q:admin` | free text against value and normalized value |

Unknown `key:value` tokens are treated as free text, so a search for
`https://host/path` never fails because of its colon. The parser is
`app.ledger.parse_query()`; saved views store the exact string.

## Worked example

1. Program **Acme** imports `app.example.com` on 2026-01-04.
2. Six months later, program **Globex** imports the same host.
3. `/ledger?q=seen:other-program` lists it once, with `seen ×2`.
4. Opening the asset timeline shows both captures, both programs, the evidence
   hash of each capture, scope status under each program, and any analyst notes.
5. The Globex graph page also lists it under **Seen in other programs**, so the
   memory appears where the operator is already looking.

## Saved views

Saved views are local rows (`savedview` table), not share links. A view has a
name, a kind (`ledger`, `diff`, `graph`), a human-editable query string, and
structured parameters. Saving the same name updates the existing view; deleting
is explicit. There is no account model and no remote storage.

## Export and round-trip

`GET /ledger/export?format=jsonl&q=...` (or
`breadcrumb ledger export "tag:needs-auth" -o auth.jsonl`) writes one
`ledger_version: 1` JSON object per asset. CSV is available for spreadsheets.

JSONL round-trips through the normal ingest path:

- the `ledger_jsonl` parser is detected by the `ledger_version` marker (or the
  full asset shape), so generic scanner JSONL is not hijacked;
- verdicts, tags, notes, observed status codes and occurrence counts survive;
- `breadcrumb ledger import auth.jsonl` recreates missing programs from the
  export's provenance and imports each row into every program that observed it;
- scope is **recomputed** for the destination program, because scope belongs to
  the program, not to the asset.

The import is additive and idempotent: re-importing the same file consolidates
entities instead of duplicating captures or findings.

## Design boundaries

- SQLite only; no Postgres/Redis/Neo4j.
- No telemetry, no remote index, no account.
- The Ledger stores no raw artifact; it points at sealed captures.
- Deleting a program removes its sighting rows; shared assets remain visible
  through the other programs that observed them.
