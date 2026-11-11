# Screenshot and evidence artifact cookbook

Breadcrumb imports screenshots that another tool already captured. It does not
launch Chromium, Selenium or Playwright. EyeWitness, Gowitness, a shell script or
a manual upload can produce the image; Breadcrumb hashes it, stores it outside
SQLite, links it to the program/target/finding, and serves it only from the local
app.

## What is stored

- **SQLite** holds metadata: program, optional target/capture/entity/finding,
  source, source URL, filename, media type, dimensions, byte size, capture time,
  SHA-256 and a relative `storage_path`.
- **The artifact directory** holds the image bytes, content-addressed as
  `sha256/ab/cd/<sha256>.<ext>`. Two rows can share one file; deleting one row
  keeps the file until the last reference is gone.
- The default root is `<database-name>.artifacts` beside the SQLite file. Set
  `BREADCRUMB_ARTIFACT_DIR` to move it to another local disk:

```bash
export BREADCRUMB_ARTIFACT_DIR="$HOME/recon/breadcrumb-artifacts"
```

Back up the database and the artifact directory together. The database alone is
metadata-only and cannot reproduce missing images.

## Supported formats and limits

| Format | Accepted | Notes |
|---|---|---|
| PNG | yes | Magic bytes and IHDR dimensions checked |
| JPEG | yes | SOF dimensions checked |
| GIF | yes | Header dimensions checked |
| WebP | yes | VP8/VP8L/VP8X dimensions checked |
| SVG | **no** | Can execute script in a browser context |
| PDF | **no** | Not a screenshot image |
| anything else | **no** | Rejected before storage |

Caps: **12 MiB per image**, **12,000 px per side**, **2,000 rows / 5 MiB per
manifest**, **1,000 images per import**. The content endpoint verifies the hash
on every read and sends `X-Content-Type-Options: nosniff` plus
`Content-Security-Policy: default-src 'none'; sandbox`.

## Import from the UI

Open **Screenshots** in the sidebar (`/artifacts`).

1. Choose the program.
2. Upload one image, or enter an EyeWitness/Gowitness manifest path.
3. Optionally choose a target/finding. With no explicit choice, Breadcrumb
   infers the target from the source URL using the program's existing scope
   rules. It **never creates a target** from an imported manifest.
4. The gallery shows thumbnails; the detail page shows dimensions, provenance,
   links, storage path, and a live hash verification.

The program page also shows its most recent screenshots.

## Import from EyeWitness

EyeWitness produces a CSV or JSON report plus image files.

```bash
python -m app.cli artifacts import ~/recon/acme/eyewitness/report.csv \
  --program 1 \
  --base-dir ~/recon/acme/eyewitness

python -m app.cli artifacts import ~/recon/acme/eyewitness/report.json \
  --program 1 \
  --base-dir ~/recon/acme/eyewitness \
  --json
```

Common fields are recognized case-insensitively, with spaces and punctuation
removed: `URL`/`Final URL`/`Host`, `Screenshot`/`Screenshot Path`/`Filename`,
`Status Code`, `Title`, `Captured At`/`Timestamp`, and source labels. Relative
paths resolve against `--base-dir`, the manifest folder, then conventional
`screenshots/` locations.

A missing image does not abort the import: that row is counted in `skipped` and
reported with its line number. Re-importing the same manifest is idempotent for
the same program, SHA-256, source URL and finding link.

## Import from Gowitness

Gowitness JSON/JSONL usually has `url` or `final_url`, `filename`, and
`perception_hash`.

```bash
python -m app.cli artifacts import ~/recon/acme/gowitness/report.jsonl \
  --program 1 \
  --base-dir ~/recon/acme/gowitness
```

The importer records the perceptual hash as provenance; it does not use it for
deduplication. Deduplication is always the exact SHA-256 of the image bytes
within the same program, source URL and finding context.

## Generic manifest shapes

Accepted JSON shapes:

```json
[
  {"url": "https://app.example.com/", "screenshot": "app.png"}
]
```

```json
{"results": [{"url": "https://app.example.com/", "filename": "app.png"}]}
```

```json
{
  "app.example.com.png": {
    "url": "https://app.example.com/",
    "status": "200 OK"
  }
}
```

JSONL is one record per line. CSV uses a header row. Unknown fields are ignored;
they never become secrets or report content automatically.

## Link with findings

```bash
# Attach every image in the manifest to finding 42
python -m app.cli artifacts import report.json --program 1 --finding 42

# Or upload a single image through the API
curl -X POST http://127.0.0.1:8787/api/v1/artifacts \
  -H "X-CSRF-Token: $TOKEN" \
  -F program_id=1 \
  -F finding_id=42 \
  -F source_url='https://app.example.com/admin' \
  -F upload=@admin.png
```

The API returns **201** for a new artifact and **200** with `duplicate: true`
when the same program/hash/source URL/finding already exists.

## Browse, export and verify

```bash
python -m app.cli artifacts list --program 1
python -m app.cli artifacts list --q "admin" --source eyewitness --json
python -m app.cli artifacts show 7 --json
python -m app.cli artifacts export 7 -o ~/recon/evidence/admin.png
python -m app.cli artifacts manifest --program 1 -o artifacts.json
python -m app.cli artifacts delete 7 --yes
```

`artifacts show` reports whether the file exists and whether its SHA-256 and size
still match. A hash mismatch is evidence corruption, not a warning to ignore:
restore the original file or delete the row and re-import.

API equivalents:

```text
GET    /api/v1/artifacts?program_id=1&target_id=&finding_id=&source=&q=&limit=&offset=
POST   /api/v1/artifacts                  multipart upload
POST   /api/v1/artifacts/import           {"manifest_path": "...", "program_id": 1}
GET    /api/v1/artifacts/manifest?program_id=1
GET    /api/v1/artifacts/{id}
GET    /api/v1/artifacts/{id}/content
DELETE /api/v1/artifacts/{id}
```

## Screenshots in reports

`include_screenshots` is a report-template checkbox, default **off**.

```bash
python -m app.cli render 1 --template technical --format html \
  --var include_screenshots=1 -o finding.html
```

- **HTML** embeds images as data URIs, so the file is self-contained.
- **PDF** embeds PNG/JPEG when the image codec is available; GIF/WebP remain
  captioned metadata instead of adding an image-conversion dependency.
- **Markdown** lists each screenshot with its source, dimensions and SHA-256.
- **JSON** includes screenshot metadata but deliberately omits `data_uri`, so
  automation payloads stay small and deterministic.
- Screenshot captions and filenames still pass through the normal redaction and
  HTML escaping pipeline.

**Pixels are not redacted.** Redaction masks text fields in the report; it
cannot remove a token, email address or customer name visible inside an image.
Review every screenshot before sharing it.

## Screenshots in a review bundle

```bash
python -m app.cli bundle 1 --template technical \
  --include-screenshots -o review.zip
```

Bundle limits are **50 images / 32 MiB**, with a separate 64 MiB uncompressed
cap for the whole zip. Images are written byte-for-byte under `screenshots/` and
listed in `manifest.json` with size and SHA-256. The verifier checks each image
and warns that pixels are not redacted. Images skipped for size/count are listed
in the manifest and in verification warnings.

Without `--include-screenshots` (or the report form checkbox), a bundle contains
screenshot metadata but no image bytes.

## Security notes

- Uploaded bytes are untrusted. Only raster magic bytes with readable dimensions
  are accepted; SVG/PDF/HTML are rejected.
- Artifact storage paths are relative and checked against the artifact root.
- The content endpoint verifies SHA-256 before serving and is sandboxed with a
  restrictive CSP.
- Manifest paths are read from the local filesystem with the user's permissions.
  This is a local-first tool, not a remote upload service.
- There is no image OCR, no remote image fetch, no browser automation and no
  telemetry in this path.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unsupported image format` | SVG/PDF/text or corrupted file | Export a PNG/JPEG/GIF/WebP |
| `could not read image dimensions` | Truncated or fake magic bytes | Re-capture the image |
| `image is too large` | Over 12 MiB | Resize before import |
| `image not found` row | Wrong `--base-dir` or relative path | Point at the folder that holds the images |
| Hash mismatch | File changed/deleted outside Breadcrumb | Restore the original or delete/re-import |
| Missing screenshots in report | `include_screenshots` unchecked | Check it in the report studio or pass `--var include_screenshots=1` |
| Bundle has no images | `--include-screenshots` not set | Add the flag or check the form box |
