"""Breadcrumb headless CLI (automation / CI).

Same engine as the web UI and API v1, no server required:

    python -m app.cli ingest scan.txt --program 1
    python -m app.cli export 1 --format sarif -o out.sarif
    python -m app.cli gate 1 --max-severity high   # exit 1 if it fails
    python -m app.cli worker --once                # run native collectors once
    python -m app.cli maintenance on --reason backup
    python -m app.cli secrets rotate                # rotate header-profile key
    python -m app.cli nvd import nvdcve-2.0.json.gz # local CVE cache for CPE matching
    python -m app.cli nvd stats
    python -m app.cli serve

Talks to the database named by BREADCRUMB_DB_PATH (default ./breadcrumb.db).
"""

import argparse
import json
import sys
from pathlib import Path

from sqlmodel import Session, select

from . import __version__, reporting
from .db import engine, init_db
from .models import Entity, Finding, Program


def _read_input(path: str) -> str:
    if path in ("-", ""):
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_ingest(args) -> int:
    from .ingest import IngestRequest, import_report, ingest
    from .parsers import analyze_detailed

    init_db()
    text = _read_input(args.file)
    if not text.strip():
        print("empty input", file=sys.stderr)
        return 2

    if args.dry_run:
        analysis = analyze_detailed(text)
        report = {
            "dry_run": True,
            "parsers": analysis.parsers,
            "parser_versions": analysis.parser_versions,
            "entities": len(analysis.entities),
            "relationships": len(analysis.relationships),
            "findings": len(analysis.findings),
            "skipped_rows": analysis.skipped_rows,
            "completeness": analysis.completeness,
            "issues": [issue.as_dict() for issue in analysis.issues],
            "warning": "no entities detected" if not analysis.entities else "",
        }
        print(json.dumps(report, indent=2, default=str))
        return 0

    source_meta = {}
    if args.source_meta:
        try:
            source_meta = json.loads(args.source_meta)
        except ValueError as exc:
            print(f"ingest: --source-meta must be JSON: {exc}", file=sys.stderr)
            return 2
    with Session(engine) as session:
        result = ingest(
            session,
            IngestRequest(
                text=text,
                program_id=args.program,
                target_id=args.target,
                source=args.source,
                command=args.command or None,
                source_meta=source_meta,
                max_entities=max(1, args.max_entities),
            ),
        )
        report = import_report(session, result.paste)
        if args.report_json:
            payload = json.dumps(report, indent=2, default=str)
            if args.report_json == "-":
                print(payload)
            else:
                path = Path(args.report_json).expanduser()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload + "\n", encoding="utf-8")
                print(f"wrote {path}")
        if args.json:
            print(json.dumps(report, indent=2, default=str))
            return 0
        print(
            f"capture #{result.paste.id}: {result.entities} entities via "
            f"{', '.join(result.paste.parsers or ['?'])}"
            + (
                f" · {result.findings} finding(s)"
                if result.findings
                else ""
            )
            + (
                f" · completeness {result.completeness:.0%}"
                if result.completeness < 1.0
                else ""
            )
            + (
                f" ({len(result.parse_errors)} parser issue(s))"
                if result.parse_errors
                else ""
            )
        )
    return 0


def cmd_doctor(args) -> int:
    """Diagnose Python, SQLite, paths, keys, port, parsers and optional tools."""
    from .doctor import format_report, run_checks

    report = run_checks()
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(format_report(report))
    return 0 if report.get("ok") else 1


def cmd_manifest(args) -> int:
    """Export a portable evidence manifest for one capture."""
    from .manifest import build_manifest, manifest_json, manifest_markdown
    from .models import Paste

    init_db()
    with Session(engine) as session:
        paste = session.get(Paste, args.paste_id)
        if paste is None:
            print(f"manifest: capture #{args.paste_id} not found", file=sys.stderr)
            return 1
        manifest = build_manifest(session, paste, redact=not args.reveal)
        text = (
            manifest_json(manifest)
            if args.format == "json"
            else manifest_markdown(manifest)
        )
        if args.output:
            path = Path(args.output).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path}")
        else:
            sys.stdout.write(text)
    return 0


def cmd_verify(args) -> int:
    """Verify a manifest offline, one capture, or the whole hash chain."""
    from .evidence import verify_chain
    from .manifest import verify_manifest_data, verify_paste_manifest
    from .models import Paste

    init_db()
    if args.manifest:
        path = Path(args.manifest).expanduser()
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"verify: could not read manifest: {exc}", file=sys.stderr)
            return 2
        raw = None
        if args.raw:
            raw = Path(args.raw).expanduser().read_text(encoding="utf-8", errors="replace")
        result = verify_manifest_data(manifest, raw=raw)
        result["manifest"] = str(path)
    elif args.paste_id:
        with Session(engine) as session:
            paste = session.get(Paste, args.paste_id)
            if paste is None:
                print(f"verify: capture #{args.paste_id} not found", file=sys.stderr)
                return 1
            result = verify_paste_manifest(session, paste)
    else:
        with Session(engine) as session:
            result = verify_chain(session)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"verification: {'OK' if result.get('valid') else 'FAILED'}")
        for check in result.get("checks", []):
            print(
                f"  {'PASS' if check['ok'] else 'FAIL'} {check['name']}: "
                f"{check.get('detail', '')}"
            )
        if "checks" not in result:
            for key, value in result.items():
                print(f"  {key}: {value}")
    return 0 if result.get("valid") else 1


def cmd_demo(args) -> int:
    """Create the sample program and print the first-report URLs."""
    from .demo import run_demo

    init_db()
    with Session(engine) as session:
        result = run_demo(session)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0
    print(f"demo program: #{result['program_id']} {result['program_name']}")
    for capture in result["captures"]:
        dup = " (reused)" if capture["duplicate"] else ""
        print(
            f"  capture #{capture['paste_id']} {capture['file']}: "
            f"{capture.get('parsed_entities', capture['entities'])} parsed entities, "
            f"{capture['findings']} finding(s), "
            f"completeness {capture['completeness']:.0%}{dup}"
        )
    print(f"entities: {result['entities']}  findings: {result['findings']}")
    print(f"report:   {result['report_url']}")
    print(f"manifest: {result['manifest_url']}")
    return 0


def cmd_programs(args) -> int:
    init_db()
    with Session(engine) as session:
        programs = session.exec(select(Program).order_by(Program.name)).all()
        if args.json:
            print(json.dumps([
                {"id": p.id, "name": p.name, "platform": p.platform} for p in programs
            ], indent=2))
            return 0
        if not programs:
            print("no programs")
            return 0
        for p in programs:
            n = len(session.exec(select(Entity).where(Entity.program_id == p.id)).all())
            print(f"{p.id:>4}  {p.name}  ({p.platform or '—'})  {n} entities")
    return 0


def cmd_findings(args) -> int:
    init_db()
    from .notify import SEVERITY_RANK

    floor = SEVERITY_RANK.get(args.min_severity.lower()) if args.min_severity else None
    with Session(engine) as session:
        stmt = select(Finding).order_by(Finding.id)
        if args.program:
            stmt = stmt.where(Finding.program_id == args.program)
        rows = [f for f in session.exec(stmt).all()
                if floor is None or SEVERITY_RANK.get(f.severity, 0) >= floor]
        if args.json:
            print(json.dumps([
                {"id": f.id, "severity": f.severity, "status": f.status,
                 "title": f.title, "tags": f.tags or []} for f in rows
            ], indent=2))
            return 0
        for f in rows:
            print(f"{f.id:>4}  [{f.severity:<8}] {f.status:<11} {f.title}")
        if not rows:
            print("no findings")
    return 0


def cmd_gate(args) -> int:
    init_db()
    from .notify import SEVERITY_RANK

    threshold = SEVERITY_RANK.get(args.max_severity.lower(), 3)
    with Session(engine) as session:
        stmt = select(Finding)
        if args.program:
            stmt = stmt.where(Finding.program_id == args.program)
        hits = [
            f for f in session.exec(stmt).all()
            if f.status not in ("resolved", "wont-fix")
            and SEVERITY_RANK.get(f.severity, 0) >= threshold
        ]
    if hits:
        print(f"GATE FAILED: {len(hits)} finding(s) at/above {args.max_severity}")
        for f in hits:
            print(f"  [{f.severity}] {f.title} ({f.status})")
        return 1
    print(f"gate passed (nothing at/above {args.max_severity})")
    return 0


def cmd_export(args) -> int:
    init_db()
    with Session(engine) as session:
        if session.get(Program, args.program) is None:
            print(f"program {args.program} not found", file=sys.stderr)
            return 1
        fmt = args.format
        if fmt == "md":
            text = reporting.to_markdown(session, args.program, mask=not args.reveal)
        elif fmt == "h1":
            text = reporting.to_hackerone(session, args.program)
        elif fmt == "csv":
            text = reporting.to_csv(session, args.program, mask=not args.reveal)
        elif fmt == "targets":
            text = reporting.targets_txt(session, args.program)
        elif fmt == "json":
            text = json.dumps(
                reporting.to_dict(session, args.program, mask=not args.reveal), indent=2
            )
        elif fmt == "sarif":
            text = json.dumps(
                reporting.to_sarif(session, args.program, mask=not args.reveal), indent=2
            )
        else:
            print(f"unknown format {fmt}", file=sys.stderr)
            return 2
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {args.output}")
        else:
            sys.stdout.write(text)
    return 0


def cmd_watch(args) -> int:
    """Drop-folder auto-ingest: the zero-friction habit loop.

    Tools (or you) drop output files into a folder; Breadcrumb ingests each new
    file into a program and moves it to a ``processed/`` subfolder.
    """
    import time
    from pathlib import Path

    from .main import _ingest

    init_db()
    folder = Path(args.folder).expanduser()
    if not folder.is_dir():
        print(f"not a directory: {folder}", file=sys.stderr)
        return 2
    done_dir = folder / "processed"
    done_dir.mkdir(exist_ok=True)
    seen: set[tuple] = set()
    print(f"watching {folder} -> program {args.program or 'unassigned'} (Ctrl+C to stop)")

    def _sweep() -> int:
        handled = 0
        for f in sorted(folder.iterdir()):
            if f.is_dir() or f.name.startswith("."):
                continue
            st = f.stat()
            key = (f.name, st.st_size, int(st.st_mtime))
            if key in seen:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            if text.strip():
                with Session(engine) as session:
                    paste = _ingest(session, text, args.program, args.target, f"watch:{f.name}")
                    n = len(session.exec(select(Entity).where(Entity.paste_id == paste.id)).all())
                    created = len(session.exec(
                        select(Finding).where(Finding.paste_id == paste.id)).all())
                print(f"  ingested {f.name}: {n} entities"
                      + (f", {created} finding(s)" if created else ""))
            seen.add(key)
            dest = done_dir / f.name
            if dest.exists():
                dest = done_dir / f"{st.st_mtime_ns}-{f.name}"
            f.rename(dest)
            handled += 1
        return handled

    if args.once:
        _sweep()
        return 0
    try:
        while True:
            _sweep()
            time.sleep(max(1, args.interval))
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def cmd_backup(args) -> int:
    from .db import backup_database

    init_db()
    dest = args.output or f"breadcrumb-backup-{__version__}.db"
    backup_database(dest)
    print(f"wrote {dest}")
    return 0


def cmd_worker(args) -> int:
    """Run the durable native-collector and opt-in adapter worker."""
    from .jobs.worker import run_worker

    init_db()
    try:
        run_worker(
            once=args.once,
            poll_interval=max(0.2, args.poll),
            lease_seconds=max(5, args.lease),
            max_jobs=max(0, args.max_jobs),
        )
    except KeyboardInterrupt:
        print("\nworker interrupted")
    return 0


def cmd_tools(args) -> int:
    """List external adapters with binary presence, version and scope mode."""
    import shutil

    from .collect.tools import adapter_specs, probe_version, strict_mode

    rows = []
    for spec in adapter_specs():
        path = shutil.which(spec.binary)
        rows.append(
            {
                "id": spec.id,
                "binary": spec.binary,
                "installed": bool(path),
                "path": path or "",
                "version": probe_version(path, spec.version_args) if path else "",
                "scope_mode": spec.scope_mode,
                "strict_policy": spec.strict_policy,
                "strict_disabled": bool(strict_mode() and spec.strict_policy == "never"),
            }
        )
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"{'adapter':12} {'installed':9} {'scope':16} {'strict':10} version")
    for row in rows:
        print(
            f"{row['id']:12} "
            f"{('yes' if row['installed'] else 'NOT INSTALLED'):9} "
            f"{row['scope_mode']:16} "
            f"{('disabled' if row['strict_disabled'] else row['strict_policy']):10} "
            f"{row['version']}"
        )
    return 0


def cmd_maintenance(args) -> int:
    """Pause/resume native worker claims during backup or migration."""
    from .db import get_app_state, set_maintenance

    enabled = args.action == "on"
    init_db()
    set_maintenance(enabled, args.reason if enabled else "")
    with Session(engine) as session:
        state = get_app_state(session)
        print(
            f"maintenance {'ON' if state.maintenance else 'OFF'}"
            + (f": {state.maintenance_reason}" if state.maintenance_reason else "")
        )
    return 0


def cmd_import_leadline(args) -> int:
    """One-way import of a Leadline SQLite database into Breadcrumb."""
    from .leadline_import import (
        LeadlineImportError,
        dry_run,
        import_leadline,
        verify_import,
    )
    from .secrets_store import SecretsError

    manifest = args.manifest or None
    try:
        if args.verify:
            result = verify_import(
                args.db,
                program_id=args.program,
                program_name=args.program_name,
                manifest_path=manifest,
            )
        elif args.dry_run:
            result = dry_run(
                args.db,
                program_id=args.program,
                program_name=args.program_name,
            )
        else:
            result = import_leadline(
                args.db,
                program_id=args.program,
                program_name=args.program_name,
                manifest_path=manifest,
                backup=not args.no_backup,
                generate_snapshots=not args.no_snapshots,
                verify=not args.no_verify,
            )
    except (LeadlineImportError, SecretsError) as exc:
        print(f"import-leadline: {exc}", file=sys.stderr)
        return 2

    if args.report:
        report_path = Path(args.report).expanduser()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(result, indent=2, default=str), encoding="utf-8"
        )
        print(f"wrote {report_path}")

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("ok", True) else 1

    if result.get("dry_run"):
        source = result["source"]
        print("Leadline import (dry run; no writes)")
        print(f"source: {source['path']}")
        print(f"sha256: {source['sha256']}")
        print(
            "source counts: "
            + ", ".join(f"{key}={value}" for key, value in result["counts"].items())
        )
        print(
            "would import: "
            + ", ".join(
                f"{key}={value}" for key, value in result["would_import"].items()
            )
        )
        print(f"distinct header sets: {result['distinct_header_sets']}")
        print(
            "triage: "
            + (", ".join(f"{key}={value}" for key, value in result["triage"].items()) or "none")
        )
        destination = result.get("destination") or {}
        if destination.get("exists"):
            program = destination.get("program")
            print(
                "destination: "
                + (
                    f"program #{program['id']} {program['name']} "
                    f"(existing import: {destination.get('counts', {})})"
                    if program
                    else "no matching program yet"
                )
            )
        else:
            print("destination: database does not exist yet")
        for item in result.get("malformed_targets", []) + result.get(
            "malformed_scans", []
        ):
            print(
                f"skip {item['table']} #{item['id']}: {item['reason']}",
                file=sys.stderr,
            )
        for warning in result.get("warnings", []):
            print(f"warning: {warning}", file=sys.stderr)
        return 0

    if args.verify:
        print(f"verification: {'OK' if result.get('ok') else 'FAILED'}")
        for check in result.get("checks", []):
            print(
                f"  {'PASS' if check['ok'] else 'FAIL'} {check['name']}: "
                f"{json.dumps(check['detail'], default=str)}"
            )
        return 0 if result.get("ok") else 1

    imported = result["counts"]["imported"]
    skipped = result["counts"]["skipped"]
    print(
        f"program: #{result['program']['id']} {result['program']['name']}"
        + (" (created)" if result["program"].get("created") else "")
    )
    print(
        "imported: "
        + ", ".join(f"{key}={value}" for key, value in imported.items())
    )
    print("skipped: " + ", ".join(f"{key}={value}" for key, value in skipped.items()))
    if result.get("backup"):
        print(f"backup: {result['backup']}")
    print(f"manifest: {result['manifest']}")
    verification = result.get("verification")
    if verification is not None:
        print(f"verification: {'OK' if verification.get('ok') else 'FAILED'}")
    for warning in result.get("warnings", []):
        print(f"warning: {warning}", file=sys.stderr)
    for error in result.get("errors", []):
        print(
            f"error: {error['table']} #{error['id']}: {error['reason']}",
            file=sys.stderr,
        )
    return 0 if result.get("ok", True) else 1


def cmd_secrets(args) -> int:
    """Rotate the header-profile encryption key (file-backed keys only)."""
    from .secrets_store import SecretsError, rotate_key_file

    if args.action != "rotate":
        print(f"unknown secrets action: {args.action}", file=sys.stderr)
        return 2
    init_db()
    try:
        path, old = rotate_key_file()
    except SecretsError as exc:
        print(f"secrets: {exc}", file=sys.stderr)
        return 1
    print(f"rotated {path}; previous keys archived at {old}")
    return 0


def cmd_nvd(args) -> int:
    """Import or inspect the offline NVD cache used for CVE verification."""
    from .collect.nvd import (
        NvdCacheError,
        default_cache_path,
        import_nvd,
        load_cache,
    )

    cache_path = args.cache or str(default_cache_path())
    if args.action == "import":
        if not args.file:
            print("nvd import needs a JSON or JSON.GZ file", file=sys.stderr)
            return 2
        try:
            report = import_nvd(args.file, cache_path, merge=not args.replace)
        except NvdCacheError as exc:
            print(f"nvd: {exc}", file=sys.stderr)
            return 1
        print(
            f"imported {report['imported']} CVE(s), {report['new']} new; "
            f"cache now holds {report['total']} CVE(s) with "
            f"{report['indexed_products']} indexed product(s): {report['path']}"
        )
        return 0

    try:
        cache = load_cache(cache_path)
    except NvdCacheError as exc:
        print(f"nvd: {exc}", file=sys.stderr)
        return 1
    stats = cache.stats()
    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        print(f"cache: {stats['path']}")
        print(
            f"{stats['cves']} CVE(s), {stats['indexed_products']} product(s), "
            f"{stats['indexed_cpe_ranges']} indexed CPE range(s), "
            f"{stats['keyword_entries']} cached keyword search(es)"
        )
        print(f"updated: {stats['updated_at']}")
    return 0


def _json_object(raw: str) -> dict:
    if not raw.strip():
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("params must be a JSON object")
    return value


def _resolve_target(session: Session, value: str, program_id: int | None = None):
    """Resolve a target id, name, or URL to a Target row."""
    from .models import Target

    value = (value or "").strip()
    if not value:
        return None
    if value.isdigit():
        row = session.get(Target, int(value))
        if row is not None:
            return row
    stmt = select(Target).order_by(Target.id)
    if program_id is not None:
        stmt = stmt.where(Target.program_id == program_id)
    rows = session.exec(stmt).all()
    lowered = value.lower().rstrip(".")
    for row in rows:
        if (row.name or "").strip().lower().rstrip(".") == lowered:
            return row
    from .history import _host_for

    host = _host_for(value)
    for row in rows:
        name = (row.name or "").strip().lower().rstrip(".")
        if row.kind == "url":
            name = _host_for(row.name)
        if host and (host == name or host.endswith("." + name)):
            return row
    return None


def cmd_collect(args) -> int:
    """Queue (and optionally run) a native collector from the CLI."""
    from . import runners
    from .history import _host_for
    from .models import ScanJob, Target
    from .attribution import attribute_target

    init_db()
    try:
        options = _json_object(args.params)
    except ValueError as exc:
        print(f"collect: {exc}", file=sys.stderr)
        return 2
    with Session(engine) as session:
        runner = runners.find_runner(session, args.collector)
        if runner is None:
            print(f"collect: unknown runner {args.collector!r}", file=sys.stderr)
            return 2
        if not (runner.native or runner.adapter):
            print(
                f"collect: {args.collector!r} is an external runner; queue it with "
                "the web UI and post output to /api/v1/pastes",
                file=sys.stderr,
            )
            return 2
        target_id = None
        if args.program is not None:
            targets = session.exec(
                select(Target).where(Target.program_id == args.program)
            ).all()
            matched = attribute_target(_host_for(args.target), targets)
            target_id = matched.id if matched else None
        job = ScanJob(
            program_id=args.program,
            target_id=target_id,
            runner=args.collector,
            target=args.target.strip(),
            status="queued",
            header_profile_id=args.header_profile,
            priority=args.priority,
            params=options,
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        print(
            f"queued job #{job.id} ({job.runner}) for {job.target}"
            + (f" in program #{job.program_id}" if job.program_id else "")
        )
        if runner.adapter and not args.run_now:
            print(
                "adapter job queued: use --run-now or set "
                "BREADCRUMB_EXTERNAL_TOOLS=1 so the worker claims it"
            )
        job_id = job.id
    if args.run_now:
        from .jobs import run_once

        worked = run_once(job_id=job_id, runner_ids=(args.collector,))
        if not worked:
            print(
                "run now: job was not claimable (already running or maintenance mode)",
                file=sys.stderr,
            )
            return 1
        with Session(engine) as session:
            job = session.get(ScanJob, job_id)
            print(f"job #{job_id} finished with status {job.status if job else '?'}")
    return 0


def cmd_jobs(args) -> int:
    """List, inspect, cancel, or retry durable scan jobs."""
    from .jobs import queue as jobs_queue
    from .models import ScanJob, ScanPhase

    init_db()
    with Session(engine) as session:
        if args.action == "list":
            stmt = select(ScanJob).order_by(ScanJob.id.desc())
            if args.status:
                stmt = stmt.where(ScanJob.status == args.status)
            if args.limit:
                stmt = stmt.limit(args.limit)
            rows = session.exec(stmt).all()
            if args.json:
                print(json.dumps(
                    [
                        {
                            "id": job.id,
                            "status": job.status,
                            "runner": job.runner,
                            "target": job.target,
                            "program_id": job.program_id,
                            "attempts": job.attempts,
                            "created_at": job.created_at,
                            "error": job.error,
                        }
                        for job in rows
                    ],
                    default=str,
                    indent=2,
                ))
                return 0
            if not rows:
                print("no jobs")
                return 0
            for job in rows:
                print(
                    f"{job.id:>4}  {job.status:<10} {job.runner:<16} "
                    f"{(job.target or '—')[:44]:<44} attempts {job.attempts}"
                )
            return 0

        if args.job_id is None:
            print(f"jobs {args.action}: a job id is required", file=sys.stderr)
            return 2
        job = session.get(ScanJob, args.job_id)
        if job is None:
            print(f"jobs: job #{args.job_id} not found", file=sys.stderr)
            return 1

        if args.action == "show":
            phases = session.exec(
                select(ScanPhase).where(ScanPhase.job_id == job.id).order_by(ScanPhase.seq)
            ).all()
            if args.json:
                payload = job.model_dump(mode="json")
                payload["phases"] = [phase.model_dump(mode="json") for phase in phases]
                print(json.dumps(payload, default=str, indent=2))
                return 0
            print(f"job #{job.id}: {job.status} ({job.runner})")
            print(f"target:  {job.target or '—'}")
            print(f"program: {job.program_id or '—'}  target_id: {job.target_id or '—'}")
            print(f"attempts: {job.attempts}/{job.max_attempts}")
            print(f"created: {job.created_at}  finished: {job.finished_at or '—'}")
            if job.error:
                print(f"error:   {job.error}")
            if job.params:
                print(f"params:  {json.dumps(job.params, sort_keys=True)}")
            if phases:
                print("phases:")
                for phase in phases:
                    print(f"  {phase.seq:>2} {phase.name:<18} {phase.status}")
            return 0

        if args.action == "cancel":
            result = jobs_queue.request_cancel(session, job.id)
            print(f"job #{job.id}: {result or 'not cancellable'}")
            return 0

        if args.action == "retry":
            if job.status in ("queued", "running"):
                print(f"job #{job.id} is already {job.status}", file=sys.stderr)
                return 1
            job.status = "queued"
            job.error = None
            job.finished_at = None
            job.output_paste_id = None
            job.cancel_requested = False
            job.next_run_at = None
            job.lease_owner = None
            job.lease_expires_at = None
            if int(job.attempts or 0) >= int(job.max_attempts or 3):
                job.max_attempts = int(job.attempts or 0) + 1
            session.add(job)
            session.commit()
            print(f"job #{job.id} requeued (attempts {job.attempts}/{job.max_attempts})")
            return 0
    return 2


def cmd_history(args) -> int:
    """Show a target's scan timeline and scan-to-scan diffs."""
    from . import history

    init_db()
    with Session(engine) as session:
        target = _resolve_target(session, args.target, args.program)
        if target is None:
            print(f"history: target {args.target!r} not found", file=sys.stderr)
            return 1
        try:
            data = history.target_history(session, target.id)
            diff = None
            if args.diff:
                if args.from_scan and args.to_scan:
                    diff = history.load_diff(
                        session, target.id, args.from_scan, args.to_scan
                    )
                else:
                    diff = data.get("latest_diff")
        except ValueError as exc:
            print(f"history: {exc}", file=sys.stderr)
            return 1
        if args.json:
            payload = dict(data)
            if args.diff:
                payload["diff"] = diff
            print(json.dumps(payload, default=str, indent=2))
            return 0
        print(f"target: {target.name} (#{target.id})")
        totals = data["totals"]
        print(
            f"scans: {totals['scans']} ({totals['completed']} completed, "
            f"{totals['failed']} failed)"
        )
        for scan in data["scans"]:
            risk = (
                f"{scan.get('risk_level')} {scan.get('risk_score')}/100"
                if scan.get("risk_level")
                else "—"
            )
            changes = scan.get("changes") or {}
            delta = ""
            if changes:
                delta = (
                    f" +{changes.get('new_findings', 0)} findings, "
                    f"+{changes.get('ports_opened', 0)} ports"
                )
            print(
                f"  #{scan.get('job_id')}  {scan.get('status', '?'):<10} "
                f"{risk:<18}{delta}"
            )
        if args.diff:
            if not diff:
                print("diff: no two completed snapshots to compare")
                return 0
            summary = diff["summary"]
            print(
                f"diff #{diff['from_scan']['job_id']} -> "
                f"#{diff['to_scan']['job_id']}: "
                f"+{summary['new_findings']} new, "
                f"{summary['removed_findings']} resolved, "
                f"+{summary['ports_opened']} ports opened, "
                f"risk {summary['risk_delta']:+d}"
            )
    return 0


def _snapshot_markdown(job, data: dict, findings: list[dict]) -> str:
    summary = data.get("severity_counts") or {}
    lines = [
        f"# Breadcrumb report: {data.get('target_name') or job.target}",
        "",
        f"- Scan: #{job.id}",
        f"- Status: {job.status}",
        f"- Risk: {data.get('risk_score', 0)} ({data.get('risk_level', 'minimal')})",
        f"- Findings: {len(findings)}",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No active findings.")
    for finding in findings:
        lines.append(
            f"### [{str(finding.get('severity') or 'info').upper()}] "
            f"{finding.get('title')}"
        )
        lines.append("")
        if finding.get("description"):
            lines.append(str(finding["description"]))
            lines.append("")
        if finding.get("evidence"):
            lines.append("```")
            lines.append(str(finding["evidence"]))
            lines.append("```")
            lines.append("")
        if finding.get("remediation"):
            lines.append(f"**Remediation:** {finding['remediation']}")
            lines.append("")
    lines.append("---")
    lines.append(
        "CONFIDENTIAL. Generated by Breadcrumb for authorized security "
        "assessments only."
    )
    return "\n".join(lines).rstrip() + "\n"


def cmd_report(args) -> int:
    """Render a job report from its history snapshot."""
    from . import history, pdf_export
    from .models import Program, ScanJob

    init_db()
    with Session(engine) as session:
        job = session.get(ScanJob, args.job_id)
        if job is None:
            print(f"report: job #{args.job_id} not found", file=sys.stderr)
            return 1
        snapshot = history.ensure_snapshot(session, job)
        if snapshot is None or snapshot.status != "ready":
            print(
                f"report: job #{job.id} has no ready snapshot "
                f"({snapshot.status if snapshot else 'missing'}); "
                f"run `breadcrumb jobs show {job.id}` or rebuild it from the job page",
                file=sys.stderr,
            )
            return 1
        data = snapshot.data or {}
        findings = [
            item
            for item in (data.get("findings") or {}).values()
            if args.include_triaged or not item.get("is_false_positive")
        ]
        if args.format == "json":
            content = json.dumps(
                {"snapshot": data, "findings": findings}, default=str, indent=2
            )
        elif args.format == "md":
            content = _snapshot_markdown(job, data, findings)
        else:
            program = session.get(Program, job.program_id) if job.program_id else None
            summary = {
                "total_findings": len(findings),
                "severity_counts": data.get("severity_counts") or {},
                "verified_cves": data.get("verified_cves") or 0,
                "unverified_cves": data.get("unverified_cves") or 0,
                "endpoints": len(data.get("endpoints") or []),
                "subdomains": len(data.get("subdomains") or []),
                "open_ports": len(data.get("ports") or {}),
                "technologies": len(data.get("technologies") or []),
                "missing_headers": len(data.get("security_headers_missing") or []),
                "risk_score": data.get("risk_score") or 0,
                "risk_level": data.get("risk_level") or "minimal",
            }
            highlights = {
                "technologies": data.get("technologies") or [],
                "cdn_waf": data.get("cdn_waf") or [],
                "security_headers_present": data.get("security_headers_present") or [],
                "security_headers_missing": data.get("security_headers_missing") or [],
                "resolved_ips": data.get("resolved_ips") or [],
                "hostnames": data.get("hostnames") or [],
                "subdomains": data.get("subdomains") or [],
                "open_ports": data.get("ports") or {},
                "discovered_endpoints": data.get("endpoints") or [],
            }
            content = pdf_export.generate_report_pdf(
                program_name=program.name if program else "Breadcrumb",
                target_name=data.get("target_name") or job.target,
                target_url=data.get("target_url") or job.target,
                scan_id=job.id,
                status=job.status,
                created_at=job.created_at,
                completed_at=job.finished_at,
                summary=summary,
                highlights=highlights,
                phases=data.get("phases") or [],
                findings=findings,
            )
        extension = {"pdf": "pdf", "json": "json", "md": "md"}[args.format]
        output = args.output or pdf_export.report_filename(job.target, job.id, extension)
        mode = "wb" if isinstance(content, bytes) else "w"
        kwargs = {} if isinstance(content, bytes) else {"encoding": "utf-8"}
        with open(output, mode, **kwargs) as fh:
            fh.write(content)
        print(f"wrote {output}")
    return 0


def cmd_version(args) -> int:  # noqa: ARG001
    print(f"breadcrumb {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="breadcrumb", description="Offline-first recon notebook CLI")
    parser.add_argument("--version", action="version", version=f"breadcrumb {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("ingest", help="ingest a file (or - for stdin)")
    p.add_argument("file")
    p.add_argument("--program", type=int, default=None)
    p.add_argument("--target", type=int, default=None)
    p.add_argument("--source", default="cli")
    p.add_argument("--command", default="", help="command that produced this artifact (redacted in manifests)")
    p.add_argument("--source-meta", default="", help="non-secret provenance as a JSON object")
    p.add_argument("--max-entities", type=int, default=25000)
    p.add_argument("--report-json", default="", help="write the import report (or - for stdout)")
    p.add_argument("--json", action="store_true", help="print the import report as JSON")
    p.add_argument("--dry-run", action="store_true", help="parse and report without writing")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("doctor", help="diagnose installation, database and parser health")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("manifest", help="export an evidence manifest for a capture")
    p.add_argument("paste_id", type=int)
    p.add_argument("--format", default="json", choices=["json", "md"])
    p.add_argument("-o", "--output", default="")
    p.add_argument("--reveal", action="store_true", help="do not redact command/secrets")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("verify", help="verify a manifest, a capture, or the evidence chain")
    p.add_argument("--manifest", default="", help="manifest JSON path")
    p.add_argument("--raw", default="", help="original artifact for offline input verification")
    p.add_argument("--paste", dest="paste_id", type=int, default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("demo", help="seed the sample program and first report")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("programs", help="list programs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_programs)

    p = sub.add_parser("findings", help="list findings")
    p.add_argument("--program", type=int, default=None)
    p.add_argument("--min-severity", default="")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("gate", help="CI gate: exit 1 if findings at/above a severity")
    p.add_argument("program", nargs="?", type=int, default=None)
    p.add_argument("--max-severity", default="high")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("export", help="export a program report")
    p.add_argument("program", type=int)
    p.add_argument("--format", default="md",
                   choices=["md", "json", "csv", "h1", "targets", "sarif"])
    p.add_argument("-o", "--output", default="")
    p.add_argument("--reveal", action="store_true", help="do not mask secrets")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("backup", help="copy the SQLite database")
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("watch", help="auto-ingest files dropped into a folder")
    p.add_argument("folder")
    p.add_argument("--program", type=int, default=None)
    p.add_argument("--target", type=int, default=None)
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--once", action="store_true", help="sweep once and exit")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("worker", help="run the native/adapter worker")
    p.add_argument("--once", action="store_true", help="claim at most one job and exit")
    p.add_argument("--poll", type=float, default=2.0, help="idle poll interval (seconds)")
    p.add_argument("--lease", type=int, default=120, help="lease duration (seconds)")
    p.add_argument("--max-jobs", type=int, default=0, help="stop after N jobs (0 = forever)")
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("tools", help="list external tool adapters and versions")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("collect", help="queue a native collector or adapter scan")
    p.add_argument("target", help="target domain, URL, IP or CIDR")
    p.add_argument("--program", type=int, default=None)
    p.add_argument("--collector", default="leadline-recon", help="native collector or adapter id")
    p.add_argument("--params", default="", help="collector options as a JSON object")
    p.add_argument("--header-profile", type=int, default=None)
    p.add_argument("--priority", type=int, default=0)
    p.add_argument("--run-now", action="store_true", help="execute immediately instead of queueing")
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("jobs", help="list, inspect, cancel, or retry scan jobs")
    p.add_argument("action", choices=["list", "show", "cancel", "retry"])
    p.add_argument("job_id", nargs="?", type=int)
    p.add_argument("--status", default="", help="filter list by status")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_jobs)

    p = sub.add_parser("history", help="target scan timeline and diffs")
    p.add_argument("target", help="target id, name, or URL")
    p.add_argument("--program", type=int, default=None)
    p.add_argument("--diff", action="store_true", help="show the latest (or selected) diff")
    p.add_argument("--from", dest="from_scan", type=int, default=0)
    p.add_argument("--to", dest="to_scan", type=int, default=0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("report", help="render a job report from its snapshot")
    p.add_argument("job_id", type=int)
    p.add_argument("--format", default="pdf", choices=["pdf", "json", "md"])
    p.add_argument("-o", "--output", default="")
    p.add_argument(
        "--include-triaged",
        action="store_true",
        help="keep false-positive findings (internal reports)",
    )
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("maintenance", help="pause or resume native worker claims")
    p.add_argument("action", choices=["on", "off"])
    p.add_argument("--reason", default="", help="why maintenance is on")
    p.set_defaults(func=cmd_maintenance)

    p = sub.add_parser(
        "import-leadline",
        help="one-way import of a Leadline SQLite database (source read-only)",
    )
    p.add_argument("--db", required=True, help="path to the Leadline SQLite database")
    p.add_argument("--program", type=int, default=None, help="merge into this program")
    p.add_argument("--program-name", default="Leadline import")
    p.add_argument("--manifest", default="", help="resume/ID-map JSON path")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="report counts; no writes")
    mode.add_argument("--verify", action="store_true", help="compare an existing import")
    p.add_argument("--no-backup", action="store_true", help="skip the destination backup")
    p.add_argument("--no-snapshots", action="store_true", help="skip history snapshots")
    p.add_argument("--no-verify", action="store_true", help="skip post-import verification")
    p.add_argument("--report", default="", help="write the JSON report to this path")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_import_leadline)

    p = sub.add_parser("secrets", help="manage header-profile encryption keys")
    p.add_argument("action", choices=["rotate"])
    p.set_defaults(func=cmd_secrets)

    p = sub.add_parser("nvd", help="import or inspect the local NVD CVE cache")
    p.add_argument("action", choices=["import", "stats"])
    p.add_argument("file", nargs="?", default="", help="NVD JSON/JSON.GZ file (import)")
    p.add_argument("--cache", default="", help="cache path (default BREADCRUMB_NVD_CACHE or ./breadcrumb.nvd.json)")
    p.add_argument("--replace", action="store_true", help="replace the cache instead of merging")
    p.add_argument("--json", action="store_true", help="machine-readable stats")
    p.set_defaults(func=cmd_nvd)

    sub.add_parser("version", help="print version").set_defaults(func=cmd_version)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
