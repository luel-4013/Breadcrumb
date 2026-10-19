"""Breadcrumb headless CLI (automation / CI).

Same engine as the web UI and API v1, no server required:

    python -m app.cli ingest scan.txt --program 1
    python -m app.cli export 1 --format sarif -o out.sarif
    python -m app.cli gate 1 --max-severity high   # exit 1 if it fails
    python -m app.cli serve

Talks to the database named by BREADCRUMB_DB_PATH (default ./breadcrumb.db).
"""

import argparse
import json
import sys

from sqlmodel import Session, select

from . import __version__, reporting
from .db import DB_PATH, engine, init_db
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
    from .main import _ingest

    init_db()
    text = _read_input(args.file)
    if not text.strip():
        print("empty input", file=sys.stderr)
        return 2
    with Session(engine) as session:
        paste = _ingest(session, text, args.program, args.target, args.source)
        count = session.exec(
            select(Entity).where(Entity.paste_id == paste.id)
        ).all()
        print(
            f"capture #{paste.id}: {len(count)} entities via "
            f"{', '.join(paste.parsers or ['?'])}"
            + (f" ({len(paste.parse_errors)} parser issue(s))" if paste.parse_errors else "")
        )
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
    import shutil

    init_db()
    dest = args.output or f"breadcrumb-backup-{__version__}.db"
    engine.dispose()
    shutil.copy2(DB_PATH, dest)
    print(f"wrote {dest}")
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
    p.set_defaults(func=cmd_ingest)

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

    sub.add_parser("version", help="print version").set_defaults(func=cmd_version)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
