"""Evidence-chain verification shared by the API and CLI.

The chain is a linear sequence of SHA-256 links. Deleting a program removes
captures and leaves a recorded *gap*, not a false tamper alarm. A broken
content hash, a fork, or a bad head/length is a real integrity failure.
"""

from __future__ import annotations

import hashlib
from collections import Counter

from sqlmodel import Session, select

from .models import EvidenceChain, Paste


def verify_chain(session: Session) -> dict:
    pastes = session.exec(select(Paste).order_by(Paste.id)).all()
    by_id = {p.id: p for p in pastes}
    broken, unsealed, gaps = None, 0, 0
    sealed = [p for p in pastes if p.content_sha256 and p.chain_hash]
    sequence_ok = True
    previous_seq = 0
    for p in sealed:
        if p.chain_seq is None or p.chain_seq <= previous_seq:
            sequence_ok = False
            break
        previous_seq = p.chain_seq
    prev_counts = Counter(p.prev_paste_id for p in sealed if p.prev_paste_id is not None)
    forks = sum(1 for count in prev_counts.values() if count > 1)
    for p in pastes:
        if not p.content_sha256 or not p.chain_hash:
            unsealed += 1
            continue
        content = hashlib.sha256(
            (p.raw or "").encode("utf-8", errors="replace")
        ).hexdigest()
        if content != p.content_sha256:
            broken = p.id
            break
        if p.prev_paste_id is None:
            expected = hashlib.sha256(f"genesis:{content}".encode("utf-8")).hexdigest()
        else:
            prev = by_id.get(p.prev_paste_id)
            if prev is None:
                gaps += 1
                continue
            expected = hashlib.sha256(
                f"{prev.chain_hash or 'genesis'}:{content}".encode("utf-8")
            ).hexdigest()
        if expected != p.chain_hash:
            broken = p.id
            break
    chain = session.get(EvidenceChain, 1)
    last = max(sealed, key=lambda p: (p.chain_seq or 0, p.id or 0)) if sealed else None
    head_ok = chain is not None and chain.head_paste_id == (last.id if last else None)
    length_ok = chain is not None and chain.length == len(sealed)
    valid = (
        broken is None
        and forks == 0
        and sequence_ok
        and head_ok
        and length_ok
    )
    return {
        "valid": valid,
        "captures": len(pastes),
        "sealed": len(pastes) - unsealed,
        "unsealed": unsealed,
        "gaps": gaps,
        "broken_at": broken,
        "forks": forks,
        "sequence_ok": sequence_ok,
        "chain_head": chain.head_paste_id if chain is not None else None,
        "chain_length": chain.length if chain is not None else 0,
        "head_ok": head_ok,
        "length_ok": length_ok,
    }
