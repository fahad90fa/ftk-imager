from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _chain_state_path(log_path: Path) -> Path:
    return log_path.with_suffix(log_path.suffix + ".chain")


def _load_chain_state(log_path: Path) -> tuple[int, str]:
    state_path = _chain_state_path(log_path)
    if not state_path.exists():
        return 0, "0" * 64

    data = json.loads(state_path.read_text(encoding="utf-8"))
    seq = int(data.get("last_seq", 0))
    last_hash = str(data.get("last_hash", "0" * 64))
    return seq, last_hash


def _save_chain_state(log_path: Path, seq: int, event_hash: str) -> None:
    state_path = _chain_state_path(log_path)
    payload = {
        "updated_at": utc_now(),
        "last_seq": seq,
        "last_hash": event_hash,
    }
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    os.replace(tmp, state_path)


def write_audit_event(log_path: Path, event: str, **fields: Any) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    prev_seq, prev_hash = _load_chain_state(log_path)
    seq = prev_seq + 1

    payload = {
        "ts": utc_now(),
        "event": event,
        "user": getpass.getuser(),
        "host": platform.node(),
        "pid": os.getpid(),
        "seq": seq,
        "prev_hash": prev_hash,
    }
    payload.update(fields)

    event_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    payload["event_hash"] = event_hash

    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")

    _save_chain_state(log_path, seq=seq, event_hash=event_hash)


def verify_audit_chain(log_path: Path, require_all_signed: bool = True) -> dict[str, Any]:
    if not log_path.exists():
        raise FileNotFoundError(log_path)

    expected_seq = 1
    expected_prev_hash = "0" * 64
    chained_events = 0
    unsigned_events = 0

    with log_path.open("r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"invalid JSON on line {lineno}: {exc}") from exc

            if "event_hash" not in payload or "prev_hash" not in payload or "seq" not in payload:
                unsigned_events += 1
                continue

            seq = int(payload["seq"])
            prev_hash = str(payload["prev_hash"])
            event_hash = str(payload["event_hash"])

            if seq != expected_seq:
                raise RuntimeError(f"sequence mismatch on line {lineno}: expected {expected_seq}, got {seq}")
            if prev_hash != expected_prev_hash:
                raise RuntimeError(f"hash link mismatch on line {lineno}")

            signed_payload = dict(payload)
            signed_payload.pop("event_hash", None)
            calculated = hashlib.sha256(_canonical_json(signed_payload).encode("utf-8")).hexdigest()
            if calculated != event_hash:
                raise RuntimeError(f"event hash mismatch on line {lineno}")

            expected_seq += 1
            expected_prev_hash = event_hash
            chained_events += 1

    if require_all_signed and unsigned_events > 0:
        raise RuntimeError(f"audit contains unsigned events: {unsigned_events}")

    return {
        "valid": True,
        "chained_events": chained_events,
        "unsigned_events": unsigned_events,
        "last_hash": expected_prev_hash,
    }
