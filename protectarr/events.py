"""Structured event history - what Protectarr did, to what, and why.

The dashboard only counts reaps; the activity log is a ring buffer of prose that
scrolls away. Neither answers the questions people actually ask afterwards:
which release was this, which app owned it, did the blocklist entry stick, and
why didn't anything come back to replace it.

Every event stores the *finding* rather than a pre-rendered sentence, so the UI
decides the wording and a new detector needs no schema change - it just writes a
new `reason` code and `describe()` learns one more line.

Storage is JSON Lines next to the config/stats files, rotated by size:

    events.jsonl      current, appended to
    events.jsonl.1    previous
    events.jsonl.2    oldest kept

Append-only is the point: a crash mid-write costs one truncated line (which
`read()` skips), never the whole history, which is what trimming old records out
of a single file in place would risk.
"""

import os
import json
import time
import uuid
import threading

from . import config as cfg_mod

SCHEMA_VERSION = 1
MAX_BYTES = 5 * 1024 * 1024
KEEP_FILES = 3                  # events.jsonl + .1 + .2
_lock = threading.Lock()


def _path():
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".", "events.jsonl")


def _files():
    """Every readable history file, newest first."""
    path = _path()
    return [path] + [f"{path}.{i}" for i in range(1, KEEP_FILES)]


def _rotate():
    """Shift events.jsonl -> .1 -> .2 and drop the oldest. Caller holds the lock."""
    path = _path()
    try:
        os.remove(f"{path}.{KEEP_FILES - 1}")
    except OSError:
        pass
    for i in range(KEEP_FILES - 2, 0, -1):
        try:
            os.replace(f"{path}.{i}", f"{path}.{i + 1}")
        except OSError:
            pass
    try:
        os.replace(path, f"{path}.1")
    except OSError:
        pass


# ---- writing ----

def finding(detector, severity, reason, **evidence):
    """Build the structured 'why' half of an event.

    `reason` is a stable machine code (the UI maps it to words); `evidence` is
    whatever that detector saw. Detectors report, policy decides - so nothing
    here says what should happen as a result.
    """
    return {"detector": detector, "severity": severity, "reason": reason,
            "evidence": {k: v for k, v in evidence.items() if v not in (None, "")}}


def record(event):
    """Append one event. Best-effort - history must never break a reap."""
    event.setdefault("schema_version", SCHEMA_VERSION)
    event.setdefault("id", uuid.uuid4().hex)
    event.setdefault("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
    event.setdefault("event_type", "detection")
    path = _path()
    with _lock:
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            if os.path.exists(path) and os.path.getsize(path) >= MAX_BYTES:
                _rotate()
            with open(path, "a") as fh:
                fh.write(json.dumps(event, separators=(",", ":")) + "\n")
        except OSError as e:
            print(f"[Protectarr] could not persist event: {e}", flush=True)
    return event


# ---- reading ----

def read(limit=200, dry_run=None, event_type=None):
    """Events newest first. `dry_run=False` gives real actions only."""
    out = []
    for p in _files():
        try:
            with open(p) as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue  # truncated tail from a crash - skip it, keep the rest
            if dry_run is not None and bool(ev.get("dry_run")) is not dry_run:
                continue
            if event_type and ev.get("event_type") != event_type:
                continue
            out.append(ev)
            if len(out) >= limit:
                return out
    return out


# ---- rendering ----

_REASON_TEXT = {
    "blocked_extension": lambda e: (
        f"Dangerous extension {e.get('extension', '')}".rstrip()),
    "lure_filename": lambda e: "Suspicious lure filename",
    "archive_no_media": lambda e: "Archive containing no media for this app",
    # Written by the probe engine once it lands; listed now to prove a new
    # detector costs one line here and no schema change.
    "content_type_mismatch": lambda e: (
        f"Claims {e.get('claimed_type', '?')} but contains "
        f"{e.get('detected_type', 'unrecognised')} data"),
}

_REQUEUE_TEXT = {
    "aired": "searched again (already aired/released)",
    "search_failed": "search command failed",
    "not_yet_aired": "held - not out yet",
    "airdate_unknown": "held - no air/release date known",
    "requeue_disabled": "requeue turned off in Safety settings",
    "verification_failed": "unknown - the check after removal failed",
    "not_applicable": "-",
}


def describe(find):
    """One line of English for a finding, evidence included."""
    if not find:
        return "-"
    ev = find.get("evidence", {})
    fn = _REASON_TEXT.get(find.get("reason"))
    text = fn(ev) if fn else (find.get("reason") or "unknown")
    name = ev.get("filename")
    return f"{text}: {name}" if name else text


def describe_requeue(rd):
    """One line of English for the requeue decision, with the held-until date."""
    if not rd:
        return "-"
    reason = rd.get("reason")
    text = _REQUEUE_TEXT.get(reason, reason or "-")
    when = rd.get("airs")
    if when and reason == "not_yet_aired":
        return f"{text} (airs {when})"
    return text
