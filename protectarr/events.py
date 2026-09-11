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
import uuid
import threading

from . import config as cfg_mod

from . import logs
from .detectors import finding  # noqa: F401 - re-export; construction lives with
                               # the detectors, which own what a Finding is.

# 1: finding carried its own severity.
# 2: severity moved to the policy block, where context can decide it; the
#    `blocked_extension` reason became the neutral `extension_match`.
# 3: detectors report everything they see, so events carry the whole `findings`
#    list and policy points at the decisive one by index.
# `normalize()` reads every version, so nothing needs migrating.
log = logs.get("events")

SCHEMA_VERSION = 3
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

def record(event):
    """Append one event. Best-effort - history must never break a reap."""
    event.setdefault("schema_version", SCHEMA_VERSION)
    event.setdefault("id", uuid.uuid4().hex)
    event.setdefault("timestamp", logs.now())
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
            log.error("Could not persist event to %s: %s", path, e)
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


def normalize(ev):
    """Flatten any schema version into (findings, decisive, severity, profile).

    v1/v2 stored one decisive finding plus an `other_findings` tail and, in v1,
    the severity on the finding itself. v3 stores the full list with an index.
    Readers work off this so the templates never branch on version.
    """
    pol = ev.get("policy") or {}
    findings = ev.get("findings")
    if findings is None:                       # v1 / v2
        head = ev.get("finding")
        findings = ([head] if head else []) + list(ev.get("other_findings") or [])
        idx = 0
    else:
        idx = pol.get("decisive_finding", 0)
    if not findings:
        return [], None, pol.get("severity"), pol.get("profile")
    if not 0 <= idx < len(findings):
        idx = 0
    decisive = findings[idx]
    severity = pol.get("severity") or decisive.get("severity")
    return findings, decisive, severity, pol.get("profile")


# ---- rendering ----

def _probe_label(detected):
    """Deferred so importing the history does not drag in the probe lane."""
    from .probe.validators import label
    return label(detected)


_REASON_TEXT = {
    "extension_match": lambda e: (
        f"Monitored extension {e.get('extension', '')}".rstrip()),
    # schema v1 spelling, kept so already-recorded history still renders.
    "blocked_extension": lambda e: (
        f"Monitored extension {e.get('extension', '')}".rstrip()),
    "lure_filename": lambda e: "Suspicious lure filename",
    "archive_no_media": lambda e: "Archive containing no media for this app",
    "content_type_mismatch": lambda e: (
        f"Claims to be {e.get('claimed_type', 'media')} but the file is "
        f"{_probe_label(e.get('detected_type'))}"),
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
