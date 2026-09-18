"""Baseline data for the untyped sensor, in a store of its own.

C1 classifies untyped payloads and acts on none of it, which is only useful if
somebody can afterwards ask what it saw. That needs somewhere to write it, and
the obvious place was measured and rejected.

`events.jsonl` is the remediation audit store: 15 MiB, no per-kind quota, no
age-based trimming. It currently holds about 790 days of history *because
almost nothing writes to it*, so any second writer takes a proportional share
at once. Measured, 28 sensor records a day - a healthy library at 200 new
torrents a day - halved remediation retention; an adversarial torrent full of
untyped sidecars reduced it to a few days. Two further things turned out to be
false: History folds any unrecognised event into a logical row of its own, and
the Dashboard's 2,000-event window cap will drop real detections to make room.

So this is a separate file with a separate budget, and nothing reads it. No
route, no template, no dashboard card, no `iter_events` path. It exists to be
read with `jq` while the sensor is being evaluated, and the audit store is
left exactly as it was.

    observations.jsonl      current, appended to
    observations.jsonl.1    ...
    observations.jsonl.3    oldest kept

2 MiB per file and four files, which measured at roughly seven months for a
healthy library at 200 new torrents a day, five weeks for a busy mixed one and
a fortnight at the adversarial corpus rate.

**One record per candidate lifecycle, written once, at the end.** A candidate
whose bytes are not available yet writes nothing at all - `probe_data_unavailable`
is the state that repeats, so it is the one state that is never recorded, and
that is what keeps this from becoming a retry firehose. Counters accumulate in
the probe memo and are flushed with the terminal record.

**Every write is best-effort.** Nothing in this module may interrupt a scan, a
detection, a remediation or the restoration of probe steering. A failure to
record what happened is not a reason to change what happens.

Known limitation, stated rather than worked around: a candidate that never
reaches a terminal state produces no record. If its torrent is removed, or
Protectarr restarts, the accumulated counters are lost with the in-memory memo.
Closing that needs a lifecycle signal the probe lane does not currently have,
and it is deliberately not invented here. `observation_id` is deterministic so
that duplicates caused by a restart can be collapsed by whoever analyses the
file.
"""

import os
import json
import hashlib
import threading

from .. import __version__ as _protectarr_version
from .. import config as cfg_mod
from .. import logs
from . import classify

log = logs.get("probe")

SCHEMA_VERSION = 1

# Independent of the audit store's budget, and deliberately smaller: this data
# answers "what did the sensor see last month", not "what did Protectarr delete
# two years ago".
MAX_BYTES = 2 * 1024 * 1024
KEEP_FILES = 4                  # observations.jsonl + .1 + .2 + .3

# Serialised budget for the one attacker-controlled string in the record.
#
# Bounded in *serialised* bytes rather than characters, which is the only bound
# that holds. `json.dumps` escapes non-ASCII, so a 160-character path of CJK
# would serialise to about 960 bytes and quietly invalidate the retention model
# the file size was chosen from. A path is escaped and measured, not counted.
PATH_BUDGET = 200

# Nothing may exceed this on disk. A backstop rather than the mechanism: the
# path budget above is what actually holds the size down, and this catches a
# field somebody adds later without thinking about length.
MAX_RECORD_BYTES = 1024

TRUNCATED = "..."

_lock = threading.Lock()


def _path():
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".",
                        "observations.jsonl")


def _files():
    """Every readable observation file, newest first."""
    path = _path()
    return [path] + [f"{path}.{i}" for i in range(1, KEEP_FILES)]


def _serialised_len(text):
    """How many bytes this string costs inside the record, quotes excluded.

    Asks the encoder rather than guessing, because the answer depends on
    escaping: one character can cost one byte or six.
    """
    return len(json.dumps(text)) - 2


def bounded(text, budget=PATH_BUDGET):
    """A path shortened to fit `budget` serialised bytes, head and tail kept.

    Both ends, because both carry meaning: the head names the torrent's folder
    and the tail names the file, and a payload hiding under a long directory
    prefix would be unidentifiable from either alone.

    Binary search rather than a character count, since the serialised cost of a
    character is not fixed. The full value is never lost - `file_hash` in the
    record is taken from it before this runs.
    """
    if not isinstance(text, str):
        return ""
    if _serialised_len(text) <= budget:
        return text

    def shortened(keep):
        head = keep // 3
        tail = keep - head
        return text[:head] + TRUNCATED + (text[-tail:] if tail else "")

    lo, hi = 0, len(text)
    best = TRUNCATED
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = shortened(mid)
        if _serialised_len(candidate) <= budget:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def _digest(*parts):
    """128 bits of SHA-256 over NUL-joined parts.

    Truncated because this identifies a candidate for later analysis rather
    than securing anything, and a full hex digest would be a fifth of the
    record. NUL-joined so that two different splits of the same characters
    cannot collide.
    """
    h = hashlib.sha256()
    h.update(b"\x00".join(p.encode("utf-8", "replace") for p in parts))
    return h.hexdigest()[:32]


def observation_id(infohash, file_path):
    """Deterministic identity for one candidate on one torrent.

    Derived from the *full* infohash and the *full* path, never from the
    bounded one, so two runs that shorten a path differently still agree. C1
    has no persistent dedupe; this is what lets an analyst collapse the
    duplicates a restart produces.
    """
    return _digest((infohash or "").lower(), file_path or "")


def build(torrent_hash, file_path, file_size, verdict, *, first_seen,
          resolved, attempts, piece_waits, steered, requested_span,
          bytes_examined):
    """The record, with every value already bounded. Never raises.

    `requested_span` and `bytes_examined` are both here and are not the same
    number: a complete twenty-byte file is read in full at a requested span of
    4096, and reporting 4096 would claim a read nobody performed.
    """
    thash = (torrent_hash or "").lower()
    full = file_path or ""
    record = {
        "schema_version": SCHEMA_VERSION,
        "observation_id": observation_id(thash, full),
        "protectarr_version": _protectarr_version,
        "classifier_version": classify.VERSION,
        "at": logs.now(),
        "infohash": thash,
        "file": bounded(full),
        "file_hash": _digest(full),
        "size": file_size if isinstance(file_size, int) else None,
        "candidate": "no_supported_format_claim",
        "state": verdict.evidence,
        "format": verdict.format,
        "hint": verdict.hint,
        "first_seen": first_seen,
        "resolved": resolved,
        "attempts": attempts,
        "piece_waits": piece_waits,
        "steered": bool(steered),
        "requested_span": requested_span,
        "bytes_examined": bytes_examined,
    }
    return {k: v for k, v in record.items() if v is not None}


def _rotate():
    """Shift .jsonl -> .1 -> ... and drop the oldest. Caller holds the lock."""
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


def record(observation):
    """Append one observation. Returns True if it reached the disk.

    Best-effort in the strongest sense: every failure below is caught, logged
    at debug and swallowed. The probe lane has settings to restore and a scan
    to finish, and neither may be put at risk by a diagnostic file.

    `json.dumps` does the serialising and nothing else does. Its default
    `ensure_ascii` escapes every control character and every non-ASCII byte,
    so a filename containing a newline becomes two characters of escape and
    cannot begin a second JSONL record. That is the whole defence against a
    release name forging entries, and it is the encoder's job rather than a
    sanitiser of ours.
    """
    try:
        line = json.dumps(observation, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        log.debug("Observation could not be serialised: %s", e)
        return False
    if len(line) + 1 > MAX_RECORD_BYTES:
        # Should be unreachable while the path is the only unbounded field.
        # Dropping it is better than writing a record that breaks the model the
        # file size was chosen from.
        log.debug("Observation of %s is %d bytes, over the %d cap; dropped",
                  observation.get("observation_id"), len(line),
                  MAX_RECORD_BYTES)
        return False

    path = _path()
    with _lock:
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            if os.path.exists(path) and os.path.getsize(path) >= MAX_BYTES:
                _rotate()
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except (OSError, ValueError) as e:
            log.debug("Could not write observation to %s: %s", path, e)
            return False
    return True
