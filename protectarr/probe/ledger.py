"""What the probe changed, written down before it changes it.

Steering a torrent means altering settings that belong to the user: per-file
priorities, sequential download, first/last-piece priority. Protectarr has to put
them back even if it is killed halfway through, so the original values are
persisted *before* the first mutation and the entry is cleared only after a
restore that has been read back and verified.

Restore is reconciling, not replaying. It writes the recorded values as they
should now be, which makes running it twice identical to running it once, and a
torrent that vanished in the meantime is simply dropped. That is what lets
`reconcile()` run unconditionally at startup, including when the probe lane has
since been turned off - disabling a feature must not strand a torrent with most
of its files switched off.
"""

import os
import json
import time
import threading

import requests

from .. import config as cfg_mod
from .. import logs

log = logs.get("probe")

VERSION = 1
_lock = threading.RLock()

# Backoff between restore attempts for one torrent. A torrent we cannot put
# back is retried during normal operation rather than only at the next start,
# but a qBittorrent that is down should not be asked every poll.
RETRY_BACKOFF = (30, 120, 300, 900, 3600)

# Set when the ledger on disk turned out to be unreadable or corrupt. Steering
# stays off for the rest of the process: the file is the only record of what the
# user's settings were, and mutating more torrents when we have already lost one
# set of originals turns a recoverable problem into a bigger one.
_broken = None


def _path():
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".", "probe.json")


def broken():
    """Why steering is disabled, or None if the ledger is healthy."""
    return _broken


def _disable(reason):
    global _broken
    if _broken:
        return
    _broken = reason
    log.critical(
        "Probe ledger unusable: %s. Steering is now disabled for this process. "
        "Any torrent left steered by an earlier run cannot be restored "
        "automatically, because the file recording its original settings is the "
        "thing that failed. Check %s and the quarantined copy beside it, then "
        "restart Protectarr.", reason, _path())


def _quarantine(path, reason):
    """Move a corrupt ledger aside instead of overwriting it.

    The file is evidence. If it holds the only record of a steered torrent's
    original priorities, replacing it with a fresh empty ledger destroys the
    one thing that could put that torrent back.
    """
    keep = f"{path}.corrupt-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        os.replace(path, keep)
        _disable(f"{reason} (the file has been kept as {keep})")
    except OSError as e:
        _disable(f"{reason}, and it could not be moved aside either ({e})")


def _load():
    """The ledger, or None if it is unusable. None is never 'empty'."""
    if _broken:
        return None
    path = _path()
    try:
        with open(path) as fh:
            raw = fh.read()
    except FileNotFoundError:
        return {"version": VERSION, "open": {}}
    except OSError as e:
        _disable(f"could not read {path}: {e}")
        return None
    try:
        data = json.loads(raw)
    except ValueError as e:
        _quarantine(path, f"{path} is not valid JSON ({e})")
        return None
    if not (isinstance(data, dict) and isinstance(data.get("open"), dict)):
        _quarantine(path, f"{path} is valid JSON but not a probe ledger")
        return None
    return data


def _save(data):
    """Write-ahead durability, not just atomicity.

    This record is written *before* qBittorrent is mutated, so losing it after a
    power cut means the torrent stays steered with nothing left that knows how
    to put it back. os.replace alone is atomic for other readers but does not
    promise the bytes or the directory entry survived; both fsyncs do.
    """
    path = _path()
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(os.path.dirname(path) or ".")
        return True
    except OSError as e:
        log.error("Could not persist the probe ledger to %s: %s", path, e)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def _fsync_dir(d):
    """Persist the rename itself. Without this a power cut can leave the
    directory entry pointing at the previous ledger even though the new file's
    contents are safely on disk."""
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        # Windows cannot open a directory this way. Protectarr ships as a Linux
        # container, so this is a developer-machine concern rather than a
        # deployment one, and a missing directory fsync degrades durability
        # without breaking correctness.
        log.debug("Directory fsync unsupported on %s; ledger rename is not "
                  "flushed", d)
        return
    try:
        os.fsync(fd)
    except OSError as e:
        log.debug("Directory fsync failed for %s: %s", d, e)
    finally:
        os.close(fd)


def entries():
    """Every probe that has not been confirmed restored."""
    with _lock:
        data = _load()
        return dict(data["open"]) if data else {}


def open_probe(torrent_hash, name, priorities, seq_dl, first_last):
    """Record what a torrent looked like before we touch it.

    Returns False if the record could not be written, and the caller must then
    not steer: mutating settings we cannot guarantee we can restore is exactly
    the failure this file exists to prevent.

    Refuses a hash that is already open. Overwriting would record the settings
    as they are *now*, which for a torrent someone else is already steering
    means recording the steered values as the originals and then faithfully
    restoring the user's files to switched-off.
    """
    with _lock:
        data = _load()
        if data is None:
            return False
        existing = data["open"].get(torrent_hash)
        if existing:
            log.error("Probe: refusing to steer %r, it already has an open "
                      "ledger entry from %s. Two probes on one torrent would "
                      "record the steered priorities as the originals.",
                      name, existing.get("opened", "an earlier run"))
            return False
        data["open"][torrent_hash] = {
            "name": name,
            "priorities": {str(i): int(p) for i, p in priorities.items()},
            "seq_dl": bool(seq_dl),
            "f_l_piece_prio": bool(first_last),
            "opened": logs.now(),
            "restore_attempts": 0,
            "next_retry": 0,
        }
        return _save(data)


def close(torrent_hash):
    with _lock:
        data = _load()
        if data is None or data["open"].pop(torrent_hash, None) is None:
            return False
        return _save(data)


def _set_next_retry(torrent_hash, when):
    """Test seam: move an entry's backoff. Not used in production code."""
    with _lock:
        data = _load()
        if data is None or torrent_hash not in data["open"]:
            return False
        data["open"][torrent_hash]["next_retry"] = when
        return _save(data)


def _bump(torrent_hash):
    """Count a failed restore and push the next attempt out."""
    with _lock:
        data = _load()
        if data is None:
            return 0
        entry = data["open"].get(torrent_hash)
        if entry:
            n = int(entry.get("restore_attempts", 0)) + 1
            entry["restore_attempts"] = n
            entry["next_retry"] = time.time() + RETRY_BACKOFF[
                min(n - 1, len(RETRY_BACKOFF) - 1)]
            _save(data)
            return n
    return 0


def _gone(exc):
    """Did this fail because qBittorrent no longer has the torrent?"""
    resp = getattr(exc, "response", None)
    return getattr(resp, "status_code", None) in (403, 404)


def restore(qb, torrent_hash, entry=None):
    """Put one torrent back the way we found it. Returns True once verified.

    A failure deliberately leaves the entry in place so the next startup tries
    again, rather than reporting success we have not actually confirmed.
    """
    entry = entry or entries().get(torrent_hash)
    if not entry:
        return True
    priorities = {int(i): int(p) for i, p in (entry.get("priorities") or {}).items()}
    want_seq = bool(entry.get("seq_dl", False))
    want_fl = bool(entry.get("f_l_piece_prio", False))
    try:
        by_prio = {}
        for idx, prio in priorities.items():
            by_prio.setdefault(prio, []).append(idx)
        for prio, ids in by_prio.items():
            qb.set_file_priority(torrent_hash, ids, prio)
        qb.set_sequential(torrent_hash, want_seq)
        qb.set_first_last_prio(torrent_hash, want_fl)
        now = {i: f.get("priority", 1) for i, f in enumerate(qb.files(torrent_hash))}
        # Both torrent-level flags are readable from torrents/info, so there is
        # no reason to take the writes on trust. They were previously set and
        # never checked, which meant a closed entry could still leave sequential
        # download switched on for the user.
        info = qb.torrent(torrent_hash) or {}
    except requests.RequestException as e:
        if _gone(e):
            # Nothing left to restore. Holding the entry open forever would mean
            # warning about it on every startup for a torrent that is gone.
            log.info("Probe ledger: %s is no longer in qBittorrent, dropping its "
                     "entry (%s)", torrent_hash[:8], entry.get("name") or "?")
            close(torrent_hash)
            return True
        n = _bump(torrent_hash)
        log.error("Probe restore failed for %s (attempt %d): %s. The recorded "
                  "priorities are %s, sequential=%s, first/last=%s.",
                  entry.get("name") or torrent_hash[:8], n, e, priorities,
                  entry.get("seq_dl"), entry.get("f_l_piece_prio"))
        return False

    mismatched = {i: (p, now.get(i)) for i, p in priorities.items()
                  if now.get(i) != p}
    flags = {}
    if bool(info.get("seq_dl")) != want_seq:
        flags["seq_dl"] = (want_seq, bool(info.get("seq_dl")))
    if bool(info.get("f_l_piece_prio")) != want_fl:
        flags["f_l_piece_prio"] = (want_fl, bool(info.get("f_l_piece_prio")))
    if mismatched or flags:
        n = _bump(torrent_hash)
        log.error("Probe restore did not verify for %s (attempt %d): "
                  "priorities differ (index: wanted, got) %s; flags differ "
                  "(wanted, got) %s. The entry is kept so it is retried.",
                  entry.get("name") or torrent_hash[:8], n,
                  mismatched or "none", flags or "none")
        return False
    close(torrent_hash)
    log.debug("Probe restore verified for %s", entry.get("name") or torrent_hash[:8])
    return True


def reconcile(qb, announce=False):
    """Restore anything an interrupted probe left steered.

    Safe to call at any time and safe to call twice, so it runs every pass
    rather than only at startup: a restore that failed once used to sit there
    until the process was restarted, which on a container that never restarts
    meant forever. Entries in backoff are skipped silently.

    `announce` is for the first call of a process, where finding anything at all
    means a crash or a restart and is worth a warning. On later passes the same
    finding is an ordinary retry.
    """
    open_entries = entries()
    if not open_entries:
        return 0
    now = time.time()
    due = {h: e for h, e in open_entries.items()
           if float(e.get("next_retry", 0) or 0) <= now}
    if not due:
        return 0
    if announce:
        log.warning("%d torrent(s) were left steered by a probe that did not "
                    "finish (a restart or a crash); restoring them now.",
                    len(due))
    restored = 0
    for torrent_hash, entry in due.items():
        if restore(qb, torrent_hash, entry):
            restored += 1
    if restored < len(due):
        log.error("%d torrent(s) could not be restored and are still steered. "
                  "Their original settings are in %s and the next attempt is "
                  "backed off.", len(due) - restored, _path())
    return restored
