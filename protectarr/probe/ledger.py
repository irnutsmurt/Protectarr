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
import threading

import requests

from .. import config as cfg_mod
from .. import logs

log = logs.get("probe")

VERSION = 1
_lock = threading.Lock()


def _path():
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".", "probe.json")


def _load():
    try:
        with open(_path()) as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("open"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": VERSION, "open": {}}


def _save(data):
    path = _path()
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
        return True
    except OSError as e:
        log.error("Could not persist the probe ledger to %s: %s", path, e)
        return False


def entries():
    """Every probe that has not been confirmed restored."""
    with _lock:
        return dict(_load()["open"])


def open_probe(torrent_hash, name, priorities, seq_dl, first_last):
    """Record what a torrent looked like before we touch it.

    Returns False if the record could not be written, and the caller must then
    not steer: mutating settings we cannot guarantee we can restore is exactly
    the failure this file exists to prevent.
    """
    with _lock:
        data = _load()
        data["open"][torrent_hash] = {
            "name": name,
            "priorities": {str(i): int(p) for i, p in priorities.items()},
            "seq_dl": bool(seq_dl),
            "f_l_piece_prio": bool(first_last),
            "opened": logs.now(),
            "restore_attempts": 0,
        }
        return _save(data)


def close(torrent_hash):
    with _lock:
        data = _load()
        if data["open"].pop(torrent_hash, None) is None:
            return False
        return _save(data)


def _bump(torrent_hash):
    with _lock:
        data = _load()
        entry = data["open"].get(torrent_hash)
        if entry:
            entry["restore_attempts"] = int(entry.get("restore_attempts", 0)) + 1
            _save(data)
            return entry["restore_attempts"]
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
    try:
        by_prio = {}
        for idx, prio in priorities.items():
            by_prio.setdefault(prio, []).append(idx)
        for prio, ids in by_prio.items():
            qb.set_file_priority(torrent_hash, ids, prio)
        qb.set_sequential(torrent_hash, entry.get("seq_dl", False))
        qb.set_first_last_prio(torrent_hash, entry.get("f_l_piece_prio", False))
        now = {i: f.get("priority", 1) for i, f in enumerate(qb.files(torrent_hash))}
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
    if mismatched:
        n = _bump(torrent_hash)
        log.error("Probe restore did not verify for %s (attempt %d): file "
                  "priorities still differ (index: wanted, got) %s. The entry is "
                  "kept so the next start retries it.",
                  entry.get("name") or torrent_hash[:8], n, mismatched)
        return False
    close(torrent_hash)
    log.debug("Probe restore verified for %s", entry.get("name") or torrent_hash[:8])
    return True


def reconcile(qb):
    """Restore anything an interrupted probe left steered.

    Safe to call at any time and safe to call twice. Returns the number of
    torrents put back.
    """
    open_entries = entries()
    if not open_entries:
        return 0
    log.warning("%d torrent(s) were left steered by a probe that did not finish "
                "(a restart or a crash); restoring them now.", len(open_entries))
    restored = 0
    for torrent_hash, entry in open_entries.items():
        if restore(qb, torrent_hash, entry):
            restored += 1
    if restored < len(open_entries):
        log.error("%d torrent(s) could not be restored and are still steered. "
                  "Their original settings are in %s.",
                  len(open_entries) - restored, _path())
    return restored
