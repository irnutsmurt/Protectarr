"""Small JSON files that have to survive a power cut.

Two of Protectarr's records are written *before* the thing they describe
happens: what a probe is about to change, and what a remediation is about to
delete. That makes ordinary atomic replacement insufficient. `os.replace` is
atomic from another reader's point of view but promises nothing about whether
the bytes, or the directory entry naming them, ever reached the disk. Losing
one of these files does not lose a cache; it loses the only knowledge that an
irreversible action was in flight.

A file that turns out to be corrupt is moved aside rather than overwritten, and
the store reports itself broken from then on. The file is evidence. Replacing
it with a fresh empty one destroys the only record of work that may still need
finishing, and doing that silently is worse than refusing to continue.
"""

import os
import json
import time
import threading

from . import config as cfg_mod
from . import logs

log = logs.get("store")


class Store:
    """A versioned dict-of-records persisted beside the config file."""

    def __init__(self, filename, version, key, label):
        self.filename = filename
        self.version = version
        self.key = key
        self.label = label
        self._lock = threading.RLock()
        self._broken = None

    def path(self):
        return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".",
                            self.filename)

    def broken(self):
        """Why this store is unusable, or None if it is healthy."""
        return self._broken

    def reset(self):
        """Forget a broken flag. For tests; a live process stays broken."""
        self._broken = None

    def _disable(self, reason):
        if self._broken:
            return
        self._broken = reason
        log.critical(
            "%s unusable: %s. Protectarr will not start new work that depends "
            "on it. Check %s and any quarantined copy beside it, then restart "
            "Protectarr.", self.label, reason, self.path())

    def _quarantine(self, path, reason):
        keep = f"{path}.corrupt-{time.strftime('%Y%m%d-%H%M%S')}"
        try:
            os.replace(path, keep)
            self._disable(f"{reason} (the file has been kept as {keep})")
        except OSError as e:
            self._disable(f"{reason}, and it could not be moved aside either ({e})")

    def load(self):
        """The whole document, or None if it is unusable.

        None is never "empty". A caller that treats the two the same will
        happily start a second irreversible action while the first is still
        unaccounted for.
        """
        if self._broken:
            return None
        path = self.path()
        try:
            with open(path) as fh:
                raw = fh.read()
        except FileNotFoundError:
            return {"version": self.version, self.key: {}}
        except OSError as e:
            self._disable(f"could not read {path}: {e}")
            return None
        try:
            data = json.loads(raw)
        except ValueError as e:
            self._quarantine(path, f"{path} is not valid JSON ({e})")
            return None
        if not (isinstance(data, dict) and isinstance(data.get(self.key), dict)):
            self._quarantine(path, f"{path} is valid JSON but not {self.label}")
            return None
        return data

    def save(self, data):
        """Flush, fsync, replace, fsync the directory. Returns success."""
        path = self.path()
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
            log.error("Could not persist %s to %s: %s", self.label, path, e)
            try:
                os.remove(tmp)
            except OSError:
                pass
            return False

    def records(self):
        """Every record, or {} if the store is unusable."""
        with self._lock:
            data = self.load()
            return dict(data[self.key]) if data else {}

    def mutate(self, fn):
        """Read, apply `fn(records)`, write back. Returns success.

        `fn` may return False to abandon the write without it counting as a
        failure - that is how a caller refuses to overwrite something.
        """
        with self._lock:
            data = self.load()
            if data is None:
                return False
            if fn(data[self.key]) is False:
                return False
            return self.save(data)


def _fsync_dir(d):
    """Persist the rename itself.

    Without this a power cut can leave the directory entry pointing at the
    previous file even though the new contents are safely on disk.
    """
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        # Windows cannot open a directory this way. Protectarr ships as a Linux
        # container, so this is a developer-machine concern rather than a
        # deployment one, and a missing directory fsync degrades durability
        # without breaking correctness.
        log.debug("Directory fsync unsupported on %s; rename is not flushed", d)
        return
    try:
        os.fsync(fd)
    except OSError as e:
        log.debug("Directory fsync failed for %s: %s", d, e)
    finally:
        os.close(fd)
