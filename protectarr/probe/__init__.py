"""The probe lane: a verdict from the bytes, not from the metadata.

Kept as its own package, and deliberately behind the fast lane, because the two
have opposite cost profiles. The fast lane reads a file list and answers in
milliseconds with no bandwidth at all; that is Protectarr's selling point and it
is never allowed to regress. The probe lane downloads a few megabytes and mutates
qBittorrent settings it then has to restore, so it is off by default, budgeted,
and only ever runs on a torrent the fast lane had nothing to say about.

    validators  does this parse as what its extension claims? (tri-state)
    paths       where are the bytes, and are they really the file's bytes?
    ledger      what did we change, written down before we change it
    engine      the two passes, the budget, and the restore

Honest calibration: the blatant `.exe` in a season pack is what people hit today
and the fast lane already kills it for free. This lane is hardening against the
next move - a payload wearing a real `.mkv` extension - not a fix for something
broken.
"""

from . import validators  # noqa: F401 - re-exported for the wording helpers
from .engine import enabled, inspect, settings, steerable, targets  # noqa: F401
from .ledger import broken, reconcile  # noqa: F401
