"""Detectors: observe and report, never judge.

A detector answers one question only - *what did we see?* It returns Findings
containing the observation and the evidence for it. It does not decide how
serious that is, and it does not decide what Protectarr should do, because both
of those depend on context the detector cannot see: an `.exe` is an attack in a
Radarr download and the entire point of a software release.

That judgement belongs to the policy layer (see `protectarr/policy.py`):

    detector -> what did we observe?
    policy   -> how dangerous is that here, and what do we do?

So a Finding deliberately has no `severity` and no `decision` field. Adding one
here would bake a media-library assumption into the observation itself, which is
the thing that stops profiles from ever working properly.
"""

from .. import logs
from ._util import finding  # noqa: F401 - re-exported for callers and tests
from . import extension, filenames, archives

# Order matters only for which finding ends up "decisive" when several fire and
# tie on severity - cheapest and most precise first.
DETECTORS = (extension, filenames, archives)

log = logs.get("detectors")


def run(files, det, ctx):
    """Run every enabled detector over a torrent's file list.

    `ctx` carries what detectors need but cannot look up themselves:
        arr_type        - owning *arr type, or None if untracked
        arr_tracked     - whether an *arr has this in its queue
        resolve_indexer - zero-arg callable, only invoked by a detector that
                          actually has a candidate (it can cost an HTTP call)

    Returns a list of findings, possibly empty.
    """
    out = []
    for mod in DETECTORS:
        try:
            out.extend(mod.detect(files, det, ctx) or [])
        except Exception as e:  # noqa: BLE001 - one broken detector must not
            # take down the scan; the others still get their say.
            log.exception("Detector %s failed", mod.__name__)
    return out
