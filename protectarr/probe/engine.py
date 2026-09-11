"""The probe transaction: look at real bytes, then put everything back.

The fast lane reads a torrent's file list and is done in milliseconds, which is
why Protectarr costs no bandwidth. It cannot see a payload wearing a genuine
media extension, because nothing in the metadata is lying. Closing that gap
needs actual bytes, and the bet this module makes is that we only need the
*first piece of one file* - a few MB on a multi-GB fake, a verdict at well under
1% downloaded.

Two passes, in cost order:

1. **Free pass.** Pieces already on disk cost nothing and mutate nothing. A
   torrent in flight has progress, and pieces straddle file boundaries, so
   headers frequently come free. Most verdicts should land here.
2. **Steered pass.** For anything still unresolved: disable every other file,
   set the target to maximal priority, turn on sequential download, and wait for
   its opening piece. Everything changed is recorded in the ledger first and
   restored in a `finally`.

Three rules this module will not bend:

*Only verified pieces are read.* A piece reaches state 2 only after its hash
checks out. Reading bytes before that would let a hostile peer feed junk into
the header of a legitimate release and have Protectarr blocklist it.

*No verdict never means block.* Budget exhaustion, a stalled torrent, an
unreadable path and an unrecognised header all end the same way: restore, say so
in the log, find nothing.

*Steering is not free, so it is not spent blindly.* Steering only influences
which piece libtorrent picks **next**; it cannot recall a piece already in
flight. On a starved torrent the next pick can be twenty minutes away, so the
budget would be burned for nothing. Fakes are heavily seeded by design - the
attacker wants downloads - so the torrents that matter are exactly the ones
where the piece arrives quickly.
"""

import time
import collections

import requests

from .. import logs
from ..detectors import finding
from . import ledger, paths, validators
from .validators import INVALID, UNKNOWN, VALID

log = logs.get("probe")

# States where steering can plausibly work. A stopped or queued torrent will
# never fetch the piece we ask for, and metaDL has no file list yet.
ACTIVE_STATES = {"downloading", "forcedDL", "stalledDL"}

# `steered` is reported separately from the findings because the caller budgets
# the two lanes differently: reading headers that are already on disk is free
# and every candidate gets it, while steering is rationed per scan.
Result = collections.namedtuple("Result", "findings steered")
NOTHING = Result((), False)

DEFAULTS = {
    "enabled": False,
    "path_mappings": [],
    "steer": True,
    "max_torrents_per_scan": 1,
    "torrent_timeout_seconds": 120,
    "scan_budget_seconds": 120,
    "min_speed_kib": 20,
    "min_seeds": 0,
    "header_bytes": 4096,
    "recheck_minutes": 15,
    "poll_seconds": 3,
    "stall_checks": 5,
}

_INT_KEYS = ("max_torrents_per_scan", "torrent_timeout_seconds",
             "scan_budget_seconds", "min_seeds", "header_bytes",
             "recheck_minutes", "poll_seconds", "stall_checks")


def settings(cfg):
    """Probe settings with every key present and sanely bounded."""
    p = dict(DEFAULTS)
    p.update((cfg.get("detection") or {}).get("probe") or {})
    for key in _INT_KEYS:
        try:
            p[key] = int(p[key])
        except (TypeError, ValueError):
            p[key] = DEFAULTS[key]
    try:
        p["min_speed_kib"] = float(p["min_speed_kib"])
    except (TypeError, ValueError):
        p["min_speed_kib"] = DEFAULTS["min_speed_kib"]
    # Floors that stop a hand-edited config from producing a probe that either
    # hammers qBittorrent or can never finish.
    p["poll_seconds"] = max(1, p["poll_seconds"])
    p["header_bytes"] = max(64, p["header_bytes"])
    p["torrent_timeout_seconds"] = max(5, p["torrent_timeout_seconds"])
    p["scan_budget_seconds"] = max(5, p["scan_budget_seconds"])
    p["max_torrents_per_scan"] = max(0, p["max_torrents_per_scan"])
    return p


def enabled(cfg):
    return bool(settings(cfg)["enabled"])


def _memo(state, torrent_hash):
    memo = state.setdefault("probe_memo", {})
    if len(memo) > 2000:        # long uptimes should not leak memory
        memo.clear()
    return memo.setdefault(torrent_hash, {"resolved": {}, "next_steer": 0.0})


def _first_piece(file_entry):
    pr = file_entry.get("piece_range")
    if isinstance(pr, (list, tuple)) and pr:
        try:
            return int(pr[0])
        except (TypeError, ValueError):
            return None
    return None


def targets(files):
    """Files whose extension the probe lane knows how to reason about."""
    out = []
    for i, f in enumerate(files or []):
        if validators.ext_of(f.get("name") or "") in validators.VALIDATABLE:
            out.append((i, f))
    return out


def steerable(torrent, p):
    """Is it worth spending steering budget on this torrent? (bool, why).

    Speed is the real signal, not seed count: a torrent pulling several MB/s
    from leechers is perfectly steerable, while one crawling from a single seed
    will not pick our piece before the budget runs out.
    """
    state = torrent.get("state") or ""
    if state not in ACTIVE_STATES:
        return False, f"state is {state or 'unknown'}"
    if (torrent.get("progress") or 0) >= 1:
        return False, "already complete"
    seeds = torrent.get("num_seeds")
    if seeds is None:
        seeds = torrent.get("num_complete") or 0
    if seeds < p["min_seeds"]:
        return False, f"only {seeds} connected seed(s)"
    speed = (torrent.get("dlspeed") or 0) / 1024.0
    if speed < p["min_speed_kib"]:
        return False, (f"downloading at {speed:.0f} KiB/s, below the "
                       f"{p['min_speed_kib']:.0f} KiB/s needed to steer it")
    return True, "ok"


def _judge(torrent, file_entry, single, mappings, nbytes, source):
    """Read one file's header and judge it. (finding|None, resolved, detail)."""
    name = file_entry.get("name") or ""
    path = paths.local_path(torrent, file_entry, single, mappings)
    read = paths.read_head(path, nbytes)
    state, detected, note = validators.validate(name, read.data, read.ready)

    if state == INVALID:
        return finding("probe", "content_type_mismatch",
                       filename=name,
                       claimed_type=validators.ext_of(name),
                       detected_type=detected,
                       header=read.data[:16].hex(" "),
                       source=source), True, note
    if state == VALID:
        return None, True, note
    # UNKNOWN. Whether it is worth coming back for depends on why: unreadable
    # bytes may arrive later, an unrecognised header never will.
    return None, read.ready, (note if read.ready else read.why)


def inspect(qb, torrent, files, cfg, state, deadline=None, allow_steer=True):
    """Probe one torrent. Returns a Result; findings may be empty.

    Never raises for an ordinary failure - an unreachable qBittorrent or an
    unreadable file is a fact about our access, not about the torrent.
    """
    p = settings(cfg)
    if not p["enabled"]:
        return NOTHING
    thash = (torrent.get("hash") or "").lower()
    name = torrent.get("name") or thash[:8]
    tgts = targets(files)
    if not thash or not tgts:
        return NOTHING

    memo = _memo(state, thash)
    mappings = paths.parse_mappings(p["path_mappings"])
    single = len(files) == 1
    nbytes = p["header_bytes"]

    try:
        piece_states = qb.piece_states(thash)
    except requests.RequestException as e:
        log.debug("Probe: could not read piece states for %s: %s", name, e)
        return NOTHING

    # ---- pass 1: whatever is already on disk ----
    findings, unresolved = [], []
    for idx, f in tgts:
        fname = f.get("name") or ""
        if memo["resolved"].get(fname):
            continue
        first = _first_piece(f)
        if first is None:
            log.warning("Probe: qBittorrent did not report piece_range for %r. "
                        "The probe lane needs it to target a file's opening "
                        "piece; qBittorrent 5.x reports it.", name)
            return NOTHING
        if not (0 <= first < len(piece_states) and piece_states[first] == 2):
            unresolved.append((idx, f, first))
            continue
        find, resolved, detail = _judge(torrent, f, single, mappings, nbytes, "free")
        log.debug("Probe free pass %s [%s]: %s", name, fname, detail)
        if resolved:
            memo["resolved"][fname] = True
        else:
            unresolved.append((idx, f, first))
        if find:
            findings.append(find)

    if findings or not unresolved:
        if findings:
            log.info("Probe: %s failed content validation without any steering "
                     "(%d file(s) checked from data already on disk)",
                     name, len(tgts))
        return Result(tuple(findings), False)

    # ---- pass 2: steer qBittorrent at one file, then put it back ----
    if not p["steer"] or not allow_steer:
        log.debug("Probe: %s has %d unresolved file(s); not steering (%s)",
                  name, len(unresolved),
                  "turned off" if not p["steer"] else "no budget left this scan")
        return NOTHING
    if cfg.get("dry_run", True):
        # Dry run means Protectarr changes nothing, and steering changes the
        # user's per-file priorities. The free pass above still runs, so a dry
        # run is not blind - it just never reaches for the settings.
        log.debug("Probe: not steering %s, this is a dry run", name)
        return NOTHING
    now = time.time()
    if now < memo.get("next_steer", 0):
        return NOTHING
    ok, why = steerable(torrent, p)
    if not ok:
        # No cooldown here: the torrent may pick up speed, and re-checking this
        # costs nothing but a dict lookup.
        log.debug("Probe: not steering %s (%s)", name, why)
        return NOTHING

    budget_end = now + p["torrent_timeout_seconds"]
    if deadline is not None:
        budget_end = min(budget_end, deadline)
    memo["next_steer"] = now + p["recheck_minutes"] * 60
    return Result(tuple(_steer(qb, torrent, files, unresolved, p, mappings,
                               single, memo, budget_end)), True)


def _steer(qb, torrent, files, unresolved, p, mappings, single, memo, deadline):
    thash = (torrent.get("hash") or "").lower()
    name = torrent.get("name") or thash[:8]
    originals = {i: int(f.get("priority", 1) or 0) for i, f in enumerate(files)}

    if not ledger.open_probe(thash, name, originals, torrent.get("seq_dl"),
                             torrent.get("f_l_piece_prio")):
        log.error("Probe: refusing to steer %r because the ledger could not be "
                  "written. A change we cannot guarantee to undo is not worth a "
                  "verdict.", name)
        return []

    # Biggest first: the disguised payload is the feature-sized file, so if the
    # budget runs out it should have been spent on the file that matters.
    order = sorted(unresolved, key=lambda u: u[1].get("size", 0) or 0, reverse=True)
    findings = []
    try:
        qb.set_sequential(thash, True)
        # Torrent-wide and its exact effect on a multi-file torrent is
        # unverified, so nothing depends on it. With a single enabled file and
        # sequential download it can only help.
        qb.set_first_last_prio(thash, True)

        for idx, f, first in order:
            if time.time() >= deadline:
                break
            fname = f.get("name") or ""
            # One file at a time. With several enabled, sequential download
            # walks the first file to its end rather than jumping to the next
            # file's opening piece, so the second target would never arrive.
            # The target is incomplete by construction (its first piece is
            # missing), so the torrent cannot look finished to the owning *arr
            # while everything else is switched off.
            others = [i for i in originals if i != idx]
            qb.set_file_priority(thash, others, 0)
            qb.set_file_priority(thash, [idx], 7)
            log.info("Probe: steering %r at %r, waiting for piece %d "
                     "(%.0fs budget)", name, fname, first, deadline - time.time())

            got, why = _wait_for_piece(qb, thash, first, deadline, p)
            if not got:
                log.info("Probe: no verdict for %r on %r (%s). No verdict never "
                         "means block.", name, fname, why)
                if why in ("download stalled", "torrent disappeared"):
                    break       # the rest of this torrent will fare no better
                continue

            find, resolved, detail = _judge(torrent, f, single, mappings,
                                            p["header_bytes"], "steered")
            log.info("Probe: %r [%s] -> %s", name, fname, detail)
            if resolved:
                memo["resolved"][fname] = True
            if find:
                findings.append(find)
                break           # one confirmed lie is enough
    except requests.RequestException as e:
        log.warning("Probe: steering %r failed: %s", name, e)
    finally:
        # The whole point of the ledger. Runs on success, on failure, and on the
        # way out of an exception.
        ledger.restore(qb, thash)
    return findings


def _wait_for_piece(qb, torrent_hash, piece, deadline, p):
    """Wait for one piece to verify. Returns (got, why).

    Gives up early on a torrent that has gone dead rather than burning the
    remaining budget watching a number that is not moving.
    """
    stalled = 0
    while True:
        try:
            states = qb.piece_states(torrent_hash)
        except requests.RequestException as e:
            return False, f"could not read piece states ({e})"
        if 0 <= piece < len(states) and states[piece] == 2:
            return True, "piece downloaded"

        try:
            current = qb.torrent(torrent_hash)
        except requests.RequestException as e:
            return False, f"could not read the torrent ({e})"
        if current is None:
            return False, "torrent disappeared"
        if (current.get("dlspeed") or 0) / 1024.0 < p["min_speed_kib"]:
            stalled += 1
            if stalled >= p["stall_checks"]:
                return False, "download stalled"
        else:
            stalled = 0

        left = deadline - time.time()
        if left <= 0:
            return False, "probe budget exhausted"
        time.sleep(min(p["poll_seconds"], left))
