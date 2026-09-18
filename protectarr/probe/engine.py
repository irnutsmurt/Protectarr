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
2. **Steered pass.** For anything still unresolved: raise the target to maximal
   priority, lower the other *wanted* files to normal, turn on sequential
   download, and wait for the target's opening piece. Everything changed is
   recorded in the ledger first and restored in a `finally`.

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

*The wanted set is never reduced.* An earlier design switched every other file
off. Measured on a live 460-file, 149.70 GiB torrent, that makes qBittorrent
recompute `size`, `completed`, `amount_left` and `progress` against the files
that are left, and the owning *arr believes the recomputed figure: one run read
90.95% complete with 2 of 460 files wanted, fifteen seconds in. Lowering the
other wanted files to priority 1 instead of 0 steers just as well, in under
twenty seconds on the same torrent, and the accounting never moves at all.
"""

import time
import collections

import requests

from .. import logs
from ..config import DEFAULTS as _CONFIG_DEFAULTS
from ..detectors import _util, finding
from . import classify, ledger, paths, pieces, validators
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

# Why a wait ended without the piece. Named because `_steer` branches on them:
# these three say something about the torrent rather than about one file, so
# the next file on the same torrent would wait out the budget for nothing.
STALLED = "download stalled"
GONE = "torrent disappeared"
NEVER_SCHEDULED = "qBittorrent never requested the piece"

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
    "no_progress_seconds": 30,
}

_INT_KEYS = ("max_torrents_per_scan", "torrent_timeout_seconds",
             "scan_budget_seconds", "min_seeds", "header_bytes",
             "recheck_minutes", "poll_seconds", "stall_checks",
             "no_progress_seconds")


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
    p["no_progress_seconds"] = max(p["poll_seconds"] * 2,
                                   p["no_progress_seconds"])
    return p


def enabled(cfg):
    return bool(settings(cfg)["enabled"])


def _memo(state, torrent_hash):
    memo = state.setdefault("probe_memo", {})
    if len(memo) > 2000:        # long uptimes should not leak memory
        memo.clear()
    return memo.setdefault(torrent_hash, {"resolved": {}, "next_steer": 0.0})


def _first_piece(file_entry):
    return pieces.piece_range(file_entry)[0]


def targets(files):
    """Files whose extension the probe lane knows how to reason about."""
    out = []
    for i, f in enumerate(files or []):
        if validators.ext_of(f.get("name") or "") in validators.VALIDATABLE:
            out.append((i, f))
    return out


# Two kinds of candidate, judged by two different questions. A typed file is
# asked "do the bytes match the claim?"; an untyped one has no claim, so it is
# asked "what do the bytes prove?" instead.
TYPED, UNTYPED = "typed", "untyped"

# Extensions that are not in any list Protectarr already keeps but that are
# unmistakably a format claim. Kept explicit rather than folded into the
# detectors' sets, because those sets drive detection and this one only decides
# where to spend a free read.
_OTHER_CLAIMS = frozenset((
    ".srt", ".sub", ".idx", ".ass", ".ssa", ".vtt", ".sup",     # subtitles
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tbn",   # images
    ".sfv", ".md5", ".sha1", ".par2", ".torrent", ".nzb",
    ".json", ".xml", ".yaml", ".yml", ".ini", ".cue", ".log", ".sh",
))

# Every extension anything downstream reads as a claim about a format.
#
# Deliberately assembled from the *defaults* rather than from the running
# config. A user who edits their blocked extensions or their archive list is
# tuning a detector; they are not asking the probe lane to start reading bytes
# it did not read before. Selection that moved with an unrelated setting would
# be a surprise, and the failure it would cause is silent.
#
# The direction of error matters and is the reason this set can be approximate:
# an extension missing from here makes a file an untyped candidate, which costs
# one local read and can never produce a finding it would not otherwise have.
# A file wrongly listed here is simply left to the lane it already had.
_DET_DEFAULTS = _CONFIG_DEFAULTS["detection"]
_ARCHIVE_CLAIMS = frozenset(
    e.lower() for e in _DET_DEFAULTS["archive_detection"]["archive_extensions"])
CLAIM_EXTS = frozenset(
    _util.VIDEO_EXTS | _util.AUDIO_EXTS | _util.BOOK_EXTS | _util.LURE_EXTS
    | _ARCHIVE_CLAIMS | _OTHER_CLAIMS | set(validators.VALIDATABLE)
    | {e.lower() for e in _DET_DEFAULTS["blocked_extensions"]})


def is_padding(name):
    """A libtorrent pad file, under both conventions seen in the wild.

    Pad files exist to align the next real file to a piece boundary. They are
    zeros by construction, so reading one answers nothing, and they are the one
    exclusion the candidate rule makes on something other than its name's
    meaning.
    """
    name = (name or "").replace("\\", "/")
    return (name.startswith("_____padding_file")
            or "/_____padding_file" in name
            or name.split("/")[0] == ".pad")


def has_format_claim(name, files=None):
    """Does this filename claim a format that anything downstream recognises?

    The condition the untyped lane is really after, stated as its negation, and
    it is not "has an extension". A dotted scene name splits to a suffix that is
    not a claim at all: `South.Park...x265-FLUX` yields `.x265-flux`, and
    `...H.265-NTb` yields `.265-ntb`. Keying on an empty extension would catch
    the spaced form of the same release and miss the dotted one.

    The numeric case needs the rest of the file list, because `.001` means a
    split archive only in the company of one; `H.264` is the commonest token in
    a scene video name and is not a claim about anything. See
    `detectors._util._is_archive_volume`, which measured that distinction.
    """
    e = _util.ext(name)
    if not e:
        return False
    if e in CLAIM_EXTS:
        return True
    return _util.is_archive(name, files, _ARCHIVE_CLAIMS)


def untyped(files):
    """Candidates with no format claim to validate. Frozen rule, no size floor.

    There is deliberately no minimum size and no cap on how many files qualify.
    A floor was measured and rejected: it excluded the synthetic sidecars it was
    aimed at, but it also drew a visibility boundary that a sub-megabyte
    executable could be parked under on purpose. The free pass costs one `open`
    per candidate and no API calls at all, so breadth here is very nearly free,
    and the steering budget - which is not free - is bounded by the existing
    per-torrent and per-scan timeouts rather than by a file count.
    """
    out = []
    for i, f in enumerate(files or []):
        name = f.get("name") or ""
        if is_padding(name) or has_format_claim(name, files):
            continue
        out.append((i, f))
    return out


def candidates(files):
    """Every file the probe lane will read bytes for, as `(index, file, kind)`.

    In index order, which is only a stable starting point: the free pass reads
    them all and the steered pass re-orders by size.
    """
    kinds = {}
    for i, f in targets(files):
        kinds[i] = (f, TYPED)
    for i, f in untyped(files):
        kinds.setdefault(i, (f, UNTYPED))
    return [(i, kinds[i][0], kinds[i][1]) for i in sorted(kinds)]


def span_for(p, kind):
    """How many opening bytes to read for one candidate.

    A typed file is read at exactly the user's `header_bytes`; that setting's
    meaning does not change. An untyped one is read at whichever is larger of
    that and the classifier's own minimum, because what the structural parsers
    need is a property of the formats and not a preference: a PE whose
    `e_lfanew` is 0x400 does not reach its signature until byte 1050, and a
    hand-lowered `header_bytes` must not quietly turn that into "unrecognised".

    The default `header_bytes` is already `CLASSIFY_BYTES`, so on a default
    install this reads exactly what it read before.
    """
    if kind == TYPED:
        return p["header_bytes"]
    return max(p["header_bytes"], classify.CLASSIFY_BYTES)


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


def affordable(piece_size, dlspeed, budget_seconds):
    """Can one piece conceivably arrive inside the budget? (bool, why).

    This is an optimistic lower bound and nothing more: it assumes the whole
    pipe is spent on the piece we asked for. It never is. Measured target share
    of the torrent's bandwidth under this steering mode was 18.6% at ~48 MB/s
    and 0% under a ~330 KiB/s throttle, so the true time is unbounded from
    above and no coefficient would honestly cover both.

    So failing this check predicts failure and is worth acting on; passing it
    predicts nothing, which is what the runtime abort in `_wait_for_piece` is
    for.
    """
    if not piece_size or not dlspeed:
        return True, "no estimate available"
    seconds = piece_size / float(dlspeed)
    if seconds > budget_seconds:
        return False, (f"one {piece_size / (1024.0 ** 2):.0f} MiB piece needs "
                       f"at least {seconds:.0f}s at "
                       f"{dlspeed / 1024.0:.0f} KiB/s, and the probe budget is "
                       f"{budget_seconds:.0f}s")
    return True, f"at best {seconds:.0f}s of a {budget_seconds:.0f}s budget"


def steer_plan(originals, idx):
    """The priority every file should hold while `idx` is being probed.

    Three rules, in the order they matter:

    * a file the user set to 0 stays at 0. It is not ours to switch on, and
      qBittorrent would never write it to disk for us to read anyway.
    * every other originally-wanted file stays wanted, at priority 1. This is
      the whole point: the wanted set keeps its size, so qBittorrent has no
      reason to recompute the torrent's accounting and the owning *arr sees
      nothing change.
    * the target goes to 7, which is the only thing that actually steers.

    Returns the full intended state, including the files that do not move, so
    that callers and tests can read it as an assertion about every file rather
    than as a diff.
    """
    return {i: (7 if i == idx else (1 if prio else 0))
            for i, prio in originals.items()}


def _changes(plan, current):
    """{priority: [file index]} for the files `plan` actually moves.

    Grouped so each distinct priority costs one API call rather than one per
    file - on a 460-file torrent the difference is two calls against 460.
    """
    out = {}
    for i, prio in sorted(plan.items()):
        if prio != current.get(i):
            out.setdefault(prio, []).append(i)
    return out


def _judge(torrent, file_entry, single, mappings, nbytes, source, kind=TYPED):
    """Read one file's header and judge it. (finding|None, resolved, detail)."""
    name = file_entry.get("name") or ""
    path = paths.local_path(torrent, file_entry, single, mappings)
    read = paths.read_head(path, nbytes)
    if kind == UNTYPED:
        return _classified(name, read, nbytes, file_entry)

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


def _classified(name, read, nbytes, file_entry):
    """The untyped half of `_judge`: what the bytes prove, and nothing more.

    No finding is returned, and that is the whole point of this stage. The
    sensor is being proven to select and classify accurately before anything
    downstream is allowed to act on what it says, so a confirmed executable
    behind a scene name is written to the log and goes no further.

    `resolved` is the classifier's own `retryable`, inverted. It is not a
    judgement about length: a complete file shorter than a parser needs has all
    the bytes it will ever have and is answered terminally, while bytes that
    should be there and are not are worth coming back for.
    """
    verdict = classify.classify(read.data, read.ready,
                                file_size=file_entry.get("size"),
                                requested=nbytes)
    detail = verdict.note if read.ready else read.why
    # The format and the hint are mutually exclusive by construction, and are
    # written differently on purpose: a format is what was proved, a hint is
    # only what was glimpsed, and the log should not let the two read alike.
    if verdict.format:
        qualifier = f" ({verdict.format})"
    elif verdict.hint:
        qualifier = f" (prefix looked like {verdict.hint}, unproven)"
    else:
        qualifier = ""
    return None, not verdict.retryable, f"{verdict.evidence}{qualifier}: {detail}"


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
    cands = candidates(files)
    if not thash or not cands:
        return NOTHING

    memo = _memo(state, thash)
    mappings = paths.parse_mappings(p["path_mappings"])
    single = len(files) == 1

    # The piece size turns a byte range into a set of pieces, so without it
    # there is no way to establish that a header is actually downloaded. It is
    # not on the torrent record, so it costs one call per torrent per scan.
    # Failing to read it ends the pass: an availability question we cannot
    # answer is answered "no", never "probably".
    #
    # Asked before the piece states, and not merely because it is the smaller
    # response: a torrent we cannot evaluate should cost one failed call, not
    # two, and the ordering makes "we did not even look" observable.
    try:
        piece_size = (qb.properties(thash) or {}).get("piece_size")
    except requests.RequestException as e:
        log.debug("Probe: could not read properties for %s: %s", name, e)
        return NOTHING
    if not piece_size:
        log.warning("Probe: qBittorrent reported no piece_size for %r, so "
                    "which pieces cover a file's header cannot be worked out. "
                    "Skipping the torrent rather than reading bytes that may "
                    "not be downloaded.", name)
        return NOTHING

    try:
        piece_states = qb.piece_states(thash)
    except requests.RequestException as e:
        log.debug("Probe: could not read piece states for %s: %s", name, e)
        return NOTHING

    # ---- pass 1: whatever is already on disk ----
    findings, unresolved = [], []
    unreadable = 0
    for idx, f, kind in cands:
        fname = f.get("name") or ""
        if memo["resolved"].get(fname):
            continue
        nbytes = span_for(p, kind)
        if _first_piece(f) is None:
            log.warning("Probe: qBittorrent did not report piece_range for %r. "
                        "The probe lane needs it to target a file's opening "
                        "piece; qBittorrent 5.x reports it.", name)
            return NOTHING
        needed = pieces.covering(files, idx, nbytes, piece_size)
        if needed is None:
            # Not steerable either: without knowing which pieces to wait for,
            # steering would spend the budget on an undefined finish line.
            log.debug("Probe: cannot establish which pieces cover the header "
                      "of %r in %r; leaving it alone", fname, name)
            continue
        if not pieces.verified(piece_states, needed):
            unresolved.append((idx, f, needed, kind))
            continue
        find, resolved, detail = _judge(torrent, f, single, mappings, nbytes,
                                        "free", kind)
        log.debug("Probe free pass %s [%s]: %s", name, fname, detail)
        if resolved:
            memo["resolved"][fname] = True
        else:
            # The opening piece is already downloaded, so steering has nothing
            # left to fetch. Being unable to read it is a path or flush problem,
            # and steering would switch off the user's files to learn exactly
            # the same nothing. Retrying for free on a later pass costs nothing.
            unreadable += 1
        if find:
            findings.append(find)

    if unreadable and not findings:
        # The overwhelmingly likely cause, and the one thing that makes the
        # whole lane silently useless, so it is said out loud rather than left
        # at debug level.
        log.warning("Probe: %d file(s) in %r have their opening piece "
                    "downloaded but could not be read. Steering cannot help "
                    "with that. Check the probe path mapping (%s) - Settings "
                    "> Content Probe can test it against live downloads.",
                    unreadable, name, paths.describe_mappings(mappings))

    if findings or not unresolved:
        if findings:
            log.info("Probe: %s failed content validation without any steering "
                     "(%d file(s) checked from data already on disk)",
                     name, len(cands))
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

    # Preflight. Cheap, and it catches the case the live test found: a slow
    # torrent where steering is not merely slow but inert. The piece size was
    # already read above, for coverage, so this costs nothing further.
    ok, why = affordable(piece_size, torrent.get("dlspeed"), budget_end - now)
    if not ok:
        # Cooldown, unlike the `steerable` rejection above: this one is a
        # statement about the piece size, which will not change.
        memo["next_steer"] = now + p["recheck_minutes"] * 60
        log.info("Probe: not steering %s, it cannot pay off (%s)", name, why)
        return NOTHING
    log.debug("Probe: %s clears the preflight (%s)", name, why)

    memo["next_steer"] = now + p["recheck_minutes"] * 60
    return Result(tuple(_steer(qb, torrent, files, unresolved, p, mappings,
                               single, memo, budget_end)), True)


def _steer(qb, torrent, files, unresolved, p, mappings, single, memo, deadline):
    thash = (torrent.get("hash") or "").lower()
    name = torrent.get("name") or thash[:8]
    originals = {i: int(f.get("priority", 1) or 0) for i, f in enumerate(files)}

    # Biggest first: the disguised payload is the feature-sized file, so if the
    # budget runs out it should have been spent on the file that matters. Files
    # the user set to 0 are dropped rather than sorted: raising one to 7 would
    # be switching on a download they turned off.
    order = sorted((u for u in unresolved if originals.get(u[0])),
                   key=lambda u: u[1].get("size", 0) or 0, reverse=True)
    if len(order) < len(unresolved):
        log.debug("Probe: %d unresolved file(s) in %r are set to 'do not "
                  "download'; leaving them that way", len(unresolved) - len(order),
                  name)
    if not order:
        return []

    if not ledger.open_probe(thash, name, originals, torrent.get("seq_dl"),
                             torrent.get("f_l_piece_prio")):
        log.error("Probe: refusing to steer %r because the ledger could not be "
                  "written. A change we cannot guarantee to undo is not worth a "
                  "verdict.", name)
        return []

    current = dict(originals)
    findings = []
    try:
        qb.set_sequential(thash, True)
        # Torrent-wide and its exact effect on a multi-file torrent is
        # unverified, so nothing depends on it. With a single enabled file and
        # sequential download it can only help.
        qb.set_first_last_prio(thash, True)

        for idx, f, needed, kind in order:
            if time.time() >= deadline:
                break
            fname = f.get("name") or ""
            # One target at a time. Several files at 7 would just recreate the
            # competition we are trying to win. Everything else that was wanted
            # stays wanted at 1, so the torrent's size and progress are exactly
            # what they were a moment ago.
            plan = steer_plan(originals, idx)
            for prio, ids in sorted(_changes(plan, current).items()):
                qb.set_file_priority(thash, ids, prio)
            current = plan
            log.info("Probe: steering %r at %r, waiting for piece(s) %s "
                     "(%.0fs budget)", name, fname,
                     ", ".join(str(n) for n in needed), deadline - time.time())

            got, why = _wait_for_pieces(qb, thash, needed, deadline, p)
            if not got:
                log.info("Probe: no verdict for %r on %r (%s). No verdict never "
                         "means block.", name, fname, why)
                if why in (STALLED, GONE, NEVER_SCHEDULED):
                    break       # the rest of this torrent will fare no better
                continue

            find, resolved, detail = _judge(torrent, f, single, mappings,
                                            span_for(p, kind), "steered", kind)
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


def _wait_for_pieces(qb, torrent_hash, needed, deadline, p):
    """Wait for every piece covering the header to verify. Returns (got, why).

    Gives up early on a torrent that has gone dead, and on a torrent that is
    alive but is never going to pick our piece.

    The observable for the second case is the target piece's own state in the
    array `torrents/pieceStates` already returns on every poll: 0 unavailable,
    1 requested, 2 verified. Nothing closer to "progress toward this specific
    piece" is on offer, and it costs no extra call.

    It was chosen over the target file's `progress`, which is the obvious
    candidate and is wrong. In the throttled comparison run the target file's
    progress advanced from 0.0368 to 0.0611 while its opening piece sat at
    state 0 for the full five minutes: bytes were arriving for the file, none
    of them for the piece we needed. File progress would have said "keep
    waiting" for the entire budget.

    Across the runs captured so far the piece state separates the two outcomes
    cleanly. Every run that succeeded left state 0 within seconds; all four
    that failed sat at 0 for their whole window without one transient 1. A
    non-zero reading latches, so a piece that is requested, dropped and
    re-requested is not mistaken for one that was never wanted.

    `needed` is usually one piece and occasionally two, because a file that
    begins partway through a piece can push a 4 KiB header over the boundary.
    All of them have to verify; any one of them moving off 0 counts as the
    torrent having started on the range.
    """
    stalled = 0
    scheduled = False
    give_up_at = time.time() + p["no_progress_seconds"]
    while True:
        try:
            states = qb.piece_states(torrent_hash)
        except requests.RequestException as e:
            return False, f"could not read piece states ({e})"
        if pieces.verified(states, needed):
            return True, "piece downloaded"
        if pieces.scheduled(states, needed):
            scheduled = True
        elif not scheduled and time.time() >= give_up_at:
            return False, NEVER_SCHEDULED

        try:
            current = qb.torrent(torrent_hash)
        except requests.RequestException as e:
            return False, f"could not read the torrent ({e})"
        if current is None:
            return False, GONE
        if (current.get("dlspeed") or 0) / 1024.0 < p["min_speed_kib"]:
            stalled += 1
            if stalled >= p["stall_checks"]:
                return False, STALLED
        else:
            stalled = 0

        left = deadline - time.time()
        if left <= 0:
            return False, "probe budget exhausted"
        time.sleep(min(p["poll_seconds"], left))
