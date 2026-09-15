"""What Protectarr is about to do to an *arr, written down before it does it.

Reaping a fake is not one action, it is three, and only the first is
irreversible:

1. DELETE the queue item with `blocklist=true`. The release is gone and the
   *arr will not grab it again.
2. Verify that it really happened, via the history + blocklist oracle in
   `arr.py`.
3. Decide whether to search for a replacement, and follow that search to a
   terminal state.

A crash between 1 and 2 used to lose everything. On the next start the queue
item is absent, which is exactly what a successful reap looks like *and* what a
reap that never happened looks like, so Protectarr could neither confirm its own
work nor safely repeat it. Hence this file: the intent is persisted before the
DELETE, and the milestone only advances on evidence.

    pending           the destructive boundary has not been verified. Anything
                      could have happened; assume nothing.
    removed           the oracle found both the downloadFailed event carrying
                      this exact infohash and the blocklist row it produced.
    settled           the replacement-search decision is finished, including
                      the terminal state of a search if one was issued.
    failed_unverified the queue item is gone and the oracle cannot account for
                      it. No automatic re-search, ever: the one thing worse
                      than not replacing a fake is asking the *arr to go and
                      find the same condemned release again.

`settled` means the *arr finished running the search command. It does not mean
a replacement was acquired, and the terminal result and message are recorded
so that distinction survives into the log.
"""

import time
import uuid

import requests

from . import events
from . import logs
from .store import Store

log = logs.get("intents")

VERSION = 1
PENDING = "pending"
REMOVED = "removed"
SETTLED = "settled"
FAILED_UNVERIFIED = "failed_unverified"
UNFINISHED = (PENDING, REMOVED)
# States that must stop a fresh remediation being started for the same torrent.
# failed_unverified is in here and is deliberately terminal: Protectarr could
# not establish what happened last time, and repeating an irreversible action
# you cannot account for is not a retry, it is a second unexplained event.
BLOCKS_NEW = (PENDING, REMOVED, FAILED_UNVERIFIED)

# Terminal command states. "unknown" is in here because an *arr that has never
# heard of the command id is not going to start knowing about it.
TERMINAL = {"completed", "failed", "aborted", "cancelled", "unknown"}

# Terminal records are kept for diagnostics rather than deleted on the spot,
# but not forever. failed_unverified is exempt from the age rule: it is the
# state a human has to look at, and quietly ageing it out would hide it.
KEEP_SETTLED_DAYS = 7
MAX_RECORDS = 500

_store = Store("intents.json", VERSION, "intents", "the remediation intents file")

# When this process started. An intent opened before it was opened by an
# earlier run, which is the only honest definition of "recovered after a
# restart" available here - `reconcile` runs on every scan, so the fact that
# reconcile made a transition says nothing on its own.
_STARTED = time.time()


def broken():
    return _store.broken()


def records():
    return _store.records()


def get(torrent_hash):
    return _store.records().get((torrent_hash or "").lower())


def unfinished():
    """Intents whose destructive boundary has not been accounted for."""
    return {h: r for h, r in _store.records().items()
            if r.get("milestone") in UNFINISHED}


def blocked():
    """Torrents that must not be remediated again without a human looking."""
    return {h: r for h, r in _store.records().items()
            if r.get("milestone") in BLOCKS_NEW}


def media_ref(client, record):
    """The fields needed to search for, and date-gate, this item later.

    A queue record does not survive the queue item, so the two ids the *arr
    will want afterwards are copied out now. Both lookups use the same field
    on every supported type, but they are read from the type table rather than
    assumed equal.
    """
    _, _, search_field = client.meta["search"]
    _, airdate_field, _ = client.meta["airdate"]
    ref = {}
    for field in (search_field, airdate_field):
        if field and record.get(field) is not None:
            ref[field] = record.get(field)
    return ref


def open_intent(torrent_hash, client, record, indexer=None, watermark=None,
                encounter_id=None):
    """Persist `pending` before the destructive call. Returns True on success.

    A False return must stop the caller from issuing the DELETE. An action we
    cannot write down is an action we cannot finish, verify, or explain, and
    doing it anyway trades a recoverable failure for an unaccountable one.

    An existing unfinished intent for the same hash is not overwritten. Two
    remediations racing on one torrent would have the second record its own
    fresh watermark over the first's, and the first's evidence would then look
    like it belonged to an event that had not happened yet.
    """
    thash = (torrent_hash or "").lower()
    if not thash:
        return False
    now = time.time()

    def apply(intents):
        existing = intents.get(thash)
        if existing and existing.get("milestone") in BLOCKS_NEW:
            log.error("Refusing to start a second remediation for %s: one from "
                      "%s is still at %r.", thash[:8],
                      time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(existing.get("opened", now))),
                      existing.get("milestone"))
            return False
        intents[thash] = {
            "milestone": PENDING,
            "hash": thash,
            # One remediation, not one torrent. The infohash cannot carry this
            # on its own: a release can legitimately be reaped, re-grabbed as
            # its own replacement and reaped again, which was not a thought
            # experiment - it happened during the live acceptance run on
            # 2026-09-13. Without a per-remediation id the history of the
            # second attempt would fold into the first.
            "remediation_id": uuid.uuid4().hex,
            # The swarm observed immediately before this remediation, if any.
            # Optional and nullable by design: the peers are harvested before
            # the intent exists, harvesting can be switched off, and the
            # category-fallback path opens no intent at all. Carried here so
            # the outcome can be written back onto the encounter from
            # `audit()`, which is the one place every later transition passes
            # through - including the ones a reconcile makes after a restart.
            # Intents written before this field existed simply have None.
            "encounter_id": encounter_id,
            "arr": client.name,
            "arr_type": client.type,
            "queue_id": record.get("id"),
            "media": media_ref(client, record),
            # The *arr's own name for the release. Kept for the log and for a
            # bug report; identity comes from the hash, never from this.
            "release_title": record.get("title"),
            # Visibility and per-indexer stats only. Measured useless as
            # identity: 13 of 14 blocklist rows named the same indexer.
            "indexer": indexer,
            # The newest history id before we act, so the event we look for
            # afterwards can be required to be newer than anything that
            # already existed. Clock-free, unlike a timestamp window.
            "watermark": watermark,
            "opened": now,
            "updated": now,
            "attempts": 0,
            "evidence": None,
            "search": None,
            "error": None,
        }
        _prune(intents)
        return True

    ok = _store.mutate(apply)
    if not ok and not _store.broken():
        log.debug("Intent for %s was refused rather than failing to write",
                  thash[:8])
    return ok


def update(torrent_hash, **fields):
    """Merge fields into an existing intent. Returns True on success."""
    thash = (torrent_hash or "").lower()

    def apply(intents):
        if thash not in intents:
            return False
        intents[thash].update(fields)
        intents[thash]["updated"] = time.time()
        _prune(intents)
        return True

    return _store.mutate(apply)


def _prune(intents):
    """Drop terminal records that are old, and cap the file's size."""
    cutoff = time.time() - KEEP_SETTLED_DAYS * 86400
    for h, rec in list(intents.items()):
        if rec.get("milestone") == SETTLED and rec.get("updated", 0) < cutoff:
            del intents[h]
    if len(intents) <= MAX_RECORDS:
        return
    # Oldest first, but never evict something still unfinished: an unfinished
    # intent is the only record that an irreversible action may be outstanding.
    finished = sorted((r.get("updated", 0), h) for h, r in intents.items()
                      if r.get("milestone") not in UNFINISHED)
    for _, h in finished[:len(intents) - MAX_RECORDS]:
        del intents[h]
    if len(intents) > MAX_RECORDS:
        log.warning("%d remediation intents are unfinished or unverified. "
                    "Protectarr keeps those rather than pruning them; check "
                    "the log for failed_unverified entries.", len(intents))


def recovered(intent):
    """Was this intent left behind by an earlier run of Protectarr?"""
    return bool(intent.get("opened")) and intent["opened"] < _STARTED


def audit(intent, source, note=None):
    """Write one History event for where a remediation has got to.

    Everything below happens on a background worker, usually minutes or a
    restart after the operator was last looking. Until now it existed only in
    the log, which means the two outcomes that most need explaining - a
    remediation recovered after a crash, and one that deliberately failed
    closed - were invisible on the History page.

    Deliberately a projection of the intent, not a copy of it. `intents.json`
    is recovery state with a 7-day age-out and a 500-record cap; the audit
    trail is `events.jsonl` and has to stand on its own once the intent is
    gone. So this writes the fields an operator needs to understand the
    outcome, and leaves the queue ids, attempt counters and watermarks where
    they belong.
    """
    search = intent.get("search") or {}
    evidence = intent.get("evidence") or {}
    events.record({
        "event_type": "remediation",
        # The join key. Present on the detection event too, so the UI relates
        # them by equality rather than by guessing from hash and timestamp.
        "remediation_id": intent.get("remediation_id"),
        "torrent": {"hash": intent.get("hash"),
                    "name": intent.get("release_title"),
                    "indexer": intent.get("indexer")},
        "owner": {"type": intent.get("arr_type"), "instance": intent.get("arr"),
                  "media": None, "release_title": intent.get("release_title")},
        "remediation": {
            "milestone": intent.get("milestone"),
            # "live" is the reap itself; "follow-up" is a later scan finishing
            # what it started. Both are routine.
            "source": source,
            # This one is not routine, and it is a separate question from
            # `source`: reconcile runs on every scan, so the transition being
            # made by reconcile proves nothing. What makes it a recovery is
            # that the intent outlived the process that opened it.
            "recovered": recovered(intent),
            "note": note,
            "verification": evidence.get("why"),
            "history_event": (evidence.get("event") or {}).get("id"),
            "blocklist_row": (evidence.get("blocklist") or {}).get("id"),
            "search": {"command_id": search.get("command_id"),
                       "state": search.get("state"),
                       "result": search.get("result"),
                       "message": search.get("message")} if search else None,
            "error": intent.get("error"),
        },
        # These are real actions on a real *arr. A reap only reaches this file
        # when it was not a dry run, so the History Live filter must show them.
        "dry_run": False,
    })
    # Keep the swarm evidence in step with the lifecycle. This runs on every
    # transition, including the ones a reconcile makes minutes or a restart
    # later, which is why the encounter id rides on the intent rather than
    # being held in memory by whoever opened it.
    _sync_encounter_outcome(intent)


def _sync_encounter_outcome(intent):
    """Snapshot the current milestone onto the encounter. Best effort.

    Imported here rather than at module scope: the evidence store is optional
    to the remediation path and must never be the reason an audit event fails
    to be written.
    """
    enc_id = intent.get("encounter_id")
    if not enc_id:
        return
    try:
        from . import evidence
        evidence.set_outcome(enc_id, intent.get("milestone"),
                             intent.get("error")
                             or (intent.get("evidence") or {}).get("why"))
    except Exception as e:  # noqa: BLE001 - evidence never blocks the audit
        log.warning("Could not update swarm evidence for remediation %s: %s",
                    intent.get("remediation_id"), e)


def verify(client, intent):
    """Ask the oracle about one intent. Returns the evidence dict.

    Deliberately does not decide anything. The caller owns the difference
    between "not yet" during a live reap and "not ever" on a restart.
    """
    return client.verify_remediation(intent.get("hash"),
                                     after_id=intent.get("watermark"))


def poll_search(client, intent):
    """Advance a search that was issued but not followed to the end.

    Returns True when the search reached a terminal state, which is the
    condition for `settled`. It is not a statement that anything was found.
    """
    search = intent.get("search") or {}
    command_id = search.get("command_id")
    if not command_id:
        return True
    state, result, message = client.command_status(command_id)
    if state is None:
        return False                 # could not look; try again later
    search = dict(search, state=state, result=result, message=message)
    update(intent["hash"], search=search)
    if state not in TERMINAL:
        return False
    log.info("%s replacement search for %r finished: %s/%s%s", client.name,
             intent.get("release_title"), state, result,
             f" ({message})" if message else "")
    return True


def reconcile(clients, on_unverified=None):
    """Account for every intent left unfinished by an earlier run.

    Runs before ordinary scanning, so a torrent whose remediation is still
    outstanding is not picked up again and remediated twice.

    Returns a summary dict. Nothing here ever issues a search: deciding to
    replace something is the caller's business, and this function's only job is
    to establish what actually happened.
    """
    by_name = {c.name: c for c in clients}
    out = {"checked": 0, "removed": 0, "unverified": 0, "unreachable": 0}
    for thash, intent in sorted(unfinished().items()):
        client = by_name.get(intent.get("arr"))
        if client is None:
            log.warning("Remediation intent for %r names the *arr %r, which is "
                        "no longer configured. Leaving it alone; removing the "
                        "instance is not evidence about the release.",
                        intent.get("release_title"), intent.get("arr"))
            out["unreachable"] += 1
            continue
        out["checked"] += 1
        try:
            _reconcile_one(client, thash, intent, out, on_unverified)
        except requests.RequestException as e:
            log.warning("Could not reconcile the remediation of %r against %s: "
                        "%s. It stays at %r and will be retried.",
                        intent.get("release_title"), client.name, e,
                        intent.get("milestone"))
            out["unreachable"] += 1
    return out


def _reconcile_one(client, thash, intent, out, on_unverified):
    if intent.get("milestone") == REMOVED:
        if poll_search(client, intent):
            update(thash, milestone=SETTLED)
            audit(get(thash) or intent, "follow-up",
                  "the replacement search reached a terminal state")
        return

    evidence = verify(client, intent)
    if evidence["verified"]:
        update(thash, milestone=REMOVED, evidence=evidence, error=None)
        out["removed"] += 1
        log.info("Remediation of %r is confirmed after a restart (history "
                 "event %s, blocklist row %s).", intent.get("release_title"),
                 (evidence["event"] or {}).get("id"),
                 (evidence["blocklist"] or {}).get("id"))
        audit(get(thash) or intent, "follow-up",
              "the removal was confirmed against the *arr's own records")
        return

    if not evidence.get("reachable", True):
        # We could not ask. That is a fact about the network, not about the
        # release, and turning it into failed_unverified would let a ten-second
        # outage produce a permanent verdict.
        log.info("Remediation of %r stays %r: %s", intent.get("release_title"),
                 intent.get("milestone"), evidence.get("why"))
        out["unreachable"] += 1
        return

    # Not verified. Is the queue item still sitting there?
    still_queued = client.queue_by_hash().get(thash)
    if still_queued:
        log.warning("Remediation of %r never reached %s: the queue item is "
                    "still there. Retrying the removal.",
                    intent.get("release_title"), client.name)
        update(thash, attempts=(intent.get("attempts") or 0) + 1,
               queue_id=still_queued.get("id"))
        return

    # The queue item is gone and the oracle cannot account for it. A 404 from a
    # repeated DELETE would say the same thing, and means no more than this.
    update(thash, milestone=FAILED_UNVERIFIED, evidence=evidence,
           error=evidence.get("why"))
    out["unverified"] += 1
    audit(get(thash) or intent, "follow-up",
          "the queue item is gone and the removal could not be verified")
    log.error(
        "REMEDIATION UNVERIFIED for %r on %s. The queue item is gone but %s. "
        "Protectarr will NOT search for a replacement, because it cannot rule "
        "out that the release was removed without being blocklisted - and "
        "searching would invite the *arr to grab it again. The intent is kept "
        "in intents.json for diagnosis.",
        intent.get("release_title"), client.name, evidence.get("why"))
    if on_unverified:
        on_unverified(client, dict(intent, evidence=evidence))
