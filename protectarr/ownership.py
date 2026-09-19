"""Who owns a torrent, remembered across passes rather than re-guessed.

Ownership used to be whatever this pass happened to see: build a map from every
*arr queue, first writer wins, and a torrent no queue mentioned was simply not
tracked. Three things are wrong with that, and all three are silent.

*First writer wins is a coin toss dressed as a decision.* Two *arrs claiming one
infohash is a real situation - the same release can satisfy two instances - and
resolving it by the order the apps appear in the config file means Protectarr
deletes a queue item from whichever app the user happened to list first.

*A queue we could not read looks exactly like a queue that does not claim it.*
Sonarr being down for one pass turned every torrent it owned into an untracked
torrent, which in allowlist mode is a torrent Protectarr may delete outright.

*A torrent that leaves a queue leaves no trace.* The *arr forgets it, so on the
next pass nothing remembers it was ever *arr-owned, and it quietly becomes an
ordinary category match.

So ownership is durable. A claim is only ever recorded from a queue we actually
read, absence only counts when we read the owner's queue and it was not there,
and a torrent that was owned stays accounted for until something positive says
otherwise.

*A queue entry is not automatically a claim.* Protectarr asks each *arr for its
unknown items as well, because `intents` needs to know whether a queue entry is
still sitting there before it retries a removal. But an unknown item is the
*arr reporting a download in its own category that it has no media record for,
and an *arr that cannot name what a download is for cannot blocklist it or
search for a replacement. Only a record carrying the media id the remediation
path needs counts as a claim - see `ArrClient.has_remediation_identity`.

The states:


    untracked   no *arr has ever been seen claiming it. Legacy: `resolve` no
                longer produces it, because "we have not found out" is a
                different thing from "nobody owns it" and now has its own name.
    provisional seen, and ownership not established yet. Written down on first
                sight, before anything is decided about the torrent, so that
                the not-knowing survives a crash or a restart. May carry a
                `candidate_owner` from an exact grab-history row, which is
                positive evidence and is never erased by a later pass that did
                not find one. Never directly deletable without a fresh
                `synchronise` saying so for that attempt.
    owned       exactly one *arr claims it right now, with a queue record
                carrying the media id remediation needs.
    orphaned    it was owned, and the owner's queue has since been read and
                does not claim it. `absent_for` is how long that has been
                continuously true; policy decides what to do at what age.
    conflicted  two or more *arrs claim it in the same pass, or a claim moved
                and we could not read the previous owner's queue to confirm it
                let go. Never resolved automatically.

What this module does NOT do is decide anything. It reports what is known and
how it came to be known; `policy` and `core` decide what that is worth.
"""

import time
import collections

from . import logs
from .store import Store

log = logs.get("ownership")

VERSION = 1

UNTRACKED = "untracked"
OWNED = "owned"
ORPHANED = "orphaned"
CONFLICTED = "conflicted"
PROVISIONAL = "provisional"

Ownership = collections.namedtuple(
    "Ownership", "state owner client record absent_for why")

# What a fresh synchronisation concluded, for one torrent, for one attempt.
#
# `cleared` is deliberately not a field of the durable record and never becomes
# one. It authorises exactly the attempt it was produced for: a dry run, a
# failed delete or a restart all discard it, and the next attempt has to ask
# the *arrs again. Yesterday's negative answer must not authorise today's
# deletion, because the *arr may have grabbed the torrent in between.
Synchronisation = collections.namedtuple(
    "Synchronisation", "cleared own why")

_store = Store("ownership.json", VERSION, "owners", "the ownership file")


def broken():
    return _store.broken()


def records():
    return _store.records()


def collect(clients):
    """Read every *arr queue. Returns (claims, readable).

    `claims` is {infohash: [(client, record)]} - a list, because two claims is
    a state to report rather than a tie to break. `readable` is the set of
    instance names whose queue we actually got, which is the difference between
    "it is not there" and "we did not look".
    """
    claims = {}
    readable = set()
    for client in clients:
        try:
            queue = client.queue_by_hash()
        except Exception as e:                      # noqa: BLE001
            log.warning("Could not read %s's queue: %s. Nothing it owns will "
                        "be treated as absent this pass.", client.name, e)
            continue
        readable.add(client.name)
        unknown = 0
        for thash, record in queue.items():
            # A queue entry is not the same thing as a claim. The *arr is asked
            # for its unknown items too, and an unknown item is the *arr saying
            # "there is a download in my category that I have no media record
            # for" - a hand-added torrent, or one whose series or movie has
            # since been deleted. Treating that as ownership sent it down the
            # *arr-aware path, which deletes the data and then cannot blocklist
            # or re-search it, because both are keyed on the media id it does
            # not have.
            if not client.has_remediation_identity(record):
                unknown += 1
                log.debug("%s lists %s but has no media record for it; that is "
                          "queue visibility, not a claim", client.name,
                          thash[:8])
                continue
            claims.setdefault(thash.lower(), []).append((client, record))
        log.debug("%s queue: %d item(s), %d claimed, %d unknown to it",
                  client.name, len(queue), len(queue) - unknown, unknown)
        if unknown:
            log.info("%s has %d download(s) in its category it has no media "
                     "record for. Protectarr does not treat those as owned: "
                     "the *arr cannot blocklist or re-search them.",
                     client.name, unknown)
    return claims, readable


def resolve(claims, readable, acquiring=(), seen=(), now=None):
    """Work out each torrent's ownership. Returns {hash: Ownership}.

    Pure apart from reading and writing the durable store: given the same
    claims, the same readable set and the same stored history, it returns the
    same answer.

    `seen` is every torrent this pass looked at. A torrent in it that nothing
    claims and nothing remembers becomes PROVISIONAL and is written down before
    any decision is taken about it, which is what makes the first-pass race
    survivable: a torrent an *arr grabbed reaches qBittorrent milliseconds
    before the *arr's own grab history names it, and Protectarr may well see it
    inside that window. Recording the uncertainty first means a crash, a
    restart or a dry run leaves the torrent protected rather than forgotten.

    `acquiring` is the infohashes qBittorrent currently reports as still
    trying to get data, and it is what the orphan clock is allowed to run on.
    This matters more than it looks: a download that *succeeds* also leaves its
    *arr's queue. The *arr imported it and moved on, which is the happy path,
    and calling that an orphan would mean every completed download in the
    library eventually looked abandoned.

    The caller decides membership from qBittorrent's own state model, not from
    speed or progress. A stalled torrent sits at 0 B/s and is exactly what an
    abandoned fake looks like, so it has to stay eligible; a torrent the user
    paused has to not be. Anything outside the set is in the same position as a
    torrent whose owner's queue we could not read: no present observation, so
    nothing is concluded.
    """
    now = time.time() if now is None else now
    stored = _store.records()
    out = {}
    live = {h.lower() for h in acquiring}
    subjects = set(claims) | live | {h.lower() for h in seen} | set(stored)

    for thash in subjects:
        claimants = claims.get(thash) or []
        prior = stored.get(thash)
        if len(claimants) > 1:
            out[thash] = _conflict(thash, claimants, prior, now)
        elif len(claimants) == 1:
            out[thash] = _claimed(thash, claimants[0], prior, readable, now)
        else:
            out[thash] = _unclaimed(thash, prior, readable, thash in live, now)

    _persist(out, stored, now)
    return out


def _conflict(thash, claimants, prior, now):
    names = sorted(c.name for c, _ in claimants)
    log.warning("%s is claimed by %s at the same time. Protectarr will not act "
                "on it: choosing between them would mean deleting a queue item "
                "from an application that is legitimately downloading it.",
                thash[:8], " and ".join(names))
    return Ownership(CONFLICTED, None, None, None, None,
                     f"claimed simultaneously by {', '.join(names)}")


def _claimed(thash, claimant, prior, readable, now):
    client, record = claimant
    if not prior or prior.get("owner") == client.name:
        return Ownership(OWNED, client.name, client, record, None,
                         "claimed by its owner")

    # A provisional record has no owner to transfer *from*. It is the state of
    # not having found out yet, so the first real claim resolves it rather than
    # competing with it. Without this the upgrade path reads as a claim moving
    # from an owner named None, which no queue can be read to confirm, and the
    # torrent lands in CONFLICTED - permanently unactionable, on its way to
    # being owned perfectly normally.
    if prior.get("state") == PROVISIONAL:
        candidate = prior.get("candidate_owner")
        if candidate and candidate != client.name:
            # Its history says one application grabbed it and a different one
            # is claiming it now. That is a real disagreement about a torrent
            # we are about to be able to delete, and it is not ours to resolve.
            return Ownership(
                CONFLICTED, candidate, None, None, None,
                f"{client.name} claims it but {candidate}'s history says "
                f"{candidate} grabbed it")
        return Ownership(OWNED, client.name, client, record, None,
                         "claimed by its owner")

    # The claim has moved. That is allowed, but only when the previous owner
    # has been *observed* letting go. An old owner we could not read might
    # still be claiming it, and two live claims is a conflict, not a transfer.
    if prior.get("owner") not in readable:
        return Ownership(
            CONFLICTED, prior.get("owner"), None, None, None,
            f"{client.name} claims it but {prior.get('owner')}'s queue could "
            f"not be read, so the transfer is not proven")
    log.info("%s has moved from %s to %s: the previous owner's queue was read "
             "and no longer claims it.", thash[:8], prior.get("owner"),
             client.name)
    return Ownership(OWNED, client.name, client, record, None,
                     f"transferred from {prior.get('owner')}")


def _unclaimed(thash, prior, readable, is_acquiring, now):
    if not prior:
        # Nothing claims it and nothing remembers it. That is not the same as
        # nobody owning it - it is the state of having not found out yet, and
        # it is what the first pass over a freshly grabbed torrent looks like.
        # It is written down so the not-knowing survives a restart, and nothing
        # destructive may happen to it until a synchronisation says otherwise.
        return Ownership(PROVISIONAL, None, None, None, None,
                         "seen for the first time; ownership not established yet")

    if prior.get("state") == PROVISIONAL:
        # Still provisional, and possibly carrying a candidate owner that an
        # earlier synchronisation found in grab history. Positive evidence is
        # not undone by a later pass that did not look for it.
        candidate = prior.get("candidate_owner")
        return Ownership(
            PROVISIONAL, candidate, None, None, None,
            f"grabbed by {candidate} according to its history, but no queue "
            f"record has established operational ownership yet" if candidate
            else "ownership not established yet")

    owner = prior.get("owner")
    if owner not in readable:
        # Could not look. Not evidence, and specifically not the start of an
        # orphan clock - a dwell that advances while we are blind measures our
        # outage rather than the torrent's absence.
        #
        # `absent_for` is None, stated rather than read back. This used to be
        # `prior.get("absent_for")`, which was always None only because
        # `_persist` happens never to write that key: the safety of the whole
        # branch rested on the absence of a field somewhere else in the file,
        # so anyone adding `absent_for` to the stored record - an obvious thing
        # to do, since `absent_since` is already there - would have silently
        # turned this into a dwell carried across an outage. A pass that could
        # not look has no measurement to report, and that is a fact about this
        # branch, not about the schema.
        return Ownership(prior.get("state", OWNED), owner, None, None, None,
                         f"{owner}'s queue could not be read, so its previous "
                         f"state stands")

    if not is_acquiring:
        # It left the queue, and it is not trying to acquire anything.
        # Overwhelmingly that is a download that finished and was imported,
        # which is the outcome the whole stack exists to produce. Abandonment
        # happens to a torrent that is still trying.
        return Ownership(prior.get("state", OWNED), owner, None, None, None,
                         f"{owner} no longer claims it and it is not trying to "
                         f"download, so it has most likely been imported")

    absent_since = prior.get("absent_since") or now
    return Ownership(ORPHANED, owner, None, None, max(0.0, now - absent_since),
                     f"{owner}'s queue was read and no longer claims it while "
                     f"it is still trying to download")


def _persist(resolved, stored, now):
    """Write back what we learned, keeping the parts observation did not touch."""
    def apply(owners):
        for thash, own in resolved.items():
            prior = stored.get(thash) or {}
            if own.state == UNTRACKED:
                continue                # nothing worth remembering yet
            if own.state == PROVISIONAL:
                # The one record written *because* we do not know something.
                # `candidate_owner` is carried forward rather than rewritten:
                # a grabbed history row is positive evidence, and a later pass
                # that did not go looking for it has not disproved it.
                rec = dict(prior)
                rec["state"] = PROVISIONAL
                rec["updated"] = now
                rec.setdefault("first_seen", now)
                owners[thash] = rec
                continue
            if own.state == CONFLICTED:
                # Deliberately does not overwrite `owner`. A conflict is not a
                # new owner, and recording one would turn an unresolved
                # situation into a decision on the next pass.
                rec = dict(prior)
                rec["state"] = CONFLICTED
                rec["updated"] = now
                rec.setdefault("first_seen", now)
                owners[thash] = rec
                continue
            rec = dict(prior)
            rec["state"] = own.state
            rec["updated"] = now
            rec.setdefault("first_seen", now)
            if own.state == OWNED:
                rec["owner"] = own.owner
                # `client` is the pass's own evidence: it is set only by
                # `_claimed`, which ran because a queue we actually read named
                # this torrent. `_unclaimed` carries a previous OWNED state
                # forward with no client at all, and that is not an observation.
                #
                # Writing these three from a carried-forward state asserted
                # things nobody saw. An *arr that was down for one pass had its
                # torrents' `owner_type` overwritten with None - erasing the one
                # field that says whether the owner is Sonarr or Radarr - and
                # their `last_claimed` moved to now, dating a claim that was
                # never made. Both survived every restart afterwards, because
                # the next outage did it again.
                if own.client:
                    rec["owner_type"] = own.client.type
                    rec["last_claimed"] = now
                    # A torrent that is claimed again is not absent, and the
                    # next absence is a new absence rather than a resumption of
                    # the old one. Only a real claim may say so.
                    rec["absent_since"] = None
            elif own.state == ORPHANED:
                rec["owner"] = own.owner
                if not rec.get("absent_since"):
                    rec["absent_since"] = now
            owners[thash] = rec
        return True

    if not _store.mutate(apply):
        log.warning("Ownership could not be persisted. Protectarr will keep "
                    "working from what it can see this pass, but a torrent "
                    "that leaves a queue may be forgotten across a restart.")


def prune(present):
    """Forget torrents qBittorrent no longer has. Returns how many went.

    `present` MUST be every infohash qBittorrent holds, from an unfiltered
    inventory. Handing it the scan's filtered list would delete the ownership
    of every torrent that finished downloading, which is most of them.

    A stale record costs a few hundred bytes and is harmless. A record deleted
    early turns a previously owned torrent back into an ordinary category
    match, which in allowlist mode is the difference between leaving something
    alone and deleting it. So this only ever removes what is provably gone.
    """
    present = {h.lower() for h in present}
    if not present:
        # An empty inventory is far more likely to be a failed call than a
        # genuinely empty qBittorrent, and acting on it would wipe everything.
        log.debug("Ownership prune skipped: the inventory was empty")
        return 0

    gone = []

    def apply(owners):
        for thash in list(owners):
            if thash not in present:
                gone.append(thash)
                del owners[thash]
        return bool(gone)

    if gone or _store.mutate(apply):
        if gone:
            log.info("Forgot ownership of %d torrent(s) qBittorrent no longer "
                     "has.", len(gone))
    return len(gone)


def actionable_orphan(own, dwell_minutes):
    """Has this orphan been verifiably absent long enough to act on?

    The dwell is continuous verified absence, which is why `_unclaimed` refuses
    to start or advance the clock on a pass where the owner's queue could not
    be read. A torrent that reappears resets it to None rather than pausing it:
    it is owned again, and the next absence is a new absence.
    """
    if own.state != ORPHANED:
        return False
    return (own.absent_for or 0) >= max(0, dwell_minutes) * 60


def _remember_candidate(thash, client, event):
    """Write down that an *arr's history says it grabbed this torrent.

    Positive evidence, so it is durable and survives a restart. It is also
    never erased by a later pass that finds no row: deleting a series or movie
    cascade-deletes its history while the torrent keeps downloading, measured
    on Sonarr 4.0.20 and Radarr 6.4.4, so an absent row is not a retraction.

    The residue that buys: a torrent whose *arr genuinely finished with it long
    ago can keep a candidate owner and stay protected from the category
    fallback indefinitely. That is the safe direction, and undoing it would
    need a lifecycle nobody has evidence for yet.
    """
    def apply(owners):
        rec = dict(owners.get(thash) or {})
        rec["state"] = PROVISIONAL
        rec.setdefault("first_seen", time.time())
        rec["candidate_owner"] = client.name
        rec["candidate_owner_type"] = client.type
        rec["candidate_evidence"] = "grab_history"
        if event is not None and event.get("id") is not None:
            rec["grab_event_id"] = event.get("id")
        rec["updated"] = time.time()
        owners[thash] = rec
        return True

    if not _store.mutate(apply):
        log.warning("Could not record that %s grabbed %s. It stays protected "
                    "this pass either way, because the refusal does not depend "
                    "on the write.", client.name, thash[:8])


class Barrier:
    """One completed refresh per *arr, for the length of one scan.

    A `RefreshMonitoredDownloads` is not a fact about a torrent. It makes the
    *arr re-read its download client, so one completed refresh establishes a
    current view of the whole population this scan is judging - and that
    population is fixed, because `core.scan` fetches qBittorrent's torrent list
    once and both detection lanes work from that one snapshot.

    So the refresh is shared and nothing else is. Each torrent still gets its
    own queue read and its own exact-hash history read, taken after the
    barrier, which is what actually establishes ownership and what lets
    evidence arriving mid-scan still be found. Caching a queue row or a history
    absence to save a call would be trading the answer for the round trip.

    A barrier lives for one *phase* of one scan, not for the whole scan. The
    probe lane runs after the main loop has finished and may hold the scan for
    its entire budget, so a barrier raised before it began would be describing
    a download-client view the *arr took minutes earlier. The phase boundary is
    what defines freshness here - not a TTL, not an elapsed-time threshold, and
    not the *arr's own polling timer, which is not ours to depend on.

    A failure is not cached across phases or scans either: each gets a clean
    attempt.
    """

    def __init__(self, clients, refresh_timeout=90, phase="scan"):
        self.clients = list(clients)
        self.refresh_timeout = refresh_timeout
        self.phase = phase
        self.refreshed = 0          # commands actually issued, for tests
        self._result = None         # None until the first candidate asks

    def establish(self):
        """(ok, why). Refreshes every *arr once, on the first call only."""
        if self._result is not None:
            return self._result
        for client in self.clients:
            ok, why = client.refresh_monitored_downloads(
                timeout=self.refresh_timeout)
            self.refreshed += 1
            if not ok:
                # One application that could not be synchronised leaves the
                # barrier incomplete for every candidate in this scan. It is
                # not retried within the scan, because a refresh that just
                # failed is not going to succeed a second later, and retrying
                # per torrent is how ten candidates become fifty commands.
                log.warning("Ownership synchronisation barrier incomplete: %s. "
                            "Nothing will be removed directly from qBittorrent "
                            "this scan.", why)
                self._result = (False, why)
                return self._result
        self._result = (True, "every application refreshed")
        log.debug("Ownership synchronisation barrier established for the %s "
                  "phase across %d application(s)", self.phase,
                  len(self.clients))
        return self._result


def synchronise(clients, thash, refresh_timeout=90, barrier=None):
    """Fresh ownership resolution for one torrent, at the destructive boundary.

    Nothing here is cached and nothing it concludes is stored as a negative.
    The only durable write is a candidate owner, which is positive evidence.

    For every configured *arr, in order: read its grab history for this exact
    hash, force a `RefreshMonitoredDownloads` and wait for it to complete, read
    its queue again, then read the history again. The refresh is the point of
    the exercise - without it the *arr's queue is up to a minute stale, and
    "not in the queue" would mean "not in the queue yet".

    Every distinction the API offers is kept. Zero rows is not a failed
    request; a refresh that timed out is not a refresh that completed; a queue
    that could not be read is not an empty queue. Any of those returns
    `cleared=False`, because an answer we could not obtain is not an answer.

    Returns a `Synchronisation`. `cleared` True means only this:

        after successfully synchronising every configured *arr and checking
        current queue and retained exact-hash history evidence, no current
        *arr ownership could be established

    It does not mean the torrent was never owned, and it does not mean no *arr
    has ever seen it. Retained history can be deleted while the torrent is
    still downloading, so absence of evidence is genuinely not evidence here.
    """
    barrier = Barrier(clients, refresh_timeout) if barrier is None else barrier
    ok, why = barrier.establish()
    if not ok:
        return Synchronisation(False, None, why)

    claimants = []      # live queue records carrying remediation identity
    grabbers = []       # (client, event) from exact-hash grab history

    for client in clients:
        # Read after the barrier, per torrent, every time. An *arr that has
        # gone away since it refreshed is not covered by having refreshed: the
        # refresh established a view, and this is the read that uses it.
        try:
            queue = client.queue_by_hash()
        except Exception as e:                      # noqa: BLE001
            return Synchronisation(
                False, None,
                f"could not read {client.name}'s queue after it refreshed ({e})")
        record = queue.get(thash.lower())
        if record is not None and client.has_remediation_identity(record):
            claimants.append((client, record))
        elif record is not None:
            log.debug("%s lists %s after refreshing but has no media record "
                      "for it, so it is not a claim", client.name, thash[:8])

        try:
            rows = client.grab_events(thash)
        except Exception as e:                      # noqa: BLE001
            return Synchronisation(
                False, None,
                f"could not read {client.name}'s history ({e})")
        if rows:
            grabbers.append((client, rows[0]))

    # Two applications both claiming it is the one situation that needs a
    # human, and it is never resolved by picking one.
    if len(claimants) > 1:
        names = sorted(c.name for c, _ in claimants)
        return Synchronisation(
            False,
            Ownership(CONFLICTED, None, None, None, None,
                      f"claimed simultaneously by {', '.join(names)}"),
            f"{' and '.join(names)} both claim it")

    if len(claimants) == 1:
        client, record = claimants[0]
        return Synchronisation(
            False,
            Ownership(OWNED, client.name, client, record, None,
                      "claimed by its owner"),
            f"{client.name} claims it")

    distinct = {c.name for c, _ in grabbers}
    if len(distinct) > 1:
        names = sorted(distinct)
        return Synchronisation(
            False,
            Ownership(CONFLICTED, None, None, None, None,
                      f"grabbed by {', '.join(names)} according to their "
                      f"histories"),
            f"{' and '.join(names)} both have a grab event for it")

    if grabbers:
        client, event = grabbers[0]
        _remember_candidate(thash, client, event)
        return Synchronisation(
            False,
            Ownership(PROVISIONAL, client.name, None, None, None,
                      f"grabbed by {client.name} according to its history, but "
                      f"no queue record has established operational ownership"),
            f"{client.name}'s history says it grabbed this release")

    return Synchronisation(
        True, None,
        "after synchronising every application and checking current queue and "
        "retained history, no current ownership could be established")
