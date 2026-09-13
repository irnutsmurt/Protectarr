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
otherwise:

    untracked   no *arr has ever been seen claiming it
    owned       exactly one *arr claims it right now
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

Ownership = collections.namedtuple(
    "Ownership", "state owner client record absent_for why")

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
        log.debug("%s queue: %d item(s)", client.name, len(queue))
        for thash, record in queue.items():
            claims.setdefault(thash.lower(), []).append((client, record))
    return claims, readable


def resolve(claims, readable, acquiring=(), now=None):
    """Work out each torrent's ownership. Returns {hash: Ownership}.

    Pure apart from reading and writing the durable store: given the same
    claims, the same readable set and the same stored history, it returns the
    same answer.

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
    subjects = set(claims) | live | set(stored)

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
        return Ownership(UNTRACKED, None, None, None, None,
                         "no *arr has been seen claiming it")

    owner = prior.get("owner")
    if owner not in readable:
        # Could not look. Not evidence, and specifically not the start of an
        # orphan clock - a dwell that advances while we are blind measures our
        # outage rather than the torrent's absence.
        return Ownership(prior.get("state", OWNED), owner, None, None,
                         prior.get("absent_for"),
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
                rec["owner_type"] = own.client.type if own.client else None
                rec["last_claimed"] = now
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
