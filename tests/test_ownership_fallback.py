"""A durable owner must survive a pass that saw no live claim.

`ownership` exists so that "Sonarr did not mention it this pass" stops being
the same input as "nothing owns it". It does that job: the record persists, and
`_unclaimed` carries a previous OWNED state forward rather than dropping to
UNTRACKED.

The carried-forward state then goes nowhere. `core.scan` builds `arr_hit` from

    owner = {h: (o.client, o.record) for h, o in resolved.items()
             if o.state == ownership.OWNED and o.client}

and `o.client` is set only by `ownership._claimed`, which runs only for a queue
that named the torrent *this pass*. That condition is right - it is the
"never assert what a pass did not observe" rule, and removing it would resurrect
the bug that dated claims nobody made. But it means a torrent whose stored
record says `owner: Sonarr` arrives at `_mode_coverage` with `arr_hit` falsy,
indistinguishable from a torrent no *arr has ever claimed.

`_mode_coverage` then consults `ownership_known`, which is a single global flag
(`len(readable) == len(arr_clients)`), and never the per-torrent record. In
`allowlist` and `either` the answer is `qbit_delete`: deleted from qBittorrent
with the files, no blocklist, no replacement search, logged as "no *arr owned
it, so there is no blocklist or requeue to verify".

`explain` now vetoes `qbit_delete` on a stored OWNED state. These are the
regression tests for that veto, and the three routes that reached the delete
before it existed:

  paused      `ORPHANABLE_STATES` excludes `pausedDL`/`stoppedDL` so the user's
              own pause is not counted as abandonment. That suppresses the
              ORPHANED label - and the ORPHANED label is the only thing that
              buys a dwell. The protection inverted: a paused owned torrent was
              *less* protected than an orphaned one, not more. Fixed.
  removed arr an *arr deleted from the config is never read, so its torrents
              carry forward forever - and `ownership_known` is still True,
              because it counts configured clients, not stored owners. Fixed by
              the same veto, since both arrive as carried-forward OWNED.
  first pass  nothing consults qBittorrent's `added_on`. A torrent qBittorrent
              has and Sonarr's queue has not yet published is UNTRACKED, not
              OWNED, so the veto does not reach it and it is **still open**.
              Left deliberately untouched: there is no durable record to
              consult, and every fix for it is either a number Protectarr
              cannot know (the *arr's queue refresh interval) or a change to
              what the ownership store persists. Its tests below pin the
              current behaviour so the gap stays visible.

The veto is state-specific on purpose. ORPHANED is not covered: that state was
earned by reading the owner's queue and watching the torrent leave it, which is
a positive observation, and the dwell is what ages it. Blocking orphans too
would disable the only thing `either` exists to catch.
"""

import os
import sys
import tempfile
import unittest

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, ownership  # noqa: E402
from protectarr.arr import ARR_TYPES, ArrClient  # noqa: E402

A = "a" * 40

DWELL = 10

SAFETY = {"allowed_categories": ["tv"], "allowed_tags": [],
          "orphan_dwell_minutes": DWELL, "category_profiles": {}}


# The states exactly as `ownership.resolve` returns them. The distinction the
# rest of this file turns on is `client`: set by `_claimed` from a queue read
# this pass, None on everything `_unclaimed` carries forward.
LIVE_OWNED = ownership.Ownership(
    ownership.OWNED, "Sonarr", "client-object", {"id": 1}, None,
    "claimed by its owner")

CARRIED_OWNED_NOT_ACQUIRING = ownership.Ownership(
    ownership.OWNED, "Sonarr", None, None, None,
    "Sonarr no longer claims it and it is not trying to download, so it has "
    "most likely been imported")

CARRIED_OWNED_UNREADABLE = ownership.Ownership(
    ownership.OWNED, "Sonarr", None, None, None,
    "Sonarr's queue could not be read, so its previous state stands")

UNTRACKED = ownership.Ownership(
    ownership.UNTRACKED, None, None, None, None,
    "no *arr has been seen claiming it")

ORPHAN_FRESH = ownership.Ownership(
    ownership.ORPHANED, "Sonarr", None, None, 60, "absent 1m")

ORPHAN_DWELLED = ownership.Ownership(
    ownership.ORPHANED, "Sonarr", None, None, (DWELL + 1) * 60, "absent 11m")


PROVISIONAL = ownership.Ownership(
    ownership.PROVISIONAL, None, None, None, None,
    "seen for the first time; ownership not established yet")

PROVISIONAL_GRABBED = ownership.Ownership(
    ownership.PROVISIONAL, "Sonarr", None, None, None,
    "grabbed by Sonarr according to its history")


def clear_store():
    """Actually empty the ownership store.

    `Store.reset()` only forgets the broken flag - it has never cleared
    records, so every mid-test `_store.reset()` was a no-op on the data. Tests
    that need a clean slate mid-test have to say so properly.
    """
    ownership._store.mutate(lambda owners: (owners.clear(), True)[1])


def judge(mode, own, hit=False, allowed=True, known=True, cleared=False):
    safety = dict(SAFETY, mode=mode)
    torrent = {"category": "tv" if allowed else "other", "tags": ""}
    return core.explain(torrent, ("client", {}) if hit else None, safety,
                        known, own=own, fallback_cleared=cleared)


class TestWhatTheDecisionSeesOfADurableOwner(unittest.TestCase):
    """The narrow question, at the policy boundary: does a stored owner reach
    the decision at all?"""

    def test_explain_still_cannot_tell_a_carried_owner_from_a_live_one(self):
        """Both are `state == OWNED`, and the field that separates them -
        `client` - is on the namedtuple `explain` is handed and is still never
        read. The veto does not change that; it changes which way the ambiguity
        resolves. Indistinguishable and safe beats indistinguishable and
        destructive.
        """
        live = judge("either", LIVE_OWNED)
        carried = judge("either", CARRIED_OWNED_NOT_ACQUIRING)
        # Outcome, not prose. `detail["why"]` differs because `ownership` words
        # the two situations differently, and that wording is for the operator.
        self.assertEqual((live.state, live.action, live.reason),
                         (carried.state, carried.action, carried.reason))
        self.assertIsNone(carried.action)

    def test_a_stored_owner_stops_a_direct_delete_in_either(self):
        j = judge("either", CARRIED_OWNED_NOT_ACQUIRING)
        self.assertIsNone(j.action)
        self.assertEqual(j.state, core.BLOCKED)
        self.assertEqual(j.reason, "owned_not_claimed_this_pass")

    def test_a_stored_owner_stops_a_direct_delete_in_allowlist(self):
        j = judge("allowlist", CARRIED_OWNED_NOT_ACQUIRING)
        self.assertIsNone(j.action)
        self.assertEqual(j.reason, "owned_not_claimed_this_pass")

    def test_the_refusal_names_the_owner_it_is_protecting(self):
        """The operator has to be able to go and look. A refusal that does not
        say which application held it is a dead end."""
        j = judge("either", CARRIED_OWNED_NOT_ACQUIRING)
        self.assertEqual(j.detail.get("owner"), "Sonarr")

    def test_no_judgement_claims_a_torrent_with_an_owner_is_unowned(self):
        """`allowlisted_and_unowned` is a factual assertion, and it reached the
        event record and the UI while `own.owner` said "Sonarr"."""
        for mode in ("allowlist", "either"):
            for own in (CARRIED_OWNED_NOT_ACQUIRING, CARRIED_OWNED_UNREADABLE,
                        LIVE_OWNED):
                j = judge(mode, own)
                self.assertNotIn("unowned", j.reason or "",
                                 f"{mode} called {own.owner}'s torrent unowned")

    def test_an_owned_torrent_is_at_least_as_protected_as_an_orphan(self):
        """The inversion, stated as the comparison that used to fail.

        ORPHANED means "we watched it leave". OWNED means "we last saw Sonarr
        holding it". The stronger claim must not buy less protection than the
        weaker one.
        """
        self.assertIsNone(judge("either", ORPHAN_FRESH).action)
        self.assertIsNone(judge("either", CARRIED_OWNED_NOT_ACQUIRING).action)


class ScanCase(unittest.TestCase):
    """Drives `core.scan` end to end with fakes, because the defect only exists
    across the seam between `ownership.resolve` and `_mode_coverage`.

    A unit test of `explain` can be satisfied by handing it a state that the
    scanner would never build. These tests build the state the way a real pass
    builds it: a first pass where Sonarr claims the torrent, then a second pass
    where it does not.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        clear_store()

    def scan(self, torrents, clients, mode="either", files=None,
             only_active=True, side_effects=True):
        """`side_effects=True` is the real destructive path, and the only one
        that synchronises. A preview deliberately does not, so tests about what
        a preview shows pass False."""
        outer = self

        class FakeQb:
            def login(self):
                pass

            def torrents(self, category=None, state_filter=None):
                return [dict(t) for t in torrents]

            def files(self, h):
                return list(files if files is not None
                            else [{"name": "Ted.Lasso.S04E08.1080p.exe",
                                   "size": 1_060_000_000}])

            def delete(self, h, delete_files=False):
                outer.fail("scan must not delete; side_effects=False")

        cfg = {
            "qbittorrent": {"url": "http://x"},
            "detection": {"only_active": only_active,
                          "blocked_extensions": [".exe"],
                          "blocked_name_keywords": [],
                          "archive_detection": {"enabled": False},
                          "probe": {"enabled": False}},
            "safety": dict(SAFETY, mode=mode),
            "arrs": [{"name": c.name, "type": c.type} for c in clients],
        }
        real_qb, real_build = core.QbitClient, core.build_clients
        core.QbitClient = lambda *a, **k: FakeQb()
        core.build_clients = lambda cfg: list(clients)
        try:
            return core.scan(cfg, {}, side_effects=side_effects)
        finally:
            core.QbitClient, core.build_clients = real_qb, real_build


class FakeArr:
    """Models the whole ownership contract, not just the queue.

    `grabbed` is the exact-hash grab history, which is what closes the
    first-pass race; `refresh_ok` and the two `*_raises` switches are how the
    fail-safe paths are exercised, because a refresh that did not complete and
    a history that could not be read must never look like an answer.
    """

    def __init__(self, name, hashes=(), broken=False, arr_type="sonarr",
                 identified=True, grabbed=(), refresh_ok=True,
                 refresh_why=None, history_raises=False, queue_raises_after=0,
                 history_raises_on=()):
        self.name = name
        self.type = arr_type
        self.meta = ARR_TYPES[arr_type]
        self.hashes = list(hashes)
        self.broken = broken
        # False makes every record an *arr "unknown" item: visible in the
        # queue, no media record behind it.
        self.identified = identified
        self.grabbed = {h.lower() for h in grabbed}
        self.refresh_ok = refresh_ok
        self.refresh_why = refresh_why or f"{name}'s refresh did not finish"
        self.history_raises = history_raises
        # 1-based call numbers that should raise. Lets a test fail exactly one
        # of the two history reads, which is the only way to catch a mutant
        # that swallows the first and carries on.
        self.history_raises_on = set(history_raises_on)
        self.history_reads = 0
        self.queue_raises_after = queue_raises_after
        self.queue_reads = 0
        self.refreshes = 0

    def queue_by_hash(self):
        self.queue_reads += 1
        if self.broken:
            raise requests.RequestException("connection refused")
        if (self.queue_raises_after
                and self.queue_reads > self.queue_raises_after):
            raise requests.RequestException("connection reset")
        rec = {"id": 1, "title": f"{self.name} item"}
        if self.identified:
            # The media id a real claim carries. Without it the *arr is merely
            # reporting a download it has no record for, which is not a claim.
            rec[ARR_TYPES[self.type]["search"][2]] = 1
        return {h: dict(rec, downloadId=h) for h in self.hashes}

    def grab_events(self, download_id, after_id=None, pages=4):
        self.history_reads += 1
        if self.history_raises or self.history_reads in self.history_raises_on:
            raise requests.RequestException("history unavailable")
        if (download_id or "").lower() in self.grabbed:
            return [{"id": 41, "downloadId": download_id.upper(),
                     "eventType": "grabbed"}]
        return []

    def refresh_monitored_downloads(self, timeout=90, poll=0.25):
        self.refreshes += 1
        if self.refresh_ok:
            return True, f"{self.name} refreshed"
        return False, self.refresh_why

    def has_remediation_identity(self, record):
        """Delegates to the production predicate rather than copying it.

        A fake that reimplements the rule cannot catch a mutation of the real
        one, which is exactly what the harness found: six mutants of
        `ArrClient.has_remediation_identity` were invisible to every
        scanner-level test here.
        """
        return ArrClient.has_remediation_identity(
            ArrClient(self.name, self.type, "http://fake", "k"), record)

    def grab_indexer(self, download_id):
        return None


B = "b" * 40


def downloading2(state="downloading", category="tv"):
    """A second distinct torrent, for tests about more than one candidate."""
    return dict(downloading(state, category), hash=B,
                name="South Park S29E02 1080p WEB H264 MeGusta")


def downloading(state="downloading", category="tv"):
    return {"hash": A, "state": state, "progress": 0.02, "size": 1_060_000_000,
            "name": "Ted Lasso S04E08 1080p WEB DL DDP5 1 x265 NTb",
            "category": category, "tags": ""}


class TestPathOneAPausedOwnedTorrent(ScanCase):
    """Sonarr owns it, the user pauses it, Sonarr's queue moves on.

    Distinct from path two: ownership was *established* here and then lost on
    the way to the decision. The record is still on disk naming Sonarr when the
    delete is chosen.
    """

    def test_a_paused_torrent_sonarr_owned_is_not_reaped(self):
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        self.assertEqual(ownership.records()[A].get("owner"), "Sonarr")

        actions = self.scan([downloading(state="pausedDL")],
                            [FakeArr("Sonarr")])

        self.assertEqual(actions, [])

    def test_the_stored_record_still_names_sonarr_after_the_refusal(self):
        """The veto must not be paid for by forgetting who the owner was. If
        the record were dropped, the next pass would see UNTRACKED and delete
        it - the same outcome, one scan later."""
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        self.scan([downloading(state="pausedDL")], [FakeArr("Sonarr")])

        self.assertEqual(ownership.records()[A].get("owner"), "Sonarr")
        self.assertEqual(ownership.records()[A].get("state"), ownership.OWNED)

        again = self.scan([downloading(state="pausedDL")], [FakeArr("Sonarr")])
        self.assertEqual(again, [])

    def test_stoppedDL_behaves_the_same_as_pausedDL(self):
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        actions = self.scan([downloading(state="stoppedDL")],
                            [FakeArr("Sonarr")])
        self.assertEqual(actions, [])

    def test_the_torrent_becomes_reapable_again_once_sonarr_claims_it(self):
        """The refusal is not a permanent quarantine. A queue that names the
        torrent again restores the normal *arr-aware path, blocklist and all."""
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        self.assertEqual(self.scan([downloading(state="pausedDL")],
                                   [FakeArr("Sonarr")]), [])

        actions = self.scan([downloading()], [FakeArr("Sonarr", [A])])
        self.assertEqual(actions[0]["decision"], "arr_fail")
        self.assertEqual(actions[0]["arr"], "Sonarr")

    def test_the_same_torrent_still_downloading_is_protected_by_the_dwell(self):
        """The control. Identical setup, one field different: a state inside
        `ORPHANABLE_STATES` earns the ORPHANED label and therefore the dwell.

        This is the inversion measured on the scanner rather than argued from
        the table - pausing the torrent is what removes its protection.
        """
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        actions = self.scan([downloading(state="stalledDL")],
                            [FakeArr("Sonarr")])
        self.assertEqual(actions, [])
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.ORPHANED)


class TestPathTwoTheFirstPassRace(ScanCase):
    """Nothing was ever established. qBittorrent has the torrent, Sonarr's
    queue has not published it yet.

    FIXED. The torrent is written down as PROVISIONAL before anything is
    decided about it, and the fallback is refused until a synchronisation run
    for that very attempt finds every *arr reachable, every refresh completed,
    and neither a claim nor a grab event anywhere.

    The window is real and was measured: a grabbed torrent reaches qBittorrent
    2.9-33.3 ms before its *arr's own grab history names it, and about 5.1 s
    before the *arr's queue publishes it. Against a 20-second poll that is
    roughly one grab in four landing inside the queue gap.
    """

    def test_a_torrent_sonarr_has_not_yet_published_is_not_deleted(self):
        """The queue gap. Sonarr grabbed it and its history says so; the queue
        has not caught up. That is enough to refuse."""
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr", grabbed=[A])])
        self.assertEqual(actions, [])
        rec = ownership.records()[A]
        self.assertEqual(rec.get("state"), ownership.PROVISIONAL)
        self.assertEqual(rec.get("candidate_owner"), "Sonarr")

    def test_the_uncertainty_is_written_down_before_anything_is_decided(self):
        """The property that survives a crash. Even with no grab history and
        nothing to find, the torrent is recorded before the destructive
        decision, so a Protectarr that dies mid-pass restarts protected rather
        than with no memory of it at all."""
        self.scan([downloading()], [FakeArr("Sonarr", broken=True)])
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.PROVISIONAL)

    def test_the_grab_history_window_is_closed_too(self):
        """The narrower race: qBittorrent has the torrent and even the grab
        history has not appeared. Nothing positive exists anywhere, so the
        refusal cannot come from evidence - it comes from the fallback needing
        clearance that this attempt did not get, because Sonarr never refreshed
        successfully."""
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr", refresh_ok=False)])
        self.assertEqual(actions, [])

    def test_nothing_in_the_decision_consults_how_old_the_torrent_is(self):
        """`added_on` is still never read. The fix is evidence-based, not a
        timer, so a torrent added one second ago and one added last week get
        the same treatment - both synchronise, both are judged on the answer."""
        for added in (2_000_000_000, 1):
            clear_store()
            arr = FakeArr("Sonarr")
            actions = self.scan([dict(downloading(), added_on=added)], [arr])
            self.assertEqual(actions[0]["decision"], "qbit_delete")
            self.assertEqual(arr.refreshes, 1)

    def test_winning_and_losing_the_race_now_reach_the_same_answer(self):
        """The comparison that used to show two incompatible outcomes.

        Before: a scan landing in the window deleted the files and never told
        Sonarr; one scan later it handed the release back. Now both refuse,
        because both find Sonarr's grab history.
        """
        raced = self.scan([downloading()], [FakeArr("Sonarr", grabbed=[A])])
        self.assertEqual(raced, [])

        clear_store()
        lucky = self.scan([downloading()],
                          [FakeArr("Sonarr", [A], grabbed=[A])])
        self.assertEqual(lucky[0]["decision"], "arr_fail")
        self.assertEqual(lucky[0]["arr"], "Sonarr")

    def test_a_live_claim_appearing_during_sync_upgrades_to_owned(self):
        """The queue caught up between the scan and the synchronisation. The
        *arr-aware path is available again, so it is used."""
        actions = self.scan([downloading()], [FakeArr("Sonarr", [A])])
        self.assertEqual(actions[0]["decision"], "arr_fail")
        self.assertEqual(ownership.records()[A].get("state"), ownership.OWNED)


class TestPathThreeAnArrRemovedFromTheConfig(ScanCase):
    """`ownership_known` counts configured clients, not stored owners.

    Delete Sonarr from the Applications page and `len(readable) ==
    len(arr_clients)` is 0 == 0, which is True. Every torrent Sonarr owned now
    carries forward with nobody able to confirm or deny it, and the flag that
    exists to catch exactly this says ownership is known.
    """

    def test_removing_the_owning_arr_does_not_make_its_torrents_deletable(self):
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        self.assertEqual(ownership.records()[A].get("owner"), "Sonarr")

        actions = self.scan([downloading()], [])

        self.assertEqual(actions, [])

    def test_an_unreachable_arr_and_a_removed_one_are_both_protected(self):
        """The pair, side by side. Same stored record, same torrent, same mode.
        Whether the *arr is still listed in the config used to decide whether
        its torrents were deleted; it no longer does.

        `ownership_known` catches the unreachable case and cannot catch the
        removed one, because it compares readable queues against configured
        clients and a removed *arr is absent from both.
        """
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        down = self.scan([downloading()], [FakeArr("Sonarr", broken=True)])
        self.assertEqual(down, [])

        clear_store()
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        gone = self.scan([downloading()], [])
        self.assertEqual(gone, [])

    def test_the_global_flag_alone_would_not_have_caught_this(self):
        """Names the reason the veto is per-torrent rather than a wider
        `ownership_known`. With every configured queue readable - there are
        none - the flag says ownership is known."""
        self.scan([downloading()], [FakeArr("Sonarr", [A])])
        j = core.explain({"category": "tv", "tags": ""}, None,
                         dict(SAFETY, mode="either"), True,
                         own=CARRIED_OWNED_UNREADABLE)
        self.assertEqual(j.reason, "owned_not_claimed_this_pass")


class TestTheBoundariesAFixMustNotMove(ScanCase):
    """Everything a one-condition patch could plausibly break, pinned first."""

    def test_arr_tracked_never_deletes_directly_whatever_the_ownership(self):
        for own in (LIVE_OWNED, CARRIED_OWNED_NOT_ACQUIRING, UNTRACKED,
                    ORPHAN_FRESH, ORPHAN_DWELLED, None):
            for allowed in (True, False):
                j = judge("arr_tracked", own, allowed=allowed)
                self.assertNotEqual(j.action, "qbit_delete", repr(own))

    def test_a_genuinely_unowned_allowlisted_torrent_is_still_reaped(self):
        """The feature this whole mode exists for. A fix that protects stored
        owners must leave this alone."""
        arr = FakeArr("Sonarr")
        actions = self.scan([downloading(category="tv")], [arr],
                            mode="allowlist")
        self.assertEqual(actions[0]["decision"], "qbit_delete")
        self.assertEqual(arr.refreshes, 1,
                         "the clearance must come from a real refresh")
        # The record stays PROVISIONAL. Nothing about the negative answer is
        # persisted, so the next attempt has to ask again.
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.PROVISIONAL)

    def test_an_unallowlisted_category_is_untouched_in_either(self):
        actions = self.scan([downloading(category="software")],
                            [FakeArr("Sonarr")])
        self.assertEqual(actions, [])

    def test_a_live_claim_still_routes_through_the_arr(self):
        actions = self.scan([downloading()], [FakeArr("Sonarr", [A])])
        self.assertEqual(actions[0]["decision"], "arr_fail")
        self.assertEqual(actions[0]["arr"], "Sonarr")

    def test_an_unreadable_queue_still_suppresses_direct_deletion(self):
        actions = self.scan([downloading()], [FakeArr("Sonarr", broken=True)])
        self.assertEqual(actions, [])

    def test_one_unreadable_queue_among_several_suppresses_it(self):
        actions = self.scan(
            [downloading()],
            [FakeArr("Sonarr", broken=True), FakeArr("Radarr", arr_type="radarr")])
        self.assertEqual(actions, [])

    def test_a_fresh_orphan_waits_and_a_dwelled_one_does_not(self):
        self.assertIsNone(judge("either", ORPHAN_FRESH).action)
        self.assertEqual(judge("either", ORPHAN_FRESH).state, core.WAITING)
        self.assertEqual(judge("either", ORPHAN_DWELLED).action, "qbit_delete")

    def test_a_conflict_is_still_refused(self):
        own = ownership.Ownership(ownership.CONFLICTED, None, None, None, None,
                                  "two claims")
        self.assertIsNone(judge("either", own).action)
        self.assertEqual(judge("either", own).state, core.BLOCKED)

    def test_untracked_with_every_queue_readable_is_the_deletable_case(self):
        """Stated so a fix cannot quietly take it out. This is path two's
        outcome and it is also the legitimate behaviour of the mode; the two are
        the same cell of the table, which is the hard part of the fix."""
        for state in (UNTRACKED, PROVISIONAL):
            for mode in ("either", "allowlist"):
                self.assertIsNone(judge(mode, state).action,
                                  "not deletable without synchronisation")
                self.assertEqual(
                    judge(mode, state, cleared=True).action, "qbit_delete",
                    "and deletable with it")


class TestTheInvariant(unittest.TestCase):
    """The promises the fix exists to keep. These three were `expectedFailure`
    while the defect stood."""

    def test_a_torrent_with_a_named_owner_is_never_deleted_as_unowned(self):
        """The one-line statement of the defect.

        If `ownership` knows a torrent's owner, no mode may delete it on the
        grounds that it is unowned. Which *arr owns it is the whole question
        `ownership` answers, and answering it must not be worth less than never
        having asked.
        """
        for mode in ("allowlist", "either"):
            for own in (CARRIED_OWNED_NOT_ACQUIRING, CARRIED_OWNED_UNREADABLE):
                self.assertNotEqual(
                    judge(mode, own).action, "qbit_delete",
                    f"{mode} deleted a torrent owned by {own.owner}")

    def test_uncertainty_about_one_torrent_is_not_settled_by_a_global_flag(self):
        """`ownership_known` is per-pass. The question `_mode_coverage` asks it
        is per-torrent: can we tell an ownerless torrent from one whose owner we
        could not reach? For a carried-forward record the answer is no,
        regardless of what the other queues did."""
        self.assertIsNone(judge("either", CARRIED_OWNED_UNREADABLE).action)

    def test_pausing_a_torrent_does_not_make_it_easier_to_delete(self):
        """`ORPHANABLE_STATES` excludes paused states to respect a deliberate
        user action. That intent must survive to the decision, not stop at the
        label."""
        paused = CARRIED_OWNED_NOT_ACQUIRING
        self.assertIsNone(judge("either", paused).action)


if __name__ == "__main__":
    unittest.main()


class TestAQueueEntryIsNotAutomaticallyAClaim(ScanCase):
    """An *arr "unknown" item is visibility, not ownership.

    Protectarr asks every *arr for its unknown items, because `intents` has to
    know whether a queue entry is still sitting there before retrying a
    removal. An unknown item is the *arr reporting a download in its own
    category that it has no media record for: a torrent the user added by hand,
    or one whose series or movie has since been deleted.

    Treating that as ownership routed it to the *arr-aware path. Measured
    against Sonarr 4.0.20.3014 and Radarr 6.4.4.10685, that path accepts the
    request (HTTP 200, "removed"), really does delete the data, and then
    produces no blocklist row, no downloadFailed event and no replacement
    search - all three are keyed on the media id the record does not carry. The
    oracle reports it unverified, which is terminal, so the intent sits in the
    triage queue with nothing able to resolve it.
    """

    def test_an_unknown_queue_item_is_not_a_claim(self):
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr", [A], identified=False)])
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.PROVISIONAL,
                         "an unknown item must not establish ownership")
        self.assertIsNone(ownership.records()[A].get("owner"))
        self.assertEqual(actions[0]["decision"], "qbit_delete")
        self.assertIsNone(actions[0]["arr"])

    def test_arr_tracked_leaves_an_unknown_queue_item_alone(self):
        """The default mode now fails safe here. It used to send the download
        down the *arr path, deleting the data and leaving an unresolvable
        remediation behind."""
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr", [A], identified=False)],
                            mode="arr_tracked")
        self.assertEqual(actions, [])

    def test_the_audit_trail_says_category_fallback_not_arr(self):
        """`via: "arr"` on a removal the *arr has no record of is a false
        statement in the one place an operator goes to find out what
        happened."""
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr", [A], identified=False)])
        self.assertEqual(actions[0]["decision"], "qbit_delete")
        self.assertIsNone(actions[0]["_owner"],
                          "no queue record may be carried into remediation")

    def test_a_record_carrying_the_media_id_is_still_a_claim(self):
        """The control. One field is the whole difference."""
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr", [A], identified=True)])
        self.assertEqual(actions[0]["decision"], "arr_fail")
        self.assertEqual(actions[0]["arr"], "Sonarr")
        self.assertEqual(ownership.records()[A].get("state"), ownership.OWNED)

    def test_every_supported_arr_type_declares_its_identity_field(self):
        """The predicate reads `search`'s own declaration, so "has an identity"
        and "a replacement search is possible" cannot drift apart. Pinned as an
        external literal: a table derived from the code would agree with it by
        construction.
        """
        from protectarr.arr import ARR_TYPES
        self.assertEqual(
            {t: meta["search"][2] for t, meta in ARR_TYPES.items()},
            {"sonarr": "episodeId", "radarr": "movieId", "whisparr": "movieId",
             "lidarr": "albumId", "readarr": "bookId"})

    def test_the_identity_field_is_the_one_search_actually_reads(self):
        """Not a parallel list. If someone changes what `search` reads, this
        predicate follows it rather than silently disagreeing."""
        from protectarr.arr import ARR_TYPES, ArrClient
        for arr_type, meta in ARR_TYPES.items():
            client = ArrClient("x", arr_type, "http://x", "k")
            field = meta["search"][2]
            self.assertTrue(client.has_remediation_identity({field: 7}),
                            f"{arr_type}: {field} should be an identity")
            self.assertFalse(client.has_remediation_identity({"id": 1}),
                             f"{arr_type}: a bare queue id is not an identity")
            self.assertIsNone(client.search({"id": 1}),
                              f"{arr_type}: search must refuse without one")

    def test_an_unknown_item_never_reaches_the_arr_aware_path(self):
        """Across every mode, so no mode can route it to `arr_fail`."""
        for mode in ("arr_tracked", "both", "allowlist", "either"):
            clear_store()
            actions = self.scan([downloading()],
                                [FakeArr("Sonarr", [A], identified=False)],
                                mode=mode)
            for row in actions:
                self.assertNotEqual(row.get("decision"), "arr_fail",
                                    f"{mode} sent an unknown item to the *arr")


class TestLegacyOwnershipRecords(ScanCase):
    """Records written before the identity rule existed.

    Older versions recorded OWNED from any queue entry, so a store can name an
    owner for a torrent that was never remediable. Those records must not stay
    protected forever on the strength of a classification we now know was
    wrong - but ownership must also not regress just because one pass happened
    not to see a claim, which is the invariant the whole module exists for.
    """

    def test_a_legacy_owned_record_does_not_stay_owned_forever(self):
        """The *arr still lists it, so its queue was read and did not claim it.
        That is a positive observation, not a missed pass, and it earns the
        ORPHANED state with its dwell rather than instant deletion."""
        self.scan([downloading()], [FakeArr("Sonarr", [A], identified=True)])
        self.assertEqual(ownership.records()[A].get("state"), ownership.OWNED)

        self.scan([downloading()], [FakeArr("Sonarr", [A], identified=False)])
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.ORPHANED)

    def test_the_dwell_still_gates_that_correction(self):
        """A transient record missing its media id - an *arr mid-import, say -
        must not become deletable immediately. The dwell is what absorbs it."""
        self.scan([downloading()], [FakeArr("Sonarr", [A], identified=True)])
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr", [A], identified=False)])
        self.assertEqual(actions, [], "a fresh orphan is not actionable")

    def test_a_returning_claim_restores_ownership(self):
        """And proves the correction is not one-way. If the media id comes
        back, so does the claim, and the next absence is a new absence."""
        self.scan([downloading()], [FakeArr("Sonarr", [A], identified=True)])
        self.scan([downloading()], [FakeArr("Sonarr", [A], identified=False)])
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.ORPHANED)

        self.scan([downloading()], [FakeArr("Sonarr", [A], identified=True)])
        rec = ownership.records()[A]
        self.assertEqual(rec.get("state"), ownership.OWNED)
        self.assertIsNone(rec.get("absent_since"),
                          "a real claim resets the absence")

    def test_a_legitimate_owner_is_untouched_by_a_pass_that_saw_nothing(self):
        """The invariant the module exists for. An *arr that simply stopped
        listing the torrent is not the same as one that listed it without a
        media id."""
        self.scan([downloading()], [FakeArr("Sonarr", [A], identified=True)])
        self.scan([downloading()], [FakeArr("Sonarr", broken=True)])
        rec = ownership.records()[A]
        self.assertEqual(rec.get("state"), ownership.OWNED)
        self.assertEqual(rec.get("owner"), "Sonarr")


class TestSynchronisationFailsSafe(ScanCase):
    """Every way the evidence can fail to arrive, and the same answer to all.

    An answer we could not obtain is not an answer. Zero rows is not a failed
    request, a refresh that timed out is not a refresh that completed, and a
    queue that could not be read is not an empty queue.
    """

    def unreachable(self, **kw):
        return self.scan([downloading()], [FakeArr("Sonarr", **kw)])

    def test_an_unreachable_arr_leaves_it_protected(self):
        self.assertEqual(self.unreachable(broken=True), [])

    def test_a_refresh_that_fails_leaves_it_protected(self):
        self.assertEqual(self.unreachable(refresh_ok=False), [])

    def test_a_refresh_that_times_out_leaves_it_protected(self):
        self.assertEqual(
            self.unreachable(refresh_ok=False,
                             refresh_why="did not finish within 90s"), [])

    def test_a_history_read_that_fails_leaves_it_protected(self):
        self.assertEqual(self.unreachable(history_raises=True), [])

    def test_a_single_failed_history_read_is_enough(self):
        """The *arr refreshed and then stopped answering. Treating that empty
        result as "no grab history" would clear the torrent for deletion, which
        is a mutant the harness specifically hunts."""
        self.assertEqual(self.unreachable(history_raises_on=(1,)), [])

    def test_the_second_candidate_gets_its_own_failure(self):
        """A shared refresh barrier must not carry a shared verdict. The first
        candidate's history read succeeded; the second one's fails, and only
        the second is affected."""
        arr = FakeArr("Sonarr", history_raises_on=(2,))
        actions = self.scan([downloading(), downloading2()], [arr],
                            mode="allowlist")
        decisions = {a["hash"]: a["decision"] for a in actions}
        self.assertEqual(decisions.get(A), "qbit_delete",
                         "the first candidate was fully evaluated")
        self.assertNotIn(B, decisions,
                         "the second candidate's own read failed, so it stays "
                         "protected")
        self.assertEqual(arr.refreshes, 1, "one barrier, not two")

    def test_a_queue_reread_that_fails_after_a_good_refresh_protects_it(self):
        """The subtle one. The first queue read succeeded, the refresh
        completed, and then the post-refresh read failed. An empty result would
        have cleared the torrent for deletion."""
        self.assertEqual(self.unreachable(queue_raises_after=1), [])

    def test_one_failing_arr_among_several_is_enough(self):
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr"),
                             FakeArr("Radarr", arr_type="radarr",
                                     refresh_ok=False)])
        self.assertEqual(actions, [])

    def test_every_failure_leaves_the_record_provisional(self):
        """None of them may write a negative. The store must still say "not
        established", so the next attempt synchronises again."""
        for kw in ({"broken": True}, {"refresh_ok": False},
                   {"history_raises": True}, {"queue_raises_after": 1}):
            clear_store()
            self.scan([downloading()], [FakeArr("Sonarr", **kw)])
            self.assertEqual(ownership.records()[A].get("state"),
                             ownership.PROVISIONAL, repr(kw))


class TestNegativeEvidenceIsNeverDurable(ScanCase):
    """A clearance authorises one attempt and then expires."""

    def test_a_clearance_is_not_written_to_the_store(self):
        arr = FakeArr("Sonarr")
        self.scan([downloading()], [arr], mode="allowlist")
        rec = ownership.records()[A]
        self.assertEqual(rec.get("state"), ownership.PROVISIONAL)
        for key in rec:
            self.assertNotIn("clear", key.lower())
            self.assertNotIn("sync", key.lower())
            self.assertNotIn("unowned", key.lower())

    def test_the_next_attempt_synchronises_again(self):
        """Yesterday's negative answer must not authorise today's delete. The
        *arr could have grabbed the torrent in between."""
        arr = FakeArr("Sonarr")
        self.scan([downloading()], [arr], mode="allowlist")
        self.assertEqual(arr.refreshes, 1)
        self.scan([downloading()], [arr], mode="allowlist")
        self.assertEqual(arr.refreshes, 2, "the second attempt must re-ask")

    def test_an_arr_that_grabbed_it_since_now_protects_it(self):
        """The reason a clearance cannot be durable, made concrete."""
        first = FakeArr("Sonarr")
        self.assertEqual(
            self.scan([downloading()], [first], mode="allowlist")[0]["decision"],
            "qbit_delete")
        second = FakeArr("Sonarr", grabbed=[A])
        self.assertEqual(self.scan([downloading()], [second],
                                   mode="allowlist"), [])

    def test_a_preview_never_synchronises(self):
        """A page render must not force five applications to refresh, and a
        preview that triggered the thing it claims to observe would be lying.

        It still reports the finding, though. Observational must not mean
        blind: the row says what was found and marks that a real scan would ask
        every application before acting, rather than promising a deletion whose
        authorisation nobody has sought.
        """
        arr = FakeArr("Sonarr")
        actions = self.scan([downloading()], [arr], side_effects=False)
        self.assertEqual(arr.refreshes, 0, "a preview must not refresh")
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["decision"], "warn")
        self.assertTrue(actions[0]["pending_ownership_sync"])

    def test_a_preview_never_reports_a_deletion_it_cannot_authorise(self):
        """The half that matters: whatever a preview shows, it is never
        `qbit_delete`, because the answer that would authorise one has not been
        asked for."""
        for mode in ("arr_tracked", "both", "allowlist", "either"):
            clear_store()
            actions = self.scan([downloading()], [FakeArr("Sonarr")],
                                mode=mode, side_effects=False)
            for row in actions:
                self.assertNotEqual(row.get("decision"), "qbit_delete", mode)


class TestCandidateOwnerDurability(ScanCase):
    """Positive evidence survives; its absence later is not a retraction."""

    def test_a_candidate_owner_is_persisted(self):
        self.scan([downloading()], [FakeArr("Sonarr", grabbed=[A])])
        rec = ownership.records()[A]
        self.assertEqual(rec.get("candidate_owner"), "Sonarr")
        self.assertEqual(rec.get("candidate_owner_type"), "sonarr")
        self.assertEqual(rec.get("candidate_evidence"), "grab_history")
        self.assertEqual(rec.get("grab_event_id"), 41)

    def test_it_survives_a_restart(self):
        """The store is the only thing that crosses a process boundary."""
        self.scan([downloading()], [FakeArr("Sonarr", grabbed=[A])])
        ownership._store.reset()        # a fresh process, same file
        actions = self.scan([downloading()], [FakeArr("Sonarr")])
        self.assertEqual(actions, [])
        self.assertEqual(ownership.records()[A].get("candidate_owner"),
                         "Sonarr")

    def test_later_history_absence_does_not_erase_it(self):
        """Deleting a series cascade-deletes its history while the torrent
        keeps downloading - measured on both apps - so a missing row is not a
        retraction of one we already saw."""
        self.scan([downloading()], [FakeArr("Sonarr", grabbed=[A])])
        actions = self.scan([downloading()], [FakeArr("Sonarr")])
        self.assertEqual(actions, [], "still protected")
        self.assertEqual(ownership.records()[A].get("candidate_owner"),
                         "Sonarr")

    def test_a_live_claim_upgrades_it_to_owned(self):
        """And the candidate stops mattering, because operational ownership is
        now established and remediation can actually run."""
        self.scan([downloading()], [FakeArr("Sonarr", grabbed=[A])])
        actions = self.scan([downloading()],
                            [FakeArr("Sonarr", [A], grabbed=[A])])
        self.assertEqual(actions[0]["decision"], "arr_fail")
        self.assertEqual(ownership.records()[A].get("state"), ownership.OWNED)

    def test_a_candidate_owner_blocks_fallback_even_when_cleared(self):
        """Positive evidence outranks a clearance. A synchronisation that found
        a grab event does not return cleared in the first place, but the table
        must refuse it independently."""
        self.assertIsNone(judge("either", PROVISIONAL_GRABBED).action)


class TestSynchronisationConflicts(ScanCase):
    """Two applications, one torrent. Never resolved by picking one."""

    def test_two_live_claims_are_a_conflict(self):
        actions = self.scan(
            [downloading()],
            [FakeArr("Sonarr", [A]),
             FakeArr("Radarr", [A], arr_type="radarr")])
        self.assertEqual(actions, [])
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.CONFLICTED)

    def test_two_grab_histories_are_a_conflict(self):
        """Neither claims it now, but both say they asked for it. Deleting it
        would be choosing between them."""
        result = ownership.synchronise(
            [FakeArr("Sonarr", grabbed=[A]),
             FakeArr("Radarr", grabbed=[A], arr_type="radarr")], A)
        self.assertFalse(result.cleared)
        self.assertEqual(result.own.state, ownership.CONFLICTED)
        self.assertIn("Radarr", result.why)
        self.assertIn("Sonarr", result.why)

    def test_a_claim_disagreeing_with_a_grab_history_is_a_conflict(self):
        """Radarr is claiming a torrent Sonarr's history says Sonarr grabbed."""
        self.scan([downloading()], [FakeArr("Sonarr", grabbed=[A])])
        self.scan([downloading()],
                  [FakeArr("Radarr", [A], arr_type="radarr")])
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.CONFLICTED)

    def test_a_conflict_is_never_cleared_for_deletion(self):
        for own in (ownership.Ownership(ownership.CONFLICTED, None, None, None,
                                        None, "two claims"),):
            for mode in ("allowlist", "either"):
                self.assertIsNone(judge(mode, own, cleared=True).action)


class TestTheScanLocalRefreshBarrier(ScanCase):
    """One completed refresh per *arr per scan, and nothing else shared.

    A `RefreshMonitoredDownloads` makes an *arr re-read its download client, so
    one completed refresh establishes a current view of the whole population
    this scan is judging - and that population is fixed, because `core.scan`
    fetches qBittorrent's torrent list once and both detection lanes work from
    that single snapshot.

    What is emphatically not shared is any verdict. Every candidate reads every
    queue and every exact-hash history for itself, after the barrier, so
    evidence that arrives mid-scan is still found.
    """

    def many(self, n):
        return [dict(downloading(), hash=f"{i:040x}",
                     name=f"Release.{i}") for i in range(n)]

    def arrs(self, m, **kw):
        types = ("sonarr", "radarr", "lidarr", "readarr", "whisparr")
        return [FakeArr(f"App{i}", arr_type=types[i % len(types)], **kw)
                for i in range(m)]

    def test_ten_candidates_across_five_arrs_cost_five_refreshes(self):
        """The whole point of the change. Per torrent it was fifty."""
        clients = self.arrs(5)
        actions = self.scan(self.many(10), clients, mode="allowlist")
        self.assertEqual(len(actions), 10, "all ten were still judged")
        self.assertEqual([c.refreshes for c in clients], [1] * 5)

    def test_every_candidate_still_reads_every_queue_and_history(self):
        """The barrier shares a refresh, not an answer."""
        clients = self.arrs(3)
        self.scan(self.many(4), clients, mode="allowlist")
        for c in clients:
            self.assertEqual(c.refreshes, 1)
            self.assertEqual(c.queue_reads, 5,
                             "one collect() pass plus one per candidate")
            self.assertEqual(c.history_reads, 4, "one per candidate")

    def test_grab_history_appearing_mid_scan_protects_the_later_candidate(self):
        """Candidate 1 is cleared, then the *arr's history gains a row for
        candidate 2. The shared barrier must not carry candidate 1's negative
        answer over to it."""
        class LateGrab(FakeArr):
            def grab_events(self, download_id, after_id=None, pages=4):
                # The row appears only once the first candidate is done with.
                if self.history_reads >= 1:
                    self.grabbed.add(B.lower())
                return super().grab_events(download_id, after_id, pages)

        arr = LateGrab("Sonarr")
        actions = self.scan([downloading(), downloading2()], [arr],
                            mode="allowlist")
        decisions = {a["hash"]: a["decision"] for a in actions}
        self.assertEqual(decisions.get(A), "qbit_delete")
        self.assertNotIn(B, decisions, "the late grab row protected it")
        self.assertEqual(arr.refreshes, 1)

    def test_a_live_claim_appearing_mid_scan_is_also_detected(self):
        """The same, through the queue rather than history."""
        class LateClaim(FakeArr):
            def queue_by_hash(self):
                out = super().queue_by_hash()
                if self.queue_reads >= 3:
                    rec = {"id": 7, "title": "late",
                           ARR_TYPES[self.type]["search"][2]: 9,
                           "downloadId": B}
                    out[B] = rec
                return out

        arr = LateClaim("Sonarr")
        actions = self.scan([downloading(), downloading2()], [arr],
                            mode="allowlist")
        decisions = {a["hash"]: a["decision"] for a in actions}
        self.assertEqual(decisions.get(A), "qbit_delete")
        self.assertEqual(decisions.get(B), "arr_fail",
                         "a claim that arrived after the barrier still wins")

    def test_one_failed_refresh_blocks_every_candidate_in_that_scan(self):
        clients = [FakeArr("Sonarr"),
                   FakeArr("Radarr", arr_type="radarr", refresh_ok=False)]
        actions = self.scan(self.many(6), clients, mode="allowlist")
        self.assertEqual(actions, [])

    def test_a_failed_barrier_is_not_retried_per_torrent(self):
        """Ten candidates against a broken *arr must not become ten commands."""
        bad = FakeArr("Radarr", arr_type="radarr", refresh_ok=False)
        self.scan(self.many(10), [FakeArr("Sonarr"), bad], mode="allowlist")
        self.assertEqual(bad.refreshes, 1)

    def test_the_next_scan_refreshes_again(self):
        """Nothing about synchronisation survives the scan."""
        arr = FakeArr("Sonarr")
        self.scan([downloading()], [arr], mode="allowlist")
        self.assertEqual(arr.refreshes, 1)
        self.scan([downloading()], [arr], mode="allowlist")
        self.assertEqual(arr.refreshes, 2)

    def test_a_failed_barrier_is_not_cached_across_scans_either(self):
        """The next scan gets a clean attempt, not yesterday's failure."""
        arr = FakeArr("Sonarr", refresh_ok=False)
        self.assertEqual(self.scan([downloading()], [arr], mode="allowlist"), [])
        arr.refresh_ok = True
        actions = self.scan([downloading()], [arr], mode="allowlist")
        self.assertEqual(actions[0]["decision"], "qbit_delete")
        self.assertEqual(arr.refreshes, 2)

    def test_no_synchronisation_state_reaches_the_store(self):
        clients = self.arrs(3)
        self.scan(self.many(3), clients, mode="allowlist")
        for rec in ownership.records().values():
            self.assertEqual(rec.get("state"), ownership.PROVISIONAL)
            for key in rec:
                for banned in ("refresh", "barrier", "sync", "clear",
                               "unowned"):
                    self.assertNotIn(banned, key.lower(), rec)

    def test_nothing_refreshes_when_no_candidate_reaches_the_boundary(self):
        """Most scans never have one. The barrier must cost nothing then."""
        clients = self.arrs(4)
        self.scan(self.many(5), clients, mode="arr_tracked")
        self.assertEqual([c.refreshes for c in clients], [0] * 4)

    def test_a_candidate_owner_still_outranks_a_successful_barrier(self):
        """Durable positive evidence is stronger than this scan refreshing."""
        self.scan([downloading()], [FakeArr("Sonarr", grabbed=[A])],
                  mode="allowlist")
        arr = FakeArr("Sonarr")
        actions = self.scan([downloading()], [arr], mode="allowlist")
        self.assertEqual(actions, [])
        self.assertEqual(ownership.records()[A].get("candidate_owner"),
                         "Sonarr")
