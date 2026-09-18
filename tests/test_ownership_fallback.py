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


def judge(mode, own, hit=False, allowed=True, known=True):
    safety = dict(SAFETY, mode=mode)
    torrent = {"category": "tv" if allowed else "other", "tags": ""}
    return core.explain(torrent, ("client", {}) if hit else None, safety,
                        known, own=own)


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
        ownership._store.reset()

    def scan(self, torrents, clients, mode="either", files=None,
             only_active=True):
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
            return core.scan(cfg, {}, side_effects=False)
        finally:
            core.QbitClient, core.build_clients = real_qb, real_build


class FakeArr:
    def __init__(self, name, hashes=(), broken=False, arr_type="sonarr"):
        self.name = name
        self.type = arr_type
        self.hashes = list(hashes)
        self.broken = broken

    def queue_by_hash(self):
        if self.broken:
            raise requests.RequestException("connection refused")
        return {h: {"id": 1, "title": f"{self.name} item", "downloadId": h}
                for h in self.hashes}

    def grab_indexer(self, download_id):
        return None


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

    STILL OPEN. The OWNED veto does not reach this and was not meant to: the
    state is UNTRACKED, there is no durable record, and a rule phrased as
    "respect the stored owner" has nothing to respect. These tests pin the
    current behaviour so the gap stays visible rather than being mistaken for
    something the ownership fix covered.
    """

    def test_a_torrent_sonarr_has_not_yet_published_reaches_the_delete(self):
        actions = self.scan([downloading()], [FakeArr("Sonarr")])

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["decision"], "qbit_delete")
        self.assertEqual(ownership.records().get(A), None)

    def test_nothing_in_the_decision_consults_how_old_the_torrent_is(self):
        """`added_on` is the field that would separate "nobody owns this" from
        "nobody owns this yet". qBittorrent reports it; Protectarr never reads
        it, so a torrent added one second ago and one added last week are the
        same input."""
        fresh = dict(downloading(), added_on=2_000_000_000)
        old = dict(downloading(), added_on=1)
        self.assertEqual(
            self.scan([fresh], [FakeArr("Sonarr")])[0]["decision"],
            self.scan([old], [FakeArr("Sonarr")])[0]["decision"])


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

        ownership._store.reset()
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
        actions = self.scan([downloading(category="tv")], [FakeArr("Sonarr")],
                            mode="allowlist")
        self.assertEqual(actions[0]["decision"], "qbit_delete")
        self.assertEqual(ownership.records().get(A), None)

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
        self.assertEqual(judge("either", UNTRACKED).action, "qbit_delete")
        self.assertEqual(judge("allowlist", UNTRACKED).action, "qbit_delete")


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
