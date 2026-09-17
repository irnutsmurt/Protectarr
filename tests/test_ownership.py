"""Ownership: what is known, how it was known, and what was only assumed.

Every test here is a variation on one question: can Protectarr tell the
difference between "no *arr claims this torrent" and "we did not manage to ask
the *arr"? The old code could not, which meant a Sonarr restart briefly turned
every torrent it owned into an untracked torrent - and in allowlist mode an
untracked torrent is one Protectarr may delete.

Run with:  python -m unittest discover -s tests
"""

import os
import sys
import time
import tempfile
import unittest

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, ownership  # noqa: E402

A = "a" * 40
B = "b" * 40


class FakeArr:
    def __init__(self, name, hashes=(), broken=False, arr_type="sonarr"):
        self.name = name
        self.type = arr_type
        self.hashes = list(hashes)
        self.broken = broken

    def queue_by_hash(self):
        if self.broken:
            raise requests.RequestException("connection refused")
        return {h: {"id": 1, "title": f"{self.name} item"} for h in self.hashes}


class OwnershipCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        ownership._store.reset()

    def pass_(self, clients, acquiring=(A,), now=None):
        claims, readable = ownership.collect(clients)
        return ownership.resolve(claims, readable, acquiring=acquiring,
                                 now=now)


class TestBasicStates(OwnershipCase):
    def test_a_torrent_no_arr_has_ever_claimed_is_untracked(self):
        got = self.pass_([FakeArr("Sonarr")])
        self.assertEqual(got[A].state, ownership.UNTRACKED)

    def test_one_claim_is_ownership(self):
        got = self.pass_([FakeArr("Sonarr", [A])])
        self.assertEqual(got[A].state, ownership.OWNED)
        self.assertEqual(got[A].owner, "Sonarr")
        self.assertIsNotNone(got[A].record)

    def test_two_simultaneous_claims_are_a_conflict(self):
        got = self.pass_([FakeArr("Sonarr", [A]), FakeArr("Radarr", [A])])
        self.assertEqual(got[A].state, ownership.CONFLICTED)
        self.assertIsNone(got[A].client, "it picked one anyway")

    def test_a_conflict_is_not_resolved_by_config_order(self):
        """Which is what first-writer-wins on the queue map amounted to."""
        one = self.pass_([FakeArr("Sonarr", [A]), FakeArr("Radarr", [A])])
        ownership._store.reset()
        cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")
        two = self.pass_([FakeArr("Radarr", [A]), FakeArr("Sonarr", [A])])
        self.assertEqual(one[A].state, two[A].state)
        self.assertEqual(one[A].owner, two[A].owner)

    def test_ownership_of_another_torrent_is_unaffected(self):
        got = self.pass_([FakeArr("Sonarr", [A])], acquiring=(A, B))
        self.assertEqual(got[A].state, ownership.OWNED)
        self.assertEqual(got[B].state, ownership.UNTRACKED)


class TestOrphanDwell(OwnershipCase):
    """Absence only counts when we looked, and only after it has lasted."""

    def test_verified_absence_makes_an_orphan(self):
        self.pass_([FakeArr("Sonarr", [A])])
        got = self.pass_([FakeArr("Sonarr")])
        self.assertEqual(got[A].state, ownership.ORPHANED)
        self.assertEqual(got[A].owner, "Sonarr")

    def test_a_fresh_orphan_is_not_yet_actionable(self):
        self.pass_([FakeArr("Sonarr", [A])])
        got = self.pass_([FakeArr("Sonarr")])
        self.assertFalse(ownership.actionable_orphan(got[A], 10))

    def test_an_orphan_becomes_actionable_once_the_dwell_elapses(self):
        t = time.time()
        self.pass_([FakeArr("Sonarr", [A])], now=t)
        self.pass_([FakeArr("Sonarr")], now=t)
        got = self.pass_([FakeArr("Sonarr")], now=t + 11 * 60)
        self.assertGreaterEqual(got[A].absent_for, 10 * 60)
        self.assertTrue(ownership.actionable_orphan(got[A], 10))

    def test_a_failed_queue_read_does_not_advance_the_dwell(self):
        """Ten minutes of not looking is not ten minutes of being absent."""
        t = time.time()
        self.pass_([FakeArr("Sonarr", [A])], now=t)
        self.pass_([FakeArr("Sonarr")], now=t)             # absent from here
        # Sonarr then goes down for an hour.
        blind = self.pass_([FakeArr("Sonarr", broken=True)], now=t + 3600)
        self.assertFalse(ownership.actionable_orphan(blind[A], 10),
                         "an outage aged the torrent into an orphan")
        # And the clock still runs from the first *verified* absence.
        seen = self.pass_([FakeArr("Sonarr")], now=t + 3601)
        self.assertGreater(seen[A].absent_for, 3600)

    def test_an_unreadable_owner_never_starts_the_clock_at_all(self):
        t = time.time()
        self.pass_([FakeArr("Sonarr", [A])], now=t)
        got = self.pass_([FakeArr("Sonarr", broken=True)], now=t + 3600)
        self.assertEqual(got[A].state, ownership.OWNED)
        self.assertIn("could not be read", got[A].why)

    def test_a_finished_download_is_not_an_orphan(self):
        """Success also removes a torrent from its *arr's queue.

        The *arr imported it and moved on, which is the outcome the whole
        stack exists to produce. Found by running a real scan: every completed
        download in a 1208-torrent library was on its way to being labelled
        abandoned, and in `either` mode an abandoned torrent in an allowlisted
        category is one Protectarr may delete.
        """
        t = time.time()
        self.pass_([FakeArr("Sonarr", [A])], now=t)
        done = self.pass_([FakeArr("Sonarr")], acquiring=(), now=t + 3600)
        self.assertNotEqual(done[A].state, ownership.ORPHANED)
        self.assertFalse(ownership.actionable_orphan(done[A], 10))
        self.assertIn("imported", done[A].why)

    def test_a_torrent_that_stops_being_watched_does_not_age(self):
        """No current observation is no current observation."""
        t = time.time()
        self.pass_([FakeArr("Sonarr", [A])], now=t)
        self.pass_([FakeArr("Sonarr")], now=t)          # orphan clock starts
        self.pass_([FakeArr("Sonarr")], acquiring=(), now=t + 3600)
        back = self.pass_([FakeArr("Sonarr")], now=t + 3601)
        self.assertEqual(back[A].state, ownership.ORPHANED)

    def test_a_torrent_that_comes_back_is_owned_again_immediately(self):
        t = time.time()
        self.pass_([FakeArr("Sonarr", [A])], now=t)
        self.pass_([FakeArr("Sonarr")], now=t)
        back = self.pass_([FakeArr("Sonarr", [A])], now=t + 60)
        self.assertEqual(back[A].state, ownership.OWNED)
        # And the next absence is a new absence, not a resumed one.
        again = self.pass_([FakeArr("Sonarr")], now=t + 61)
        self.assertLess(again[A].absent_for, 5)


class TestTransfer(OwnershipCase):
    """A claim may move, but only when the old owner is seen letting go."""

    def test_a_transfer_is_accepted_when_the_old_owner_is_readable(self):
        self.pass_([FakeArr("Sonarr", [A])])
        got = self.pass_([FakeArr("Sonarr"), FakeArr("Radarr", [A])])
        self.assertEqual(got[A].state, ownership.OWNED)
        self.assertEqual(got[A].owner, "Radarr")
        self.assertIn("transferred", got[A].why)

    def test_a_transfer_is_refused_when_the_old_owner_is_unreadable(self):
        """Sonarr might still be claiming it, and two live claims is a conflict."""
        self.pass_([FakeArr("Sonarr", [A])])
        got = self.pass_([FakeArr("Sonarr", broken=True), FakeArr("Radarr", [A])])
        self.assertEqual(got[A].state, ownership.CONFLICTED)
        self.assertIn("not proven", got[A].why)

    def test_an_unproven_transfer_does_not_rewrite_the_owner(self):
        """Otherwise the next pass would treat the guess as established fact."""
        self.pass_([FakeArr("Sonarr", [A])])
        self.pass_([FakeArr("Sonarr", broken=True), FakeArr("Radarr", [A])])
        self.assertEqual(ownership.records()[A]["owner"], "Sonarr")

    def test_the_same_owner_reclaiming_is_not_a_transfer(self):
        self.pass_([FakeArr("Sonarr", [A])])
        got = self.pass_([FakeArr("Sonarr", [A])])
        self.assertEqual(got[A].why, "claimed by its owner")


class TestPruning(OwnershipCase):
    def test_a_torrent_qbittorrent_still_has_is_never_forgotten(self):
        self.pass_([FakeArr("Sonarr", [A])])
        self.assertEqual(ownership.prune([A]), 0)
        self.assertIn(A, ownership.records())

    def test_a_torrent_qbittorrent_no_longer_has_is_forgotten(self):
        self.pass_([FakeArr("Sonarr", [A])])
        self.assertEqual(ownership.prune([B]), 1)
        self.assertNotIn(A, ownership.records())

    def test_an_empty_inventory_is_treated_as_a_failed_call(self):
        """Far likelier than a genuinely empty qBittorrent, and destructive."""
        self.pass_([FakeArr("Sonarr", [A])])
        self.assertEqual(ownership.prune([]), 0)
        self.assertIn(A, ownership.records())

    def test_case_does_not_matter(self):
        self.pass_([FakeArr("Sonarr", [A])])
        self.assertEqual(ownership.prune([A.upper()]), 0)
        self.assertIn(A, ownership.records())


class TestDurability(OwnershipCase):
    def test_ownership_survives_a_restart(self):
        self.pass_([FakeArr("Sonarr", [A])])
        ownership._store.reset()            # a fresh process
        got = self.pass_([FakeArr("Sonarr")])
        self.assertEqual(got[A].state, ownership.ORPHANED,
                         "it forgot the torrent had ever been owned")

    def test_a_previously_owned_torrent_never_reads_as_untracked(self):
        """The whole reason this is durable.

        Untracked is the state that lets allowlist mode delete something
        outright. A torrent that was *arr-owned must reach that state through
        an explicit prune, never by being forgotten.
        """
        self.pass_([FakeArr("Sonarr", [A])])
        for clients in ([FakeArr("Sonarr")],
                        [FakeArr("Sonarr", broken=True)],
                        []):
            ownership._store.reset()
            got = self.pass_(clients)
            self.assertNotEqual(got[A].state, ownership.UNTRACKED,
                                f"untracked after a pass with {clients!r}")


class TestScanFeedsOwnershipCorrectly(OwnershipCase):
    """What the scan actually hands to `resolve`, not what it could hand it."""

    def _scan(self, torrents, clients):
        class FakeQb:
            def login(self): pass
            def torrents(self, category=None, state_filter=None):
                return list(torrents) if state_filter is None else list(torrents)
            def files(self, h): return []

        real_qb, real_build = core.QbitClient, core.build_clients
        core.QbitClient = lambda *a, **k: FakeQb()
        core.build_clients = lambda cfg: list(clients)
        try:
            core.scan({"qbittorrent": {"url": "http://x"},
                       "detection": {"only_active": False},
                       "safety": {}, "arrs": []}, {}, side_effects=False)
        finally:
            core.QbitClient, core.build_clients = real_qb, real_build

    def _state_becomes_orphan(self, state, progress=0.4):
        self.pass_([FakeArr("Sonarr", [A])])
        self._scan([{"hash": A, "state": state, "progress": progress,
                     "name": "t"}], [FakeArr("Sonarr")])
        return ownership.records()[A].get("state") == ownership.ORPHANED

    def test_a_completed_torrent_is_not_offered_as_an_orphan_candidate(self):
        """A download that succeeded also leaves its *arr's queue.

        `only_active: false` puts finished torrents in the scan list, so this
        cannot be left to qBittorrent's state filter.
        """
        for state in ("uploading", "stalledUP", "queuedUP", "checkingUP",
                      "pausedUP", "forcedUP"):
            self.setUp()
            self.assertFalse(self._state_becomes_orphan(state, progress=1.0),
                             f"a finished torrent in {state} became an orphan")

    def test_a_stalled_download_is_still_an_orphan_candidate(self):
        """Eligibility is not keyed on speed, and this is why.

        A torrent with no seeds sits at 0 B/s indefinitely. That is exactly
        what an abandoned fake looks like, so excluding it would exclude the
        case orphan handling exists for.
        """
        self.assertTrue(self._state_becomes_orphan("stalledDL"))

    def test_a_torrent_the_user_paused_is_not_an_orphan_candidate(self):
        """They stopped it on purpose. Queue absence is not a reason to act."""
        for state in ("pausedDL", "stoppedDL"):
            self.setUp()
            self.assertFalse(self._state_becomes_orphan(state),
                             f"a user-paused torrent in {state} became an orphan")

    def test_the_ordinary_downloading_states_are_candidates(self):
        for state in ("downloading", "forcedDL", "queuedDL", "metaDL",
                      "allocating"):
            self.setUp()
            self.assertTrue(self._state_becomes_orphan(state),
                            f"{state} was not treated as still acquiring")

    def test_the_orphanable_set_is_derived_from_the_downloading_set(self):
        """So the two cannot drift apart as qBittorrent adds states."""
        self.assertTrue(core.ORPHANABLE_STATES < core.DOWNLOADING_STATES)
        self.assertEqual(core.DOWNLOADING_STATES - core.ORPHANABLE_STATES,
                         {"pausedDL", "stoppedDL"})


class TestAnOutageNeverWritesAnObservation(OwnershipCase):
    """The stored record may only ever assert what a pass actually saw.

    `_unclaimed` carries a previous OWNED state forward when the owner's queue
    could not be read, which is the whole point of the module. But `_persist`
    then wrote `owner_type`, `last_claimed` and `absent_since` from that
    carried-forward state as if a claim had been observed. Nothing read those
    two fields at the time, so it was invisible; the Active Downloads view is
    the first consumer and would have shown an unknown application type and a
    claim timestamp that moved every time Sonarr restarted.
    """

    def stored(self, thash=A):
        return ownership.records()[thash]

    def claim_then_outage(self, arr_type="sonarr"):
        live = FakeArr("Sonarr", [A], arr_type=arr_type)
        self.pass_([live], now=1000.0)
        before = dict(self.stored())
        self.pass_([FakeArr("Sonarr", [A], broken=True)], now=2000.0)
        return before, dict(self.stored())

    def test_an_outage_does_not_erase_a_known_owner_type(self):
        before, after = self.claim_then_outage()
        self.assertEqual(before["owner_type"], "sonarr")
        self.assertEqual(after["owner_type"], "sonarr")

    def test_an_outage_does_not_advance_last_claimed(self):
        before, after = self.claim_then_outage()
        self.assertEqual(before["last_claimed"], 1000.0)
        self.assertEqual(after["last_claimed"], 1000.0)

    def test_the_outage_still_keeps_the_owner_and_the_state(self):
        """The carried-forward parts are the point of the module and must not
        have been thrown out with the fix."""
        _, after = self.claim_then_outage()
        self.assertEqual(after["owner"], "Sonarr")
        self.assertEqual(after["state"], ownership.OWNED)

    def test_updated_still_moves_because_the_pass_really_happened(self):
        """`updated` is when Protectarr last considered this record, which is
        true on an outage pass. It is not a claim."""
        _, after = self.claim_then_outage()
        self.assertEqual(after["updated"], 2000.0)

    def test_a_real_claim_does_advance_last_claimed(self):
        """The fix must not freeze the field for everyone."""
        live = FakeArr("Sonarr", [A])
        self.pass_([live], now=1000.0)
        self.pass_([live], now=3000.0)
        self.assertEqual(self.stored()["last_claimed"], 3000.0)

    def test_a_real_claim_still_records_the_owner_type(self):
        live = FakeArr("Radarr", [A], arr_type="radarr")
        self.pass_([live], now=1000.0)
        self.assertEqual(self.stored()["owner_type"], "radarr")

    def test_a_reclaimed_orphan_still_has_its_dwell_cleared(self):
        """`absent_since = None` moved inside the observed-claim branch, so the
        reset that `actionable_orphan` documents has to still happen."""
        live = FakeArr("Sonarr", [A])
        self.pass_([live], now=1000.0)
        self.pass_([FakeArr("Sonarr")], now=2000.0)          # absent
        self.assertIsNotNone(self.stored()["absent_since"])
        self.pass_([live], now=3000.0)                        # claimed again
        self.assertIsNone(self.stored()["absent_since"])
        self.assertEqual(self.stored()["state"], ownership.OWNED)

    def test_an_outage_during_an_orphan_does_not_clear_the_dwell(self):
        """The other direction: a carried-forward ORPHANED state must keep the
        clock it already had rather than having it reset by an outage."""
        live = FakeArr("Sonarr", [A])
        self.pass_([live], now=1000.0)
        self.pass_([FakeArr("Sonarr")], now=2000.0)          # absent, verified
        started = self.stored()["absent_since"]
        self.pass_([FakeArr("Sonarr", broken=True)], now=2500.0)
        self.assertEqual(self.stored()["absent_since"], started)

    def test_an_outage_rewrites_nothing_at_all_on_a_record_it_did_not_see(self):
        """The invariant, stated against a record this code did not write.

        `absent_since = None` is inside the guard for the same reason as the
        other two, but no pass Protectarr runs can currently produce an OWNED
        record that still has a dwell on it - so moving that one line back out
        is invisible to a test that starts from a live pass. A store restored
        from a backup, or written by hand while debugging, is not bound by that
        and is exactly when an operator is least able to afford Protectarr
        quietly editing fields it never observed.

        So this seeds the record directly and asserts the whole of it survives
        an outage untouched apart from `updated`.
        """
        seeded = {"state": ownership.OWNED, "owner": "Sonarr",
                  "owner_type": "sonarr", "first_seen": 10.0,
                  "last_claimed": 20.0, "absent_since": 30.0}
        ownership._store.save(
            {"version": ownership.VERSION, "owners": {A: dict(seeded)}})

        self.pass_([FakeArr("Sonarr", [A], broken=True)], now=9999.0)

        after = self.stored()
        self.assertEqual(after["updated"], 9999.0)
        self.assertEqual({k: v for k, v in after.items() if k != "updated"},
                         seeded)

    def test_a_type_change_on_a_real_claim_is_still_recorded(self):
        """Someone re-pointing an instance at a different app type is an
        observation, and must overwrite."""
        self.pass_([FakeArr("Sonarr", [A], arr_type="sonarr")], now=1000.0)
        self.pass_([FakeArr("Sonarr", [A], arr_type="radarr")], now=2000.0)
        self.assertEqual(self.stored()["owner_type"], "radarr")


class TestEvaluateHonoursOwnership(OwnershipCase):
    """The states have to actually change what Protectarr does."""

    TORRENT = {"category": "tv", "tags": ""}
    SAFETY = {"mode": "either", "allowed_categories": ["tv"],
              "orphan_dwell_minutes": 10}

    def test_a_conflicted_torrent_is_left_alone(self):
        own = ownership.Ownership(ownership.CONFLICTED, None, None, None, None,
                                  "two claims")
        self.assertIsNone(core.evaluate(self.TORRENT, "x.exe", None,
                                        self.SAFETY, True, own=own))

    def test_a_conflicted_torrent_is_left_alone_even_with_a_claim(self):
        own = ownership.Ownership(ownership.CONFLICTED, None, None, None, None,
                                  "two claims")
        self.assertIsNone(core.evaluate(self.TORRENT, "x.exe", ("c", {}),
                                        self.SAFETY, True, own=own))

    def test_a_fresh_orphan_is_left_alone(self):
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  60, "absent")
        self.assertIsNone(core.evaluate(self.TORRENT, "x.exe", None,
                                        self.SAFETY, True, own=own))

    def test_a_dwelled_orphan_is_actionable(self):
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  11 * 60, "absent")
        self.assertEqual(core.evaluate(self.TORRENT, "x.exe", None,
                                       self.SAFETY, True, own=own),
                         "qbit_delete")

    def test_an_owned_torrent_still_goes_to_its_arr(self):
        own = ownership.Ownership(ownership.OWNED, "Sonarr", None, {}, None,
                                  "claimed")
        self.assertEqual(core.evaluate(self.TORRENT, "x.exe", ("c", {}),
                                       self.SAFETY, True, own=own),
                         "arr_fail")

    def test_nothing_changes_when_ownership_is_not_supplied(self):
        """Callers that do not track ownership behave exactly as before."""
        self.assertEqual(core.evaluate(self.TORRENT, "x.exe", ("c", {}),
                                       self.SAFETY, True), "arr_fail")


if __name__ == "__main__":
    unittest.main()
