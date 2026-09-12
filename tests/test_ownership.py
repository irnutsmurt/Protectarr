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

    def pass_(self, clients, downloading=(A,), now=None):
        claims, readable = ownership.collect(clients)
        return ownership.resolve(claims, readable, downloading=downloading,
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
        got = self.pass_([FakeArr("Sonarr", [A])], downloading=(A, B))
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
        done = self.pass_([FakeArr("Sonarr")], downloading=(), now=t + 3600)
        self.assertNotEqual(done[A].state, ownership.ORPHANED)
        self.assertFalse(ownership.actionable_orphan(done[A], 10))
        self.assertIn("imported", done[A].why)

    def test_a_torrent_that_stops_being_watched_does_not_age(self):
        """No current observation is no current observation."""
        t = time.time()
        self.pass_([FakeArr("Sonarr", [A])], now=t)
        self.pass_([FakeArr("Sonarr")], now=t)          # orphan clock starts
        self.pass_([FakeArr("Sonarr")], downloading=(), now=t + 3600)
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

    def test_a_completed_torrent_is_not_offered_as_an_orphan_candidate(self):
        """The scan must filter on progress, not just hand over every hash.

        `only_active: false` puts finished torrents in the scan list, so the
        filtering cannot be left to the state filter.
        """
        self.pass_([FakeArr("Sonarr", [A])])
        self._scan([{"hash": A, "state": "uploading", "progress": 1.0,
                     "name": "done"}],
                   [FakeArr("Sonarr")])
        self.assertNotEqual(ownership.records()[A].get("state"),
                            ownership.ORPHANED)

    def test_an_incomplete_torrent_still_becomes_an_orphan(self):
        self.pass_([FakeArr("Sonarr", [A])])
        self._scan([{"hash": A, "state": "downloading", "progress": 0.4,
                     "name": "going"}],
                   [FakeArr("Sonarr")])
        self.assertEqual(ownership.records()[A].get("state"),
                         ownership.ORPHANED)


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
