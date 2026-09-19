"""`core.explain`: the same decision, with the reason kept.

`evaluate` answers "what would happen" and collapses every refusal into None.
The Active Downloads view has to tell an operator *which* refusal it was, so
`explain` is the table and `evaluate` is a projection of it.

Two things are tested here that `test_evaluate_matrix` cannot:

  * the reasons themselves, which `evaluate` discards
  * that the projection really is a projection - `evaluate` is re-derived from
    `explain` for all 240 cells and compared to the recorded table, so the two
    cannot drift apart without a named failure
"""

import unittest

from protectarr import core
from protectarr import ownership

from tests.test_evaluate_matrix import (COLUMNS, EXPECTED, OWNERSHIPS, SAFETY,
                                        TRACKED, DWELL_MINUTES)


def judge(mode, own_key="none", hit=False, allowed=True, known=True,
          cleared=False, **safety_over):
    safety = dict(SAFETY, mode=mode, **safety_over)
    torrent = {"category": "tv" if allowed else "other", "tags": ""}
    return core.explain(torrent, TRACKED if hit else None, safety, known,
                        own=OWNERSHIPS[own_key], fallback_cleared=cleared)


class TestEvaluateIsAProjectionOfExplain(unittest.TestCase):
    """The whole point of the refactor, asserted rather than assumed."""

    def test_every_cell_agrees_with_the_recorded_table(self):
        checked = 0
        for (mode, own_key), row in sorted(EXPECTED.items()):
            for (hit, allowed, known), want in zip(COLUMNS, row):
                got = judge(mode, own_key, hit, allowed, known).action
                self.assertEqual(
                    got, want,
                    f"mode={mode} ownership={own_key} tracked={hit} "
                    f"allowlisted={allowed} known={known}")
                checked += 1
        self.assertEqual(checked, 320)

    def test_an_action_is_only_ever_offered_on_permitted(self):
        """A refusal that still carried an action would be a loaded gun."""
        for (mode, own_key), row in EXPECTED.items():
            for hit, allowed, known in COLUMNS:
                j = judge(mode, own_key, hit, allowed, known)
                if j.state != core.PERMITTED:
                    self.assertIsNone(j.action, f"{mode}/{own_key} {j.state}")
                else:
                    self.assertIn(j.action, ("arr_fail", "qbit_delete"))

    def test_every_judgement_carries_a_reason(self):
        for (mode, own_key), row in EXPECTED.items():
            for hit, allowed, known in COLUMNS:
                j = judge(mode, own_key, hit, allowed, known)
                self.assertTrue(j.reason, f"{mode}/{own_key} had no reason")

    def test_the_four_states_are_the_whole_vocabulary(self):
        seen = set()
        for (mode, own_key), row in EXPECTED.items():
            for hit, allowed, known in COLUMNS:
                seen.add(judge(mode, own_key, hit, allowed, known).state)
        self.assertEqual(seen, {core.PERMITTED, core.WAITING, core.BLOCKED,
                                core.NOT_COVERED})


class TestTheReasonsEvaluateThrewAway(unittest.TestCase):

    def test_a_conflict_says_so_and_names_the_claimants(self):
        own = ownership.Ownership(
            ownership.CONFLICTED, None, None, None, None,
            "claimed simultaneously by Radarr, Sonarr")
        j = core.explain({"category": "tv", "tags": ""}, None,
                         dict(SAFETY, mode="either"), True, own=own)
        self.assertEqual(j.state, core.BLOCKED)
        self.assertEqual(j.reason, "ownership_conflict")
        self.assertIn("Radarr", j.detail["why"])
        self.assertIn("Sonarr", j.detail["why"])

    def test_a_conflict_outranks_a_mode_that_would_not_cover_it(self):
        """The conflict is *why* no *arr appears to own it, so it is the more
        useful thing to say even in arr_tracked mode."""
        j = judge("arr_tracked", "conflicted", hit=False)
        self.assertEqual(j.state, core.BLOCKED)

    def test_a_fresh_orphan_reports_how_long_it_still_has(self):
        j = judge("either", "orphan_fresh", hit=False, allowed=True)
        self.assertEqual(j.state, core.WAITING)
        self.assertEqual(j.reason, "orphan_dwell")
        self.assertEqual(j.detail["absent_for"], 60)
        self.assertEqual(j.detail["required"], DWELL_MINUTES * 60)
        self.assertEqual(j.detail["owner"], "Sonarr")
        self.assertTrue(j.detail["measurable"])

    def test_an_unmeasurable_dwell_is_flagged_rather_than_shown_as_zero(self):
        """`absent_for` is None whenever the absence could not be verified this
        pass: the owner was unreachable, or the user paused the torrent. A
        progress bar drawn from zero there would be inventing a measurement."""
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  None, "Sonarr's queue could not be read")
        j = core.explain({"category": "tv", "tags": ""}, None,
                         dict(SAFETY, mode="either"), True, own=own)
        self.assertEqual(j.state, core.WAITING)
        self.assertFalse(j.detail["measurable"])
        self.assertIsNone(j.detail["absent_for"])

    def test_waiting_is_never_reported_where_waiting_would_not_help(self):
        """arr_tracked does not cover an orphan no *arr currently claims, so
        its dwell expiring changes nothing. Saying "waiting" would promise an
        outcome that never arrives."""
        self.assertEqual(judge("arr_tracked", "orphan_fresh", hit=False).state,
                         core.NOT_COVERED)
        self.assertEqual(
            judge("arr_tracked", "orphan_dwelled", hit=False).state,
            core.NOT_COVERED)

    def test_waiting_is_reported_where_it_does_lead_somewhere(self):
        self.assertEqual(
            judge("either", "orphan_fresh", hit=False, allowed=True).state,
            core.WAITING)
        self.assertEqual(
            judge("either", "orphan_dwelled", hit=False, allowed=True).state,
            core.PERMITTED)

    def test_an_unreadable_queue_is_its_own_reason(self):
        """Distinct from "not allowlisted": the operator's fix is to bring an
        application back, not to edit a list.

        Both modes that can delete directly are checked. They are two separate
        branches carrying the same token, and testing only one of them let a
        mutation relabel the other as `not_allowlisted` with the suite green,
        which would have sent an operator to edit a list that was already
        correct.
        """
        for mode in ("allowlist", "either"):
            j = judge(mode, "none", hit=False, allowed=True, known=False)
            self.assertEqual(j.state, core.NOT_COVERED, mode)
            self.assertEqual(j.reason, "ownership_unknown", mode)

    def test_only_the_modes_that_delete_directly_can_be_held_by_that(self):
        """arr_tracked and both never delete from qBittorrent, so an unreadable
        queue is not what is stopping them and must not be blamed."""
        for mode in ("arr_tracked", "both"):
            j = judge(mode, "none", hit=False, allowed=True, known=False)
            self.assertNotEqual(j.reason, "ownership_unknown", mode)

    def test_not_tracked_and_not_allowlisted_are_told_apart(self):
        self.assertEqual(judge("arr_tracked", hit=False).reason, "not_tracked")
        self.assertEqual(
            judge("allowlist", hit=False, allowed=False).reason,
            "not_allowlisted")

    def test_both_names_whichever_half_is_missing(self):
        self.assertEqual(judge("both", hit=True, allowed=False).reason,
                         "not_allowlisted")
        self.assertEqual(judge("both", hit=False, allowed=True).reason,
                         "not_tracked")
        self.assertEqual(judge("both", hit=False, allowed=False).reason,
                         "not_tracked_and_not_allowlisted")

    def test_an_unknown_mode_is_named_as_such(self):
        j = judge("bogus", hit=True, allowed=True)
        self.assertEqual(j.state, core.NOT_COVERED)
        self.assertEqual(j.reason, "unknown_mode")
        self.assertEqual(j.detail["mode"], "bogus")

    def test_a_permitted_torrent_says_which_route_it_would_take(self):
        self.assertEqual(judge("either", hit=True).reason, "tracked_by_arr")
        self.assertEqual(
            judge("either", hit=False, allowed=True, cleared=True).reason,
            "allowlisted_and_unowned")


class TestExplainIsSafeForARequestThread(unittest.TestCase):
    """It is about to be called from Flask while the scanner is running."""

    def test_it_does_not_mutate_anything_it_is_given(self):
        torrent = {"category": "tv", "tags": "a,b"}
        safety = dict(SAFETY, mode="either")
        own = OWNERSHIPS["orphan_fresh"]
        before = (dict(torrent), dict(safety), tuple(own))
        core.explain(torrent, None, safety, True, own=own)
        self.assertEqual((torrent, safety, tuple(own)),
                         (before[0], before[1], before[2]))

    def test_it_is_deterministic(self):
        args = ({"category": "tv", "tags": ""}, None,
                dict(SAFETY, mode="either"), True)
        first = core.explain(*args, own=OWNERSHIPS["orphan_fresh"])
        second = core.explain(*args, own=OWNERSHIPS["orphan_fresh"])
        self.assertEqual(first, second)

    def test_it_works_without_an_ownership_record_at_all(self):
        """Callers that do not track ownership must still get an answer."""
        j = core.explain({"category": "tv", "tags": ""}, TRACKED,
                         dict(SAFETY, mode="arr_tracked"), True)
        self.assertEqual(j.state, core.PERMITTED)
        self.assertEqual(j.action, "arr_fail")


if __name__ == "__main__":
    unittest.main()
