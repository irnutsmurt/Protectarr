"""The Active Downloads snapshot: what it contains, and what it refuses to.

The snapshot is presentation state. It is allowed to be wrong about nothing and
is allowed to invent nothing, because every field on it is about to be shown to
an operator as a statement of what Protectarr currently believes.

Several of these are acceptance tests for decisions taken before any of it was
written, and they are named so a failure says which promise broke.
"""

import os
import sys
import tempfile
import time
import unittest

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, ownership, snapshot  # noqa: E402

A = "a" * 40
B = "b" * 40
C = "c" * 40


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


def torrent(thash, **over):
    t = {"hash": thash, "name": f"Release.{thash[:4]}", "state": "downloading",
         "progress": 0.4, "size": 1000, "category": "tv", "tags": "",
         "dlspeed": 1000, "eta": 60}
    t.update(over)
    return t


CFG = {"safety": {"mode": "either", "allowed_categories": ["tv"],
                  "orphan_dwell_minutes": 10},
       "detection": {}, "arrs": [], "dry_run": True}


def build(torrents, resolved=None, owner=None, cfg=None, **over):
    kw = {"taken_at": 1000.0, "resolved": resolved or {}, "owner": owner or {},
          "ownership_known": True, "unreadable": [], "cfg": cfg or CFG,
          "arr_by_name": {}, "explain": core.explain}
    kw.update(over)
    return snapshot.build(torrents, **kw)


class TestTheSpineIsTheTorrentList(unittest.TestCase):
    """Never ownership.json. Records outlive their torrents by up to an hour."""

    def test_a_stale_ownership_record_with_no_torrent_does_not_render(self):
        resolved = {
            A: ownership.Ownership(ownership.OWNED, "Sonarr", None, {}, None,
                                   "claimed"),
            B: ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                   9999, "long gone"),
        }
        snap = build([torrent(A)], resolved=resolved)
        self.assertEqual([r["hash"] for r in snap["rows"]], [A])

    def test_a_torrent_with_no_ownership_record_still_renders(self):
        snap = build([torrent(A)], resolved={})
        self.assertEqual(len(snap["rows"]), 1)
        self.assertEqual(snap["rows"][0]["ownership"], "untracked")

    def test_the_row_order_follows_qbittorrent(self):
        snap = build([torrent(C), torrent(A), torrent(B)])
        self.assertEqual([r["hash"] for r in snap["rows"]], [C, A, B])


class TestPausedOrphansDoNotCountTowardAction(unittest.TestCase):
    """Acceptance test.

    A paused orphan keeps `absent_since` on disk, and a page that computed the
    dwell from that would show a countdown advancing toward a removal that the
    engine will never perform. The snapshot carries the engine's own answer,
    and the engine reports `absent_for` as None whenever the absence could not
    be verified this pass.
    """

    def orphan(self, absent_for):
        return {A: ownership.Ownership(ownership.ORPHANED, "Sonarr", None,
                                       None, absent_for, "absent")}

    def test_an_unmeasurable_dwell_is_reported_as_unmeasurable(self):
        snap = build([torrent(A, state="pausedDL")],
                     resolved=self.orphan(None))
        row = snap["rows"][0]
        self.assertIsNone(row["absent_for"])
        self.assertEqual(row["policy_state"], core.WAITING)
        self.assertFalse(row["policy_detail"]["measurable"])

    def test_it_is_never_rendered_as_zero_progress(self):
        """The distinction the whole test exists for: None is not 0."""
        snap = build([torrent(A, state="pausedDL")],
                     resolved=self.orphan(None))
        self.assertIsNot(snap["rows"][0]["absent_for"], 0)
        self.assertIsNone(snap["rows"][0]["absent_for"])

    def test_a_measurable_dwell_still_reports_its_numbers(self):
        snap = build([torrent(A)], resolved=self.orphan(120))
        detail = snap["rows"][0]["policy_detail"]
        self.assertEqual(detail["absent_for"], 120)
        self.assertEqual(detail["required"], 600)
        self.assertTrue(detail["measurable"])

    def test_a_dwelled_orphan_reports_permitted_not_waiting(self):
        snap = build([torrent(A)], resolved=self.orphan(11 * 60))
        self.assertEqual(snap["rows"][0]["policy_state"], core.PERMITTED)


class TestTorrentsTheLoopCannotInspect(unittest.TestCase):
    """Acceptance test: metaDL is present and honestly labelled."""

    def test_a_metadata_torrent_is_included(self):
        snap = build([torrent(A, state="metaDL")])
        self.assertEqual([r["hash"] for r in snap["rows"]], [A])

    def test_it_is_not_claimed_to_have_been_inspected(self):
        row = build([torrent(A, state="metaDL")])["rows"][0]
        self.assertFalse(row["inspected"])
        self.assertEqual(row["skip_reason"], "awaiting_metadata")

    def test_both_metadata_states_are_recognised(self):
        for state in ("metaDL", "forcedMetaDL"):
            row = build([torrent(A, state=state)])["rows"][0]
            self.assertEqual(row["skip_reason"], "awaiting_metadata", state)

    def test_an_ordinary_torrent_is_marked_inspected(self):
        row = build([torrent(A)])["rows"][0]
        self.assertTrue(row["inspected"])
        self.assertIsNone(row["skip_reason"])

    def test_it_carries_no_finding(self):
        """Not inspected is not the same as inspected and clean."""
        row = build([torrent(A, state="metaDL")])["rows"][0]
        self.assertIsNone(row["finding"])


class TestConflictsCarryTheirClaimants(unittest.TestCase):
    """Acceptance test: the rationale comes from the pass, not from disk.

    `ownership._persist` deliberately never writes the claimants, because
    recording one would turn an unresolved conflict into a decision on the next
    pass. The snapshot is the right place for that explanation precisely
    because it is not authoritative.
    """

    def test_the_rationale_survives_into_the_row(self):
        own = ownership.Ownership(
            ownership.CONFLICTED, None, None, None, None,
            "claimed simultaneously by Radarr, Sonarr")
        row = build([torrent(A)], resolved={A: own})["rows"][0]
        self.assertEqual(row["ownership"], "conflicted")
        self.assertIn("Radarr", row["ownership_why"])
        self.assertIn("Sonarr", row["ownership_why"])

    def test_the_policy_state_says_blocked(self):
        own = ownership.Ownership(ownership.CONFLICTED, None, None, None, None,
                                  "claimed simultaneously by Radarr, Sonarr")
        row = build([torrent(A)], resolved={A: own})["rows"][0]
        self.assertEqual(row["policy_state"], core.BLOCKED)
        self.assertEqual(row["policy_reason"], "ownership_conflict")
        self.assertIn("Sonarr", row["policy_detail"]["why"])


class TestNothingIsEverPresentedAsAnIntention(unittest.TestCase):
    """`would` is what policy permits, not what is queued to happen."""

    def test_a_permitted_row_carries_no_finding_of_its_own(self):
        row = build([torrent(A)])["rows"][0]
        self.assertEqual(row["policy_state"], core.PERMITTED)
        self.assertIsNone(row["finding"])

    def test_the_action_is_only_populated_where_policy_permits(self):
        blocked = ownership.Ownership(ownership.CONFLICTED, None, None, None,
                                      None, "two claims")
        row = build([torrent(A)], resolved={A: blocked})["rows"][0]
        self.assertIsNone(row["would"])

    def test_a_flagged_torrent_carries_its_finding(self):
        action = {"hash": A, "bad_file": "setup.exe",
                  "reason": "blocked extension .exe", "decision": "arr_fail",
                  "policy": {"severity": "critical"},
                  "findings": [{"reason": "extension_match"}]}
        row = build([torrent(A)], actions=[action])["rows"][0]
        self.assertEqual(row["finding"]["file"], "setup.exe")
        self.assertEqual(row["finding"]["severity"], "critical")
        self.assertEqual(row["finding"]["count"], 1)


class TestTheSnapshotHeader(unittest.TestCase):

    def test_it_records_when_the_torrent_list_was_read(self):
        self.assertEqual(build([])["taken_at"], 1000.0)

    def test_it_records_which_queues_could_not_be_read(self):
        snap = build([], ownership_known=False, unreadable=["Radarr", "Sonarr"])
        self.assertFalse(snap["ownership_known"])
        self.assertEqual(snap["unreadable"], ["Radarr", "Sonarr"])

    def test_it_records_the_safety_mode_and_dry_run(self):
        snap = build([])
        self.assertEqual(snap["safety_mode"], "either")
        self.assertTrue(snap["dry_run"])

    def test_age_is_measured_from_the_torrent_list_read(self):
        snap = build([])
        self.assertEqual(snapshot.age(snap, now=1090.0), 90.0)

    def test_age_never_goes_negative_on_a_clock_change(self):
        self.assertEqual(snapshot.age(build([]), now=500.0), 0.0)

    def test_age_of_nothing_is_none_rather_than_zero(self):
        self.assertIsNone(snapshot.age(None))


class TestPublication(unittest.TestCase):

    def test_no_snapshot_before_the_first_pass(self):
        """Not an empty list. "Protectarr has not finished a pass yet" and
        "nothing is downloading" are different things."""
        self.assertIsNone(snapshot.published({}))

    def test_publishing_replaces_the_whole_snapshot_in_one_rebind(self):
        state = {}
        first = build([torrent(A)])
        snapshot.publish(state, first)
        self.assertIs(snapshot.published(state), first)
        second = build([torrent(B)])
        snapshot.publish(state, second)
        self.assertIs(snapshot.published(state), second)

    def test_the_previous_snapshot_is_not_mutated_by_the_next(self):
        """A request thread rendering the old one keeps a coherent view."""
        state = {}
        first = build([torrent(A)])
        snapshot.publish(state, first)
        held = snapshot.published(state)
        snapshot.publish(state, build([torrent(B), torrent(C)]))
        self.assertEqual([r["hash"] for r in held["rows"]], [A])


class TestProfileResolutionReportsItsSource(unittest.TestCase):

    def test_the_builtin_default_says_so(self):
        row = build([torrent(A)])["rows"][0]
        self.assertEqual(row["profile"], "media")
        self.assertEqual(row["profile_source"], "builtin")

    def test_a_configured_default_is_distinguished_from_the_builtin(self):
        cfg = dict(CFG, detection={"profile": "media"})
        row = build([torrent(A)], cfg=cfg)["rows"][0]
        self.assertEqual(row["profile_source"], "default")

    def test_a_category_mapping_wins_over_the_default(self):
        cfg = dict(CFG, detection={"profile": "media"},
                   safety=dict(CFG["safety"],
                               category_profiles={"tv": "software"}))
        row = build([torrent(A)], cfg=cfg)["rows"][0]
        self.assertEqual(row["profile"], "software")
        self.assertEqual(row["profile_source"], "category")

    def test_an_application_setting_wins_over_everything(self):
        client = FakeArr("Sonarr", [A])
        cfg = dict(CFG, detection={"profile": "media"},
                   safety=dict(CFG["safety"],
                               category_profiles={"tv": "software"}))
        row = build([torrent(A)], cfg=cfg,
                    owner={A: (client, {})},
                    arr_by_name={"Sonarr": {"profile": "custom"}})["rows"][0]
        self.assertEqual(row["profile"], "custom")
        self.assertEqual(row["profile_source"], "application")

    def test_the_name_only_helper_still_agrees(self):
        """`policy.resolve` is now a projection and must not have drifted."""
        from protectarr import policy
        for arr_entry in ({}, {"profile": "x"}):
            for category in ("", "tv"):
                self.assertEqual(
                    policy.resolve(CFG, arr_entry, category),
                    policy.resolve_with_source(CFG, arr_entry, category)[0])


class TestOwnerTypeComesFromThisPass(unittest.TestCase):

    def test_a_live_claim_reports_the_application_type(self):
        client = FakeArr("Radarr", [A], arr_type="radarr")
        own = ownership.Ownership(ownership.OWNED, "Radarr", client, {}, None,
                                  "claimed")
        row = build([torrent(A)], resolved={A: own},
                    owner={A: (client, {})})["rows"][0]
        self.assertEqual(row["owner_type"], "radarr")

    def test_an_orphan_has_no_live_claim_so_no_type_is_asserted(self):
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  120, "absent")
        row = build([torrent(A)], resolved={A: own})["rows"][0]
        self.assertEqual(row["owner"], "Sonarr")
        self.assertIsNone(row["owner_type"])


class TestProbeReporting(unittest.TestCase):

    def test_a_disabled_probe_says_so_rather_than_looking_idle(self):
        row = build([torrent(A)], probe_on=False)["rows"][0]
        self.assertFalse(row["probe"]["enabled"])
        self.assertFalse(row["probe"]["steered"])

    def test_a_steered_torrent_is_reported_as_steered(self):
        row = build([torrent(A)], probe_on=True,
                    steered={A: {"opened": "2026-09-17 10:00:00 +0000"}},
                    )["rows"][0]
        self.assertTrue(row["probe"]["steered"])
        self.assertEqual(row["probe"]["opened"], "2026-09-17 10:00:00 +0000")

    def test_a_candidate_is_distinguished_from_a_steered_torrent(self):
        row = build([torrent(A)], probe_on=True, candidates=[A])["rows"][0]
        self.assertTrue(row["probe"]["candidate"])
        self.assertFalse(row["probe"]["steered"])


class TestRemediationReporting(unittest.TestCase):

    INTENT = {"milestone": "failed_unverified", "remediation_id": "r1",
              "opened": 500.0, "arr": "Sonarr", "error": "no history event",
              "queue_id": 7, "watermark": 991, "attempts": 3,
              "search": {"command_id": 12, "state": "completed",
                         "result": "successful", "message": "0 reports"}}

    def row(self):
        return build([torrent(A)],
                     intents_by_hash={A: self.INTENT})["rows"][0]

    def test_the_milestone_and_error_are_carried(self):
        rem = self.row()["remediation"]
        self.assertEqual(rem["milestone"], "failed_unverified")
        self.assertEqual(rem["error"], "no history event")
        self.assertEqual(rem["remediation_id"], "r1")

    def test_the_search_outcome_is_carried(self):
        rem = self.row()["remediation"]
        self.assertEqual(rem["search_state"], "completed")
        self.assertEqual(rem["search_message"], "0 reports")

    def test_recovery_state_is_not_leaked_onto_the_page(self):
        """Queue ids, watermarks and attempt counters are how a remediation is
        resumed. They age into noise and belong nowhere near an operator."""
        rem = self.row()["remediation"]
        for leaked in ("queue_id", "watermark", "attempts"):
            self.assertNotIn(leaked, rem)

    def test_a_torrent_with_no_intent_carries_none(self):
        self.assertIsNone(build([torrent(A)])["rows"][0]["remediation"])


class ScanCase(unittest.TestCase):
    """Drives a whole `core.scan` against a fake qBittorrent."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        ownership._store.reset()
        self.state = {}
        self.torrents = [torrent(A)]
        self.fail_list = False
        case = self

        class FakeQb:
            def login(self):
                pass

            def torrents(self, category=None, state_filter=None):
                if case.fail_list:
                    raise requests.RequestException("qBittorrent is down")
                return list(case.torrents)

            def files(self, h):
                return [{"name": "movie.mkv", "size": 10}]

        self.real = core.QbitClient
        core.QbitClient = lambda *a, **k: FakeQb()
        self.addCleanup(setattr, core, "QbitClient", self.real)

    def cfg(self, **over):
        c = {"qbittorrent": {"url": "http://x"},
             "detection": {"only_active": True, "blocked_extensions": [".exe"]},
             "safety": {"mode": "either", "allowed_categories": ["tv"],
                        "orphan_dwell_minutes": 10},
             "arrs": [], "dry_run": True}
        c.update(over)
        return c

    def scan(self, **kw):
        return core.scan(self.cfg(), self.state, **kw)


class TestScanPublishesASnapshot(ScanCase):

    def test_a_pass_publishes_one(self):
        self.scan()
        snap = snapshot.published(self.state)
        self.assertIsNotNone(snap)
        self.assertEqual([r["hash"] for r in snap["rows"]], [A])

    def test_the_timestamp_is_the_torrent_list_read_not_the_pass_end(self):
        """A probe lane can hold a pass for its full budget. Stamping at the
        end would make a two-minute-old list claim to be current, so the two
        moments are pulled apart here far enough to tell them apart.
        """
        read_at = []
        real_files = core.QbitClient

        class Slow:
            def login(self):
                pass

            def torrents(self, category=None, state_filter=None):
                read_at.append(time.time())
                return [torrent(A)]

            def files(self, h):
                time.sleep(0.25)          # stands in for the probe lane
                return [{"name": "movie.mkv", "size": 10}]

        core.QbitClient = lambda *a, **k: Slow()
        try:
            self.scan()
        finally:
            core.QbitClient = real_files

        taken = snapshot.published(self.state)["taken_at"]
        finished = time.time()
        self.assertAlmostEqual(taken, read_at[0], delta=0.05)
        self.assertGreater(finished - taken, 0.2,
                           "the pass was not slow enough to tell the two "
                           "moments apart")

    def test_a_second_pass_replaces_the_first(self):
        self.scan()
        self.torrents = [torrent(B), torrent(C)]
        self.scan()
        self.assertEqual(
            [r["hash"] for r in snapshot.published(self.state)["rows"]],
            [B, C])

    def test_a_pass_that_finds_nothing_publishes_an_empty_list_not_nothing(self):
        """An empty qBittorrent is a fact, and different from never having
        scanned."""
        self.torrents = []
        self.scan()
        snap = snapshot.published(self.state)
        self.assertIsNotNone(snap)
        self.assertEqual(snap["rows"], [])


class TestAnUnreadableQueueReachesTheSnapshot(ScanCase):
    """The page has to be able to say *why* it is not sure who owns things.

    `ownership_known` is what suppresses direct deletion for the whole pass,
    and the named instances are what an operator goes and fixes. Both are
    established inside `scan` and were previously discarded with it.
    """

    def with_arrs(self, *clients):
        real = core.build_clients
        core.build_clients = lambda cfg: list(clients)
        self.addCleanup(setattr, core, "build_clients", real)

    def test_a_broken_queue_is_named_in_the_snapshot(self):
        self.with_arrs(FakeArr("Sonarr", [A], broken=True),
                       FakeArr("Radarr", []))
        self.scan()
        snap = snapshot.published(self.state)
        self.assertEqual(snap["unreadable"], ["Sonarr"])

    def test_ownership_known_is_false_when_a_queue_could_not_be_read(self):
        self.with_arrs(FakeArr("Sonarr", [A], broken=True))
        self.scan()
        self.assertFalse(snapshot.published(self.state)["ownership_known"])

    def test_ownership_known_is_true_when_every_queue_answered(self):
        self.with_arrs(FakeArr("Sonarr", [A]), FakeArr("Radarr", []))
        self.scan()
        snap = snapshot.published(self.state)
        self.assertTrue(snap["ownership_known"])
        self.assertEqual(snap["unreadable"], [])

    def test_the_rows_say_what_that_cost_them(self):
        """In `either` mode an unreadable queue is what stops a direct
        deletion, and the row names that rather than blaming the allowlist."""
        self.with_arrs(FakeArr("Sonarr", [], broken=True))
        self.scan()
        row = snapshot.published(self.state)["rows"][0]
        self.assertEqual(row["policy_state"], core.NOT_COVERED)
        self.assertEqual(row["policy_reason"], "ownership_unknown")


class TestAFailedPassPreservesTheLastGoodSnapshot(ScanCase):
    """Acceptance test: an outage must never look like an empty library."""

    def test_the_previous_snapshot_survives(self):
        self.scan()
        good = snapshot.published(self.state)
        self.fail_list = True
        with self.assertRaises(requests.RequestException):
            self.scan()
        self.assertIs(snapshot.published(self.state), good)
        self.assertEqual([r["hash"] for r in good["rows"]], [A])

    def test_nothing_is_published_if_the_very_first_pass_fails(self):
        self.fail_list = True
        with self.assertRaises(requests.RequestException):
            self.scan()
        self.assertIsNone(snapshot.published(self.state))

    def test_its_age_is_what_marks_it_stale(self):
        self.scan()
        snap = snapshot.published(self.state)
        self.assertGreater(snapshot.age(snap, now=snap["taken_at"] + 300), 299)


class TestPreviewDoesNotPublish(ScanCase):
    """An observational pass runs the probe lane without steering, so its view
    of what is steered is not the live one."""

    def test_an_observational_pass_leaves_the_snapshot_alone(self):
        self.scan()
        good = snapshot.published(self.state)
        self.torrents = [torrent(B)]
        self.scan(side_effects=False)
        self.assertIs(snapshot.published(self.state), good)

    def test_an_observational_first_pass_publishes_nothing(self):
        self.scan(side_effects=False)
        self.assertIsNone(snapshot.published(self.state))


class TestSnapshotFailureNeverBreaksAScan(ScanCase):
    """It is a view. A scan protects downloads."""

    def test_a_broken_projection_is_logged_and_swallowed(self):
        real = snapshot.build
        snapshot.build = lambda *a, **k: 1 / 0
        try:
            actions = self.scan()
        finally:
            snapshot.build = real
        self.assertEqual(actions, [])
        self.assertIsNone(snapshot.published(self.state))


class TestTagsAreSplitOnce(unittest.TestCase):

    def test_tags_become_a_list(self):
        row = build([torrent(A, tags="tv, keep ,")])["rows"][0]
        self.assertEqual(row["tags"], ["tv", "keep"])

    def test_no_tags_is_an_empty_list_not_a_blank_entry(self):
        self.assertEqual(build([torrent(A, tags="")])["rows"][0]["tags"], [])


if __name__ == "__main__":
    unittest.main()
