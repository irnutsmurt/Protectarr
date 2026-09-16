"""Swarm Observations: evidence that says what it actually knows.

The thing being defended against here is a data model that quietly asserts
"IP observed in a fake == bad IP". The old harvest ledger did exactly that: it
recorded peers before the removal was attempted, kept no outcome, and the page
described them as "peers seen sharing confirmed fakes" whether or not the
remediation had succeeded, failed, or never been attempted at all.

So the tests below care less about storage mechanics than about which claims
survive a round trip. An encounter that failed must not read as one that
worked; a migrated row must not acquire an outcome it never had; and a count
that is known to be incomplete must not print as though it were exact.

Structure over prose, for the same reason test_audit.py says so: every page
extends base.html, so asserting that a word appears somewhere in the response
passes on every route in the application.

Run with:  python -m unittest discover -s tests
"""

import os
import re
import sys
import json
import time
import sqlite3
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, evidence, events, intents, web  # noqa: E402

# Imported at module scope, not inside setUp. test_intents sets CONFIG_PATH as
# a side effect of being imported, so a lazy import would fire partway through
# whichever test touched it first and point that test at a different store.
from test_intents import (FakeArr, FakeQb, HASH, VERIFIED,  # noqa: E402
                          UNVERIFIED, action, conf, queue_record)

HASH2 = "aa11bb22cc33dd44ee55ff6677889900aabbccdd"


# RFC 5737 documentation ranges. This is a public repository and these tests
# are about peers in fake torrents, so the addresses in them must not be real
# hosts that could be read as an accusation.
def peers(*ips, progress=0.5, client="qBittorrent/5.2.3"):
    return [{"ip": ip, "port": 6881 + i, "client": client,
             "progress": progress, "flags": "D U", "country": "Germany",
             "connection": "BT"} for i, ip in enumerate(ips)]


class EvidenceCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        evidence.reset()
        intents._store.reset()

    def meta(self, **over):
        m = {"infohash": HASH, "release_title": "Rel", "trigger_file": "x.exe",
             "source": evidence.ARR, "finding": "extension match: x.exe",
             "severity": "decisive", "indexer": "Nyaa", "arr_instance": "Sonarr"}
        m.update(over)
        return m

    def db(self):
        return sqlite3.connect(evidence.path())

    def legacy(self, ledger):
        with open(os.path.join(self.dir, "harvest.json"), "w") as fh:
            json.dump(ledger, fh)


class TestEncounterIdentity(EvidenceCase):
    """One harvest pass is one encounter, and it has its own durable id."""

    def test_each_pass_is_a_separate_encounter(self):
        a = evidence.record_encounter(peers("192.0.2.1"), self.meta())
        b = evidence.record_encounter(peers("192.0.2.1"), self.meta())
        self.assertTrue(a and b)
        self.assertNotEqual(a, b)

    def test_the_same_infohash_reaped_twice_does_not_collapse(self):
        """The case the old ledger lost, and the reason encounters exist.

        A release can be reaped, re-grabbed as its own replacement and reaped
        again under one infohash. The old `torrents[hash] = tinfo` overwrote
        the first sighting; here both must survive as distinct encounters.
        """
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        p = evidence.profile("192.0.2.1")
        self.assertEqual(p["encounters"], 2)
        self.assertEqual(p["distinct_torrents"], 1)
        self.assertEqual(len(p["history"]), 2)

    def test_distinct_torrents_counts_infohashes_not_encounters(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.record_encounter(peers("192.0.2.1"), self.meta(infohash=HASH2))
        p = evidence.profile("192.0.2.1")
        self.assertEqual(p["encounters"], 3)
        self.assertEqual(p["distinct_torrents"], 2)

    def test_remediation_id_is_not_reused_as_the_encounter_id(self):
        enc = evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.attach_remediation(enc, "rem-123")
        row = self.db().execute(
            "SELECT encounter_id, remediation_id FROM encounters").fetchone()
        self.assertEqual(row[0], enc)
        self.assertEqual(row[1], "rem-123")
        self.assertNotEqual(row[0], row[1])

    def test_a_qbit_fallback_encounter_has_no_remediation(self):
        """No *arr owns it, so there is no lifecycle and the column stays NULL.

        `remediation_id` keeps its strict meaning. Giving one to a category
        fallback would make "has a remediation_id" stop meaning "has a
        remediation", which is the whole reason a separate id exists.
        """
        enc = evidence.record_encounter(peers("192.0.2.1"),
                                        self.meta(source=evidence.QBIT))
        row = self.db().execute(
            "SELECT source, remediation_id FROM encounters").fetchone()
        self.assertEqual(row[0], evidence.QBIT)
        self.assertIsNone(row[1])

    def test_an_empty_swarm_is_not_persisted(self):
        self.assertIsNone(evidence.record_encounter([], self.meta()))
        self.assertEqual(evidence.counts()["encounters"], 0)

    def test_a_peer_seen_twice_in_one_pass_is_one_observation(self):
        evidence.record_encounter(peers("192.0.2.1") + peers("192.0.2.1"),
                                  self.meta())
        self.assertEqual(evidence.counts()["observations"], 1)


class TestOutcomeIsNeverAssumed(EvidenceCase):
    """The claim lives on the encounter, and starts out absent."""

    def test_a_fresh_encounter_has_no_outcome(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        self.assertIsNone(evidence.profile("192.0.2.1")["history"][0]["outcome"])

    def test_unknown_outcome_renders_as_outcome_unknown(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        self.assertEqual(web._outcome(None), ("Outcome Unknown", "off"))
        detail = web._swarm_detail(evidence.profile("192.0.2.1"))
        self.assertEqual(detail["history"][0]["outcome_label"],
                         "Outcome Unknown")

    def test_outcome_unknown_reuses_an_existing_pill_class(self):
        """No new CSS class for it, per the approved UX review."""
        css = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "protectarr", "static",
            "style.css")).read()
        _, cls = web._outcome(None)
        self.assertIn(f".pill.{cls}", css)

    def test_a_failed_remediation_does_not_read_as_a_successful_one(self):
        enc = evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.set_outcome(enc, "failed_unverified", "could not prove it")
        detail = web._swarm_detail(evidence.profile("192.0.2.1"))
        self.assertEqual(detail["history"][0]["outcome_label"],
                         "Failed Unverified")
        self.assertEqual(detail["history"][0]["outcome_class"], "bad")

    def test_failed_unverified_wording_matches_history(self):
        """Same fact, same words. Two vocabularies for one milestone drift."""
        self.assertEqual(web._outcome("failed_unverified")[0],
                         web._MILESTONES["failed_unverified"][0])
        self.assertEqual(web._outcome("settled")[0],
                         web._MILESTONES["settled"][0])

    def test_setting_an_outcome_does_not_touch_the_observations(self):
        enc = evidence.record_encounter(peers("192.0.2.1", "192.0.2.2"),
                                        self.meta())
        before = evidence.counts()
        evidence.set_outcome(enc, "settled")
        self.assertEqual(evidence.counts(), before)


class TestLivePathWiring(EvidenceCase):
    """What core.apply_actions actually records around a real reap."""

    def act(self, decision="arr_fail", client=None, swarm=("203.0.113.9",), **over):
        a = action(decision=decision, client=client)
        a["_qb"] = type("Qb", (), {
            "peers": lambda self, h: peers(*swarm),
            "delete": lambda self, h, delete_files=False: None})()
        cfg = conf(harvest={"enabled": True}, **over)
        core.apply_actions([a], {"stats": core.load_stats()}, cfg)
        return a

    def test_a_verified_reap_links_the_encounter_to_its_remediation(self):
        arr = FakeArr(queue={HASH: queue_record()})
        self.act(client=arr)
        row = self.db().execute(
            "SELECT remediation_id, outcome FROM encounters").fetchone()
        self.assertEqual(row[0], intents.get(HASH)["remediation_id"])
        self.assertEqual(row[1], intents.get(HASH)["milestone"])

    def test_the_encounter_id_is_carried_on_the_intent(self):
        """So a reconcile after a restart can still find the encounter."""
        arr = FakeArr(queue={HASH: queue_record()})
        self.act(client=arr)
        enc = self.db().execute("SELECT encounter_id FROM encounters").fetchone()
        self.assertEqual(intents.get(HASH)["encounter_id"], enc[0])

    def test_an_unverified_remediation_is_recorded_as_such(self):
        arr = FakeArr(evidence=UNVERIFIED, queue={HASH: queue_record()})
        self.act(client=arr)
        outcome = self.db().execute(
            "SELECT outcome FROM encounters").fetchone()[0]
        self.assertEqual(outcome, "failed_unverified")
        self.assertEqual(web._outcome(outcome)[0], "Failed Unverified")

    def test_the_category_fallback_records_an_outcome_of_its_own(self):
        self.act(decision="qbit_delete")
        row = self.db().execute(
            "SELECT source, remediation_id, outcome FROM encounters").fetchone()
        self.assertEqual(row[0], evidence.QBIT)
        self.assertIsNone(row[1])
        self.assertEqual(row[2], "deleted_no_arr")

    def test_a_dry_run_records_no_evidence(self):
        """Nothing was removed, so no swarm was taken from anywhere."""
        self.act(client=FakeArr(queue={HASH: queue_record()}), dry_run=True)
        self.assertEqual(evidence.counts()["encounters"], 0)

    def test_harvest_disabled_records_no_evidence(self):
        a = action(client=FakeArr(queue={HASH: queue_record()}))
        a["_qb"] = type("Qb", (), {"peers": lambda self, h: peers("203.0.113.9"),
                                   "delete": lambda self, h, **k: None})()
        core.apply_actions([a], {"stats": core.load_stats()},
                           conf(harvest={"enabled": False}))
        self.assertEqual(evidence.counts()["encounters"], 0)

    def test_evidence_failure_does_not_block_the_reap(self):
        """The security action outranks the audit trail of it.

        A store that cannot be written must cost the observation, never the
        removal. This is the one failure mode where being quiet is correct, so
        the counter in health() is what makes the loss visible.
        """
        arr = FakeArr(queue={HASH: queue_record()})
        real = evidence.record_encounter
        evidence.record_encounter = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("disk on fire"))
        try:
            self.act(client=arr)
        finally:
            evidence.record_encounter = real
        self.assertEqual(arr.deletes, [42])           # the reap still happened
        self.assertEqual(events.read()[0]["action"]["result"], "reaped")

    def test_a_peer_read_failure_does_not_block_the_reap(self):
        arr = FakeArr(queue={HASH: queue_record()})
        a = action(client=arr)
        a["_qb"] = type("Qb", (), {
            "peers": lambda self, h: (_ for _ in ()).throw(
                RuntimeError("qBittorrent went away")),
            "delete": lambda self, h, **k: None})()
        core.apply_actions([a], {"stats": core.load_stats()},
                           conf(harvest={"enabled": True}))
        self.assertEqual(arr.deletes, [42])
        self.assertEqual(evidence.counts()["encounters"], 0)


class TestDurability(EvidenceCase):
    """PR2's standard: quarantine, never a silent reset."""

    def test_the_database_runs_in_wal_mode(self):
        evidence.init()
        mode = self.db().execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

    def test_a_corrupt_database_is_quarantined_not_replaced(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.reset()
        with open(evidence.path(), "wb") as fh:
            fh.write(b"this is not a database, it is a ransom note")
        self.assertFalse(evidence.init())
        self.assertTrue(evidence.broken())
        kept = [f for f in os.listdir(self.dir) if ".corrupt-" in f]
        self.assertTrue(kept, "the corrupt file must be kept for diagnosis")

    def test_quarantine_takes_the_wal_and_shm_with_it(self):
        """A WAL left behind belongs to a database that no longer exists.

        SQLite would replay it into whatever file appears under that name next,
        which is how "quarantined" turns into "corrupted something else".

        Driven through `_quarantine` directly rather than through a corrupt
        file, because SQLite deletes an unreadable WAL itself while failing to
        open it. Going the indirect route asserts nothing about this loop: it
        passes whether or not the sidecars are handled at all, which is exactly
        what the mutation run showed.
        """
        evidence.init()
        for suffix in ("-wal", "-shm"):
            with open(evidence.path() + suffix, "wb") as fh:
                fh.write(b"stale")
        evidence._quarantine("test")
        left = [f for f in os.listdir(self.dir)
                if f.startswith("evidence.db-")]
        self.assertEqual(left, [], f"stale sidecars left behind: {left}")
        kept = sorted(f for f in os.listdir(self.dir) if ".corrupt-" in f)
        self.assertEqual(len(kept), 3, f"sidecars were not kept: {kept}")

    def test_a_corrupt_file_leaves_no_sidecars_behind(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.reset()
        for suffix in ("-wal", "-shm"):
            with open(evidence.path() + suffix, "wb") as fh:
                fh.write(b"stale")
        with open(evidence.path(), "wb") as fh:
            fh.write(b"not a database")
        evidence.init()
        left = [f for f in os.listdir(self.dir)
                if f.startswith("evidence.db-")]
        self.assertEqual(left, [], f"stale sidecars left behind: {left}")

    def test_a_broken_store_never_reports_itself_as_empty(self):
        """The bug this module was written to remove.

        `harvest.load()` returned {} on a parse error, the page rendered "no
        peers harvested yet", and the next write overwrote the evidence. An
        unreadable store has to be distinguishable from an empty one.
        """
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.reset()
        with open(evidence.path(), "wb") as fh:
            fh.write(b"corrupt")
        evidence.init()
        self.assertIsNone(evidence.observations())     # not []
        self.assertTrue(evidence.broken())

    def test_a_broken_store_does_not_get_overwritten_by_the_next_write(self):
        """The corrupt bytes survive, and nothing takes their place.

        Quarantine moves the file aside, so the original path is *expected* to
        be gone. What must not happen is a fresh database appearing there and
        the write succeeding into it, which is how the evidence would be lost
        while everything carried on looking healthy.
        """
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.reset()
        with open(evidence.path(), "wb") as fh:
            fh.write(b"corrupt")
        evidence.init()
        self.assertIsNone(evidence.record_encounter(peers("192.0.2.2"),
                                                    self.meta()))
        self.assertFalse(os.path.exists(evidence.path()),
                         "a new database was created over the quarantine")
        kept = [f for f in os.listdir(self.dir) if ".corrupt-" in f]
        self.assertEqual(len(kept), 1)
        with open(os.path.join(self.dir, kept[0]), "rb") as fh:
            self.assertEqual(fh.read(), b"corrupt")

    def test_failures_are_counted_for_the_system_page(self):
        evidence.init()
        evidence._fail("could not write", RuntimeError("nope"))
        h = evidence.health()
        self.assertEqual(h["failures"], 1)
        self.assertIn("could not write", h["last_failure"])


class TestMigration(EvidenceCase):
    """Preserve what was recorded. Invent nothing that was not."""

    LEDGER = {"ips": {
        # Two passes over one hash: three IPs were in both, and the old ledger
        # kept only the later `last` for them. This is the real shape measured
        # from the live ledger, reduced.
        "192.0.2.1": {"first_seen": "2026-09-12 17:58:03 -0700",
                    "last_seen": "2026-09-12 18:09:06 -0700", "hits": 2,
                    "seed_hits": 0, "max_progress": 0,
                    "torrents": {HASH: {"name": "Rel", "ext": "x.exe",
                                        "indexer": "Nyaa", "app": "Radarr",
                                        "last": "2026-09-12 18:09:06 -0700"}},
                    "clients": [], "ports": [], "countries": []},
        "192.0.2.2": {"first_seen": "2026-09-12 17:58:03 -0700",
                    "last_seen": "2026-09-12 17:58:03 -0700", "hits": 1,
                    "seed_hits": 0, "max_progress": 0,
                    "torrents": {HASH: {"name": "Rel", "ext": "x.exe",
                                        "indexer": "Nyaa", "app": "Radarr",
                                        "last": "2026-09-12 17:58:03 -0700"}},
                    "clients": [], "ports": [], "countries": []},
    }}

    def test_distinct_last_values_become_distinct_encounters(self):
        """`record()` stamped one `now` per pass onto every IP it touched.

        So an identical `last` means one pass and a differing `last` for the
        same hash means separate passes. Keying on the hash alone would merge
        them and under-report the encounter count.
        """
        self.legacy(self.LEDGER)
        out = evidence.migrate_legacy()
        self.assertEqual(out["encounters"], 2)
        self.assertEqual(out["observations"], 2)

    def test_migrated_rows_have_no_outcome(self):
        self.legacy(self.LEDGER)
        evidence.migrate_legacy()
        outcomes = [r[0] for r in
                    self.db().execute("SELECT outcome FROM encounters")]
        self.assertEqual(outcomes, [None, None])

    def test_unattributable_sightings_are_counted_not_placed(self):
        """192.0.2.1 has hits=2 but one placeable pair. The extra is not invented.

        It is logically placeable in this one case, but the rule that makes it
        so only holds when the IP has exactly one infohash, and writing a row
        we cannot always justify is how a lower bound turns into a false fact.
        """
        self.legacy(self.LEDGER)
        evidence.migrate_legacy()
        p = evidence.profile("192.0.2.1")
        self.assertEqual(p["legacy_unattributed"], 1)
        self.assertEqual(len(p["history"]), 1)
        self.assertTrue(p["encounters_lower_bound"])

    def test_a_lower_bound_count_renders_with_a_plus(self):
        self.legacy(self.LEDGER)
        evidence.migrate_legacy()
        rows = {r["ip"]: r for r in
                [web._swarm_view(x) for x in evidence.observations()]}
        self.assertEqual(rows["192.0.2.1"]["encounters_display"], "1+")
        self.assertEqual(rows["192.0.2.2"]["encounters_display"], "1")

    def test_the_finding_type_is_not_guessed(self):
        """The old ledger kept the filename but never which rule fired."""
        self.legacy(self.LEDGER)
        evidence.migrate_legacy()
        finding = evidence.profile("192.0.2.2")["history"][0]["finding"]
        self.assertIn("x.exe", finding)
        self.assertIn("not recorded", finding)

    def test_per_ip_aggregates_are_not_attributed_to_an_encounter(self):
        """`max_progress` and `clients` spanned every torrent, not one pass."""
        ledger = json.loads(json.dumps(self.LEDGER))
        ledger["ips"]["192.0.2.2"]["max_progress"] = 1.0
        ledger["ips"]["192.0.2.2"]["clients"] = ["qBittorrent/5.2.3"]
        self.legacy(ledger)
        evidence.migrate_legacy()
        row = evidence.profile("192.0.2.2")["history"][0]
        self.assertIsNone(row["progress"])
        self.assertIsNone(row["client"])
        self.assertTrue(evidence.profile("192.0.2.2")["ever_seeder"])

    def test_the_original_is_renamed_not_deleted(self):
        self.legacy(self.LEDGER)
        out = evidence.migrate_legacy()
        self.assertFalse(os.path.exists(os.path.join(self.dir, "harvest.json")))
        self.assertTrue(os.path.exists(out["kept"]))

    def test_migration_runs_once(self):
        self.legacy(self.LEDGER)
        self.assertTrue(evidence.migrate_legacy())
        self.legacy(self.LEDGER)                      # a stray copy reappears
        self.assertIsNone(evidence.migrate_legacy())
        self.assertEqual(evidence.counts()["encounters"], 2)

    def test_an_unreadable_ledger_is_not_marked_migrated(self):
        with open(os.path.join(self.dir, "harvest.json"), "w") as fh:
            fh.write("{not json")
        self.assertIsNone(evidence.migrate_legacy())
        done = self.db().execute(
            "SELECT value FROM meta WHERE key = 'legacy_migrated'").fetchone()
        self.assertIsNone(done)

    def test_an_unparseable_timestamp_does_not_become_now(self):
        """A fabricated recent date would then drive the retention rules."""
        ledger = json.loads(json.dumps(self.LEDGER))
        ledger["ips"]["192.0.2.2"]["torrents"][HASH]["last"] = "not a date"
        ledger["ips"]["192.0.2.2"]["last_seen"] = "also not a date"
        ledger["ips"]["192.0.2.2"]["first_seen"] = "still not a date"
        self.legacy(ledger)
        evidence.migrate_legacy()
        self.assertIsNone(evidence.profile("192.0.2.2")["history"][0]["observed_at"])


class TestRetention(EvidenceCase):
    """Detail expires. Recurrence evidence does not."""

    CFG = {"harvest": {"detail_encounters": 2, "single_profile_days": 90,
                       "recurring_profile_days": 365}}

    def test_detail_expires_beyond_the_newest_n_encounters(self):
        for i in range(4):
            evidence.record_encounter(peers(f"192.0.2.{i}"),
                                      self.meta(infohash=f"{i:040x}"))
        out = evidence.prune(self.CFG)
        self.assertEqual(out["details_expired"], 2)
        self.assertEqual(evidence.counts()["observations"], 2)

    def test_encounter_headers_survive_so_the_history_is_not_lost(self):
        for i in range(4):
            evidence.record_encounter(peers(f"192.0.2.{i}"),
                                      self.meta(infohash=f"{i:040x}"))
        evidence.prune(self.CFG)
        self.assertEqual(evidence.counts()["encounters"], 4)

    def test_recurrence_evidence_outlives_the_detail_behind_it(self):
        """The whole point of a durable profile rather than a rebuilt cache."""
        for i in range(4):
            evidence.record_encounter(peers("198.51.100.7"),
                                      self.meta(infohash=f"{i:040x}"))
        evidence.prune(self.CFG)
        p = evidence.profile("198.51.100.7")
        self.assertEqual(p["encounters"], 4)
        self.assertEqual(p["distinct_torrents"], 4)
        self.assertEqual(p["retained_details"], 2)

    def test_expired_detail_and_legacy_loss_are_reported_separately(self):
        """Two different losses, two different explanations.

        Retention expiring detail is a policy working. The legacy ledger
        overwriting a sighting is data destroyed before any policy existed.
        Calling both "pruned" blames the wrong one.
        """
        for i in range(4):
            evidence.record_encounter(peers("198.51.100.7"),
                                      self.meta(infohash=f"{i:040x}"))
        evidence.prune(self.CFG)
        d = web._swarm_detail(evidence.profile("198.51.100.7"))
        self.assertEqual(d["details_expired"], 2)
        self.assertEqual(d["legacy_unattributed"], 0)

    def test_single_sighting_profiles_expire_before_recurring_ones(self):
        old = time.time() - 200 * 86400
        evidence.record_encounter(peers("192.0.2.1"),
                                  self.meta(observed_at=old))
        for i in range(2):
            evidence.record_encounter(peers("192.0.2.2"),
                                      self.meta(infohash=f"{i:040x}",
                                                observed_at=old))
        out = evidence.prune(self.CFG)
        self.assertEqual(out["profiles_expired"], 1)
        self.assertIsNone(evidence.profile("192.0.2.1"))
        self.assertIsNotNone(evidence.profile("192.0.2.2"))

    def test_an_expired_profile_takes_its_rows_with_it(self):
        evidence.record_encounter(peers("192.0.2.1"),
                                  self.meta(observed_at=time.time() - 200 * 86400))
        evidence.prune(self.CFG)
        db = self.db()
        self.assertEqual(db.execute("SELECT COUNT(*) FROM peer_observations "
                                    "WHERE ip='192.0.2.1'").fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM ip_torrent "
                                    "WHERE ip='192.0.2.1'").fetchone()[0], 0)

    def test_recent_profiles_are_left_alone(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        out = evidence.prune(self.CFG)
        self.assertEqual(out["profiles_expired"], 0)
        self.assertIsNotNone(evidence.profile("192.0.2.1"))

    def test_retention_is_config_only(self):
        """No Settings UI for these in v0.5.0, by ruling."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Every Settings template, walked. This used to list one directory and
        # match names starting with "settings", which only ever caught
        # settings_index.html - the seven templates that actually held the
        # forms were never read. The cards live under templates/settings/ now,
        # so the walk is both the fix and what the test always meant.
        forms = ""
        tdir = os.path.join(root, "protectarr", "templates")
        for base, _, names in os.walk(tdir):
            for name in names:
                if name.startswith("settings") or "settings" in base:
                    with open(os.path.join(base, name)) as fh:
                        forms += fh.read()
        assert "blocked_extensions" in forms, "the settings sweep found no forms"
        for key in ("detail_encounters", "single_profile_days",
                    "recurring_profile_days"):
            self.assertNotIn(key, forms)

    def test_the_defaults_are_the_agreed_numbers(self):
        s = evidence.settings(cfg_mod.DEFAULTS)
        self.assertEqual(s["detail_encounters"], 2000)
        self.assertEqual(s["single_profile_days"], 90)
        self.assertEqual(s["recurring_profile_days"], 365)


class TestPageSemantics(EvidenceCase):
    """What the rendered page is allowed to claim."""

    def client(self):
        class Loose(dict):
            def __getattr__(self, k):
                return self.get(k)
        service = Loose(state=Loose(stats=Loose(reaped_total=0), running=False,
                                    last_scan=None, last_error=None,
                                    blocklist=Loose(), banned=Loose()))
        app = web.create_app(service)
        app.config["TESTING"] = True
        c = app.test_client()
        with c.session_transaction() as s:
            s["user"] = "test"
        return c

    def page(self):
        return self.client().get("/watchlist").data.decode()

    def test_the_table_exposes_both_counts(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        html = self.page()
        self.assertIn("<th style=\"text-align:right\">Encounters</th>", html)
        self.assertIn("<th style=\"text-align:right\">Distinct Torrents</th>",
                      html)

    def test_the_approved_column_set_is_what_renders(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        html = self.page()
        head = re.search(r"<thead>(.*?)</thead>", html, re.S).group(1)
        got = re.findall(r"<th[^>]*>(.*?)</th>", head, re.S)
        self.assertEqual([g.strip() for g in got],
                         ["IP Address", "Encounters", "Distinct Torrents",
                          "Latest Associated Finding", "Last Observed",
                          "Details"])

    def test_raw_connection_counts_are_not_in_the_table(self):
        """`hits` and `seed_hits` were the two most prominent old columns."""
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        head = re.search(r"<thead>(.*?)</thead>", self.page(), re.S).group(1)
        for word in ("Observations", "Hits", "Role", "Distinct fakes"):
            self.assertNotIn(word, head)

    def test_the_page_does_not_call_an_ip_malicious(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        html = self.page().lower()
        for word in ("malicious", "threat", "confidence", "reputation",
                     "attacker"):
            self.assertNotIn(word, html)

    def test_the_word_source_is_not_used_for_an_ip(self):
        """The old page said seeding IPs were "the likely sources"."""
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        body = re.search(r'<div class="card">(.*?)</div>\s*</div>',
                         self.page(), re.S).group(1)
        self.assertNotIn("source", body.lower())

    def test_a_broken_store_says_so_rather_than_showing_an_empty_table(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.reset()
        with open(evidence.path(), "wb") as fh:
            fh.write(b"corrupt")
        evidence.init()
        html = self.page()
        self.assertIn("could not be read", html)
        self.assertNotIn("No swarms observed yet", html)

    def test_the_remediation_outcome_column_is_labelled(self):
        """"Failed Unverified" describes the action, not the peer."""
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        self.assertIn("Remediation Outcome", self.page())

    def test_the_nav_is_renamed(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        html = self.page()
        self.assertIn('title="Swarm Observations"', html)
        self.assertNotIn("IP Watchlist", html)


class TestEncounterTableLayout(EvidenceCase):
    """The dialog's table, and the one rule that stops its header wrapping.

    Structural, not visual: the measured behaviour lives in the report, but the
    shape these assertions pin down is what the measurement depended on. The
    History table shipped a regression once by making a cell unbreakable
    without a scroll container around it, so the container is asserted too.
    """

    def setUp(self):
        super().setUp()
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tpl = open(os.path.join(root, "protectarr", "templates",
                                     "watchlist.html")).read()
        self.css = open(os.path.join(root, "protectarr", "static",
                                     "style.css")).read()

    def test_the_encounter_table_is_marked_for_the_header_rule(self):
        self.assertIn('table class="applist enc-table"', self.tpl)

    def test_the_nowrap_rule_is_scoped_to_header_cells(self):
        """thead only. Body cells must keep wrapping or Release cannot flex."""
        rule = re.search(r"\.enc-table\s+([^{]*)\{([^}]*)\}", self.css)
        self.assertIsNotNone(rule, "the enc-table rule is missing")
        self.assertEqual(rule.group(1).strip(), "thead th")
        self.assertIn("nowrap", rule.group(2))

    def test_nowrap_is_not_applied_to_the_whole_table(self):
        for bad in (".enc-table { white-space: nowrap",
                    ".enc-table td { white-space: nowrap",
                    ".enc-table tbody"):
            self.assertNotIn(bad, self.css)

    def test_the_table_sits_in_a_horizontal_scroll_container(self):
        """So an unbreakable header scrolls the dialog, never the page."""
        i = self.tpl.index('table class="applist enc-table"')
        self.assertIn('overflow-x:auto', self.tpl[max(0, i - 120):i])

    def test_the_release_cell_still_wraps(self):
        self.assertIn("word-break:break-word", self.tpl)

    def test_the_wide_modal_variant_is_opt_in(self):
        """A dialog has to ask for the width; 560px stays the default.

        History opted in too in 0.5.1, so this no longer checks that History
        is narrow - that would now be asserting the opposite of the design.
        What still has to hold is that `wide` is a separate class a dialog
        chooses, not something `.modal` grew: the Applications dialogs are
        key/value forms that 940px would only stretch.
        """
        self.assertIn('<div class="modal wide">', self.tpl)
        self.assertRegex(self.css, r"\.modal\s*\{[^}]*max-width:\s*560px")
        self.assertRegex(self.css, r"\.modal\.wide\s*\{[^}]*max-width")
        apps = open(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "protectarr", "templates", "applications.html")).read()
        self.assertIn('<div class="modal">', apps)


class TestRetentionNotices(EvidenceCase):
    """Wording for the two losses, including the nothing-left case."""

    def setUp(self):
        super().setUp()
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tpl = open(os.path.join(root, "protectarr", "templates",
                                     "watchlist.html")).read()
        self.notices = self._notices_source()

    def _notices_source(self):
        """The body of notices(), with comments and JS string joins removed.

        Asserting against the raw template does not work: the copy is built
        from adjacent string literals, so no sentence appears contiguously, and
        the surrounding comment explains the wording using the very words the
        wording must avoid.
        """
        i = self.tpl.index("function notices(")
        j = self.tpl.index("\nfunction ", i + 1)
        body = self.tpl[i:j]
        body = re.sub(r"//[^\n]*", "", body)          # drop line comments
        body = re.sub(r"'\s*\+\s*'", "", body)        # join split literals
        return re.sub(r"\s+", " ", body)

    def test_zero_retained_does_not_open_by_counting_nothing(self):
        self.assertIn("No detailed encounter records retained. Older details "
                      "have expired under the configured retention policy.",
                      self.notices)

    def test_the_some_retained_wording_is_still_there(self):
        self.assertIn("retained encounter detail", self.notices)
        self.assertIn("Older encounter details have expired under the "
                      "configured retention policy.", self.notices)

    def test_the_legacy_notice_is_a_separate_sentence(self):
        """Two losses, two causes. Neither is allowed to absorb the other."""
        self.assertIn("could not be attributed to a specific encounter.",
                      self.notices)
        # The legacy loss predates any retention policy, so blaming retention
        # for it would be wrong in exactly the way the wording exists to avoid.
        self.assertNotIn("prune", self.notices.lower())
        legacy = self.notices[self.notices.index("legacy_unattributed > 0"):]
        self.assertNotIn("retention", legacy.lower())

    def test_both_notices_can_apply_at_once(self):
        for i in range(3):
            evidence.record_encounter(peers("198.51.100.7"),
                                      self.meta(infohash=f"{i:040x}"))
        evidence.prune({"harvest": {"detail_encounters": 1,
                                    "single_profile_days": 3650,
                                    "recurring_profile_days": 3650}})
        with evidence._connect() as db:
            db.execute("UPDATE ip_profile SET legacy_unattributed = 2 "
                       "WHERE ip = ?", ("198.51.100.7",))
        d = web._swarm_detail(evidence.profile("198.51.100.7"))
        self.assertEqual(d["retained_details"], 1)
        self.assertEqual(d["details_expired"], 2)
        self.assertEqual(d["legacy_unattributed"], 2)


class TestApi(EvidenceCase):
    def client(self):
        return TestPageSemantics.client(self)

    def test_a_broken_store_is_a_503_not_an_empty_list(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.reset()
        with open(evidence.path(), "wb") as fh:
            fh.write(b"corrupt")
        evidence.init()
        r = self.client().get("/api/v1/watchlist")
        self.assertEqual(r.status_code, 503)

    def test_filters_are_offered_on_both_counts(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        c = self.client()
        self.assertEqual(len(c.get("/api/v1/watchlist?min_encounters=2").json), 1)
        self.assertEqual(len(c.get("/api/v1/watchlist?min_torrents=2").json), 0)

    def test_the_old_min_fakes_name_still_filters_on_torrents(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        r = self.client().get("/api/v1/watchlist?min_fakes=2")
        self.assertEqual(r.json, [])

    def test_a_single_ip_can_be_fetched(self):
        evidence.record_encounter(peers("192.0.2.1"), self.meta())
        r = self.client().get("/api/v1/watchlist?ip=192.0.2.1")
        self.assertEqual(r.json["ip"], "192.0.2.1")
        self.assertEqual(len(r.json["history"]), 1)


if __name__ == "__main__":
    unittest.main()
