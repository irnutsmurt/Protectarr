"""Remediation intents: the write-ahead record of an irreversible action.

The failure this file exists to prevent: Protectarr deletes a queue item with
`blocklist=true`, the process dies, and on the next start the queue item is
simply absent. Absent is what success looks like. Absent is also what "the
delete never happened" looks like, and what "someone removed it by hand" looks
like. Without a record written *before* the delete there is nothing that can
tell those apart, and the tempting move - assume it worked and search for a
replacement - is the one that asks the *arr to grab the fake again.

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

from protectarr import core, events, detectors, intents  # noqa: E402
from protectarr.arr import ARR_TYPES  # noqa: E402

HASH = "ffcff9e6cd9a5d4cad048ba041f987676fd8dca0"
VERIFIED = {"verified": True, "event": {"id": 101, "date": "2026-09-12T20:37:45Z",
                                        "source_title": "Rel", "message": "m"},
            "blocklist": {"id": 7, "date": "2026-09-12T20:37:45Z",
                          "indexer": "IX"},
            "why": "history event and blocklist row both found"}
UNVERIFIED = {"verified": False, "event": None, "blocklist": None,
              "why": "no downloadFailed event for this infohash"}


class FakeArr:
    """An *arr that records what was asked of it."""

    type = "sonarr"
    meta = ARR_TYPES["sonarr"]

    def __init__(self, name="Sonarr", evidence=None, delete="removed",
                 queue=None, command=("completed", "successful",
                                      "0 reports downloaded")):
        self.name = name
        self.evidence = evidence or VERIFIED
        self.delete = delete
        self._queue = queue or {}
        self._command = command
        self.deletes = []
        self.searches = []
        self.watermarks = 0

    def grab_indexer(self, download_id):
        return "LimeTorrents (Prowlarr)"

    def history_watermark(self):
        self.watermarks += 1
        return 100

    def fail(self, queue_id):
        self.deletes.append(queue_id)
        if isinstance(self.delete, Exception):
            raise self.delete
        return self.delete

    def verify_remediation(self, download_id, after_id=None, **kw):
        if callable(self.evidence):
            return self.evidence(download_id, after_id)
        return self.evidence

    def queue_by_hash(self):
        return dict(self._queue)

    def has_remediation_identity(self, record):
        return record.get(self.meta["search"][2]) is not None

    def search(self, record):
        self.searches.append(record)
        return 555

    def command_status(self, command_id):
        return self._command

    def airdate_status(self, record, grace=0):
        import datetime
        return True, datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)


class FakeQb:
    def peers(self, h):
        return []

    def delete(self, h, delete_files=False):
        pass


def queue_record():
    return {"id": 42, "title": "Rel", "episodeId": 16801,
            "downloadId": HASH.upper()}


def action(decision="arr_fail", client=None):
    f = detectors.finding("extension", "extension_match", filename="x.exe")
    return {"hash": HASH, "name": "Rel", "bad_file": "x.exe", "reason": "r",
            "finding": f, "findings": [f], "policy": {}, "size": 1,
            "category": "tv", "tags": "", "decision": decision,
            "safety_mode": "either", "arr": None,
            "_owner": (client, queue_record()) if client else None,
            "_qb": FakeQb()}


def conf(**over):
    c = {"dry_run": False, "harvest": {"enabled": False},
         "safety": {"requeue_after_airdate": True, "airdate_grace_hours": 0}}
    c.update(over)
    return c


class IntentCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        intents._store.reset()

    def reap(self, client, **over):
        core.apply_actions([action(client=client)], {"stats": core.load_stats()},
                           conf(**over))
        return events.read()[0]

    def intent(self):
        return intents.get(HASH)


class TestWriteAhead(IntentCase):
    """Nothing irreversible happens before the record of it is on disk."""

    def test_the_intent_is_written_before_the_delete(self):
        client = FakeArr()
        order = []
        original = intents.open_intent

        def spy(*a, **kw):
            order.append("intent")
            return original(*a, **kw)

        client_fail = client.fail

        def fail_spy(queue_id):
            order.append("delete")
            return client_fail(queue_id)

        client.fail = fail_spy
        intents.open_intent = spy
        try:
            self.reap(client)
        finally:
            intents.open_intent = original
        self.assertEqual(order, ["intent", "delete"])

    def test_an_unwritable_store_stops_the_delete(self):
        """The whole point. An action we cannot record is one we cannot finish."""
        os.mkdir(intents._store.path())      # a directory where the file goes
        client = FakeArr()
        ev = self.reap(client)
        self.assertEqual(client.deletes, [], "it deleted anyway")
        self.assertEqual(ev["action"]["result"], "failed")
        self.assertFalse(ev["action"]["removed"])

    def test_the_watermark_is_read_before_the_delete(self):
        """An event that already existed must not be able to satisfy us."""
        client = FakeArr()
        self.reap(client)
        self.assertEqual(client.watermarks, 1)
        self.assertEqual(self.intent()["watermark"], 100)

    def test_a_second_remediation_for_the_same_torrent_is_refused(self):
        client = FakeArr(evidence=UNVERIFIED)
        self.reap(client)
        self.assertEqual(self.intent()["milestone"], intents.FAILED_UNVERIFIED)

        before = len(events.read())
        again = FakeArr(evidence=UNVERIFIED)
        core.apply_actions([action(client=again)], {"stats": core.load_stats()},
                           conf())
        self.assertEqual(again.deletes, [],
                         "a torrent already being remediated was hit twice")
        # And it is skipped quietly. Without that, every 20-second scan would
        # file a fresh "failed" event for the same torrent forever, burying
        # the one that actually describes what went wrong.
        self.assertEqual(len(events.read()), before,
                         "the skip recorded an event instead of staying quiet")

    def test_the_store_itself_refuses_a_second_intent(self):
        """The inner of the two guards, tested without going through a scan.

        `apply_actions` skips these torrents so the log does not fill with
        refusals, but the refusal that matters is this one - it is the thing
        standing between a bug upstream and a second irreversible action.
        """
        client = FakeArr()
        for milestone in (intents.PENDING, intents.REMOVED,
                          intents.FAILED_UNVERIFIED):
            intents._store.mutate(
                lambda d, m=milestone: d.__setitem__(HASH, {"milestone": m}))
            self.assertFalse(
                intents.open_intent(HASH, client, queue_record()),
                f"a {milestone} intent was overwritten")

    def test_a_settled_torrent_may_be_remediated_again(self):
        """The same release can legitimately be grabbed and go bad twice."""
        client = FakeArr()
        intents._store.mutate(
            lambda d: d.__setitem__(HASH, {"milestone": intents.SETTLED}))
        self.assertTrue(intents.open_intent(HASH, client, queue_record()))

    def test_the_queue_record_is_not_persisted_wholesale(self):
        """Only what the oracle and a later search actually need."""
        self.reap(FakeArr())
        rec = self.intent()
        self.assertEqual(rec["media"], {"episodeId": 16801})
        self.assertNotIn("downloadId", rec)
        self.assertNotIn("statusMessages", rec)


class TestMilestones(IntentCase):
    def test_a_verified_removal_reaches_removed(self):
        client = FakeArr()
        ev = self.reap(client)
        self.assertTrue(ev["action"]["blocklisted"])
        self.assertEqual(ev["action"]["history_event"], 101)
        self.assertEqual(ev["action"]["blocklist_row"], 7)
        # A search was issued, so it is not settled until that search ends.
        self.assertEqual(self.intent()["milestone"], intents.REMOVED)
        self.assertEqual(self.intent()["search"]["command_id"], 555)

    def test_an_unverified_removal_reaches_failed_unverified(self):
        client = FakeArr(evidence=UNVERIFIED)
        ev = self.reap(client)
        self.assertFalse(ev["action"]["blocklisted"])
        self.assertEqual(self.intent()["milestone"], intents.FAILED_UNVERIFIED)

    def test_failed_unverified_never_searches(self):
        """Searching would invite the *arr to grab the same release again."""
        client = FakeArr(evidence=UNVERIFIED)
        ev = self.reap(client)
        self.assertEqual(client.searches, [], "it searched for a replacement")
        self.assertEqual(ev["redownload"]["decision"], "held")
        self.assertEqual(ev["redownload"]["reason"], "remediation_unverified")

    def test_holding_for_an_airdate_settles_immediately(self):
        """No search was issued, so there is no command to follow."""
        import datetime

        client = FakeArr()
        client.airdate_status = lambda rec, g: (
            False, datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
        self.reap(client)
        self.assertEqual(client.searches, [])
        self.assertEqual(self.intent()["milestone"], intents.SETTLED)

    def test_a_delete_that_reports_absent_is_recorded_as_such(self):
        client = FakeArr(delete="absent")
        ev = self.reap(client)
        self.assertEqual(ev["action"]["queue_delete"], "absent")
        # Absent proves nothing on its own; the oracle is what decided.
        self.assertTrue(ev["action"]["blocklisted"])


class TestCouldNotAskIsNotAVerdict(IntentCase):
    """An *arr that was briefly down is not evidence about a release.

    `verified: False` has two causes and they need opposite handling. "The
    history has no such event" is a finding. "We could not read the history" is
    an outage, and letting an outage produce failed_unverified would condemn a
    torrent for ten seconds of network trouble, permanently, since
    failed_unverified is deliberately terminal.
    """

    UNREACHABLE = {"verified": False, "reachable": False, "event": None,
                   "blocklist": None, "why": "could not read Sonarr's history"}

    def test_an_unreachable_arr_leaves_the_intent_pending(self):
        client = FakeArr(evidence=self.UNREACHABLE)
        self.reap(client)
        self.assertEqual(self.intent()["milestone"], intents.PENDING)

    def test_an_unreachable_arr_still_does_not_search(self):
        client = FakeArr(evidence=self.UNREACHABLE)
        ev = self.reap(client)
        self.assertEqual(client.searches, [])
        self.assertEqual(ev["redownload"]["reason"], "remediation_unverified")

    def test_a_pending_intent_can_still_be_resolved_later(self):
        """Which is exactly what failed_unverified would have prevented."""
        client = FakeArr(evidence=self.UNREACHABLE)
        self.reap(client)
        client.evidence = VERIFIED
        intents.reconcile([client])
        self.assertEqual(self.intent()["milestone"], intents.REMOVED)

    def test_a_real_absence_is_still_terminal(self):
        client = FakeArr(evidence=UNVERIFIED)
        self.reap(client)
        self.assertEqual(self.intent()["milestone"], intents.FAILED_UNVERIFIED)

    def test_a_read_failure_reaches_the_caller_as_unreachable(self):
        """Measured at the client, not just modelled in the fake."""
        from protectarr.arr import ArrClient

        real = ArrClient("Sonarr", "sonarr", "http://x", "test-api-key")

        def boom(url, params=None, timeout=None):
            raise requests.RequestException("connection refused")

        real._s.get = boom
        got = real.verify_remediation(HASH, retries=1)
        self.assertFalse(got["verified"])
        self.assertFalse(got["reachable"])


class TestRestartRecovery(IntentCase):
    """What a crash between the delete and the verification leaves behind."""

    def pending(self, **over):
        client = FakeArr()
        rec = {"milestone": intents.PENDING, "hash": HASH, "arr": "Sonarr",
               "arr_type": "sonarr", "queue_id": 42,
               "media": {"episodeId": 16801}, "release_title": "Rel",
               "indexer": "IX", "watermark": 100, "opened": time.time(),
               "updated": time.time(), "attempts": 0, "evidence": None,
               "search": None, "error": None}
        rec.update(over)
        intents._store.mutate(lambda d: d.__setitem__(HASH, rec))
        return client

    def test_a_pending_intent_the_oracle_confirms_becomes_removed(self):
        client = self.pending()
        out = intents.reconcile([client])
        self.assertEqual(out["removed"], 1)
        self.assertEqual(self.intent()["milestone"], intents.REMOVED)

    def test_a_queue_item_still_present_is_retried_not_written_off(self):
        client = self.pending()
        client.evidence = UNVERIFIED
        client._queue = {HASH: {"id": 77}}
        intents.reconcile([client])
        rec = self.intent()
        self.assertEqual(rec["milestone"], intents.PENDING)
        self.assertEqual(rec["attempts"], 1)
        self.assertEqual(rec["queue_id"], 77, "the queue id is refreshed")

    def test_gone_from_the_queue_and_unverified_is_failed_unverified(self):
        """A repeated DELETE would 404 here, and 404 proves nothing."""
        client = self.pending()
        client.evidence = UNVERIFIED
        out = intents.reconcile([client])
        self.assertEqual(out["unverified"], 1)
        rec = self.intent()
        self.assertEqual(rec["milestone"], intents.FAILED_UNVERIFIED)
        self.assertEqual(client.searches, [])

    def test_an_arr_that_raises_leaves_the_intent_alone(self):
        """"Could not look" is not "did not happen"."""
        client = self.pending()

        def boom(download_id, after_id=None, **kw):
            raise requests.RequestException("connection refused")

        client.verify_remediation = boom
        out = intents.reconcile([client])
        self.assertEqual(out["unreachable"], 1)
        self.assertEqual(self.intent()["milestone"], intents.PENDING)

    def test_an_unreachable_verdict_does_not_become_failed_unverified(self):
        """The oracle reporting `reachable: False` is the same non-answer.

        The queue is empty here, which is the shape that otherwise means
        "gone and unaccounted for". It must not mean that when the reason we
        cannot account for it is that we could not ask.
        """
        client = self.pending()
        client.evidence = {"verified": False, "reachable": False,
                           "event": None, "blocklist": None,
                           "why": "could not read Sonarr's history"}
        out = intents.reconcile([client])
        self.assertEqual(out["unverified"], 0)
        self.assertEqual(out["unreachable"], 1)
        self.assertEqual(self.intent()["milestone"], intents.PENDING)

    def test_an_arr_that_is_no_longer_configured_leaves_the_intent_alone(self):
        self.pending()
        out = intents.reconcile([])
        self.assertEqual(out["unreachable"], 1)
        self.assertEqual(self.intent()["milestone"], intents.PENDING)

    def test_a_settled_intent_is_not_reconciled_again(self):
        client = self.pending(milestone=intents.SETTLED)
        out = intents.reconcile([client])
        self.assertEqual(out["checked"], 0)


class TestSearchFollowUp(IntentCase):
    def test_the_command_id_survives_a_restart(self):
        client = FakeArr()
        self.reap(client)
        # A fresh process reads it back off disk.
        intents._store.reset()
        self.assertEqual(intents.get(HASH)["search"]["command_id"], 555)

    def test_a_terminal_search_settles_the_intent_even_with_nothing_found(self):
        """"0 reports downloaded" is a finished search, not a failed one."""
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        rec = self.intent()
        self.assertEqual(rec["milestone"], intents.SETTLED)
        self.assertEqual(rec["search"]["result"], "successful")
        self.assertEqual(rec["search"]["message"], "0 reports downloaded")

    def test_a_running_search_does_not_settle_the_intent(self):
        client = FakeArr()
        self.reap(client)
        client._command = ("started", None, None)
        intents.reconcile([client])
        self.assertEqual(self.intent()["milestone"], intents.REMOVED)

    def test_a_command_the_arr_has_forgotten_is_terminal(self):
        """Commands age out. Waiting for that one to finish waits forever."""
        client = FakeArr()
        self.reap(client)
        client._command = ("unknown", None, None)
        intents.reconcile([client])
        self.assertEqual(self.intent()["milestone"], intents.SETTLED)

    def test_an_unreadable_command_is_retried_rather_than_settled(self):
        client = FakeArr()
        self.reap(client)
        client._command = (None, None, None)
        intents.reconcile([client])
        self.assertEqual(self.intent()["milestone"], intents.REMOVED)


class TestStoreDurability(IntentCase):
    def test_a_corrupt_store_is_quarantined_not_overwritten(self):
        """The file is the only record that an irreversible action happened."""
        self.reap(FakeArr())
        path = intents._store.path()
        with open(path, "w") as fh:
            fh.write("{not json")
        intents._store.reset()

        self.assertEqual(intents.records(), {})
        self.assertIsNotNone(intents.broken())
        leftovers = [f for f in os.listdir(self.dir) if ".corrupt-" in f]
        self.assertEqual(len(leftovers), 1)

    def test_a_broken_store_stops_new_remediations(self):
        intents._store._broken = "under test"
        client = FakeArr()
        self.reap(client)
        self.assertEqual(client.deletes, [])

    def test_settled_records_age_out_but_unverified_ones_do_not(self):
        old = time.time() - intents.KEEP_SETTLED_DAYS * 86400 - 60

        def seed(d):
            d["a" * 40] = {"milestone": intents.SETTLED, "updated": old}
            d["b" * 40] = {"milestone": intents.FAILED_UNVERIFIED, "updated": old}
            d["c" * 40] = {"milestone": intents.PENDING, "updated": old}

        intents._store.mutate(seed)
        intents.update("c" * 40, error=None)        # any write triggers a prune
        left = intents.records()
        self.assertNotIn("a" * 40, left)
        self.assertIn("b" * 40, left, "an unverified remediation was hidden")
        self.assertIn("c" * 40, left)

    def test_the_size_cap_never_evicts_an_unfinished_remediation(self):
        """An unfinished intent is the only record that an action is in flight.

        Dropping one to keep the file small trades a large file for a torrent
        nobody can account for.
        """
        now = time.time()

        def seed(d):
            for i in range(intents.MAX_RECORDS + 50):
                d[f"{i:040d}"] = {"milestone": intents.SETTLED,
                                  "updated": now + i}
            d["f" * 40] = {"milestone": intents.PENDING, "updated": now - 10000}
            d["e" * 40] = {"milestone": intents.REMOVED, "updated": now - 10000}

        intents._store.mutate(seed)
        intents.update("f" * 40, error=None)
        left = intents.records()
        self.assertLessEqual(len(left), intents.MAX_RECORDS + 2)
        self.assertIn("f" * 40, left, "a pending remediation was evicted")
        self.assertIn("e" * 40, left, "an unsettled remediation was evicted")


if __name__ == "__main__":
    unittest.main()
