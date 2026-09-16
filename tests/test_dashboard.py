"""The Dashboard: healthy, anything to do, what happened, what patterns.

Two things are being defended here, and they are the two the design review
called out by name.

The first is that a number on this page must not claim more than it knows.
`events.jsonl` is the only complete record of what Protectarr did, and reading
all of it is unbounded, so the scan is capped - which means every count derived
from it can be a lower bound. A lower bound printed as an exact figure is worse
than no figure, so the truncation has to survive all the way to the rendered
page.

The second is that the evidence store must never become the remediation count.
It looks ideal: indexed on time, carries outcome, indexer and finding. It is
also incomplete by design - `record_encounter` writes nothing when harvesting
is off, when the swarm was empty, or when the write failed - so counting it
would silently under-report exactly the fakes nobody was seeding.

Run with:  python -m unittest discover -s tests
"""

import os
import re
import sys
import json
import time
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

import browser  # noqa: E402
from protectarr import dashboard, events, evidence, intents, logs, web  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LONG_TITLE = ("Les Murs vagabonds / Drifting Home / Ame wo Tsugeru Hyouryuu "
              "Danchi (2022) [Blu-Ray JPN 1080p-HEVC Multi VF / VOSTFR / "
              "English Sub] [Complete Season Batch v2 REPACK PROPER]")


def stamp(ago):
    """A timestamp `ago` seconds in the past, in the format events use."""
    return time.strftime(logs.TS_FORMAT, time.localtime(time.time() - ago))


def detection(ago=60, result="reaped", indexer="Nyaa", dry=False,
              reason="extension_match", ext=".exe", rid=None, title="Rel.2024",
              instance="Radarr", category=None):
    ev = {
        "event_type": "detection", "schema_version": 3,
        "id": os.urandom(8).hex(), "timestamp": stamp(ago),
        "torrent": {"hash": os.urandom(20).hex(), "name": title,
                    "size": 1234567, "category": category, "indexer": indexer},
        "owner": {"type": "radarr", "instance": instance, "media": "Some Film",
                  "release_title": title},
        "findings": [{"detector": "filelist", "reason": reason,
                      "evidence": {"filename": "Setup" + (ext or ""),
                                   "extension": ext}}],
        "policy": {"profile": "media", "severity": "critical",
                   "decision": "block", "decisive_finding": 0},
        "peers_harvested": 12, "dry_run": dry,
        "action": {"result": result, "decision": "arr_fail", "removed": True,
                   "blocklisted": True, "verification": "downloadFailed matched"},
        "redownload": {"decision": "searched", "reason": "aired"},
    }
    if rid:
        ev["remediation_id"] = rid
    return ev


def lifecycle(rid, milestone="settled", ago=30, title="Rel.2024"):
    """A remediation's follow-up event. Carries no finding and no action."""
    return {
        "event_type": "remediation", "schema_version": 3,
        "id": os.urandom(8).hex(), "timestamp": stamp(ago),
        "remediation_id": rid, "dry_run": False,
        "torrent": {"hash": os.urandom(20).hex(), "name": title,
                    "indexer": "Nyaa"},
        "owner": {"type": "radarr", "instance": "Radarr", "media": None,
                  "release_title": title},
        "remediation": {"milestone": milestone, "source": "live",
                        "recovered": False, "note": "",
                        "verification": "downloadFailed matched",
                        "search": None, "error": None},
    }


class DashCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        evidence.reset()
        intents._store.reset()

    def write(self, evs):
        """Newest-first input, written oldest-first as the real file is."""
        with open(os.path.join(self.dir, "events.jsonl"), "w") as fh:
            for ev in reversed(evs):
                fh.write(json.dumps(ev, separators=(",", ":")) + "\n")

    def collect(self, **kw):
        return dashboard.collect(fold=web._history_rows, **kw)


# --------------------------------------------------------------- aggregation

class TestWhatCountsAsARemediation(DashCase):

    def test_a_reap_counts(self):
        self.write([detection(ago=60)])
        self.assertEqual(self.collect()["remediations_24h"], 1)

    def test_a_partial_counts(self):
        """The destructive half went through; the follow-up did not.

        That is a remediation that needs looking at, not one that did not
        happen, and leaving it out would under-report exactly the cases the
        operator most needs to see.
        """
        self.write([detection(result="partial")])
        self.assertEqual(self.collect()["remediations_24h"], 1)

    def test_a_flagged_release_is_not_a_remediation(self):
        """Nothing was removed, so nothing was remediated."""
        self.write([detection(result="warned")])
        self.assertEqual(self.collect()["remediations_24h"], 0)

    def test_a_dry_run_is_in_none_of_the_counts(self):
        """Not the remediation count, and not the trend cards either.

        Asserting only the remediation count proves nothing about the dry-run
        guard: a dry run's result is `would_reap`, which the removed-results
        filter already rejects. The findings and indexers are where the guard
        is actually load-bearing.
        """
        self.write([detection(result="would_reap", dry=True),
                    detection(result="reaped", dry=True)])
        agg = self.collect()
        self.assertEqual(agg["remediations_24h"], 0)
        self.assertEqual(agg["findings_total"], 0)
        self.assertEqual(agg["indexers_total"], 0)

    def test_older_than_24h_is_not_in_the_24h_count(self):
        self.write([detection(ago=25 * 3600)])
        agg = self.collect()
        self.assertEqual(agg["remediations_24h"], 0)
        # Still inside the 7-day window, so the trend cards keep it.
        self.assertEqual(agg["indexers_total"], 1)

    def test_older_than_7d_is_in_nothing(self):
        self.write([detection(ago=8 * 86400)])
        agg = self.collect()
        self.assertEqual(agg["remediations_24h"], 0)
        self.assertEqual(agg["findings_total"], 0)
        self.assertEqual(agg["indexers_total"], 0)


class TestOneRemediationCountsOnce(DashCase):
    """The fold problem: a remediation writes several events over its life."""

    def test_three_events_for_one_reap_count_once(self):
        rid = "a" * 32
        self.write([lifecycle(rid, "settled", ago=10),
                    lifecycle(rid, "removed", ago=20),
                    detection(ago=30, rid=rid)])
        self.assertEqual(self.collect()["remediations_24h"], 1)

    def test_lifecycle_events_alone_count_nothing(self):
        """Their detection event is beyond the window or the cap.

        Counting them would invent remediations out of follow-up notices, and
        counting them as their own would make the number grow every time a
        reconcile ran.
        """
        rid = "b" * 32
        self.write([lifecycle(rid, "settled", ago=10),
                    lifecycle(rid, "removed", ago=20)])
        self.assertEqual(self.collect()["remediations_24h"], 0)

    def test_the_indexer_is_counted_once_per_remediation(self):
        rid = "c" * 32
        self.write([lifecycle(rid, "settled", ago=10),
                    lifecycle(rid, "removed", ago=20),
                    detection(ago=30, rid=rid, indexer="Nyaa")])
        self.assertEqual(self.collect()["indexers"],
                         [{"label": "Nyaa", "count": 1}])


class TestFindingSemantics(DashCase):

    def test_the_category_is_the_reason_not_the_filename(self):
        """Two releases, same detector, different files: one category."""
        self.write([detection(title="A"), detection(title="B")])
        self.assertEqual(self.collect()["findings"],
                         [{"label": "Monitored extension .exe", "count": 2}])

    def test_extensions_are_distinguished(self):
        self.write([detection(ext=".exe"), detection(ext=".scr"),
                    detection(ext=".exe")])
        self.assertEqual(self.collect()["findings"], [
            {"label": "Monitored extension .exe", "count": 2},
            {"label": "Monitored extension .scr", "count": 1}])

    def test_richer_reasons_are_used_over_the_extension(self):
        """A lure or a content mismatch is not described by a file extension."""
        # Extensions deliberately present: the point is that a lure or a
        # mismatch is named by its reason even when there is an extension
        # sitting in the evidence to flatten it to.
        self.write([detection(reason="lure_filename", ext=".mkv"),
                    detection(reason="content_type_mismatch", ext=".mp4"),
                    detection(reason="archive_no_media", ext=".rar")])
        labels = {f["label"] for f in self.collect()["findings"]}
        self.assertEqual(labels, {"Lure filename", "Content type mismatch",
                                  "Archive with no media"})

    def test_a_flagged_release_still_contributes_a_finding(self):
        """It was found, it just was not removed.

        Otherwise a Protectarr in warn-only mode reports that it is finding
        nothing, which is the opposite of what it is doing.
        """
        self.write([detection(result="warned")])
        agg = self.collect()
        self.assertEqual(agg["findings_total"], 1)
        self.assertEqual(agg["indexers_total"], 0)

    def test_an_unknown_reason_is_named_not_dropped(self):
        self.write([detection(reason="brand_new_detector", ext=None)])
        self.assertEqual(self.collect()["findings"],
                         [{"label": "Brand new detector", "count": 1}])

    def test_the_ranking_is_bounded(self):
        self.write([detection(ext=".e%d" % i) for i in range(30)])
        self.assertEqual(len(self.collect()["findings"]), dashboard.TOP_N)

    def test_ties_are_ordered_by_name_not_by_chance(self):
        """Equal counts that reorder between loads read as data changing."""
        self.write([detection(ext=".zzz"), detection(ext=".aaa")])
        self.assertEqual([f["label"] for f in self.collect()["findings"]],
                         ["Monitored extension .aaa", "Monitored extension .zzz"])


class TestIndexerAttribution(DashCase):

    def test_a_missing_indexer_is_unknown_not_invented(self):
        """The category-fallback delete has no owning *arr and no indexer.

        `stats.by_indexer` fills that slot with the qBittorrent category and is
        wrong because of it. This must not learn the same habit.
        """
        self.write([detection(indexer=None, category="tv-sonarr")])
        self.assertEqual(self.collect()["indexers"],
                         [{"label": dashboard.UNKNOWN_INDEXER, "count": 1}])

    def test_an_empty_indexer_is_unknown(self):
        self.write([detection(indexer="")])
        self.assertEqual(self.collect()["indexers"][0]["label"],
                         dashboard.UNKNOWN_INDEXER)

    def test_the_ranking_is_bounded(self):
        self.write([detection(indexer="ix%d" % i) for i in range(30)])
        self.assertEqual(len(self.collect()["indexers"]), dashboard.TOP_N)


# ------------------------------------------------------------- the hard bound

class TestTheScanIsBounded(DashCase):

    def test_the_cap_stops_the_walk(self):
        self.write([detection(ago=60) for _ in range(50)])
        agg = self.collect(cap=10)
        self.assertEqual(agg["scanned"], 10)
        self.assertTrue(agg["truncated"])

    def test_the_count_is_what_was_counted_never_the_cap(self):
        """`2000+` may only appear if 2,000 were actually counted.

        The failure this guards against is printing the cap with a `+` on it,
        which looks like a number and is not one.
        """
        self.write([detection(ago=60) for _ in range(50)])
        agg = self.collect(cap=10)
        self.assertEqual(agg["remediations_24h"], 10)
        self.assertLess(agg["remediations_24h"], 50)

    def test_truncation_is_a_lower_bound_not_a_wrong_number(self):
        self.write([detection(ago=60) for _ in range(50)])
        capped = self.collect(cap=10)["remediations_24h"]
        full = self.collect(cap=1000)["remediations_24h"]
        self.assertLessEqual(capped, full)
        self.assertEqual(full, 50)

    def test_a_partial_remediation_at_the_cap_boundary_undercounts_honestly(self):
        """The cap can cut between a remediation's events.

        Its lifecycle events are inside and its detection event is outside, so
        it contributes nothing - which is a lower bound, and is why the page
        says `+`. What must not happen is the lifecycle events being counted to
        make up the difference.
        """
        rid = "d" * 32
        self.write([lifecycle(rid, "settled", ago=10),
                    lifecycle(rid, "removed", ago=20),
                    detection(ago=30, rid=rid)])
        agg = self.collect(cap=2)
        self.assertEqual(agg["remediations_24h"], 0)
        self.assertTrue(agg["truncated"])

    def test_not_truncated_when_the_window_ends_the_walk(self):
        """Reading everything that could matter is not truncation.

        The tail behind the cutoff has to be longer than one event: with a
        single old record the stream is exhausted at the moment the window
        stops the walk, so "is there more?" answers no for the wrong reason
        and a broken truncation test still passes.
        """
        self.write([detection(ago=60)] + [detection(ago=8 * 86400)] * 40)
        agg = self.collect(cap=1000)
        self.assertFalse(agg["truncated"])
        self.assertLess(agg["scanned"], 5)

    def test_not_truncated_when_the_store_is_smaller_than_the_cap(self):
        self.write([detection(ago=60) for _ in range(5)])
        self.assertFalse(self.collect(cap=5)["truncated"])

    def test_dry_runs_are_counted_against_the_cap(self):
        """They cost a parse, and parsing is what the cap exists to bound.

        A cap that only counted qualifying events would let a store full of dry
        runs spend the whole budget while still calling itself bounded.
        """
        self.write([detection(dry=True, result="would_reap") for _ in range(50)])
        agg = self.collect(cap=10)
        self.assertEqual(agg["scanned"], 10)
        self.assertTrue(agg["truncated"])

    def test_the_window_stops_the_walk_before_the_cap(self):
        self.write([detection(ago=60)] + [detection(ago=8 * 86400)] * 100)
        self.assertLess(self.collect(cap=1000)["scanned"], 5)

    def test_one_unreadable_timestamp_does_not_truncate_the_history(self):
        bad = detection(ago=60)
        bad["timestamp"] = "not a timestamp"
        self.write([bad, detection(ago=120), detection(ago=180)])
        self.assertEqual(self.collect()["remediations_24h"], 2)


class TestTimestampParsing(unittest.TestCase):

    def test_the_offset_is_applied(self):
        a = dashboard.parse_ts("2026-09-15 12:00:00 +0000")
        b = dashboard.parse_ts("2026-09-15 12:00:00 -0700")
        self.assertEqual(b - a, 7 * 3600)

    def test_a_daylight_saving_change_orders_correctly(self):
        """The reason this is not a lexicographic compare of the first 19 bytes.

        Across a fall-back the same wall clock is two different instants an hour
        apart. Comparing the text calls them equal, so an hour of events sorts
        wrongly twice a year and the 24-hour window quietly moves.
        """
        before = "2026-11-01 01:30:00 -0700"
        after = "2026-11-01 01:30:00 -0800"
        self.assertLess(dashboard.parse_ts(before), dashboard.parse_ts(after))
        self.assertEqual(before[:19], after[:19])

    def test_junk_is_none_not_an_exception(self):
        for bad in (None, "", "yesterday", "2026-13-45 99:99:99 +0000", "2026"):
            with self.subTest(value=bad):
                self.assertIsNone(dashboard.parse_ts(bad))

    def test_a_missing_offset_still_parses(self):
        self.assertIsNotNone(dashboard.parse_ts("2026-09-15 12:00:00"))


# ------------------------------------------------------------------ the page

class PageCase(DashCase):

    def service(self, last_error=None, last_scan=None, last_reap=None):
        class Loose(dict):
            def __getattr__(self, k):
                return self.get(k)
        return Loose(state=Loose(
            stats=Loose(reaped_total=0, by_indexer=Loose(), by_app=Loose(),
                        last_reap=last_reap, first_seen=None),
            running=True, last_scan=last_scan, last_error=last_error,
            blocklist=Loose(), banned=Loose()))

    def client(self, **kw):
        cfg_mod.save({"qbittorrent": {"url": ""}, "arrs": [], "dry_run": False})
        app = web.create_app(self.service(**kw))
        app.config["TESTING"] = True
        c = app.test_client()
        with c.session_transaction() as s:
            s["user"] = "test"
        return c

    def page(self, **kw):
        return self.client(**kw).get("/dashboard").data.decode()

    def card(self, html, title):
        """The body of one named card, so an assertion cannot match elsewhere.

        Depth-counted rather than a lazy regex. Every card body contains nested
        divs, so `(.*?)</div>` stops at the first inner close and returns a
        fragment - which passes `assertNotIn` for anything below the cut and
        proves nothing.
        """
        m = re.search(r"<h2>" + re.escape(title) + r"\b.*?</h2>\s*"
                      r'<div class="body">', html, re.S)
        self.assertIsNotNone(m, "no card titled %r" % title)
        start = m.end()
        depth, i = 1, start
        for tag in re.finditer(r"<(/?)div\b", html[start:]):
            depth += -1 if tag.group(1) else 1
            if depth == 0:
                i = start + tag.start()
                break
        else:
            self.fail("unbalanced divs in the %r card" % title)
        return html[start:i]


class TestVitals(PageCase):

    def test_the_24h_count_renders(self):
        self.write([detection(ago=60), detection(ago=120)])
        self.assertIn(">2</div>", self.card(self.page(), "24h Remediations"))

    def test_truncation_reaches_the_page(self):
        """And it is the remediation count that is shown, not the scan depth.

        Every third event here is a flagged release, which is scanned but is
        not a remediation, so the two numbers differ: 12 events read, 8 of them
        removals. A page that printed the scan depth would say "12+".
        """
        self.write([detection(ago=60,
                              result="warned" if i % 3 == 2 else "reaped")
                    for i in range(60)])
        old = dashboard.EVENT_CAP
        dashboard.EVENT_CAP = 12
        try:
            body = self.card(self.page(), "24h Remediations")
        finally:
            dashboard.EVENT_CAP = old
        self.assertIn("8+", body)
        self.assertNotIn("12+", body)
        self.assertIn("scan capped", body)

    def test_the_cap_is_never_printed_as_the_count(self):
        """Only counted remediations may appear, with or without the `+`."""
        self.write([detection(ago=60) for _ in range(60)])
        old = dashboard.EVENT_CAP
        dashboard.EVENT_CAP = 10
        try:
            html = self.page()
        finally:
            dashboard.EVENT_CAP = old
        self.assertNotIn("60+", html)

    def test_zero_remediations_is_quiet(self):
        """`0` is a healthy state and must not be coloured or alarmed."""
        self.write([])
        body = self.card(self.page(), "24h Remediations")
        self.assertIn(">0</div>", body)
        self.assertIn("none in the last 24 hours", body)
        self.assertNotIn("bad", body)

    def test_no_previous_remediation_is_not_a_failure(self):
        body = self.card(self.page(), "Last Remediation")
        self.assertIn("None yet", body)
        self.assertNotIn("pill bad", body)
        self.assertNotIn("danger", body)

    def test_the_last_remediation_is_relative_and_absolute(self):
        ts = stamp(3 * 3600)
        body = self.card(self.page(last_reap=ts), "Last Remediation")
        self.assertIn("3 hours ago", body)
        self.assertIn(ts, body)

    def test_the_last_scan_is_secondary_not_the_remediation_time(self):
        """They are different facts and must not be merged."""
        body = self.card(self.page(last_scan=stamp(60),
                                   last_reap=stamp(3 * 3600)),
                         "Last Remediation")
        self.assertIn("3 hours ago", body)
        self.assertRegex(body, r'sub muted">\s*Last scan')

    def test_the_evidence_store_is_a_health_row(self):
        self.assertIn("Evidence store", self.card(self.page(), "System Health"))


class TestAttention(PageCase):

    def open_failed(self, n=1, ago=3600):
        recs = {}
        for i in range(n):
            h = ("%040x" % i)
            recs[h] = {
                "milestone": intents.FAILED_UNVERIFIED, "hash": h,
                "remediation_id": "r%030d" % i,
                "opened": time.time() - ago - i, "updated": time.time(),
                "arr": "Radarr", "arr_type": "radarr",
                "release_title": "Bad.Release.%d" % i,
                "evidence": {"why": "no downloadFailed event matched"},
                "error": None, "search": None, "attempts": 1,
                "queue_id": 1, "watermark": 1, "media": None, "indexer": "Nyaa"}
        intents._store.mutate(lambda d: d.update(recs))

    def test_quiet_when_nothing_is_wrong(self):
        body = self.card(self.page(), "Attention Required")
        self.assertIn(">0</div>", body)
        self.assertIn("Nothing needs you", body)
        self.assertNotIn("alarm", body)

    def test_failed_unverified_raises_the_count(self):
        self.open_failed(2)
        body = self.card(self.page(), "Attention Required")
        self.assertIn(">2</div>", body)
        self.assertIn("2 remediation", body)

    def test_a_scan_error_raises_the_count(self):
        body = self.card(self.page(last_error="qBittorrent unreachable"),
                         "Attention Required")
        self.assertIn(">1</div>", body)
        self.assertIn("1 system", body)
        self.assertIn("qBittorrent unreachable", body)

    def test_the_two_classes_are_counted_separately(self):
        self.open_failed(2)
        body = self.card(self.page(last_error="boom"), "Attention Required")
        self.assertIn(">3</div>", body)
        self.assertIn("2 remediation", body)
        self.assertIn("1 system", body)

    def test_an_alarm_colours_the_card_and_zero_does_not(self):
        self.assertNotIn("vital attn alarm", self.page())
        self.open_failed(1)
        self.assertIn("alarm", self.page())

    def test_an_evidence_store_failure_is_system_attention(self):
        evidence._broken = "evidence.db failed its integrity check"
        try:
            body = self.card(self.page(), "Attention Required")
            self.assertIn("1 system", body)
            self.assertIn("Evidence store unusable", body)
        finally:
            evidence.reset()

    def test_an_evidence_store_failure_does_not_become_a_triage_row(self):
        """A broken database is not a release, and inventing a History row for
        it so that it fits the table would be a fabricated record."""
        evidence._broken = "evidence.db failed its integrity check"
        try:
            html = self.page()
            self.assertNotIn("Triage Queue", html)
            self.assertIn("Evidence store unusable", html)
        finally:
            evidence.reset()

    def test_a_scan_error_alone_shows_no_triage_queue(self):
        html = self.page(last_error="qBittorrent unreachable")
        self.assertNotIn("Triage Queue", html)
        self.assertIn("qBittorrent unreachable", html)

    def test_system_attention_routes_to_the_system_page(self):
        self.assertIn('href="/system"', self.page(last_error="boom"))


class TestTriageQueue(PageCase):

    def failed(self, n, ago=3600, rid=None, title=None):
        recs = {}
        for i in range(n):
            h = "%040x" % i
            recs[h] = {
                "milestone": intents.FAILED_UNVERIFIED, "hash": h,
                "remediation_id": rid or ("r%030d" % i),
                # Descending age, so record 0 is the oldest.
                "opened": time.time() - ago - (n - i) * 60,
                "updated": time.time(), "arr": "Radarr", "arr_type": "radarr",
                "release_title": title or ("Bad.Release.%d" % i),
                "evidence": {"why": "no downloadFailed event matched"},
                "error": None, "search": None, "attempts": 1,
                "queue_id": 1, "watermark": 1, "media": None, "indexer": "Nyaa"}
        intents._store.mutate(lambda d: d.update(recs))

    def settled(self, n):
        recs = {}
        for i in range(n):
            h = "ff%038x" % i
            recs[h] = {"milestone": intents.SETTLED, "hash": h,
                       "remediation_id": "s%030d" % i,
                       "opened": time.time(), "updated": time.time(),
                       "arr": "Radarr", "release_title": "Fine.%d" % i,
                       "evidence": None, "error": None, "search": None}
        intents._store.mutate(lambda d: d.update(recs))

    def test_absent_when_nothing_is_actionable(self):
        self.assertNotIn("Triage Queue", self.page())

    def test_settled_and_pending_are_not_actionable(self):
        """`pending` resolves itself on the next scan. Listing it would turn the
        normal few seconds after a reap into a queue of things looking broken."""
        self.settled(3)
        intents._store.mutate(lambda d: d.update({
            "aa" + "0" * 38: {"milestone": intents.PENDING, "hash": "aa",
                              "opened": time.time(), "updated": time.time(),
                              "release_title": "InFlight", "evidence": None,
                              "error": None, "search": None}}))
        self.assertNotIn("Triage Queue", self.page())

    def test_present_when_a_remediation_failed_unverified(self):
        self.failed(1)
        self.assertIn("Triage Queue", self.page())

    def test_oldest_first(self):
        self.failed(3)
        body = self.card(self.page(), "Triage Queue")
        order = re.findall(r"Bad\.Release\.(\d)", body)
        self.assertEqual(order, ["0", "1", "2"])

    def test_bounded_to_five_with_a_route_to_history(self):
        self.failed(9)
        body = self.card(self.page(), "Triage Queue")
        self.assertEqual(len(re.findall(r"Bad\.Release\.\d", body)), 5)
        self.assertIn("Showing 5 of 9", body)
        self.assertIn("View all in History", body)

    def test_no_view_all_link_when_everything_fits(self):
        self.failed(2)
        self.assertNotIn("View all in History",
                         self.card(self.page(), "Triage Queue"))

    def test_the_issue_is_always_named(self):
        self.failed(1)
        self.assertIn("no downloadFailed event matched",
                      self.card(self.page(), "Triage Queue"))

    def test_an_issue_falls_back_rather_than_rendering_blank(self):
        """A triage row with no issue named is a row nobody can act on."""
        rows = web._triage({"h": {"milestone": intents.FAILED_UNVERIFIED,
                                  "opened": time.time(), "evidence": None,
                                  "error": None, "release_title": "X"}})
        self.assertTrue(rows[0]["issue"])

    def test_details_opens_the_same_dossier_history_would(self):
        """And the right one: the index has to address that row's record.

        Asserting only that a button exists would pass if every triage row
        opened row 0, which is the failure mode of matching by position instead
        of by `remediation_id`.
        """
        rid = "e" * 32
        # Noise in front, so index 0 is the wrong answer and a positional bug
        # cannot pass by coincidence.
        self.write([detection(ago=100, title="Unrelated.A"),
                    detection(ago=200, title="Unrelated.B"),
                    detection(ago=600, rid=rid, title="The.Triaged.Release")])
        self.failed(1, rid=rid)
        html = self.page()
        body = self.card(html, "Triage Queue")
        idx = int(re.search(r"showDetails\((\d+)\)", body).group(1))
        self.assertGreater(idx, 0)
        rows = json.loads(re.search(r"var ROWS = (\[.*?\]);", html, re.S).group(1))
        self.assertEqual(rows[idx]["release"], "The.Triaged.Release")

    def test_the_dossier_is_available_past_the_end_of_recent_activity(self):
        """A triage row can be older than the five entries shown above it, so
        `detail_rows` has to carry every folded row, not just the visible five."""
        rid = "e" * 32
        self.write([detection(ago=100 + i * 60, title="Newer.%d" % i)
                    for i in range(10)]
                   + [detection(ago=5000, rid=rid, title="Old.Triaged")])
        self.failed(1, rid=rid)
        html = self.page()
        idx = int(re.search(r"showDetails\((\d+)\)",
                            self.card(html, "Triage Queue")).group(1))
        self.assertGreaterEqual(idx, 5)
        rows = json.loads(re.search(r"var ROWS = (\[.*?\]);", html, re.S).group(1))
        self.assertEqual(rows[idx]["release"], "Old.Triaged")

    def test_no_details_button_when_the_event_has_rotated_out(self):
        """Better than a button that opens a dialog of blanks."""
        self.failed(1, rid="f" * 32)
        body = self.card(self.page(), "Triage Queue")
        self.assertNotIn("showDetails", body)
        self.assertIn("not retained", body)


class TestRecentActivity(PageCase):

    def test_it_shows_the_newest_five(self):
        self.write([detection(ago=i * 60, title="Rel.%d" % i)
                    for i in range(12)])
        body = self.card(self.page(), "Recent Activity")
        self.assertEqual(len(re.findall(r"Rel\.\d+", body)), 5)
        self.assertIn("Rel.0", body)
        self.assertNotIn("Rel.6", body)

    def test_it_is_not_limited_to_successful_remediations(self):
        """Failure and transitional outcomes are what someone comes here for."""
        self.write([detection(ago=60, result="warned", title="Flagged.Only"),
                    detection(ago=120, result="partial", title="Half.Done")])
        body = self.card(self.page(), "Recent Activity")
        self.assertIn("Flagged.Only", body)
        self.assertIn("Half.Done", body)

    def test_it_reuses_history_pills_rather_than_inventing_wording(self):
        rid = "a" * 32
        self.write([lifecycle(rid, intents.FAILED_UNVERIFIED, ago=10),
                    detection(ago=20, rid=rid)])
        body = self.card(self.page(), "Recent Activity")
        self.assertIn("Failed Unverified", body)
        self.assertIn('class="pill bad"', body)

    def test_the_empty_state_is_neutral(self):
        body = self.card(self.page(), "Recent Activity")
        self.assertIn("Nothing recorded yet", body)
        self.assertNotIn("pill bad", body)

    def test_dry_runs_do_not_appear(self):
        self.write([detection(dry=True, result="would_reap", title="Dry.One")])
        self.assertNotIn("Dry.One", self.card(self.page(), "Recent Activity"))


class TestTrendCards(PageCase):

    def test_findings_render_as_bars(self):
        self.write([detection(ext=".exe"), detection(ext=".exe"),
                    detection(ext=".scr")])
        body = self.card(self.page(), "Recent Findings")
        self.assertIn("Monitored extension .exe", body)
        self.assertIn("bar-fill", body)
        # Ranked against the largest count, so the top row is a full bar.
        self.assertIn("width: 100.0%", body)
        self.assertIn("width: 50.0%", body)

    def test_indexers_render_and_disclaim(self):
        self.write([detection(indexer="Nyaa")])
        body = self.card(self.page(), "Recent Associated Indexers")
        self.assertIn("Nyaa", body)
        self.assertIn("does not mean the", body)

    def test_the_indexer_card_title_is_exact(self):
        self.assertIn("<h2>Recent Associated Indexers", self.page())

    def test_empty_states_are_neutral(self):
        html = self.page()
        self.assertIn("Nothing found in the last 7 days", html)
        self.assertIn("No removals in the last 7 days", html)

    def test_truncation_is_disclosed_on_both_trend_cards(self):
        self.write([detection(ago=60) for _ in range(60)])
        old = dashboard.EVENT_CAP
        dashboard.EVENT_CAP = 10
        try:
            html = self.page()
        finally:
            dashboard.EVENT_CAP = old
        self.assertEqual(html.count("Event scan capped to preserve performance"), 2)

    def test_volume_is_not_coloured_as_success(self):
        """Remediation volume is a fact, not an achievement.

        The accent green means confirmed-healthy elsewhere in this UI, so
        spending it on "how many fakes arrived" would make a bad week look
        like a good one.
        """
        self.write([detection()])
        self.assertIn("bar-fill neutral", self.page())


class TestNoContaminatedStats(PageCase):
    """`stats.by_indexer` records a qBittorrent category into the indexer
    bucket on the category-fallback path, so the Dashboard must not read it."""

    def test_the_template_never_reads_by_indexer(self):
        tpl = open(os.path.join(ROOT, "protectarr", "templates",
                                "dashboard.html")).read()
        self.assertNotIn("by_indexer", tpl)
        self.assertNotIn("REAPED_BY_INDEXER", tpl)

    def test_a_contaminated_stat_does_not_reach_the_page(self):
        class Loose(dict):
            def __getattr__(self, k):
                return self.get(k)
        cfg_mod.save({"qbittorrent": {"url": ""}, "arrs": [], "dry_run": False})
        svc = Loose(state=Loose(
            stats=Loose(reaped_total=3, last_reap=None, first_seen=None,
                        by_app=Loose(), by_indexer={"tv-sonarr": 3}),
            running=True, last_scan=None, last_error=None,
            blocklist=Loose(), banned=Loose()))
        # Events too: the trend cards are dropped entirely when there is
        # nothing to rank, and an absent card cannot show a contaminated value
        # whatever the template says.
        self.write([detection(indexer="Nyaa", category="tv-sonarr")])
        app = web.create_app(svc)
        app.config["TESTING"] = True
        c = app.test_client()
        with c.session_transaction() as s:
            s["user"] = "test"
        html = c.get("/dashboard").data.decode()
        # Scoped to the card, not the whole page. The category is legitimately
        # in the Details payload - it is the torrent's qBittorrent category and
        # the dossier shows it as one. The defect being guarded against is it
        # appearing as an *indexer*, which is the specific confusion
        # `stats.by_indexer` already makes.
        card = self.card(html, "Recent Associated Indexers")
        self.assertIn("Nyaa", card)
        self.assertNotIn("tv-sonarr", card)

    def test_the_indexer_card_is_fed_from_events(self):
        self.write([detection(indexer="FromEvents")])
        self.assertIn("FromEvents",
                      self.card(self.page(), "Recent Associated Indexers"))


class TestRemovedSurfaces(PageCase):
    """The cards the redesign deleted, and the CSS that drew them."""

    def setUp(self):
        super().setUp()
        self.html = self.page()
        # Comments stripped: the block that removed these rules names them in
        # prose to say why they went, and matching that would report the
        # explanation as the thing it explains.
        self.css = re.sub(r"/\*.*?\*/", "",
                          open(os.path.join(ROOT, "protectarr", "static",
                                            "style.css")).read(), flags=re.S)

    def test_the_count_cards_are_gone(self):
        for gone in ("Indexers seen", "Malicious reaped", "Library monitored",
                     "in qBittorrent", "across all apps"):
            with self.subTest(surface=gone):
                self.assertNotIn(gone, self.html)

    def test_the_application_health_table_is_gone(self):
        self.assertNotIn("<th>Type</th>", self.html)
        self.assertNotIn("apps_tbody", self.html)

    def test_the_indexers_table_is_gone(self):
        self.assertNotIn("indexers_tbody", self.html)

    def test_the_svg_charts_are_gone(self):
        # Not `<svg class`: the sidebar's nav icons are inline SVG and always
        # will be, so that would assert the navigation away.
        for gone in ("barChart", "library_chart", "reaped_chart",
                     'class="chart"', "chart-wrap", "niceNum"):
            with self.subTest(surface=gone):
                self.assertNotIn(gone, self.html)

    def test_the_chart_css_went_with_them(self):
        """Dead CSS describing deleted surfaces misleads the next reader."""
        for gone in (".statcard", ".chart-wrap", ".legend .leg"):
            with self.subTest(rule=gone):
                self.assertNotIn(gone, self.css)

    def test_persisted_statistics_were_not_deleted(self):
        """Removing a card is not authority to drop the data behind it.

        `stats.json` still feeds Last Remediation here and the API, so the
        writer and the endpoint both have to survive the redesign.
        """
        from protectarr import core
        self.assertTrue(hasattr(core, "record_reap"))
        self.assertIn("reaped_total", core.load_stats())
        self.assertIn("by_indexer", core.load_stats())


class TestHealthCheckCost(DashCase):
    """What `/api/dashboard` is allowed to ask the network for.

    The old route made roughly 3N+2 serialised calls and two of the three
    per-app calls existed only to fill surfaces that no longer exist. The
    library fetch was the worst of them: every movie or series an app knows
    about, with every field, to compute two integers.

    These fakes raise on the calls that should be gone, so a reintroduction
    fails loudly instead of quietly costing a second per app.
    """

    class FakeArr:
        def __init__(self, name, calls):
            self.name, self.type, self.calls = name, "radarr", calls

        def test(self):
            self.calls.append((self.name, "test"))
            return True, "Radarr 5.2"

        def library_stats(self):
            raise AssertionError("library_stats() must not be called: it "
                                 "fetches the whole library for two integers")

        def indexers(self):
            raise AssertionError("indexers() must not be called: the Dashboard "
                                 "has no indexer inventory any more")

    class FakeQb:
        def __init__(self, calls, **kw):
            self.calls = calls

        def test(self):
            self.calls.append(("qBittorrent", "test"))
            return True, "qBittorrent 5.2.3"

        def login(self):
            self.calls.append(("qBittorrent", "login"))

        def torrents(self, *a, **kw):
            raise AssertionError("torrents() must not be called: the torrent "
                                 "counters were removed from the Dashboard")

    def call(self, n_apps=2):
        calls = []
        cfg_mod.save({"qbittorrent": {"url": "http://qb.invalid"},
                      "arrs": [], "dry_run": False})
        real_build, real_qb = web.build_clients, web.QbitClient
        web.build_clients = lambda cfg: [
            self.FakeArr("App%d" % i, calls) for i in range(n_apps)]
        web.QbitClient = lambda *a, **kw: self.FakeQb(calls)

        class Loose(dict):
            def __getattr__(self, k):
                return self.get(k)
        try:
            app = web.create_app(Loose(state=Loose(
                stats=Loose(), running=True, last_scan=None, last_error=None,
                blocklist=Loose(), banned=Loose())))
            app.config["TESTING"] = True
            c = app.test_client()
            with c.session_transaction() as s:
                s["user"] = "test"
            r = c.get("/api/dashboard")
        finally:
            web.build_clients, web.QbitClient = real_build, real_qb
        return r, calls

    def test_one_call_per_service_and_no_more(self):
        r, calls = self.call(n_apps=2)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(calls), 3, "expected N+1 calls, got %r" % (calls,))
        self.assertEqual(sorted(calls),
                         [("App0", "test"), ("App1", "test"),
                          ("qBittorrent", "test")])

    def test_it_scales_as_n_plus_one(self):
        for n in (0, 1, 5):
            with self.subTest(apps=n):
                _, calls = self.call(n_apps=n)
                self.assertEqual(len(calls), n + 1)

    def test_the_library_fetch_is_gone_from_the_source_not_just_unused(self):
        src = open(os.path.join(ROOT, "protectarr", "web.py")).read()
        self.assertNotIn("library_stats", src)

    def test_the_indexer_enumeration_is_gone_from_the_source(self):
        src = open(os.path.join(ROOT, "protectarr", "web.py")).read()
        self.assertNotIn("client.indexers()", src)

    def test_it_reports_services_not_inventory(self):
        r, _ = self.call(n_apps=1)
        data = r.get_json()["data"]
        self.assertEqual(sorted(data), ["errors", "services"])
        for gone in ("indexers", "apps", "total_torrents", "active_torrents"):
            with self.subTest(field=gone):
                self.assertNotIn(gone, data)

    def test_an_unconfigured_service_is_neither_healthy_nor_broken(self):
        """Being set up is not a fault, and must not raise the alarm count."""
        cfg_mod.save({"qbittorrent": {"url": ""}, "arrs": [], "dry_run": False})

        class Loose(dict):
            def __getattr__(self, k):
                return self.get(k)
        app = web.create_app(Loose(state=Loose(
            stats=Loose(), running=True, last_scan=None, last_error=None,
            blocklist=Loose(), banned=Loose())))
        app.config["TESTING"] = True
        c = app.test_client()
        with c.session_transaction() as s:
            s["user"] = "test"
        data = c.get("/api/dashboard").get_json()["data"]
        qb = [s for s in data["services"] if s["name"] == "qBittorrent"][0]
        self.assertIsNone(qb["ok"])
        self.assertEqual(data["errors"], [])

    def test_the_endpoint_still_requires_authentication(self):
        cfg_mod.save({"qbittorrent": {"url": ""}, "arrs": [],
                      "dry_run": False,
                      "web": {"auth": {"method": "forms", "username": "u",
                                       "password_hash": "x"}}})

        class Loose(dict):
            def __getattr__(self, k):
                return self.get(k)
        app = web.create_app(Loose(state=Loose(
            stats=Loose(), running=True, last_scan=None, last_error=None,
            blocklist=Loose(), banned=Loose())))
        app.config["TESTING"] = True
        r = app.test_client().get("/api/dashboard")
        self.assertEqual(r.status_code, 401)


CSS_PATH = os.path.join(ROOT, "protectarr", "static", "style.css")
TPL_DIR = os.path.join(ROOT, "protectarr", "templates")


def read_tpl(name):
    """The template source. Some of what this page promises is markup the
    stylesheet can only act on if it is there - `data-label`, and the class
    that opts a table into the stacked layout - and a rendered page cannot
    tell a missing attribute from a cell that happened to be empty."""
    with open(os.path.join(TPL_DIR, name)) as fh:
        return fh.read()


def media_query_for(css, needle):
    """The @media condition enclosing a declaration, or None if it is top level."""
    i = css.index(needle)
    depth, cond = 0, None
    for m in re.finditer(r"@media([^{]*)\{|\{|\}", css[:i]):
        if m.group(0).startswith("@media"):
            if depth == 0:
                cond = m.group(1).strip()
            depth += 1
        elif m.group(0) == "{":
            if depth:
                depth += 1
        else:
            if depth:
                depth -= 1
                if depth == 0:
                    cond = None
    return cond


class TestResponsiveRules(unittest.TestCase):
    """Structural, not pixel-perfect: the properties whose loss would silently
    undo the measured layout."""

    @classmethod
    def setUpClass(cls):
        cls.css = read_css()

    def test_the_stacked_layout_is_the_default(self):
        """Columns are added by a min-width query, never removed by one.

        A layout that starts multi-column and is torn down for small screens
        breaks on any width the queries did not anticipate. Starting stacked
        means an unmatched query is a working page.
        """
        for grid in (".vitals", ".trends"):
            with self.subTest(grid=grid):
                for m in re.finditer(re.escape(grid) + r"\s*\{[^}]*\}", self.css):
                    if "grid-template-columns" in m.group(0):
                        cond = media_query_for(self.css, m.group(0))
                        self.assertIsNotNone(
                            cond, "%s gets columns outside a media query" % grid)
                        self.assertIn("min-width", cond)

    def test_the_breakpoints_were_measured_for_this_page(self):
        """Not 900px. That is the Details dialog's knee and unrelated to this
        grid; reusing it would be a tidiness argument, not a measurement."""
        conds = [media_query_for(self.css, s) for s in (
            ".vitals { grid-template-columns: repeat(4, 1fr); }",
            ".trends { grid-template-columns: 1fr 1fr; }",
            ".vitals { grid-template-columns: 1fr 1fr; }")]
        px = [int(re.search(r"min-width:\s*(\d+)px", c).group(1)) for c in conds]
        self.assertEqual(len(set(px)), 3, "three grids sharing one breakpoint")
        for p in px:
            self.assertNotEqual(p, 900)

    def test_four_columns_need_more_room_than_two(self):
        four = media_query_for(self.css, ".vitals { grid-template-columns: repeat(4, 1fr); }")
        two = media_query_for(self.css, ".vitals { grid-template-columns: 1fr 1fr; }")
        self.assertGreater(int(re.search(r"(\d+)px", four).group(1)),
                           int(re.search(r"(\d+)px", two).group(1)))

    def test_the_narrow_bar_label_wins_on_source_order(self):
        """It lost once, and the symptom was a 49px bar at 375px rather than
        anything that looked like a broken rule."""
        base = self.css.index(".bar-label { width: 160px")
        override = self.css.index(".bar-label { width: 104px")
        self.assertGreater(override, base,
                           "the narrow-label override is declared before the "
                           "rule it overrides, so it never applies")

    def test_both_row_tables_opt_into_the_stacked_layout(self):
        """Triage and Recent Activity are the two tables with columns that
        matter. Without the class the narrow rules match nothing, and the
        failure is invisible until someone opens the page on a phone."""
        html = read_tpl("dashboard.html")
        tables = re.findall(r"<table class=\"([^\"]+)\"", html)
        self.assertEqual(len(tables), 2, "the Dashboard's tables changed")
        for cls in tables:
            self.assertIn("rowcards", cls)

    def test_every_column_that_loses_its_heading_names_itself(self):
        """The header row is hidden in the stacked layout, so a cell with no
        `data-label` becomes an unlabelled paragraph. Date and the release are
        exempt: a timestamp and a title say what they are."""
        html = read_tpl("dashboard.html")
        for label in ("Issue", "Finding", "Outcome"):
            with self.subTest(column=label):
                self.assertIn('data-label="%s"' % label, html)

    def test_the_stacked_layout_arrives_by_max_width(self):
        """The one place a max-width query is right: this is not a column count
        being added, it is a table changing into something else below the width
        where it stops fitting."""
        cond = media_query_for(self.css, ".rowcards td + td { margin-top: 9px; }")
        self.assertIsNotNone(cond, "the stacked rules are not in a media query")
        self.assertIn("max-width", cond)

    def test_the_tables_got_their_own_breakpoint(self):
        """Measured on these tables, not borrowed. 900 is the Details dialog's,
        720 is the shell's, and the grids have three more of their own."""
        px = int(re.search(r"(\d+)px", media_query_for(
            self.css, ".rowcards td + td { margin-top: 9px; }")).group(1))
        for other in (900, 720, 980, 1024, 620, 480):
            self.assertNotEqual(px, other)

    def test_the_stacked_rules_do_not_depend_on_source_order(self):
        """They overrule `th, td`, which is declared *after* them in the file.

        That is only safe because every one of them is qualified by the
        `.rowcards` class and so outranks an element-only selector wherever it
        sits. Drop the class from any of them and the rule starts depending on
        position, which is how the narrow bar label failed: not as a broken
        rule, as a 49px bar that looked like a layout result.
        """
        # Comments out first: they sit between the selectors in this block and
        # would be read as part of the one that follows them.
        css = re.sub(r"/\*.*?\*/", "", self.css, flags=re.S)
        start = css.rindex("@media", 0, css.index(".rowcards td + td"))
        depth, end = 0, len(css)
        for m in re.finditer(r"[{}]", css[start:]):
            depth += 1 if m.group(0) == "{" else -1
            if not depth:
                end = start + m.start()
                break
        block = css[css.index("{", start) + 1:end]
        selectors = [s.strip() for m in re.finditer(r"([^{}]+)\{[^{}]*\}", block)
                     for s in m.group(1).split(",") if s.strip()]
        self.assertGreater(len(selectors), 5)
        for sel in selectors:
            with self.subTest(selector=sel):
                self.assertTrue(sel.startswith(".rowcards"),
                                "%r is not qualified by the table's own class, "
                                "so it wins or loses on source order" % sel)

    def test_the_action_column_is_aligned_from_the_stylesheet(self):
        """A style attribute beats any selector, so an inline `text-align`
        would leave the narrow layout unable to change its mind without
        `!important`."""
        html = read_tpl("dashboard.html")
        self.assertNotIn("text-align:right", html)
        self.assertIn(".rowcards td.act { text-align: right; }", self.css)

    def test_a_long_title_breaks_words_rather_than_characters(self):
        """`break-all` would shred ordinary prose in the same cells. Only an
        overlong unbreakable token - which a release name is - may be split."""
        block = self.css[self.css.index(".rowcards code"):]
        rule = block[:block.index("}")]
        self.assertIn("overflow-wrap: break-word", rule)
        # Comments stripped first. The rule above is explained by a comment
        # naming `break-all` as the thing it is not, and asserting against the
        # raw file matches that sentence and fails on its own reasoning.
        self.assertNotIn("break-all",
                         re.sub(r"/\*.*?\*/", "", self.css, flags=re.S))

    def test_no_broad_nowrap_was_added(self):
        """The 0.3.x regression: an unbreakable cell sets a column floor and
        pushes the overflow onto the page."""
        for m in re.finditer(r"([^{}]+)\{([^}]*white-space:\s*nowrap[^}]*)\}",
                             self.css):
            sel = m.group(1).strip().splitlines()[-1].strip()
            with self.subTest(selector=sel):
                self.assertNotRegex(sel, r"^\s*(td|\.applist td|\.bar-row)\s*$")


def read_css():
    with open(CSS_PATH) as fh:
        return fh.read()


@unittest.skipUnless(browser.BROWSER, browser.REASON)
class TestDashboardGeometry(PageCase):
    """Rendered measurements. The numbers in the CSS comments came from here."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()

    def render(self, **kw):
        """The Dashboard as a standalone file a browser can open."""
        html = self.page(**kw).replace(
            'href="/static/style.css"', 'href="file://%s"' % CSS_PATH)
        # No network behind a file:// page, so the health fetch would sit on
        # the virtual-time budget until it expired.
        html = html.replace("fetch('/api/dashboard'", "fetch('data:application/json,"
                            + '{\\"ok\\":true,\\"data\\":{\\"services\\":[]}}' + "'")
        path = os.path.join(self.tmp, "d%d.html" % len(os.listdir(self.tmp)))
        with open(path, "w") as fh:
            fh.write(html)
        return path

    PROBE = """(function(){
      var d = document.documentElement;
      var cols = function (sel) {
        var xs = {};
        [].forEach.call(document.querySelectorAll(sel), function (el) {
          xs[Math.round(el.getBoundingClientRect().left)] = 1; });
        return Object.keys(xs).length;
      };
      var bar = 1e9;
      [].forEach.call(document.querySelectorAll('.bar-track'), function (el) {
        bar = Math.min(bar, Math.round(el.getBoundingClientRect().width)); });
      // Per row table: is it stacked, does it want more width than its
      // scrolling wrapper gives it, and how many body cells are sitting past
      // the wrapper's right edge where only a sideways drag would find them.
      var tables = [].map.call(document.querySelectorAll('.rowcards'),
        function (t) {
          var wrap = t.parentNode, tr = t.querySelector('tbody tr');
          var edge = wrap.getBoundingClientRect().right, off = 0;
          [].forEach.call(t.querySelectorAll('tbody td'), function (td) {
            if (td.getBoundingClientRect().right > edge + 1) off++; });
          // The heading each cell prints for itself once the header row is
          // gone. Generated content, so it is not in the DOM to be read - only
          // the computed style of the pseudo-element knows whether the label
          // reached the screen or the rule quietly produced nothing.
          var labels = [].map.call(t.querySelectorAll('tbody td[data-label]'),
            function (td) {
              return [td.getAttribute('data-label'),
                      getComputedStyle(td, ':before').content];
            });
          return {stacked: tr ? getComputedStyle(tr).display === 'block' : null,
                  deficit: Math.round(t.scrollWidth - wrap.clientWidth),
                  labels: labels, offscreen: off};
        });
      return {overflow: Math.max(0, d.scrollWidth - d.clientWidth),
              vitals: cols('.vitals > .card'), trends: cols('.trends > .card'),
              tables: tables, bar: bar === 1e9 ? null : bar};
    })()"""

    def measure(self, path, width):
        src = open(path).read().replace(
            "</body>",
            '<pre id="OUT"></pre><script>window.addEventListener("load",'
            'function(){document.getElementById("OUT").textContent='
            "JSON.stringify(%s);});</script></body>" % self.PROBE)
        p = os.path.join(self.tmp, "m%d.html" % len(os.listdir(self.tmp)))
        with open(p, "w") as fh:
            fh.write(src)
        dom = browser.dom(p, width, 1400, budget=3000)
        m = re.search(r'<pre id="OUT">(.*?)</pre>', dom, re.S)
        self.assertTrue(m and m.group(1).strip(), "page did not render at %d" % width)
        return json.loads(m.group(1))

    def busy(self):
        """Long labels, many findings, a fault - the widest content there is."""
        self.write([detection(ago=600, title=LONG_TITLE,
                              indexer="AnimeTosho (Prowlarr) - Public Feed")]
                   + [detection(ago=900 + i * 600, ext=".e%d" % i)
                      for i in range(8)])
        return self.render(last_error="qBittorrent: Connection refused",
                           last_reap=stamp(900))

    def test_no_page_level_overflow_at_any_width(self):
        """Tables may scroll inside their own wrapper. The page may not."""
        path = self.busy()
        for w in (1920, 1600, 1440, 1366, 1280, 1024, 900, 768, 600, 500):
            with self.subTest(width=w):
                self.assertEqual(self.measure(path, w)["overflow"], 0)

    def test_the_vitals_collapse_in_the_measured_order(self):
        path = self.busy()
        self.assertEqual(self.measure(path, 1440)["vitals"], 4)
        self.assertEqual(self.measure(path, 1024)["vitals"], 4)
        self.assertEqual(self.measure(path, 900)["vitals"], 2)
        self.assertEqual(self.measure(path, 600)["vitals"], 2)

    def test_the_trends_stack_before_the_bars_become_unreadable(self):
        """Two columns save height but narrow the track, and the track is the
        card's whole content."""
        path = self.busy()
        self.assertEqual(self.measure(path, 1024)["trends"], 2)
        self.assertEqual(self.measure(path, 900)["trends"], 1)

    def test_the_bar_track_stays_usable_everywhere(self):
        path = self.busy()
        for w in (1920, 1280, 1024, 980, 900, 768, 600, 500):
            with self.subTest(width=w):
                self.assertGreaterEqual(self.measure(path, w)["bar"], 100)

    def crowded(self):
        """Both row tables at once, with the widest content each can hold.

        The Triage Queue only renders when something is actionable, so a
        fixture without intents measures half the page and passes.
        """
        rid = "aa" + "0" * 30
        self.write([lifecycle(rid, intents.FAILED_UNVERIFIED, ago=600,
                              title=LONG_TITLE),
                    detection(ago=900, rid=rid, title=LONG_TITLE,
                              indexer="AnimeTosho (Prowlarr) - Public Feed")]
                   + [detection(ago=1200 + i * 600,
                                title="Some.Release.%d.2024.2160p.BluRay-GRP" % i,
                                ext=".e%d" % i) for i in range(8)])
        recs = {}
        for i in range(5):
            h = "%040x" % i
            recs[h] = {"milestone": intents.FAILED_UNVERIFIED, "hash": h,
                       "remediation_id": rid if i == 0 else "r%030d" % i,
                       "opened": time.time() - 7200 - i * 900,
                       "updated": time.time(), "arr": "Radarr Anime",
                       "arr_type": "radarr",
                       "release_title": LONG_TITLE if i == 0 else "Bad.%d" % i,
                       "evidence": {"why": "no downloadFailed event carrying "
                                           "this infohash appeared in the arr "
                                           "history"},
                       "error": None, "search": None, "attempts": 1,
                       "queue_id": 1, "watermark": 1, "media": None,
                       "indexer": "AnimeTosho (Prowlarr) - Public Feed"}
        intents._store.mutate(lambda d: d.update(recs))
        return self.render(last_reap=stamp(900), last_scan=stamp(45))

    def test_the_row_tables_are_tables_on_desktop(self):
        """The narrow layout is an addition. Nothing above the breakpoint may
        change shape, because the desktop table is the reviewed one."""
        path = self.crowded()
        for w in (1920, 1440, 1024, 900, 870):
            with self.subTest(width=w):
                r = self.measure(path, w)
                self.assertEqual(len(r["tables"]), 2)
                for t in r["tables"]:
                    self.assertFalse(t["stacked"])
                    self.assertLessEqual(t["deficit"], 0)

    def test_nothing_is_hidden_off_the_right_below_the_breakpoint(self):
        """The failure this replaced: Issue, Outcome and Details went off the
        right edge, and the off-screen cell still set the row height, so the
        rows were 251px tall with two lines of visible text in them."""
        path = self.crowded()
        for w in (869, 768, 600, 500):
            with self.subTest(width=w):
                r = self.measure(path, w)
                self.assertEqual(len(r["tables"]), 2)
                for t in r["tables"]:
                    self.assertTrue(t["stacked"])
                    self.assertLessEqual(t["deficit"], 0)
                    self.assertEqual(t["offscreen"], 0)

    def test_each_field_prints_the_heading_it_lost(self):
        """The header row is hidden down here, so every labelled cell has to
        say what it is. The attribute being present proves nothing on its own:
        the rule that turns it into visible text is a separate thing and can
        fail on its own, leaving a card of unheaded paragraphs."""
        path = self.crowded()
        for w in (768, 500):
            r = self.measure(path, w)
            for t in r["tables"]:
                self.assertTrue(t["labels"], "no labelled cells to check")
                for attr, shown in t["labels"]:
                    with self.subTest(width=w, label=attr):
                        self.assertIn(attr, shown)

    def test_the_stacked_rows_never_push_the_page_sideways(self):
        path = self.crowded()
        for w in (869, 768, 600, 500):
            with self.subTest(width=w):
                self.assertEqual(self.measure(path, w)["overflow"], 0)

    def test_a_long_release_name_does_not_widen_the_page(self):
        self.write([detection(ago=60, title=LONG_TITLE * 2,
                              indexer="X" * 80)])
        path = self.render()
        for w in (1920, 1024, 768, 600, 500):
            with self.subTest(width=w):
                self.assertEqual(self.measure(path, w)["overflow"], 0)


if __name__ == "__main__":
    unittest.main()
