"""How deep History reaches, and what it does when it runs out of evidence.

v0.3.0 added lifecycle events without changing the page's read budget, which
broke two things quietly. The page read a fixed 400 raw events and folded
whatever came back:

  * three events per remediation meant 400 events were only ~134 rows, so the
    page's depth fell to roughly a third of what 0.2.x showed and nothing said
    so;
  * a remediation straddling the 400th event was built from its lifecycle
    event alone, producing a row that asserted "Settled" next to no finding,
    no severity and no action - an audit trail claiming Protectarr settled
    something it never detected.

The fix bounds *rows* and streams events, so these tests are mostly about the
boundary: a remediation whose evidence sits just past wherever the reader
happened to stop must still come back whole, and one whose evidence has
genuinely rotated away must say that rather than render blanks.

Run with:  python -m unittest discover -s tests
"""

import os
import re
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import events, web  # noqa: E402

# Imported at module scope deliberately. test_audit sets `cfg_mod.CONFIG_PATH`
# in its module body, so importing it from inside setUp re-points the config
# directory *after* setUp has chosen one, and the first test to trigger the
# import reads an empty event store. Paying that side effect once, here, before
# any setUp runs, is what keeps it from being a test-ordering landmine.
from test_audit import FakeService  # noqa: E402


def detection(rid=None, name="Rel", dry_run=False, ts="2026-09-14 10:00:00 -0700"):
    """The rich event: findings, policy, torrent record, action."""
    ev = {"schema_version": 3, "id": f"d-{rid or name}", "event_type": "detection",
          "dry_run": dry_run, "timestamp": ts,
          "torrent": {"hash": "A" * 40, "name": name, "size": 1011654820,
                      "category": "tv", "indexer": "IX"},
          "owner": {"type": "sonarr", "instance": "Sonarr", "media": "Show",
                    "release_title": name},
          "findings": [{"detector": "extension", "reason": "extension_match",
                        "evidence": {"filename": name + ".exe",
                                     "extension": ".exe"}}],
          "policy": {"profile": "media", "severity": "critical",
                     "decision": "block", "decisive_finding": 0},
          "peers_harvested": 83,
          "action": {"result": "reaped", "decision": "arr_fail", "via": "arr",
                     "removed": True, "blocklisted": True},
          "redownload": {"decision": "held", "reason": "not_yet_aired",
                         "airs": "2026-09-20"}}
    if rid:
        ev["remediation_id"] = rid
    return ev


def lifecycle(rid, milestone="settled", dry_run=False,
              ts="2026-09-14 11:00:00 -0700", name="Rel"):
    """The thin event, shaped as intents.audit() writes it.

    Carries a torrent block and an owner block but no findings, no policy and
    no action, which is exactly why a row built from one alone is degraded.
    """
    return {"schema_version": 3, "id": f"l-{rid}-{milestone}",
            "event_type": "remediation", "remediation_id": rid,
            "dry_run": dry_run, "timestamp": ts,
            "torrent": {"hash": "A" * 40, "name": name, "indexer": "IX"},
            "owner": {"type": "sonarr", "instance": "Sonarr", "media": None,
                      "release_title": name},
            "remediation": {"milestone": milestone, "source": "follow-up",
                            "recovered": False, "verification": "both found",
                            "history_event": 17725, "blocklist_row": 16}}


class StoreCase(unittest.TestCase):
    """Writes event files directly, including rotated ones.

    `events.record()` cannot place an event in `events.jsonl.1` without
    generating 5 MB of filler first, and the rotation boundary is one of the
    things being tested.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")

    def write(self, evs, rotation=0):
        """`rotation=0` is events.jsonl, 1 is .jsonl.1, 2 is .jsonl.2."""
        path = os.path.join(self.dir, "events.jsonl")
        if rotation:
            path = f"{path}.{rotation}"
        with open(path, "a") as fh:
            for ev in evs:
                fh.write(json.dumps(ev, separators=(",", ":")) + "\n")

    def rows(self, limit=web.HISTORY_LIMIT, dry_run=None):
        return web._history_rows(events.iter_events(dry_run=dry_run), limit=limit)


class TestReverseReader(StoreCase):
    """`_reversed_lines` underpins every ordering guarantee above it."""

    def lines(self, text, chunk):
        p = os.path.join(self.dir, "f.jsonl")
        with open(p, "w") as fh:
            fh.write(text)
        return [l.decode() for l in events._reversed_lines(p, chunk=chunk)]

    def test_it_yields_lines_last_first(self):
        self.assertEqual(self.lines("a\nb\nc\n", 65536), ["c", "b", "a"])

    def test_ordering_survives_every_chunk_boundary(self):
        """A chunk boundary lands mid-line for most chunk sizes.

        Swept rather than spot-checked: the carry-over of a partial leading
        fragment is the whole trick, and an off-by-one there would show up at
        one specific alignment and nowhere else.
        """
        src = [f"line{i:03d}" for i in range(40)]
        want = list(reversed(src))
        for chunk in range(1, 45):
            self.assertEqual(self.lines("\n".join(src) + "\n", chunk), want,
                             f"wrong order at chunk={chunk}")

    def test_a_file_with_no_trailing_newline_keeps_its_last_line(self):
        self.assertEqual(self.lines("a\nbb\nccc", 4), ["ccc", "bb", "a"])

    def test_blank_lines_are_skipped(self):
        self.assertEqual(self.lines("a\n\n\nb\n", 2), ["b", "a"])

    def test_an_empty_file_yields_nothing(self):
        self.assertEqual(self.lines("", 16), [])

    def test_a_line_longer_than_the_chunk_is_returned_whole(self):
        long = "x" * 5000
        self.assertEqual(self.lines(f"a\n{long}\n", 64), [long, "a"])

    def test_a_missing_file_is_not_an_error(self):
        gone = os.path.join(self.dir, "nope.jsonl")
        self.assertEqual(list(events._reversed_lines(gone)), [])


class TestIterEvents(StoreCase):
    def test_newest_first_within_one_file(self):
        self.write([detection(name="old"), detection(name="mid"),
                    detection(name="new")])
        got = [e["torrent"]["name"] for e in events.iter_events()]
        self.assertEqual(got, ["new", "mid", "old"])

    def test_newest_first_across_the_rotation_boundary(self):
        """Rotation never interleaves, so file order carries the ordering."""
        self.write([detection(name="oldest")], rotation=2)
        self.write([detection(name="middle")], rotation=1)
        self.write([detection(name="newest")])
        got = [e["torrent"]["name"] for e in events.iter_events()]
        self.assertEqual(got, ["newest", "middle", "oldest"])

    def test_it_is_lazy_and_does_not_open_files_it_does_not_reach(self):
        """The point of the rewrite: depth is paid for, not pre-paid.

        Spies on which paths get opened rather than timing anything, because a
        timing assertion would pass on a fast machine regardless.
        """
        self.write([detection(name=f"old{i}") for i in range(5)], rotation=1)
        self.write([detection(name=f"new{i}") for i in range(5)])
        opened = []
        real = events._reversed_lines

        def spy(path, **kw):
            opened.append(os.path.basename(path))
            return real(path, **kw)

        events._reversed_lines = spy
        try:
            it = events.iter_events()
            next(it), next(it)
        finally:
            events._reversed_lines = real
        self.assertEqual(opened, ["events.jsonl"])
        self.assertNotIn("events.jsonl.1", opened)

    def test_read_still_returns_a_capped_list(self):
        """`/api/v1/events` keeps its old contract."""
        self.write([detection(name=f"r{i}") for i in range(10)])
        got = events.read(limit=3)
        self.assertIsInstance(got, list)
        self.assertEqual(len(got), 3)


class TestLifecycleSplitAcrossBoundaries(StoreCase):
    """A remediation must come back whole regardless of where reading stopped."""

    def test_evidence_beyond_the_former_400_event_cap_is_still_found(self):
        """The exact shape that produced a degraded row before this change.

        Newest-first the stream is: two lifecycle events for X, then 400
        unrelated detections, then X's detection event at position 403. The old
        reader stopped at 400 and built X from a lifecycle event alone.
        """
        self.write([detection(rid="X", name="Wanted")])
        self.write([detection(name=f"filler{i:03d}") for i in range(400)])
        self.write([lifecycle("X", "removed", ts="2026-09-14 12:00:00 -0700",
                              name="Wanted"),
                    lifecycle("X", "settled", ts="2026-09-14 13:00:00 -0700",
                              name="Wanted")])
        row = self.rows()[0]
        self.assertFalse(row["base_missing"])
        self.assertEqual(row["status"]["label"], "Settled")
        # The evidence the old code lost.
        self.assertIn("Monitored extension .exe", row["why"])
        self.assertEqual(row["severity"], "critical")
        self.assertEqual(row["ev"]["action"]["result"], "reaped")
        self.assertIsNotNone(row["size"])

    def test_evidence_in_a_rotated_file_is_still_found(self):
        self.write([detection(rid="X", name="Wanted")], rotation=1)
        self.write([lifecycle("X", "settled", name="Wanted")])
        row = self.rows()[0]
        self.assertFalse(row["base_missing"])
        self.assertIn("Monitored extension .exe", row["why"])
        self.assertEqual(row["ev"]["action"]["result"], "reaped")

    def test_evidence_two_rotations_back_is_still_found(self):
        self.write([detection(rid="X", name="Wanted")], rotation=2)
        self.write([detection(name=f"filler{i}") for i in range(30)], rotation=1)
        self.write([lifecycle("X", "settled", name="Wanted")])
        row = self.rows()[0]
        self.assertFalse(row["base_missing"])
        self.assertIn("Monitored extension .exe", row["why"])

    def test_a_group_first_seen_past_the_limit_does_not_extend_the_read(self):
        """Step 5: only groups already on the page justify reading further.

        A pending group below the 250th row cannot change what is rendered, so
        chasing its evidence would be work with no visible effect.
        """
        self.write([detection(rid="TooOld", name="TooOld")])
        self.write([detection(name=f"filler{i:03d}") for i in range(300)])
        self.write([lifecycle("TooOld", "settled", name="TooOld")])
        opened = []
        real = events._reversed_lines

        def spy(path, **kw):
            opened.append(os.path.basename(path))
            return real(path, **kw)

        events._reversed_lines = spy
        try:
            rows = self.rows()
        finally:
            events._reversed_lines = real
        self.assertEqual(len(rows), web.HISTORY_LIMIT)
        # It stopped inside events.jsonl and never went looking in the
        # rotated files for an event belonging to a row nobody can see.
        self.assertEqual(opened, ["events.jsonl"])


class TestEvidenceGenuinelyGone(StoreCase):
    def test_a_row_whose_detection_event_rotated_away_says_so(self):
        self.write([lifecycle("X", "settled", name="Orphaned")])
        row = self.rows()[0]
        self.assertTrue(row["base_missing"])
        self.assertEqual(row["status"]["label"], "Settled")

    def test_it_is_not_silently_dropped(self):
        """Dropping it would hide a remediation that genuinely happened."""
        self.write([lifecycle("X", "settled", name="Orphaned")])
        self.assertEqual(len(self.rows()), 1)

    def test_the_page_names_the_missing_evidence(self):
        self.write([lifecycle("X", "settled", name="Orphaned")])
        rows = self.rows()
        self.assertEqual(web._detail(rows[0])["why"],
                         "Detection event no longer retained")
        self.assertTrue(web._detail(rows[0])["base_missing"])

    def test_a_complete_row_is_not_marked_truncated(self):
        self.write([detection(rid="X", name="Fine")])
        self.write([lifecycle("X", "settled", name="Fine")])
        row = self.rows()[0]
        self.assertFalse(row["base_missing"])
        self.assertNotEqual(web._detail(row)["why"],
                            "Detection event no longer retained")


class TestDepthIsRowsNotEvents(StoreCase):
    def test_lifecycle_events_no_longer_eat_into_page_depth(self):
        """300 remediations at 3 events each is 900 events and 250 rows.

        Under the old fixed 400-event read this returned about 134 rows. The
        page's reach must depend on how many things happened, not on how
        talkative each one was.
        """
        for i in range(300):
            rid = f"r{i:03d}"
            self.write([detection(rid=rid, name=f"Rel{i:03d}"),
                        lifecycle(rid, "removed", name=f"Rel{i:03d}"),
                        lifecycle(rid, "settled", name=f"Rel{i:03d}")])
        rows = self.rows()
        self.assertEqual(len(rows), web.HISTORY_LIMIT)
        self.assertTrue(all(not r["base_missing"] for r in rows))
        self.assertTrue(all(len(r["timeline"]) == 3 for r in rows))

    def test_no_raw_event_cap_governs_the_page(self):
        """Guards against a fixed read budget being reintroduced.

        Asserts on the route, so it fails if `history()` goes back to calling
        `events.read(limit=N)`.
        """
        for i in range(260):
            rid = f"r{i:03d}"
            self.write([detection(rid=rid, name=f"Rel{i:03d}"),
                        lifecycle(rid, "removed", name=f"Rel{i:03d}"),
                        lifecycle(rid, "settled", name=f"Rel{i:03d}")])
        rows = self.rows()
        self.assertEqual(len(rows), 250)
        self.assertEqual(sum(len(r["timeline"]) for r in rows), 750)

    def test_newest_250_are_the_ones_kept(self):
        for i in range(300):
            self.write([detection(name=f"Rel{i:03d}",
                                  ts=f"2026-09-14 {i // 60:02d}:{i % 60:02d}:00 -0700")])
        rows = self.rows()
        names = [r["ev"]["torrent"]["name"] for r in rows]
        self.assertEqual(len(names), 250)
        self.assertEqual(names[0], "Rel299")
        self.assertEqual(names[-1], "Rel050")
        self.assertEqual(names, sorted(names, reverse=True))
        self.assertNotIn("Rel049", names)


class TestFilteringAndFooter(StoreCase):
    """Counts and wording for Live, Dry run and All."""

    def setUp(self):
        super().setUp()
        cfg_mod.save({
            "web": {"host": "0.0.0.0", "port": 8090, "api_key": "web-test-key-value",
                    "secret_key": "s" * 40,
                    "auth": {"method": "none", "required": "enabled",
                             "username": "", "password_hash": "",
                             "trusted_proxies": []}},
            "qbittorrent": {"url": "http://qb:8080", "username": "admin",
                            "password": "qbit-test-password-value", "api_key": "",
                            "verify_ssl": True, "web_url": ""},
            "arrs": [{"name": "Sonarr", "type": "sonarr", "url": "http://s:8989",
                      "api_key": "sonarr-test-api-key-value"}],
            "logging": {"level": "info", "console_level": "error",
                        "file_enabled": False,
                        "path": os.path.join(self.dir, "logs"),
                        "retention_days": 3},
        })
        self.app = web.create_app(FakeService())
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"

    def footer(self, show):
        html = self.client.get(f"/history?show={show}").get_data(as_text=True)
        m = re.search(r"Showing[^.]*\.", html)
        return re.sub(r"\s+", " ", m.group(0)).strip() if m else None

    def test_live_excludes_dry_run_events(self):
        self.write([detection(name="Real"), detection(name="Test", dry_run=True)])
        self.assertEqual(len(self.rows(dry_run=False)), 1)
        self.assertEqual(self.rows(dry_run=False)[0]["ev"]["torrent"]["name"],
                         "Real")

    def test_dry_excludes_live_events(self):
        self.write([detection(name="Real"), detection(name="Test", dry_run=True)])
        self.assertEqual(len(self.rows(dry_run=True)), 1)
        self.assertEqual(self.rows(dry_run=True)[0]["ev"]["torrent"]["name"],
                         "Test")

    def test_all_includes_both(self):
        self.write([detection(name="Real"), detection(name="Test", dry_run=True)])
        self.assertEqual(len(self.rows(dry_run=None)), 2)

    def test_a_lifecycle_row_is_folded_before_the_filter_count(self):
        """Filtering happens on events, folding after, so a dry-run lifecycle
        event never joins a live row."""
        self.write([detection(rid="X", name="Rel"),
                    lifecycle("X", "settled", name="Rel"),
                    lifecycle("X", "removed", dry_run=True, name="Rel")])
        live = self.rows(dry_run=False)
        self.assertEqual(len(live), 1)
        self.assertEqual(len(live[0]["timeline"]), 2)

    # ---- wording ----

    def test_the_footer_says_entries_not_events(self):
        """`event(s)` stopped being true when one row began folding several."""
        self.write([detection(rid="X", name="Rel"),
                    lifecycle("X", "settled", name="Rel"),
                    detection(rid="Y", name="Rel2"),
                    lifecycle("Y", "settled", name="Rel2")])
        self.assertIn("history entries", self.footer("live"))
        self.assertNotIn("event(s)", self.footer("live"))

    def test_it_reports_the_event_count_when_folding_changed_it(self):
        for i in range(3):
            rid = f"r{i}"
            self.write([detection(rid=rid, name=f"Rel{i}"),
                        lifecycle(rid, "settled", name=f"Rel{i}")])
        self.assertEqual(self.footer("live"),
                         "Showing 3 history entries from 6 events, live only.")

    def test_it_omits_the_event_count_when_nothing_was_folded(self):
        self.write([detection(name="A"), detection(name="B")])
        self.assertEqual(self.footer("live"),
                         "Showing 2 history entries, live only.")

    def test_a_single_entry_is_singular(self):
        self.write([detection(name="Only")])
        self.assertEqual(self.footer("live"), "Showing 1 history entry, live only.")

    def test_dry_run_wording(self):
        self.write([detection(name="Test", dry_run=True)])
        self.assertEqual(self.footer("dry"),
                         "Showing 1 history entry, dry run only.")

    def test_all_has_no_scope_clause(self):
        """"all" has no qualifier to add, and "all only" would be nonsense."""
        self.write([detection(name="A"), detection(name="B", dry_run=True)])
        self.assertEqual(self.footer("all"), "Showing 2 history entries.")

    def test_the_truncated_row_renders_its_explanation(self):
        """Asserted on the cell markup, not on the text being present.

        `_detail()` also carries this string into the `var ROWS` JSON, so
        `assertIn("Detection event no longer retained", html)` passes with the
        template branch deleted. Mutation testing caught that; the span is what
        actually proves the Why cell renders it.
        """
        self.write([lifecycle("X", "settled", name="Orphaned")])
        html = self.client.get("/history?show=live").get_data(as_text=True)
        self.assertIn('<span class="hint">Detection event no longer retained</span>',
                      html)
        # The status it does know is still shown, so the row is not just a
        # shrug: something was settled, the evidence for it is what is gone.
        self.assertIn('<span class="pill on">Settled</span>', html)


if __name__ == "__main__":
    unittest.main()
