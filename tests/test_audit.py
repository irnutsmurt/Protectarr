"""The audit trail: what an operator can find out afterwards, from History.

The gap this closes: `intents.reconcile()` performed the two transitions that
most need explaining - a remediation recovered after a crash, and one that
deliberately failed closed - and wrote nothing but a log line. The dashboard
counted a reap, History showed the reap, and then the story stopped. Whether
the replacement search ever finished, and whether Protectarr had quietly
refused to search at all, existed only in a file nobody reads until something
has already gone wrong.

Every test here asserts on structure rather than on prose appearing somewhere
in the page. A page extends `base.html`, so `assertIn("Protectarr")` passes on
every route in the application; that mistake was made once during the version
work and it is not worth making twice.

Run with:  python -m unittest discover -s tests
"""

import os
import re
import sys
import json
import time
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The remediation fakes live next door; reusing them keeps one definition of
# what an *arr answers rather than two that drift.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, events, intents, web  # noqa: E402

from test_intents import (FakeArr, HASH, VERIFIED, UNVERIFIED,  # noqa: E402
                          action, conf, queue_record)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class AuditCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        intents._store.reset()

    def reap(self, client, **over):
        core.apply_actions([action(client=client)], {"stats": core.load_stats()},
                           conf(**over))

    def rows(self):
        return web._history_rows(events.read(limit=50))

    def stranded(self, **over):
        """An intent left behind by an EARLIER process.

        `opened` predates `intents._STARTED`, which is the only honest
        definition of "recovered after a restart" available in-process:
        reconcile runs on every scan, so the transition being made by reconcile
        says nothing on its own.
        """
        rec = {"milestone": intents.PENDING, "hash": HASH,
               "remediation_id": "rid-from-an-earlier-run",
               "arr": "Sonarr", "arr_type": "sonarr", "queue_id": 42,
               "media": {"episodeId": 16801}, "release_title": "Rel",
               "indexer": "IX", "watermark": 100,
               "opened": intents._STARTED - 5000, "updated": time.time(),
               "attempts": 0, "evidence": None, "search": None, "error": None}
        rec.update(over)
        intents._store.mutate(lambda d: d.__setitem__(HASH, rec))
        return rec


class TestReconcileWritesAudit(AuditCase):
    def test_a_settled_search_reaches_history(self):
        client = FakeArr()
        self.reap(client)
        before = len(events.read(limit=50))
        intents.reconcile([client])
        after = events.read(limit=50)
        self.assertEqual(len(after), before + 1, "reconcile wrote nothing")
        self.assertEqual(after[0]["event_type"], "remediation")
        self.assertEqual(after[0]["remediation"]["milestone"], intents.SETTLED)

    def test_a_recovered_removal_reaches_history(self):
        self.stranded()
        intents.reconcile([FakeArr()])
        ev = events.read(limit=50)[0]
        self.assertEqual(ev["remediation"]["milestone"], intents.REMOVED)
        self.assertTrue(ev["remediation"]["recovered"])

    def test_failed_unverified_reaches_history(self):
        """The whole point. Protectarr refused to act and said so."""
        self.stranded()
        intents.reconcile([FakeArr(evidence=UNVERIFIED)])
        ev = events.read(limit=50)[0]
        self.assertEqual(ev["remediation"]["milestone"],
                         intents.FAILED_UNVERIFIED)
        self.assertEqual(ev["remediation"]["verification"], UNVERIFIED["why"])

    def test_an_unreachable_arr_writes_nothing(self):
        """No transition, no event. An outage is not a remediation outcome."""
        self.stranded()
        intents.reconcile([FakeArr(evidence={
            "verified": False, "reachable": False, "event": None,
            "blocklist": None, "why": "could not read Sonarr's history"})])
        self.assertEqual(events.read(limit=50), [])

    def test_audit_events_are_live_not_dry_run(self):
        """Otherwise the default History filter would hide every one of them."""
        self.stranded()
        intents.reconcile([FakeArr()])
        self.assertEqual(len(events.read(limit=50, dry_run=False)), 1)
        self.assertEqual(events.read(limit=50, dry_run=True), [])

    def test_the_intent_record_is_not_dumped_wholesale(self):
        """`intents.json` is recovery state; the event is a projection of it.

        Queue ids, watermarks and attempt counters are operational detail that
        would age into noise, and the audit trail has to outlive the intent.
        """
        self.stranded()
        intents.reconcile([FakeArr()])
        blob = json.dumps(events.read(limit=50)[0])
        for leaked in ("watermark", "queue_id", "attempts"):
            self.assertNotIn(leaked, blob)


class TestRemediationIdentity(AuditCase):
    def test_the_reap_and_its_follow_up_share_an_id(self):
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        ids = {e.get("remediation_id") for e in events.read(limit=50)}
        self.assertEqual(len(ids), 1)
        self.assertNotIn(None, ids)

    def test_two_remediations_of_one_hash_stay_separate(self):
        """Not hypothetical: this happened during the live acceptance run.

        A release was reaped, Radarr grabbed it again as its own replacement,
        and it was reaped a second time. Keyed on the infohash, the two would
        fold into one row and the first one's outcome would vanish.
        """
        first = FakeArr()
        self.reap(first)
        intents.reconcile([first])
        intents._store.mutate(lambda d: d.__setitem__(
            HASH, dict(d[HASH], milestone=intents.SETTLED)))
        self.reap(FakeArr())

        rows = self.rows()
        self.assertEqual(len(rows), 2, "two remediations folded into one row")
        self.assertNotEqual(rows[0]["ev"].get("remediation_id"),
                            rows[1]["ev"].get("remediation_id"))

    def test_events_without_an_id_are_never_folded_together(self):
        """A warn and a category-fallback delete have no lifecycle at all."""
        rows = web._history_rows([
            {"timestamp": "t2", "torrent": {"name": "A"}, "action": {"result": "warned"}},
            {"timestamp": "t1", "torrent": {"name": "B"}, "action": {"result": "warned"}},
        ])
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["status"] for r in rows], [None, None])


class TestHistoryFold(AuditCase):
    def test_one_row_carries_the_latest_status_and_the_original_finding(self):
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])

        rows = self.rows()
        self.assertEqual(len(rows), 1, "the lifecycle event became its own row")
        self.assertEqual(rows[0]["status"]["milestone"], intents.SETTLED)
        # The finding lives on the detection event, which is the older of the
        # two. A fold that kept only the newest would lose it.
        self.assertIn("x.exe", rows[0]["why"])

    def test_the_fold_keeps_the_detection_events_other_columns(self):
        """Regression: the first fold re-derived only the finding.

        Size and the requeue decision live on the detection event too, and a
        row that took them from the newest lifecycle event showed a dash for
        both.
        """
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        row = self.rows()[0]
        self.assertNotEqual(row["requeue"], "-")
        self.assertIn("searched", row["requeue"])

    def test_the_timeline_holds_every_event_for_the_remediation(self):
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        self.assertEqual(len(self.rows()[0]["timeline"]), 2)


class TestStatusPills(AuditCase):
    def pill(self, milestone, **rem):
        row = {"ev": {}, "latest": {"remediation": dict(
            {"milestone": milestone}, **rem)}, "timeline": []}
        return web._history_status(row)

    def test_settled_is_positive(self):
        self.assertEqual(self.pill("settled")["label"], "Settled")
        self.assertEqual(self.pill("settled")["cls"], "on")

    def test_settled_does_not_claim_a_replacement_arrived(self):
        """The distinction the terminal *arr message exists to preserve."""
        self.assertIn("does not mean a replacement was downloaded",
                      self.pill("settled")["why"])

    def test_failed_unverified_is_prominent(self):
        got = self.pill("failed_unverified")
        self.assertEqual(got["label"], "Failed Unverified")
        self.assertEqual(got["cls"], "bad", "it must not read as a neutral grey")

    def test_failed_unverified_explains_that_nothing_was_searched(self):
        self.assertIn("stopped rather than searching",
                      self.pill("failed_unverified")["why"])

    def test_an_unfinished_remediation_reads_as_pending(self):
        self.assertEqual(self.pill("pending")["label"], "Pending")
        self.assertEqual(self.pill("removed")["label"], "Pending")

    def test_removed_still_says_what_it_is_waiting_for(self):
        """Compressed to one pill, not lost: the line underneath is exact."""
        self.assertIn("waiting for the replacement search",
                      self.pill("removed")["why"])

    def test_work_left_by_an_earlier_process_reads_as_recovering(self):
        self.assertEqual(self.pill("pending", recovered=True)["label"],
                         "Recovering")

    def test_a_finished_remediation_is_not_labelled_recovering(self):
        self.assertEqual(self.pill("settled", recovered=True)["label"],
                         "Settled")

    def test_the_bad_pill_exists_in_the_stylesheet(self):
        """A class no CSS defines renders as unstyled text, silently."""
        with open(os.path.join(REPO, "protectarr", "static", "style.css")) as fh:
            css = fh.read()
        self.assertIn(".pill.bad", css)
        self.assertIn("--danger", css.split(".pill.bad")[1][:120])


class TestDetailViewModel(AuditCase):
    def detail(self):
        return web._detail(self.rows()[0])

    def test_the_terminal_search_message_survives_into_the_dialog(self):
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        self.assertEqual(self.detail()["search_message"],
                         "0 reports downloaded")

    def test_the_oracle_evidence_is_available(self):
        self.reap(FakeArr())
        got = self.detail()
        self.assertEqual(got["history_event"], 101)
        self.assertEqual(got["blocklist_row"], 7)
        self.assertEqual(got["verification"], VERIFIED["why"])

    def test_a_failed_unverified_reason_is_available(self):
        self.stranded()
        intents.reconcile([FakeArr(evidence=UNVERIFIED)])
        self.assertEqual(self.detail()["verification"], UNVERIFIED["why"])

    def test_recovery_is_reported_only_when_it_happened(self):
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        self.assertFalse(self.detail()["recovered"],
                         "routine follow-up was labelled a crash recovery")

        intents._store.reset()
        os.remove(os.path.join(self.dir, "events.jsonl"))
        self.stranded()
        intents.reconcile([FakeArr()])
        self.assertTrue(self.detail()["recovered"])

    def test_it_is_an_allowlist_not_a_dump(self):
        """It is serialised into the page, so the fields are named.

        Same reasoning as `_arrs_for_browser`: a denylist fails open on the day
        someone adds a field and forgets this function exists.
        """
        self.reap(FakeArr())
        row = self.rows()[0]
        row["ev"]["torrent"]["secret_field"] = "SHOULD-NOT-APPEAR"
        self.assertNotIn("SHOULD-NOT-APPEAR", json.dumps(web._detail(row)))

    def test_absent_fields_are_present_as_none_for_the_dialog_to_drop(self):
        rows = web._history_rows([{"timestamp": "t", "torrent": {"name": "A"},
                                   "action": {"result": "warned"}}])
        got = web._detail(rows[0])
        self.assertIsNone(got["search_message"])
        self.assertIsNone(got["history_event"])
        self.assertIsNone(got["status"])


class TestPreviewGuarantee(AuditCase):
    def test_the_backend_states_that_it_was_observational(self):
        svc = core.ProtectarrService()
        svc.state["stats"] = core.load_stats()
        real = core.scan
        core.scan = lambda cfg, state, side_effects=True: []
        try:
            out = svc.preview()
        finally:
            core.scan = real
        self.assertTrue(out["observational"])
        self.assertEqual(out["actions"], [])

    def test_the_flag_and_the_scan_come_from_one_decision(self):
        """So a caller cannot make preview side-effecting and keep the claim.

        Asserts on the source: the value passed to `scan` is the same local the
        flag is derived from, rather than two independent literals that happen
        to agree today.
        """
        with open(os.path.join(REPO, "protectarr", "core.py")) as fh:
            src = fh.read()
        body = src.split("def preview(self):")[1].split("def apply_banned_ips")[0]
        self.assertIn("side_effects = False", body)
        self.assertIn("side_effects=side_effects", body)
        self.assertIn('"observational": not side_effects', body)

    def test_the_ui_only_claims_safety_when_the_backend_says_so(self):
        """The message must live inside the `observational === true` branch."""
        with open(os.path.join(REPO, "protectarr", "templates", "_js.html")) as fh:
            js = fh.read()
        self.assertIn("r.observational === true", js)
        guarded = js.split("r.observational === true")[1].split(": ''")[0]
        self.assertIn("no priorities, files, or remediation state were changed",
                      guarded)

    def test_the_ui_does_not_claim_nothing_was_done(self):
        """Preview still reads qBittorrent and the *arrs, and reads free bytes."""
        with open(os.path.join(REPO, "protectarr", "templates", "_js.html")) as fh:
            js = fh.read()
        self.assertNotIn("nothing was done", js.lower())
        self.assertIn("still read qBittorrent", js)


class Loose(dict):
    def __missing__(self, key):
        return Loose()


class FakeService:
    state = Loose(stats=Loose(by_indexer={}), running=False)

    def reload(self):
        pass

    def preview(self):
        return {"observational": True, "actions": []}


class WebCase(AuditCase):
    """A live Flask client, so these assert on what a browser is actually sent."""

    QBIT_PASS = "qbit-test-password-value"
    SONARR_KEY = "sonarr-test-api-key-value"

    def setUp(self):
        super().setUp()
        cfg_mod.save({
            "web": {"host": "0.0.0.0", "port": 8090, "api_key": "web-test-key-value",
                    "secret_key": "s" * 40,
                    "auth": {"method": "none", "required": "enabled",
                             "username": "", "password_hash": "",
                             "trusted_proxies": []}},
            "qbittorrent": {"url": "http://qb:8080", "username": "admin",
                            "password": self.QBIT_PASS, "api_key": "",
                            "verify_ssl": True, "web_url": ""},
            "arrs": [{"name": "Sonarr", "type": "sonarr", "url": "http://s:8989",
                      "api_key": self.SONARR_KEY}],
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

    def save(self, section, **fields):
        fields["csrf_token"] = "test-csrf-token"
        return self.client.post(f"/settings/{section}/save", data=fields,
                                follow_redirects=True)


class TestNewSettingsAreSaved(WebCase):
    SAFETY = {"safety_mode": "either", "airdate_grace_hours": "0"}
    PROBE = {"probe_max": "1", "probe_timeout": "120", "probe_budget": "120",
             "probe_recheck": "15", "probe_minspeed": "20"}

    def test_the_orphan_dwell_field_is_on_the_reaping_rules_page(self):
        """Asserted on the input, not on text that could come from base.html."""
        html = self.client.get("/settings/safety").get_data(as_text=True)
        self.assertIn('name="orphan_dwell_minutes"', html)
        self.assertIn("Ownership &amp; Orphan Handling", html)

    def test_the_orphan_dwell_help_keeps_the_key_semantic(self):
        """"Could not observe" must not read as "confirmed absent"."""
        html = self.client.get("/settings/safety").get_data(as_text=True)
        self.assertIn("continuously confirmed absent", html)
        self.assertIn("does\n        <b>not</b> count", html)

    def test_orphan_dwell_saves(self):
        self.save("safety", orphan_dwell_minutes="25", **self.SAFETY)
        self.assertEqual(cfg_mod.load()["safety"]["orphan_dwell_minutes"], 25)

    def test_orphan_dwell_is_clamped(self):
        self.save("safety", orphan_dwell_minutes="99999", **self.SAFETY)
        self.assertEqual(cfg_mod.load()["safety"]["orphan_dwell_minutes"], 1440)
        self.save("safety", orphan_dwell_minutes="-5", **self.SAFETY)
        self.assertEqual(cfg_mod.load()["safety"]["orphan_dwell_minutes"], 0)

    def test_orphan_dwell_survives_rubbish(self):
        self.save("safety", orphan_dwell_minutes="30", **self.SAFETY)
        self.save("safety", orphan_dwell_minutes="not a number", **self.SAFETY)
        self.assertEqual(cfg_mod.load()["safety"]["orphan_dwell_minutes"], 30)

    def test_the_no_progress_field_is_on_the_probe_page(self):
        html = self.client.get("/settings/probe").get_data(as_text=True)
        self.assertIn('name="probe_noprogress"', html)

    def test_the_no_progress_help_does_not_claim_whole_file_progress(self):
        """It watches one piece. The file can advance while that piece does not."""
        html = self.client.get("/settings/probe").get_data(as_text=True)
        self.assertIn("opening piece", html)
        self.assertIn("not the file's overall progress", html)

    def test_no_progress_seconds_saves(self):
        self.save("probe", probe_noprogress="45", **self.PROBE)
        pr = cfg_mod.load()["detection"]["probe"]
        self.assertEqual(pr["no_progress_seconds"], 45)

    def test_no_progress_seconds_is_clamped(self):
        self.save("probe", probe_noprogress="99999", **self.PROBE)
        self.assertEqual(
            cfg_mod.load()["detection"]["probe"]["no_progress_seconds"], 900)

    def test_the_prune_interval_stays_out_of_the_ui(self):
        """Measured cheap and not something a user has a reason to tune."""
        for path in ("/settings/safety", "/settings/probe"):
            html = self.client.get(path).get_data(as_text=True)
            self.assertNotIn("ownership_prune_minutes", html)


class TestHistoryPageRenders(WebCase):
    def test_a_remediation_row_shows_its_status_pill(self):
        """Asserted on the pill element, which base.html does not contain."""
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        html = self.client.get("/history").get_data(as_text=True)
        self.assertIn('<span class="pill on">Settled</span>', html)

    def test_a_failed_unverified_row_is_visually_prominent(self):
        self.stranded()
        intents.reconcile([FakeArr(evidence=UNVERIFIED)])
        html = self.client.get("/history").get_data(as_text=True)
        self.assertIn('<span class="pill bad">Failed Unverified</span>', html)

    def test_every_row_offers_details(self):
        self.reap(FakeArr())
        html = self.client.get("/history").get_data(as_text=True)
        self.assertIn('onclick="showDetails(0)"', html)

    def test_the_detail_payload_reaches_the_page(self):
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        html = self.client.get("/history").get_data(as_text=True)
        blob = re.search(r"var ROWS = (\[.*?\]);", html, re.S)
        self.assertIsNotNone(blob, "the details view model was not rendered")
        rows = json.loads(blob.group(1))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["search_message"], "0 reports downloaded")

    def test_an_empty_history_still_renders(self):
        self.assertEqual(self.client.get("/history").status_code, 200)


class TestHistoryTableLayout(WebCase):
    """The v0.3.0 layout regression, asserted structurally rather than in pixels.

    What broke: the Action cell inherited `white-space: nowrap` from when it
    held one pill and a short line. v0.3.0 put the remediation status in there,
    whose unverified wording runs to about 105 characters. Unwrapped, that set
    a 636px MINIMUM on the column - measured in chromium - and a table cannot
    shrink below a column's minimum. Everything else was squeezed around it
    (Release fell to 116px and wrapped to 441px tall) and the table overflowed
    its scroll container by 101px, putting the Details button off the edge.

    A pixel assertion would be brittle across font stacks and would fail on a
    CI runner for reasons that have nothing to do with this bug. The invariant
    worth keeping is structural: no cell holding variable-length prose may
    refuse to wrap.
    """

    LONG = ("Les Murs vagabonds / Drifting Home / Ame wo Tsugeru Hyouryuu "
            "Danchi (2022) [Blu-Ray JPN 1080p-HEVC Multi VF / VOSTFR / Eng]")

    def body(self):
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        html = self.client.get("/history").get_data(as_text=True)
        return html, html.split('<table class="applist">')[1].split("</table>")[0]

    def test_no_history_cell_refuses_to_wrap(self):
        """The actual regression. Any nowrap cell can pin the table open."""
        _, table = self.body()
        offenders = [c[:90] for c in re.findall(r"<td[^>]*>", table)
                     if "nowrap" in c]
        self.assertEqual(offenders, [], "a History cell sets white-space:nowrap, "
                                        "which can hold the table wider than "
                                        "its container")

    def test_the_details_button_is_not_the_toolbar_button(self):
        """`.tool-btn` is the toolbar's icon-over-label flex style.

        In a table cell it is both oversized and the wrong vocabulary;
        `.btn.small` already exists for a control inside a table.
        """
        _, table = self.body()
        button = re.search(r"<button[^>]*showDetails[^>]*>", table).group(0)
        self.assertNotIn("tool-btn", button)
        self.assertIn("btn small", button)

    def test_the_table_keeps_a_scroll_container_for_narrow_screens(self):
        """The fallback below tablet width, where no layout fits.

        Deliberately on the table's own wrapper, so the page itself never
        scrolls horizontally.
        """
        html, _ = self.body()
        before = html.split('<table class="applist">')[0]
        self.assertIn("overflow-x:auto", before.rsplit("<div", 1)[-1])

    def test_every_column_survived_the_fix(self):
        """A layout fix that quietly drops a column is not a fix."""
        html, table = self.body()
        head = table.split("<thead>")[1].split("</thead>")[0]
        heads = re.findall(r"<th[^>]*>(.*?)</th>", head, re.S)
        self.assertEqual([h.strip() for h in heads],
                         ["When", "Release", "Why", "Action", "Replacement",
                          "Peers", ""])
        cells = re.findall(r"<td", table.split("<tbody>")[1])
        self.assertEqual(len(cells) % 7, 0, "a row lost or gained a cell")

    def test_a_very_long_release_name_does_not_add_a_nowrap_cell(self):
        """The content that made the bug visible, run through the page."""
        events.record({
            "event_type": "detection", "dry_run": False,
            "timestamp": "2026-09-12 23:17:45 -0700",
            "torrent": {"hash": "f" * 40, "name": self.LONG, "size": 1011654820,
                        "category": "tv", "indexer": "LimeTorrents (Prowlarr)"},
            "owner": {"type": "sonarr", "instance": "Sonarr", "media": "X",
                      "release_title": self.LONG},
            "findings": [{"detector": "extension", "reason": "extension_match",
                          "evidence": {"filename": "x.exe", "extension": ".exe"}}],
            "policy": {"profile": "media", "severity": "critical",
                       "decision": "block", "decisive_finding": 0},
            "action": {"result": "reaped", "decision": "arr_fail", "via": "arr",
                       "removed": True, "blocklisted": False,
                       "verification": "no downloadFailed event for this infohash"},
            "redownload": {"decision": "held", "reason": "not_yet_aired"},
        })
        html = self.client.get("/history").get_data(as_text=True)
        table = html.split('<table class="applist">')[1].split("</table>")[0]
        self.assertIn(self.LONG, table)
        self.assertEqual([c for c in re.findall(r"<td[^>]*>", table)
                          if "nowrap" in c], [])


class TestNoCredentialRegression(WebCase):
    def test_no_page_leaks_a_credential(self):
        """The sweep, extended to the pages this pass touched.

        History now serialises a view model into the page, which is exactly the
        shape of change that leaks something later.
        """
        client = FakeArr()
        self.reap(client)
        intents.reconcile([client])
        secrets = (self.QBIT_PASS, self.SONARR_KEY, "web-test-key-value")
        for path in ("/", "/dashboard", "/history", "/system",
                     "/settings/safety", "/settings/probe",
                     "/settings/security", "/settings/logging"):
            html = self.client.get(path).get_data(as_text=True)
            for s in secrets:
                self.assertNotIn(s, html, f"{s[:8]}... leaked into {path}")

    def test_the_credential_placeholders_are_not_submitted_values(self):
        """No mask sentinel: the inputs are empty and the hint is a placeholder."""
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('placeholder="(unchanged)"', html)
        self.assertNotIn('value="(unchanged)"', html)
        self.assertNotIn('value="********"', html)


if __name__ == "__main__":
    unittest.main()
