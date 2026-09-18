"""The Active Downloads page: what it says, and what it refuses to say.

The page is a projection of the last completed scan. Most of what is tested
here is about that sentence being visible to the operator rather than implied,
because the three states it can be in - no snapshot, stale, current - look
identical if the page only ever renders rows.
"""

import os
import re
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, intents, ownership, snapshot, web  # noqa: E402

A, B, C, D = ("a" * 40, "b" * 40, "c" * 40, "d" * 40)

TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "protectarr", "templates")


def flat(html):
    """Markup with its whitespace normalised, for asserting on prose.

    A sentence in a template is wrapped for the source, not for the reader, so
    asserting on it literally pins the indentation rather than the words. That
    cost a false failure during the 0.7.0 work when a paragraph moved into a
    disclosure and re-indented.
    """
    return re.sub(r"\s+", " ", html)


class Arr:
    def __init__(self, name, arr_type="sonarr"):
        self.name, self.type = name, arr_type


class Service:
    def __init__(self):
        self.state = {"stats": {}, "last_scan": None, "last_error": None,
                      "running": True}


CFG = {"safety": {"mode": "either", "allowed_categories": ["tv"],
                  "orphan_dwell_minutes": 10},
       "detection": {}, "arrs": [], "dry_run": False}


def torrent(thash, **over):
    t = {"hash": thash, "name": f"Release.{thash[:4]}", "state": "downloading",
         "progress": 0.4, "size": 1000, "category": "tv", "tags": "x",
         "dlspeed": 1, "eta": 1}
    t.update(over)
    return t


class PageCase(unittest.TestCase):
    def setUp(self):
        self.service = Service()
        self.app = web.create_app(self.service)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def publish(self, torrents, taken_at=None, **kw):
        kw.setdefault("resolved", {})
        kw.setdefault("owner", {})
        kw.setdefault("ownership_known", True)
        kw.setdefault("unreadable", [])
        kw.setdefault("cfg", CFG)
        kw.setdefault("arr_by_name", {})
        snap = snapshot.build(
            torrents, taken_at if taken_at is not None else time.time(),
            kw.pop("resolved"), kw.pop("owner"), kw.pop("ownership_known"),
            kw.pop("unreadable"), kw.pop("cfg"), kw.pop("arr_by_name"),
            explain=core.explain, **kw)
        return snapshot.publish(self.service.state, snap)

    def get(self):
        r = self.client.get("/active")
        self.assertEqual(r.status_code, 200)
        return r.get_data(as_text=True)


class TestTheThreeStatesArePutInWords(PageCase):

    def test_before_any_scan_it_says_so_rather_than_showing_nothing(self):
        html = self.get()
        self.assertIn("No scan has completed since Protectarr started", html)
        # No table at all, rather than an empty one. Asserted on the markup the
        # table itself emits: the class name alone also appears in the filter
        # script's selector, and `<table` in the shared dialog's builder, and
        # neither of those renders anything on its own.
        self.assertNotIn('class="applist dlcards"', html)
        self.assertNotIn("data-buckets", html)

    def test_it_does_not_claim_the_library_is_empty(self):
        """The failure mode this replaces: an outage at startup rendering as
        "nothing is downloading"."""
        html = self.get()
        self.assertNotIn("nothing downloading", html)

    def test_an_empty_snapshot_is_different_from_no_snapshot(self):
        self.publish([])
        html = self.get()
        self.assertIn("had nothing downloading", html)
        self.assertNotIn("No scan has completed", html)

    def test_a_current_snapshot_states_its_own_age(self):
        self.publish([torrent(A)])
        self.assertIn("Snapshot from the scan that finished", self.get())

    def test_a_stale_snapshot_says_the_last_scan_failed(self):
        self.publish([torrent(A)])
        self.service.state["last_error"] = "Connection refused"
        html = self.get()
        self.assertIn("Showing the last successful scan", html)
        self.assertIn("Connection refused", html)

    def test_a_stale_snapshot_still_shows_its_rows(self):
        """An outage must never empty the table."""
        self.publish([torrent(A), torrent(B)])
        self.service.state["last_error"] = "Connection refused"
        html = self.get()
        self.assertEqual(html.count('<tr data-buckets='), 2)

    def test_an_unreadable_queue_gets_its_own_banner(self):
        """Distinct from staleness. A stale snapshot is old; this one is
        current and *means less*, because with a queue unread Protectarr
        cannot attribute ownership and declines to delete anything directly."""
        self.publish([torrent(A)], ownership_known=False,
                     unreadable=["Radarr", "Sonarr"])
        html = self.get()
        self.assertIn("Could not read the queues of Radarr, Sonarr",
                      flat(html))
        self.assertIn("warnbox", html)

    def test_no_banner_when_every_queue_answered(self):
        self.publish([torrent(A)])
        self.assertNotIn("Could not read the queue", self.get())

    def test_the_banner_is_not_the_stale_notice(self):
        """Both can be true at once and they say different things."""
        self.publish([torrent(A)], ownership_known=False, unreadable=["Sonarr"])
        html = self.get()
        self.assertIn("Could not read the queue of Sonarr", flat(html))
        self.assertNotIn("Showing the last successful scan", html)

    def test_the_banner_reads_naturally_for_one_and_for_several(self):
        """One application and three produce the same sentence shape.

        `queue`/`queues` is the only thing that inflects. The sentence about
        what is still shown says "affected applications" rather than pointing
        back at the list, so it does not have to agree with a count at all.
        """
        for names, want in ((["Sonarr"], "queue of Sonarr"),
                            (["Radarr", "Sonarr"], "queues of Radarr, Sonarr"),
                            (["Lidarr", "Radarr", "Sonarr"],
                             "queues of Lidarr, Radarr, Sonarr")):
            with self.subTest(applications=len(names)):
                self.publish([torrent(A)], ownership_known=False,
                             unreadable=names)
                text = flat(self.get())
                self.assertIn(f"Could not read the {want}.", text)
                self.assertIn("Torrents owned by affected applications are "
                              "still shown with their last known owner.", text)

    def test_the_age_is_coarse_rather_than_a_stopwatch(self):
        self.publish([torrent(A)], taken_at=time.time() - 3600)
        self.assertIn("1 hour ago", self.get())


class TestTheProtectarrStateVocabulary(PageCase):
    """Decision 1: never imply that policy permission means a planned delete."""

    def state_of(self, row_over=None, **kw):
        self.publish([torrent(A, **(row_over or {}))], **kw)
        snap = snapshot.published(self.service.state)
        return web._active_rows(snap)[0]["state"]

    def test_a_healthy_covered_torrent_reads_as_monitoring(self):
        s = self.state_of()
        self.assertEqual(s["label"], "Monitoring")
        self.assertEqual(s["why"], "can remediate if a finding appears")

    def test_monitoring_never_says_anything_about_deleting(self):
        s = self.state_of()
        for word in ("delete", "remove", "will be", "queued"):
            self.assertNotIn(word, s["label"].lower())

    def test_a_conflict_reads_as_blocked_and_names_the_claimants(self):
        own = ownership.Ownership(ownership.CONFLICTED, None, None, None, None,
                                  "claimed simultaneously by Radarr, Sonarr")
        s = self.state_of(resolved={A: own})
        self.assertEqual(s["label"], "Blocked")
        self.assertIn("Radarr", s["why"])

    def test_an_owned_torrent_not_reclaimed_reads_as_blocked_and_names_it(self):
        """The refusal an operator sees when the OWNED veto fires: a paused
        torrent Sonarr owns, in a mode that would otherwise delete it."""
        own = ownership.Ownership(
            ownership.OWNED, "Sonarr", None, None, None,
            "Sonarr no longer claims it and it is not trying to download")
        s = self.state_of(resolved={A: own})
        self.assertEqual(s["label"], "Blocked")
        self.assertIn("Sonarr", s["why"])

    def test_that_refusal_does_not_claim_the_arr_currently_owns_it(self):
        """It says "previously owned", in the past tense, deliberately.

        Sonarr's queue does not list this torrent - that is the entire reason
        the veto fired. Telling someone Sonarr is tracking it sends them to a
        queue where it does not appear.
        """
        own = ownership.Ownership(ownership.OWNED, "Sonarr", None, None, None,
                                  "carried forward")
        why = self.state_of(resolved={A: own})["why"].lower()
        self.assertIn("previously owned by sonarr", why)
        for claim in ("is tracking", "currently", "claims it", "is downloading"):
            self.assertNotIn(claim, why)

    def test_that_refusal_never_inherits_the_conflict_sentence(self):
        """`_blocked_why` used to fall back to the conflict wording for every
        BLOCKED judgement, so a new reason would have told an operator that two
        applications claim a torrent that only ever had one owner."""
        own = ownership.Ownership(ownership.OWNED, "Sonarr", None, None, None,
                                  "carried forward")
        why = self.state_of(resolved={A: own})["why"].lower()
        self.assertNotIn("more than one", why)

    def test_every_blocked_reason_has_wording(self):
        """The BLOCKED twin of the NOT_COVERED sweep below. A refusal rendered
        as a bare token like `owned_not_claimed_this_pass` is not an
        explanation."""
        states = {
            "conflicted": ownership.Ownership(
                ownership.CONFLICTED, None, None, None, None, "two claims"),
            "owned": ownership.Ownership(
                ownership.OWNED, "Sonarr", None, None, None, "carried"),
            "orphan": ownership.Ownership(
                ownership.ORPHANED, "Sonarr", None, None, 60, "absent"),
            "untracked": ownership.Ownership(
                ownership.UNTRACKED, None, None, None, None, "never claimed"),
        }
        seen = set()
        for mode in ("arr_tracked", "both", "allowlist", "either"):
            for own in states.values():
                for hit in (None, ("c", {})):
                    j = core.explain({"category": "tv", "tags": ""}, hit,
                                     dict(CFG["safety"], mode=mode), True,
                                     own=own)
                    if j.state != core.BLOCKED:
                        continue
                    seen.add(j.reason)
                    why = web._blocked_why(j.reason, j.detail or {})
                    self.assertNotEqual(why, j.reason,
                                        f"{j.reason} rendered as a bare token")
        self.assertEqual(seen, {"ownership_conflict",
                                "owned_not_claimed_this_pass"})

    def test_an_orphan_inside_its_dwell_shows_both_numbers(self):
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  6 * 60, "absent")
        s = self.state_of(resolved={A: own})
        self.assertEqual(s["label"], "Waiting")
        self.assertEqual(s["why"], "orphan dwell 6m / 10m")

    def test_an_unmeasurable_dwell_says_so_instead_of_showing_zero(self):
        """Acceptance: a paused orphan must not appear to be counting down."""
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  None, "the user paused it")
        s = self.state_of({"state": "pausedDL"}, resolved={A: own})
        self.assertEqual(s["label"], "Waiting")
        self.assertIn("not being measured", s["why"])
        self.assertNotIn("0m", s["why"])

    def test_a_metadata_torrent_says_it_has_not_been_inspected(self):
        s = self.state_of({"state": "metaDL"})
        self.assertEqual(s["label"], "Waiting for metadata")

    def test_a_steered_torrent_says_the_probe_is_running(self):
        s = self.state_of(probe_on=True, steered={A: {"opened": "now"}})
        self.assertEqual(s["label"], "Probe in progress")

    def test_an_out_of_scope_torrent_names_what_would_change_it(self):
        s = self.state_of({"category": "other"})
        self.assertEqual(s["label"], "Not actionable by policy")
        self.assertIn("allowlist", s["why"])

    def test_an_unreadable_queue_is_named_rather_than_blamed_on_the_list(self):
        s = self.state_of(ownership_known=False)
        self.assertEqual(s["label"], "Not actionable by policy")
        self.assertIn("queue could not be read", s["why"])
        self.assertNotIn("allowlist", s["why"])

    def test_a_finding_outranks_everything_else(self):
        action = {"hash": A, "bad_file": "x.exe", "reason": "blocked extension",
                  "decision": "qbit_delete", "policy": {"severity": "critical"},
                  "findings": [{}]}
        s = self.state_of({"state": "metaDL"}, actions=[action])
        self.assertEqual(s["label"], "Flagged")

    def test_every_reason_token_the_engine_can_emit_has_wording(self):
        """A reason added to `explain` without wording here would render as a
        bare token like `not_tracked` in front of an operator."""
        emitted = set()
        for mode in ("arr_tracked", "both", "allowlist", "either", "bogus"):
            for hit in (None, ("c", {})):
                for allowed in (True, False):
                    for known in (True, False):
                        j = core.explain(
                            {"category": "tv" if allowed else "z", "tags": ""},
                            hit, dict(CFG["safety"], mode=mode), known)
                        if j.state == core.NOT_COVERED:
                            emitted.add(j.reason)
        self.assertTrue(emitted)
        self.assertEqual(emitted - set(web._NOT_COVERED), set())


class TestTheFilters(PageCase):
    """Decision 10, reusing the Dashboard's attention definition."""

    def publish_mixed(self):
        conflict = ownership.Ownership(ownership.CONFLICTED, None, None, None,
                                       None, "two claims")
        orphan = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                     60, "absent")
        owned = ownership.Ownership(ownership.OWNED, "Sonarr", None, {}, None,
                                    "claimed")
        self.publish([torrent(A), torrent(B), torrent(C), torrent(D)],
                     resolved={A: owned, B: orphan, C: conflict})
        return snapshot.published(self.service.state)

    def buckets(self):
        return [r["filters"].split()
                for r in web._active_rows(self.publish_mixed())]

    def test_every_row_is_in_all(self):
        self.assertTrue(all("all" in b for b in self.buckets()))

    def test_each_row_lands_in_its_ownership_bucket(self):
        got = [b[1] for b in self.buckets()]
        self.assertEqual(got, ["owned", "orphaned", "conflicted", "untracked"])

    def test_a_conflict_needs_attention(self):
        self.assertIn("attention", self.buckets()[2])

    def test_a_flagged_torrent_needs_attention(self):
        """The gap that let a mutation hide: every other attention test passes
        with the finding clause removed entirely, because a conflict and a
        failed remediation each satisfy the rest of the condition on their
        own."""
        action = {"hash": A, "bad_file": "x.exe", "reason": "blocked extension",
                  "decision": "qbit_delete", "policy": {"severity": "critical"},
                  "findings": [{}]}
        self.publish([torrent(A)], actions=[action])
        rows = web._active_rows(snapshot.published(self.service.state))
        self.assertIn("attention", rows[0]["filters"])
        self.assertTrue(rows[0]["attention"])

    def test_an_ordinary_monitored_torrent_does_not(self):
        """The other half of the same pair: without this, a mutation making
        everything need attention would pass too."""
        self.publish([torrent(A)])
        rows = web._active_rows(snapshot.published(self.service.state))
        self.assertNotIn("attention", rows[0]["filters"])
        self.assertFalse(rows[0]["attention"])

    def test_an_ordinary_orphan_does_not_need_attention(self):
        """Waiting out a dwell is Protectarr working, not a problem."""
        self.assertNotIn("attention", self.buckets()[1])

    def test_a_failed_unverified_remediation_needs_attention(self):
        """The same milestone the Dashboard's Triage Queue selects on."""
        self.publish([torrent(A)], intents_by_hash={
            A: {"milestone": intents.FAILED_UNVERIFIED}})
        rows = web._active_rows(snapshot.published(self.service.state))
        self.assertIn("attention", rows[0]["filters"])

    def test_a_pending_remediation_does_not(self):
        """Transient by design; a reconcile finishes it."""
        self.publish([torrent(A)], intents_by_hash={A: {"milestone": "pending"}})
        rows = web._active_rows(snapshot.published(self.service.state))
        self.assertNotIn("attention", rows[0]["filters"])

    def test_the_buttons_cover_exactly_the_agreed_set(self):
        self.publish([torrent(A)])
        html = self.get()
        found = re.findall(r'data-filter="(\w+)"', html)
        self.assertEqual(found, ["all", "attention", "owned", "orphaned",
                                 "conflicted", "untracked"])


class TestThePageIsReadOnly(PageCase):
    """Decision 12. v0.8.0 ships visibility and nothing else."""

    def test_the_page_contains_no_form_at_all(self):
        self.publish([torrent(A)])
        html = self.get()
        body = html[html.index("Active Downloads"):]
        self.assertNotIn("<form", body)

    def test_no_button_posts_anywhere(self):
        self.publish([torrent(A)])
        html = self.get()
        for verb in ("delete", "blocklist", "re-search", "requeue", "probe now",
                     "force", "clear conflict", "resolve"):
            self.assertNotIn(f">{verb}", html.lower())

    def test_the_only_buttons_are_details_and_the_filters(self):
        self.publish([torrent(A)])
        html = self.get()
        table = html[html.index("<tbody>"):html.index("</tbody>")]
        onclicks = re.findall(r'onclick="(\w+)', table)
        self.assertEqual(set(onclicks), {"showDetails"})

    def test_it_says_plainly_that_it_changes_nothing(self):
        self.publish([torrent(A)])
        self.assertIn("read-only view", self.get())


class TestUntrustedTextIsEscaped(PageCase):
    """The release name on this page is attacker-controlled by construction.

    Protectarr exists because someone published a torrent designed to fool the
    person who downloads it. That person names the torrent, its category and
    its tags, and this page renders all three - once as markup and once inside
    a JSON payload the Details dialog reads. Both have to hold.
    """

    EVIL = '<img src=x onerror=alert(1)>"><script>alert(2)</script>'

    def render(self):
        self.publish([torrent(A, name=self.EVIL, category=self.EVIL,
                              tags=self.EVIL)])
        return self.get()

    def test_no_executable_markup_reaches_the_document(self):
        html = self.render()
        self.assertNotIn("<script>alert(2)</script>", html)
        self.assertNotIn("<img src=x", html)

    def test_the_table_cells_escape_it(self):
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", self.render())

    def test_the_details_payload_escapes_it_too(self):
        """`tojson` turns `<` into `\\u003c`, which is what stops a release
        name closing the script element it is being embedded in."""
        html = self.render()
        blob = html[html.index("var ROWS ="):]
        blob = blob[:blob.index("</script>")]
        self.assertNotIn("<script", blob)
        self.assertNotIn("</", blob)
        self.assertIn("\\u003cscript\\u003e", blob)

    def test_a_quote_cannot_escape_the_filter_attribute(self):
        """`data-buckets` is built from the ownership state, which is a closed
        set, but the assertion is cheap and the attribute drives filtering."""
        html = self.render()
        for m in re.finditer(r'data-buckets="([^"]*)"', html):
            self.assertRegex(m.group(1), r"^[a-z ]+$")


class TestTheDetailsDossierIsTheSharedOne(PageCase):

    def test_it_includes_the_shared_partial_rather_than_redefining_it(self):
        html = open(os.path.join(TEMPLATES, "active.html")).read()
        self.assertIn('{% include "_details.html" %}', html)
        self.assertNotIn("function showDetails", html)

    def test_the_dossier_carries_the_agreed_sections(self):
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  120, "Sonarr no longer claims it")
        self.publish([torrent(A)], resolved={A: own})
        row = snapshot.published(self.service.state)["rows"][0]
        titles = [s["title"] for s in web._active_detail(row)["extra"]]
        self.assertEqual(titles, ["In qBittorrent", "Ownership", "Policy",
                                  "Content probe"])

    def test_the_conflict_claimants_only_exist_in_the_dossier(self):
        own = ownership.Ownership(ownership.CONFLICTED, None, None, None, None,
                                  "claimed simultaneously by Radarr, Sonarr")
        self.publish([torrent(A)], resolved={A: own})
        row = snapshot.published(self.service.state)["rows"][0]
        section = [s for s in web._active_detail(row)["extra"]
                   if s["title"] == "Ownership"][0]
        pairs = dict((k, v) for k, v in section["rows"])
        self.assertIn("Radarr", pairs["How Protectarr knows"])

    def test_an_orphan_reports_its_dwell_in_the_dossier(self):
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  120, "absent")
        self.publish([torrent(A)], resolved={A: own})
        row = snapshot.published(self.service.state)["rows"][0]
        section = [s for s in web._active_detail(row)["extra"]
                   if s["title"] == "Ownership"][0]
        pairs = dict((k, v) for k, v in section["rows"])
        self.assertEqual(pairs["Orphan dwell"], "absent 2m of 10m required")

    def test_an_unmeasurable_dwell_says_so_in_the_dossier_too(self):
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  None, "paused")
        self.publish([torrent(A, state="pausedDL")], resolved={A: own})
        row = snapshot.published(self.service.state)["rows"][0]
        section = [s for s in web._active_detail(row)["extra"]
                   if s["title"] == "Ownership"][0]
        pairs = dict((k, v) for k, v in section["rows"])
        self.assertEqual(pairs["Orphan dwell"], "not being measured on this pass")

    def test_the_dossier_does_not_repeat_the_profile_under_why(self):
        """`Why` is the finding section. On a torrent with no finding it used
        to render as a heading over a single Profile row, which answers a
        question nobody asked; Policy shows the profile with its source."""
        self.publish([torrent(A)])
        detail = web._active_detail(
            snapshot.published(self.service.state)["rows"][0])
        self.assertIsNone(detail.get("profile"))
        self.assertIsNone(detail["why"])
        policy = [s for s in detail["extra"] if s["title"] == "Policy"][0]
        self.assertIn("media", [v for _, v in policy["rows"]])

    def test_the_command_id_in_the_dossier_is_the_arrs(self):
        self.publish([torrent(A)], intents_by_hash={
            A: {"milestone": "pending", "remediation_id": "r1",
                "search": {"command_id": 99, "state": "started"}}})
        detail = web._active_detail(
            snapshot.published(self.service.state)["rows"][0])
        self.assertEqual(detail["search_command"], 99)

    def test_empty_rows_are_dropped_rather_than_rendered_blank(self):
        """The shared dialog's own rule; asserted here because half these
        sections are empty for an ordinary untracked torrent."""
        self.publish([torrent(A)])
        row = snapshot.published(self.service.state)["rows"][0]
        probe_rows = [s for s in web._active_detail(row)["extra"]
                      if s["title"] == "Content probe"][0]["rows"]
        self.assertTrue(any(v is None for _, v in probe_rows))


class TestTheNavigationEntry(unittest.TestCase):

    def setUp(self):
        self.html = open(os.path.join(TEMPLATES, "base.html")).read()

    def test_it_has_a_nav_link(self):
        self.assertIn("navlink('active', 'active', 'Active Downloads')",
                      self.html)

    def test_it_has_its_own_icon(self):
        self.assertIn("'active':", self.html)

    def test_it_sits_between_the_dashboard_and_history(self):
        i = self.html.index("navlink('active'")
        self.assertLess(self.html.index("navlink('dashboard'"), i)
        self.assertLess(i, self.html.index("navlink('history'"))


class TestAgeWording(unittest.TestCase):

    def test_seconds_are_not_quoted_as_a_stopwatch(self):
        self.assertEqual(web._age_text(18), "moments")
        self.assertEqual(web._age_text(89), "moments")

    def test_minutes_hours_and_days(self):
        self.assertEqual(web._age_text(90), "1 minutes")
        self.assertEqual(web._age_text(3600), "1 hour")
        self.assertEqual(web._age_text(7200), "2 hours")
        self.assertEqual(web._age_text(60 * 60 * 72), "3 days")

    def test_nothing_is_none_rather_than_zero(self):
        self.assertIsNone(web._age_text(None))

    def test_the_dwell_formatter_is_coarse_too(self):
        self.assertEqual(web._mins(360), "6m")
        self.assertEqual(web._mins(600), "10m")
        self.assertEqual(web._mins(3600), "1h")
        self.assertEqual(web._mins(3660), "1h 1m")
        self.assertIsNone(web._mins(None))


if __name__ == "__main__":
    unittest.main()
