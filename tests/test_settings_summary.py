"""What the header chips and the Current Policy box are allowed to claim.

Two rules run through all of it.

The first is that these describe *saved* configuration. They are rendered by
the server from `cfg` and nothing recomputes them in the browser, so a card
with unsaved edits keeps showing the state it would have if you navigated away.
That is asserted structurally rather than trusted.

The second is that "enabled" is not the same as "doing something". Several
configurations are switched on and provably inert: archive detection with no
indexers selected returns `[]` without looking at a file, the probe cannot
steer during a dry run, a blocklist that is not applied to qBittorrent is a
downloaded file nobody reads. A chip saying "Enabled" on any of those answers
the operator's question wrongly, which is worse than showing nothing.

The Current Policy rows are the same problem at a larger size. Every row here
came from reading `core.evaluate()` and `apply_actions()` rather than from the
labels on the form, and the edge cases are the point of the test file: a mode
that makes a row inapplicable has to say so, not quietly show a value that
cannot take effect.

Run with:  python -m unittest discover -s tests
"""

import os
import re
import sys
import copy
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import web  # noqa: E402

SONARR = {"name": "Sonarr", "type": "sonarr", "url": "http://s.invalid",
          "api_key": "sonarr-test-key"}
LIDARR = {"name": "Lidarr", "type": "lidarr", "url": "http://l.invalid",
          "api_key": "lidarr-test-key"}


def cfg(**over):
    """A saved config with the shape the summaries read, plus overrides."""
    base = {
        "dry_run": False,
        "arrs": [dict(SONARR)],
        "detection": {
            "blocked_extensions": [".exe", ".scr"],
            "archive_detection": {"enabled": False, "indexers": []},
            "probe": {"enabled": False, "steer": True},
        },
        "safety": {"mode": "arr_tracked", "allowed_categories": [],
                   "allowed_tags": [], "requeue_after_airdate": True,
                   "airdate_grace_hours": 0, "orphan_dwell_minutes": 10},
        "ip_blocklist": {"enabled": False, "apply_to_qbit": True},
        "banned_ips": {"enabled": False, "ips": []},
        "logging": {"level": "info", "file_enabled": True},
        "web": {"auth": {"method": "none", "required": "enabled"}},
    }
    out = copy.deepcopy(base)

    def merge(node, patch):
        for k, v in patch.items():
            if isinstance(v, dict) and isinstance(node.get(k), dict):
                merge(node[k], v)
            else:
                node[k] = v
    merge(out, over)
    return out


def rows(config):
    return {label: (value, muted)
            for label, value, muted in web._current_policy(config)}


class TestTheChipsDescribeWhatIsSaved(unittest.TestCase):
    def chip(self, key, config):
        return web._summaries(config)[key]

    def test_a_plain_off_switch_reads_as_disabled(self):
        for key, over in (("archive", {}),
                          ("probe", {}),
                          ("blocklist", {}),
                          ("bannedips", {})):
            with self.subTest(chip=key):
                c = self.chip(key, cfg(**over))
                self.assertEqual(c["text"], "Disabled")
                self.assertEqual(c["tone"], "off")

    def test_archive_detection_with_no_indexers_is_not_called_enabled(self):
        """The detector returns [] before looking at a file. Enabled and inert."""
        c = self.chip("archive", cfg(detection={"archive_detection": {
            "enabled": True, "indexers": []}}))
        self.assertEqual(c["text"], "Enabled, no indexers")
        self.assertEqual(c["tone"], "warn")

    def test_archive_detection_with_indexers_is_enabled(self):
        c = self.chip("archive", cfg(detection={"archive_detection": {
            "enabled": True, "indexers": ["Nyaa"]}}))
        self.assertEqual(c, {"text": "Enabled", "tone": "on"})

    def test_a_whitespace_only_indexer_does_not_count(self):
        c = self.chip("archive", cfg(detection={"archive_detection": {
            "enabled": True, "indexers": ["  "]}}))
        self.assertEqual(c["tone"], "warn")

    def test_the_probe_in_a_dry_run_says_it_cannot_steer(self):
        """`engine.inspect` refuses to steer in a dry run, so an operator
        testing with dry run on gets the free pass only."""
        c = self.chip("probe", cfg(dry_run=True,
                                   detection={"probe": {"enabled": True}}))
        self.assertEqual(c["text"], "Enabled, read-only in dry run")
        self.assertEqual(c["tone"], "warn")

    def test_the_probe_with_steering_off_says_so(self):
        c = self.chip("probe", cfg(detection={"probe": {"enabled": True,
                                                        "steer": False}}))
        self.assertEqual(c["text"], "Enabled, no steering")

    def test_a_fully_live_probe_is_just_enabled(self):
        c = self.chip("probe", cfg(detection={"probe": {"enabled": True,
                                                        "steer": True}}))
        self.assertEqual(c, {"text": "Enabled", "tone": "on"})

    def test_a_blocklist_that_is_never_applied_says_so(self):
        c = self.chip("blocklist", cfg(ip_blocklist={"enabled": True,
                                                     "apply_to_qbit": False}))
        self.assertEqual(c["text"], "Enabled, not applied")
        self.assertEqual(c["tone"], "warn")

    def test_an_empty_ban_list_is_not_called_enabled(self):
        c = self.chip("bannedips", cfg(banned_ips={"enabled": True, "ips": []}))
        self.assertEqual(c["text"], "Enabled, list empty")

    def test_the_ban_count_is_singular_when_there_is_one(self):
        one = self.chip("bannedips", cfg(banned_ips={"enabled": True,
                                                     "ips": ["203.0.113.7"]}))
        two = self.chip("bannedips", cfg(banned_ips={"enabled": True,
                                                     "ips": ["203.0.113.7",
                                                             "198.51.100.4"]}))
        self.assertEqual(one["text"], "Enabled, 1 address")
        self.assertEqual(two["text"], "Enabled, 2 addresses")

    def test_security_names_the_method_and_the_local_bypass(self):
        self.assertEqual(self.chip("security", cfg())["text"],
                         "No authentication")
        self.assertEqual(
            self.chip("security", cfg(web={"auth": {"method": "forms"}}))["text"],
            "Forms")
        self.assertEqual(
            self.chip("security", cfg(web={"auth": {
                "method": "basic", "required": "local_disabled"}}))["text"],
            "Basic, not for local addresses")

    def test_an_empty_extension_list_is_flagged_rather_than_counted(self):
        c = self.chip("detection", cfg(detection={"blocked_extensions": []}))
        self.assertEqual(c["tone"], "warn")
        self.assertEqual(c["text"], "0 extensions monitored")

    def test_logging_says_whether_a_file_is_written(self):
        self.assertIn("writing a file",
                      self.chip("logging", cfg())["text"])
        self.assertIn("no file",
                      self.chip("logging",
                                cfg(logging={"file_enabled": False}))["text"])


class TestThePolicyRowsSurviveTheEdgeCases(unittest.TestCase):
    def test_dry_run_leads_and_does_not_hide_the_rest(self):
        r = rows(cfg(dry_run=True))
        self.assertEqual(r["Mode"][0], "Dry run, nothing is removed")
        self.assertIn("Scope", r)
        self.assertIn("Replacement search", r)

    def test_live_says_so_plainly(self):
        self.assertEqual(rows(cfg())["Mode"][0],
                         "Live, fakes are removed for real")

    def test_each_mode_gets_its_own_scope_wording(self):
        want = {"arr_tracked": "Arr-tracked only",
                "either": "Arr + category fallback",
                "both": "Arr and category matched",
                "allowlist": "Category matched only"}
        for mode, label in want.items():
            with self.subTest(mode=mode):
                self.assertEqual(rows(cfg(safety={"mode": mode}))["Scope"][0],
                                 label)

    def test_arr_tracked_does_not_present_the_allowlist_as_active(self):
        """`allowlisted()` is never consulted in this mode. Showing the saved
        categories as if they were in force is the misleading simplification
        this box exists to avoid."""
        value, muted = rows(cfg(safety={"mode": "arr_tracked",
                                        "allowed_categories": ["tv"]}))[
            "Category fallback"]
        self.assertTrue(muted)
        self.assertIn("Not used in this mode", value)
        self.assertNotIn("tv", value)

    def test_an_empty_allowlist_in_a_mode_that_uses_it_says_nothing_matches(self):
        value, muted = rows(cfg(safety={"mode": "allowlist"}))["Category fallback"]
        self.assertFalse(muted)
        self.assertIn("Nothing selected", value)

    def test_tags_are_named_as_well_as_categories(self):
        """The match is category OR tag, so naming only one describes a
        narrower rule than the one in force."""
        value, _ = rows(cfg(safety={"mode": "either",
                                    "allowed_categories": ["tv-sonarr"],
                                    "allowed_tags": ["public"]}))[
            "Category fallback"]
        self.assertIn("Categories: tv-sonarr", value)
        self.assertIn("Tags: public", value)

    def test_tags_alone_are_not_described_as_categories(self):
        value, _ = rows(cfg(safety={"mode": "either",
                                    "allowed_tags": ["public"]}))[
            "Category fallback"]
        self.assertIn("Tags: public", value)
        self.assertNotIn("Categories", value)

    def test_the_orphan_dwell_is_marked_unused_where_it_cannot_apply(self):
        """Under arr_tracked and both, an orphan has no owning application, so
        nothing ever reaches the dwell."""
        for mode in ("arr_tracked", "both"):
            with self.subTest(mode=mode):
                value, muted = rows(cfg(safety={"mode": mode}))["Orphan handling"]
                self.assertTrue(muted)
                self.assertIn("Not used in this mode", value)

    def test_the_orphan_dwell_is_shown_where_it_does_apply(self):
        for mode in ("either", "allowlist"):
            with self.subTest(mode=mode):
                value, muted = rows(cfg(safety={"mode": mode,
                                                "orphan_dwell_minutes": 10}))[
                    "Orphan handling"]
                self.assertFalse(muted)
                self.assertIn("10 minutes", value)

    def test_a_zero_dwell_is_described_rather_than_printed_as_zero(self):
        value, _ = rows(cfg(safety={"mode": "either",
                                    "orphan_dwell_minutes": 0}))["Orphan handling"]
        self.assertIn("as soon as absence is confirmed", value)

    def test_one_minute_is_singular(self):
        value, _ = rows(cfg(safety={"mode": "either",
                                    "orphan_dwell_minutes": 1}))["Orphan handling"]
        self.assertIn("1 minute of", value)

    def test_replacement_search_off_is_stated_plainly(self):
        value, _ = rows(cfg(safety={"requeue_after_airdate": False}))[
            "Replacement search"]
        self.assertEqual(value, "Never. Blocklist only.")

    def test_replacement_search_names_the_verification_requirement(self):
        """It is never unconditional: an unverified removal does not search,
        because that would invite the application to grab the same release."""
        value, _ = rows(cfg())["Replacement search"]
        self.assertIn("verified removal", value)

    def test_a_fallback_delete_is_said_not_to_be_replaced(self):
        """qbit_delete has no owning application, so there is nothing to
        search with. The row must not imply otherwise."""
        for mode in ("either", "allowlist"):
            with self.subTest(mode=mode):
                value, _ = rows(cfg(safety={"mode": mode}))["Replacement search"]
                self.assertIn("never replaced", value)
        for mode in ("arr_tracked", "both"):
            with self.subTest(mode=mode):
                value, _ = rows(cfg(safety={"mode": mode}))["Replacement search"]
                self.assertNotIn("never replaced", value)

    def test_application_types_with_no_release_date_are_called_out(self):
        """Lidarr and Readarr have no air-date resource, so every search is
        held. "Enabled" would be true and useless."""
        value, _ = rows(cfg(arrs=[dict(LIDARR)]))["Replacement search"]
        self.assertIn("Always held", value)
        self.assertIn("no release date", value)

    def test_one_capable_application_is_enough(self):
        value, _ = rows(cfg(arrs=[dict(LIDARR), dict(SONARR)]))[
            "Replacement search"]
        self.assertNotIn("Always held", value)

    def test_no_applications_configured_is_said_rather_than_guessed(self):
        value, _ = rows(cfg(arrs=[]))["Replacement search"]
        self.assertIn("No applications configured", value)

    def test_the_grace_is_muted_when_the_search_is_off(self):
        value, muted = rows(cfg(safety={"requeue_after_airdate": False}))[
            "Air-date constraint"]
        self.assertTrue(muted)
        self.assertIn("Not used", value)

    def test_a_zero_grace_is_described_rather_than_printed_as_zero(self):
        value, _ = rows(cfg(safety={"airdate_grace_hours": 0}))[
            "Air-date constraint"]
        self.assertEqual(value, "As soon as it has aired")

    def test_a_grace_is_stated_in_hours(self):
        self.assertIn("1 hour after",
                      rows(cfg(safety={"airdate_grace_hours": 1}))[
                          "Air-date constraint"][0])
        self.assertIn("6 hours after",
                      rows(cfg(safety={"airdate_grace_hours": 6}))[
                          "Air-date constraint"][0])

    def test_custom_profiles_are_admitted_to(self):
        """Four places can set a profile and none of them is in this UI. A box
        that says nothing implies the default judgement everywhere."""
        self.assertNotIn("Judgement", rows(cfg()))
        for over in ({"detection": {"profile": "software"}},
                     {"detection": {"profiles": {"mine": {}}}},
                     {"safety": {"category_profiles": {"games": "software"}}},
                     {"arrs": [dict(SONARR, profile="software")]}):
            with self.subTest(over=str(over)[:40]):
                self.assertIn("Judgement", rows(cfg(**over)))

    def test_the_rows_are_in_the_agreed_order(self):
        order = [label for label, _, _ in web._current_policy(cfg())]
        self.assertEqual(order, ["Mode", "Scope", "Category fallback",
                                 "Orphan handling", "Replacement search",
                                 "Air-date constraint"])

    def test_no_row_is_ever_dropped_for_being_inapplicable(self):
        """A row that vanishes reads as a setting that was lost."""
        for mode in ("arr_tracked", "either", "both", "allowlist"):
            for requeue in (True, False):
                with self.subTest(mode=mode, requeue=requeue):
                    got = rows(cfg(safety={"mode": mode,
                                           "requeue_after_airdate": requeue}))
                    for label in ("Mode", "Scope", "Category fallback",
                                  "Orphan handling", "Replacement search",
                                  "Air-date constraint"):
                        self.assertIn(label, got)


class FakeService:
    class _State(dict):
        def __getattr__(self, k):
            return self.get(k)

    state = _State(stats=_State(by_indexer={}), running=False,
                   blocklist=_State(), banned=_State())

    def reload(self):
        pass

    def apply_banned_ips(self, c):
        pass

    def update_blocklist(self, c, force=False):
        pass


class TestTheyAreRenderedNotComputed(unittest.TestCase):
    """The promise that a chip follows saved state is only worth anything if
    the browser has no way to move it."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        cfg_mod.save(cfg(detection={"probe": {"enabled": True}},
                         dry_run=False,
                         web={"api_key": "web-test-key-value",
                              "secret_key": "s" * 40,
                              "auth": {"method": "none"}}))
        self.app = web.create_app(FakeService())
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"

    def page(self, key):
        return self.client.get(f"/settings/{key}").get_data(as_text=True)

    def body(self, key):
        return self.page(key).split('<main class="content')[1].split("</main>")[0]

    def test_the_chips_are_in_the_served_html(self):
        html = self.body("detection-remediation")
        self.assertRegex(html, r'<span class="chip on">Enabled</span>')

    def test_no_script_writes_a_chip_or_a_policy_row(self):
        for key in ("detection-remediation", "network", "administration"):
            body = self.body(key)
            with self.subTest(page=key):
                for script in re.findall(r"<script>(.*?)</script>", body, re.S):
                    self.assertNotIn("chip", script)
                    self.assertNotIn("policy", script)

    def test_the_policy_box_is_only_on_the_card_that_owns_it(self):
        self.assertIn('class="policy"', self.body("detection-remediation"))
        for key in ("network", "administration"):
            self.assertNotIn('class="policy"', self.body(key))

    def test_the_chip_follows_the_saved_value_not_the_form(self):
        """Saving a change moves the chip; nothing else does."""
        self.assertIn(">Enabled<", self.body("detection-remediation"))
        self.client.post("/settings/probe/save",
                         data={"csrf_token": "test-csrf-token"},
                         follow_redirects=True)
        html = self.body("detection-remediation")
        self.assertRegex(html, r'<span class="chip off">Disabled</span>')


if __name__ == "__main__":
    unittest.main()
