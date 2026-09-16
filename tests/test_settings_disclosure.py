"""What Settings is allowed to hide, and what it is not.

0.7.0 gives each card two levels of disclosure:

  .howto   explanation. What a feature is and why it behaves the way it does.
  .adv     controls. Engine tuning most operators never touch.

Both are native <details>, which matters for a reason that is not cosmetic: a
closed <details> still submits everything inside it. `fieldset disabled` does
not, and against `save_section()`'s overwrite semantics a control that stops
being posted is a control that gets erased. The browser test at the bottom
pins that, because the entire Advanced Tuning design rests on it.

The rest of this file is the editorial contract, written down so that
"collapse the long bits" cannot drift into "collapse anything that makes the
page shorter":

  * core policy controls are never inside a disclosure,
  * safety warnings are never inside a disclosure,
  * Advanced Tuning holds only the controls agreed to be advanced,
  * a hint describes the control above it, never the one below.

Run with:  python -m unittest discover -s tests
"""

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import web  # noqa: E402
import browser  # noqa: E402

PAGES = ("detection-remediation", "network", "administration")

# Every control that must be reachable without opening anything. Taken from the
# frozen "Core Policy - always exposed" list, plus the controls that carry a
# saved value an operator is expected to read at a glance.
CORE_CONTROLS = [
    ("detection-remediation", "blocked_extensions"),
    ("detection-remediation", "blocked_name_keywords"),
    ("detection-remediation", "only_active"),
    ("detection-remediation", "archive_enabled"),
    ("detection-remediation", "dry_run"),
    ("detection-remediation", "safety_mode"),
    ("detection-remediation", "allowed_categories"),
    ("detection-remediation", "allowed_tags"),
    ("detection-remediation", "requeue_after_airdate"),
    ("detection-remediation", "orphan_dwell_minutes"),
    ("detection-remediation", "probe_enabled"),
    ("detection-remediation", "map_from"),
    ("detection-remediation", "map_to"),
    ("network", "bl_enabled"),
    ("network", "bl_url"),
    ("network", "bl_path"),
    ("network", "bl_interval"),
    ("network", "bl_apply"),
    ("network", "bl_trackers"),
    ("network", "bip_enabled"),
    ("network", "bip_ips"),
    ("network", "bip_merge"),
    ("administration", "auth_method"),
    ("administration", "auth_required"),
    ("administration", "auth_username"),
    ("administration", "auth_password"),
    ("administration", "trusted_proxies"),
    ("administration", "log_level"),
    ("administration", "log_console_level"),
    ("administration", "timezone"),
    ("administration", "log_file_enabled"),
    ("administration", "log_path"),
    ("administration", "log_retention"),
]

# The only controls Advanced Tuning is allowed to contain. Anything else in
# there is normal policy that got folded away to shorten a page.
ADVANCED_CONTROLS = {
    "airdate_grace_hours",
    "probe_steer", "probe_max", "probe_timeout", "probe_budget",
    "probe_recheck", "probe_noprogress", "probe_minspeed",
}

# Sentences that must survive in the open. Each one is the line that tells an
# operator what a switch can cost them.
SAFETY_LINES = [
    ("detection-remediation", "Legit releases are sometimes packed in RARs"),
    ("detection-remediation", "off by default"),
    ("detection-remediation", "never a removal"),
    ("network", "replaces</b> qBittorrent's whole banned list"),
    ("administration", "Credentials are redacted from every log"),
]


class FakeService:
    class _State(dict):
        def __getattr__(self, k):
            return self.get(k)

    state = _State(stats=_State(by_indexer={}), running=False,
                   blocklist=_State(), banned=_State())

    def reload(self):
        pass

    def apply_banned_ips(self, cfg):
        pass

    def update_blocklist(self, cfg, force=False):
        pass


class DisclosureCase(unittest.TestCase):
    _cache = {}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        cfg_mod.save({
            "web": {"api_key": "web-test-key-value", "secret_key": "s" * 40,
                    "auth": {"method": "none", "required": "enabled",
                             "username": "", "password_hash": "",
                             "trusted_proxies": []}},
            # Saved values on purpose: the allowlist boxes and the mapping
            # rows are only in the server-rendered HTML when something is
            # saved, and an empty config would make "the control is visible"
            # vacuously false rather than true.
            "detection": {"probe": {"path_mappings": [
                {"from": "/a", "to": "/b"}]}},
            "safety": {"allowed_categories": ["tv-sonarr"],
                       "allowed_tags": ["protectarr"]},
            "logging": {"file_enabled": False,
                        "path": os.path.join(self.dir, "logs")},
        })
        self.app = web.create_app(FakeService())
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"

    def page(self, key):
        return self.client.get(f"/settings/{key}").get_data(as_text=True)

    @staticmethod
    def body(html):
        """Just the cards, without the shell."""
        return html.split('<main class="content')[1].split("</main>")[0]

    @staticmethod
    def disclosures(html):
        """Every <details> block's inner HTML, with its class."""
        out = []
        for m in re.finditer(r'<details class="(howto|adv)">(.*?)</details>',
                             html, re.S):
            out.append((m.group(1), m.group(2)))
        return out

    def outside_disclosures(self, html):
        """The page with every <details> block removed."""
        return re.sub(r'<details class="(?:howto|adv)">.*?</details>', "",
                      html, flags=re.S)


class TestCorePolicyStaysVisible(DisclosureCase):
    def test_no_core_control_is_behind_a_disclosure(self):
        """The rule that keeps this from becoming a page-shortening exercise."""
        for key, name in CORE_CONTROLS:
            with self.subTest(control=name):
                open_html = self.outside_disclosures(self.page(key))
                self.assertIn(f'name="{name}"', open_html,
                              f"{name} is only reachable by opening something")

    def test_every_safety_line_is_in_the_open(self):
        for key, line in SAFETY_LINES:
            with self.subTest(line=line[:40]):
                self.assertIn(line, self.outside_disclosures(self.page(key)))

    def test_the_live_warning_is_in_the_open_in_both_states(self):
        """The line changes with the setting, so both versions of it have to be
        checked. The Live one is the one that matters and it is the one a
        default test config would never render."""
        for live, wanted in ((False, "nothing will be reaped"),
                             (True, "fakes will be removed for real")):
            with self.subTest(live=live):
                cfg = cfg_mod.load()
                cfg["dry_run"] = not live
                cfg_mod.save(cfg)
                html = self.outside_disclosures(self.page("detection-remediation"))
                self.assertIn(wanted, html)

    def test_lure_filenames_are_not_advanced_tuning(self):
        """Named explicitly in the brief, and an easy one to get wrong: it is a
        detector with a list, which looks like tuning and is not."""
        page = self.page("detection-remediation")
        for _, inner in [d for d in self.disclosures(page) if d[0] == "adv"]:
            self.assertNotIn("blocked_name_keywords", inner)
        self.assertIn("Lure Filenames", self.outside_disclosures(page))


class TestAdvancedTuningHoldsOnlyTuning(DisclosureCase):
    def advanced_names(self, key):
        names = set()
        for kind, inner in self.disclosures(self.page(key)):
            if kind == "adv":
                names |= set(re.findall(r'name="([^"]+)"', inner))
        return names

    def test_nothing_but_the_agreed_controls_is_collapsed(self):
        found = set()
        for key in PAGES:
            found |= self.advanced_names(key)
        self.assertEqual(found - {"csrf_token"}, ADVANCED_CONTROLS)

    def test_the_agreed_controls_really_are_collapsed(self):
        """Both directions, so a control cannot quietly graduate out of
        Advanced Tuning either."""
        page = self.page("detection-remediation")
        openp = self.outside_disclosures(page)
        for name in ADVANCED_CONTROLS:
            with self.subTest(control=name):
                self.assertIn(f'name="{name}"', page)
                self.assertNotIn(f'name="{name}"', openp)

    def test_explanation_disclosures_hold_no_controls_at_all(self):
        """`.howto` is for prose. A control in there is a control nobody will
        find, filed under a heading that does not suggest looking."""
        for key in PAGES:
            for kind, inner in self.disclosures(self.page(key)):
                if kind == "howto":
                    with self.subTest(page=key):
                        self.assertNotRegex(inner, r"<(input|select|textarea)")


class TestTheDisclosuresAreWellFormed(DisclosureCase):
    def test_every_disclosure_has_a_summary(self):
        for key in PAGES:
            for kind, inner in self.disclosures(self.page(key)):
                with self.subTest(page=key, kind=kind):
                    self.assertRegex(inner, r"<summary>[^<]+</summary>")

    def test_the_two_kinds_are_labelled_consistently(self):
        labels = set()
        for key in PAGES:
            for kind, inner in self.disclosures(self.page(key)):
                labels.add((kind, re.search(r"<summary>(.*?)</summary>",
                                            inner).group(1)))
        self.assertEqual(labels, {("howto", "How this works"),
                                  ("adv", "Advanced tuning")})

    def test_no_control_anywhere_is_disabled(self):
        """`fieldset disabled` and `disabled` drop controls from the POST, and
        against these overwrite semantics that erases them. Pinned across the
        whole of Settings so it cannot be reintroduced as a styling shortcut."""
        for key in PAGES:
            body = self.body(self.page(key))
            with self.subTest(page=key):
                self.assertNotIn("<fieldset", body)
                self.assertNotRegex(body, r"<(input|select|textarea)[^>]*\sdisabled")

    def test_a_hint_describes_the_control_above_it(self):
        """label / control / hint, in that order. A hint sitting between a
        label and its own control reads as a caption for the wrong thing."""
        for key in PAGES:
            body = self.body(self.page(key))
            bad = re.findall(
                r'<label[^>]*>(?:(?!</label>).)*</label>\s*'
                r'<p class="hint">(?:(?!</p>).)*</p>\s*'
                r'<(?:input|select|textarea)',
                body, re.S)
            with self.subTest(page=key):
                self.assertEqual(bad, [], f"{key}: hint before its control")


@unittest.skipIf(browser.BROWSER is None, browser.REASON)
class TestAClosedDisclosureStillSubmits(DisclosureCase):
    """The mechanism Advanced Tuning depends on, verified in a real browser.

    If a closed <details> ever stopped serialising its controls, every field
    inside Advanced Tuning would arrive missing and `save_section()` would
    clear it. That would not show up as a rendering bug; it would show up as an
    operator's probe budget resetting itself.
    """

    PROBE = """
    <script>
    window.addEventListener('load', function () {
      var out = {};
      document.querySelectorAll('form[action*="/settings/"]').forEach(function (f) {
        var names = [];
        new FormData(f).forEach(function (v, k) { names.push(k); });
        out[f.getAttribute('action')] = names;
      });
      out._openDetails = document.querySelectorAll('details[open]').length;
      out._details = document.querySelectorAll('details').length;
      var p = document.createElement('pre');
      p.id = 'MEASURED'; p.textContent = JSON.stringify(out);
      document.body.appendChild(p);
    });
    </script>"""

    def test_the_advanced_fields_are_in_the_form_data_while_collapsed(self):
        import json
        html = self.page("detection-remediation")
        path = os.path.join(self.dir, "page.html")
        with open(path, "w") as fh:
            fh.write(html.replace("</body>", self.PROBE + "</body>"))
        dom = browser.dom(path, 1280, 900)
        m = re.search(r'<pre id="MEASURED">(.*?)</pre>', dom, re.S)
        self.assertIsNotNone(m, "the probe did not run")
        data = json.loads(m.group(1).replace("&quot;", '"')
                          .replace("&amp;", "&").replace("&lt;", "<")
                          .replace("&gt;", ">"))

        self.assertGreater(data["_details"], 0, "no disclosures on the page")
        self.assertEqual(data["_openDetails"], 0,
                         "a disclosure starts open, so this proves nothing")

        posted = set(data["/settings/safety/save"])
        self.assertIn("airdate_grace_hours", posted)
        posted_probe = set(data["/settings/probe/save"])
        for name in ("probe_max", "probe_timeout", "probe_budget",
                     "probe_recheck", "probe_noprogress", "probe_minspeed"):
            self.assertIn(name, posted_probe)

    def test_a_collapsed_checkbox_still_reports_its_checked_state(self):
        """Checkboxes are the ones that would fail silently: an absent
        checkbox is indistinguishable from an unchecked one, so a <details>
        that dropped them would read as the operator turning steering off."""
        import json
        cfg = cfg_mod.load()
        cfg["detection"]["probe"]["steer"] = True
        cfg_mod.save(cfg)
        html = self.page("detection-remediation")
        path = os.path.join(self.dir, "steer.html")
        with open(path, "w") as fh:
            fh.write(html.replace("</body>", self.PROBE + "</body>"))
        dom = browser.dom(path, 1280, 900)
        m = re.search(r'<pre id="MEASURED">(.*?)</pre>', dom, re.S)
        data = json.loads(m.group(1).replace("&quot;", '"')
                          .replace("&amp;", "&").replace("&lt;", "<")
                          .replace("&gt;", ">"))
        self.assertIn("probe_steer", data["/settings/probe/save"])


if __name__ == "__main__":
    unittest.main()
