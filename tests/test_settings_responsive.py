"""Settings at the widths people actually use.

Every number asserted here was measured against this content rather than
picked, and each one has a reason that is written down next to it:

  236  the width a path-mapping input needs. `/General Storage/torrents`, the
       example in our own documentation, renders at 188px of text plus 24px of
       box; a realistic unRAID path needs 233. The generic `.row` minimum of
       160 gave these fields 179px at 768, so the documented example did not
       fit in the field that documents it.
  539  the last width where the log-file table fits. Four columns have a
       min-content width of 433px against a card that is the viewport less 106.
  200  the API key field's floor. Copy and Show take 136px of one flex line,
       which left 133px at 375 for a 64-character key.
   44  the touch target, the same number and the same reason as the History
       Details button in 0.6.1.

Browser assertions stop at 500px because chromium will not open a window
narrower than that; the same convention as tests/test_history_layout.py. The
widths below 500 are covered by the structural half of this file.

Run with:  python -m unittest discover -s tests
"""

import os
import re
import sys
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import web  # noqa: E402
import browser  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_PATH = os.path.join(ROOT, "protectarr", "static", "style.css")

# The measured numbers, named once.
MAP_MIN = 236          # a path-mapping input never narrower than this
LOG_TABLE_VW = 539     # the last width the log table fits at
SECRET_MIN = 200       # the API key field's floor
TOUCH = 44
HEADER_VW = 653       # the narrowest a dirty card header fits on one line

WIDE = (1440, 1024, 768)
NARROW = (600, 500)
ALL_WIDTHS = WIDE + NARROW


def css():
    with open(CSS_PATH) as fh:
        return fh.read()


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


class ResponsiveCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="protectarr-responsive-")
        cfg_mod.CONFIG_PATH = os.path.join(cls.tmp, "config.yaml")
        logs = os.path.join(cls.tmp, "logs")
        os.makedirs(logs, exist_ok=True)
        # Real-shaped log files, because the table's width is a function of the
        # longest filename and an empty directory would measure nothing.
        for name, size in (("protectarr.log", 412_000),
                           ("protectarr.log.2026-09-14.gz", 38_200),
                           ("protectarr.log.2026-09-13.gz", 41_900)):
            with open(os.path.join(logs, name), "wb") as fh:
                fh.write(b"x" * size)
        cfg_mod.save({
            "web": {"api_key": "0" * 64, "secret_key": "s" * 40,
                    "auth": {"method": "forms", "required": "enabled",
                             "username": "admin",
                             "password_hash": "pbkdf2:sha256:1$fake$notreal",
                             "trusted_proxies": ["172.18.0.0/16"]}},
            "detection": {"probe": {"enabled": True, "path_mappings": [
                # The path from the documentation, and a longer realistic one.
                {"from": "/General Storage/torrents", "to": "/downloads"},
                {"from": "/mnt/user/data/torrents/complete", "to": "/media"}]}},
            "safety": {"mode": "either", "allowed_categories": ["tv-sonarr"],
                       "allowed_tags": ["public"]},
            "ip_blocklist": {"enabled": True},
            "banned_ips": {"enabled": True, "ips": ["203.0.113.7"]},
            "logging": {"file_enabled": True, "path": logs},
        })
        app = web.create_app(FakeService())
        app.config["TESTING"] = True
        client = app.test_client()
        with client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"
        sheet = css()
        cls.pages = {}
        for key in ("detection-remediation", "network", "administration"):
            html = client.get(f"/settings/{key}").get_data(as_text=True)
            # file:// has no server behind /static, so both assets are inlined.
            # Function replacements: a string one would read the stylesheet's
            # CSS escapes as regex group references.
            html = re.sub(r'<link rel="stylesheet"[^>]*>',
                          lambda m: "<style>%s</style>" % sheet, html)
            html = re.sub(r'<script src="[^"]*settings\.js[^"]*"></script>',
                          lambda m: "", html)
            cls.pages[key] = html

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)


PROBE = """(function () {
  var de = document.documentElement;
  function box(el) { var r = el.getBoundingClientRect();
    return {w: Math.round(r.width), h: Math.round(r.height)}; }
  function all(sel) { return [].slice.call(document.querySelectorAll(sel)); }

  var tbl = document.querySelector('.logcards');
  var wrap = tbl ? tbl.parentNode : null;
  var secret = document.querySelector('#apikey_input');
  var lists = all('.checklist');

  return {
    vw: window.innerWidth,
    overflow: Math.max(0, de.scrollWidth - de.clientWidth),
    mapInputs: all('[name=map_from], [name=map_to]').map(function (i) {
      return box(i).w; }),
    removeBtns: all('.maprow button').map(box),
    secret: secret ? box(secret).w : null,
    tableW: tbl ? Math.round(tbl.scrollWidth) : null,
    wrapW: wrap ? Math.round(wrap.clientWidth) : null,
    rowDisplay: tbl ? getComputedStyle(tbl.querySelector('tbody tr')).display : null,
    // Generated content is not in the DOM: a label that never rendered looks
    // exactly like one that did unless the pseudo-element is asked.
    labels: tbl ? [].map.call(tbl.querySelectorAll('tbody td[data-label]'),
      function (td) { return [td.getAttribute('data-label'),
                              getComputedStyle(td, ':before').content]; }) : [],
    checkH: all('label.check').map(function (l) { return box(l).h; }),
    btnH: all('.card .body .btn, .card .body button[type=submit]')
            .filter(function (b) { return box(b).w > 0; }).map(box),
    summaryH: all('details > summary').map(box),
    listScrolls: lists.map(function (l) {
      return l.scrollHeight > l.clientHeight + 1; }),
    offRight: (function () {
      var n = 0;
      all('.content *').forEach(function (el) {
        var r = el.getBoundingClientRect();
        if (r.width && r.right > de.clientWidth + 1) n++;
      });
      return n;
    })()
  };
})()"""


@unittest.skipIf(browser.BROWSER is None, browser.REASON)
class TestGeometry(ResponsiveCase):
    def measure(self, key, width):
        src = self.pages[key].replace(
            "</body>",
            '<pre id="OUT"></pre><script>window.addEventListener("load",'
            'function(){document.getElementById("OUT").textContent='
            "JSON.stringify(%s);});</script></body>" % PROBE)
        p = os.path.join(self.tmp, "m-%s-%d.html" % (key, width))
        with open(p, "w") as fh:
            fh.write(src)
        dom = browser.dom(p, width, 1200, budget=4000)
        m = re.search(r'<pre id="OUT">(.*?)</pre>', dom, re.S)
        self.assertTrue(m and m.group(1).strip(),
                        "%s did not render at %d" % (key, width))
        return json.loads(m.group(1).replace("&quot;", '"')
                          .replace("&amp;", "&").replace("&lt;", "<")
                          .replace("&gt;", ">"))

    def test_no_page_scrolls_sideways_at_any_width(self):
        for key in self.pages:
            for w in ALL_WIDTHS:
                with self.subTest(page=key, width=w):
                    d = self.measure(key, w)
                    self.assertEqual(d["overflow"], 0)
                    self.assertEqual(d["offRight"], 0,
                                     "something is hanging off the right edge")

    def test_a_path_mapping_input_always_fits_a_real_path(self):
        """179px at 768 was the defect: our own documented example is 188."""
        for w in ALL_WIDTHS:
            with self.subTest(width=w):
                d = self.measure("detection-remediation", w)
                self.assertTrue(d["mapInputs"], "no mapping rows rendered")
                self.assertGreaterEqual(min(d["mapInputs"]), MAP_MIN)

    def test_the_remove_button_is_not_stretched_to_fill_a_column(self):
        """`flex: 1` was turning a 79px button into 321px and wrapping its
        label onto two lines."""
        for w in (1440, 768):
            with self.subTest(width=w):
                d = self.measure("detection-remediation", w)
                for b in d["removeBtns"]:
                    self.assertLess(b["w"], 160)
                    self.assertLessEqual(b["h"], 40, "the label wrapped")

    def test_the_log_table_is_a_table_while_it_fits(self):
        for w in (1440, 1024, 768, 600):
            with self.subTest(width=w):
                d = self.measure("administration", w)
                self.assertEqual(d["rowDisplay"], "table-row")
                self.assertLessEqual(d["tableW"], d["wrapW"])

    def test_the_log_table_stacks_once_it_stops_fitting(self):
        d = self.measure("administration", LOG_TABLE_VW - 39)
        self.assertEqual(d["rowDisplay"], "block")
        self.assertLessEqual(d["tableW"], d["wrapW"],
                             "stacked and still scrolling sideways")

    def test_every_stacked_log_cell_prints_the_heading_it_lost(self):
        d = self.measure("administration", LOG_TABLE_VW - 39)
        self.assertTrue(d["labels"])
        for label, content in d["labels"]:
            with self.subTest(label=label):
                self.assertIn(label, content,
                              "the ::before never rendered")

    def test_the_api_key_field_keeps_a_usable_width(self):
        for w in ALL_WIDTHS:
            with self.subTest(width=w):
                d = self.measure("administration", w)
                self.assertGreaterEqual(d["secret"], SECRET_MIN)

    def test_touch_targets_are_reachable_on_a_phone(self):
        for key in self.pages:
            d = self.measure(key, 500)
            with self.subTest(page=key):
                if d["checkH"]:
                    self.assertGreaterEqual(min(d["checkH"]), TOUCH)
                if d["btnH"]:
                    self.assertGreaterEqual(min(b["h"] for b in d["btnH"]), TOUCH)
                if d["summaryH"]:
                    self.assertGreaterEqual(min(s["h"] for s in d["summaryH"]),
                                            TOUCH)

    def test_the_desktop_is_not_given_phone_sized_controls(self):
        """The touch sizing is for touch. A 1440px desktop keeps its density."""
        d = self.measure("detection-remediation", 1440)
        self.assertLess(min(d["checkH"]), TOUCH)
        self.assertLess(min(b["h"] for b in d["btnH"]), TOUCH)

    def test_no_list_becomes_a_scroll_trap_on_a_phone(self):
        """A scroll region inside a scrolling page swallows the gesture and the
        page looks stuck."""
        d = self.measure("detection-remediation", 500)
        self.assertNotIn(True, d["listScrolls"])

    def test_the_lists_still_cap_their_height_on_a_desktop(self):
        """The cap exists so a hundred categories do not bury the form. Only
        the phone gives it up."""
        self.assertIn("max-height: 260px", css())


class TestTheBreakpointsAreDeclaredWhereTheyWereMeasured(ResponsiveCase):
    """The structural half. These also cover 430 and 375, which chromium will
    not open a window for."""

    def test_the_log_table_breakpoint_is_its_own_measured_number(self):
        sheet = css()
        self.assertIn("@media (max-width: %dpx)" % (LOG_TABLE_VW - 1), sheet)
        # Not History's. The two tables have different content and stacking
        # this one at 869 would cost density on a tablet for nothing.
        self.assertIn("@media (max-width: 869px)", sheet)
        self.assertNotEqual(LOG_TABLE_VW - 1, 869)

    def test_the_stacked_log_rules_are_scoped_to_the_log_table(self):
        sheet = css()
        block = sheet.split("@media (max-width: %dpx)" % (LOG_TABLE_VW - 1))[1]
        block = block.split("\n}\n")[0]
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith(("/*", "*", "}")):
                continue
            if "{" in line:
                for sel in line.split("{")[0].split(","):
                    sel = sel.strip()
                    if sel:
                        self.assertTrue(sel.startswith(".logcards"),
                                        "%r escapes the log table" % sel)

    def test_the_log_table_opts_in_and_labels_its_cells(self):
        html = self.pages["administration"]
        self.assertIn('class="applist logcards"', html)
        for label in ("File", "Size", "Modified"):
            self.assertIn('data-label="%s"' % label, html)

    def test_the_mapping_minimum_is_stated_rather_than_inherited(self):
        sheet = css()
        self.assertIn(".maprow > div { min-width: %dpx; }" % MAP_MIN, sheet)
        # The generic rule it overrides is still there for everything else.
        self.assertIn(".row > * { flex: 1; min-width: 160px; }", sheet)

    def test_the_secret_field_wraps_on_its_own_minimum(self):
        """No breakpoint: the buttons drop to their own line exactly when they
        stop fitting beside the input, at whatever width that is."""
        sheet = css()
        self.assertIn(".secret-field { flex-wrap: wrap; }", sheet)
        self.assertIn(".secret-field input { min-width: %dpx; }" % SECRET_MIN,
                      sheet)

    def test_touch_sizing_is_not_keyed_on_width_alone(self):
        """A tablet held in two hands is a touch device at any width."""
        self.assertIn("@media (max-width: 720px), (pointer: coarse)", css())

    def test_the_dirty_strip_takes_its_own_line_when_the_header_cannot_hold_it(self):
        """Measured, not picked: the widest dirty header is Remediation
        Policy's, which needs 587px of card and so 653px of viewport."""
        sheet = css()
        marker = "@media (max-width: %dpx)" % (HEADER_VW - 1)
        self.assertIn(marker, sheet)
        block = sheet.split(marker)[1].split("\n}\n")[0]
        self.assertIn(".card > h2 { flex-wrap: wrap; }", block)
        self.assertIn("width: 100%", block)

    def test_settings_has_one_narrow_breakpoint_not_several_guessed_ones(self):
        """The Current Policy rows stack at the same number for the same
        reason. Two breakpoints a few pixels apart drift."""
        sheet = css()
        marker = "@media (max-width: %dpx)" % (HEADER_VW - 1)
        block = sheet.split(marker)[1].split("\n}\n")[0]
        self.assertIn(".policy-row", block)
        self.assertEqual(sheet.count(marker), 1)

    def test_no_settings_template_carries_an_inline_width(self):
        """Widths belong in the stylesheet, where a breakpoint can reach them.
        The two exceptions are the small numeric fields, which are capped so a
        four-digit box does not span the card."""
        tdir = os.path.join(ROOT, "protectarr", "templates", "settings")
        for name in sorted(os.listdir(tdir)):
            with open(os.path.join(tdir, name)) as fh:
                src = fh.read()
            for m in re.finditer(r'style="([^"]*width[^"]*)"', src):
                with self.subTest(template=name, style=m.group(1)):
                    self.assertIn("max-width", m.group(1))


if __name__ == "__main__":
    unittest.main()
