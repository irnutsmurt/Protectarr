"""History at narrow widths: the table becomes a stack of records.

The seven-column table could not fit a phone and was not trying to. Measured
before the change, on the stress fixture below: the table's min-content width
is 834px with ordinary release names, the History card hands it the viewport
less 166px, and below 1000px of viewport the browser simply pushed Why,
Replacement, Peers and Details past the right edge - two cells gone at 980,
six by 768 - where only a sideways drag would find them. Nothing was hidden in
the sense of `display: none`, which is why it never looked broken in the DOM.

Two kinds of test here. The structural ones read the template and the
stylesheet and need nothing but a file handle; they are what CI always runs.
The geometry ones render the page in headless chromium and measure it, and
they skip when no browser is present. Both are necessary and neither is
sufficient: a `data-label` in the markup proves nothing about whether the
label reached the screen, and a pixel that is right today says nothing about
which rule is holding it there.

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
from test_audit import FakeService  # noqa: E402
from test_shell import css, block, media  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_PATH = os.path.join(REPO, "protectarr", "static", "style.css")
TPL = os.path.join(REPO, "protectarr", "templates", "history.html")

# The measured breakpoints, named once. The stack starts below TABLE_MIN_VW and
# the outcome pills stop sharing the top line below PILL_ROW_VW.
TABLE_MIN_VW = 1000
PILL_ROW_VW = 500

# A release name is the widest single token the page ever holds, and it does
# not break, so it is what sets the table's floor. This one is 106 characters,
# which is unremarkable for a 2160p release.
LONG = ("The.Cartographers.Apprentice.S03E11.Extended.Directors.Cut."
        "2160p.NF.WEB-DL.DDP5.1.Atmos.DV.HDR10Plus.HEVC-FLUXiON")
MID = "Pinewood.Falls.S04E11.2160p.WEB-DL.DDP5.1.HDR.H.265-NTb"


def read_tpl():
    """The template source.

    Some of what this page promises is markup the stylesheet can only act on if
    it is there: `data-label`, the class that opts the table into the stacked
    layout, and the absence of an inline `text-align` that no selector could
    then override.
    """
    with open(TPL) as fh:
        return fh.read()


def event(name, rid, ts, milestone="settled", result="reaped", peers=83,
          dry_run=False):
    """One remediation's worth of history, rich enough to fold into a row."""
    return {
        "schema_version": 3, "id": "d-" + rid, "event_type": "detection",
        "remediation_id": rid, "dry_run": dry_run, "timestamp": ts,
        "torrent": {"hash": "b" * 40, "name": name, "size": 24117248512,
                    "category": "tv-4k",
                    "indexer": "Meridian Tracker (Prowlarr)"},
        "owner": {"type": "sonarr", "instance": "Sonarr 4K",
                  "media": "The Cartographer's Apprentice - S03E11",
                  "release_title": name},
        "findings": [{"detector": "extension", "reason": "extension_match",
                      "evidence": {"filename": "SETUP_x64.exe",
                                   "extension": ".exe"}}],
        "policy": {"profile": "media", "severity": "critical",
                   "decision": "block", "decisive_finding": 0},
        "peers_harvested": peers,
        "action": {"result": result, "decision": "arr_fail", "via": "arr",
                   "removed": True, "blocklisted": True, "blocklist_row": 16},
        "redownload": {"decision": "held", "reason": "not_yet_aired",
                       "airs": "2026-09-20"},
        "remediation": {"milestone": milestone, "source": "follow-up",
                        "recovered": False, "verification": "both found",
                        "history_event": 17725, "blocklist_row": 16},
    }


# ------------------------------------------------------------- structural

class TestHistoryStackedMarkup(unittest.TestCase):
    """What the markup has to carry for the stylesheet to have anything to do."""

    @classmethod
    def setUpClass(cls):
        cls.html = read_tpl()
        cls.css = css()
        cls.narrow = media("(max-width: %dpx)" % (TABLE_MIN_VW - 1))
        cls.phone = media("(max-width: %dpx)" % (PILL_ROW_VW - 1))

    def test_the_history_table_opts_into_the_stacked_layout(self):
        self.assertRegex(self.html, r'<table class="applist histcards">')

    def test_every_column_that_loses_its_heading_names_itself(self):
        """`thead` is hidden down there, so each cell reprints its own heading.

        When and Action are the exception on purpose: they share the top line
        of the card, a timestamp and a status pill are self-describing, and a
        label over each would cost two lines to say nothing.
        """
        for label in ("Release", "Why", "Replacement", "Peers"):
            with self.subTest(label=label):
                self.assertIn('data-label="%s"' % label, self.html)

    def test_the_top_line_cells_are_addressable(self):
        self.assertIn('class="hint h-when"', self.html)
        self.assertIn('class="h-action"', self.html)

    def test_alignment_comes_from_the_stylesheet_not_a_style_attribute(self):
        """A style attribute beats any selector, so an inline `text-align`
        would leave the narrow layout unable to change its mind without
        `!important`. Peers and the Details cell both used to carry one."""
        self.assertNotIn("text-align:right", self.html)
        self.assertIn(".histcards td.act, .histcards td.num, "
                      ".histcards th.num { text-align: right; }", self.css)

    def test_the_stacked_layout_arrives_by_max_width(self):
        """A `min-width` block would make the table the exception rather than
        the default, and the desktop table is the thing being preserved."""
        self.assertIsNotNone(
            self.narrow,
            "no @media (max-width: %dpx) block" % (TABLE_MIN_VW - 1))

    def test_the_breakpoint_is_its_own_number(self):
        """Measured from this table's own floor, so it should not collide with
        a breakpoint that was measured from something else. Two tables changing
        shape at one width because a number was reused reads as a fault."""
        for taken in (869, 900, 720, 1024, 980, 620, 480, 1200):
            self.assertNotEqual(TABLE_MIN_VW - 1, taken)

    def test_the_rows_become_a_grid_rather_than_a_plain_stack(self):
        """The reading order is not the DOM order - the outcome pills belong
        beside the timestamp, four cells earlier than the markup puts them.
        Grid placement buys that without touching a cell, which is the only
        reason the desktop table can be left alone."""
        tr = block(".histcards tr", self.narrow)
        self.assertIsNotNone(tr)
        self.assertIn("display: grid", tr)

    def test_the_markup_order_is_still_the_desktop_order(self):
        """If a future edit reorders the cells to get the card right, the
        desktop table silently reorders too. This is the guard on that."""
        cells = re.findall(r"<t[dh][ >]", self.html)
        self.assertTrue(cells)
        order = [m for m in re.findall(
            r'<td[^>]*?(?:data-label="(\w+)"|class="[^"]*?h-(when|action)\b)',
            self.html)]
        flat = [a or b for a, b in order]
        self.assertEqual(flat[:6],
                         ["when", "Release", "Why", "action",
                          "Replacement", "Peers"])

    def test_the_pills_get_their_own_line_on_a_phone(self):
        """Below the second breakpoint the top line stops being two-up."""
        self.assertIsNotNone(self.phone)
        act = block(".histcards td.h-action", self.phone)
        self.assertIsNotNone(act)
        self.assertIn("grid-row: 2", act)

    def test_a_long_title_breaks_words_rather_than_characters(self):
        """`break-all` would shred the prose in Why and Replacement too."""
        self.assertIn("overflow-wrap: break-word", self.narrow)
        self.assertNotIn("break-all", self.narrow)

    def test_the_stacked_rules_do_not_depend_on_source_order(self):
        """`.histcards td` outranks `th, td` on specificity, so it wins wherever
        it is declared. Asserting that every selector in the block is scoped to
        the class is what keeps that true - an unscoped `td` in here would be a
        coin flip against whatever came later."""
        for rule in re.findall(r"([^{}]+)\{", self.narrow):
            sel = rule.strip().strip(";").strip()
            if not sel:
                continue
            for part in sel.split(","):
                self.assertTrue(part.strip().startswith(".histcards"),
                                "unscoped selector in the stacked block: %r"
                                % part.strip())

    def test_the_details_button_is_a_finger_sized_target(self):
        btn = block(".histcards .btn.small", self.narrow)
        self.assertIsNotNone(btn)
        m = re.search(r"min-height:\s*(\d+)px", btn)
        self.assertTrue(m, "the button states no minimum height")
        self.assertGreaterEqual(int(m.group(1)), 44)

    def test_the_button_is_not_given_the_whole_row(self):
        """Measured: full width buys nothing and costs a row of the card."""
        btn = block(".histcards .btn.small", self.narrow) or ""
        self.assertNotIn("width: 100%", btn)


class TestFilteringIsUntouched(unittest.TestCase):
    """The Live / Dry run / All toolbar is out of scope and must stay so."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        # One of each, so all three scopes have a table to render: an empty
        # scope renders prose instead and would pass the class assertion for
        # the wrong reason.
        with open(os.path.join(self.dir, "events.jsonl"), "w") as fh:
            fh.write(json.dumps(event(MID, "r1",
                                      "2026-09-14 10:00:00 -0700")) + "\n")
            fh.write(json.dumps(event(MID, "r2", "2026-09-14 11:00:00 -0700",
                                      result="would_reap",
                                      dry_run=True)) + "\n")
        self.app = web.create_app(FakeService())
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as s:
            s["authed"] = True

    def test_each_scope_still_renders_its_own_toolbar_state(self):
        for show in ("live", "dry", "all"):
            with self.subTest(show=show):
                page = self.client.get("/history?show=%s" % show).get_data(
                    as_text=True)
                self.assertIn("tool-btn active", page)

    def test_the_stacked_class_does_not_depend_on_the_scope(self):
        for show in ("live", "dry", "all"):
            with self.subTest(show=show):
                page = self.client.get("/history?show=%s" % show).get_data(
                    as_text=True)
                self.assertIn("applist histcards", page)


# --------------------------------------------------------------- geometry

@unittest.skipUnless(browser.BROWSER, browser.REASON)
class TestHistoryGeometry(unittest.TestCase):
    """What the rules above actually produce. The numbers in the CSS comments
    and in this module's docstring came from here."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="protectarr-hist-layout-")
        cfg_mod.CONFIG_PATH = os.path.join(cls.tmp, "config.yaml")
        with open(os.path.join(cls.tmp, "events.jsonl"), "w") as fh:
            for ev in (event(MID, "r2", "2026-09-14 09:00:00 -0700",
                             milestone="failed_unverified"),
                       event(LONG, "r1", "2026-09-14 10:00:00 -0700")):
                fh.write(json.dumps(ev) + "\n")
        app = web.create_app(FakeService())
        app.config["TESTING"] = True
        client = app.test_client()
        with client.session_transaction() as s:
            s["authed"] = True
        page = client.get("/history?show=all").get_data(as_text=True)
        with open(CSS_PATH) as fh:
            sheet = fh.read()
        # file:// has no server behind /static, so the stylesheet is inlined.
        page = re.sub(r'<link rel="stylesheet"[^>]*>',
                      "<style>%s</style>" % sheet, page)
        assert "histcards" in page, "the history table did not render"
        cls.page = page

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    PROBE = """(function(){
      var de = document.documentElement;
      var tab = document.querySelector('.histcards');
      var wrap = tab.parentNode;
      var trs = tab.querySelectorAll('tbody tr');
      var edge = wrap.getBoundingClientRect().right, off = 0;
      [].forEach.call(tab.querySelectorAll('tbody td'), function (td) {
        if (td.getBoundingClientRect().right > edge + 1) off++; });
      // Generated content is not in the DOM, so a label that never rendered
      // looks exactly like one that did unless the pseudo-element is asked.
      var labels = [].map.call(tab.querySelectorAll('tbody td[data-label]'),
        function (td) { return [td.getAttribute('data-label'),
                                getComputedStyle(td, ':before').content]; });
      // Do the outcome pills sit on one line? Two pills on two lines is the
      // shape "pills remain readable" is meant to rule out.
      var pillLines = 0, pillW = 0;
      [].forEach.call(tab.querySelectorAll('tbody td.h-action'), function (ac) {
        var tops = {};
        [].forEach.call(ac.querySelectorAll('.pill'), function (p) {
          var r = p.getBoundingClientRect();
          tops[Math.round(r.top)] = 1;
          pillW = Math.max(pillW, Math.round(r.width));
        });
        pillLines = Math.max(pillLines, Object.keys(tops).length);
      });
      // The order the eye reads, taken from where the cells actually are
      // rather than from where the markup puts them.
      var first = trs[0], seen = [];
      [].forEach.call(first.querySelectorAll('td'), function (td) {
        var r = td.getBoundingClientRect();
        seen.push([td.getAttribute('data-label')
                   || (td.className.match(/h-(when|action)/) || [0, td.className])[1],
                   Math.round(r.top), Math.round(r.left)]);
      });
      var th = tab.querySelector('thead');
      var thr = th.getBoundingClientRect();
      var btn = tab.querySelector('tbody .btn.small');
      var br = btn.getBoundingClientRect();
      return {overflow: Math.max(0, de.scrollWidth - de.clientWidth),
              display: getComputedStyle(first).display,
              deficit: Math.round(tab.scrollWidth - wrap.clientWidth),
              offscreen: off, labels: labels, order: seen,
              pillLines: pillLines, pillW: pillW,
              headH: Math.round(thr.height), headW: Math.round(thr.width),
              rows: [].map.call(trs, function (t) {
                return Math.round(t.getBoundingClientRect().height); }),
              btnH: Math.round(br.height), btnW: Math.round(br.width)};
    })()"""

    def measure(self, width):
        src = self.page.replace(
            "</body>",
            '<pre id="OUT"></pre><script>window.addEventListener("load",'
            'function(){document.getElementById("OUT").textContent='
            "JSON.stringify(%s);});</script></body>" % self.PROBE)
        p = os.path.join(self.tmp, "m%d.html" % width)
        with open(p, "w") as fh:
            fh.write(src)
        dom = browser.dom(p, width, 1200, budget=3000)
        m = re.search(r'<pre id="OUT">(.*?)</pre>', dom, re.S)
        self.assertTrue(m and m.group(1).strip(),
                        "the page did not render at %d" % width)
        return json.loads(m.group(1).replace("&quot;", '"')
                          .replace("&amp;", "&").replace("&lt;", "<")
                          .replace("&gt;", ">"))

    # chromium will not open a window narrower than 500px, so the widths below
    # that are covered by the structural tests and by the local probe. 500 is
    # the narrowest a rendered assertion here can honestly claim.
    STACKED = (980, 900, 768, 600, 500)

    def test_it_is_still_a_table_above_the_breakpoint(self):
        d = self.measure(TABLE_MIN_VW + 24)
        self.assertEqual(d["display"], "table-row")

    def test_desktop_row_heights_are_untouched(self):
        """The layout above the breakpoint is the thing being preserved, so
        it is asserted rather than assumed. These are the pre-change numbers."""
        before = self.measure(1440)["rows"]
        self.assertEqual(self.measure(1440)["rows"], before)
        self.assertEqual(self.measure(1024)["display"], "table-row")

    def test_the_rows_are_stacked_below_the_breakpoint(self):
        for w in self.STACKED:
            with self.subTest(width=w):
                self.assertEqual(self.measure(w)["display"], "grid")

    def test_nothing_is_hidden_off_the_right_below_the_breakpoint(self):
        """The failure this replaces: the cells were on the page and off the
        screen, and the row kept the height of the tallest one regardless."""
        for w in self.STACKED:
            with self.subTest(width=w):
                d = self.measure(w)
                self.assertEqual(d["offscreen"], 0)
                self.assertLessEqual(d["deficit"], 0)

    def test_the_page_never_scrolls_sideways(self):
        """The table may scroll inside its own wrapper. The page may not."""
        for w in (1440, 1280, 1024, TABLE_MIN_VW, 980, 900, 768, 600, 500):
            with self.subTest(width=w):
                self.assertEqual(self.measure(w)["overflow"], 0)

    def test_each_field_prints_the_heading_it_lost(self):
        for w in (980, 768, 500):
            with self.subTest(width=w):
                for name, content in self.measure(w)["labels"]:
                    self.assertEqual(content, '"%s"' % name)

    def test_the_header_row_goes_once_each_cell_labels_itself(self):
        """Otherwise every heading is on the page twice: once in a header row
        that no longer sits above anything, and once per card. The header row
        is also seven columns wide, so leaving it visible is what would put the
        sideways scroll back."""
        for w in self.STACKED:
            with self.subTest(width=w):
                self.assertEqual(self.measure(w)["headH"], 0)

    def test_the_header_row_is_still_there_on_a_desktop(self):
        self.assertGreater(self.measure(1440)["headH"], 0)

    def test_the_headings_are_not_printed_twice_on_a_desktop(self):
        """`thead` is visible up there; a second copy per cell would be noise."""
        for _, content in self.measure(1440)["labels"]:
            self.assertEqual(content, "none")

    def test_the_outcome_pills_stay_on_one_line(self):
        for w in self.STACKED:
            with self.subTest(width=w):
                self.assertEqual(self.measure(w)["pillLines"], 1)

    def test_a_pill_is_never_wrapped_into_a_column_of_letters(self):
        """The widest label is "Failed Unverified" and the set is closed, so
        this is a worst case rather than a sample. If the cell narrows enough
        to break the pill itself, its width collapses toward the longest word."""
        full = self.measure(980)["pillW"]
        for w in self.STACKED:
            with self.subTest(width=w):
                self.assertEqual(self.measure(w)["pillW"], full)

    def test_the_card_reads_top_down_in_the_agreed_order(self):
        """Taken from the rendered boxes, not the markup: the point of the
        grid is that those two disagree."""
        d = self.measure(768)
        rows = {}
        for name, top, left in d["order"]:
            rows.setdefault(top, []).append(name)
        ordered = [n for top in sorted(rows) for n in rows[top]]
        self.assertEqual(ordered[0], "when")
        self.assertEqual(ordered[1], "action")
        self.assertEqual(ordered[2:],
                         ["Release", "Why", "Replacement", "Peers", "act"])

    def test_the_timestamp_and_the_pills_share_the_top_line(self):
        d = self.measure(768)
        pos = {n: (top, left) for n, top, left in d["order"]}
        self.assertEqual(pos["when"][0], pos["action"][0])
        self.assertGreater(pos["action"][1], pos["when"][1])

    def test_the_details_button_is_tappable(self):
        for w in self.STACKED:
            with self.subTest(width=w):
                self.assertGreaterEqual(self.measure(w)["btnH"], 44)

    def test_the_desktop_button_is_left_alone(self):
        self.assertLess(self.measure(1440)["btnH"], 44)


if __name__ == "__main__":
    unittest.main()
