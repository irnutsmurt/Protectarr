"""What the Active Downloads table actually does at each width.

The brief for this page was "do not repeat the History-table problem", so the
numbers here are the point rather than decoration. History's desktop table has
a 1366px floor because a release name is one unbreakable token and nothing caps
the cell it lives in. This table caps it, and these tests are what stop the cap
being removed by someone who does not know what it was for.

The measured floor is 688px, which is a 854px viewport. The stacked layout
still starts at 999px, matching History, so there is 145px of deliberate
headroom - see the stylesheet for why that is a choice rather than a constraint.
"""

import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, ownership, snapshot, web  # noqa: E402
from tests import browser  # noqa: E402

CSS_PATH = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "protectarr", "static", "style.css")

# The floor this page is designed to hold, and the viewport it implies once the
# card has taken its gutter. Both measured; see the class docstring.
TABLE_FLOOR = 688
CARD_GUTTER = 166
STACK_AT = 999

# The case History cannot survive: one unbreakable 124-character token.
LONG = ("Some.Very.Long.Show.Name.With.Extra.Words.And.More.Words.S04E11."
        "2160p.WEB-DL.DDP5.1.Atmos.DV.HDR.H.265-SOMEVERYLONGGROUPNAME")

A, B, C, D = ("a" * 40, "b" * 40, "c" * 40, "d" * 40)


class FakeService:
    def __init__(self, state):
        self.state = state


def torrent(thash, name, **over):
    t = {"hash": thash, "name": name, "state": "downloading", "progress": 0.39,
         "size": 20_300_000_000, "category": "tv-sonarr", "tags": "protectarr",
         "dlspeed": 4_500_000, "eta": 2700}
    t.update(over)
    return t


CFG = {"safety": {"mode": "either", "allowed_categories": ["tv-sonarr"],
                  "orphan_dwell_minutes": 10},
       "detection": {}, "arrs": [], "dry_run": False}


def build_page(long_name=False):
    """The real page, with the stylesheet inlined so file:// can render it."""
    first = LONG if long_name else \
        "Some.Show.S04E11.2160p.WEB-DL.DDP5.1.Atmos.DV.HDR.H.265-GROUPNAME"
    torrents = [
        torrent(A, first),
        torrent(B, "Another.Movie.2024.1080p.BluRay.REMUX.AVC.DTS-HD.MA.5.1-GRP"),
        torrent(C, "Contested.Release.S02E05.2160p.WEB-DL-GROUP"),
        torrent(D, "Stalled.Pack.S01.COMPLETE.1080p.WEB-DL-TEAM",
                state="stalledDL", progress=0.02),
    ]
    resolved = {
        A: ownership.Ownership(ownership.OWNED, "Sonarr", None, {}, None,
                               "claimed by its owner"),
        C: ownership.Ownership(ownership.CONFLICTED, None, None, None, None,
                               "claimed simultaneously by Radarr, Sonarr"),
        D: ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                               6 * 60, "Sonarr no longer claims it"),
    }
    state = {"stats": {}, "last_scan": None, "last_error": None,
             "running": True}
    snapshot.publish(state, snapshot.build(
        torrents, time.time() - 30, resolved, {}, True, [], CFG, {},
        intents_by_hash={C: {"milestone": "failed_unverified",
                             "remediation_id": "r1", "arr": "Sonarr",
                             "error": "no history event"}},
        explain=core.explain))

    app = web.create_app(FakeService(state))
    app.config["TESTING"] = True
    page = app.test_client().get("/active").get_data(as_text=True)
    with open(CSS_PATH) as fh:
        sheet = fh.read()
    # A function replacement, not a string: `re.sub` processes backslash
    # escapes in a string replacement and the stylesheet carries CSS escapes
    # like `\25B8`, which it reads as a group reference and refuses.
    page = re.sub(r'<link rel="stylesheet"[^>]*>',
                  lambda m: "<style>%s</style>" % sheet, page)
    assert 'class="applist dlcards"' in page, "the table did not render"
    return page


class TestTheStackedRulesAreDeclared(unittest.TestCase):
    """Structural, so they hold on a machine with no browser."""

    @classmethod
    def setUpClass(cls):
        with open(CSS_PATH) as fh:
            cls.css = fh.read()
        cls.page = build_page()

    def block(self, needle):
        i = self.css.index(needle)
        start = self.css.rindex("@media", 0, i)
        return self.css[start:self.css.index("\n}", i) + 2]

    def test_the_table_opts_into_the_stacked_layout(self):
        self.assertIn('class="applist dlcards"', self.page)

    def test_the_stacked_layout_arrives_by_max_width(self):
        blk = self.block(".dlcards, .dlcards tbody, .dlcards td")
        self.assertRegex(blk.split("{")[0], r"max-width:\s*\d+px")

    def test_it_stacks_at_the_same_width_as_history(self):
        """Two tables on adjacent pages changing shape at different widths
        reads as a rendering fault."""
        blk = self.block(".dlcards, .dlcards tbody, .dlcards td")
        px = int(re.search(r"max-width:\s*(\d+)px", blk).group(1))
        self.assertEqual(px, STACK_AT)
        hist = self.block(".histcards, .histcards tbody")
        self.assertEqual(int(re.search(r"max-width:\s*(\d+)px", hist).group(1)),
                         px)

    def test_every_column_that_loses_its_heading_names_itself(self):
        """Once `thead` is gone the label is all the cell has."""
        # Scoped to the table's own head. The shared Details dialog builds
        # `<th>` in a JavaScript string, and matching that produced a
        # "heading" of `' + esc(p[0]) + '`.
        head = self.page[self.page.index('class="applist dlcards"'):]
        head = head[head.index("<thead>"):head.index("</thead>")]
        headings = [h.strip() for h in re.findall(r"<th[^>]*>([^<]*)</th>", head)
                    if h.strip()]
        self.assertTrue(headings, "no column headings were found")
        for h in headings:
            self.assertIn(f'data-label="{h}"', self.page,
                          f"the {h} column has no stacked label")

    def test_the_release_cell_is_capped(self):
        """The one rule the whole floor depends on."""
        self.assertIn(".dlcards td.dl-name { max-width: 260px; }", self.css)
        self.assertIn("overflow-wrap: anywhere", self.css)

    def test_the_cap_is_lifted_once_the_rows_are_cards(self):
        """A 260px block in a full-width card would waste most of the line."""
        blk = self.block(".dlcards, .dlcards tbody, .dlcards td")
        self.assertIn(".dlcards td.dl-name { max-width: none; }", blk)

    def test_no_nowrap_was_added_to_the_state_cell(self):
        """History learned this one the hard way: an unwrappable sentence sets
        a floor on its column and the table cannot shrink past it."""
        for m in re.finditer(r"\.dlcards[^{]*\{([^}]*)\}", self.css):
            self.assertNotIn("nowrap", m.group(1))


@unittest.skipUnless(browser.BROWSER, browser.REASON)
class TestActiveGeometry(unittest.TestCase):
    """What those rules actually produce. The numbers in the stylesheet's
    comments came from here."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="protectarr-active-layout-")
        cls.page = build_page()
        cls.long_page = build_page(long_name=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    PROBE = """(function(){
      var de = document.documentElement;
      var tab = document.querySelector('.dlcards');
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
      var btn = tab.querySelector('tbody .btn.small');
      var br = btn.getBoundingClientRect();
      return {overflow: Math.max(0, de.scrollWidth - de.clientWidth),
              display: getComputedStyle(trs[0]).display,
              deficit: Math.round(tab.scrollWidth - wrap.clientWidth),
              offscreen: off, labels: labels,
              btnH: Math.round(br.height), btnW: Math.round(br.width),
              rows: [].map.call(trs, function (t) {
                return Math.round(t.getBoundingClientRect().height); })};
    })()"""

    FLOOR_PROBE = """(function(){
      var tab = document.querySelector('.dlcards');
      tab.parentNode.style.width = 'min-content';
      return {floor: Math.ceil(tab.getBoundingClientRect().width),
              release: Math.ceil(
                tab.querySelector('thead th').getBoundingClientRect().width)};
    })()"""

    def probe(self, width, probe=None, page=None, name="m"):
        src = (page or self.page).replace(
            "</body>",
            '<pre id="OUT"></pre><script>window.addEventListener("load",'
            'function(){document.getElementById("OUT").textContent='
            "JSON.stringify(%s);});</script></body>" % (probe or self.PROBE))
        p = os.path.join(self.tmp, "%s%d.html" % (name, width))
        with open(p, "w") as fh:
            fh.write(src)
        dom = browser.dom(p, width, 1200, budget=3000)
        m = re.search(r'<pre id="OUT">(.*?)</pre>', dom, re.S)
        self.assertTrue(m and m.group(1).strip(),
                        "the page did not render at %d" % width)
        return json.loads(m.group(1).replace("&quot;", '"')
                          .replace("&amp;", "&").replace("&lt;", "<")
                          .replace("&gt;", ">"))

    # Chromium will not open a window narrower than 500px, so 500 is the
    # narrowest a rendered assertion here can honestly claim.
    WIDTHS = (1440, 1280, 1024, 1000, 999, 900, 768, 600, 500)

    def test_the_table_floor_is_what_the_stylesheet_claims(self):
        d = self.probe(1600, probe=self.FLOOR_PROBE, name="floor")
        self.assertEqual(d["floor"], TABLE_FLOOR)

    def test_a_pathological_release_name_does_not_move_the_floor(self):
        """The entire reason for the cap. History's floor moves to 1366px
        under this exact test; this one must not move at all."""
        ordinary = self.probe(1600, probe=self.FLOOR_PROBE, name="floor")
        long_ = self.probe(1600, probe=self.FLOOR_PROBE, page=self.long_page,
                           name="floorlong")
        self.assertEqual(long_["floor"], ordinary["floor"])
        self.assertEqual(long_["release"], ordinary["release"])

    def test_the_floor_leaves_real_headroom_above_the_breakpoint(self):
        """If a future column eats this, the breakpoint has to move with it."""
        self.assertLess(TABLE_FLOOR + CARD_GUTTER, STACK_AT)

    def test_it_is_a_table_above_the_breakpoint(self):
        self.assertEqual(self.probe(STACK_AT + 1)["display"], "table-row")

    def test_it_is_stacked_below_the_breakpoint(self):
        self.assertNotEqual(self.probe(STACK_AT)["display"], "table-row")

    def test_the_page_never_scrolls_sideways(self):
        for w in self.WIDTHS:
            with self.subTest(width=w):
                self.assertEqual(self.probe(w)["overflow"], 0)

    def test_nothing_is_hidden_off_the_right_at_any_width(self):
        for w in self.WIDTHS:
            with self.subTest(width=w):
                d = self.probe(w)
                self.assertEqual(d["offscreen"], 0)
                self.assertLessEqual(d["deficit"], 0)

    def test_a_long_name_does_not_overflow_the_page_either(self):
        for w in (1440, 1024, 768, 600, 500):
            with self.subTest(width=w):
                d = self.probe(w, page=self.long_page, name="long")
                self.assertEqual(d["overflow"], 0)
                self.assertEqual(d["offscreen"], 0)

    def test_each_field_prints_the_heading_it_lost(self):
        for name, content in self.probe(768)["labels"]:
            self.assertIn(name, content,
                          f"{name} did not print its label when stacked")

    def test_the_headings_are_not_printed_twice_on_a_desktop(self):
        for _, content in self.probe(1440)["labels"]:
            self.assertIn(content, ("none", "normal"))

    def test_the_details_button_is_tappable_when_stacked(self):
        """44px, the same target History's card uses."""
        for w in (999, 900, 768, 600, 500):
            with self.subTest(width=w):
                self.assertGreaterEqual(self.probe(w)["btnH"], 44)

    def test_the_desktop_button_is_left_alone(self):
        self.assertLess(self.probe(1440)["btnH"], 44)

    def test_the_short_fields_share_lines_when_stacked(self):
        """Measured: one field per line put the card at 460px, and 172px of it
        was four cells each spending a 43px line on one short word. Two
        columns took that to 319px.

        Asserted as "these cells sit beside each other" rather than as a total
        height. A row carrying a real remediation explanation is legitimately
        taller than one that is not - the conflicted row in this fixture is
        413px and should be - so a height cap would either be loose enough to
        pass a single-column regression or tight enough to fail on content.
        """
        d = self.probe(768, probe="""(function(){
          var out = [];
          [].forEach.call(document.querySelectorAll('.dlcards tbody tr'),
            function (tr) {
              var tops = {};
              [].forEach.call(tr.querySelectorAll('td[data-label]'),
                function (td) {
                  if (getComputedStyle(td).display === 'none') return;
                  var t = Math.round(td.getBoundingClientRect().top);
                  (tops[t] = tops[t] || []).push(td.getAttribute('data-label'));
                });
              out.push(Object.keys(tops).map(function (k) { return tops[k]; }));
            });
          return {lines: out};
        })()""", name="pairs")
        for lines in d["lines"]:
            paired = [ln for ln in lines if len(ln) > 1]
            self.assertTrue(
                paired,
                "no two fields share a line, so the grid collapsed back to "
                "one field per row")
            # Release and the two prose cells keep the full width they need.
            for ln in lines:
                if len(ln) > 1:
                    self.assertNotIn("Release", ln)
                    self.assertNotIn("Protectarr", ln)

    def test_the_pairs_hold_all_the_way_down(self):
        """No second breakpoint dropping these cards to one column.

        There was one at 380px, on the assumption that two columns stop being
        readable on the narrower phones. Measured through an iframe - chromium
        will not open a window below 500px - the pairs hold to 280px with
        nothing clipped, and at 375 the rule was costing 103px of card height
        to solve a problem no real device has.
        """
        d = self.probe(500, probe="""(function(){
          var tr = document.querySelector('.dlcards tbody tr');
          return {cols: getComputedStyle(tr).gridTemplateColumns.split(' ').length};
        })()""", name="cols")
        self.assertEqual(d["cols"], 2)
        self.assertNotIn("max-width: 380px", open(CSS_PATH).read())

    def test_a_field_with_nothing_in_it_is_not_given_a_line(self):
        """A heading over a dash is most of a card and none of the
        information. The desktop table still renders the cell, because the
        column has to line up."""
        d = self.probe(768, probe="""(function(){
          var tr = document.querySelector('.dlcards tbody tr');
          var td = tr.querySelector('td.dl-empty');
          return {hidden: td ? getComputedStyle(td).display : 'no-empty-cell',
                  desktopMarked: !!td};
        })()""", name="empty")
        self.assertTrue(d["desktopMarked"], "no cell was marked empty")
        self.assertEqual(d["hidden"], "none")

    def test_the_empty_cell_is_still_there_on_a_desktop(self):
        d = self.probe(1440, probe="""(function(){
          var td = document.querySelector('.dlcards tbody tr td.dl-empty');
          return {display: td ? getComputedStyle(td).display : null};
        })()""", name="emptydesk")
        self.assertEqual(d["display"], "table-cell")


@unittest.skipUnless(browser.BROWSER, browser.REASON)
class TestTheDossierActuallyRendersTheExtraSections(unittest.TestCase):
    """The Python payload having the sections is not the same as the dialog
    showing them.

    Two mutations survived on exactly that gap: deleting the loop in
    `_details.html` that renders `r.extra`, and making every extra section
    span both grid columns. Both left `web._active_detail` untouched, so every
    assertion about the payload still passed while the dialog rendered either
    nothing or a single stretched column.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="protectarr-active-dossier-")
        cls.page = build_page()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    PROBE = """(function(){
      // Row 2 is the conflicted one: it has a remediation as well as the
      // ownership rationale, so it exercises a built-in section and an extra
      // one in the same dialog.
      showDetails(2);
      var body = document.getElementById('detail_body');
      return {
        sections: [].map.call(body.querySelectorAll('h3'), function (h) {
          var r = h.parentElement.getBoundingClientRect();
          return {name: h.textContent.trim(), left: Math.round(r.left),
                  w: Math.round(r.width),
                  span: h.parentElement.classList.contains('span')};
        }),
        text: body.textContent,
        bodyW: Math.round(body.getBoundingClientRect().width)
      };
    })()"""

    def dialog(self, width=1200):
        src = self.page.replace(
            "</body>",
            '<pre id="OUT"></pre><script>window.addEventListener("load",'
            'function(){document.getElementById("OUT").textContent='
            "JSON.stringify(%s);});</script></body>" % self.PROBE)
        p = os.path.join(self.tmp, "d%d.html" % width)
        with open(p, "w") as fh:
            fh.write(src)
        dom = browser.dom(p, width, 1400, budget=3000)
        m = re.search(r'<pre id="OUT">(.*?)</pre>', dom, re.S)
        self.assertTrue(m and m.group(1).strip(), "the dialog did not render")
        return json.loads(m.group(1).replace("&quot;", '"')
                          .replace("&amp;", "&").replace("&lt;", "<")
                          .replace("&gt;", ">"))

    def test_the_extra_sections_reach_the_screen(self):
        names = [s["name"] for s in self.dialog()["sections"]]
        for want in ("In qBittorrent", "Ownership", "Policy"):
            self.assertIn(want, names)

    def test_the_built_in_sections_still_render_alongside_them(self):
        names = [s["name"] for s in self.dialog()["sections"]]
        self.assertIn("Release", names)
        self.assertIn("Remediation", names)

    def test_release_comes_first_and_ownership_follows_it(self):
        names = [s["name"] for s in self.dialog()["sections"]]
        self.assertEqual(names[0], "Release")
        self.assertLess(names.index("Ownership"), names.index("Remediation"))

    def test_no_extra_section_spans_the_grid(self):
        """Timeline is the only full-width section, and it belongs to History.
        A spanning section here would put one field per row in a dialog whose
        whole point is two columns."""
        for s in self.dialog()["sections"]:
            if s["name"] in ("In qBittorrent", "Ownership", "Policy",
                             "Content probe"):
                self.assertFalse(s["span"], f"{s['name']} spans the grid")

    def test_the_sections_really_do_sit_in_two_columns(self):
        d = self.dialog()
        lefts = {s["left"] for s in d["sections"]}
        self.assertGreater(len(lefts), 1,
                           "every section starts at the same x, so the dialog "
                           "rendered as a single column")

    def test_the_conflict_claimants_are_visible_in_the_dialog(self):
        """The one place they appear at all: the ownership store deliberately
        never records them."""
        text = self.dialog()["text"]
        self.assertIn("Radarr", text)
        self.assertIn("Sonarr", text)

    def test_an_empty_section_is_not_rendered_as_a_heading_over_nothing(self):
        """The probe is off in this fixture, so Content probe has one row and
        the rest are dropped rather than printed blank."""
        names = [s["name"] for s in self.dialog()["sections"]]
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()
