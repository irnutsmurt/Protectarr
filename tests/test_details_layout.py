"""The History Details dossier: two columns where there is room, one where there isn't.

Structural, not pixel-perfect. The rules asserted here are the ones whose loss
would silently undo the change or reintroduce a fault this project has already
shipped once:

  * the dialog opts into the wide variant rather than the 560px default
  * a section is one grid item, so its heading and table cannot land in
    different cells
  * the second column lives behind a min-width query, so the mobile stack is
    reached by the query not matching rather than by a second set of rules
  * `white-space: nowrap` never reaches a body cell outside that query, which
    is the mistake that put the History Details button outside its scroll
    container in 0.3.x

The browser checks below are skipped when this machine has no working headless
browser, so CI keeps running the structural half. What counts as "working" is
probed rather than assumed; see tests/browser.py.
"""
import os
import re
import sys
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import browser  # noqa: E402
from protectarr import config as cfg_mod  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(ROOT, "protectarr", "templates")
CSS_PATH = os.path.join(ROOT, "protectarr", "static", "style.css")


def read(path):
    with open(path) as fh:
        return fh.read()


def blocks(css, selector):
    """Every declaration block for an exact selector, media query or not."""
    out = []
    for m in re.finditer(re.escape(selector) + r"\s*\{([^}]*)\}", css):
        out.append(m.group(1))
    return out


def media_query_for(css, selector):
    """The @media condition a selector sits inside, or None for top level."""
    at = css.index(selector)
    depth, cond = 0, None
    for m in re.finditer(r"@media([^{]*)\{|\{|\}", css[:at]):
        tok = m.group(0)
        if tok.startswith("@media"):
            depth += 1
            cond = m.group(1).strip()
        elif tok == "{":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                cond = None
    return cond if depth else None


class TestDetailGridStructure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # The dialog's markup stayed on the pages that open it; its rendering
        # moved to the shared partial in 0.6.0, when the Dashboard's Triage
        # Queue needed the same dossier. `html` is the two together, because
        # what these tests assert is a property of the dialog, not of whichever
        # file happens to hold each half this release.
        cls.pages = {name: read(os.path.join(TEMPLATES, name))
                     for name in ("history.html", "dashboard.html")}
        cls.partial = read(os.path.join(TEMPLATES, "_details.html"))
        cls.html = cls.partial + "".join(cls.pages.values())
        cls.css = read(CSS_PATH)

    def test_every_page_that_opens_the_dialog_opts_into_the_wide_modal(self):
        """Both callers, not just History.

        The Dashboard reuses the dialog by including the same partial, so a
        page that forgot the `wide` class would render the same dossier into
        the 560px default and get the 1840px column back.
        """
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn('<div class="modal wide">', html)

    def test_the_dialog_body_is_the_grid(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn('class="modal-body detail-grid" id="detail_body"',
                              html)

    def test_the_dialog_is_rendered_from_one_place(self):
        """One implementation, included twice - not two copies.

        Two copies would drift, and the Triage row's Details button exists
        precisely to open the same record History would.
        """
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn('{% include "_details.html" %}', html)
                self.assertNotIn("function showDetails", html)

    def test_a_section_is_one_grid_item(self):
        """The <section> wrapper, without which the h3 and table split up."""
        self.assertIn('<section class="dsec', self.html)
        self.assertIn("</table></section>", self.html)

    def test_the_second_column_is_behind_a_min_width_query(self):
        cond = media_query_for(self.css, ".detail-grid { grid-template-columns")
        self.assertIsNotNone(cond, "the two-column rule is not in a media query")
        self.assertRegex(cond, r"min-width:\s*\d+px")

    def test_the_breakpoint_clears_the_mobile_stack(self):
        """Above 720px, which the responsive block already owns."""
        cond = media_query_for(self.css, ".detail-grid { grid-template-columns")
        px = int(re.search(r"min-width:\s*(\d+)px", cond).group(1))
        self.assertGreater(px, 720)

    def test_the_default_is_a_single_column(self):
        """Mobile is the absence of the query, not a second rule undoing it.

        Checked over every `.detail-grid` block rather than just the one that
        declares `display: grid`, so hoisting the columns into a rule of their
        own is caught as well as adding them to the base rule.
        """
        found = False
        for m in re.finditer(r"\.detail-grid\s*\{([^}]*)\}", self.css):
            if "grid-template-columns" not in m.group(1):
                continue
            found = True
            cond = media_query_for(self.css, m.group(0))
            self.assertIsNotNone(
                cond, "a second column applies at every width, including the "
                      "375px stack")
        self.assertTrue(found, "the grid never gets a second column")

    def test_full_span_sections_span_every_column(self):
        span = blocks(self.css, ".dsec.span")
        self.assertTrue(any("grid-column: 1 / -1" in b for b in span),
                        "no full-span rule")
        cond = media_query_for(self.css, ".dsec.span { grid-column")
        self.assertIsNotNone(cond,
                             "spanning outside the query would apply to the "
                             "single-column stack, where it means nothing")

    def test_timeline_is_the_only_full_span_section(self):
        """`span` is passed once, and by the chronological section.

        The title is found by walking back to the nearest `section(` call
        rather than by looking a fixed distance behind the span marker. The
        fixed window was 400 characters and broke the moment the Timeline's
        map body grew past it, which is a property of the formatting rather
        than of the thing being asserted.
        """
        calls = re.findall(r"section\((.{0,40}?),", self.html, re.S)
        spans = re.findall(r"\}\), true\);|\], true\);", self.html)
        self.assertEqual(len(spans), 1, "more than one section asks to span")
        i = self.html.index("}), true);") if "}), true);" in self.html \
            else self.html.index("], true);")
        before = self.html[:i]
        j = before.rindex("section(")
        self.assertIn("'Timeline'", before[j:j + 40],
                      "the spanning section is not the Timeline")
        self.assertTrue(calls, "section() is never called")

    def test_no_broad_nowrap_rule_was_added(self):
        """Every nowrap touching the dossier is inside the min-width query.

        A body cell that cannot wrap sets a floor on its column, the table
        cannot shrink past it, and the overflow lands on the page. That is
        exactly how the Details button ended up outside its scroll container
        before, so the rule is only allowed where the width is guaranteed.
        """
        for m in re.finditer(r"(\.dsec[^{}]*)\{[^}]*white-space:\s*nowrap",
                             self.css):
            sel = m.group(1).strip()
            cond = media_query_for(self.css, m.group(0)[:40])
            self.assertIsNotNone(cond, f"{sel} may not wrap at any width")
            self.assertRegex(cond, r"min-width:\s*\d+px")
            self.assertIn(".span", sel,
                          "only the full-width section has room for this")

    def test_value_cells_still_wrap(self):
        cells = blocks(self.css, ".dsec td")
        self.assertTrue(any("word-break: break-word" in b for b in cells))

    def test_swarm_observations_is_untouched(self):
        """Nothing here reaches the peer profile dialog."""
        peer = read(os.path.join(TEMPLATES, "watchlist.html"))
        self.assertNotIn("detail-grid", peer)
        self.assertNotIn("dsec", peer)
        self.assertIn('<div class="modal-body" id="peer_body">', peer)
        # And the peer dialog's own rule is still the one it shipped with.
        self.assertRegex(self.css, r"\.enc-table thead th\s*\{[^}]*nowrap")


# --------------------------------------------------------------------------
# Rendered geometry. Needs a browser, so it is skipped rather than faked.

STRESS = {
    "release": "The.Cartographers.Apprentice.S03E11.Extended.Directors.Cut."
               "2160p.NF.WEB-DL.DDP5.1.Atmos.DV.HDR10Plus.HEVC-FLUXiON",
    "media": "The Cartographer's Apprentice - S03E11 - The Meridian Line",
    "app": "Sonarr 4K (sonarr)", "indexer": "Meridian Tracker (Prowlarr)",
    "size": "22.5 GiB", "category": "tv-4k", "hash": "a" * 40,
    "why": "extension match: WATCH_HD_PLAYER_Setup_x64.exe",
    "base_missing": False,
    "also": ["archive only: Subtitles_and_Codecs.rar",
             "lure filename: HOW_TO_PLAY_THIS_FILE.txt"],
    "severity": "critical", "profile": "media", "decision": "arr_fail",
    "status": {"label": "Failed Unverified", "cls": "off",
               "milestone": "failed_unverified",
               "why": "removed, but the blocklist entry could not be proved"},
    "recovered": True, "queue_delete": "removed",
    "verification": "no downloadFailed event for this infohash after id 41977",
    "history_event": None, "blocklist_row": None,
    "error": "could not prove the release was blocklisted, so no replacement "
             "search was issued",
    "requeue": "held - remediation unverified",
    "search_command": 1126044, "search_state": "completed",
    "search_result": "successful",
    "search_message": "Completed search for 1 series. 0 reports downloaded.",
    # Each entry carries a relative age on its own line under the timestamp,
    # which is the widest the label column ever gets. `resumed` and a note
    # together are the worst case for the value column.
    "timeline": [
        {"when": "2026-09-15 10:13:03 -0700", "rel": "3 days ago",
         "what": "Handed back to the application", "note": None,
         "resumed": False},
        {"when": "2026-09-15 10:13:06 -0700", "rel": "3 days ago",
         "what": "Removal verified", "note": None, "resumed": False},
        {"when": "2026-09-15 10:13:54 -0700", "rel": "3 days ago",
         "what": "Removal verified", "resumed": True,
         # A real note, as `intents.reconcile` writes them. The earlier
         # placeholder said "after a restart", which the `resumed` marker
         # already says, so the stress record was rehearsing a duplication
         # that production cannot produce.
         "note": "the removal was confirmed against the *arr's own records"},
        {"when": "2026-09-15 10:14:39 -0700", "rel": "3 days ago",
         "what": "Could not verify the removal", "note": None,
         "resumed": False},
    ],
}

PROBE = """
<script>
window.addEventListener('load', function () {
  var d = document, win = window;
  showDetails(0);
  var body = d.getElementById('detail_body');
  var secs = [], heads = body.querySelectorAll('h3');
  for (var i = 0; i < heads.length; i++) {
    var r = heads[i].parentElement.getBoundingClientRect();
    secs.push({name: heads[i].textContent.trim(), left: Math.round(r.left),
               w: Math.round(r.width)});
  }
  var m = d.querySelector('#detailModal .modal').getBoundingClientRect();
  var p = d.createElement('pre');
  p.id = 'M';
  p.textContent = JSON.stringify({
    vw: win.innerWidth, modalW: Math.round(m.width), modalH: Math.round(m.height),
    bodyW: Math.round(body.getBoundingClientRect().width),
    overflow: d.documentElement.scrollWidth - d.documentElement.clientWidth,
    sections: secs});
  d.body.appendChild(p);
});
</script>"""


@unittest.skipUnless(browser.BROWSER, browser.REASON)
class TestDetailGridGeometry(unittest.TestCase):
    """What the rules above actually produce, at a desktop and a phone width.

    The page is written to a file with the stylesheet inlined so there is no
    server to stand up, and the record is a worst case: a 120-character release
    name, three findings, Failed Unverified with an error, a terminal search
    message and a four-step timeline.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="protectarr-detail-")
        cfg_mod.CONFIG_PATH = os.path.join(cls.tmp, "config.yaml")
        with open(cfg_mod.CONFIG_PATH, "w") as fh:
            fh.write("web:\n  api_key: test-api-key\n")
        from protectarr import web

        class Loose(dict):
            def __getattr__(self, k):
                return self.get(k)

        service = Loose(state=Loose(
            stats=Loose(reaped_total=0, last_reap=None), running=True,
            last_scan=None, last_error=None, blocklist=Loose(), banned=Loose()))
        app = web.create_app(service)
        app.config["TESTING"] = True
        client = app.test_client()
        with client.session_transaction() as s:
            s["user"] = "admin"
        page = client.get("/history?show=live").data.decode()
        # Inline the stylesheet: file:// has no server behind /static.
        sheet = read(CSS_PATH)
        # A function replacement: a string one would treat the stylesheet's CSS
        # escapes (`\25B8`) as regex group references.
        page = re.sub(r'<link rel="stylesheet"[^>]*>',
                      lambda m: "<style>%s</style>" % sheet, page)
        # One stress record, injected where the real page puts its rows.
        page = re.sub(r"var ROWS = .*?;\n",
                      "var ROWS = [%s];\n" % json.dumps(STRESS), page, count=1)
        cls.page = page.replace("</body>", PROBE + "</body>")
        assert "showDetails" in cls.page

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def measure(self, width, height=900):
        path = os.path.join(self.tmp, "p%d.html" % width)
        with open(path, "w") as fh:
            fh.write(self.page)
        out = browser.dom(path, width, height)
        m = re.search(r'<pre id="M">(.*?)</pre>', out, re.S)
        self.assertTrue(m and m.group(1).strip(), "the dialog never rendered")
        return json.loads(m.group(1).replace("&quot;", '"')
                          .replace("&amp;", "&").replace("&lt;", "<")
                          .replace("&gt;", ">"))

    def test_desktop_lays_the_sections_out_in_two_columns(self):
        d = self.measure(1440)
        lefts = sorted({s["left"] for s in d["sections"]})
        self.assertEqual(len(lefts), 2,
                         "expected two column origins, got %r" % lefts)

    def test_desktop_pairs_the_first_two_sections_side_by_side(self):
        d = self.measure(1440)
        first, second = d["sections"][0], d["sections"][1]
        self.assertNotEqual(first["left"], second["left"])

    def test_the_timeline_spans_both_columns(self):
        d = self.measure(1440)
        timeline = [s for s in d["sections"] if s["name"] == "Timeline"]
        self.assertEqual(len(timeline), 1)
        self.assertGreater(timeline[0]["w"], d["bodyW"] * 0.9)
        narrow = [s for s in d["sections"] if s["name"] != "Timeline"]
        self.assertTrue(all(s["w"] < d["bodyW"] * 0.6 for s in narrow))

    def test_mobile_collapses_to_one_column(self):
        d = self.measure(375)
        lefts = {s["left"] for s in d["sections"]}
        self.assertEqual(len(lefts), 1, "phone width is not a single stack")

    def test_the_dialog_is_shorter_on_a_desktop_than_on_a_phone(self):
        """The point of the change, stated as an invariant rather than a number."""
        self.assertLess(self.measure(1440)["modalH"],
                        self.measure(768)["modalH"])

    def test_no_page_level_horizontal_overflow_at_any_width(self):
        for w in (1920, 1440, 1280, 1024, 900, 768, 600):
            with self.subTest(width=w):
                self.assertEqual(self.measure(w)["overflow"], 0)

    def test_the_timestamp_column_survives_the_narrowest_phone(self):
        """The Timeline's label column is the one cell in the dialog that
        cannot wrap above 900px, and it now holds two lines rather than one.
        320px is narrower than any phone Protectarr is likely to meet, which
        is the point: if it fits there it fits everywhere."""
        for w in (320, 360, 375, 414):
            with self.subTest(width=w):
                self.assertEqual(self.measure(w)["overflow"], 0)

    def test_the_relative_age_does_not_widen_the_timestamp_column(self):
        """It sits under the timestamp, not beside it. Beside it would add
        about twelve characters to a nowrap cell and push the dialog out."""
        wide = self.measure(1440)
        timeline = [s for s in wide["sections"] if s["name"] == "Timeline"][0]
        self.assertGreater(timeline["w"], wide["bodyW"] * 0.9)
        self.assertEqual(wide["overflow"], 0)


if __name__ == "__main__":
    unittest.main()
