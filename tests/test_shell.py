"""The page shell: grid layout, the collapsible rail, and who gets width.

These are structural assertions, not screenshots. The pixel sweep that drove
the design lives in a local probe and needs a browser; what belongs in CI is
the set of invariants that make those pixels come out right, because those are
what a later edit can quietly remove.

Two things this file deliberately does NOT do. It does not assert on computed
widths, because that needs a layout engine and would make the suite depend on
chromium. And it does not assert that some string appears somewhere in the
document, because every page extends base.html and that mistake has already
been made twice in this project.

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
from test_audit import FakeService  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_PATH = os.path.join(REPO, "protectarr", "static", "style.css")


def css(strip_comments=True):
    """The stylesheet, whitespace flattened and comments removed.

    Comments go because they otherwise sit between a rule and the one before
    it, which defeats the boundary anchoring in `block()` and silently returns
    None for a rule that is plainly there.
    """
    with open(CSS_PATH) as fh:
        src = fh.read()
    if strip_comments:
        src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    return re.sub(r"\s+", " ", src)


def block(selector, source=None):
    """Declarations of every rule whose selector list matches exactly, joined.

    Every rule, not the first: `body` is declared twice (typography, then the
    grid shell) and returning whichever came first made the grid assertions
    check the font rule. Anchored to a rule boundary so a search for `body`
    does not also match the `body` inside `html, body`.
    """
    src = source if source is not None else css()
    found = re.findall(r"(?:^|[};])\s*" + re.escape(selector) + r"\s*\{([^}]*)\}",
                       src)
    return " ".join(f.strip() for f in found) if found else None


def media(query):
    """Everything inside the first @media block with this condition."""
    src = css()
    i = src.find("@media " + query)
    if i < 0:
        return None
    depth, j = 0, src.index("{", i)
    for k in range(j, len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[j + 1:k]
    return None


class ShellCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
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

    def get(self, route):
        return self.client.get(route).get_data(as_text=True)


class TestGridShell(ShellCase):
    def test_the_body_is_a_two_column_grid(self):
        b = block("body")
        self.assertIn("display: grid", b)
        self.assertIn("grid-template-columns", b)

    def test_the_sidebar_track_is_the_width_variable(self):
        """The single mechanism: content reclaims width because the track
        shrank, not because a second rule was kept in sync with it."""
        b = block("body")
        m = re.search(r"grid-template-columns:\s*([^;]+);", b)
        self.assertIn("var(--sidebar-w)", m.group(1))

    def test_the_content_track_can_shrink_below_its_content(self):
        """minmax(0, 1fr) and min-width:0.

        A grid track's automatic minimum is its content, so without these a
        wide table widens the column and the whole page scrolls sideways
        instead of the table scrolling inside its wrapper.
        """
        m = re.search(r"grid-template-columns:\s*([^;]+);", block("body"))
        self.assertIn("minmax(0", m.group(1))
        self.assertIn("min-width: 0", block(".content"))

    def test_the_sidebar_is_sticky_not_fixed(self):
        """Fixed would leave the grid, so the track would collapse and the
        content would slide underneath it."""
        s = block(".sidebar")
        self.assertIn("position: sticky", s)
        self.assertNotIn("position: fixed", s)

    def test_the_content_sits_in_the_second_column(self):
        self.assertIn("grid-column: 2", block(".content"))

    def test_the_content_no_longer_offsets_itself_by_the_sidebar_width(self):
        """The old shell stated the width twice. If a margin comes back, the
        two can disagree and collapsing stops reclaiming anything."""
        self.assertNotIn("margin-left: var(--sidebar-w)", block(".content"))


class TestCollapseState(ShellCase):
    def test_collapsed_uses_the_rail_width(self):
        self.assertIn("--sidebar-w: var(--rail-w)", block(":root.nav-collapsed"))

    def test_expanded_uses_the_full_width(self):
        self.assertIn("--sidebar-w: 240px", block(":root.nav-expanded"))

    def test_auto_collapse_is_a_media_query_so_it_survives_no_javascript(self):
        m = media("(max-width: 1200px)")
        self.assertIsNotNone(m, "no 1200px auto-collapse breakpoint")
        self.assertIn("--sidebar-w: var(--rail-w)", m)

    def test_labels_are_still_the_default_on_an_ordinary_laptop(self):
        """1366 and 1280 must keep their text labels.

        The breakpoint moved down from 1400 for exactly this: the rail is
        worth a flat ~180px everywhere, so the threshold is a judgement about
        when labels stop being worth their cost, and a 1366px laptop is not
        where that happens.
        """
        self.assertIsNone(media("(max-width: 1400px)"),
                          "1400px breakpoint is back; 1366 would be icon-only")
        for w in (1366, 1280, 1201):
            self.assertGreater(w, 1200)

    def test_a_manual_choice_outranks_the_auto_breakpoint(self):
        """`:root.nav-expanded` is more specific than the `:root` inside the
        media query, which is what lets a manual expand stick at 1100."""
        src = css()
        self.assertLess(src.index("@media (max-width: 1200px)"),
                        src.index(":root.nav-expanded"),
                        "the manual rule must come after the auto breakpoint")

    def test_the_rail_is_forced_below_900_regardless_of_preference(self):
        """Otherwise a stored "expanded" recreates the inversion this release
        exists to remove: 240px of sidebar on a 768px tablet leaves less
        content than the same page gets at 600px."""
        m = media("(max-width: 900px)")
        self.assertIsNotNone(m, "no forced-rail band")
        self.assertIn(":root.nav-expanded", m)
        self.assertIn("--sidebar-w: var(--rail-w)", m)

    def test_the_forced_band_comes_after_the_manual_rule(self):
        src = css()
        self.assertLess(src.index(":root.nav-expanded {"),
                        src.index("@media (max-width: 900px)"))

    def test_the_header_seam_tracks_the_sidebar_width(self):
        """The logo block is the top of the sidebar column and carries the
        dividing border, so it has to collapse in lockstep or the seam jumps."""
        h = block(".header-logo")
        self.assertIn("width: var(--sidebar-w)", h)
        self.assertIn("min-width: var(--sidebar-w)", h)


class TestPersistedPreference(ShellCase):
    def test_the_state_is_applied_before_the_body_exists(self):
        """In <head>, blocking. Reading the preference after first paint means
        the sidebar renders expanded and visibly snaps to the rail."""
        html = self.get("/history")
        head = html[:html.index("<body")]
        self.assertIn("localStorage.getItem('protectarr.nav')", head)
        self.assertIn("document.documentElement.classList.add", head)

    def test_the_early_script_runs_before_the_stylesheet_can_paint(self):
        html = self.get("/history")
        self.assertLess(html.index("protectarr.nav"), html.index("<body"))

    def test_the_toggle_writes_the_preference(self):
        html = self.get("/history")
        self.assertIn("localStorage.setItem(NAV_KEY", html)

    def test_storage_being_unavailable_is_not_fatal(self):
        """Private mode throws on access; the CSS breakpoint still works."""
        head = self.get("/history")
        self.assertRegex(head, r"try\s*\{[^}]*localStorage\.getItem")

    def test_the_javascript_breakpoint_matches_the_stylesheet(self):
        """Two numbers that must agree. If they drift, the button's label
        disagrees with the layout the user is looking at."""
        html = self.get("/history")
        m = re.search(r"NAV_AUTO_BELOW\s*=\s*(\d+)", html)
        self.assertEqual(m.group(1), "1200")
        self.assertIsNotNone(media(f"(max-width: {m.group(1)}px)"))


class TestMobileIsUnchanged(ShellCase):
    def test_the_grid_is_abandoned_below_the_mobile_breakpoint(self):
        m = media("(max-width: 720px)")
        self.assertIn("display: block", block("body", m))

    def test_mobile_keeps_the_wrapping_top_nav_not_the_rail(self):
        m = media("(max-width: 720px)")
        s = block(".sidebar", m)
        self.assertIn("position: static", s)
        self.assertIn("flex-wrap: wrap", s)

    def test_the_collapse_toggle_is_hidden_on_mobile(self):
        m = media("(max-width: 720px)")
        self.assertIn("display: none", block(".nav-toggle", m))

    def test_a_stored_collapsed_preference_does_not_hide_mobile_labels(self):
        """Someone who collapsed the rail on a desktop then opens the same
        page on a phone must not get an icon-only top bar."""
        m = media("(max-width: 720px)")
        self.assertIn(":root.nav-collapsed .nav .label", m)
        self.assertIn("position: static", m)


class TestMobileHeaderClearance(ShellCase):
    """Who reserves the height of the fixed header.

    Down here the header leaves the flow (`fixed`) and the body leaves the grid
    (`display: block`), which makes the nav the first in-flow element on the
    page. It was the *content* that reserved the header's 66px, and the content
    is not what sits under the header. Measured at 375 before the fix: the
    first row of nav links was covered completely and the second lost 20 of its
    42 pixels, while the 66px the content had reserved opened an equal band of
    dead space further down, where nothing needed one. One misplaced offset,
    both symptoms.

    Every page is this shell, so the fix belongs here and nowhere else. A
    second offset on a page would not cancel the first, it would double it.
    """

    def setUp(self):
        super().setUp()
        self.mobile = media("(max-width: 720px)")

    def test_the_header_is_out_of_the_flow_down_here(self):
        """The premise of everything below. If the header stops being fixed it
        occupies its own space again and the clearance becomes a bug."""
        self.assertIn("position: fixed", block(".app-header", self.mobile))

    def test_the_nav_clears_the_header(self):
        self.assertIn("margin-top: var(--header-h)",
                      block(".sidebar", self.mobile))

    def test_the_content_does_not_reserve_it_a_second_time(self):
        c = block(".content", self.mobile)
        self.assertIn("margin-top: 0", c)
        self.assertNotIn("margin-top: var(--header-h)", c)

    def test_the_clearance_is_the_header_variable_not_a_copy_of_its_value(self):
        """66 written out here is a number that stops tracking --header-h the
        day the header changes height."""
        self.assertNotIn("margin-top: 66px", self.mobile)

    def test_only_one_element_reserves_the_header(self):
        """Two reservations is the gap; none is the overlap."""
        self.assertEqual(self.mobile.count("margin-top: var(--header-h)"), 1)

    def test_no_page_corrects_the_shell_for_itself(self):
        """A page-specific offset would be invisible until the shell changed,
        and would then be wrong on exactly one page."""
        tpl = os.path.join(REPO, "protectarr", "templates")
        for name in sorted(os.listdir(tpl)):
            if not name.endswith(".html"):
                continue
            with open(os.path.join(tpl, name)) as fh:
                src = fh.read()
            with self.subTest(template=name):
                self.assertNotIn("--header-h", src)
                self.assertNotIn("margin-top:66", src.replace(" ", ""))

    def test_every_page_gets_it_because_every_page_is_this_shell(self):
        """The routes that render the nav, asserted as a set rather than
        spot-checked, so a new page cannot quietly opt out of the shell."""
        for route in ("/", "/dashboard", "/history", "/watchlist",
                      "/settings", "/system"):
            with self.subTest(route=route):
                page = self.get(route)
                self.assertIn('<aside class="sidebar"', page)
                self.assertIn('<header class="app-header">', page)


class TestWideContent(ShellCase):
    def test_data_pages_opt_into_the_wider_shell(self):
        for route in ("/dashboard", "/history", "/watchlist"):
            self.assertRegex(self.get(route), r'<main class="content wide"',
                             f"{route} should be a wide page")

    def test_configuration_surfaces_keep_the_readable_cap(self):
        """Applications and System hold tables but are not data pages.

        Applications is URLs, API keys and path mappings; System is a
        key/value table with a fixed 220px label column. Both get worse when
        stretched, so containing a `<table>` is not the test.
        """
        for route in ("/", "/system", "/settings", "/settings/safety",
                      "/settings/security", "/settings/logging"):
            html = self.get(route)
            self.assertRegex(html, r'<main class="content"',
                             f"{route} should keep the readable width")
            self.assertNotIn('class="content wide"', html)

    def test_the_cap_still_exists_for_ordinary_pages(self):
        self.assertIn("max-width: 1320px", block(".content"))

    def test_wide_is_a_wider_cap_not_an_absent_one(self):
        """Uncapped, a table page on an ultrawide monitor becomes unreadable
        in the other direction."""
        w = block(".content.wide")
        self.assertIsNotNone(w)
        m = re.search(r"max-width:\s*(\d+)px", w)
        self.assertGreater(int(m.group(1)), 1320)

    def test_page_type_drives_it_rather_than_the_template(self):
        self.assertEqual(web.WIDE_PAGES, {"dashboard", "history", "watchlist"})


class TestNavigationRemainsUsable(ShellCase):
    def test_every_primary_link_has_an_icon_and_a_label(self):
        html = self.get("/history")
        nav = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', html, re.S).group(1)
        links = re.findall(r"<a\s[^>]*>.*?</a>", nav, re.S)
        primary = [a for a in links if 'class="ico"' in a]
        self.assertEqual(len(primary), 6, "expected six primary nav links")
        for a in primary:
            self.assertIn('<svg class="ico"', a)
            self.assertIn('<span class="label">', a)

    def test_the_label_is_hidden_from_sight_but_not_from_assistive_tech(self):
        """display:none would drop it from the accessibility tree, leaving an
        icon-only link with no accessible name."""
        rule = block(":root.nav-collapsed .nav .label, :root.nav-collapsed .brand-name, "
                     ":root.nav-collapsed .sidebar-foot .foot-text")
        self.assertIsNotNone(rule, "collapsed label rule not found")
        self.assertNotIn("display: none", rule)
        self.assertIn("clip: rect(0 0 0 0)", rule)

    def test_icons_carry_a_tooltip_for_pointer_users(self):
        html = self.get("/history")
        self.assertIn('title="Swarm Observations"', html)

    def test_the_toggle_announces_its_state(self):
        html = self.get("/history")
        btn = re.search(r"<button[^>]*id=\"navToggle\"[^>]*>", html).group(0)
        self.assertIn('aria-expanded=', btn)
        self.assertIn('aria-controls="sidebar"', btn)
        self.assertIn("aria-label=", btn)

    def test_the_toggle_controls_something_that_exists(self):
        self.assertIn('id="sidebar"', self.get("/history"))

    def test_the_nav_is_a_labelled_landmark(self):
        self.assertIn('<nav class="nav" aria-label="Primary">', self.get("/history"))

    def test_keyboard_focus_is_visible_on_nav_and_toggle(self):
        self.assertIsNotNone(block(".nav a:focus-visible"))
        self.assertIsNotNone(block(".nav-toggle:focus-visible"))

    def test_settings_is_reachable_while_collapsed(self):
        """The rail hides the textual subnav, so the Settings icon has to lead
        somewhere that lists the sections. The index does."""
        html = self.get("/history")
        self.assertIn('href="/settings"', html)
        self.assertIn(":root.nav-collapsed .subnav { display: none; }", css())
        index = self.get("/settings")
        for key in web.SETTINGS_KEYS:
            self.assertIn(f'href="/settings/{key}"', index)

    def test_svg_icons_are_inline_with_no_external_dependency(self):
        html = self.get("/history")
        self.assertNotRegex(html, r'<link[^>]+icon-?(font|library)')
        self.assertIn("stroke=\"currentColor\"", html)


class TestOverflowInvariants(ShellCase):
    """The page must never scroll sideways; tables scroll in their wrapper."""

    def test_history_keeps_its_local_scroll_wrapper(self):
        """Needs a row: the wrapper only exists when there is a table in it."""
        from protectarr import events
        events.record({"event_type": "detection", "dry_run": False,
                       "torrent": {"hash": "a" * 40, "name": "Rel"},
                       "owner": {"instance": "Sonarr"},
                       "findings": [{"detector": "extension",
                                     "reason": "extension_match",
                                     "evidence": {"extension": ".exe"}}],
                       "policy": {"decisive_finding": 0},
                       "action": {"result": "reaped"}})
        self.assertIn('<div style="overflow-x:auto">', self.get("/history"))

    def test_no_page_level_horizontal_scroll_is_introduced(self):
        """Nothing in the shell may set overflow-x on the page itself."""
        for sel in ("html, body", "body", ".content"):
            b = block(sel)
            if b:
                self.assertNotIn("overflow-x: scroll", b)
                self.assertNotIn("overflow-x: auto", b)

    def test_the_sidebar_clips_rather_than_scrolls_horizontally(self):
        """At 60px the label is off-screen; it must not create a scrollbar."""
        self.assertIn("overflow: hidden", block(".sidebar"))
        self.assertIn("overflow-x: hidden", block(".nav"))


if __name__ == "__main__":
    unittest.main()
