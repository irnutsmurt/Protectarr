"""Unsaved changes, per card, driven in a real browser.

The design this checks: one card is one form is one save boundary, so unsaved
state is per card too. Several can be dirty at once, each saves on its own, and
nothing anywhere looks like it saves the page.

Three things are worth stating about why these are browser tests rather than
markup assertions.

`defaultValue` / `defaultChecked` / `defaultSelected` are the browser's own
record of what the server sent. Nothing else can be asserted from the HTML,
and the whole reason for using them is that dirty state then needs no snapshot
of form values, which is what keeps stored secrets out of it: the password
field renders blank, so its default is blank, so typing is dirty and not
typing is clean without anyone knowing the stored hash.

Discard is `form.reset()` plus a clone of the one container whose rows can be
added and removed. Getting that wrong is invisible in the markup and obvious
the moment a row is removed and put back.

And a page reload would be the easy implementation of Discard, which is exactly
why there is a test that discarding one dirty card leaves another dirty card
alone.

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

from protectarr import web  # noqa: E402
import browser  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "protectarr", "static")


def read(name):
    with open(os.path.join(STATIC, name)) as fh:
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


@unittest.skipIf(browser.BROWSER is None, browser.REASON)
class DirtyCase(unittest.TestCase):
    PAGE = "detection-remediation"

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        cfg_mod.save({
            "dry_run": False,
            "web": {"api_key": "web-test-key-value", "secret_key": "s" * 40,
                    "auth": {"method": "forms", "required": "enabled",
                             "username": "admin",
                             "password_hash": "pbkdf2:sha256:1$fake$notreal",
                             "trusted_proxies": []}},
            "detection": {"probe": {"enabled": True, "path_mappings": [
                {"from": "/one", "to": "/uno"}, {"from": "/two", "to": "/dos"}]}},
            "safety": {"mode": "either", "allowed_categories": ["tv-sonarr"],
                       "allowed_tags": ["public"]},
            "banned_ips": {"enabled": True, "ips": ["203.0.113.7"]},
            "logging": {"file_enabled": False,
                        "path": os.path.join(self.dir, "logs")},
        })
        app = web.create_app(FakeService())
        app.config["TESTING"] = True
        self.client = app.test_client()
        with self.client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"

    def run_script(self, body, page=None):
        """Render a Settings page with the real CSS and JS inlined, run `body`
        after everything has settled, and bring back whatever it reports."""
        html = self.client.get(f"/settings/{page or self.PAGE}") \
                          .get_data(as_text=True)
        sheet, script = read("style.css"), read("settings.js")
        # Function replacements: a string one would read the stylesheet's CSS
        # escapes as regex group references.
        html = re.sub(r'<link rel="stylesheet"[^>]*>',
                      lambda m: "<style>%s</style>" % sheet, html)
        html = re.sub(r'<script src="[^"]*settings\.js[^"]*"></script>',
                      lambda m: "<script>%s</script>" % script, html)
        # Both directions: the <script src> is gone and the source it pointed
        # at is here. Checking only one of those is how a test ends up
        # measuring a page with no behaviour on it.
        assert "settings.js" not in html, "the script tag was not replaced"
        assert "has-dirty-ui" in html, "the script source was not inlined"
        probe = """
<script>
window.addEventListener('load', function () {
  // The category, tag and indexer lists arrive from a fetch that cannot
  // succeed here; letting it settle first means the test measures the page an
  // operator actually sees.
  setTimeout(async function () {
    var REPORT = {};
    // Removing a row is only noticed by a MutationObserver, which runs a
    // microtask after the click. Reading the class immediately would measure
    // the moment before the UI has had its chance to react.
    function flush() { return new Promise(function (r) { setTimeout(r, 0); }); }
    function q(s) { return document.querySelector(s); }
    function qa(s) { return Array.prototype.slice.call(document.querySelectorAll(s)); }
    function form(section) { return q('form[action="/settings/' + section + '/save"]'); }
    function card(section) { return q('#section-' + section); }
    function dirty(section) { return card(section).classList.contains('dirty'); }
    function bar(section) { return card(section).querySelector('.dirtybar'); }
    function type(el, v) {
      el.value = v;
      el.dispatchEvent(new Event('input', {bubbles: true}));
      el.dispatchEvent(new Event('change', {bubbles: true}));
    }
    function click(el) { el.click(); }
    function discard(section) {
      var b = bar(section).querySelectorAll('button');
      b[0].click();
    }
    %(body)s
    var pre = document.createElement('pre');
    pre.id = 'MEASURED';
    pre.textContent = JSON.stringify(REPORT);
    document.body.appendChild(pre);
  }, 250);
});
</script>"""
        path = os.path.join(self.dir, "page.html")
        with open(path, "w") as fh:
            fh.write(html.replace("</body>", (probe % {"body": body}) + "</body>"))
        dom = browser.dom(path, 1280, 1000, budget=6000)
        m = re.search(r'<pre id="MEASURED">(.*?)</pre>', dom, re.S)
        self.assertIsNotNone(m, "the probe did not run")
        return json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&")
                          .replace("&lt;", "<").replace("&gt;", ">"))


class TestTheRestingState(DirtyCase):
    def test_nothing_is_dirty_when_the_page_arrives(self):
        r = self.run_script("""
          REPORT.dirty = qa('.card.dirty').length;
          REPORT.visibleBars = qa('.dirtybar:not([hidden])').length;
          REPORT.bars = qa('.dirtybar').length;
        """)
        self.assertEqual(r["dirty"], 0)
        self.assertEqual(r["visibleBars"], 0)
        self.assertEqual(r["bars"], 3, "one strip per form on this page")

    def test_a_clean_card_shows_no_save_at_all(self):
        """The in-body Save is hidden once the strip exists, so a clean card
        offers nothing to press."""
        r = self.run_script("""
          REPORT.inBody = qa('.card-actions').map(function (a) {
            return getComputedStyle(a).display; });
          REPORT.hasClass = document.documentElement.classList.contains('has-dirty-ui');
        """)
        self.assertTrue(r["hasClass"])
        self.assertEqual(set(r["inBody"]), {"none"})

    def test_every_save_strip_sits_inside_its_own_form(self):
        """A submit in the header works natively because the header is inside
        the form. Nothing needs a `form=` attribute pointing across cards."""
        r = self.run_script("""
          REPORT.rows = qa('.dirtybar').map(function (b) {
            var f = b.closest('form');
            var save = b.querySelector('button[type=submit]');
            return [f ? f.getAttribute('action') : null,
                    save ? save.form.getAttribute('action') : null];
          });
          REPORT.formAttrs = qa('[form]').length;
        """)
        for own, reached in r["rows"]:
            self.assertEqual(own, reached)
        self.assertEqual(r["formAttrs"], 0)

    def test_the_two_truthful_labels_survive_into_the_strip(self):
        r = self.run_script("""
          REPORT.labels = qa('.dirtybar button[type=submit]').map(function (b) {
            return [b.closest('form').getAttribute('action'), b.textContent]; });
        """, page="network")
        got = dict(r["labels"])
        self.assertEqual(got["/settings/bannedips/save"], "Save & Apply")
        self.assertEqual(got["/settings/blocklist/save"], "Save")

    def test_the_blocklist_refresh_stays_reachable_on_a_clean_card(self):
        """It is an operation, not an edit. Useful when nothing has changed."""
        r = self.run_script("""
          var b = q('button[name=do_update]');
          REPORT.display = getComputedStyle(b.closest('.card-ops')).display;
          REPORT.dirty = qa('.card.dirty').length;
        """, page="network")
        self.assertNotEqual(r["display"], "none")
        self.assertEqual(r["dirty"], 0)


class TestTheStripStaysReachable(DirtyCase):
    """Detection & Remediation is over 4000px tall. A Save that scrolls away
    while you are still editing is the problem the header strip solves."""

    def test_the_strip_pins_below_the_app_header_while_the_card_scrolls(self):
        r = self.run_script("""
          type(q('[name=blocked_extensions]'), '.exe, .lnk');
          var h2 = q('#section-detection > h2');
          REPORT.position = getComputedStyle(h2).position;
          REPORT.headerH = Math.round(q('.app-header').getBoundingClientRect().height);
          REPORT.before = Math.round(h2.getBoundingClientRect().top);
          window.scrollTo(0, 700);
          REPORT.cardTop = Math.round(card('detection').getBoundingClientRect().top);
          REPORT.after = Math.round(h2.getBoundingClientRect().top);
          REPORT.barVisible = !bar('detection').hidden;
        """)
        self.assertEqual(r["position"], "sticky")
        self.assertLess(r["cardTop"], 0, "the card did not scroll past")
        self.assertEqual(r["after"], r["headerH"],
                         "the strip did not pin below the app header")
        self.assertTrue(r["barVisible"])

    def test_the_card_does_not_become_its_own_scroll_container(self):
        """`overflow: hidden` on the card would pin the strip to the card
        instead of the viewport, which is stickiness that never does anything."""
        r = self.run_script("""
          REPORT.overflow = getComputedStyle(card('detection')).overflow;
        """)
        self.assertEqual(r["overflow"], "clip")

    def test_the_chip_and_the_strip_do_not_fight_for_the_right_edge(self):
        """Two competing `margin-left: auto` would split the free space and
        strand the chip in the middle of the header."""
        r = self.run_script("""
          type(q('[name=blocked_extensions]'), '.exe, .lnk');
          var h2 = q('#section-detection > h2');
          var chip = h2.querySelector('.chip'), b = h2.querySelector('.dirtybar');
          var hr = h2.getBoundingClientRect();
          REPORT.barFromRight = Math.round(hr.right - b.getBoundingClientRect().right);
          REPORT.chipBeforeBar =
            chip.getBoundingClientRect().right <= b.getBoundingClientRect().left;
          REPORT.gap = Math.round(b.getBoundingClientRect().left
                                  - chip.getBoundingClientRect().right);
        """)
        self.assertTrue(r["chipBeforeBar"])
        self.assertLess(r["barFromRight"], 24, "the strip is not at the right edge")
        self.assertLess(r["gap"], 40, "the chip was stranded mid-header")


class TestDirtyIsPerCard(DirtyCase):
    def test_editing_one_card_marks_only_that_card(self):
        r = self.run_script("""
          type(q('[name=blocked_extensions]'), '.exe, .bat');
          REPORT.detection = dirty('detection');
          REPORT.safety = dirty('safety');
          REPORT.probe = dirty('probe');
          REPORT.barVisible = !bar('detection').hidden;
        """)
        self.assertTrue(r["detection"])
        self.assertTrue(r["barVisible"])
        self.assertFalse(r["safety"])
        self.assertFalse(r["probe"])

    def test_two_cards_can_be_dirty_at_once(self):
        r = self.run_script("""
          type(q('[name=blocked_extensions]'), '.exe');
          type(q('[name=orphan_dwell_minutes]'), '45');
          REPORT.dirty = qa('.card.dirty').map(function (c) { return c.id; });
        """)
        self.assertEqual(sorted(r["dirty"]),
                         ["section-detection", "section-safety"])

    def test_a_checkbox_counts_as_an_edit(self):
        r = self.run_script("""
          var cb = q('[name=only_active]');
          REPORT.before = dirty('detection');
          click(cb);
          REPORT.after = dirty('detection');
          click(cb);
          REPORT.back = dirty('detection');
        """)
        self.assertFalse(r["before"])
        self.assertTrue(r["after"])
        self.assertFalse(r["back"], "returning to the saved value is not dirty")

    def test_a_select_counts_as_an_edit(self):
        r = self.run_script("""
          var sel = q('[name=safety_mode]');
          sel.value = 'both';
          sel.dispatchEvent(new Event('change', {bubbles: true}));
          REPORT.after = dirty('safety');
          sel.value = 'either';
          sel.dispatchEvent(new Event('change', {bubbles: true}));
          REPORT.back = dirty('safety');
        """)
        self.assertTrue(r["after"])
        self.assertFalse(r["back"])

    def test_a_control_inside_advanced_tuning_still_counts(self):
        """It is collapsed, not absent. An edit made there has to mark the card
        or the operator gets no Save."""
        r = self.run_script("""
          type(q('[name=probe_budget]'), '900');
          REPORT.dirty = dirty('probe');
          REPORT.openDetails = qa('details[open]').length;
        """)
        self.assertTrue(r["dirty"])
        self.assertEqual(r["openDetails"], 0)


class TestDiscardIsPerCardToo(DirtyCase):
    def test_discard_restores_the_saved_values(self):
        r = self.run_script("""
          var ta = q('[name=blocked_extensions]');
          REPORT.saved = ta.value;
          type(ta, 'nonsense');
          REPORT.edited = ta.value;
          discard('detection');
          REPORT.after = ta.value;
          REPORT.dirty = dirty('detection');
        """)
        self.assertNotEqual(r["saved"], r["edited"])
        self.assertEqual(r["after"], r["saved"])
        self.assertFalse(r["dirty"])

    def test_discarding_one_card_leaves_another_dirty_card_alone(self):
        """The reason Discard is not a page reload."""
        r = self.run_script("""
          type(q('[name=blocked_extensions]'), '.exe');
          type(q('[name=orphan_dwell_minutes]'), '45');
          discard('detection');
          REPORT.detectionDirty = dirty('detection');
          REPORT.safetyDirty = dirty('safety');
          REPORT.safetyValue = q('[name=orphan_dwell_minutes]').value;
        """)
        self.assertFalse(r["detectionDirty"])
        self.assertTrue(r["safetyDirty"], "the other card's edit was destroyed")
        self.assertEqual(r["safetyValue"], "45")

    def test_discard_puts_back_a_removed_mapping_row(self):
        """`form.reset()` cannot do this, which is why a clone is kept."""
        r = self.run_script("""
          REPORT.before = qa('#map_rows .maprow').length;
          q('#map_rows .maprow button').click();
          await flush();
          REPORT.removed = qa('#map_rows .maprow').length;
          REPORT.dirtyAfterRemove = dirty('probe');
          discard('probe');
          await flush();
          REPORT.after = qa('#map_rows .maprow').length;
          REPORT.values = qa('#map_rows [name=map_from]').map(function (i) { return i.value; });
          REPORT.dirty = dirty('probe');
        """)
        self.assertEqual(r["before"], 2)
        self.assertEqual(r["removed"], 1)
        self.assertTrue(r["dirtyAfterRemove"])
        self.assertEqual(r["after"], 2)
        self.assertEqual(r["values"], ["/one", "/two"])
        self.assertFalse(r["dirty"])

    def test_discard_removes_an_added_mapping_row(self):
        r = self.run_script("""
          addMapping('/three', '/tres');
          await flush();
          REPORT.added = qa('#map_rows .maprow').length;
          REPORT.dirtyAfterAdd = dirty('probe');
          discard('probe');
          await flush();
          REPORT.after = qa('#map_rows .maprow').length;
          REPORT.dirty = dirty('probe');
        """)
        self.assertEqual(r["added"], 3)
        self.assertTrue(r["dirtyAfterAdd"])
        self.assertEqual(r["after"], 2)
        self.assertFalse(r["dirty"])

    def test_the_empty_state_note_is_recomputed_after_a_restore(self):
        """The note belongs to the card, and Discard replaced the container it
        was describing."""
        r = self.run_script("""
          qa('#map_rows .maprow button').forEach(function (b) { b.click(); });
          await flush();
          REPORT.noteWhenEmpty = getComputedStyle(q('#map_empty')).display;
          discard('probe');
          REPORT.noteWhenRestored = getComputedStyle(q('#map_empty')).display;
        """)
        self.assertNotEqual(r["noteWhenEmpty"], "none")
        self.assertEqual(r["noteWhenRestored"], "none")

    def test_rows_can_still_be_added_after_a_discard(self):
        """Discard swaps the container, so anything watching the old one has to
        be re-attached or the next edit goes unnoticed."""
        r = self.run_script("""
          addMapping('/three', '/tres');
          discard('probe');
          addMapping('/four', '/quatro');
          await flush();
          REPORT.rows = qa('#map_rows .maprow').length;
          REPORT.dirty = dirty('probe');
        """)
        self.assertEqual(r["rows"], 3)
        self.assertTrue(r["dirty"], "the restored container is not being watched")


class TestAnInactiveSectionIsStillSubmitted(DirtyCase):
    """`inert`, never `disabled`.

    A disabled control is not submitted, and against `save_section()`'s
    overwrite semantics a field that stops being posted is a field that gets
    cleared. Muting the probe's settings with `disabled` would erase the path
    mappings the next time anyone saved that card. This is the regression test
    for the property the whole approach rests on.
    """

    def test_turning_a_feature_off_mutes_its_settings(self):
        r = self.run_script("""
          var box = q('[data-active-when=probe_enabled]');
          REPORT.activeBefore = box.inert;
          click(q('[name=probe_enabled]'));
          REPORT.inertAfter = box.inert;
          REPORT.aria = box.getAttribute('aria-disabled');
          REPORT.muted = box.classList.contains('inactive');
          REPORT.opacity = getComputedStyle(box).opacity;
        """)
        self.assertFalse(r["activeBefore"])
        self.assertTrue(r["inertAfter"])
        self.assertEqual(r["aria"], "true")
        self.assertTrue(r["muted"])
        self.assertLess(float(r["opacity"]), 1.0)

    def test_a_muted_control_is_still_a_successful_form_control(self):
        """The measurement the design rests on, taken through the real form."""
        r = self.run_script("""
          click(q('[name=probe_enabled]'));
          var box = q('[data-active-when=probe_enabled]');
          REPORT.inert = box.inert;
          var names = [];
          new FormData(form('probe')).forEach(function (v, k) { names.push(k); });
          REPORT.posted = names;
          REPORT.disabledAttrs =
            qa('[data-active-when] [disabled]').length;
          REPORT.stillDefault = q('[name=map_from]').value;
        """)
        self.assertTrue(r["inert"])
        for name in ("map_from", "map_to", "probe_budget", "probe_minspeed"):
            self.assertIn(name, r["posted"],
                          "%s would be cleared on the next save" % name)
        self.assertEqual(r["disabledAttrs"], 0)
        self.assertEqual(r["stillDefault"], "/one")

    def test_a_muted_checkbox_still_reports_being_checked(self):
        """The one that fails silently: an absent checkbox is indistinguishable
        from an unchecked one, so muting that dropped it would read as the
        operator turning steering off."""
        r = self.run_script("""
          click(q('[name=probe_enabled]'));
          var names = [];
          new FormData(form('probe')).forEach(function (v, k) { names.push(k); });
          REPORT.posted = names;
        """)
        self.assertIn("probe_steer", r["posted"])

    def test_turning_it_back_on_restores_interaction(self):
        r = self.run_script("""
          var cb = q('[name=probe_enabled]'), box = q('[data-active-when=probe_enabled]');
          click(cb);
          REPORT.off = box.inert;
          click(cb);
          REPORT.on = box.inert;
          REPORT.aria = box.getAttribute('aria-disabled');
        """)
        self.assertTrue(r["off"])
        self.assertFalse(r["on"])
        self.assertIsNone(r["aria"])

    def test_the_master_switch_is_never_inside_what_it_mutes(self):
        """A switch that mutes itself cannot be switched back.

        Checked on every page, not just this class's default: the muted
        sections are spread across all three, and a test that looked at one of
        them would miss a trapped switch on either of the others.
        """
        total = 0
        for page in ("detection-remediation", "network", "administration"):
            r = self.run_script("""
              REPORT.trapped = qa('[data-active-when]').filter(function (box) {
                var name = (box.dataset.activeWhen || '').split(/[!=]/)[0];
                return !!box.querySelector('[name="' + name + '"]');
              }).map(function (box) { return box.dataset.activeWhen; });
              REPORT.boxes = qa('[data-active-when]').length;
            """, page=page)
            with self.subTest(page=page):
                self.assertEqual(r["trapped"], [])
            total += r["boxes"]
        self.assertGreaterEqual(total, 5, "the muted sections are not declared")

    def test_discard_restores_the_muting_too(self):
        r = self.run_script("""
          var box = q('[data-active-when=probe_enabled]');
          click(q('[name=probe_enabled]'));
          REPORT.afterEdit = box.inert;
          discard('probe');
          REPORT.afterDiscard = q('[data-active-when=probe_enabled]').inert;
        """)
        self.assertTrue(r["afterEdit"])
        self.assertFalse(r["afterDiscard"])

    def test_nothing_is_muted_without_javascript(self):
        """`inert` is applied by script only, so the no-script page stays fully
        editable rather than fully frozen."""
        seen = 0
        for page in ("detection-remediation", "network", "administration"):
            html = self.client.get("/settings/" + page).get_data(as_text=True)
            with self.subTest(page=page):
                self.assertNotIn(" inert", html)
                self.assertNotIn("aria-disabled", html)
            seen += html.count("data-active-when")
        self.assertGreaterEqual(seen, 5, "the muted sections are not declared")


class TestSecretsStayOutOfIt(DirtyCase):
    PAGE = "administration"

    def test_an_untouched_blank_password_is_not_an_edit(self):
        r = self.run_script("""
          var pw = q('[name=auth_password]');
          REPORT.value = pw.value;
          REPORT.defaultValue = pw.defaultValue;
          REPORT.dirty = dirty('security');
        """)
        self.assertEqual(r["value"], "")
        self.assertEqual(r["defaultValue"], "")
        self.assertFalse(r["dirty"])

    def test_typing_a_password_is_an_edit(self):
        r = self.run_script("""
          type(q('[name=auth_password]'), 'a-new-password');
          REPORT.dirty = dirty('security');
          discard('security');
          REPORT.after = q('[name=auth_password]').value;
          REPORT.cleanAgain = dirty('security');
        """)
        self.assertTrue(r["dirty"])
        self.assertEqual(r["after"], "")
        self.assertFalse(r["cleanAgain"])

    def test_no_stored_secret_is_anywhere_in_the_page(self):
        r = self.run_script("""
          // Assembled rather than written out: this script is part of
          // documentElement.innerHTML, so a literal needle would always find
          // itself and the test would fail whatever the page contained.
          var hash = 'pbk' + 'df2', key = 'web-test-' + 'key-value';
          var page = document.documentElement.innerHTML;
          REPORT.html = page.indexOf(hash) !== -1;
          REPORT.apiKey = page.indexOf(key) !== -1;
        """)
        self.assertFalse(r["html"], "the password hash reached the browser")
        self.assertFalse(r["apiKey"], "the API key reached the browser")


class TestTheChipsIgnoreUnsavedEdits(DirtyCase):
    def test_editing_a_card_does_not_move_its_saved_state_chip(self):
        """The chip answers "what is saved". An edit is not a save."""
        r = self.run_script("""
          var chip = card('probe').querySelector('.chip');
          REPORT.before = [chip.textContent, chip.className];
          click(q('[name=probe_enabled]'));
          REPORT.dirty = dirty('probe');
          var after = card('probe').querySelector('.chip');
          REPORT.after = [after.textContent, after.className];
        """)
        self.assertTrue(r["dirty"])
        self.assertEqual(r["before"], r["after"])

    def test_editing_the_policy_does_not_move_the_current_policy_box(self):
        r = self.run_script("""
          function text() { return q('.policy').textContent.replace(/\\s+/g, ' ').trim(); }
          REPORT.before = text();
          var sel = q('[name=safety_mode]');
          sel.value = 'arr_tracked';
          sel.dispatchEvent(new Event('change', {bubbles: true}));
          REPORT.dirty = dirty('safety');
          REPORT.after = text();
        """)
        self.assertTrue(r["dirty"])
        self.assertEqual(r["before"], r["after"])


if __name__ == "__main__":
    unittest.main()
