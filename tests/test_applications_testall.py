"""Test All, driven in a real browser with the network stubbed.

The behaviour being pinned is entirely about feedback. Before this, Test All
fired one bulk request and every row changed at once whenever it came back,
with nothing on the button to say anything was happening; on a slow or
unreachable application that is indistinguishable from a click that did not
register, and clicking again just queued another one.

So: one request per application in order, the button carries the count, each
row resolves as its own answer arrives, a second click does nothing while it is
running, and the button returns to its own name afterwards rather than keeping
a result as its label.

`window.fetch` is replaced before the click so the sequence is controlled and
slow enough to observe. That is the point of the test: the intermediate states
are the feature, and a real network would make them unobservable.

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

ARRS = [
    {"name": "Sonarr", "type": "sonarr", "url": "http://s.invalid:8989",
     "api_key": "sonarr-test-key"},
    {"name": "Radarr", "type": "radarr", "url": "http://r.invalid:7878",
     "api_key": "radarr-test-key"},
    {"name": "Lidarr", "type": "lidarr", "url": "http://l.invalid:8686",
     "api_key": "lidarr-test-key"},
]
# qBittorrent plus the three applications.
TARGETS = 1 + len(ARRS)


class FakeService:
    class _State(dict):
        def __getattr__(self, k):
            return self.get(k)

    state = _State(stats=_State(by_indexer={}), running=True, last_scan=None,
                   last_error=None, blocklist=_State(), banned=_State())

    def reload(self):
        pass


@unittest.skipIf(browser.BROWSER is None, browser.REASON)
class TestAllCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="protectarr-testall-")
        cfg_mod.CONFIG_PATH = os.path.join(cls.tmp, "config.yaml")
        cfg_mod.save({
            "qbittorrent": {"url": "http://qb.invalid:8080", "username": "admin",
                            "password": "qbit-test-password", "api_key": "",
                            "verify_ssl": True, "web_url": "http://qb.local"},
            "arrs": ARRS,
            "web": {"api_key": "web-test-key-value", "secret_key": "s" * 40,
                    "auth": {"method": "none", "required": "enabled",
                             "username": "", "password_hash": "",
                             "trusted_proxies": []}},
            "logging": {"file_enabled": False,
                        "path": os.path.join(cls.tmp, "logs")},
        })
        app = web.create_app(FakeService())
        app.config["TESTING"] = True
        client = app.test_client()
        with client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"
        html = client.get("/").get_data(as_text=True)
        with open(CSS_PATH) as fh:
            sheet = fh.read()
        # Function replacement: a string one would read the stylesheet's CSS
        # escapes as regex group references.
        html = re.sub(r'<link rel="stylesheet"[^>]*>',
                      lambda m: "<style>%s</style>" % sheet, html)
        assert "testAll(this)" in html, "the toolbar button did not render"
        cls.page = html

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # Every fetch is answered here, after a delay long enough that the
    # intermediate states can be sampled. `FAIL` names the applications that
    # should come back unreachable.
    # A stand-in Response, not a stub of whatever the caller happens to use.
    # The first version only implemented `.json()`, which is all the old code
    # called; the moment the page started reading `.text()` so it could survive
    # a non-JSON answer, eleven tests failed against a fake that no real
    # browser would ever hand back.
    STUB = """
    var CALLS = [];
    var FAIL = %(fail)s;
    function response(payload, status) {
      var text = JSON.stringify(payload);
      return {status: status || 200, ok: (status || 200) < 400,
              text: function () { return Promise.resolve(text); },
              json: function () { return Promise.resolve(JSON.parse(text)); }};
    }
    window.fetch = function (url, opts) {
      var body = {};
      try { body = JSON.parse((opts || {}).body || '{}'); } catch (e) {}
      CALLS.push({url: String(url), body: body});
      var name = body.name || 'qBittorrent';
      var ok = FAIL.indexOf(name) === -1;
      return new Promise(function (resolve) {
        setTimeout(function () {
          resolve(response({ok: ok, message: ok ? 'Online' : 'Refused'}));
        }, %(delay)d);
      });
    };
    """

    def drive(self, body, fail=(), delay=60):
        probe = """
<script>
%(stub)s
function q(s) { return document.querySelector(s); }
function qa(s) { return [].slice.call(document.querySelectorAll(s)); }
function wait(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
function btn() { return document.getElementById('testAllBtn'); }
// The icon glyph is part of textContent, so it is taken off: the assertions
// are about the words, and an emoji in the expected string would make every
// one of them a test of the icon as well.
function label() {
  var b = btn(), icon = b.querySelector('.ti');
  var t = b.textContent;
  if (icon) t = t.replace(icon.textContent, '');
  return t.trim();
}
function states() {
  return qa('.st').map(function (el) {
    return el.className.replace('st ', ''); });
}
window.addEventListener('load', function () {
  setTimeout(async function () {
    var REPORT = {};
    %(body)s
    var pre = document.createElement('pre');
    pre.id = 'MEASURED'; pre.textContent = JSON.stringify(REPORT);
    document.body.appendChild(pre);
  }, 120);
});
</script>""" % {"stub": self.STUB % {"fail": json.dumps(list(fail)),
                                    "delay": delay},
                "body": body}
        path = os.path.join(self.tmp, "p.html")
        with open(path, "w") as fh:
            fh.write(self.page.replace("</body>", probe + "</body>"))
        dom = browser.dom(path, 1280, 900, budget=15000)
        m = re.search(r'<pre id="MEASURED">(.*?)</pre>', dom, re.S)
        self.assertIsNotNone(m, "the probe did not run")
        return json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&")
                          .replace("&lt;", "<").replace("&gt;", ">"))


class TestTheProgressIsVisible(TestAllCase):
    def test_the_button_says_what_it_is_doing_and_how_far_along(self):
        r = self.drive("""
          REPORT.before = label();
          btn().click();
          await wait(20);
          REPORT.first = label();
          REPORT.spinner = !!q('#testAllBtn .spinner');
          REPORT.busy = btn().getAttribute('aria-busy');
          await wait(140);
          REPORT.later = label();
        """)
        self.assertEqual(r["before"], "Test All")
        self.assertEqual(r["first"], "Testing 1 of %d" % TARGETS)
        self.assertTrue(r["spinner"], "no progress indicator")
        self.assertEqual(r["busy"], "true")
        self.assertEqual(r["later"], "Testing 3 of %d" % TARGETS)

    def test_the_count_reaches_every_target_exactly_once(self):
        r = self.drive("""
          var seen = [];
          var timer = setInterval(function () {
            var t = label();
            if (t && seen[seen.length - 1] !== t) seen.push(t);
          }, 8);
          btn().click();
          await wait(%d);
          clearInterval(timer);
          REPORT.seen = seen;
          REPORT.calls = CALLS.length;
        """ % (60 * TARGETS + 400))
        counts = [s for s in r["seen"] if s.startswith("Testing ")]
        self.assertEqual(counts,
                         ["Testing %d of %d" % (i, TARGETS)
                          for i in range(1, TARGETS + 1)])
        self.assertEqual(r["calls"], TARGETS, "one request per target")

    def test_progress_is_announced_not_only_drawn(self):
        r = self.drive("""
          btn().click();
          await wait(20);
          REPORT.live = q('#testAllStatus').textContent;
          REPORT.role = q('#testAllStatus').getAttribute('role');
          REPORT.polite = q('#testAllStatus').getAttribute('aria-live');
        """)
        self.assertIn("Testing 1 of %d" % TARGETS, r["live"])
        self.assertIn("qBittorrent", r["live"])
        self.assertEqual(r["role"], "status")
        self.assertEqual(r["polite"], "polite")

    def test_there_is_no_overlay_or_modal(self):
        r = self.drive("""
          btn().click();
          await wait(40);
          REPORT.openModals = qa('#qbitModal:not([hidden]), #appModal:not([hidden])').length;
          REPORT.toolbarVisible = getComputedStyle(q('.toolbar')).display;
          REPORT.tableVisible = getComputedStyle(q('.applist')).display;
        """)
        self.assertEqual(r["openModals"], 0)
        self.assertNotEqual(r["toolbarVisible"], "none")
        self.assertNotEqual(r["tableVisible"], "none")


class TestEachRowResolvesOnItsOwn(TestAllCase):
    def test_statuses_land_one_at_a_time_rather_than_all_at_once(self):
        r = self.drive("""
          REPORT.beforeClick = states();
          btn().click();
          REPORT.atStart = states();
          await wait(90);
          REPORT.afterOne = states();
          await wait(60);
          REPORT.afterTwo = states();
          await wait(400);
          REPORT.atEnd = states();
        """)
        # Right after the click every row has been reset and the first is
        # already in flight, so "unknown" is not the whole picture. What
        # matters is that no row is still showing a verdict.
        self.assertEqual(r["atStart"].count("st-ok"), 0)
        self.assertEqual(r["atStart"].count("st-err"), 0)
        self.assertEqual(len(r["beforeClick"]), TARGETS)
        self.assertEqual(r["afterOne"].count("st-ok"), 1)
        self.assertEqual(r["afterTwo"].count("st-ok"), 2)
        self.assertEqual(r["atEnd"].count("st-ok"), TARGETS)

    def test_the_row_being_tested_says_so(self):
        r = self.drive("""
          btn().click();
          await wait(20);
          REPORT.testing = states().filter(function (c) {
            return c.indexOf('st-testing') !== -1; }).length;
          await wait(400);
          REPORT.afterwards = states().filter(function (c) {
            return c.indexOf('st-testing') !== -1; }).length;
        """)
        self.assertEqual(r["testing"], 1, "exactly one row is in flight")
        self.assertEqual(r["afterwards"], 0)

    def test_a_failure_marks_only_the_one_that_failed(self):
        r = self.drive("""
          btn().click();
          await wait(500);
          REPORT.states = states();
          REPORT.titles = qa('.st').map(function (e) { return e.title; });
        """, fail=("Radarr",))
        self.assertEqual(r["states"].count("st-err"), 1)
        self.assertEqual(r["states"].count("st-ok"), TARGETS - 1)
        self.assertIn("Refused", r["titles"])

    def test_no_request_carries_an_api_key(self):
        """A per-app test sends an index; the server resolves the stored key.
        The browser never has it to send."""
        r = self.drive("""
          btn().click();
          await wait(500);
          REPORT.bodies = CALLS.map(function (c) { return c.body; });
        """)
        for body in r["bodies"]:
            self.assertNotIn("api_key", body)
            self.assertNotIn("password", body)
        arr_calls = [b for b in r["bodies"] if "index" in b]
        self.assertEqual(sorted(b["index"] for b in arr_calls),
                         list(range(len(ARRS))))


class TestItCannotBeStartedTwice(TestAllCase):
    def test_a_second_click_while_running_does_nothing(self):
        r = self.drive("""
          btn().click();
          await wait(20);
          btn().click();
          btn().click();
          await wait(500);
          REPORT.calls = CALLS.length;
        """)
        self.assertEqual(r["calls"], TARGETS,
                         "a repeat click queued another run")

    def test_the_button_is_disabled_while_it_runs(self):
        r = self.drive("""
          btn().click();
          await wait(20);
          REPORT.duringDisabled = btn().disabled;
          // 4 requests at 60ms, then the 2600ms the result stays up.
          await wait(3200);
          REPORT.afterDisabled = btn().disabled;
        """)
        self.assertTrue(r["duringDisabled"])
        self.assertFalse(r["afterDisabled"])


class TestItFinishesAndGetsOutOfTheWay(TestAllCase):
    def test_it_ends_with_a_result_then_returns_to_its_own_name(self):
        r = self.drive("""
          btn().click();
          await wait(450);
          REPORT.done = label();
          REPORT.spinnerGone = !q('#testAllBtn .spinner');
          await wait(2900);
          REPORT.settled = label();
          REPORT.busy = btn().getAttribute('aria-busy');
        """)
        self.assertEqual(r["done"], "All %d online" % TARGETS)
        self.assertTrue(r["spinnerGone"])
        self.assertEqual(r["settled"], "Test All",
                         "a result must not become the button's name")
        self.assertIsNone(r["busy"])

    def test_the_completion_state_names_the_failures(self):
        r = self.drive("""
          btn().click();
          await wait(450);
          REPORT.done = label();
          REPORT.live = q('#testAllStatus').textContent;
        """, fail=("Radarr", "Lidarr"))
        self.assertEqual(r["done"], "2 of %d failed" % TARGETS)
        self.assertEqual(r["live"], "2 of %d failed" % TARGETS)

    def test_it_can_be_run_again_once_it_has_settled(self):
        r = self.drive("""
          btn().click();
          await wait(450);
          await wait(2900);
          REPORT.first = CALLS.length;
          btn().click();
          await wait(450);
          REPORT.second = CALLS.length;
        """)
        self.assertEqual(r["first"], TARGETS)
        self.assertEqual(r["second"], TARGETS * 2)

    def test_the_label_does_not_move_when_the_spinner_replaces_the_icon(self):
        """The spinner stands where the icon stood, so it has to take the
        icon's box. A smaller one shifted the label up nine pixels at the
        moment the button was most likely to be looked at."""
        r = self.drive("""
          function labelTop() {
            var b = btn();
            var w = document.createTreeWalker(b, NodeFilter.SHOW_TEXT), n;
            while ((n = w.nextNode())) {
              if (!n.textContent.trim()) continue;
              if (n.parentNode.classList &&
                  n.parentNode.classList.contains('ti')) continue;
              var r = document.createRange(); r.selectNode(n);
              return Math.round(r.getBoundingClientRect().top);
            }
            return null;
          }
          function iconBox() {
            var el = q('#testAllBtn .ti') || q('#testAllBtn .spinner');
            return Math.round(el.getBoundingClientRect().height);
          }
          REPORT.beforeTop = labelTop();
          REPORT.beforeIcon = iconBox();
          btn().click();
          await wait(30);
          REPORT.duringTop = labelTop();
          REPORT.duringIcon = iconBox();
        """)
        self.assertEqual(r["beforeIcon"], r["duringIcon"])
        self.assertEqual(r["beforeTop"], r["duringTop"])

    def test_the_toolbar_does_not_jump_while_the_label_changes(self):
        """The button is the last one in the toolbar, so it may grow to the
        right, but nothing before it is allowed to move."""
        r = self.drive("""
          function lefts() { return qa('.toolbar > *').map(function (el) {
            return Math.round(el.getBoundingClientRect().left); }); }
          REPORT.before = lefts();
          REPORT.heightBefore = Math.round(q('.toolbar').getBoundingClientRect().height);
          btn().click();
          await wait(40);
          REPORT.during = lefts();
          REPORT.heightDuring = Math.round(q('.toolbar').getBoundingClientRect().height);
        """)
        self.assertEqual(r["before"], r["during"])
        self.assertEqual(r["heightBefore"], r["heightDuring"],
                         "the spinner changed the toolbar's height")


if __name__ == "__main__":
    unittest.main()
