"""The System page activity log: opens at the newest line, and can follow.

This is polish on a viewer that already existed, so most of what these tests
protect is what did *not* change: the same redacted ring, the same endpoint, no
second log path, and no way for the browser to accumulate more than the ring
holds however long a Live session runs.

The behavioural half drives a real browser with `fetch` stubbed, because the
things worth asserting - that scrolling up is not undone by the next poll, and
that a failed poll leaves the lines on screen alone - are timing and scroll
state, which no amount of reading the template can show. It is skipped when
this machine has no working headless browser, which is probed rather than
assumed; see tests/browser.py.
"""
import os
import re
import sys
import json
import shutil
import logging
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import browser  # noqa: E402
from protectarr import config as cfg_mod  # noqa: E402
from protectarr import logs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(ROOT, "protectarr", "templates", "system.html")
CSS_PATH = os.path.join(ROOT, "protectarr", "static", "style.css")

FAKE_KEY = "0123456789abcdef" * 4


def read(path):
    with open(path) as fh:
        return fh.read()


class Loose(dict):
    def __getattr__(self, k):
        return self.get(k)


def stub_service():
    return Loose(state=Loose(
        stats=Loose(reaped_total=0, last_reap=None), running=True,
        last_scan=None, last_error=None, blocklist=Loose(), banned=Loose()))


class SystemPageCase(unittest.TestCase):
    """A configured app with a real logger attached, and a signed-in client."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="protectarr-logview-")
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        self.cfg = {
            "logging": {"level": "debug", "console_level": "error",
                        "file_enabled": False},
            "web": {"api_key": FAKE_KEY, "auth": {"method": "none"}},
            "qbittorrent": {"password": "hunter2hunter2"},
            "arrs": [], "harvest": {},
        }
        with open(cfg_mod.CONFIG_PATH, "w") as fh:
            json.dump(self.cfg, fh)     # YAML reads JSON
        logs._ring.clear()
        logs.configure(self.cfg)
        from protectarr import web
        app = web.create_app(stub_service())
        app.config["TESTING"] = True
        self.web = web
        self.client = app.test_client()
        with self.client.session_transaction() as s:
            s["user"] = "admin"

    def tearDown(self):
        for h in list(logging.getLogger(logs.LOGGER_NAME).handlers):
            logging.getLogger(logs.LOGGER_NAME).removeHandler(h)
        logs._ring.clear()
        shutil.rmtree(self.dir, ignore_errors=True)


class TestItUsesTheExistingLogPath(SystemPageCase):
    """No new endpoint, no second source, no unredacted variant."""

    def test_the_page_polls_the_endpoint_that_already_existed(self):
        html = read(TEMPLATE)
        self.assertIn('url_for("api_log")', html)

    def test_no_streaming_transport_was_introduced(self):
        html = read(TEMPLATE)
        for banned in ("WebSocket", "EventSource", "/stream", "text/event-stream"):
            self.assertNotIn(banned, html)

    def test_the_endpoint_serves_the_same_lines_the_page_was_rendered_with(self):
        log = logs.get("test")
        for i in range(5):
            log.info("scan pass %d", i)
        page = self.client.get("/system").data.decode()
        api = self.client.get("/api/v1/log?limit=%d" % logs.RING_SIZE).get_json()
        self.assertEqual(api, logs.ring())
        for line in api:
            self.assertIn(line, page)

    def test_the_endpoint_is_redacted_exactly_as_the_page_is(self):
        """The whole reason Live may reuse it: it is the same ring."""
        logs.get("test").info("calling with apikey=%s", FAKE_KEY)
        api = self.client.get("/api/v1/log?limit=%d" % logs.RING_SIZE).get_json()
        self.assertTrue(api)
        blob = "\n".join(api)
        self.assertNotIn(FAKE_KEY, blob)
        self.assertIn(logs.MASK, blob)
        self.assertNotIn(FAKE_KEY, self.client.get("/system").data.decode())

    def test_the_endpoint_still_refuses_an_anonymous_caller(self):
        self.cfg["web"]["auth"] = {"method": "forms", "username": "admin",
                                   "password_hash": "x"}
        with open(cfg_mod.CONFIG_PATH, "w") as fh:
            json.dump(self.cfg, fh)
        app = self.web.create_app(stub_service())
        app.config["TESTING"] = True
        r = app.test_client().get("/api/v1/log")
        self.assertEqual(r.status_code, 401)

    def test_the_poll_asks_for_exactly_what_the_ring_holds(self):
        """Not a literal. A smaller RING_SIZE would otherwise truncate Live."""
        page = self.client.get("/system").data.decode()
        self.assertIn("?limit=%d" % logs.RING_SIZE, page)

    def test_the_endpoint_cannot_return_more_than_the_ring(self):
        log = logs.get("test")
        for i in range(logs.RING_SIZE + 200):
            log.info("line %d", i)
        api = self.client.get("/api/v1/log?limit=100000").get_json()
        self.assertEqual(len(api), logs.RING_SIZE)


class TestViewerMarkup(SystemPageCase):
    """The controls exist, and the box is replaced rather than appended to."""

    def setUp(self):
        super().setUp()
        self.html = read(TEMPLATE)

    def test_the_order_is_still_oldest_first(self):
        """Following the tail is the feature; reversing the log is not."""
        log = logs.get("test")
        log.info("first")
        log.info("second")
        page = self.client.get("/system").data.decode()
        self.assertLess(page.index("first"), page.index("second"))

    def test_there_is_a_live_toggle(self):
        self.assertIn('id="live_toggle"', self.html)
        self.assertIn('type="checkbox"', self.html)

    def test_live_defaults_to_off(self):
        """Nothing polls until someone asks for it.

        The box is filled server-side, so an operator who opens System to read
        what happened gets that without a request loop starting behind them.
        Checked against the rendered page, not the template, because a default
        could arrive from the view as easily as from a literal attribute.
        """
        page = self.client.get("/system").data.decode()
        tag = re.search(r"<input[^>]*id=\"live_toggle\"[^>]*>", page)
        self.assertIsNotNone(tag, "the toggle is not in the rendered page")
        self.assertNotIn("checked", tag.group(0))

    def test_polling_is_off_until_the_toggle_is_used(self):
        """No interval is armed at load."""
        body = self.html[self.html.index("{% block scripts %}"):]
        armed = re.search(r"setInterval", body)
        self.assertTrue(armed)
        before = body[:armed.start()]
        self.assertIn("toggle.checked", before[-200:],
                      "setInterval is not guarded by the toggle")

    def test_the_box_is_replaced_not_appended_to(self):
        """What keeps the browser copy bounded by the ring."""
        body = self.html[self.html.index("{% block scripts %}"):]
        self.assertIn("box.textContent = text", body)
        for grow in ("box.textContent +=", "box.innerHTML +=",
                     "appendChild", "insertAdjacentHTML"):
            self.assertNotIn(grow, body)

    def test_nothing_is_deduplicated_by_message_text(self):
        """Identical lines legitimately repeat, so none of this may appear."""
        body = self.html[self.html.index("{% block scripts %}"):]
        for dedupe in ("indexOf(", "lastIndexOf(", "new Set(", "filter("):
            self.assertNotIn(dedupe, body)

    def test_the_session_cookie_is_sent_with_the_poll(self):
        self.assertIn("credentials: 'same-origin'", self.html)

    def test_a_failed_poll_reports_without_clearing(self):
        body = self.html[self.html.index("{% block scripts %}"):]
        catch = body[body.index(".catch("):]
        self.assertIn("Live update failed", catch)
        self.assertNotIn("box.textContent", catch,
                         "the failure path touches the displayed lines")

    def test_the_poll_interval_is_a_few_seconds(self):
        self.assertGreaterEqual(self.web.LOG_POLL_MS, 1000)
        self.assertLessEqual(self.web.LOG_POLL_MS, 15000)


# --------------------------------------------------------------------------
# Behaviour, in a browser, with the network replaced.

DRIVER = """
<script>
(function () {
  var box = document.getElementById('log_box');
  var toggle = document.getElementById('live_toggle');
  var status = document.getElementById('live_status');
  var jump = document.getElementById('log_latest');
  var out = {}, calls = 0, mode = 'ok', server = [];
  for (var i = 0; i < 40; i++) server.push('[10:00:00] INFO    line ' + i);

  function push(n) {
    for (var i = 0; i < n; i++)
      server.push('[10:00:00] INFO    added ' + server.length);
    // The server side of the ring: the endpoint never returns more than this.
    if (server.length > RING) server = server.slice(-RING);
  }
  window.fetch = function () {
    calls++;
    if (mode === 'fail') return Promise.reject(new Error('down'));
    var body = server.slice();
    return Promise.resolve({ok: true, json: function () {
      return Promise.resolve(body); }});
  };
  function atBottom() {
    return box.scrollHeight - box.scrollTop - box.clientHeight <= 24;
  }
  function lines() { return box.textContent.split('\\n').length; }
  function at(t, fn) { setTimeout(fn, t); }
  // Headless chromium under --virtual-time-budget dispatches at most one
  // scroll event for the whole run: it produces no compositor frames, and the
  // frame is where the coalesced event would go. Measured, not assumed. So the
  // driver scrolls and then says so, which still exercises the page's own
  // listener - only the browser's dispatch is stood in for.
  function scrollTo(top) {
    box.scrollTop = top;
    box.dispatchEvent(new Event('scroll'));
  }

  out.jumpHiddenAtLoad = !shown(jump);
  out.initialScrollTop = box.scrollTop;
  out.initialAtBottom = atBottom();
  out.initialScrollable = box.scrollHeight > box.clientHeight + 24;

  at(50, function () {
    out.callsWhileOff = calls;
    // The change event is what a click produces; dispatching it drives the
    // same handler a person would.
    toggle.checked = true;
    toggle.dispatchEvent(new Event('change'));
  });
  at(300, function () {
    out.callsAfterEnabling = calls;
    out.followedFirstPoll = atBottom();
    out.linesAfterFirstPoll = lines();
    push(30);
    scrollTo(0);                          // the operator reads older lines
  });
  // A scroll event is dispatched asynchronously, so the control's state is
  // read on a later turn rather than in the handler that moved the box.
  // Whether it is on screen, not whether the attribute is set: `.btn` carries
  // an explicit display, which beats the user agent's rule for [hidden], so
  // the property can be true while the button is still visible.
  function shown(el) { return getComputedStyle(el).display !== 'none'; }
  at(350, function () { out.jumpShownWhenScrolledUp = shown(jump); });
  at(5400, function () {
    out.scrollTopAfterPollWhileScrolledUp = box.scrollTop;
    out.linesWhileScrolledUp = lines();
    scrollTo(box.scrollHeight);           // and goes back to the bottom
    push(30);
  });
  at(5450, function () { out.jumpHiddenAtBottom = !shown(jump); });
  at(10400, function () {
    out.followResumed = atBottom();
    out.expectedTail = server[server.length - 1];
    out.tailAfterResuming = box.textContent.slice(-out.expectedTail.length);
    mode = 'fail';
    out.textBeforeFailure = box.textContent;
  });
  at(15400, function () {
    out.textSurvivedFailure = (box.textContent === out.textBeforeFailure);
    out.statusOnFailure = status.textContent;
    mode = 'ok';
    push(30);
  });
  at(20400, function () {
    out.statusAfterRecovery = status.textContent;
    out.recoveredContent = (box.textContent !== out.textBeforeFailure);
    push(5000);                           // far more than the ring can hold
  });
  at(25400, function () {
    out.linesAfterFlood = lines();
    toggle.checked = false;
    toggle.dispatchEvent(new Event('change'));
    out.callsAtStop = calls;
  });
  at(31000, function () {
    out.callsAfterStopping = calls;
    out.navigated = (document.location.hash !== '');
    var p = document.createElement('pre');
    p.id = 'M';
    p.textContent = JSON.stringify(out);
    document.body.appendChild(p);
  });
})();
</script>"""


RESTING = """
<script>
window.addEventListener('load', function () {
  var box = document.getElementById('log_box');
  var toggle = document.getElementById('live_toggle');
  var jump = document.getElementById('log_latest');
  var p = document.createElement('pre');
  p.id = 'M';
  p.textContent = JSON.stringify({
    live: toggle.checked,
    scrollTop: Math.round(box.scrollTop),
    maxScroll: Math.round(box.scrollHeight - box.clientHeight),
    clientH: box.clientHeight,
    scrollH: box.scrollHeight,
    lines: box.textContent.split('\\n').length,
    jumpShown: getComputedStyle(jump).display !== 'none'});
  document.body.appendChild(p);
});
</script>"""


@unittest.skipUnless(browser.BROWSER, browser.REASON)
class TestRestingState(SystemPageCase):
    """The page as it arrives, with nothing touched and no network stubbed.

    Deliberately separate from the scripted session below, which enables Live
    a moment after load. Positioning at the newest line is not a Live feature
    and must not come to depend on one, so it is proved in a run where the
    toggle is never dispatched and `fetch` is never replaced.
    """

    trace = None

    def setUp(self):
        super().setUp()
        if TestRestingState.trace is not None:
            return
        log = logs.get("test")
        for i in range(logs.RING_SIZE + 50):
            log.info("Scan pass %d complete: 18 torrents inspected, 0 flagged", i)
        page = self.client.get("/system").data.decode()
        sheet = read(CSS_PATH)
        # A function replacement: a string one would treat the stylesheet's CSS
        # escapes (`\25B8`) as regex group references.
        page = re.sub(r'<link rel="stylesheet"[^>]*>',
                      lambda m: "<style>%s</style>" % sheet, page)
        path = os.path.join(self.dir, "resting.html")
        with open(path, "w") as fh:
            fh.write(page.replace("</body>", RESTING + "</body>"))
        out = browser.dom(path, 1440, 900)
        m = re.search(r'<pre id="M">(.*?)</pre>', out, re.S)
        self.assertTrue(m and m.group(1).strip(), "the page never reported")
        TestRestingState.trace = json.loads(
            m.group(1).replace("&quot;", '"').replace("&amp;", "&"))

    def test_live_is_off_when_the_page_arrives(self):
        self.assertFalse(self.trace["live"])

    def test_it_is_scrolled_to_the_newest_line_with_live_off(self):
        """Exactly at the bottom, not merely near it."""
        self.assertGreater(self.trace["maxScroll"], 0,
                           "the fixture did not overflow the box")
        self.assertEqual(self.trace["scrollTop"], self.trace["maxScroll"])

    def test_the_distance_it_saves_is_the_reason_this_exists(self):
        """A full ring is about 36 screenfuls below the fold."""
        self.assertEqual(self.trace["lines"], logs.RING_SIZE)
        screens = self.trace["maxScroll"] / float(self.trace["clientH"])
        self.assertGreater(screens, 20)

    def test_the_jump_control_is_not_shown_at_rest(self):
        self.assertFalse(self.trace["jumpShown"])


@unittest.skipUnless(browser.BROWSER, browser.REASON)
class TestViewerBehaviour(SystemPageCase):
    """One scripted session, asserted from its trace.

    The whole session runs once and every test reads a field out of the same
    trace: chromium's virtual clock fast-forwards the 5s interval, but a
    browser per assertion would still be about thirty seconds of process spawn
    for facts that are all true of one run.
    """

    trace = None

    def setUp(self):
        super().setUp()
        if TestViewerBehaviour.trace is not None:
            return
        log = logs.get("test")
        for i in range(120):
            log.info("startup line %d", i)
        page = self.client.get("/system").data.decode()
        sheet = read(CSS_PATH)
        # A function replacement: a string one would treat the stylesheet's CSS
        # escapes (`\25B8`) as regex group references.
        page = re.sub(r'<link rel="stylesheet"[^>]*>',
                      lambda m: "<style>%s</style>" % sheet, page)
        page = page.replace("</body>", "<script>var RING = %d;</script>%s</body>"
                            % (logs.RING_SIZE, DRIVER))
        path = os.path.join(self.dir, "system.html")
        with open(path, "w") as fh:
            fh.write(page)
        out = browser.dom(path, 1440, 900, budget=40000)
        m = re.search(r'<pre id="M">(.*?)</pre>', out, re.S)
        self.assertTrue(m and m.group(1).strip(),
                        "the driver never finished:\n" + out[-2000:])
        TestViewerBehaviour.trace = json.loads(
            m.group(1).replace("&quot;", '"').replace("&amp;", "&")
            .replace("&lt;", "<").replace("&gt;", ">"))

    def test_it_opens_on_the_newest_lines(self):
        self.assertTrue(self.trace["initialScrollable"],
                        "the fixture did not produce a scrollable box")
        self.assertTrue(self.trace["initialAtBottom"])
        self.assertGreater(self.trace["initialScrollTop"], 0)

    def test_nothing_is_polled_until_live_is_switched_on(self):
        self.assertEqual(self.trace["callsWhileOff"], 0)

    def test_switching_live_on_refreshes_immediately(self):
        """Not after one interval of staring at a stale box."""
        self.assertGreaterEqual(self.trace["callsAfterEnabling"], 1)

    def test_new_content_arrives_without_a_page_load(self):
        self.assertFalse(self.trace["navigated"])
        self.assertGreater(self.trace["linesWhileScrolledUp"],
                           self.trace["linesAfterFirstPoll"])

    def test_scrolling_up_is_not_undone_by_the_next_poll(self):
        self.assertEqual(self.trace["scrollTopAfterPollWhileScrolledUp"], 0)

    def test_returning_to_the_bottom_resumes_following(self):
        self.assertTrue(self.trace["followResumed"])
        self.assertEqual(self.trace["tailAfterResuming"],
                         self.trace["expectedTail"])

    def test_the_jump_control_appears_only_when_it_would_do_something(self):
        """Measured as computed display, not as the `hidden` property.

        `.btn` declares `display: inline-flex`, which outranks the user
        agent's `[hidden] { display: none }`. Asserting `el.hidden` passed
        while the button sat on screen at all times, which is how the first
        version of this shipped.
        """
        self.assertTrue(self.trace["jumpHiddenAtLoad"])
        self.assertTrue(self.trace["jumpShownWhenScrolledUp"])
        self.assertTrue(self.trace["jumpHiddenAtBottom"])

    def test_a_failed_refresh_keeps_the_lines_on_screen(self):
        self.assertTrue(self.trace["textSurvivedFailure"])
        self.assertEqual(self.trace["statusOnFailure"], "Live update failed")

    def test_it_recovers_on_the_next_successful_refresh(self):
        self.assertEqual(self.trace["statusAfterRecovery"], "")
        self.assertTrue(self.trace["recoveredContent"])

    def test_the_browser_copy_stays_bounded(self):
        """5,000 lines pushed through a 500-line ring is still 500 lines."""
        self.assertLessEqual(self.trace["linesAfterFlood"], logs.RING_SIZE)

    def test_switching_live_off_stops_the_polling(self):
        self.assertEqual(self.trace["callsAfterStopping"],
                         self.trace["callsAtStop"])


if __name__ == "__main__":
    unittest.main()
