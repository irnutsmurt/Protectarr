"""What the pickers say when they cannot fill themselves in.

Reported from a screenshot: the Allowed Categories and Allowed Tags lists were
showing `SyntaxError: Unexpected token '<' ...` where an explanation should be.

That is not a demo artefact. Two different failures reached the same place and
both were rendered raw:

  the endpoint answering `{ok: false, message: <a requests exception>}`, which
  is what an unreachable qBittorrent produces, and

  the request never reaching the endpoint at all, which makes `r.json()` throw.
  Measured: with Forms authentication and an expired session, `/qbit/taxonomy`
  and `/api/dashboard` both answer 401 with `Content-Type: text/html` and the
  body `Unauthorized`. A proxy in front of Protectarr answers HTML; so does an
  unhandled error.

The first names a Python library at an operator. The second names the parser,
and points at qBittorrent when the actual problem is their session.

So the contract here is: the card gets one short sentence naming the component
that is actually in trouble, the raw failure goes to the console, and the saved
selections stay on screen either way, because an unreachable qBittorrent is not
evidence that a category stopped existing.

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

# Anything that would tell the operator they are reading a stack trace.
LEAKY = ("SyntaxError", "Unexpected token", "JSON.parse", "TypeError",
         "not valid JSON", "<!DOCTYPE", "Traceback")


class FakeService:
    class _State(dict):
        def __getattr__(self, k):
            return self.get(k)

    state = _State(stats=_State(by_indexer={}), running=False,
                   blocklist=_State(), banned=_State())

    def reload(self):
        pass


class TestTheServerReallyAnswersWithNonJson(unittest.TestCase):
    """The half that does not need a browser: proving the failure is real."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        cfg_mod.save({
            "qbittorrent": {"url": "http://192.0.2.10:8080"},
            "web": {"api_key": "k" * 64, "secret_key": "s" * 40,
                    "auth": {"method": "forms", "required": "enabled",
                             "username": "admin",
                             "password_hash": "pbkdf2:sha256:1$fake$notreal",
                             "trusted_proxies": []}},
            "logging": {"file_enabled": False,
                        "path": os.path.join(self.dir, "logs")},
        })
        self.app = web.create_app(FakeService())
        self.app.config["TESTING"] = True

    def test_an_expired_session_answers_these_endpoints_with_text(self):
        """The production path behind the reported screenshot. Not a 302 to a
        login page and not JSON: 401 with a plain-text body, which is exactly
        what `r.json()` cannot parse."""
        anon = self.app.test_client()
        for path in ("/qbit/taxonomy", "/api/dashboard"):
            with self.subTest(path=path):
                r = anon.get(path)
                self.assertEqual(r.status_code, 401)
                self.assertNotIn("json", r.headers.get("Content-Type", ""))
                with self.assertRaises(ValueError):
                    json.loads(r.get_data(as_text=True))

    def test_an_unreachable_qbittorrent_still_answers_with_json(self):
        """The other failure, which the endpoint does handle. It has to stay
        distinguishable from the one above: different component, different
        fix."""
        authed = self.app.test_client()
        with authed.session_transaction() as s:
            s["authed"] = True
        r = authed.get("/qbit/taxonomy")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertFalse(body["ok"])
        self.assertTrue(body["message"])


@unittest.skipIf(browser.BROWSER is None, browser.REASON)
class PickerCase(unittest.TestCase):
    """Drives the real page with the two failures stubbed in turn."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        cfg_mod.save({
            "qbittorrent": {"url": "http://192.0.2.10:8080"},
            "safety": {"mode": "either",
                       "allowed_categories": ["tv-sonarr", "radarr"],
                       "allowed_tags": ["protectarr"]},
            "detection": {"archive_detection": {
                "enabled": True, "indexers": ["Meridian Tracker (Prowlarr)"]}},
            "web": {"api_key": "k" * 64, "secret_key": "s" * 40,
                    "auth": {"method": "none", "required": "enabled",
                             "username": "", "password_hash": "",
                             "trusted_proxies": []}},
            "logging": {"file_enabled": False,
                        "path": os.path.join(self.dir, "logs")},
        })
        app = web.create_app(FakeService())
        app.config["TESTING"] = True
        self.client = app.test_client()
        with self.client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"

    @staticmethod
    def inject(html, probe):
        """Append `probe` before the LAST `</body>`, not the first.

        `str.replace` with no count replaces every occurrence, and one of the
        stubs here builds a fake proxy error page whose JavaScript string
        contains `</body>`. The probe was being spliced into the middle of that
        string literal, which made the stub a syntax error, which meant it
        never ran and every simulated failure came out as "Protectarr is not
        responding" instead.
        """
        i = html.rfind("</body>")
        assert i != -1, "no </body> in the rendered page"
        return html[:i] + probe + html[i:]

    def install(self, html, stub):
        """The stub has to be in place before the page's own scripts run.

        The card scripts call `fetchJson` at parse time, in the body. A stub
        appended after them never gets used: the real `fetch` has already run
        against a file:// URL and rejected, and every failure reads as
        "Protectarr is not responding" whatever was being simulated. It goes
        after the head script that defines `fetchJson` and before the body.
        """
        assert "function fetchJson" in html, "the helper is not on the page"
        out = html.replace("</head>", "<script>%s</script></head>" % stub, 1)
        assert out != html, "no </head> to install the stub before"
        return out

    def drive(self, stub):
        html = self.install(
            self.client.get("/settings/detection-remediation")
                       .get_data(as_text=True), stub)
        probe = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function text(sel) {
      var el = document.querySelector(sel);
      return el ? el.textContent.replace(/\\s+/g, ' ').trim() : null;
    }
    var out = {cats: text('#cat_boxes'), tags: text('#tag_boxes'),
               indexers: text('#indexer_boxes'),
               savedCats: [].map.call(
                 document.querySelectorAll('[name=allowed_categories]'),
                 function (i) { return i.value; }),
               savedChecked: [].every.call(
                 document.querySelectorAll('[name=allowed_categories]'),
                 function (i) { return i.checked; }),
               savedIdx: [].map.call(
                 document.querySelectorAll('[name=archive_indexers]'),
                 function (i) { return i.value; })};
    var pre = document.createElement('pre');
    pre.id = 'MEASURED'; pre.textContent = JSON.stringify(out);
    document.body.appendChild(pre);
  }, 400);
});
</script>"""
        path = os.path.join(self.dir, "p.html")
        with open(path, "w") as fh:
            fh.write(self.inject(html, probe))
        dom = browser.dom(path, 1280, 900, budget=6000)
        m = re.search(r'<pre id="MEASURED">(.*?)</pre>', dom, re.S)
        self.assertIsNotNone(m, "the probe did not run")
        return json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&")
                          .replace("&lt;", "<").replace("&gt;", ">"))

    # An expired session, exactly as measured from the server above.
    UNAUTHORIZED = """
    window.fetch = function () {
      return Promise.resolve({
        status: 401, ok: false,
        text: function () { return Promise.resolve('Unauthorized'); },
        json: function () { return Promise.reject(new SyntaxError(
          "Unexpected token 'U', \\"Unauthorized\\" is not valid JSON")); }});
    };"""

    # A reverse proxy answering with its own error page.
    PROXY_HTML = """
    window.fetch = function () {
      var body = '<!DOCTYPE html><html><head><title>502</title></head>' +
                 '<body><h1>502 Bad Gateway</h1></body></html>';
      return Promise.resolve({
        status: 502, ok: false,
        text: function () { return Promise.resolve(body); },
        json: function () { return Promise.reject(new SyntaxError(
          "Unexpected token '<'")); }});
    };"""

    # Nothing listening at all.
    NO_SERVER = """
    window.fetch = function () {
      return Promise.reject(new TypeError('Failed to fetch'));
    };"""

    # The endpoint answering honestly that qBittorrent is down.
    QBIT_DOWN = """
    window.fetch = function (url) {
      var payload = String(url).indexOf('taxonomy') !== -1
        ? {ok: false, message: "HTTPConnectionPool(host='192.0.2.10', port=8080): "
            + "Max retries exceeded with url: /api/v2/auth/login "
            + "(Caused by NewConnectionError('<urllib3.connection.HTTPConnection "
            + "object at 0x7f>: Failed to establish a new connection: "
            + "[Errno 111] Connection refused'))"}
        : {ok: true, data: {indexers: [], errors: ['Sonarr: connection refused']}};
      var text = JSON.stringify(payload);
      return Promise.resolve({
        status: 200, ok: true,
        text: function () { return Promise.resolve(text); },
        json: function () { return Promise.resolve(JSON.parse(text)); }});
    };"""


class TestNoRawExceptionReachesTheCard(PickerCase):
    def test_an_expired_session_does_not_print_a_syntaxerror(self):
        """The reported defect, in the shape production produces it."""
        r = self.drive(self.UNAUTHORIZED)
        for field in ("cats", "tags", "indexers"):
            with self.subTest(field=field):
                for needle in LEAKY:
                    self.assertNotIn(needle, r[field])

    def test_a_proxy_error_page_does_not_print_a_syntaxerror(self):
        r = self.drive(self.PROXY_HTML)
        for field in ("cats", "tags", "indexers"):
            with self.subTest(field=field):
                for needle in LEAKY:
                    self.assertNotIn(needle, r[field])

    def test_no_server_at_all_does_not_print_a_typeerror(self):
        r = self.drive(self.NO_SERVER)
        for field in ("cats", "tags", "indexers"):
            with self.subTest(field=field):
                for needle in LEAKY:
                    self.assertNotIn(needle, r[field])

    def test_an_unreachable_qbittorrent_does_not_print_a_python_traceback(self):
        """The endpoint's own message is a requests exception. It is true, and
        it still has no business being the sentence in the card."""
        r = self.drive(self.QBIT_DOWN)
        for field in ("cats", "tags"):
            with self.subTest(field=field):
                self.assertNotIn("urllib3", r[field])
                self.assertNotIn("Errno", r[field])
                self.assertNotIn("HTTPConnectionPool", r[field])


class TestTheMessageNamesTheRightComponent(PickerCase):
    def test_a_down_qbittorrent_is_blamed_on_qbittorrent(self):
        r = self.drive(self.QBIT_DOWN)
        self.assertIn("Could not reach qBittorrent", r["cats"])
        self.assertIn("showing your saved categories", r["cats"])
        self.assertIn("showing your saved tags", r["tags"])

    def test_an_expired_session_is_blamed_on_the_session(self):
        """Not on qBittorrent. Telling someone their download client is down
        when their session expired sends them to debug the wrong machine."""
        r = self.drive(self.UNAUTHORIZED)
        for field in ("cats", "tags", "indexers"):
            with self.subTest(field=field):
                self.assertIn("session has expired", r[field])
                self.assertNotIn("Could not reach qBittorrent", r[field])

    def test_an_unreachable_protectarr_says_so(self):
        r = self.drive(self.NO_SERVER)
        self.assertIn("Protectarr is not responding", r["cats"])

    def test_an_unexpected_response_is_not_dressed_up_as_something_known(self):
        r = self.drive(self.PROXY_HTML)
        self.assertIn("unexpected response", r["cats"])

    def test_the_indexer_list_blames_the_applications(self):
        r = self.drive(self.QBIT_DOWN)
        self.assertIn("Could not reach your applications", r["indexers"])


class TestTheSavedSelectionSurvivesEveryFailure(PickerCase):
    """The reason these pickers report a failure rather than rendering empty:
    an unreachable qBittorrent is not evidence that a category stopped
    existing, and an empty POST would wipe the list."""

    def test_saved_categories_stay_on_screen_and_stay_checked(self):
        for name, stub in (("session", self.UNAUTHORIZED),
                           ("proxy", self.PROXY_HTML),
                           ("offline", self.NO_SERVER),
                           ("qbit down", self.QBIT_DOWN)):
            with self.subTest(failure=name):
                r = self.drive(stub)
                self.assertEqual(sorted(r["savedCats"]),
                                 ["radarr", "tv-sonarr"])
                self.assertTrue(r["savedChecked"])

    def test_saved_indexers_stay_on_screen(self):
        for name, stub in (("session", self.UNAUTHORIZED),
                           ("qbit down", self.QBIT_DOWN)):
            with self.subTest(failure=name):
                r = self.drive(stub)
                self.assertEqual(r["savedIdx"], ["Meridian Tracker (Prowlarr)"])


class TestTheDetailIsKeptWhereItIsUseful(PickerCase):
    """Concise in the card, complete in the console. A bug report still has the
    thing that identifies the failure."""

    CAPTURE = """
    window.__log = [];
    ['error', 'warn'].forEach(function (level) {
      var orig = console[level];
      console[level] = function () {
        window.__log.push(Array.prototype.map.call(arguments, function (a) {
          try { return typeof a === 'string' ? a : JSON.stringify(a); }
          catch (e) { return String(a); }
        }).join(' '));
        orig.apply(console, arguments);
      };
    });"""

    def logs(self, stub):
        html = self.install(
            self.client.get("/settings/detection-remediation")
                       .get_data(as_text=True),
            self.CAPTURE + "\n" + stub)
        probe = """
<script>window.addEventListener('load', function () {
  setTimeout(function () {
    var pre = document.createElement('pre');
    pre.id = 'MEASURED';
    pre.textContent = JSON.stringify(window.__log);
    document.body.appendChild(pre);
  }, 400);
});</script>"""
        path = os.path.join(self.dir, "log.html")
        with open(path, "w") as fh:
            fh.write(self.inject(html, probe))
        dom = browser.dom(path, 1280, 900, budget=6000)
        m = re.search(r'<pre id="MEASURED">(.*?)</pre>', dom, re.S)
        self.assertIsNotNone(m, "the probe did not run")
        return " ".join(json.loads(
            m.group(1).replace("&quot;", '"').replace("&amp;", "&")
            .replace("&lt;", "<").replace("&gt;", ">")))

    def test_a_non_json_answer_is_logged_with_its_status_and_body(self):
        out = self.logs(self.PROXY_HTML)
        self.assertIn("did not answer with JSON", out)
        self.assertIn("502", out)
        self.assertIn("Bad Gateway", out)

    def test_the_qbittorrent_exception_is_logged_in_full(self):
        out = self.logs(self.QBIT_DOWN)
        self.assertIn("HTTPConnectionPool", out)
        self.assertIn("Connection refused", out)

    def test_nothing_is_logged_when_everything_works(self):
        ok = """
        window.fetch = function (url) {
          var payload = String(url).indexOf('taxonomy') !== -1
            ? {ok: true, data: {categories: [{name: 'tv-sonarr', meta: ''}],
                                tags: [{name: 'protectarr', meta: ''}]}}
            : {ok: true, data: {indexers: [{name: 'Meridian Tracker (Prowlarr)'}],
                                errors: []}};
          var text = JSON.stringify(payload);
          return Promise.resolve({status: 200, ok: true,
            text: function () { return Promise.resolve(text); },
            json: function () { return Promise.resolve(JSON.parse(text)); }});
        };"""
        self.assertEqual(self.logs(ok), "")


if __name__ == "__main__":
    unittest.main()
