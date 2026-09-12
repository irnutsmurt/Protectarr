"""What must never reach the browser, and what must never reach a log.

Protectarr's whole job is holding other people's *arr and qBittorrent keys, and
a real key was once committed to this repo. These tests are the standing guard
on that, so the next person to add a credential field has to trip over them.

Every credential here is deliberately fake. Never paste a live one in: the repo
is public, and these tests would then leak exactly what they exist to prove
never leaks. See .gitleaks.toml, which fails CI on a real key.

Run with:  python -m unittest discover -s tests
"""

import os
import sys
import json
import logging
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402
from protectarr import logs  # noqa: E402

try:
    import flask  # noqa: F401
    from protectarr import web as web_mod
    HAVE_FLASK = True
except ImportError:  # pragma: no cover
    HAVE_FLASK = False

# Shaped like the real things so the assertions are meaningful, obviously
# synthetic so the scanner and a human reviewer both know at a glance.
SONARR_KEY = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
RADARR_KEY = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
QBIT_KEY = "qbt_abcdefgh12345678"
QBIT_PASS = "hunter2hunter2"
WEB_KEY = "0123456789abcdef" * 4


class Loose(dict):
    """A dict that answers any key with another one of itself.

    The sweep below renders every page, and the point of it is to look for
    credentials, not to maintain a faithful copy of the service state. Without
    this, adding a field to a template breaks a security test for no reason.
    """

    def __missing__(self, key):
        return Loose()


class FakeService:
    """Just enough surface for create_app() and the pages under test."""

    state = Loose(stats=Loose(by_indexer={}), running=False)

    def reload(self):
        pass

    def preview(self):
        return []


def base_config(tmpdir):
    return {
        "web": {"host": "0.0.0.0", "port": 8090, "api_key": WEB_KEY,
                "secret_key": "s" * 40,
                "auth": {"method": "none", "required": "enabled",
                         "username": "", "password_hash": "",
                         "trusted_proxies": []}},
        "qbittorrent": {"url": "http://qb:8080", "username": "admin",
                        "password": QBIT_PASS, "api_key": QBIT_KEY,
                        "verify_ssl": True, "web_url": ""},
        "arrs": [
            {"name": "Sonarr", "type": "sonarr", "url": "http://s:8989",
             "api_key": SONARR_KEY},
            {"name": "Radarr", "type": "radarr", "url": "http://r:7878",
             "api_key": RADARR_KEY},
        ],
        "logging": {"level": "info", "console_level": "error",
                    "file_enabled": False, "path": os.path.join(tmpdir, "logs"),
                    "retention_days": 3},
    }


@unittest.skipUnless(HAVE_FLASK, "Flask not installed")
class WebCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        cfg_mod.save(base_config(self.dir))
        self.app = web_mod.create_app(FakeService())
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def cfg(self):
        return cfg_mod.load()

    def csrf(self):
        """Give the session a token and hand back its value for the form."""
        with self.client.session_transaction() as s:
            s["csrf"] = "test-csrf-token"
            s["authed"] = True
        return "test-csrf-token"

    def jpost(self, path, payload):
        """JSON POST carrying the CSRF header the guard requires."""
        return self.client.post(path, json=payload,
                                headers={"X-CSRF-Token": self.csrf()})

    def body(self, path):
        r = self.client.get(path)
        self.assertEqual(r.status_code, 200, path)
        return r.get_data(as_text=True)


class TestNothingLeaksIntoThePage(WebCase):
    """The rendered HTML and JavaScript are the exposure everyone forgets: a
    value in `window.APPS` is in view-source, in the browser cache and in any
    saved copy of the page, for as long as the tab is open."""

    def test_arr_keys_are_absent_from_the_applications_page(self):
        html = self.body("/")
        self.assertNotIn(SONARR_KEY, html)
        self.assertNotIn(RADARR_KEY, html)

    def test_the_page_still_knows_which_apps_exist(self):
        """Proving absence is easy by rendering nothing. It has to still work."""
        html = self.body("/")
        self.assertIn("Sonarr", html)
        self.assertIn("http://s:8989", html)

    def test_qbittorrent_credentials_are_absent_from_the_page(self):
        html = self.body("/")
        self.assertNotIn(QBIT_KEY, html)
        self.assertNotIn(QBIT_PASS, html)

    def test_the_protectarr_key_is_absent_from_the_security_page(self):
        html = self.body("/settings/security")
        self.assertNotIn(WEB_KEY, html)

    def test_no_page_anywhere_contains_a_credential(self):
        """A sweep, so a new page that renders cfg wholesale is caught by this
        file rather than by a user reading their own HTML source."""
        secrets = (SONARR_KEY, RADARR_KEY, QBIT_KEY, QBIT_PASS, WEB_KEY)
        for path in ("/", "/dashboard", "/system", "/settings/security",
                     "/settings/safety", "/settings/probe", "/settings/logging"):
            r = self.client.get(path)
            if r.status_code != 200:
                continue
            html = r.get_data(as_text=True)
            for s in secrets:
                self.assertNotIn(s, html, f"{s[:6]}… leaked into {path}")


class TestArrViewModel(WebCase):
    def test_the_view_model_has_no_api_key_field_at_all(self):
        """Not "api_key is empty" but "api_key is not a key of this dict". An
        allowlist fails closed when someone adds a credential field later."""
        for row in web_mod._arrs_for_browser(self.cfg()):
            self.assertNotIn("api_key", row)
            self.assertEqual(
                set(row), {"index", "name", "type", "url", "web_url", "has_key"})

    def test_it_reports_whether_a_key_is_stored(self):
        cfg = self.cfg()
        cfg["arrs"][1]["api_key"] = ""
        rows = web_mod._arrs_for_browser(cfg)
        self.assertTrue(rows[0]["has_key"])
        self.assertFalse(rows[1]["has_key"])

    def test_no_credential_survives_json_serialisation_of_the_view(self):
        blob = json.dumps(web_mod._arrs_for_browser(self.cfg()))
        self.assertNotIn(SONARR_KEY, blob)
        self.assertNotIn(RADARR_KEY, blob)


class TestBlankMeansUnchanged(WebCase):
    """Required credentials keep their value when the field is left blank.
    Optional ones get an explicit clear action instead, because an empty box
    cannot mean both "I did not touch this" and "remove it"."""

    def post(self, path, data):
        data["csrf_token"] = self.csrf()
        return self.client.post(path, data=data, follow_redirects=False)

    def test_editing_an_arr_without_retyping_the_key_keeps_it(self):
        self.post("/applications/app/save",
                  {"arr_index": "0", "arr_name": "Sonarr", "arr_type": "sonarr",
                   "arr_url": "http://moved:8989", "arr_key": ""})
        arr = self.cfg()["arrs"][0]
        self.assertEqual(arr["url"], "http://moved:8989")
        self.assertEqual(arr["api_key"], SONARR_KEY)

    def test_a_typed_key_still_replaces_the_stored_one(self):
        self.post("/applications/app/save",
                  {"arr_index": "0", "arr_name": "Sonarr", "arr_type": "sonarr",
                   "arr_url": "http://s:8989", "arr_key": "c" * 32})
        self.assertEqual(self.cfg()["arrs"][0]["api_key"], "c" * 32)

    def test_adding_a_new_arr_with_no_key_is_rejected(self):
        """Blank means "unchanged", and on a new app there is nothing to leave
        unchanged, so it has to be an error rather than a keyless entry."""
        before = len(self.cfg()["arrs"])
        self.post("/applications/app/save",
                  {"arr_index": "", "arr_name": "Lidarr", "arr_type": "lidarr",
                   "arr_url": "http://l:8686", "arr_key": ""})
        self.assertEqual(len(self.cfg()["arrs"]), before)

    def test_blank_qbittorrent_fields_keep_both_credentials(self):
        self.post("/applications/qbit/save",
                  {"qbit_url": "http://qb:9090", "qbit_username": "admin",
                   "qbit_api_key": "", "qbit_password": ""})
        q = self.cfg()["qbittorrent"]
        self.assertEqual(q["url"], "http://qb:9090")
        self.assertEqual(q["api_key"], QBIT_KEY)
        self.assertEqual(q["password"], QBIT_PASS)

    def test_the_clear_checkbox_removes_an_optional_credential(self):
        self.post("/applications/qbit/save",
                  {"qbit_url": "http://qb:8080", "qbit_username": "admin",
                   "qbit_api_key": "", "qbit_api_key_clear": "on",
                   "qbit_password": ""})
        q = self.cfg()["qbittorrent"]
        self.assertEqual(q["api_key"], "")
        self.assertEqual(q["password"], QBIT_PASS, "only the one asked for")

    def test_clearing_the_password_leaves_the_key(self):
        self.post("/applications/qbit/save",
                  {"qbit_url": "http://qb:8080", "qbit_username": "admin",
                   "qbit_api_key": "", "qbit_password": "",
                   "qbit_password_clear": "on"})
        q = self.cfg()["qbittorrent"]
        self.assertEqual(q["password"], "")
        self.assertEqual(q["api_key"], QBIT_KEY)


class TestConnectionTestsUseStoredCredentials(WebCase):
    """Blanking the field must not break Test, or people will work around it by
    pasting the key back in, which is the habit we are trying to remove."""

    def test_arr_test_resolves_the_stored_key_by_index(self):
        seen = {}

        class FakeArr:
            def __init__(self, name, atype, url, api_key, **kw):
                seen["key"] = api_key

            def test(self):
                return True, "ok"

        real, web_mod.ArrClient = web_mod.ArrClient, FakeArr
        try:
            self.jpost("/test/arr",{"name": "Sonarr", "type": "sonarr",
                                                "url": "http://s:8989",
                                                "api_key": "", "index": 0})
        finally:
            web_mod.ArrClient = real
        self.assertEqual(seen["key"], SONARR_KEY)

    def test_an_unknown_index_does_not_hand_back_someone_elses_key(self):
        seen = {}

        class FakeArr:
            def __init__(self, name, atype, url, api_key, **kw):
                seen["key"] = api_key

            def test(self):
                return True, "ok"

        real, web_mod.ArrClient = web_mod.ArrClient, FakeArr
        try:
            self.jpost("/test/arr",{"name": "X", "type": "sonarr",
                                                "url": "http://x", "api_key": "",
                                                "index": 99})
        finally:
            web_mod.ArrClient = real
        self.assertEqual(seen["key"], "")


class TestRevealEndpoint(WebCase):
    def test_it_returns_the_key_when_asked(self):
        r = self.client.get("/settings/security/apikey")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["key"], WEB_KEY)

    def test_the_response_is_not_cacheable(self):
        r = self.client.get("/settings/security/apikey")
        self.assertIn("no-store", r.headers.get("Cache-Control", ""))

    def test_it_is_behind_the_same_auth_as_the_settings_page(self):
        """An endpoint that hands out the API key is the last place to get the
        guard wrong, so this asserts 401 rather than trusting the route table."""
        cfg = self.cfg()
        cfg["web"]["auth"] = {"method": "forms", "required": "enabled",
                              "username": "rob", "password_hash": "x",
                              "trusted_proxies": []}
        cfg_mod.save(cfg)
        fresh = self.app.test_client()
        self.assertEqual(fresh.get("/settings/security/apikey").status_code, 401)

    def test_the_api_key_itself_still_opens_it(self):
        cfg = self.cfg()
        cfg["web"]["auth"] = {"method": "forms", "required": "enabled",
                              "username": "rob", "password_hash": "x",
                              "trusted_proxies": []}
        cfg_mod.save(cfg)
        fresh = self.app.test_client()
        r = fresh.get("/settings/security/apikey", headers={"X-Api-Key": WEB_KEY})
        self.assertEqual(r.status_code, 200)


class TestThirdPartyLogging(unittest.TestCase):
    """werkzeug's access line carries the full request target, and Protectarr
    documents `?apikey=` as a supported way to call its own API. Those records
    go to the werkzeug logger, so they have to reach our redacting handlers
    rather than the root logger's."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        self.cfg = base_config(self.dir)
        self.cfg["logging"]["level"] = "debug"
        self.cfg["logging"]["file_enabled"] = True
        logs._ring.clear()
        logs.configure(self.cfg)

    def tearDown(self):
        for name in (logs.LOGGER_NAME,) + logs.THIRD_PARTY_LOGGERS:
            lg = logging.getLogger(name)
            for h in list(lg.handlers):
                lg.removeHandler(h)
                h.close()

    def ring_text(self):
        return "\n".join(logs.ring())

    def test_third_party_loggers_do_not_escape_to_the_root_logger(self):
        for name in logs.THIRD_PARTY_LOGGERS:
            lg = logging.getLogger(name)
            self.assertFalse(lg.propagate, f"{name} still propagates to root")
            self.assertTrue(lg.handlers, f"{name} has no redacting handler")

    def test_an_access_line_with_a_key_in_the_query_string_is_redacted(self):
        logging.getLogger("werkzeug").info(
            '127.0.0.1 - - "GET /api/v1/status?apikey=%s HTTP/1.1" 200 -', WEB_KEY)
        text = self.ring_text()
        self.assertNotIn(WEB_KEY, text)
        self.assertIn(logs.MASK, text)

    def test_a_urllib3_child_logger_is_covered_too(self):
        """A filter on the `urllib3` logger would never run for these; taking
        over the handler is what makes the child case work."""
        logging.getLogger("urllib3.connectionpool").info(
            'http://sonarr:8989 "GET /api/v3/queue?apikey=%s HTTP/1.1" 200', SONARR_KEY)
        self.assertNotIn(SONARR_KEY, self.ring_text())

    def test_reconfiguring_does_not_leave_a_closed_handler_behind(self):
        logs.configure(self.cfg)
        logging.getLogger("werkzeug").info("still working")
        self.assertIn("still working", self.ring_text())


if __name__ == "__main__":
    unittest.main()
