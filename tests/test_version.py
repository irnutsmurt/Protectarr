"""Every surface that shows a version must show the same one.

Protectarr reported v0.1.0 for its entire public life, across the probe lane,
the ownership model, the remediation oracle and everything else. Nothing was
broken by that, which is exactly the problem: a version that never changes is
not wrong in any way a test would catch, it just quietly stops being an
identifier. A bug report saying "I'm on v0.1.0 / latest" narrowed the build
down to several months of master.

So these tests do not check that the version is any particular string. They
check that no surface can drift away from `protectarr.__version__`, and that
nobody can pin one by writing the number down a second time.

Run with:  python -m unittest discover -s tests
"""

import os
import re
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

import protectarr  # noqa: E402

try:
    from protectarr import web as web_mod
    HAVE_FLASK = True
except ImportError:                             # pragma: no cover
    HAVE_FLASK = False

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Assigning or passing a version as a string literal instead of reading
# `__version__`. Deliberately NOT a bare "\d+\.\d+\.\d+" - the package is full
# of IP addresses, CIDR blocks and qBittorrent version requirements, and a
# check that cries wolf on those would be turned off within a week.
VERSION_PIN = re.compile(
    r"""(?:__version__\s*=|[\w.]*version\s*=\s*|Protectarr\s+v)\s*"""
    r"""["']?\d+\.\d+\.\d+""",
    re.IGNORECASE)

# Files allowed to contain one, and why.
ALLOWED = {
    # The source of truth itself.
    os.path.join("protectarr", "__init__.py"),
    # This file, which necessarily talks about versions.
    os.path.join("tests", "test_version.py"),
}


class Loose(dict):
    def __missing__(self, key):
        return Loose()


class FakeService:
    state = Loose(stats=Loose(by_indexer={}), running=False)

    def reload(self):
        pass

    def preview(self):
        return []


@unittest.skipUnless(HAVE_FLASK, "Flask not installed")
class TestVersionSurfaces(unittest.TestCase):
    """Compared against `__version__`, never against a literal.

    A test asserting "0.2.0" would have to be edited on every release, which
    makes it a chore that gets done mechanically rather than a check. These
    fail only when a surface stops agreeing with the package.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        cfg_mod.save({
            "web": {"host": "0.0.0.0", "port": 8090, "api_key": "test-api-key",
                    "secret_key": "s" * 40,
                    "auth": {"method": "none", "required": "enabled",
                             "username": "", "password_hash": "",
                             "trusted_proxies": []}},
            "qbittorrent": {"url": "http://qb:8080", "username": "admin",
                            "password": "test-password", "api_key": "",
                            "verify_ssl": True, "web_url": ""},
            "arrs": [],
            "logging": {"level": "info", "console_level": "error",
                        "file_enabled": False,
                        "path": os.path.join(self.dir, "logs"),
                        "retention_days": 3},
        })
        self.app = web_mod.create_app(FakeService())
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def authed(self):
        with self.client.session_transaction() as s:
            s["authed"] = True
        return self.client

    def test_the_health_check_reports_the_package_version(self):
        """`/ping` is the health check; there is no `/api/v1/health`."""
        body = json.loads(self.client.get("/ping").data)
        self.assertEqual(body["version"], protectarr.__version__)
        self.assertEqual(body["app"], "Protectarr")

    def test_the_api_index_reports_the_package_version(self):
        body = json.loads(self.authed().get("/api/v1").data)
        self.assertEqual(body["version"], protectarr.__version__)

    def test_system_status_reports_the_package_version(self):
        body = json.loads(self.authed().get("/api/v1/system/status").data)
        self.assertEqual(body["version"], protectarr.__version__)

    def test_every_page_footer_shows_the_package_version(self):
        """The sidebar is on every page, so this is the one users read."""
        page = self.authed().get("/").data.decode()
        self.assertIn(f"Protectarr v{protectarr.__version__}", page)

    def test_the_system_page_shows_the_package_version(self):
        """Asserted on the table row, not on the page.

        Every page extends base.html, whose sidebar already prints the
        version, so `assertIn(...)` against the whole document passes even
        when the System page's own row is pinned to something else. The first
        version of this test did exactly that and proved nothing.
        """
        page = self.authed().get("/system").data.decode()
        row = re.search(r"<th[^>]*>Version</th>\s*<td>(.*?)</td>", page,
                        re.S)
        self.assertIsNotNone(row, "the System page has no Version row")
        self.assertEqual(row.group(1).strip(),
                         f"Protectarr v{protectarr.__version__}")

    def test_no_surface_was_missed(self):
        """Anything new that reports a version has to be added here.

        Counts the places `__version__` is handed out and fails if that number
        grows, so a new endpoint cannot quietly ship without a test. Update the
        expected count in the same commit that adds the surface.
        """
        with open(os.path.join(REPO, "protectarr", "web.py")) as fh:
            source = fh.read()
        self.assertEqual(source.count("version=__version__"), 4,
                         "a version-reporting surface was added or removed; "
                         "add a test for it above and update this count")


class TestTheVersionIsWrittenDownOnce(unittest.TestCase):
    def _scan(self):
        offenders = []
        for root, dirs, files in os.walk(os.path.join(REPO, "protectarr")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in sorted(files):
                if not name.endswith((".py", ".html")):
                    continue
                path = os.path.join(root, name)
                rel = os.path.relpath(path, REPO)
                if rel in ALLOWED:
                    continue
                with open(path, encoding="utf-8") as fh:
                    for i, line in enumerate(fh, 1):
                        if VERSION_PIN.search(line):
                            offenders.append(f"{rel}:{i}: {line.strip()[:70]}")
        return offenders

    def test_nothing_else_pins_a_version(self):
        """A second copy is how the first one goes stale.

        Templates read `{{ version }}` and web.py reads `__version__`. A
        literal anywhere else in the shipped package is a pin waiting to be
        forgotten on the next release.
        """
        self.assertEqual(self._scan(), [], "hardcoded version(s):\n" +
                         "\n".join(self._scan()))

    def test_the_scan_would_actually_catch_one(self):
        """The check above passes trivially if the pattern matches nothing.

        Plants each shape of pin in a temporary file inside the package and
        asserts the scan finds it, so "no offenders" means the scan looked
        rather than that it was blind.
        """
        planted = os.path.join(REPO, "protectarr", "_version_canary.html")
        for line in ('<div>Protectarr v9.9.9</div>',
                     '{{ version }}<!-- version = "9.9.9" -->',
                     '<span>__version__ = "9.9.9"</span>'):
            try:
                with open(planted, "w") as fh:
                    fh.write(line + "\n")
                found = self._scan()
                self.assertTrue(
                    any("_version_canary" in o for o in found),
                    f"the scan missed a planted pin: {line!r}")
            finally:
                os.remove(planted)

    def test_the_version_is_a_sane_semver(self):
        """A tag is derived from it, so a typo here becomes a bad release."""
        self.assertRegex(protectarr.__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
