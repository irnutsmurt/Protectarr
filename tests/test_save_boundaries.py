"""What each Settings section owns, and what happens to a field it did not get.

This file exists to be written down BEFORE the 0.7.0 consolidation, not after.
Seven Settings pages are becoming three, and the thing that makes that risky is
not the templates - it is that `save_section()` is one handler with seven
branches, each of which overwrites every key it knows about from the form. A
form that omits half a section silently erases that half, so merging two cards
into one form, or splitting one section's fields across two forms, is a data
loss bug that no amount of looking at the page would reveal.

So the semantics are pinned here as a table rather than described in prose:

  OWNS    every config path a full post to that section writes, exactly.
  EMPTY   what each of those paths becomes when the form arrives with nothing
          in it, which is what a partial form looks like to the backend.

If the consolidation moves a key between sections, changes what an omitted
field means, or quietly introduces a page-wide save, one of these fails. The
tests deliberately assert on the *set* of changed paths rather than spot
checking a few keys, because a key that moved to the wrong owner is precisely
the failure a spot check would miss.

Nothing here asserts that the current behaviour is good. `test_settings_guards`
covers the cases where it was actively harmful. This file only says what it is,
so that a refactor has to change it on purpose.

Run with:  python -m unittest discover -s tests
"""

import os
import sys
import copy
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import logs, web  # noqa: E402

ZONES = logs.available_timezones()
TZ_BASE = "UTC" if "UTC" in ZONES else (ZONES[0] if ZONES else "")
TZ_NEW = ("America/Los_Angeles" if "America/Los_Angeles" in ZONES
          else (ZONES[-1] if ZONES else ""))


def flat(node, prefix=""):
    """Config as dot-paths to leaves. A list is a leaf: the interesting
    question is whether a save replaced it, not what moved inside it."""
    out = {}
    for key, val in (node or {}).items():
        path = f"{prefix}{key}"
        if isinstance(val, dict):
            out.update(flat(val, path + "."))
        else:
            out[path] = val
    return out


# ---------------------------------------------------------------------------
# The table. One entry per existing save boundary.
#
#   form   a complete post, every field present and every value different from
#          BASE, so a path that does not change is a path this section does not
#          own rather than a coincidence.
#   owns   exactly the paths that post writes.
#   empty  what those paths become when the form arrives with nothing in it.
#          A path absent from `empty` is one an empty post leaves alone, and
#          each of those is a guard worth knowing about.
# ---------------------------------------------------------------------------

SECTIONS = {
    "detection": {
        "form": {"blocked_extensions": ".foo, .bar",
                 "blocked_name_keywords": "lure one, lure two",
                 "archive_enabled": "on",
                 "archive_indexers": ["Indexer A", "Indexer B"]},
        # `only_active` is deliberately omitted from `form`: it is a checkbox,
        # and "present means on" is the semantic being pinned.
        "owns": {"detection.blocked_extensions",
                 "detection.only_active",
                 "detection.blocked_name_keywords",
                 "detection.archive_detection.enabled",
                 "detection.archive_detection.indexers"},
        "empty": {"detection.only_active": False,
                  "detection.blocked_name_keywords": [],
                  "detection.archive_detection.enabled": False,
                  "detection.archive_detection.indexers": []},
    },
    "safety": {
        "form": {"safety_mode": "allowlist",
                 "allowed_categories": ["cat-one", "cat-two"],
                 "allowed_tags": ["tag-one"],
                 "airdate_grace_hours": "9",
                 "orphan_dwell_minutes": "33"},
        "owns": {"dry_run",
                 "safety.mode",
                 "safety.allowed_categories",
                 "safety.allowed_tags",
                 "safety.requeue_after_airdate",
                 "safety.airdate_grace_hours",
                 "safety.orphan_dwell_minutes"},
        "empty": {"dry_run": False,
                  "safety.mode": "arr_tracked",
                  "safety.allowed_categories": [],
                  "safety.allowed_tags": [],
                  "safety.requeue_after_airdate": False,
                  "safety.airdate_grace_hours": 0,
                  "safety.orphan_dwell_minutes": 0},
    },
    "probe": {
        "form": {"probe_enabled": "on",
                 "map_from": ["/from/one", "/from/two"],
                 "map_to": ["/to/one", "/to/two"],
                 "probe_max": "4", "probe_timeout": "45",
                 "probe_budget": "600", "probe_minspeed": "77",
                 "probe_recheck": "31", "probe_noprogress": "88"},
        "owns": {"detection.probe.enabled",
                 "detection.probe.steer",
                 "detection.probe.path_mappings",
                 "detection.probe.max_torrents_per_scan",
                 "detection.probe.torrent_timeout_seconds",
                 "detection.probe.scan_budget_seconds",
                 "detection.probe.min_speed_kib",
                 "detection.probe.recheck_minutes",
                 "detection.probe.no_progress_seconds"},
        # The numbers do not go to zero, they go to whatever `or 0` then the
        # clamp produces, which is the floor for four of them.
        "empty": {"detection.probe.enabled": False,
                  "detection.probe.steer": False,
                  "detection.probe.path_mappings": [],
                  "detection.probe.max_torrents_per_scan": 0,
                  "detection.probe.torrent_timeout_seconds": 5,
                  "detection.probe.scan_budget_seconds": 5,
                  "detection.probe.min_speed_kib": 0,
                  "detection.probe.recheck_minutes": 1,
                  "detection.probe.no_progress_seconds": 0},
    },
    "blocklist": {
        "form": {"bl_enabled": "on", "bl_url": "http://example.invalid/list.gz",
                 "bl_path": "/blocklist/other.p2p", "bl_interval": "48",
                 "bl_apply": "on", "bl_trackers": "on"},
        "owns": {"ip_blocklist.enabled", "ip_blocklist.url",
                 "ip_blocklist.path", "ip_blocklist.update_interval_hours",
                 "ip_blocklist.apply_to_qbit", "ip_blocklist.block_trackers"},
        "empty": {"ip_blocklist.enabled": False,
                  "ip_blocklist.url": "",
                  "ip_blocklist.path": "",
                  "ip_blocklist.update_interval_hours": 24,
                  "ip_blocklist.apply_to_qbit": False,
                  "ip_blocklist.block_trackers": False},
    },
    "bannedips": {
        "form": {"bip_enabled": "on", "bip_ips": "203.0.113.9\n198.51.100.4",
                 "bip_merge": "on"},
        "owns": {"banned_ips.enabled", "banned_ips.ips",
                 "banned_ips.merge_existing"},
        "empty": {"banned_ips.enabled": False,
                  "banned_ips.ips": [],
                  "banned_ips.merge_existing": False},
    },
    "security": {
        "form": {"auth_method": "basic", "auth_required": "local_disabled",
                 "auth_username": "someone-else",
                 "auth_password": "a-different-test-password",
                 "trusted_proxies": "10.1.0.0/16, 10.2.0.0/16"},
        "owns": {"web.auth.method", "web.auth.required", "web.auth.username",
                 "web.auth.password_hash", "web.auth.trusted_proxies"},
        # `password_hash` is absent on purpose: blank means unchanged, which is
        # the one field on these pages where an omitted value is NOT a wipe.
        "empty": {"web.auth.method": "none",
                  "web.auth.required": "enabled",
                  "web.auth.username": "",
                  "web.auth.trusted_proxies": []},
    },
    "logging": {
        "form": {"log_level": "debug", "log_console_level": "warning",
                 "log_file_enabled": "on",
                 # A writable path: `logs.configure()` runs for real after a
                 # logging save, and an unwritable one buries the suite in
                 # permission warnings that have nothing to do with the
                 # boundary being pinned.
                 "log_path": os.path.join(tempfile.gettempdir(),
                                          "protectarr-boundary-logs"),
                 "log_retention": "21", "timezone": TZ_NEW},
        "owns": {"logging.level", "logging.console_level",
                 "logging.file_enabled", "logging.path",
                 "logging.retention_days", "timezone"},
        # The two levels are absent: they are validated against `logs.LEVELS`,
        # so an empty value is ignored rather than stored.
        "empty": {"logging.file_enabled": False,
                  "logging.path": "",
                  "logging.retention_days": 0,
                  "timezone": ""},
    },
}

BASE = {
    "dry_run": True,
    "timezone": TZ_BASE,
    # Every value here is non-empty on purpose. A baseline that already sits at
    # the value a stray write would produce makes that write invisible to a
    # before/after diff, which is how a mutation that cleared `web_url` from
    # the blocklist branch survived the first run of this file's harness.
    "qbittorrent": {"url": "http://qb.invalid:8080", "username": "admin",
                    "password": "qbit-test-password", "api_key": "qbit-test-key",
                    "verify_ssl": True, "web_url": "http://qb.invalid:9090"},
    "arrs": [{"name": "Sonarr", "type": "sonarr", "url": "http://s.invalid:8989",
              "api_key": "sonarr-test-api-key"}],
    "detection": {
        "blocked_extensions": [".exe", ".scr"],
        "only_active": True,
        "blocked_name_keywords": ["password"],
        "archive_detection": {"enabled": False, "indexers": ["Baseline IX"]},
        "probe": {"enabled": False, "steer": True,
                  "path_mappings": [{"from": "/base", "to": "/base"}],
                  "max_torrents_per_scan": 1, "torrent_timeout_seconds": 120,
                  "scan_budget_seconds": 120, "min_speed_kib": 20,
                  "recheck_minutes": 15, "no_progress_seconds": 30},
    },
    "safety": {"mode": "either", "allowed_categories": ["base-cat"],
               "allowed_tags": ["base-tag"], "requeue_after_airdate": True,
               "airdate_grace_hours": 3, "orphan_dwell_minutes": 10},
    "ip_blocklist": {"enabled": False, "url": "http://base.invalid/l.gz",
                     "path": "/blocklist/base.p2p",
                     "update_interval_hours": 12, "apply_to_qbit": False,
                     "block_trackers": False},
    "banned_ips": {"enabled": False, "ips": ["192.0.2.1"],
                   "merge_existing": False},
    "logging": {"level": "info", "console_level": "error",
                "file_enabled": False, "path": "", "retention_days": 3},
    "web": {"api_key": "web-test-key-value", "secret_key": "s" * 40,
            "auth": {"method": "forms", "required": "enabled",
                     "username": "admin",
                     # A real werkzeug hash, so "blank preserves it" is being
                     # asserted against something a login would actually use.
                     "password_hash": "", "trusted_proxies": ["10.0.0.0/8"]}},
}


class FakeService:
    class _State(dict):
        def __getattr__(self, k):
            return self.get(k)

    state = _State(stats=_State(by_indexer={}), running=False,
                   blocklist=_State(), banned=_State())

    def __init__(self):
        self.reloads = 0
        self.applied = 0
        self.updates = 0

    def reload(self):
        self.reloads += 1

    def apply_banned_ips(self, cfg):
        self.applied += 1

    def update_blocklist(self, cfg, force=False):
        self.updates += 1


class BoundaryCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        base = copy.deepcopy(BASE)
        base["logging"]["path"] = os.path.join(self.dir, "logs")
        SECTIONS["logging"]["empty"]  # table is read, not mutated
        cfg_mod.save(base)
        # Set a real password hash through the handler, so the security
        # section starts from a configuration a login could succeed against.
        self.service = FakeService()
        self.app = web.create_app(self.service)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"
        self.post("security", auth_method="forms", auth_required="enabled",
                  auth_username="admin", auth_password="baseline-password",
                  trusted_proxies="10.0.0.0/8")

    def post(self, section, **fields):
        fields["csrf_token"] = "test-csrf-token"
        return self.client.post(f"/settings/{section}/save", data=fields,
                                follow_redirects=True)

    def snapshot(self):
        return flat(cfg_mod.load())

    def changed(self, before, after):
        keys = set(before) | set(after)
        return {k for k in keys if before.get(k, "\0absent") != after.get(k, "\0absent")}


class TestEachSectionOwnsExactlyTheseKeys(BoundaryCase):
    """A full post writes its own keys and nothing else.

    This is what makes the three-page consolidation safe to reason about: as
    long as each form still posts to the section that owns its fields, the
    pages can be arranged any way at all.
    """

    def test_a_full_post_writes_exactly_the_declared_paths(self):
        for name, spec in SECTIONS.items():
            with self.subTest(section=name):
                self.setUp()
                before = self.snapshot()
                self.post(name, **spec["form"])
                after = self.snapshot()
                self.assertEqual(self.changed(before, after), spec["owns"])

    def test_a_section_never_touches_another_sections_keys(self):
        """Stated from the other side, because this is the property the
        consolidation could break without any single section looking wrong."""
        others = {}
        for name, spec in SECTIONS.items():
            others[name] = set().union(
                *(s["owns"] for n, s in SECTIONS.items() if n != name))
        for name, spec in SECTIONS.items():
            with self.subTest(section=name):
                self.setUp()
                before = self.snapshot()
                self.post(name, **spec["form"])
                after = self.snapshot()
                trespass = self.changed(before, after) & others[name]
                self.assertEqual(trespass, set())

    def test_no_section_disturbs_a_credential_it_does_not_own(self):
        """The *arr keys and the qBittorrent password live on Applications.
        Nothing under Settings has any business rewriting them."""
        for name, spec in SECTIONS.items():
            with self.subTest(section=name):
                self.setUp()
                self.post(name, **spec["form"])
                cfg = cfg_mod.load()
                self.assertEqual(cfg["qbittorrent"]["password"],
                                 "qbit-test-password")
                self.assertEqual(cfg["arrs"][0]["api_key"],
                                 "sonarr-test-api-key")
                self.assertEqual(cfg["web"]["api_key"], "web-test-key-value")


class TestAnOmittedFieldIsCleared(BoundaryCase):
    """The overwrite semantics, stated as a table.

    Every value here is what a *partial form* would do to that key, which is
    the exact failure mode the consolidation has to avoid. If 0.7.0 ever makes
    a card post fewer fields than its section owns, this is what the operator
    would silently lose.
    """

    def test_an_empty_post_produces_the_declared_values(self):
        for name, spec in SECTIONS.items():
            with self.subTest(section=name):
                self.setUp()
                self.post(name)
                after = self.snapshot()
                for path, want in spec["empty"].items():
                    self.assertEqual(after[path], want,
                                     f"{name}: {path} after an empty post")

    def test_an_empty_post_touches_nothing_outside_the_declared_table(self):
        """A key that quietly starts being cleared by an empty post has to be
        recorded here rather than discovered later.

        Subset rather than equality, because a baseline value that already
        equals its post-empty value does not show up as a change, and the two
        tests either side of this one want that baseline set differently. The
        other direction - a key that quietly stops being cleared - is what
        `test_an_empty_post_produces_the_declared_values` is for.
        """
        for name, spec in SECTIONS.items():
            with self.subTest(section=name):
                self.setUp()
                before = self.snapshot()
                self.post(name)
                after = self.snapshot()
                self.assertLessEqual(self.changed(before, after),
                                     set(spec["empty"]))

    def test_dropping_one_field_from_an_otherwise_full_post_clears_it(self):
        """The realistic version: a card that forgot one input, not a form
        that sent nothing."""
        cases = [("detection", "archive_indexers",
                  "detection.archive_detection.indexers", []),
                 ("safety", "allowed_categories",
                  "safety.allowed_categories", []),
                 ("probe", "probe_enabled",
                  "detection.probe.enabled", False),
                 ("blocklist", "bl_url", "ip_blocklist.url", ""),
                 ("bannedips", "bip_ips", "banned_ips.ips", []),
                 ("logging", "log_path", "logging.path", "")]
        for name, field, path, want in cases:
            with self.subTest(section=name, field=field):
                self.setUp()
                form = dict(SECTIONS[name]["form"])
                form.pop(field)
                self.post(name, **form)
                self.assertEqual(self.snapshot()[path], want)


class TestTheGuardsThatSurviveAnEmptyPost(BoundaryCase):
    """Three fields do NOT follow the overwrite rule. Pinned separately so a
    refactor cannot make them consistent by accident."""

    def test_the_extension_list_cannot_be_emptied_from_the_form(self):
        """`if exts:` guards it, and nothing guards the keyword list beside
        it. That asymmetry is load bearing until somebody decides otherwise."""
        self.post("detection", blocked_extensions="",
                  blocked_name_keywords="")
        cfg = cfg_mod.load()["detection"]
        self.assertEqual(cfg["blocked_extensions"], [".exe", ".scr"])
        self.assertEqual(cfg["blocked_name_keywords"], [])

    def test_a_blank_password_keeps_the_stored_hash(self):
        was = cfg_mod.load()["web"]["auth"]["password_hash"]
        self.assertTrue(was)
        self.post("security", auth_method="forms", auth_required="enabled",
                  auth_username="admin", auth_password="",
                  trusted_proxies="10.0.0.0/8")
        self.assertEqual(cfg_mod.load()["web"]["auth"]["password_hash"], was)

    def test_an_unrecognised_log_level_is_ignored_not_stored(self):
        self.post("logging", log_level="chatty", log_console_level="",
                  log_retention="3")
        lg = cfg_mod.load()["logging"]
        self.assertEqual(lg["level"], "info")
        self.assertEqual(lg["console_level"], "error")

    def test_an_unknown_timezone_is_refused_with_a_message(self):
        r = self.post("logging", timezone="Mars/Olympus_Mons",
                      log_level="info", log_console_level="error")
        self.assertIn("Unknown timezone", r.get_data(as_text=True))
        self.assertEqual(cfg_mod.load()["timezone"], TZ_BASE)

    def test_a_half_filled_path_mapping_is_dropped_with_a_message(self):
        r = self.post("probe", probe_enabled="on",
                      map_from=["/only/a/source"], map_to=[""])
        self.assertIn("needs both paths", r.get_data(as_text=True))
        self.assertEqual(
            cfg_mod.load()["detection"]["probe"]["path_mappings"], [])


class TestTheSideEffectsBelongToTheirSection(BoundaryCase):
    """Two sections do something to the outside world on save. Which Save
    button causes that is part of the boundary, so merging those two cards
    into one form would fire one of them for the wrong reason."""

    def test_every_section_reloads_the_worker(self):
        for name, spec in SECTIONS.items():
            with self.subTest(section=name):
                self.setUp()
                before = self.service.reloads
                self.post(name, **spec["form"])
                self.assertEqual(self.service.reloads, before + 1)

    def test_only_banned_ips_pushes_to_qbittorrent(self):
        for name, spec in SECTIONS.items():
            with self.subTest(section=name):
                self.setUp()
                self.post(name, **spec["form"])
                self.assertEqual(self.service.applied,
                                 1 if name == "bannedips" else 0)

    def test_banned_ips_pushes_on_every_save_not_just_a_button(self):
        self.post("bannedips")
        self.assertEqual(self.service.applied, 1)

    def test_the_blocklist_only_refreshes_when_the_button_asked(self):
        self.post("blocklist", **SECTIONS["blocklist"]["form"])
        self.assertEqual(self.service.updates, 0)
        self.post("blocklist", do_update="1", **SECTIONS["blocklist"]["form"])
        self.assertEqual(self.service.updates, 1)


class TestTheRoutesThemselves(BoundaryCase):
    """The seven URLs are public and bookmarkable, and four other test files
    name them. Whatever 0.7.0 does with the navigation, they have to keep
    resolving."""

    def test_every_declared_section_has_a_page_and_a_save(self):
        for name in SECTIONS:
            with self.subTest(section=name):
                self.assertEqual(
                    self.client.get(f"/settings/{name}").status_code, 200)
                self.assertEqual(self.post(name).status_code, 200)

    def test_the_table_here_matches_the_sections_the_app_declares(self):
        """So a section added to `web.py` without a boundary entry fails here
        rather than shipping unpinned."""
        self.assertEqual(set(SECTIONS), set(web.SETTINGS_KEYS))

    def test_an_unknown_section_goes_to_the_index_rather_than_404(self):
        r = self.client.get("/settings/nonsense")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/settings"))
        r = self.client.post("/settings/nonsense/save",
                             data={"csrf_token": "test-csrf-token"})
        self.assertEqual(r.status_code, 302)

    def test_there_is_no_page_wide_save_endpoint(self):
        """0.7.0 must not grow one. Seven independent boundaries is the
        contract the pages are being rearranged around."""
        saves = {str(r) for r in self.app.url_map.iter_rules()
                 if "save" in str(r) and "settings" in str(r)}
        self.assertEqual(saves, {"/settings/<section>/save"})


if __name__ == "__main__":
    unittest.main()
