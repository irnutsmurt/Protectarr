"""The three ways a Settings save could hurt you, and the environment.

Every test here came from a defect that was reachable from the browser:

  * three number fields called `int()` on a string the browser is happy to
    submit. `<input type=number>` treats `1e9` as a valid value, so typing it
    was a 500.
  * choosing Forms authentication with both credential fields empty saved a
    configuration that could authenticate nobody, recoverable only by editing
    config.yaml by hand.
  * saving any Settings page copied environment-provided secrets into
    config.yaml, and an environment variable defined as empty - which is what
    the shipped docker-compose.yml does - blanked a credential the WebUI had
    stored.

Run with:  python -m unittest discover -s tests
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import web  # noqa: E402

ENV_KEYS = ("PROTECTARR_QBIT_URL", "PROTECTARR_QBIT_API_KEY",
            "PROTECTARR_QBIT_USERNAME", "PROTECTARR_QBIT_PASSWORD",
            "PROTECTARR_WEB_API_KEY", "PROTECTARR_DRY_RUN")


class EnvCase(unittest.TestCase):
    """Every test runs with a known environment and restores it afterwards.

    The override table is process-global, so a leaked variable would not fail
    this file, it would fail whichever file happened to run next.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        self._saved = {k: os.environ.get(k) for k in ENV_KEYS}
        for k in ENV_KEYS:
            os.environ.pop(k, None)
        self.addCleanup(self._restore)

    def _restore(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class FakeService:
    """Enough of the worker for a save to complete.

    `bannedips` and `blocklist` reach for these on every save, so a harness
    without them cannot exercise the branches that own two of the three
    numbers under test.
    """

    class _State(dict):
        def __getattr__(self, k):
            return self.get(k)

    state = _State(stats=_State(by_indexer={}), running=False,
                   blocklist=_State(), banned=_State())

    def __init__(self):
        self.applied = 0
        self.updated = 0

    def reload(self):
        pass

    def apply_banned_ips(self, cfg):
        self.applied += 1

    def update_blocklist(self, cfg, force=False):
        self.updated += 1


class WebCase(EnvCase):
    def setUp(self):
        super().setUp()
        cfg_mod.save({
            "web": {"api_key": "web-test-key-value", "secret_key": "s" * 40,
                    "auth": {"method": "none", "required": "enabled",
                             "username": "", "password_hash": "",
                             "trusted_proxies": []}},
            "safety": {"airdate_grace_hours": 6, "orphan_dwell_minutes": 10},
            "ip_blocklist": {"update_interval_hours": 12},
            "logging": {"level": "info", "console_level": "error",
                        "file_enabled": False, "retention_days": 3},
        })
        self.service = FakeService()
        self.app = web.create_app(self.service)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "test-csrf-token"

    def save(self, section, **fields):
        fields["csrf_token"] = "test-csrf-token"
        return self.client.post(f"/settings/{section}/save", data=fields,
                                follow_redirects=True)

    def cfg(self):
        return cfg_mod.load()

    def page(self, section):
        return self.client.get(f"/settings/{section}",
                               follow_redirects=True).get_data(as_text=True)


# --------------------------------------------------------------------------
# 1. The numbers
# --------------------------------------------------------------------------

# (section, form field, config path, low, high, what a blank field means)
NUMBERS = [
    ("safety", "airdate_grace_hours", ("safety", "airdate_grace_hours"),
     0, 8760, 0),
    ("blocklist", "bl_interval", ("ip_blocklist", "update_interval_hours"),
     1, 8760, 24),
    ("logging", "log_retention", ("logging", "retention_days"),
     0, 365, 0),
]


class TestNumericFieldsCannotCrash(WebCase):
    def stored(self, path):
        node = self.cfg()
        for key in path:
            node = node[key]
        return node

    def test_exponent_notation_does_not_500(self):
        """The defect itself. A browser considers `1e9` valid and submits it."""
        for section, field, path, lo, hi, _ in NUMBERS:
            with self.subTest(field=field):
                r = self.save(section, **{field: "1e9"})
                self.assertEqual(r.status_code, 200)
                self.assertEqual(self.stored(path), hi)

    def test_a_number_in_range_is_stored_as_given(self):
        for section, field, path, lo, hi, _ in NUMBERS:
            with self.subTest(field=field):
                want = lo + 5
                self.save(section, **{field: str(want)})
                self.assertEqual(self.stored(path), want)

    def test_it_is_clamped_at_both_ends(self):
        for section, field, path, lo, hi, _ in NUMBERS:
            with self.subTest(field=field):
                self.save(section, **{field: "99999999"})
                self.assertEqual(self.stored(path), hi)
                self.save(section, **{field: "-500"})
                self.assertEqual(self.stored(path), lo)

    def test_rubbish_leaves_the_stored_value_alone(self):
        """Matching `orphan_dwell_minutes`, which has always behaved this way."""
        for section, field, path, lo, hi, _ in NUMBERS:
            with self.subTest(field=field):
                self.save(section, **{field: str(lo + 7)})
                r = self.save(section, **{field: "not a number"})
                self.assertEqual(r.status_code, 200)
                self.assertEqual(self.stored(path), lo + 7)

    def test_a_fractional_value_truncates_rather_than_crashing(self):
        for section, field, path, lo, hi, _ in NUMBERS:
            with self.subTest(field=field):
                self.save(section, **{field: str(lo + 3) + ".7"})
                self.assertEqual(self.stored(path), lo + 3)

    def test_a_blank_field_still_means_what_it_always_meant(self):
        """Pinned because it is surprising: blank retention is 0, not 14."""
        for section, field, path, lo, hi, blank in NUMBERS:
            with self.subTest(field=field):
                self.save(section, **{field: ""})
                self.assertEqual(self.stored(path), blank)

    def test_the_form_declares_the_same_ceiling_the_server_enforces(self):
        """A browser that silently disagreed with the server would make the
        clamp look like data loss."""
        html = self.page("safety")
        self.assertIn('name="airdate_grace_hours"', html)
        self.assertRegex(html, r'name="airdate_grace_hours"[^>]*max="8760"')
        html = self.page("blocklist")
        self.assertRegex(html, r'name="bl_interval"[^>]*max="8760"')
        html = self.page("logging")
        self.assertRegex(html, r'name="log_retention"[^>]*max="365"')


# --------------------------------------------------------------------------
# 2. The lockout
# --------------------------------------------------------------------------

class TestAuthCannotLockYouOut(WebCase):
    def auth(self):
        return self.cfg()["web"]["auth"]

    def test_forms_with_no_credentials_at_all_is_refused(self):
        """The defect: three clicks, and the only way back was the YAML."""
        r = self.save("security", auth_method="forms", auth_required="enabled",
                      auth_username="", auth_password="")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.auth()["method"], "none")
        self.assertEqual(self.auth()["password_hash"], "")

    def test_basic_with_no_credentials_at_all_is_refused(self):
        self.save("security", auth_method="basic", auth_required="enabled",
                  auth_username="", auth_password="")
        self.assertEqual(self.auth()["method"], "none")

    def test_a_username_with_no_password_is_refused(self):
        self.save("security", auth_method="forms", auth_required="enabled",
                  auth_username="admin", auth_password="")
        self.assertEqual(self.auth()["method"], "none")
        self.assertEqual(self.auth()["username"], "")

    def test_a_password_with_no_username_is_refused(self):
        self.save("security", auth_method="forms", auth_required="enabled",
                  auth_username="", auth_password="test-password")
        self.assertEqual(self.auth()["method"], "none")

    def test_the_refusal_says_which_half_is_missing(self):
        r = self.save("security", auth_method="forms", auth_required="enabled",
                      auth_username="admin", auth_password="")
        body = r.get_data(as_text=True)
        self.assertIn("needs a password", body)
        self.assertIn("Nothing was saved", body)

    def test_nothing_at_all_is_written_when_it_is_refused(self):
        """A half-applied security config is worse than a rejected one."""
        self.save("security", auth_method="none", auth_required="enabled",
                  auth_username="keepme", auth_password="test-password")
        before = dict(self.auth())
        self.save("security", auth_method="forms", auth_required="local_disabled",
                  auth_username="", auth_password="",
                  trusted_proxies="10.0.0.0/8")
        self.assertEqual(self.auth(), before)

    def test_local_disabled_is_not_an_exemption(self):
        """It depends on trusted_proxies being right, and one proxy change
        later the instance would be unreachable."""
        self.save("security", auth_method="forms",
                  auth_required="local_disabled",
                  auth_username="", auth_password="")
        self.assertEqual(self.auth()["method"], "none")

    def test_a_complete_configuration_still_saves(self):
        self.save("security", auth_method="forms", auth_required="enabled",
                  auth_username="admin", auth_password="test-password")
        self.assertEqual(self.auth()["method"], "forms")
        self.assertEqual(self.auth()["username"], "admin")
        self.assertTrue(self.auth()["password_hash"])

    def test_blank_password_still_means_unchanged_once_one_is_set(self):
        """The existing secret contract. The check asks whether a hash would
        exist, not whether one was typed."""
        self.save("security", auth_method="forms", auth_required="enabled",
                  auth_username="admin", auth_password="test-password")
        was = self.auth()["password_hash"]
        self.save("security", auth_method="forms", auth_required="enabled",
                  auth_username="renamed", auth_password="")
        self.assertEqual(self.auth()["password_hash"], was)
        self.assertEqual(self.auth()["username"], "renamed")

    def test_blanking_the_username_of_a_working_setup_is_refused(self):
        """`check_password` compares the username too, so an empty one is the
        same lockout by a different route."""
        self.save("security", auth_method="forms", auth_required="enabled",
                  auth_username="admin", auth_password="test-password")
        self.save("security", auth_method="forms", auth_required="enabled",
                  auth_username="", auth_password="")
        self.assertEqual(self.auth()["username"], "admin")

    def test_turning_authentication_off_is_always_allowed(self):
        self.save("security", auth_method="forms", auth_required="enabled",
                  auth_username="admin", auth_password="test-password")
        self.save("security", auth_method="none", auth_required="enabled",
                  auth_username="", auth_password="")
        self.assertEqual(self.auth()["method"], "none")

    def test_the_refused_configuration_would_really_have_locked_you_out(self):
        """The test that makes the rest of this class worth having: it drives
        the actual login path rather than trusting the reasoning."""
        raw = cfg_mod._read_file()
        raw.setdefault("web", {})["auth"] = {
            "method": "forms", "required": "enabled",
            "username": "", "password_hash": "", "trusted_proxies": []}
        cfg_mod._persist(raw)
        fresh = self.app.test_client()
        self.assertEqual(fresh.get("/").status_code, 302)
        self.assertIn("/login", fresh.get("/").headers["Location"])
        with fresh.session_transaction() as s:
            s["csrf"] = "t"
        r = fresh.post("/login", data={"username": "", "password": "",
                                       "csrf_token": "t"})
        self.assertNotIn("authed", [k for k in r.headers.get("Set-Cookie", "")])
        self.assertEqual(r.status_code, 200)
        self.assertIn("Incorrect username or password", r.get_data(as_text=True))


# --------------------------------------------------------------------------
# 3. The environment
# --------------------------------------------------------------------------

class TestEmptyEnvVarMeansNotProvided(EnvCase):
    """`${QBIT_PASSWORD:-}` in the shipped compose file DEFINES the variable
    as empty. Treating that as "set to blank" blanked a stored credential on
    every load."""

    def test_an_absent_variable_leaves_the_file_value_alone(self):
        cfg_mod.save({"qbittorrent": {"password": "from-the-webui"}})
        self.assertEqual(cfg_mod.load()["qbittorrent"]["password"],
                         "from-the-webui")

    def test_an_empty_variable_does_not_blank_the_file_value(self):
        cfg_mod.save({"qbittorrent": {"password": "from-the-webui",
                                      "api_key": "key-from-the-webui"}})
        os.environ["PROTECTARR_QBIT_PASSWORD"] = ""
        os.environ["PROTECTARR_QBIT_API_KEY"] = ""
        q = cfg_mod.load()["qbittorrent"]
        self.assertEqual(q["password"], "from-the-webui")
        self.assertEqual(q["api_key"], "key-from-the-webui")

    def test_a_whitespace_only_variable_counts_as_empty(self):
        cfg_mod.save({"qbittorrent": {"password": "from-the-webui"}})
        os.environ["PROTECTARR_QBIT_PASSWORD"] = "   "
        self.assertEqual(cfg_mod.load()["qbittorrent"]["password"],
                         "from-the-webui")

    def test_a_real_variable_still_wins(self):
        """The precedence that must not regress."""
        cfg_mod.save({"qbittorrent": {"password": "from-the-webui"}})
        os.environ["PROTECTARR_QBIT_PASSWORD"] = "from-the-environment"
        self.assertEqual(cfg_mod.load()["qbittorrent"]["password"],
                         "from-the-environment")

    def test_an_empty_dry_run_does_not_mean_live(self):
        """`"" .lower() in ("1","true",...)` was False, so an empty variable
        turned dry run OFF. That is the dangerous direction to get wrong."""
        cfg_mod.save({"dry_run": True})
        os.environ["PROTECTARR_DRY_RUN"] = ""
        self.assertIs(cfg_mod.load()["dry_run"], True)

    def test_dry_run_still_reads_a_real_value(self):
        cfg_mod.save({"dry_run": True})
        for val, want in (("false", False), ("0", False), ("no", False),
                          ("true", True), ("1", True), ("on", True)):
            with self.subTest(val=val):
                os.environ["PROTECTARR_DRY_RUN"] = val
                self.assertIs(cfg_mod.load()["dry_run"], want)

    def test_the_api_key_env_check_agrees_with_the_override(self):
        """These two read the same variable and used to disagree about empty:
        one would report "not from the environment" while the other applied it
        anyway, so the UI offered a Regenerate that could not take effect."""
        for val in (None, "", "   "):
            with self.subTest(val=val):
                if val is None:
                    os.environ.pop("PROTECTARR_WEB_API_KEY", None)
                else:
                    os.environ["PROTECTARR_WEB_API_KEY"] = val
                self.assertFalse(cfg_mod.api_key_is_from_env())
                cfg_mod.save({"web": {"api_key": "key-from-the-file"}})
                self.assertEqual(cfg_mod.load()["web"]["api_key"],
                                 "key-from-the-file")
        os.environ["PROTECTARR_WEB_API_KEY"] = "key-from-the-environment"
        self.assertTrue(cfg_mod.api_key_is_from_env())
        self.assertEqual(cfg_mod.load()["web"]["api_key"],
                         "key-from-the-environment")


class TestEnvSecretsStayInTheEnvironment(EnvCase):
    """`save()` has always documented that env overrides are not written back.
    It was handed the dict `load()` produced, which had them merged in."""

    def raw(self):
        return cfg_mod._read_file()

    def test_an_unrelated_save_does_not_materialise_the_secret(self):
        """The defect: saving the Logging page wrote the qBittorrent password."""
        cfg_mod.save({"qbittorrent": {"password": ""}})
        os.environ["PROTECTARR_QBIT_PASSWORD"] = "env-only-secret"
        cfg = cfg_mod.load()
        cfg["logging"]["level"] = "debug"
        cfg_mod.save(cfg)
        self.assertEqual(self.raw()["qbittorrent"]["password"], "")
        self.assertEqual(self.raw()["logging"]["level"], "debug")

    def test_it_holds_for_every_override(self):
        pairs = {"PROTECTARR_QBIT_URL": (("qbittorrent", "url"), "http://env:1"),
                 "PROTECTARR_QBIT_API_KEY": (("qbittorrent", "api_key"), "env-key"),
                 "PROTECTARR_QBIT_USERNAME": (("qbittorrent", "username"), "env-user"),
                 "PROTECTARR_QBIT_PASSWORD": (("qbittorrent", "password"), "env-pass"),
                 "PROTECTARR_WEB_API_KEY": (("web", "api_key"), "env-web-key")}
        for env, (path, val) in pairs.items():
            os.environ[env] = val
        cfg_mod.save(cfg_mod.load())
        raw = self.raw()
        for env, (path, val) in pairs.items():
            with self.subTest(env=env):
                node = raw
                for key in path:
                    node = node[key]
                self.assertNotEqual(node, val, f"{env} was written to disk")

    def test_a_value_the_file_already_had_survives_the_save(self):
        """The strip restores what the file said, not the default, so a save
        cannot be a quiet way to lose a stored credential."""
        cfg_mod.save({"qbittorrent": {"password": "the-stored-one"}})
        os.environ["PROTECTARR_QBIT_PASSWORD"] = "env-only-secret"
        cfg_mod.save(cfg_mod.load())
        self.assertEqual(self.raw()["qbittorrent"]["password"], "the-stored-one")

    def test_a_deliberate_edit_is_still_written(self):
        """Only an untouched value is taken back out. Approved semantics: an
        edit lands in the file and is shadowed until the variable goes away."""
        os.environ["PROTECTARR_QBIT_PASSWORD"] = "env-only-secret"
        cfg = cfg_mod.load()
        cfg["qbittorrent"]["password"] = "typed-by-the-operator"
        cfg_mod.save(cfg)
        self.assertEqual(self.raw()["qbittorrent"]["password"],
                         "typed-by-the-operator")
        # Precedence is unchanged: the variable still wins at runtime.
        self.assertEqual(cfg_mod.load()["qbittorrent"]["password"],
                         "env-only-secret")
        os.environ.pop("PROTECTARR_QBIT_PASSWORD")
        self.assertEqual(cfg_mod.load()["qbittorrent"]["password"],
                         "typed-by-the-operator")

    def test_dry_run_is_stripped_by_value_not_by_name(self):
        """It is the one override that is not a string, so it is the one a
        type-blind comparison would get wrong."""
        cfg_mod.save({"dry_run": True})
        os.environ["PROTECTARR_DRY_RUN"] = "false"
        cfg_mod.save(cfg_mod.load())
        self.assertIs(self.raw()["dry_run"], True)

    def test_save_does_not_mutate_the_dict_it_was_given(self):
        """The caller keeps using it."""
        os.environ["PROTECTARR_QBIT_PASSWORD"] = "env-only-secret"
        cfg = cfg_mod.load()
        cfg_mod.save(cfg)
        self.assertEqual(cfg["qbittorrent"]["password"], "env-only-secret")

    def test_the_settings_pages_do_not_materialise_it_either(self):
        """Through the real handler, because that is where it happened."""
        cfg_mod.save({"qbittorrent": {"password": ""}})
        os.environ["PROTECTARR_QBIT_PASSWORD"] = "env-only-secret"
        app = web.create_app(FakeService())
        app.config["TESTING"] = True
        client = app.test_client()
        with client.session_transaction() as s:
            s["authed"] = True
            s["csrf"] = "t"
        for section, fields in (("logging", {"log_level": "debug"}),
                                ("safety", {"safety_mode": "either"}),
                                ("detection", {"blocked_extensions": ".exe"})):
            with self.subTest(section=section):
                fields["csrf_token"] = "t"
                client.post(f"/settings/{section}/save", data=fields,
                            follow_redirects=True)
                self.assertEqual(self.raw()["qbittorrent"]["password"], "")


if __name__ == "__main__":
    unittest.main()
