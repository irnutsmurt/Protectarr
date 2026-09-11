"""Adversarial tests: identity, timing, state, and bad inputs.

The rule these encode:

    Any uncertainty fails safe toward "do not delete".
    Any confirmed finding fails hard and stays fully explainable.

Two real bugs came out of writing these. Both have a test named after them:
`test_unreachable_arr_does_not_make_everything_look_like_an_orphan` and
`test_worker_survives_an_unexpected_error`.

Run with:  python -m unittest discover -s tests
"""

import os
import sys
import time
import tempfile
import unittest

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, detectors, policy, logs, events  # noqa: E402

logs.configure({"logging": {"level": "critical", "console_level": "critical",
                            "file_enabled": False}})

DET = {"blocked_extensions": [".exe", ".scr"],
       "blocked_name_keywords": ["password"],
       "archive_detection": {"enabled": False, "indexers": [],
                             "archive_extensions": [".rar"]},
       "only_active": True}


def run_detect(names, arr_type="sonarr", tracked=True):
    return detectors.run([{"name": n} for n in names], DET,
                         {"arr_type": arr_type, "arr_tracked": tracked,
                          "resolve_indexer": lambda: "IX"})


class FakeQb:
    def __init__(self, torrents, files_by_hash=None, files_raises=None):
        self._t, self._f, self._raise = torrents, files_by_hash or {}, files_raises
    def login(self): pass
    def torrents(self, category=None, state_filter=None): return self._t
    def files(self, h):
        if self._raise:
            raise self._raise
        return self._f.get(h, [])
    def peers(self, h): return []
    def delete(self, h, delete_files=False): pass


def scan_with(cfg, qb, clients):
    real_qb, real_build = core.QbitClient, core.build_clients
    core.QbitClient = lambda *a, **k: qb
    core.build_clients = lambda c: clients
    try:
        return core.scan(cfg, {})
    finally:
        core.QbitClient, core.build_clients = real_qb, real_build


def cfg_for(mode="either", cats=("tv",)):
    return {"qbittorrent": {"url": "http://x"}, "detection": DET,
            "safety": {"mode": mode, "allowed_categories": list(cats),
                       "allowed_tags": []},
            "arrs": [{"name": "Sonarr", "type": "sonarr"}]}


def torrent(**kw):
    base = {"hash": "aa" * 20, "name": "Show S01E01", "state": "downloading",
            "category": "tv", "tags": "", "size": 1}
    base.update(kw)
    return base


class ArrStub:
    name, type = "Sonarr", "sonarr"
    def __init__(self, queue=None, raises=None):
        self._q, self._raises = queue or {}, raises
    def queue_by_hash(self):
        if self._raises:
            raise self._raises
        return self._q


# ---------------------------------------------------------------- state ----

class TestState(unittest.TestCase):
    def test_unreachable_arr_does_not_make_everything_look_like_an_orphan(self):
        """THE bug. Sonarr restarting emptied the ownership map, so in `either`
        mode every tracked download looked orphaned and would have been deleted
        straight out of qBittorrent."""
        t = torrent()
        qb = FakeQb([t], {t["hash"]: [{"name": "Show.S01E01.exe"}]})
        dead = ArrStub(raises=requests.RequestException("connection refused"))
        self.assertEqual(scan_with(cfg_for("either"), qb, [dead]), [],
                         "ownership unknown must never mean 'delete it'")

    def test_same_applies_to_allowlist_mode(self):
        t = torrent()
        qb = FakeQb([t], {t["hash"]: [{"name": "Show.S01E01.exe"}]})
        dead = ArrStub(raises=requests.RequestException("boom"))
        self.assertEqual(scan_with(cfg_for("allowlist"), qb, [dead]), [])

    def test_a_genuine_orphan_is_still_reaped_when_the_arr_answers(self):
        t = torrent()
        qb = FakeQb([t], {t["hash"]: [{"name": "Show.S01E01.exe"}]})
        actions = scan_with(cfg_for("either"), qb, [ArrStub(queue={})])
        self.assertEqual([a["decision"] for a in actions], ["qbit_delete"])

    def test_worker_survives_an_unexpected_error(self):
        """The loop used to die on any non-HTTP exception while the UI kept
        reporting running=True, so Protectarr looked healthy and scanned
        nothing."""
        class Exploding(FakeQb):
            def torrents(self, category=None, state_filter=None):
                raise ValueError("something nobody predicted")

        real = core.QbitClient
        core.QbitClient = lambda *a, **k: Exploding([])
        try:
            svc = core.ProtectarrService()
            svc.state["poll_interval"] = 1
            svc.start()
            time.sleep(1.5)
            self.assertTrue(svc._thread.is_alive(), "the scan loop died")
            self.assertIn("ValueError", svc.state.get("last_error") or "")
            svc.stop()
        finally:
            core.QbitClient = real

    def test_running_flag_is_cleared_if_the_loop_ever_exits(self):
        svc = core.ProtectarrService()
        svc.state["running"] = True
        svc._stop.set()
        svc._run()
        self.assertFalse(svc.state["running"], "the UI must not claim it is running")

    def test_truncated_event_history_still_reads(self):
        d = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(d, "config.yaml")
        events.record({"dry_run": False, "torrent": {"name": "good"}})
        with open(os.path.join(d, "events.jsonl"), "a") as fh:
            fh.write('{"torrent": {"na')          # killed mid-write
        self.assertEqual(len(events.read()), 1)

    def test_corrupt_stats_falls_back_to_defaults(self):
        d = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(d, "config.yaml")
        with open(os.path.join(d, "stats.json"), "w") as fh:
            fh.write("{not json at all")
        self.assertEqual(core.load_stats()["reaped_total"], 0)


# ----------------------------------------------------------- bad inputs ----

class TestBadInputs(unittest.TestCase):
    def test_uppercase_extension(self):
        self.assertTrue(run_detect(["MOVIE.EXE"]))

    def test_double_extension(self):
        found = run_detect(["movie.mkv.exe"])
        self.assertEqual(found[0]["evidence"]["extension"], ".exe")

    def test_extension_only_in_the_middle_is_not_a_match(self):
        self.assertFalse(run_detect(["movie.exe.mkv"]))

    def test_unicode_and_rtl_filenames(self):
        for name in ("фильм.exe", "映画.exe", "mov‮ie.exe", "🎬.exe"):
            with self.subTest(name=name):
                self.assertTrue(run_detect([name]))

    def test_no_files_returned(self):
        self.assertEqual(run_detect([]), [])

    def test_malformed_file_list_is_skipped_not_fatal(self):
        t = torrent()
        qb = FakeQb([t], {})
        qb.files = lambda h: None
        self.assertEqual(scan_with(cfg_for("arr_tracked"), qb, [ArrStub()]), [])

    def test_file_entries_missing_a_name(self):
        found = detectors.run([{}, {"name": None}, {"name": "a.exe"}], DET,
                              {"arr_type": "sonarr", "arr_tracked": True,
                               "resolve_indexer": lambda: None})
        self.assertEqual(len(found), 1)

    def test_newline_in_a_filename_cannot_forge_a_log_line(self):
        logs.configure({"logging": {"level": "info", "console_level": "critical",
                                    "file_enabled": False}})
        logs.get("t").info("Reaped %s", "x\nINFO: everything was deleted")
        line = logs.ring()[-1]
        self.assertNotIn("\n", line)
        self.assertIn("\\n", line)
        logs.configure({"logging": {"level": "critical", "console_level": "critical",
                                    "file_enabled": False}})

    def test_quotes_and_control_chars_survive_the_event_store(self):
        d = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(d, "config.yaml")
        nasty = 'He said "hi"\n\tand\\ then\r\x00 <script>'
        events.record({"dry_run": False, "torrent": {"name": nasty}})
        self.assertEqual(events.read()[0]["torrent"]["name"], nasty)

    def test_a_very_large_file_list_is_handled(self):
        names = [f"dir/sub/ep{i:04}.mkv" for i in range(5000)] + ["payload.exe"]
        found = run_detect(names)
        self.assertEqual(len(found), 1)

    def test_deeply_nested_paths(self):
        self.assertTrue(run_detect(["/".join(["d"] * 200) + "/x.exe"]))


# -------------------------------------------------------------- identity ----

class TestIdentity(unittest.TestCase):
    def test_blank_category_is_not_allowlisted_by_accident(self):
        self.assertIsNone(core.evaluate({"category": "", "tags": ""}, "x.exe", None,
                                        {"mode": "either", "allowed_categories": [""],
                                         "allowed_tags": []}))

    def test_category_match_is_case_insensitive(self):
        self.assertEqual(
            core.evaluate({"category": "TV", "tags": ""}, "x.exe", None,
                          {"mode": "either", "allowed_categories": ["tv"],
                           "allowed_tags": []}), "qbit_delete")

    def test_untracked_torrent_in_an_unlisted_category_is_left_alone(self):
        self.assertIsNone(
            core.evaluate({"category": "linux-isos", "tags": ""}, "x.exe", None,
                          {"mode": "either", "allowed_categories": ["tv"],
                           "allowed_tags": []}))

    def test_policy_runs_before_safety_so_a_software_category_never_reaches_it(self):
        cfg = {"detection": {"profiles": {}}, "safety": {}}
        find = run_detect(["setup.exe"])[0]
        self.assertEqual(policy.judge(cfg, "software", find)["decision"], "allow")


# ---------------------------------------------------------------- timing ----

class TestTiming(unittest.TestCase):
    def test_torrent_vanishing_mid_scan_is_not_fatal(self):
        t = torrent()
        qb = FakeQb([t], files_raises=requests.RequestException("404 gone"))
        self.assertEqual(scan_with(cfg_for("either"), qb, [ArrStub()]), [])

    def test_removal_succeeding_then_verification_failing_is_partial(self):
        d = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(d, "config.yaml")

        class Client:
            name, type = "Sonarr", "sonarr"
            def grab_indexer(self, x): return "IX"
            def fail(self, i): pass
            def blocklist_match(self, torrent_hash=None, titles=()):
                raise requests.RequestException("timed out after the delete")

        f = detectors.finding("extension", "extension_match", filename="x.exe")
        core.apply_actions([{
            "hash": "abc", "name": "R", "bad_file": "x.exe", "reason": "r",
            "finding": f, "findings": [f], "policy": {}, "size": 1,
            "category": "tv", "tags": "", "decision": "arr_fail",
            "_owner": (Client(), {"id": 1, "title": "R"}), "_qb": FakeQb([]),
        }], {"stats": core.load_stats()},
            {"dry_run": False, "harvest": {"enabled": False}, "safety": {}})
        act = events.read()[0]["action"]
        self.assertEqual(act["result"], "partial")
        self.assertTrue(act["removed"])
        self.assertIsNone(act["blocklisted"], "must not claim it was not blocklisted")


if __name__ == "__main__":
    unittest.main()
