"""Detection + policy tests.

The point of the detector/policy split was that it changes *structure*, not
behaviour. `test_media_profile_matches_legacy_behaviour` is the one that matters:
it replays the pre-refactor rules over a corpus of file lists and asserts the new
pipeline reaches the same reap-or-not answer every time.

Run with:  python -m unittest discover -s tests
"""

import os
import sys
import posixpath
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import detectors, policy  # noqa: E402
from protectarr.detectors import _util  # noqa: E402

DET = {
    "blocked_extensions": [".exe", ".scr", ".msi", ".url"],
    "blocked_name_keywords": ["password", "how to play"],
    "archive_detection": {"enabled": True, "indexers": ["BadTracker"],
                          "archive_extensions": [".rar", ".zip", ".7z"]},
}
CFG = {"detection": DET, "safety": {}, "arrs": []}


def files(*names):
    return [{"name": n} for n in names]


def run(fl, arr_type="sonarr", tracked=True, indexer="BadTracker", det=DET):
    return detectors.run(fl, det, {
        "arr_type": arr_type, "arr_tracked": tracked,
        "resolve_indexer": lambda: indexer,
    })


# ---- the legacy rules, transcribed from before the refactor ----

def legacy_is_reapable(fl, arr_type, tracked, indexer):
    """Exactly what core.py did pre-refactor: first extension hit, else first
    lure filename, else the indexer-scoped archive rule."""
    exts = {e.lower() for e in DET["blocked_extensions"]}
    keywords = [k.lower() for k in DET["blocked_name_keywords"]]
    for f in fl:
        name = f["name"]
        e = posixpath.splitext(name)[1].lower()
        if e in exts:
            return True
        if keywords and e in _util.LURE_EXTS:
            if any(k in posixpath.basename(name).lower() for k in keywords):
                return True
    ad = DET["archive_detection"]
    if not ad["enabled"] or not tracked:
        return False
    archive_exts = {e.lower() for e in ad["archive_extensions"]}
    media = _util.media_exts(arr_type)
    first_archive = None
    for f in fl:
        e = posixpath.splitext(f["name"])[1].lower()
        if e in media:
            return False
        if first_archive is None and _util.is_archive(e, archive_exts):
            first_archive = f["name"]
    if first_archive and indexer and indexer in set(ad["indexers"]):
        return True
    return False


CORPUS = [
    # (files, arr_type, arr_tracked, indexer)
    (files("Ted.Lasso.S04E07.1080p.WEB-DL.exe"), "sonarr", True, "BadTracker"),
    (files("Movie.2026.1080p.mkv"), "radarr", True, "BadTracker"),
    (files("Movie.2026.1080p.mkv", "README.txt"), "radarr", True, "BadTracker"),
    (files("Movie.2026.mkv", "PASSWORD.txt"), "radarr", True, "BadTracker"),
    (files("Movie.2026.mkv", "HOW TO PLAY.nfo"), "radarr", True, "BadTracker"),
    (files("Password.mkv"), "radarr", True, "BadTracker"),          # not a lure ext
    (files("release.rar", "release.r00"), "radarr", True, "BadTracker"),
    (files("release.rar", "release.r00"), "radarr", True, "GoodTracker"),
    (files("release.rar", "movie.mkv"), "radarr", True, "BadTracker"),
    (files("release.rar"), "radarr", False, "BadTracker"),          # untracked
    (files("album.flac"), "lidarr", True, "BadTracker"),
    (files("album.zip"), "lidarr", True, "BadTracker"),
    (files("book.epub"), "readarr", True, "BadTracker"),
    (files("setup.msi", "readme.txt"), "radarr", True, "BadTracker"),
    (files("thing.url"), "radarr", True, "BadTracker"),
    (files("sub/dir/Movie.exe"), "radarr", True, "BadTracker"),
    (files(), "radarr", True, "BadTracker"),
]


class TestNoBehaviourChange(unittest.TestCase):
    def test_media_profile_matches_legacy_behaviour(self):
        for fl, arr_type, tracked, indexer in CORPUS:
            with self.subTest(files=[f["name"] for f in fl], arr=arr_type,
                              tracked=tracked, indexer=indexer):
                found = run(fl, arr_type, tracked, indexer)
                judged = [(f, policy.judge(CFG, "media", f)) for f in found]
                blocks = policy.outcome(judged) == "block"
                self.assertEqual(blocks,
                                 legacy_is_reapable(fl, arr_type, tracked, indexer))


class TestDetectors(unittest.TestCase):
    def test_findings_carry_no_verdict(self):
        for f in run(files("a.exe", "PASSWORD.txt")):
            self.assertNotIn("severity", f)
            self.assertNotIn("decision", f)
            self.assertEqual(set(f), {"detector", "reason", "evidence"})

    def test_extension_reports_every_hit(self):
        found = run(files("a.exe", "b.scr", "c.mkv"))
        self.assertEqual([f["evidence"]["filename"] for f in found], ["a.exe", "b.scr"])

    def test_lure_only_matches_text_files(self):
        self.assertTrue(run(files("PASSWORD.txt")))
        self.assertFalse(run(files("Password.mkv")))

    def test_archive_rule_needs_scoped_indexer(self):
        self.assertTrue(run(files("x.rar"), indexer="BadTracker"))
        self.assertFalse(run(files("x.rar"), indexer="GoodTracker"))
        self.assertFalse(run(files("x.rar"), indexer=None))

    def test_indexer_resolved_only_when_there_is_a_candidate(self):
        calls = []

        def resolve():
            calls.append(1)
            return "BadTracker"

        detectors.run(files("movie.mkv"), DET,
                      {"arr_type": "radarr", "arr_tracked": True,
                       "resolve_indexer": resolve})
        self.assertEqual(calls, [], "media present, must not cost an HTTP call")
        detectors.run(files("x.rar"), DET,
                      {"arr_type": "radarr", "arr_tracked": True,
                       "resolve_indexer": resolve})
        self.assertEqual(len(calls), 1)

    def test_broken_detector_does_not_abort_the_scan(self):
        class Boom:
            __name__ = "boom"

            @staticmethod
            def detect(fl, det, ctx):
                raise RuntimeError("nope")

        original = detectors.DETECTORS
        detectors.DETECTORS = (Boom,) + original
        try:
            self.assertTrue(run(files("a.exe")))
        finally:
            detectors.DETECTORS = original


class TestPolicy(unittest.TestCase):
    def test_same_finding_opposite_verdict_by_profile(self):
        find = run(files("setup.exe"))[0]
        self.assertEqual(policy.judge(CFG, "media", find),
                         {"profile": "media", "severity": "critical", "decision": "block"})
        self.assertEqual(policy.judge(CFG, "software", find),
                         {"profile": "software", "severity": "info", "decision": "allow"})

    def test_unknown_reason_warns_rather_than_blocks(self):
        future = detectors.finding("probe", "some_future_reason", filename="x.mkv")
        self.assertEqual(policy.judge(CFG, "media", future)["decision"], "warn")

    def test_undefined_profile_falls_back_to_media(self):
        find = run(files("a.exe"))[0]
        self.assertEqual(policy.judge(CFG, "nonexistent", find)["profile"], "media")

    def test_decisive_prefers_block_then_severity(self):
        found = run(files("PASSWORD.txt", "a.exe"))
        judged = [(f, policy.judge(CFG, "media", f)) for f in found]
        top, verdict = policy.decisive(judged)
        self.assertEqual(top["reason"], "extension_match")
        self.assertEqual(verdict["severity"], "critical")

    def test_software_profile_still_flags_the_lure(self):
        found = run(files("setup.exe", "PASSWORD.txt"))
        judged = [(f, policy.judge(CFG, "software", f)) for f in found]
        self.assertEqual(policy.outcome(judged), "warn")
        self.assertEqual(policy.decisive(judged)[0]["reason"], "lure_filename")

    def test_resolution_order_arr_then_category_then_default(self):
        cfg = {"detection": {"profile": "media"},
               "safety": {"category_profiles": {"apps": "software"}}}
        self.assertEqual(policy.resolve(cfg, {"profile": "software"}, "tv"), "software")
        self.assertEqual(policy.resolve(cfg, {}, "apps"), "software")
        self.assertEqual(policy.resolve(cfg, {}, "tv"), "media")
        self.assertEqual(policy.resolve({}, None, ""), "media")

    def test_config_can_override_a_builtin_rule(self):
        cfg = {"detection": {"profiles": {
            "media": {"lure_filename": {"severity": "medium", "decision": "warn"}}}}}
        find = run(files("PASSWORD.txt"))[0]
        self.assertEqual(policy.judge(cfg, "media", find),
                         {"profile": "media", "severity": "medium", "decision": "warn"})
        # untouched rules still come from the builtin
        self.assertEqual(policy.judge(cfg, "media", run(files("a.exe"))[0])["decision"],
                         "block")

    def test_garbage_override_is_ignored(self):
        cfg = {"detection": {"profiles": {
            "media": {"extension_match": {"severity": "nonsense", "decision": "vape"}}}}}
        self.assertEqual(policy.judge(cfg, "media", run(files("a.exe"))[0])["decision"],
                         "block")


if __name__ == "__main__":
    unittest.main()
