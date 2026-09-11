"""Detection + policy tests.

The detector/policy split changes structure, not what Protectarr *does*.
`test_media_profile_matches_legacy_behaviour` is the one that matters: it replays
the pre-refactor rules over a corpus of file lists and asserts the new pipeline
reaches the same reap-or-not answer every time.

Note the precise claim: **action** behaviour is unchanged. Recorded output did
change, deliberately - detectors no longer stop at the first hit, so a torrent
with both an `.exe` and a `PASSWORD.txt` now reports both and names the `.exe` as
decisive rather than whichever happened to come first in the file list.

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


class TestActionBehaviourUnchanged(unittest.TestCase):
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


class TestEventNormalisation(unittest.TestCase):
    """Every schema version has to keep rendering; history is append-only."""

    def setUp(self):
        from protectarr import events
        self.events = events

    def test_v1_severity_on_the_finding(self):
        ev = {"schema_version": 1,
              "finding": {"detector": "extension", "severity": "critical",
                          "reason": "blocked_extension",
                          "evidence": {"filename": "a.exe", "extension": ".exe"}}}
        found, decisive, sev, profile = self.events.normalize(ev)
        self.assertEqual(len(found), 1)
        self.assertEqual(decisive["reason"], "blocked_extension")
        self.assertEqual(sev, "critical")
        self.assertIsNone(profile)
        self.assertIn("Monitored extension .exe", self.events.describe(decisive))

    def test_v2_decisive_plus_tail(self):
        ev = {"schema_version": 2,
              "finding": {"detector": "extension", "reason": "extension_match",
                          "evidence": {"filename": "a.exe"}},
              "other_findings": [{"detector": "filename", "reason": "lure_filename",
                                  "evidence": {"filename": "PASSWORD.txt"}}],
              "policy": {"profile": "media", "severity": "critical", "decision": "block"}}
        found, decisive, sev, profile = self.events.normalize(ev)
        self.assertEqual(len(found), 2)
        self.assertEqual(decisive["reason"], "extension_match")
        self.assertEqual((sev, profile), ("critical", "media"))

    def test_v3_indexed_into_the_list(self):
        ev = {"schema_version": 3,
              "findings": [{"detector": "filename", "reason": "lure_filename",
                            "evidence": {"filename": "PASSWORD.txt"}},
                           {"detector": "extension", "reason": "extension_match",
                            "evidence": {"filename": "a.exe"}}],
              "policy": {"profile": "media", "severity": "critical",
                         "decision": "block", "decisive_finding": 1}}
        found, decisive, sev, _ = self.events.normalize(ev)
        self.assertEqual(len(found), 2)
        self.assertEqual(decisive["reason"], "extension_match")
        self.assertEqual(sev, "critical")

    def test_out_of_range_index_does_not_explode(self):
        ev = {"findings": [{"detector": "x", "reason": "y", "evidence": {}}],
              "policy": {"decisive_finding": 7}}
        _, decisive, _, _ = self.events.normalize(ev)
        self.assertEqual(decisive["reason"], "y")

    def test_empty_event(self):
        self.assertEqual(self.events.normalize({}), ([], None, None, None))


class TestWarnFingerprint(unittest.TestCase):
    def test_same_observations_dedupe_but_a_new_one_does_not(self):
        from protectarr import core
        a = {"hash": "abc", "findings": [
            {"detector": "filename", "reason": "lure_filename",
             "evidence": {"filename": "PASSWORD.txt"}}]}
        same = {"hash": "abc", "findings": [dict(a["findings"][0])]}
        more = {"hash": "abc", "findings": a["findings"] + [
            {"detector": "probe", "reason": "content_type_mismatch",
             "evidence": {"filename": "movie.mkv"}}]}
        other_torrent = {"hash": "def", "findings": a["findings"]}
        self.assertEqual(core._warn_fingerprint(a), core._warn_fingerprint(same))
        self.assertNotEqual(core._warn_fingerprint(a), core._warn_fingerprint(more))
        self.assertNotEqual(core._warn_fingerprint(a), core._warn_fingerprint(other_torrent))


if __name__ == "__main__":
    unittest.main()


class TestBlocklistConfirmation(unittest.TestCase):
    """The live reap of 2026-09-11 19:10 reported blocklisted=false because the
    queue title and the blocklist's sourceTitle differ only by separator."""

    def setUp(self):
        from protectarr.arr import ArrClient
        self.client = ArrClient("Sonarr", "sonarr", "http://x", "k")
        self.records = []
        self.calls = 0

        class FakeResp:
            def __init__(inner, records):
                inner._r = records

            def raise_for_status(inner):
                pass

            def json(inner):
                return {"records": inner._r}

        def fake_get(url, params=None, timeout=None):
            self.calls += 1
            return FakeResp(self.records)

        self.client._s.get = fake_get

    QUEUE = "Ted Lasso S04E07 1080p ATVP WEB-DL DDP5 1 H 264-NTb"
    RAW = "Ted.Lasso.S04E07.1080p.ATVP.WEB-DL.DDP5.1.H.264-NTb"

    HASH = "ffcff9e6cd9a5d4cad048ba041f987676fd8dca0"

    def match(self, **kw):
        kw.setdefault("retries", 1)
        return self.client.blocklist_match(**kw)

    def test_dotted_blocklist_entry_matches_spaced_queue_title(self):
        self.records = [{"sourceTitle": self.RAW}]
        self.assertEqual(self.match(titles=self.QUEUE), "normalized")

    def test_spaced_blocklist_entry_matches_too(self):
        self.records = [{"sourceTitle": self.QUEUE}]
        self.assertEqual(self.match(titles=self.RAW), "normalized")

    def test_exact_title_beats_the_normalised_fallback(self):
        self.records = [{"sourceTitle": self.QUEUE}]
        self.assertEqual(self.match(titles=self.QUEUE), "title")

    def test_hash_wins_even_when_a_title_also_matches(self):
        self.records = [{"sourceTitle": self.QUEUE,
                         "torrentInfoHash": self.HASH.upper()}]
        self.assertEqual(self.match(torrent_hash=self.HASH,
                                    titles=self.QUEUE), "hash")

    def test_hash_on_a_later_record_is_not_pre_empted_by_a_weak_match(self):
        self.records = [{"sourceTitle": self.RAW},
                        {"sourceTitle": "unrelated", "downloadId": self.HASH}]
        self.assertEqual(self.match(torrent_hash=self.HASH,
                                    titles=self.QUEUE), "hash")

    def test_downloadid_is_accepted_as_the_hash(self):
        self.records = [{"sourceTitle": "unrelated", "downloadId": self.HASH}]
        self.assertEqual(self.match(torrent_hash=self.HASH), "hash")

    def test_missing_hash_field_degrades_to_titles(self):
        self.records = [{"sourceTitle": self.RAW}]
        self.assertEqual(self.match(torrent_hash=self.HASH,
                                    titles=self.QUEUE), "normalized")

    def test_several_candidate_titles(self):
        self.records = [{"sourceTitle": self.RAW}]
        self.assertEqual(
            self.match(titles=["something else entirely", self.QUEUE]), "normalized")

    def test_a_different_release_still_does_not_match(self):
        self.records = [{"sourceTitle":
                         "Ted.Lasso.S04E07.1080p.ATVP.WEB-DL.DDP5.1.H.264-OTHER"}]
        self.assertIsNone(self.match(titles=self.QUEUE))

    def test_a_different_episode_still_does_not_match(self):
        self.records = [{"sourceTitle":
                         "Ted.Lasso.S04E06.1080p.ATVP.WEB-DL.DDP5.1.H.264-NTb"}]
        self.assertIsNone(self.match(titles=self.QUEUE))

    def test_a_different_torrent_hash_does_not_match(self):
        self.records = [{"sourceTitle": "unrelated", "torrentInfoHash": "deadbeef"}]
        self.assertIsNone(self.match(torrent_hash=self.HASH))

    def test_nothing_to_match_on_short_circuits_without_calling_the_api(self):
        self.assertIsNone(self.match(titles=["", None], retries=3))
        self.assertEqual(self.calls, 0)

    def test_polls_because_sonarr_writes_the_entry_late(self):
        self.records = []
        self.assertIsNone(self.match(titles=self.QUEUE, retries=3, delay=0))
        self.assertEqual(self.calls, 3)


class TestQueueIncludes(unittest.TestCase):
    """owner.media was null on the live event because the queue record had no
    nested series object. These are the params that fix that."""

    def test_every_arr_type_asks_for_its_media_object(self):
        from protectarr.arr import ARR_TYPES
        for name, meta in ARR_TYPES.items():
            with self.subTest(arr=name):
                self.assertTrue(meta.get("queue_includes"))

    def test_includes_are_sent_on_the_queue_call(self):
        from protectarr.arr import ArrClient
        seen = {}

        class R:
            def raise_for_status(self): pass
            def json(self): return {"records": []}

        c = ArrClient("Sonarr", "sonarr", "http://x", "k")
        c._s.get = lambda url, params=None, timeout=None: (
            seen.update(params or {}), R())[1]
        c.queue_by_hash()
        self.assertEqual(seen.get("includeSeries"), "true")
        self.assertEqual(seen.get("includeEpisode"), "true")
        self.assertEqual(seen.get("includeUnknownSeriesItems"), "true")

    def test_media_name_reads_the_nested_object(self):
        from protectarr.core import _media_name
        self.assertEqual(_media_name({"series": {"title": "Ted Lasso"}}), "Ted Lasso")
        self.assertEqual(_media_name({"movie": {"title": "Dune"}}), "Dune")
        self.assertIsNone(_media_name({"title": "release name only"}))


class TestServerSideFilter(unittest.TestCase):
    """The unfiltered torrent list was 2.4 MB every 20s on a 1214-torrent
    library, to inspect one torrent. Verified live against qBittorrent 5.2.3
    that filter=downloading includes stoppedDL and stalledDL, so it does not
    narrow what Protectarr would have looked at."""

    def _scan_with(self, only_active):
        from protectarr import core
        seen = {}

        class FakeQb:
            def login(self): pass
            def torrents(self, category=None, state_filter=None):
                seen["state_filter"] = state_filter
                return []
            def files(self, h): return []

        real = core.QbitClient
        core.QbitClient = lambda *a, **k: FakeQb()
        try:
            core.scan({"qbittorrent": {"url": "http://x"},
                       "detection": {"only_active": only_active},
                       "safety": {}, "arrs": []}, {})
        finally:
            core.QbitClient = real
        return seen.get("state_filter")

    def test_filter_is_pushed_server_side_when_only_active(self):
        self.assertEqual(self._scan_with(True), "downloading")

    def test_no_filter_when_only_active_is_off(self):
        self.assertIsNone(self._scan_with(False))

    def test_client_still_passes_the_param_through(self):
        from protectarr.qbit import QbitClient
        seen = {}

        class R:
            content = b"[]"
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return []

        qb = QbitClient("http://x", api_key="k")
        qb._s.get = lambda url, params=None, timeout=None: (seen.update(params or {}), R())[1]
        qb.torrents(state_filter="downloading")
        self.assertEqual(seen.get("filter"), "downloading")
        seen.clear()
        qb.torrents()
        self.assertNotIn("filter", seen)


class TestSafetyModes(unittest.TestCase):
    """Each mode has a different blind spot. `either` is the union, added
    because an *arr that fails a release drops it from its queue while the
    torrent keeps downloading in qBittorrent, owned by nobody."""

    SAFETY = {"allowed_categories": ["tv"], "allowed_tags": []}
    TRACKED = object()          # stands in for (client, record)

    def verdict(self, mode, category, tracked):
        from protectarr import core
        safety = dict(self.SAFETY, mode=mode)
        torrent = {"category": category, "tags": ""}
        return core.evaluate(torrent, "bad.exe",
                             self.TRACKED if tracked else None, safety)

    def test_arr_tracked_leaves_orphans_alone(self):
        self.assertEqual(self.verdict("arr_tracked", "tv", True), "arr_fail")
        self.assertIsNone(self.verdict("arr_tracked", "tv", False))

    def test_allowlist_misses_tracked_outside_the_list(self):
        self.assertEqual(self.verdict("allowlist", "tv", True), "arr_fail")
        self.assertEqual(self.verdict("allowlist", "tv", False), "qbit_delete")
        self.assertIsNone(self.verdict("allowlist", "movies", True))

    def test_both_is_an_and(self):
        self.assertEqual(self.verdict("both", "tv", True), "arr_fail")
        self.assertIsNone(self.verdict("both", "movies", True))
        self.assertIsNone(self.verdict("both", "tv", False))

    def test_either_catches_the_orphan(self):
        """The live case: Sonarr failed the release and dropped it, the torrent
        kept downloading a .exe, and arr_tracked would not touch it."""
        self.assertEqual(self.verdict("either", "tv", False), "qbit_delete")

    def test_either_still_prefers_the_arr_when_one_owns_it(self):
        # Only the *arr path blocklists the release and decides about requeue,
        # so it must win even when the category is also allowlisted.
        self.assertEqual(self.verdict("either", "tv", True), "arr_fail")

    def test_either_covers_tracked_outside_the_allowlist(self):
        self.assertEqual(self.verdict("either", "movies", True), "arr_fail")

    def test_either_still_protects_unlisted_orphans(self):
        # A hand-added torrent in a category you never listed stays untouched.
        self.assertIsNone(self.verdict("either", "linux-isos", False))

    def test_either_is_a_superset_of_the_others(self):
        for category in ("tv", "movies", "linux-isos"):
            for tracked in (True, False):
                for mode in ("arr_tracked", "allowlist", "both"):
                    if self.verdict(mode, category, tracked) is not None:
                        with self.subTest(mode=mode, cat=category, tracked=tracked):
                            self.assertIsNotNone(
                                self.verdict("either", category, tracked),
                                "either must act wherever a narrower mode would")

    def test_unknown_mode_does_nothing(self):
        self.assertIsNone(self.verdict("nonsense", "tv", True))
