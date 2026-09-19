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
        if first_archive is None and _util.is_archive(f["name"], fl, archive_exts):
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


class TestAThreeDigitSuffixNeedsAVolumeFamily(unittest.TestCase):
    """A number on the end of a name is not evidence of a split archive.

    `H.264` and `H.265` are the commonest tokens in a scene video name and both
    are three digits. Until this was measured they read as archive volumes, and
    `archive_no_media` is a blocking finding, so an ordinary episode could be
    deleted on the stated evidence that it was an archive.
    """

    EXTS = {".rar", ".zip", ".7z"}

    # (title, file list, {filename: is it an archive})
    CASES = [
        ("a lone H.264 release is not an archive",
         ["Yellowjackets.S03E02.1080p.WEB-DL.DDP5.1.H.264"],
         {"Yellowjackets.S03E02.1080p.WEB-DL.DDP5.1.H.264": False}),
        ("a lone H.265 release is not an archive",
         ["The.Last.of.Us.S02E03.2160p.WEB-DL.DV.HDR.H.265"],
         {"The.Last.of.Us.S02E03.2160p.WEB-DL.DV.HDR.H.265": False}),
        ("a .001 beside its .rar is a volume",
         ["archive.rar", "archive.001"],
         {"archive.001": True}),
        ("a contiguous set is a volume even with no .rar present",
         ["payload.001", "payload.002", "payload.003"],
         {"payload.001": True, "payload.002": True, "payload.003": True}),
        ("a zero-based set is a volume",
         ["payload.000", "payload.001", "payload.002"],
         {"payload.000": True, "payload.001": True}),
        ("numeric suffixes that form no sequence are not volumes",
         ["Show.S01E01.1080p.WEB.H.264", "Movie.2024.2160p.HDR.H.265"],
         {"Show.S01E01.1080p.WEB.H.264": False,
          "Movie.2024.2160p.HDR.H.265": False}),
        ("one release in two codecs is not a volume set",
         ["Interstellar.2014.2160p.UHD.BluRay.H.264",
          "Interstellar.2014.2160p.UHD.BluRay.H.265"],
         {"Interstellar.2014.2160p.UHD.BluRay.H.264": False,
          "Interstellar.2014.2160p.UHD.BluRay.H.265": False}),
        ("a stem that already claims an archive is a volume",
         ["release.7z.001", "release.7z.002"],
         {"release.7z.001": True, "release.7z.002": True}),
        ("a single 7z volume with no siblings is still a volume",
         ["release.7z.001"], {"release.7z.001": True}),
        ("a lone .001 with nothing to be part of is not a volume",
         # The conservative reading of "family". One member is not a set, and
         # `is_archive` returning True is the answer that can get a torrent
         # deleted, so it is not the answer to guess at.
         ["payload.001"], {"payload.001": False}),
        ("a same-stem sidecar is not an archive sibling",
         ["payload.001", "payload.nfo"], {"payload.001": False}),
        ("two-digit suffixes are not volume numbers",
         # Split sets are `.001`-style or `.rNN`. `.00`/`.01` is neither, and
         # two-digit tails do occur in release names - `...1080p.60` is a
         # framerate.
         ["payload.00", "payload.01"],
         {"payload.00": False, "payload.01": False}),
        ("a set with a gap in it is not a set",
         ["broken.001", "broken.003"],
         {"broken.001": False, "broken.003": False}),
        ("an episode pack ending in H.264 holds no archives",
         ["Fallout.S01E0%d.1080p.AMZN.WEB-DL.DDP5.1.H.264" % n
          for n in range(1, 5)],
         {"Fallout.S01E01.1080p.AMZN.WEB-DL.DDP5.1.H.264": False,
          "Fallout.S01E04.1080p.AMZN.WEB-DL.DDP5.1.H.264": False}),
        ("an unrelated archive in the torrent does not adopt a .264 file",
         ["scene.rar", "Bonus.Feature.1080p.WEB.H.264"],
         {"scene.rar": True, "Bonus.Feature.1080p.WEB.H.264": False}),
        ("rar part files keep working",
         ["show.rar", "show.r00", "show.r01"],
         {"show.r00": True, "show.r01": True}),
    ]

    def test_every_case(self):
        for title, names, expected in self.CASES:
            fl = files(*names)
            for name, want in expected.items():
                with self.subTest(case=title, file=name):
                    self.assertEqual(
                        _util.is_archive(name, fl, self.EXTS), want, title)

    def test_an_episode_named_h264_earns_no_archive_finding(self):
        self.assertFalse(run(files("Yellowjackets.S03E02.1080p.WEB-DL.H.264")))

    def test_a_real_volume_set_still_earns_one(self):
        found = run(files("payload.001", "payload.002", "payload.003"))
        self.assertEqual([f["reason"] for f in found], ["archive_no_media"])


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


class OracleCase(unittest.TestCase):
    """A fake Servarr that answers /history, /blocklist and /command.

    The shapes are copied from live Sonarr and Radarr instances, including the
    two that bite: the history `downloadId` filter is case sensitive, and
    `eventType` comes back as a name although it must be sent as a number.
    """

    ARR_TYPE = "sonarr"
    HASH = "FFCFF9E6CD9A5D4CAD048BA041F987676FD8DCA0"
    TITLE = "Ted.Lasso.S04E07.1080p.ATVP.WEB-DL.DDP5.1.H.264-NTb"
    WHEN = "2026-09-12T20:37:45Z"

    def setUp(self):
        from protectarr.arr import ArrClient
        self.client = ArrClient("Sonarr", self.ARR_TYPE, "http://x", "test-api-key")
        self.history = []
        self.blocklist = []
        self.calls = []
        # Set to False to model an *arr whose filter is case insensitive.
        self.case_sensitive = True
        # Set to True to model a server that ignores the filter entirely and
        # hands back everything. Measured behaviour for a parameter Servarr
        # does not understand: HTTP 200, default result, no complaint.
        self.ignores_filters = False

        test = self

        class FakeResp:
            status_code = 200

            def __init__(inner, body):
                inner._b = body

            def raise_for_status(inner):
                pass

            def json(inner):
                return inner._b

        def fake_get(url, params=None, timeout=None):
            params = params or {}
            test.calls.append((url, dict(params)))
            if url.endswith("/history"):
                recs = list(test.history)
                want = params.get("downloadId")
                if want and not test.ignores_filters:
                    recs = [r for r in recs
                            if (r.get("downloadId") == want
                                if test.case_sensitive
                                else (r.get("downloadId") or "").lower() == want.lower())]
                if params.get("eventType") is not None and not test.ignores_filters:
                    # Servarr rejects the name; only the number filters.
                    recs = [r for r in recs if r.get("eventType") == "downloadFailed"]
                recs.sort(key=lambda r: r.get("id", 0), reverse=True)
                return FakeResp({"records": recs[:params.get("pageSize", 100)],
                                 "totalRecords": len(recs)})
            if url.endswith("/blocklist"):
                recs = sorted(test.blocklist, key=lambda r: r.get("id", 0),
                              reverse=True)
                return FakeResp({"records": recs[:params.get("pageSize", 100)],
                                 "totalRecords": len(recs)})
            raise AssertionError("unexpected GET " + url)

        self.client._s.get = fake_get

    def event(self, **over):
        rec = {"id": 17725, "date": self.WHEN, "downloadId": self.HASH,
               "sourceTitle": self.TITLE, "eventType": "downloadFailed",
               "episodeId": 16801, "seriesId": 187,
               "data": {"message": "Manually marked as failed"}}
        rec.update(over)
        return rec

    def row(self, **over):
        rec = {"id": 14, "date": self.WHEN, "sourceTitle": self.TITLE,
               "episodeIds": [16801], "seriesId": 187,
               "indexer": "LimeTorrents (Prowlarr)"}
        rec.update(over)
        return rec


class TestHistoryOracle(OracleCase):
    """Identity comes from the infohash on the history event, nothing else."""

    def test_a_matching_event_and_row_verify(self):
        self.history = [self.event()]
        self.blocklist = [self.row()]
        got = self.client.verify_remediation(self.HASH.lower(), retries=1)
        self.assertTrue(got["verified"])
        self.assertEqual(got["event"]["id"], 17725)
        self.assertEqual(got["blocklist"]["id"], 14)
        self.assertEqual(got["event"]["message"], "Manually marked as failed")

    def test_the_hash_is_uppercased_because_the_filter_is_case_sensitive(self):
        """qBittorrent says lowercase; Servarr stores and matches uppercase.

        Sending the hash as handed to us returns HTTP 200 with zero records,
        which reads exactly like a remediation that never happened.
        """
        self.history = [self.event()]
        self.blocklist = [self.row()]
        self.assertTrue(
            self.client.verify_remediation(self.HASH.lower(), retries=1)["verified"])
        asked = [p.get("downloadId") for _, p in self.calls if "downloadId" in p]
        self.assertIn(self.HASH.upper(), asked)

    def test_the_event_type_is_sent_as_a_number(self):
        """`eventType=downloadFailed` is HTTP 400 on both apps."""
        self.history = [self.event()]
        self.blocklist = [self.row()]
        self.client.verify_remediation(self.HASH, retries=1)
        types = [p.get("eventType") for _, p in self.calls if "eventType" in p]
        self.assertTrue(types)
        for value in types:
            self.assertEqual(value, 4)

    def test_an_event_for_another_torrent_is_ignored(self):
        """A filter Servarr does not apply is returned as 200 and no complaint.

        `sortKey=wibble` behaves exactly this way on both apps, so every
        server-side filter is re-applied here rather than trusted.
        """
        self.ignores_filters = True
        self.history = [self.event(downloadId="A" * 40, id=17726)]
        self.blocklist = [self.row()]
        got = self.client.verify_remediation(self.HASH, retries=1)
        self.assertFalse(got["verified"])

    def test_an_event_of_another_type_is_ignored(self):
        """Same reason: `grabbed` for this hash is not a failed download."""
        self.ignores_filters = True
        self.history = [self.event(eventType="grabbed", id=17726)]
        self.blocklist = [self.row()]
        self.assertFalse(
            self.client.verify_remediation(self.HASH, retries=1)["verified"])

    def test_no_event_is_not_verified(self):
        self.blocklist = [self.row()]
        got = self.client.verify_remediation(self.HASH, retries=1)
        self.assertFalse(got["verified"])
        self.assertIsNone(got["event"])

    def test_an_event_without_a_blocklist_row_is_reported_separately(self):
        """History proves the delete was processed, not that it blocklisted.

        `blocklist=true` is its own query parameter, and whether a
        downloadFailed event can happen without a row is untested. The two
        failures must not read the same in a bug report.
        """
        self.history = [self.event()]
        got = self.client.verify_remediation(self.HASH, retries=1)
        self.assertFalse(got["verified"])
        self.assertIsNotNone(got["event"])
        self.assertIsNone(got["blocklist"])
        self.assertIn("no blocklist row", got["why"])

    def test_an_older_event_does_not_satisfy_a_newer_intent(self):
        """The watermark is the whole point of recording one."""
        self.history = [self.event(id=100)]
        self.blocklist = [self.row()]
        self.assertTrue(self.client.verify_remediation(self.HASH, retries=1)["verified"])
        self.assertFalse(self.client.verify_remediation(
            self.HASH, after_id=100, retries=1)["verified"])
        self.assertTrue(self.client.verify_remediation(
            self.HASH, after_id=99, retries=1)["verified"])

    def test_no_hash_verifies_nothing(self):
        self.history = [self.event()]
        self.blocklist = [self.row()]
        got = self.client.verify_remediation("", retries=1)
        self.assertFalse(got["verified"])
        self.assertEqual(self.calls, [], "it should not have asked")

    def test_it_polls_because_the_records_land_a_moment_later(self):
        self.history = [self.event()]

        rows = [self.row()]
        original = self.client.blocklist_rows
        state = {"n": 0}

        def late():
            state["n"] += 1
            return rows if state["n"] > 1 else []

        self.client.blocklist_rows = late
        got = self.client.verify_remediation(self.HASH, retries=3, delay=0)
        self.assertTrue(got["verified"])
        self.client.blocklist_rows = original


class TestBlocklistCorrelation(OracleCase):
    """Exact fields only. No normalisation, ever."""

    def test_a_duplicate_title_is_resolved_by_date(self):
        """Six live Sonarr titles appear twice, from re-grabbing a release.

        The decoy is given the higher id so that it is the one considered
        first. Picking whichever row happens to come back first would pass
        without the date check and correlate the wrong remediation.
        """
        self.history = [self.event()]
        self.blocklist = [self.row(id=14, date="2026-09-01T10:00:00Z"),
                          self.row(id=13)]
        got = self.client.verify_remediation(self.HASH, retries=1)
        self.assertEqual(got["blocklist"]["id"], 13)

    def test_the_same_media_from_another_remediation_does_not_count(self):
        """Episode 19135 is on four separate blocklist rows. Media is not id."""
        self.history = [self.event()]
        self.blocklist = [self.row(id=9, sourceTitle="Something.Else.720p",
                                   date="2026-09-01T10:00:00Z")]
        got = self.client.verify_remediation(self.HASH, retries=1)
        self.assertFalse(got["verified"])

    def test_a_row_for_a_different_episode_is_rejected(self):
        self.history = [self.event()]
        self.blocklist = [self.row(episodeIds=[99999])]
        self.assertFalse(
            self.client.verify_remediation(self.HASH, retries=1)["verified"])

    def test_titles_are_compared_byte_for_byte(self):
        """qBittorrent's spaced name is never one of the two strings compared.

        Both sides are the *arr's own rendering of the release, so they are
        identical - including Radarr's doubled year. The old matcher compared
        the download client's name against the *arr's, which is why it needed
        separator-insensitive matching and why that was the wrong fix.
        """
        self.history = [self.event()]
        self.blocklist = [self.row(
            sourceTitle="Ted Lasso S04E07 1080p ATVP WEB-DL DDP5 1 H 264-NTb")]
        self.assertFalse(
            self.client.verify_remediation(self.HASH, retries=1)["verified"])

    def test_a_missing_media_id_does_not_block_the_match(self):
        """Corroboration when both sides state one, never a requirement."""
        self.history = [self.event()]
        self.blocklist = [self.row(episodeIds=[])]
        self.assertTrue(
            self.client.verify_remediation(self.HASH, retries=1)["verified"])


class TestRadarrOracle(OracleCase):
    """The same chain on Radarr, where the doubled year lives."""

    ARR_TYPE = "radarr"
    HASH = "A28B34794D0F57B24D6385C67F0979DC844DE95A"
    TITLE = "THE FIRST SLAM DUNK (2022) 2022 [BluRay.2160p.AV1.FLAC.ITA.OPUS]"
    WHEN = "2026-09-12T20:43:52Z"

    def event(self, **over):
        rec = {"id": 26, "date": self.WHEN, "downloadId": self.HASH,
               "sourceTitle": self.TITLE, "eventType": "downloadFailed",
               "movieId": 18,
               "data": {"message": "Manually marked as failed"}}
        rec.update(over)
        return rec

    def row(self, **over):
        rec = {"id": 1, "date": self.WHEN, "sourceTitle": self.TITLE,
               "movieId": 18, "indexer": "Nyaa.si (Prowlarr)"}
        rec.update(over)
        return rec

    def test_the_doubled_year_needs_no_normalisation(self):
        self.history = [self.event()]
        self.blocklist = [self.row()]
        got = self.client.verify_remediation(self.HASH.lower(), retries=1)
        self.assertTrue(got["verified"])
        self.assertEqual(got["blocklist"]["id"], 1)

    def test_a_different_movie_is_rejected(self):
        self.history = [self.event()]
        self.blocklist = [self.row(movieId=99)]
        self.assertFalse(
            self.client.verify_remediation(self.HASH, retries=1)["verified"])


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

    def _calls(self, only_active):
        """Every state_filter the scan asked for, in order."""
        from protectarr import core
        seen = []

        class FakeQb:
            def login(self): pass
            def torrents(self, category=None, state_filter=None):
                seen.append(state_filter)
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
        return seen

    def _scan_with(self, only_active):
        return self._calls(only_active)[0]

    def test_filter_is_pushed_server_side_when_only_active(self):
        self.assertEqual(self._scan_with(True), "downloading")

    def test_no_filter_when_only_active_is_off(self):
        self.assertIsNone(self._scan_with(False))

    def test_the_ownership_prune_is_the_only_unfiltered_call(self):
        """Pruning needs every hash qBittorrent has, including finished ones.

        Handing it the filtered list would forget the ownership of every
        torrent that finished downloading, which is most of them, and a
        forgotten owner is how a previously *arr-owned torrent becomes an
        ordinary category match.
        """
        calls = self._calls(True)
        self.assertEqual(calls, ["downloading", None])

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

    def verdict(self, mode, category, tracked, cleared=True):
        """What each mode does with one torrent.

        `cleared=True` by default: these pin the *mode* dispatch, and since the
        first-pass race fix a direct deletion additionally needs a fresh
        synchronisation. Leaving that un-cleared would make every row read
        None and hide the thing being tested. The synchronisation itself is
        pinned in `test_ownership_fallback`.
        """
        from protectarr import core
        safety = dict(self.SAFETY, mode=mode)
        torrent = {"category": category, "tags": ""}
        return core.evaluate(torrent, "bad.exe",
                             self.TRACKED if tracked else None, safety,
                             fallback_cleared=cleared)

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

    def test_no_mode_deletes_directly_without_a_synchronisation(self):
        """The other half of the default above, stated rather than implied."""
        for mode in ("arr_tracked", "both", "allowlist", "either"):
            self.assertIsNone(self.verdict(mode, "tv", False, cleared=False),
                              f"{mode} deleted without synchronising")

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


class TestFallbackIsLabelled(unittest.TestCase):
    """An orphan deleted from qBittorrent and a release failed through its *arr
    are different events: the fallback path cannot blocklist the release or make
    a requeue decision. History has to say which happened."""

    def _run(self, decision, tracked):
        import os, tempfile, datetime
        from protectarr import config as c, detectors
        c.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")
        from protectarr import core, events

        class Qb:
            def peers(self, h): return []
            def delete(self, h, delete_files=False): pass

        from protectarr.arr import ARR_TYPES

        class Client:
            name, type = "Sonarr", "sonarr"
            meta = ARR_TYPES["sonarr"]
            def grab_indexer(self, d): return "IX"
            def history_watermark(self): return 100
            def fail(self, i): return "removed"
            def verify_remediation(self, h, after_id=None):
                return {"verified": True, "event": {"id": 101},
                        "blocklist": {"id": 7}, "why": "both found"}
            def airdate_status(self, rec, g): return True, datetime.datetime(
                2026, 9, 17, tzinfo=datetime.timezone.utc)
            def search(self, rec): return 555

        f = detectors.finding("extension", "extension_match", filename="x.exe")
        a = {"hash": "abc", "name": "Rel", "bad_file": "x.exe", "reason": "r",
             "finding": f, "findings": [f], "policy": {"profile": "media",
             "severity": "critical", "decision": "block", "decisive_finding": 0},
             "size": 1, "category": "tv", "tags": "", "decision": decision,
             "safety_mode": "either", "arr": None,
             "_owner": (Client(), {"id": 1, "title": "Rel"}) if tracked else None,
             "_qb": Qb()}
        core.apply_actions([a], {"stats": core.load_stats()},
                           {"dry_run": False, "harvest": {"enabled": False},
                            "safety": {"requeue_after_airdate": True,
                                       "airdate_grace_hours": 0}})
        return events.read()[0]["action"]

    def test_arr_path_is_labelled_arr(self):
        act = self._run("arr_fail", tracked=True)
        self.assertEqual(act["via"], "arr")
        self.assertEqual(act["safety_mode"], "either")
        self.assertTrue(act["blocklisted"])

    def test_fallback_path_is_labelled_and_claims_no_blocklist(self):
        act = self._run("qbit_delete", tracked=False)
        self.assertEqual(act["via"], "category_fallback")
        self.assertEqual(act["safety_mode"], "either")
        self.assertFalse(act["blocklisted"],
                         "no owning *arr means no release blocklist to claim")
