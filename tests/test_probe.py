"""Probe-lane tests: validators, path mapping, the ledger, and the transaction.

The rule this lane lives or dies by:

    Only INVALID is evidence. Everything else - an unreadable file, a sparse
    file, an unrecognised header, a mislabelled but genuine release, a budget
    that ran out - must end in silence, never in an accusation.

The other half is the ledger. Steering changes settings that belong to the user,
so every test that steers also asserts the settings came back, including the
paths where the probe fails, raises, or is killed mid-flight.

Run with:  python -m unittest discover -s tests
"""

import os
import sys
import json
import time
import tempfile
import unittest

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import core, logs, probe  # noqa: E402
from protectarr.probe import engine, ledger, paths, validators  # noqa: E402
from protectarr.probe.validators import INVALID, UNKNOWN, VALID  # noqa: E402

logs.configure({"logging": {"level": "critical", "console_level": "critical",
                            "file_enabled": False}})

# Real opening bytes, not approximations - the point is to test the matcher.
MKV = b"\x1a\x45\xdf\xa3\x01\x00\x00\x00"
MP4 = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00"
AVI = b"RIFF\x24\x00\x00\x00AVI LIST"
FLAC = b"fLaC\x00\x00\x00\x22"
# MZ + a DOS stub whose e_lfanew points at a PE signature.
PE = (b"MZ" + b"\x90" * 0x3a + (0x80).to_bytes(4, "little")
      + b"\x00" * (0x80 - 0x40) + b"PE\x00\x00" + b"\x00" * 64)


def cfg(**probe_over):
    p = dict(engine.DEFAULTS, enabled=True)
    p.update(probe_over)
    return {"detection": {"probe": p}, "dry_run": False,
            "safety": {"mode": "arr_tracked"}, "arrs": []}


class TestValidators(unittest.TestCase):
    """Positive validation, and the deliberate width of UNKNOWN."""

    def test_real_media_validates(self):
        for name, head, detected in (("a.mkv", MKV, "matroska"),
                                     ("a.mp4", MP4, "iso_bmff"),
                                     ("a.avi", AVI, "avi"),
                                     ("a.flac", FLAC, "flac")):
            state, got, _ = validators.validate(name, head)
            self.assertEqual((state, got), (VALID, detected), name)

    def test_executable_wearing_a_media_extension_is_invalid(self):
        for name in ("Show.S01E01.1080p.mkv", "movie.mp4", "album.flac"):
            state, detected, _ = validators.validate(name, PE)
            self.assertEqual(state, INVALID, name)
            self.assertEqual(detected, "windows_pe")

    def test_mz_without_a_reachable_pe_header_still_accuses(self):
        """A truncated read costs us the PE confirmation, not the verdict: no
        media container may begin with "MZ" either."""
        state, detected, _ = validators.validate("x.mkv", b"MZ\x90\x00\x03")
        self.assertEqual((state, detected), (INVALID, "dos_mz"))

    def test_sparse_file_is_unknown_not_invalid(self):
        """The bug a naive implementation ships with: every in-flight torrent
        reads back as zeros, and calling that "not Matroska" would blocklist the
        entire library."""
        state, _, _ = validators.validate("x.mkv", b"\x00" * 64, ready=False)
        self.assertEqual(state, UNKNOWN)

    def test_unreadable_file_is_unknown(self):
        self.assertEqual(validators.validate("x.mkv", b"")[0], UNKNOWN)

    def test_unrecognised_header_is_unknown(self):
        state, detected, _ = validators.validate("x.mkv", b"\x11\x22\x33\x44" * 4)
        self.assertEqual((state, detected), (UNKNOWN, None))

    def test_mp4_with_a_legal_non_ftyp_first_box_is_valid(self):
        """ISO 14496-12 lets a file open with moov/mdat/free, so demanding ftyp
        would fail real files."""
        self.assertEqual(validators.validate("x.mp4", b"\x00\x00\x00\x10moov")[0],
                         VALID)

    def test_mislabelled_media_is_not_accused(self):
        """An .mkv that is really an AVI is a bad rename. Deleting somebody's
        real release over that is worse than missing it."""
        state, detected, _ = validators.validate("x.mkv", AVI)
        self.assertEqual((state, detected), (UNKNOWN, "avi"))

    def test_extension_with_no_validator_is_unknown(self):
        self.assertEqual(validators.validate("x.iso", PE)[0], UNKNOWN)

    def test_epub_that_is_a_program_is_invalid_but_a_rar_is_not(self):
        self.assertEqual(validators.validate("book.epub", PE)[0], INVALID)
        self.assertEqual(validators.validate("book.epub", b"Rar!\x1a\x07\x00")[0],
                         UNKNOWN)

    def test_every_expected_type_is_one_sniff_can_produce(self):
        """Guards against a typo in EXPECTED quietly making an extension
        unvalidatable-but-accusable."""
        producible = set(validators.CONFIDENT) | {"riff"}
        for ext, types in validators.EXPECTED.items():
            self.assertTrue(types <= producible, f"{ext}: {types - producible}")


class TestPaths(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_mapping_forms_and_longest_prefix_wins(self):
        m = paths.parse_mappings([{"from": "/downloads", "to": "/mnt/dl"},
                                  "/downloads/tv = /mnt/tv"])
        self.assertEqual(paths.map_path("/downloads/tv/a.mkv", m), "/mnt/tv/a.mkv")
        self.assertEqual(paths.map_path("/downloads/x/a.mkv", m), "/mnt/dl/x/a.mkv")

    def test_mapping_does_not_match_a_partial_directory_name(self):
        m = paths.parse_mappings([{"from": "/downloads", "to": "/mnt/dl"}])
        self.assertEqual(paths.map_path("/downloads-old/a.mkv", m),
                         "/downloads-old/a.mkv")

    def test_unmapped_path_is_left_alone(self):
        self.assertEqual(paths.map_path("/a/b.mkv", []), "/a/b.mkv")

    def test_single_file_torrent_uses_content_path_directly(self):
        t = {"content_path": "/downloads/a.mkv", "save_path": "/downloads"}
        self.assertEqual(paths.local_path(t, {"name": "a.mkv"}, True, []),
                         "/downloads/a.mkv")

    def test_multi_file_torrent_joins_the_relative_name(self):
        t = {"content_path": "/downloads/Show.S01", "save_path": "/downloads"}
        self.assertEqual(
            paths.local_path(t, {"name": "Season 1/ep1.mkv"}, False, []),
            "/downloads/Show.S01/Season 1/ep1.mkv")

    def test_incomplete_suffix_is_found(self):
        p = os.path.join(self.dir, "a.mkv")
        with open(p + ".!qB", "wb") as fh:
            fh.write(MKV)
        read = paths.read_head(p, 64)
        self.assertTrue(read.ready)
        self.assertEqual(read.data, MKV)

    def test_all_zero_read_is_not_ready(self):
        p = os.path.join(self.dir, "z.mkv")
        with open(p, "wb") as fh:
            fh.write(b"\x00" * 4096)
        self.assertFalse(paths.read_head(p, 4096).ready)

    def test_mp4_leading_zero_bytes_are_still_ready(self):
        """An MP4 legally opens with a four-byte box length of 00 00 00 20, so
        the sparse check has to look at the whole read, not the first bytes."""
        p = os.path.join(self.dir, "m.mp4")
        with open(p, "wb") as fh:
            fh.write(MP4)
        self.assertTrue(paths.read_head(p, 4096).ready)

    def test_missing_file_is_not_ready_and_never_raises(self):
        read = paths.read_head(os.path.join(self.dir, "nope.mkv"), 64)
        self.assertFalse(read.ready)
        self.assertIn("check the probe path mapping", read.why)


# ---- a qBittorrent stand-in ----

class FakeQb:
    """Records every mutation, so a test can assert what was put back."""

    def __init__(self, files, piece_states, torrent=None, arrive_after=None):
        self.files_list = files
        self.states = list(piece_states)
        self.info = torrent or {}
        self.calls = []
        # piece index -> how many pieceStates polls before it verifies
        self.arrive_after = dict(arrive_after or {})
        self.polls = 0
        self.raise_on_priority = False

    def piece_states(self, h):
        self.polls += 1
        for piece, after in list(self.arrive_after.items()):
            if self.polls > after:
                self.states[piece] = 2
        return list(self.states)

    def files(self, h):
        return self.files_list

    def torrent(self, h):
        return self.info

    def set_file_priority(self, h, ids, priority):
        self.calls.append(("prio", sorted(ids), priority))
        if self.raise_on_priority:
            raise requests.RequestException("boom")
        for i in ids:
            self.files_list[i]["priority"] = priority

    def set_sequential(self, h, on):
        self.calls.append(("seq", bool(on)))
        self.info["seq_dl"] = bool(on)

    def set_first_last_prio(self, h, on):
        self.calls.append(("flp", bool(on)))
        self.info["f_l_piece_prio"] = bool(on)


def write(dirpath, name, data):
    path = os.path.join(dirpath, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


class ProbeCase(unittest.TestCase):
    """Shared fixture: a two-file torrent on a temp 'download directory'."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        self.content = os.path.join(self.dir, "Show.S01")
        os.makedirs(self.content, exist_ok=True)
        self.torrent = {"hash": "abc123", "name": "Show.S01",
                        "content_path": self.content, "state": "downloading",
                        "progress": 0.02, "dlspeed": 5 * 1024 * 1024,
                        "num_seeds": 12, "seq_dl": False, "f_l_piece_prio": False}
        self.files = [
            {"name": "ep1.mkv", "priority": 1, "size": 900, "piece_range": [0, 4]},
            {"name": "ep2.mkv", "priority": 1, "size": 800, "piece_range": [5, 9]},
        ]
        self.state = {}

    def probe(self, qb, conf=None, **kw):
        return engine.inspect(qb, self.torrent, self.files,
                              conf or cfg(), self.state, **kw)


class TestFreePass(ProbeCase):
    """Pieces already on disk cost nothing and must mutate nothing."""

    def test_finds_an_executable_without_touching_anything(self):
        write(self.content, "ep1.mkv", PE)
        qb = FakeQb(self.files, [2] * 10, self.torrent)
        res = self.probe(qb)
        self.assertEqual(len(res.findings), 1)
        find = res.findings[0]
        self.assertEqual(find["reason"], "content_type_mismatch")
        self.assertEqual(find["evidence"]["detected_type"], "windows_pe")
        self.assertEqual(find["evidence"]["claimed_type"], ".mkv")
        self.assertEqual(find["evidence"]["source"], "free")
        self.assertFalse(res.steered)
        self.assertEqual(qb.calls, [], "the free pass must not change settings")

    def test_real_media_produces_nothing(self):
        write(self.content, "ep1.mkv", MKV)
        write(self.content, "ep2.mkv", MKV)
        qb = FakeQb(self.files, [2] * 10, self.torrent)
        self.assertEqual(self.probe(qb).findings, ())

    def test_unverified_piece_is_never_read(self):
        """A piece only reaches state 2 after its hash checks out. Trusting
        bytes before that would let a hostile peer feed a junk header into a
        legitimate release and have Protectarr blocklist it."""
        write(self.content, "ep1.mkv", PE)
        qb = FakeQb(self.files, [1] * 10, self.torrent)      # nothing verified
        res = self.probe(qb, cfg(steer=False))
        self.assertEqual(res.findings, ())

    def test_missing_download_directory_is_silent(self):
        """No path mapping means Protectarr cannot see the bytes. That is a fact
        about our filesystem access, not about the torrent."""
        qb = FakeQb(self.files, [2] * 10, self.torrent)
        self.assertEqual(self.probe(qb, cfg(steer=False)).findings, ())

    def test_torrent_with_no_media_files_is_skipped_entirely(self):
        self.files = [{"name": "readme.txt", "priority": 1, "piece_range": [0, 1]}]
        qb = FakeQb(self.files, [2] * 10, self.torrent)
        self.assertEqual(self.probe(qb), engine.NOTHING)
        self.assertEqual(qb.polls, 0, "should not even ask for piece states")


class TestSteering(ProbeCase):
    """The transaction: change settings, get a verdict, put everything back."""

    def _conf(self, **kw):
        over = dict(poll_seconds=0, torrent_timeout_seconds=5)
        over.update(kw)
        return cfg(**over)

    def test_steers_to_the_piece_then_restores_everything(self):
        write(self.content, "ep1.mkv", PE)
        self.files[0]["priority"] = 4       # a non-default the user chose
        qb = FakeQb(self.files, [0] * 10, self.torrent, arrive_after={0: 1})
        res = self.probe(qb, self._conf())

        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]["evidence"]["source"], "steered")
        self.assertTrue(res.steered)
        self.assertEqual([f["priority"] for f in qb.files_list], [4, 1])
        self.assertFalse(qb.info["seq_dl"])
        self.assertFalse(qb.info["f_l_piece_prio"])
        self.assertEqual(ledger.entries(), {}, "ledger must be closed")

    def test_timeout_restores_and_accuses_nobody(self):
        qb = FakeQb(self.files, [0] * 10, self.torrent)     # piece never arrives
        res = self.probe(qb, self._conf(stall_checks=99),
                         deadline=time.time() + 0.2)
        self.assertEqual(res.findings, ())
        self.assertEqual([f["priority"] for f in qb.files_list], [1, 1])
        self.assertEqual(ledger.entries(), {})

    def test_a_stalled_torrent_gives_up_early_instead_of_burning_the_budget(self):
        """Steering only influences the NEXT piece libtorrent picks; it cannot
        recall one already in flight. On a dead torrent the budget buys nothing,
        so it is not spent."""
        self.torrent["dlspeed"] = 0
        qb = FakeQb(self.files, [0] * 10, self.torrent)
        started = time.time()
        res = self.probe(qb, self._conf(torrent_timeout_seconds=30))
        self.assertEqual(res.findings, ())
        self.assertLess(time.time() - started, 5)
        self.assertEqual(qb.calls, [], "a torrent this slow is never steered")

    def test_settings_are_restored_even_when_qbittorrent_blows_up(self):
        write(self.content, "ep1.mkv", PE)
        qb = FakeQb(self.files, [0] * 10, self.torrent, arrive_after={0: 1})

        original = qb.set_file_priority
        calls = []

        def explode(h, ids, priority):
            calls.append(priority)
            if len(calls) == 2:             # fail mid-transaction
                raise requests.RequestException("qBittorrent went away")
            return original(h, ids, priority)

        qb.set_file_priority = explode
        res = self.probe(qb, self._conf())
        self.assertEqual(res.findings, ())
        self.assertEqual(ledger.entries(), {},
                         "restore runs in a finally, so the ledger closes")

    def test_a_dry_run_never_steers(self):
        conf = self._conf()
        conf["dry_run"] = True
        qb = FakeQb(self.files, [0] * 10, self.torrent, arrive_after={0: 1})
        res = self.probe(qb, conf)
        self.assertEqual(qb.calls, [])
        self.assertFalse(res.steered)

    def test_steering_is_refused_when_the_ledger_cannot_be_written(self):
        """A change we cannot guarantee we can undo is not worth a verdict."""
        cfg_mod.CONFIG_PATH = "/proc/definitely-not-writable/config.yaml"
        try:
            qb = FakeQb(self.files, [0] * 10, self.torrent, arrive_after={0: 1})
            self.probe(qb, self._conf())
            self.assertEqual(qb.calls, [])
        finally:
            cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")

    def test_the_same_torrent_is_not_re_steered_every_pass(self):
        qb = FakeQb(self.files, [0] * 10, self.torrent)
        conf = self._conf(stall_checks=99)
        self.probe(qb, conf, deadline=time.time() + 0.2)
        first = len(qb.calls)
        self.probe(qb, conf, deadline=time.time() + 0.2)
        self.assertEqual(len(qb.calls), first, "cooldown should hold it off")

    def test_no_steering_budget_means_no_mutation(self):
        qb = FakeQb(self.files, [0] * 10, self.torrent, arrive_after={0: 1})
        res = self.probe(qb, self._conf(), allow_steer=False)
        self.assertEqual(qb.calls, [])
        self.assertFalse(res.steered)


class TestLedger(ProbeCase):
    """Surviving a process that dies mid-probe."""

    def test_reconcile_restores_what_a_killed_probe_left_behind(self):
        ledger.open_probe("abc123", "Show.S01", {0: 4, 1: 1}, False, False)
        # what the dead process had done to the torrent before it was killed
        self.files[0]["priority"] = 0
        self.files[1]["priority"] = 7
        self.torrent["seq_dl"] = True
        qb = FakeQb(self.files, [0] * 10, self.torrent)
        self.assertEqual(ledger.reconcile(qb), 1)
        self.assertEqual([f["priority"] for f in qb.files_list], [4, 1])
        self.assertFalse(qb.info["seq_dl"])
        self.assertEqual(ledger.entries(), {})

    def test_reconcile_is_idempotent(self):
        ledger.open_probe("abc123", "Show.S01", {0: 1, 1: 1}, False, False)
        qb = FakeQb(self.files, [0] * 10, self.torrent)
        ledger.reconcile(qb)
        self.assertEqual(ledger.reconcile(qb), 0)

    def test_a_failed_restore_keeps_the_entry_for_next_time(self):
        ledger.open_probe("abc123", "Show.S01", {0: 4, 1: 1}, False, False)
        qb = FakeQb(self.files, [0] * 10, self.torrent)
        qb.raise_on_priority = True
        self.assertFalse(ledger.restore(qb, "abc123"))
        self.assertIn("abc123", ledger.entries())
        self.assertEqual(ledger.entries()["abc123"]["restore_attempts"], 1)

    def test_a_vanished_torrent_is_dropped_rather_than_warned_about_forever(self):
        ledger.open_probe("gone", "Old", {0: 1}, False, False)

        class Gone(FakeQb):
            def set_file_priority(self, h, ids, priority):
                err = requests.RequestException("not found")
                err.response = type("R", (), {"status_code": 404})()
                raise err

        self.assertTrue(ledger.restore(Gone(self.files, [], self.torrent), "gone"))
        self.assertEqual(ledger.entries(), {})

    def test_a_corrupt_ledger_does_not_break_startup(self):
        with open(os.path.join(self.dir, "probe.json"), "w") as fh:
            fh.write("{not json")
        self.assertEqual(ledger.entries(), {})

    def test_priorities_survive_the_json_round_trip_as_integers(self):
        """JSON object keys are strings. Restoring index "0" as the string "0"
        would silently match nothing."""
        ledger.open_probe("abc123", "Show.S01", {0: 6, 1: 0}, False, False)
        with open(os.path.join(self.dir, "probe.json")) as fh:
            raw = json.load(fh)
        self.assertEqual(raw["open"]["abc123"]["priorities"], {"0": 6, "1": 0})
        qb = FakeQb(self.files, [0] * 10, self.torrent)
        self.assertTrue(ledger.restore(qb, "abc123"))
        self.assertEqual([f["priority"] for f in qb.files_list], [6, 0])


class TestSteerability(unittest.TestCase):
    def setUp(self):
        self.p = engine.settings(cfg())

    def base(self, **over):
        t = {"state": "downloading", "progress": 0.1, "dlspeed": 5 * 1024 * 1024,
             "num_seeds": 5}
        t.update(over)
        return t

    def test_a_healthy_torrent_is_steerable(self):
        self.assertTrue(engine.steerable(self.base(), self.p)[0])

    def test_paused_complete_and_crawling_torrents_are_not(self):
        for over in ({"state": "stoppedDL"}, {"progress": 1.0}, {"dlspeed": 1024}):
            self.assertFalse(engine.steerable(self.base(**over), self.p)[0], over)

    def test_a_hand_edited_config_cannot_produce_a_hot_loop(self):
        p = engine.settings({"detection": {"probe": {
            "poll_seconds": 0, "header_bytes": 1, "torrent_timeout_seconds": -5,
            "max_torrents_per_scan": "nonsense"}}})
        self.assertGreaterEqual(p["poll_seconds"], 1)
        self.assertGreaterEqual(p["header_bytes"], 64)
        self.assertGreaterEqual(p["torrent_timeout_seconds"], 5)
        self.assertEqual(p["max_torrents_per_scan"],
                         engine.DEFAULTS["max_torrents_per_scan"])


class TestWiring(ProbeCase):
    """The lane's place in a scan: same policy, same safety rules, second."""

    def test_a_probe_finding_is_judged_like_any_other(self):
        find = {"detector": "probe", "reason": "content_type_mismatch",
                "evidence": {"filename": "ep1.mkv", "claimed_type": ".mkv",
                             "detected_type": "windows_pe"}}
        conf = {"detection": {}, "safety": {"mode": "allowlist",
                                            "allowed_categories": ["tv"]},
                "arrs": [], "dry_run": False}
        t = dict(self.torrent, category="tv")
        row = core._assess(t, [find], None, {}, conf, conf["safety"], True, None)
        self.assertEqual(row["decision"], "qbit_delete")
        self.assertEqual(row["policy"]["severity"], "critical")
        self.assertIn("Windows program", row["reason"])

    def test_the_software_profile_only_warns_about_a_mismatch(self):
        find = {"detector": "probe", "reason": "content_type_mismatch",
                "evidence": {"filename": "ep1.mkv", "claimed_type": ".mkv",
                             "detected_type": "windows_pe"}}
        conf = {"detection": {"profile": "software"},
                "safety": {"mode": "allowlist", "allowed_categories": ["tv"]},
                "arrs": [], "dry_run": False}
        t = dict(self.torrent, category="tv")
        row = core._assess(t, [find], None, {}, conf, conf["safety"], True, None)
        self.assertEqual(row["decision"], "warn")

    def test_the_probe_lane_is_off_by_default(self):
        self.assertFalse(probe.enabled(cfg_mod.load()))


try:
    from protectarr import web as web_mod
except ImportError:                     # Flask not installed
    web_mod = None


@unittest.skipIf(web_mod is None, "Flask is not installed")
class TestMappingEntry(unittest.TestCase):
    """Two labelled fields per mapping, rather than one "a = b" text box.

    The text box silently dropped anything it could not parse, so typing a bare
    folder path - the obvious thing to do - looked exactly like "saving is
    broken" and pointed at nothing.
    """

    def form(self, froms, tos):
        from werkzeug.datastructures import MultiDict
        return MultiDict([("map_from", v) for v in froms]
                         + [("map_to", v) for v in tos])

    def test_a_pair_of_paths_becomes_a_mapping(self):
        got, partial = web_mod._mappings_from_form(
            self.form(["/General Storage/torrents"], ["/downloads"]))
        self.assertEqual(got, [{"from": "/General Storage/torrents",
                                "to": "/downloads"}])
        self.assertEqual(partial, [])

    def test_paths_containing_spaces_survive(self):
        got, _ = web_mod._mappings_from_form(
            self.form(["/General Storage/t"], ["/a b/c"]))
        self.assertEqual(got[0], {"from": "/General Storage/t", "to": "/a b/c"})

    def test_no_mappings_is_a_valid_answer(self):
        """Mirroring qBittorrent's path in the compose file needs no mapping at
        all, so an empty form must save cleanly and say nothing."""
        got, partial = web_mod._mappings_from_form(self.form([], []))
        self.assertEqual((got, partial), ([], []))

    def test_a_half_filled_row_is_reported_not_swallowed(self):
        got, partial = web_mod._mappings_from_form(
            self.form(["/General Storage/torrents"], [""]))
        self.assertEqual(got, [])
        self.assertEqual(partial, ["/General Storage/torrents"])

    def test_hand_edited_yaml_still_renders_in_the_form(self):
        """config.example.yaml documents the dict form, and the old text box
        wrote "a = b" strings. Both have to come back as fields."""
        self.assertEqual(web_mod._mapping_rows([{"from": "/a", "to": "/b"}]),
                         [{"from": "/a", "to": "/b"}])
        self.assertEqual(web_mod._mapping_rows(["/a = /b"]),
                         [{"from": "/a", "to": "/b"}])
        self.assertEqual(web_mod._mapping_rows([{"from": "/a"}, None, 7]), [])


class ScanQb(FakeQb):
    """Enough qBittorrent for core.scan() to run a whole pass."""

    def __init__(self, torrents, files_by_hash, piece_states):
        FakeQb.__init__(self, [], piece_states)
        self._t, self._f = torrents, files_by_hash

    def login(self):
        pass

    def torrents(self, category=None, state_filter=None):
        return self._t

    def files(self, h):
        return self._f.get(h, [])

    def set_file_priority(self, h, ids, priority):
        self.calls.append(("prio", sorted(ids), priority))
        for i in ids:
            self._f[h][i]["priority"] = priority

    def peers(self, h):
        return []


class TestScanIntegration(unittest.TestCase):
    """Where the probe lane sits in a scan, which is as much a safety property
    as the validators are."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        self.content = os.path.join(self.dir, "dl")
        os.makedirs(self.content, exist_ok=True)

    def _cfg(self, mode="allowlist", **probe_over):
        c = cfg(**probe_over)
        c["qbittorrent"] = {"url": "http://x"}
        c["detection"].update(blocked_extensions=[".exe"],
                              blocked_name_keywords=[], only_active=True,
                              archive_detection={"enabled": False, "indexers": [],
                                                 "archive_extensions": []})
        c["safety"] = {"mode": mode, "allowed_categories": ["tv"],
                       "allowed_tags": []}
        return c

    def _torrent(self, name, **kw):
        # A single-file torrent's content_path IS the file, which is what makes
        # the mapping in probe.paths work without a special case.
        t = {"hash": name, "name": name, "state": "downloading", "category": "tv",
             "tags": "", "size": 1, "progress": 0.02,
             "content_path": os.path.join(self.content, "movie.mkv"),
             "dlspeed": 5 * 1024 * 1024, "num_seeds": 9}
        t.update(kw)
        return t

    def _scan(self, cfg_dict, qb):
        real_qb, real_build = core.QbitClient, core.build_clients
        core.QbitClient = lambda *a, **k: qb
        core.build_clients = lambda c: []
        try:
            return core.scan(cfg_dict, {})
        finally:
            core.QbitClient, core.build_clients = real_qb, real_build

    def test_a_disguised_payload_is_reaped_through_the_normal_path(self):
        write(self.content, "movie.mkv", PE)
        t = self._torrent("t1")
        files = {"t1": [{"name": "movie.mkv", "priority": 1, "size": 9,
                         "piece_range": [0, 4]}]}
        actions = self._scan(self._cfg(), ScanQb([t], files, [2] * 10))
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["decision"], "qbit_delete")
        self.assertEqual(actions[0]["findings"][0]["reason"],
                         "content_type_mismatch")

    def test_a_torrent_outside_the_reaping_rules_is_never_probed(self):
        """Steering a torrent Protectarr may never touch would be a change made
        for no possible outcome."""
        write(self.content, "movie.mkv", PE)
        t = self._torrent("t1", category="not-allowlisted")
        files = {"t1": [{"name": "movie.mkv", "priority": 1, "size": 9,
                         "piece_range": [0, 4]}]}
        qb = ScanQb([t], files, [2] * 10)
        self.assertEqual(self._scan(self._cfg(), qb), [])
        self.assertEqual(qb.polls, 0, "should not even look at piece states")

    def test_a_queued_reap_goes_first_and_the_probe_waits_a_pass(self):
        """A known fake beats a suspected one, and probing blocks the pass for
        as long as its budget allows."""
        write(self.content, "movie.mkv", PE)
        obvious = self._torrent("t1", content_path=self.content)
        subtle = self._torrent("t2")
        files = {"t1": [{"name": "payload.exe", "priority": 1, "piece_range": [0, 1]}],
                 "t2": [{"name": "movie.mkv", "priority": 1, "size": 9,
                         "piece_range": [0, 4]}]}
        qb = ScanQb([obvious, subtle], files, [2] * 10)
        actions = self._scan(self._cfg(), qb)
        self.assertEqual([a["hash"] for a in actions], ["t1"])
        self.assertEqual(qb.polls, 0, "the probe lane sat this pass out")

    def test_the_fast_lane_still_decides_when_the_probe_is_off(self):
        write(self.content, "movie.mkv", PE)
        t = self._torrent("t1")
        files = {"t1": [{"name": "movie.mkv", "priority": 1, "size": 9,
                         "piece_range": [0, 4]}]}
        qb = ScanQb([t], files, [2] * 10)
        self.assertEqual(self._scan(self._cfg(enabled=False), qb), [])
        self.assertEqual(qb.polls, 0)

    def test_an_interrupted_probe_is_reconciled_on_the_first_scan(self):
        ledger.open_probe("t1", "left steered", {0: 3}, True, False)
        t = self._torrent("t1")
        files = {"t1": [{"name": "movie.mkv", "priority": 0, "size": 9,
                         "piece_range": [0, 4]}]}
        qb = ScanQb([t], files, [0] * 10)
        self._scan(self._cfg(enabled=False), qb)
        self.assertEqual(ledger.entries(), {},
                         "turning the probe off must not strand a torrent")
        self.assertEqual(files["t1"][0]["priority"], 3)


if __name__ == "__main__":
    unittest.main()
