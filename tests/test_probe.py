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
from protectarr.probe import engine, ledger, paths, pieces, validators  # noqa: E402
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

    def test_mz_without_a_reachable_pe_header_accuses_nobody(self):
        """Starting like a Windows program is not being one.

        This used to return INVALID on the grounds that no media container may
        begin with "MZ" either. True, but it makes two bytes enough to delete a
        download, and the same branch fires when a short read or a header
        budget smaller than the file's `e_lfanew` costs us the confirmation we
        would otherwise have had. Only a structurally verified PE accuses now.
        """
        state, detected, note = validators.validate("x.mkv", b"MZ\x90\x00\x03")
        self.assertEqual((state, detected), (UNKNOWN, "dos_mz"))
        self.assertIn("not confirmed", note)
        self.assertNotIn("dos_mz", validators.CONFIDENT)

    def test_a_pe_signature_before_the_dos_header_ends_is_not_confirmation(self):
        """`e_lfanew` pointing inside the 0x40-byte DOS header it lives in is
        not a layout any linker produces, and accepting it would let a crafted
        file confirm itself out of bytes it also controls."""
        head = bytearray(b"\x00" * 0x80)
        head[0:2] = b"MZ"
        head[4:8] = b"PE\x00\x00"           # a signature, in the wrong place
        head[0x3c:0x40] = (4).to_bytes(4, "little")
        state, detected, _ = validators.validate("x.mkv", bytes(head))
        self.assertEqual((state, detected), (UNKNOWN, "dos_mz"))

    def test_a_full_dos_header_with_no_signature_at_the_pointer_is_not_a_pe(self):
        """The bytes are all there, `e_lfanew` is legal, and what it points at
        is not a PE signature. This is the check itself, with nothing else
        standing in front of it."""
        head = bytearray(b"\x00" * 128)
        head[0:2] = b"MZ"
        head[0x3c:0x40] = (0x40).to_bytes(4, "little")
        state, detected, _ = validators.validate("x.mkv", bytes(head))
        self.assertEqual((state, detected), (UNKNOWN, "dos_mz"))

    def test_an_e_lfanew_past_the_header_budget_is_not_confirmation(self):
        """The pointer is readable, its target is not. That is an unconfirmed
        program, not a confirmed one and not a clean file."""
        head = bytearray(b"\x00" * 128)
        head[0:2] = b"MZ"
        head[0x3c:0x40] = (4096).to_bytes(4, "little")
        self.assertEqual(validators.sniff(bytes(head)), "dos_mz")

    def test_a_verified_pe_is_still_accused(self):
        """The half of the behaviour that must not move."""
        state, detected, _ = validators.validate("x.mkv", PE)
        self.assertEqual((state, detected), (INVALID, "windows_pe"))

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

class TestPieceCoverage(unittest.TestCase):
    """Which pieces have to be verified before a header can be read.

    The promise: `covering` never returns fewer pieces than the range really
    occupies. Returning too many costs a retry; returning too few hands a
    structural parser a header that is half real bytes and half sparse padding.

    The layout numbers are from a real 460-file capture
    (`captures/multifile-capture-20260912-125601.json`, 16 MiB pieces): summing
    the preceding file sizes reproduced qBittorrent's own `piece_range` for all
    460 files, and the closest any file came to the end of its first piece was
    12177 bytes. That is the margin a 4096-byte header clears and a 16384-byte
    one does not, which is why the crossing case is not hypothetical.
    """

    MIB = 16 * 1024 * 1024

    def _torrent(self, *sizes):
        """A back-to-back file list with piece ranges qBittorrent would report."""
        out, offset = [], 0
        for i, size in enumerate(sizes):
            out.append({"name": f"f{i}.mkv", "size": size,
                        "piece_range": [offset // self.MIB,
                                        (offset + size - 1) // self.MIB]})
            offset += size
        return out

    def test_a_header_inside_the_first_piece_needs_only_that_piece(self):
        files = self._torrent(5 * self.MIB)
        self.assertEqual(pieces.covering(files, 0, 4096, self.MIB), [0])

    def test_a_header_crossing_a_boundary_needs_both_pieces(self):
        files = self._torrent(self.MIB - 100, 5 * self.MIB)
        self.assertEqual(pieces.covering(files, 1, 4096, self.MIB), [0, 1])

    def test_the_measured_worst_case_from_the_capture_stays_inside_one_piece(self):
        """12177 bytes of slack, the real nearest miss, with the real default.

        The second file begins 12177 bytes before the end of piece 0, so piece
        0 is its first piece and a 4096-byte header fits with room to spare.
        """
        files = self._torrent(self.MIB - 12177, 5 * self.MIB)
        self.assertEqual(files[1]["piece_range"][0], 0)
        self.assertEqual(pieces.covering(files, 1, 4096, self.MIB), [0])

    def test_the_same_file_crosses_once_the_header_budget_is_raised(self):
        """Same layout, `header_bytes` at 16384. The boundary problem is one
        config change away from real on a torrent we have actually seen."""
        files = self._torrent(self.MIB - 12177, 5 * self.MIB)
        self.assertEqual(pieces.covering(files, 1, 16384, self.MIB), [0, 1])

    def test_a_file_inside_a_single_piece_needs_no_arithmetic(self):
        files = [{"name": "a.mkv", "size": 900, "piece_range": [7, 7]}]
        self.assertEqual(pieces.covering(files, 0, 4096, self.MIB), [7])

    def test_the_range_never_extends_past_the_file_it_belongs_to(self):
        """A header budget larger than the file's own pieces must not demand
        pieces belonging to the next file. Those may be set to "do not
        download", in which case waiting for them would never end."""
        files = [{"name": "a.mkv", "size": None, "piece_range": [3, 4]}]
        self.assertEqual(pieces.covering(files, 0, 4096, 1024), [3, 4])

    def test_a_list_that_contradicts_its_first_piece_degrades_to_the_worst_case(self):
        """A hidden padding file makes the running offset wrong. Summing the
        preceding sizes puts this file in piece 1, qBittorrent says piece 0,
        and a derivation that disagrees with the authority is discarded rather
        than preferred."""
        files = [{"name": "a.mkv", "size": self.MIB, "piece_range": [0, 0]},
                 {"name": "b.mkv", "size": 5 * self.MIB, "piece_range": [0, 5]}]
        self.assertEqual(pieces.covering(files, 1, 4096, self.MIB), [0, 1])

    def test_a_list_that_contradicts_its_last_piece_degrades_to_the_worst_case(self):
        """The other half of the same check, and the reason both halves exist:
        here the derived *first* piece agrees and only the last disagrees, so
        checking one end would have accepted a layout that is wrong."""
        files = [{"name": "a.mkv", "size": self.MIB, "piece_range": [0, 0]},
                 {"name": "b.mkv", "size": 5 * self.MIB, "piece_range": [1, 99]}]
        self.assertEqual(pieces.covering(files, 1, 4096, self.MIB), [1, 2])

    def test_an_unreadable_size_earlier_in_the_list_degrades_the_same_way(self):
        files = self._torrent(self.MIB, 5 * self.MIB)
        files[0]["size"] = None
        self.assertEqual(pieces.covering(files, 1, 4096, self.MIB), [1, 2])

    def test_coverage_is_unknowable_without_a_piece_size(self):
        files = self._torrent(5 * self.MIB)
        for bad in (None, 0, "", -1, "sixteen"):
            with self.subTest(piece_size=bad):
                self.assertIsNone(pieces.covering(files, 0, 4096, bad))

    def test_coverage_is_unknowable_without_a_piece_range(self):
        for entry in ({"name": "a.mkv", "size": 900},
                      {"name": "a.mkv", "size": 900, "piece_range": []},
                      {"name": "a.mkv", "size": 900, "piece_range": [3]},
                      {"name": "a.mkv", "size": 900, "piece_range": [5, 2]},
                      {"name": "a.mkv", "size": 900, "piece_range": ["a", "b"]}):
            with self.subTest(entry=entry):
                self.assertIsNone(pieces.covering([entry], 0, 4096, self.MIB))

    def test_an_empty_file_has_no_header_to_cover(self):
        files = [{"name": "a.mkv", "size": 0, "piece_range": [0, 0]}]
        self.assertIsNone(pieces.covering(files, 0, 4096, self.MIB))

    def test_unknown_coverage_is_never_verified(self):
        """The single most important line in the module: None means no."""
        self.assertFalse(pieces.verified([2] * 10, None))
        self.assertFalse(pieces.verified([2] * 10, []))

    def test_every_needed_piece_must_be_verified_not_merely_requested(self):
        self.assertTrue(pieces.verified([2, 2, 0], [0, 1]))
        self.assertFalse(pieces.verified([2, 1, 2], [0, 1]))
        self.assertFalse(pieces.verified([2, 0, 2], [0, 1]))

    def test_a_piece_index_past_the_reported_states_is_not_verified(self):
        self.assertFalse(pieces.verified([2, 2], [1, 2]))
        self.assertFalse(pieces.verified([], [0]))

    def test_any_needed_piece_moving_off_zero_counts_as_scheduled(self):
        self.assertFalse(pieces.scheduled([0, 0], [0, 1]))
        self.assertTrue(pieces.scheduled([0, 1], [0, 1]))
        self.assertTrue(pieces.scheduled([2, 0], [0, 1]))
        self.assertFalse(pieces.scheduled([1, 1], None))


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
        # Small enough that the preflight never rejects the fixture; the tests
        # that care about the preflight set it themselves. It is also what
        # `probe.pieces` turns a header length into a set of pieces with, so it
        # has to agree with the file sizes and piece ranges in the fixture.
        self.props = {"piece_size": PIECE}

    def properties(self, h):
        return dict(self.props)

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


PIECE = 16384   # bytes; big enough that a default 4096-byte header fits inside


class ProbeCase(unittest.TestCase):
    """Shared fixture: a two-file torrent on a temp 'download directory'.

    The sizes and piece ranges are consistent with each other and with `PIECE`,
    which they were not before `probe.pieces` existed: file sizes of 900 and 800
    bytes spread across five pieces each describe a torrent that cannot exist.
    Nothing read them until coverage had to be worked out, and then they made
    every file look like it straddled a boundary.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        # A ledger declared broken stays broken for the life of the process,
        # which is right in production and poison across tests.
        ledger._broken = None
        self.content = os.path.join(self.dir, "Show.S01")
        os.makedirs(self.content, exist_ok=True)
        self.torrent = {"hash": "abc123", "name": "Show.S01",
                        "content_path": self.content, "state": "downloading",
                        "progress": 0.02, "dlspeed": 5 * 1024 * 1024,
                        "num_seeds": 12, "seq_dl": False, "f_l_piece_prio": False}
        # ep1 occupies pieces 0-5 and ep2 pieces 6-9, back to back, both
        # starting on a boundary. ep1 stays the larger of the two so the
        # biggest-first steering order is unchanged.
        self.files = [
            {"name": "ep1.mkv", "priority": 1, "size": 6 * PIECE,
             "piece_range": [0, 5]},
            {"name": "ep2.mkv", "priority": 1, "size": 4 * PIECE,
             "piece_range": [6, 9]},
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

    def test_an_unreadable_file_never_causes_steering(self):
        """Steering fetches a missing piece. When the piece is already
        downloaded and still cannot be read, the problem is the path mapping,
        and steering would switch off the user's files to learn the same
        nothing. The first version of this shipped doing exactly that, and a
        wrong mapping made it happen on every eligible torrent."""
        qb = FakeQb(self.files, [2] * 10, self.torrent)     # all downloaded
        res = self.probe(qb, cfg(poll_seconds=0))           # steering allowed
        self.assertEqual(res.findings, ())
        self.assertFalse(res.steered)
        self.assertEqual(qb.calls, [],
                         "nothing to fetch, so nothing should have been touched")

    def test_torrent_with_no_media_files_is_skipped_entirely(self):
        self.files = [{"name": "readme.txt", "priority": 1, "piece_range": [0, 1]}]
        qb = FakeQb(self.files, [2] * 10, self.torrent)
        self.assertEqual(self.probe(qb), engine.NOTHING)
        self.assertEqual(qb.polls, 0, "should not even ask for piece states")


class TestHeadersThatStraddleAPieceBoundary(ProbeCase):
    """A file rarely starts on a piece boundary, so its header rarely fits in
    one piece. Every piece the header touches must be verified before a byte of
    it is read.

    The bytes are written to disk in full in all of these, deliberately. The
    thing under test is the gate, not the filesystem: if the gate is what stops
    the read, then a real in-flight torrent - where those bytes would be sparse
    zeros - is safe too. Asserting on an absent file would pass even with the
    gate deleted.
    """

    def _straddling(self, payload):
        """ep1.mkv beginning 100 bytes before the end of piece 0, so a 4096-byte
        header runs into piece 1. The leading file is not a probe target."""
        self.files = [
            {"name": "art.jpg", "priority": 1, "size": PIECE - 100,
             "piece_range": [0, 0]},
            {"name": "ep1.mkv", "priority": 1, "size": 5 * PIECE,
             "piece_range": [0, 5]},
        ]
        write(self.content, "ep1.mkv", payload)
        return self.files

    def test_a_header_inside_one_verified_piece_is_read(self):
        write(self.content, "ep1.mkv", PE)
        qb = FakeQb(self.files, [2] + [0] * 9, self.torrent)
        res = self.probe(qb, cfg(steer=False))
        self.assertEqual([f["reason"] for f in res.findings],
                         ["content_type_mismatch"])
        self.assertEqual(pieces.covering(self.files, 0, 4096, PIECE), [0])

    def test_a_header_crossing_into_a_second_verified_piece_is_read(self):
        self._straddling(PE)
        qb = FakeQb(self.files, [2, 2] + [0] * 8, self.torrent)
        res = self.probe(qb, cfg(steer=False))
        self.assertEqual([f["reason"] for f in res.findings],
                         ["content_type_mismatch"])
        self.assertEqual(res.findings[0]["evidence"]["detected_type"],
                         "windows_pe")

    def test_the_second_piece_being_unavailable_stops_the_read(self):
        """The regression this module exists for. Piece 0 is verified and the
        old rule would have called that enough, read 4096 bytes, and judged a
        header whose tail was not downloaded."""
        self._straddling(PE)
        qb = FakeQb(self.files, [2] + [0] * 9, self.torrent)
        res = self.probe(qb, cfg(steer=False))
        self.assertEqual(res.findings, ())
        self.assertEqual(pieces.covering(self.files, 1, 4096, PIECE), [0, 1])

    def test_the_same_torrent_resolves_once_the_second_piece_arrives(self):
        """Proves the refusal above was about availability and nothing else:
        same bytes, same file, same call, one more verified piece."""
        self._straddling(PE)
        self.assertEqual(self.probe(FakeQb(self.files, [2] + [0] * 9,
                                           self.torrent),
                                    cfg(steer=False)).findings, ())
        res = self.probe(FakeQb(self.files, [2, 2] + [0] * 8, self.torrent),
                         cfg(steer=False))
        self.assertEqual(len(res.findings), 1)

    def test_a_pe_whose_signature_sits_in_the_next_piece_is_not_confirmed_early(self):
        """`e_lfanew` points 0x80 bytes in, and the file starts 100 bytes before
        the boundary, so the PE signature itself lives in piece 1. Reading only
        piece 1's worth of "MZ" would at best have produced the unconfirmed
        `dos_mz`, which is a quieter way to be wrong but still wrong."""
        self._straddling(PE)
        self.assertEqual(pieces.covering(self.files, 1, 4096, PIECE), [0, 1])
        self.assertGreater((PIECE - 100) + 0x80, PIECE,
                           "fixture must actually put the signature over the line")
        no_second = self.probe(FakeQb(self.files, [2] + [0] * 9, self.torrent),
                               cfg(steer=False))
        self.assertEqual(no_second.findings, ())
        both = self.probe(FakeQb(self.files, [2, 2] + [0] * 8, self.torrent),
                          cfg(steer=False))
        self.assertEqual(both.findings[0]["evidence"]["detected_type"],
                         "windows_pe")

    def test_a_missing_piece_size_stops_the_pass_rather_than_guessing(self):
        """Without it there is no way to turn a byte range into pieces, and an
        availability question we cannot answer is answered no.

        The piece states are never even fetched, which is the observable that
        separates "refused up front" from "carried on and found nothing"."""
        write(self.content, "ep1.mkv", PE)
        qb = FakeQb(self.files, [2] * 10, self.torrent)
        qb.props = {}
        res = self.probe(qb, cfg(steer=False))
        self.assertEqual(res.findings, ())
        self.assertEqual(qb.calls, [])
        self.assertEqual(qb.polls, 0, "should not ask for piece states either")

    def test_a_file_whose_coverage_cannot_be_worked_out_is_left_alone(self):
        """Coverage can be unknowable for one file while the torrent is fine:
        here qBittorrent reports a zero size against a real piece range. The
        file is skipped rather than falling back to its opening piece, which
        would be the old rule under a new name."""
        write(self.content, "ep1.mkv", PE)
        self.files[0]["size"] = 0
        qb = FakeQb(self.files, [2] * 10, self.torrent)
        res = self.probe(qb, cfg(steer=False))
        self.assertIsNone(pieces.covering(self.files, 0, 4096, PIECE))
        self.assertEqual(res.findings, ())

    def test_steering_waits_for_every_piece_the_header_touches(self):
        """Piece 0 arrives immediately, piece 1 only later. The old wait
        returned as soon as the first piece verified."""
        self._straddling(PE)
        qb = FakeQb(self.files, [0] * 10, self.torrent,
                    arrive_after={0: 1, 1: 4})
        res = self.probe(qb, cfg(poll_seconds=0, torrent_timeout_seconds=5))
        self.assertEqual(len(res.findings), 1)
        self.assertGreater(qb.polls, 4, "must have kept polling for piece 1")
        self.assertEqual(ledger.entries(), {}, "ledger must be closed")

    def test_steering_that_never_gets_the_second_piece_accuses_nobody(self):
        self._straddling(PE)
        qb = FakeQb(self.files, [0] * 10, self.torrent, arrive_after={0: 1})
        res = self.probe(qb, cfg(poll_seconds=0, torrent_timeout_seconds=1,
                                 stall_checks=99))
        self.assertEqual(res.findings, ())
        self.assertEqual([f["priority"] for f in qb.files_list], [1, 1])
        self.assertEqual(ledger.entries(), {})


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
            # Fail on the target boost, which is the mutation that steers. The
            # ledger is open by now and the flags are already toggled, so the
            # only thing that can put the torrent back is the `finally`.
            if priority == 7:
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


class TestWantedSetIsPreserved(ProbeCase):
    """Steering must not change what qBittorrent thinks the torrent is.

    Measured on a live 460-file torrent: switching the other files off makes
    qBittorrent recompute `size` and `progress` against the survivors, and the
    owning *arr believes it. One run read 90.95% complete, 15 seconds in. So
    every file that was wanted stays wanted, and only the *order* changes.
    """

    def _many(self, priorities):
        """A torrent of len(priorities) files, one piece each."""
        self.files = [{"name": f"ep{i}.mkv", "priority": p, "size": 900 - i,
                       "piece_range": [i, i]}
                      for i, p in enumerate(priorities)]
        return self.files

    def _conf(self, **kw):
        over = dict(poll_seconds=0, torrent_timeout_seconds=5)
        over.update(kw)
        return cfg(**over)

    def test_every_wanted_file_is_still_wanted_while_steering(self):
        self._many([1, 1, 1, 1])
        write(self.content, "ep0.mkv", PE)
        qb = FakeQb(self.files, [0] * 4, self.torrent, arrive_after={0: 1})

        seen = []
        original = qb.set_file_priority

        def watch(h, ids, priority):
            original(h, ids, priority)
            seen.append([f["priority"] for f in qb.files_list])

        qb.set_file_priority = watch
        self.probe(qb, self._conf())

        self.assertTrue(seen, "it never steered")
        for snapshot in seen:
            self.assertNotIn(0, snapshot,
                             "a wanted file was dropped from the wanted set")

    def test_the_target_is_the_only_file_raised(self):
        self._many([1, 1, 1, 1])
        write(self.content, "ep0.mkv", PE)
        qb = FakeQb(self.files, [0] * 4, self.torrent, arrive_after={0: 1})
        self.probe(qb, self._conf())
        boosts = [c for c in qb.calls if c[0] == "prio" and c[2] == 7]
        self.assertEqual(len(boosts), 1)
        self.assertEqual(boosts[0][1], [0], "the biggest file is ep0")

    def test_a_file_the_user_switched_off_is_left_off(self):
        """Priority 0 is the user's decision, and not ours to reverse."""
        self._many([0, 1])
        write(self.content, "ep0.mkv", PE)     # the fake is in the skipped file
        write(self.content, "ep1.mkv", PE)
        qb = FakeQb(self.files, [0] * 2, self.torrent, arrive_after={1: 1})
        self.probe(qb, self._conf())

        self.assertEqual(qb.files_list[0]["priority"], 0)
        for _, ids, prio in [c for c in qb.calls if c[0] == "prio"]:
            self.assertFalse(0 in ids and prio,
                             f"the skipped file was switched on ({prio})")

    def test_nothing_is_steered_when_every_candidate_is_switched_off(self):
        self._many([0, 0])
        write(self.content, "ep0.mkv", PE)
        qb = FakeQb(self.files, [0] * 2, self.torrent, arrive_after={0: 1})
        res = self.probe(qb, self._conf())
        self.assertEqual(qb.calls, [], "there was nothing worth steering for")
        self.assertEqual(res.findings, ())
        self.assertEqual(ledger.entries(), {}, "and no ledger entry was opened")

    def test_a_previous_target_is_put_back_to_normal_not_left_at_seven(self):
        """Two targets in one probe: the first must not stay boosted."""
        self._many([1, 1])
        write(self.content, "ep0.mkv", MKV)    # resolves, no finding
        write(self.content, "ep1.mkv", PE)
        # Piece 0 arrives so ep0 is judged; piece 1 arrives later so the probe
        # moves on to ep1.
        qb = FakeQb(self.files, [0] * 2, self.torrent,
                    arrive_after={0: 1, 1: 3})
        res = self.probe(qb, self._conf())

        self.assertEqual(len(res.findings), 1)
        boosted = [c for c in qb.calls if c[0] == "prio" and c[2] == 7]
        self.assertEqual([c[1] for c in boosted], [[0], [1]])
        demoted = [c for c in qb.calls if c[0] == "prio" and c[2] == 1
                   and c[1] == [0]]
        self.assertTrue(demoted, "ep0 was left at priority 7 while ep1 probed")

    def test_the_accounting_qbittorrent_reports_mid_steer_is_not_consulted(self):
        """qBittorrent lags on recompute, so those fields are poison here.

        `size`, `completed`, `amount_left` and `progress` still read pre-steer
        values in the same second as a priority change, and briefly again after
        the restore. Anything that branched on them during a steer would be
        reading a number the client has not caught up with yet, so nothing
        does. Poisoning them to look like a finished torrent must change
        nothing.
        """
        self._many([1, 1])
        write(self.content, "ep0.mkv", PE)
        qb = FakeQb(self.files, [0] * 2, self.torrent, arrive_after={0: 2})

        def lying(h):
            return dict(qb.info, progress=1.0, size=0, completed=0,
                        amount_left=0)

        qb.torrent = lying
        res = self.probe(qb, self._conf())
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]["evidence"]["source"], "steered")


class TestProbeGivesUpEarly(ProbeCase):
    """Sitting steered for the full budget while nothing happens is a cost."""

    def _conf(self, **kw):
        over = dict(poll_seconds=0, torrent_timeout_seconds=60,
                    no_progress_seconds=0)
        over.update(kw)
        return cfg(**over)

    def test_a_piece_qbittorrent_never_requests_aborts_and_restores(self):
        write(self.content, "ep1.mkv", PE)
        # arrive_after is empty, so every piece stays at state 0 forever.
        qb = FakeQb(self.files, [0] * 10, self.torrent)
        started = time.time()
        res = self.probe(qb, self._conf())

        self.assertEqual(res.findings, ())
        self.assertLess(time.time() - started, 5,
                        "it waited out the whole 60s budget")
        self.assertEqual([f["priority"] for f in qb.files_list], [1, 1])
        self.assertEqual(ledger.entries(), {})

    def test_a_requested_piece_is_given_the_full_budget(self):
        """State 1 means libtorrent has our piece in flight. That is progress."""
        write(self.content, "ep1.mkv", PE)
        states = [0] * 10
        states[0] = 1                       # requested, not yet verified
        qb = FakeQb(self.files, states, self.torrent, arrive_after={0: 4})
        res = self.probe(qb, self._conf())
        self.assertEqual(len(res.findings), 1)

    def test_a_piece_that_is_requested_then_dropped_still_counts(self):
        """Non-zero latches: re-requesting is not 'never scheduled'."""
        write(self.content, "ep1.mkv", PE)
        qb = FakeQb(self.files, [0] * 10, self.torrent, arrive_after={0: 6})

        original = qb.piece_states

        def flicker(h):
            # Poll 1 is the free pass. Polls 2-3 see the piece requested, 4-6
            # see it dropped again, and arrive_after verifies it at poll 7.
            states = original(h)
            if qb.polls in (2, 3):
                states[0] = 1
            elif qb.polls in (4, 5, 6):
                states[0] = 0
            return states

        qb.piece_states = flicker
        res = self.probe(qb, self._conf())
        self.assertEqual(len(res.findings), 1)


class TestPreflight(unittest.TestCase):
    """An optimistic lower bound. Failing it is meaningful; passing it is not."""

    def test_a_piece_that_cannot_arrive_in_time_is_refused(self):
        ok, why = engine.affordable(16 * 1024 ** 2, 330 * 1024, 20)
        self.assertFalse(ok)
        self.assertIn("50s", why)

    def test_a_piece_that_could_arrive_is_allowed(self):
        ok, _ = engine.affordable(16 * 1024 ** 2, 48 * 1024 ** 2, 120)
        self.assertTrue(ok)

    def test_a_missing_piece_size_does_not_block_the_probe(self):
        """No estimate is not the same as a bad estimate."""
        self.assertTrue(engine.affordable(None, 1024, 10)[0])
        self.assertTrue(engine.affordable(1024, 0, 10)[0])

    def test_the_bound_is_optimistic_and_says_so(self):
        """330 KiB/s took >300s in the live run. The check still passes it.

        Recorded deliberately: the preflight assumes the whole pipe goes to our
        piece, the measured share was 18.6% at speed and 0% throttled, and no
        fixed coefficient covers both. The runtime abort is what catches this
        case, not the preflight.
        """
        self.assertTrue(engine.affordable(16 * 1024 ** 2, 330 * 1024, 120)[0])


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

    def test_a_corrupt_ledger_is_quarantined_not_emptied(self):
        """The file is the only record of what the user's settings were. If it
        is unreadable we have lost that, and the honest response is to say so
        loudly and stop steering - not to start a fresh empty ledger, which
        looks exactly like "nothing was ever steered"."""
        path = os.path.join(self.dir, "probe.json")
        with open(path, "w") as fh:
            fh.write('{"version": 1, "open": {"abc123": {"priorities"')
        self.assertEqual(ledger.entries(), {})
        self.assertIsNotNone(ledger.broken())
        self.assertFalse(os.path.exists(path), "the corrupt file was left in place")
        kept = [f for f in os.listdir(self.dir) if f.startswith("probe.json.corrupt-")]
        self.assertEqual(len(kept), 1, "the evidence was not preserved")
        with open(os.path.join(self.dir, kept[0])) as fh:
            self.assertIn("abc123", fh.read(), "the quarantined copy was mangled")

    def test_a_broken_ledger_refuses_to_open_new_probes(self):
        with open(os.path.join(self.dir, "probe.json"), "w") as fh:
            fh.write("{not json")
        ledger.entries()                      # trips the detection
        self.assertFalse(ledger.open_probe("new", "X", {0: 1}, False, False))

    def test_a_second_probe_on_one_torrent_is_refused(self):
        """Overwriting would record the first probe's steered priorities as the
        originals, so the restore would faithfully switch the user's files off."""
        self.assertTrue(
            ledger.open_probe("abc123", "Show.S01", {0: 1, 1: 1}, False, False))
        self.assertFalse(
            ledger.open_probe("abc123", "Show.S01", {0: 0, 1: 7}, True, True))
        self.assertEqual(ledger.entries()["abc123"]["priorities"],
                         {"0": 1, "1": 1}, "the true originals were overwritten")

    def test_restore_verifies_the_torrent_level_flags_too(self):
        """set_sequential and set_first_last_prio were previously issued and
        never read back, so a closed entry could leave sequential download on."""
        ledger.open_probe("abc123", "Show.S01", {0: 1, 1: 1}, False, False)

        class Deaf(FakeQb):
            def set_sequential(self, h, on):
                self.calls.append(("seq", bool(on)))     # claims success, lies

        qb = Deaf(self.files, [0] * 10, self.torrent)
        qb.info["seq_dl"] = True
        self.assertFalse(ledger.restore(qb, "abc123"))
        self.assertIn("abc123", ledger.entries(), "closed on an unverified flag")

    def test_a_failed_restore_is_retried_later_not_every_pass(self):
        ledger.open_probe("abc123", "Show.S01", {0: 4, 1: 1}, False, False)
        qb = FakeQb(self.files, [0] * 10, self.torrent)
        qb.raise_on_priority = True
        self.assertFalse(ledger.restore(qb, "abc123"))
        # Backed off, so an immediate reconcile leaves it alone entirely.
        qb.calls.clear()
        self.assertEqual(ledger.reconcile(qb), 0)
        self.assertEqual(qb.calls, [], "hammered qBittorrent while backed off")
        # ... but it is still open, and comes back round once the backoff lapses.
        self.assertIn("abc123", ledger.entries())
        ledger._set_next_retry("abc123", 0)
        qb.raise_on_priority = False
        self.assertEqual(ledger.reconcile(qb), 1)

    def test_the_temp_file_is_not_left_behind_when_a_write_fails(self):
        ledger.open_probe("abc123", "Show.S01", {0: 1}, False, False)
        stray = [f for f in os.listdir(self.dir) if f.endswith(".tmp")]
        self.assertEqual(stray, [])

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


class TestPreviewIsObservational(unittest.TestCase):
    """Preview is reached from the WebUI and reads as a read-only question.

    It used to run the probe lane for real whenever `dry_run` was off, so on a
    production install the preview button steered live torrents. Steering does
    restore itself, so nothing broke, but a GET that toggles the user's
    sequential-download setting is not a preview.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        ledger._broken = None
        self.content = os.path.join(self.dir, "dl")
        os.makedirs(self.content, exist_ok=True)
        c = cfg(enabled=True, steer=True, min_speed_kib=0, min_seeds=0,
                poll_seconds=1, torrent_timeout_seconds=5, stall_checks=1)
        c["dry_run"] = False            # production: reaping is armed
        c["qbittorrent"] = {"url": "http://x"}
        c["arrs"] = []
        c["detection"].update(blocked_extensions=[".exe"],
                              blocked_name_keywords=[], only_active=True,
                              archive_detection={"enabled": False, "indexers": [],
                                                 "archive_extensions": []})
        c["safety"] = {"mode": "allowlist", "allowed_categories": ["tv"],
                       "allowed_tags": []}
        cfg_mod.save(c)
        self.torrent = {"hash": "t1", "name": "Season.Pack", "state": "downloading",
                        "category": "tv", "tags": "", "size": 10 ** 10,
                        "progress": 0.02, "dlspeed": 5 * 1024 * 1024,
                        "num_seeds": 30, "seq_dl": False, "f_l_piece_prio": False,
                        "content_path": os.path.join(self.content, "Season.Pack")}
        self.files = {"t1": [
            {"name": "E01.mkv", "priority": 1, "size": 10 ** 9, "piece_range": [0, 4]},
            {"name": "E02.mkv", "priority": 1, "size": 10 ** 9, "piece_range": [5, 9]}]}

    def service(self, qb):
        real_qb, real_build = core.QbitClient, core.build_clients
        core.QbitClient = lambda *a, **k: qb
        core.build_clients = lambda c: []
        self.addCleanup(lambda: setattr(core, "QbitClient", real_qb))
        self.addCleanup(lambda: setattr(core, "build_clients", real_build))
        return core.ProtectarrService()

    def test_preview_changes_nothing_in_qbittorrent(self):
        qb = ScanQb([self.torrent], self.files, [0] * 10)   # nothing downloaded
        svc = self.service(qb)
        svc.preview()
        self.assertEqual(qb.calls, [],
                         "preview mutated the torrent: %r" % (qb.calls,))

    def test_preview_opens_no_ledger_entry(self):
        qb = ScanQb([self.torrent], self.files, [0] * 10)
        self.service(qb).preview()
        self.assertEqual(ledger.entries(), {})

    def test_preview_still_reports_what_the_free_pass_can_see(self):
        """Observational must not mean blind. Bytes already on disk cost
        nothing to read, so a preview still has to surface those findings."""
        os.makedirs(self.torrent["content_path"], exist_ok=True)
        write(self.torrent["content_path"], "E01.mkv", PE)
        qb = ScanQb([self.torrent], self.files, [2] * 10)   # all downloaded
        out = self.service(qb).preview()
        self.assertTrue(out["observational"])
        self.assertEqual([r["hash"] for r in out["actions"]], ["t1"])
        self.assertEqual(qb.calls, [], "the free pass is not free")

    def test_a_real_scan_still_steers(self):
        """The guard is on preview, not on the feature."""
        qb = ScanQb([self.torrent], self.files, [0] * 10)
        real_qb, real_build = core.QbitClient, core.build_clients
        core.QbitClient = lambda *a, **k: qb
        core.build_clients = lambda c: []
        try:
            core.scan(cfg_mod.load(), {})
        finally:
            core.QbitClient, core.build_clients = real_qb, real_build
        self.assertTrue(qb.calls, "side effects were disabled everywhere")

    def test_preview_refuses_rather_than_running_a_second_scan(self):
        qb = ScanQb([self.torrent], self.files, [0] * 10)
        svc = self.service(qb)
        svc._scan_lock.acquire()            # stand in for the worker mid-pass
        try:
            with self.assertRaises(RuntimeError):
                svc.preview()
        finally:
            svc._scan_lock.release()

    def test_scan_now_reports_busy_rather_than_overlapping(self):
        qb = ScanQb([self.torrent], self.files, [0] * 10)
        svc = self.service(qb)
        svc._scan_lock.acquire()
        try:
            self.assertTrue(svc.scan_now().get("busy"))
        finally:
            svc._scan_lock.release()


class TestTrailingDotAndSpace(unittest.TestCase):
    """Windows drops trailing dots and spaces from a path, so `setup.exe ` runs
    as `setup.exe` while splitting as extension `.exe `."""

    DET = {"blocked_extensions": [".exe"], "blocked_name_keywords": []}
    CTX = {"arr_type": "sonarr", "arr_tracked": True, "resolve_indexer": lambda: None}

    def fires(self, name):
        from protectarr.detectors import extension
        return extension.detect([{"name": name}], self.DET, self.CTX)

    def test_trailing_space_no_longer_evades(self):
        self.assertTrue(self.fires("setup.exe "))

    def test_trailing_dot_no_longer_evades(self):
        self.assertTrue(self.fires("setup.exe."))

    def test_a_run_of_dots_and_spaces_no_longer_evades(self):
        self.assertTrue(self.fires("setup.exe...  "))

    def test_a_leading_space_is_left_alone(self):
        """rstrip, not strip: ` .hidden` is a different file from `hidden`."""
        from protectarr.detectors._util import detection_name
        self.assertEqual(detection_name(" .hidden"), " .hidden")

    def test_the_finding_reports_the_raw_name_not_the_stripped_one(self):
        """Canonicalisation is for matching. What gets logged, recorded and
        shown to the user has to be the name qBittorrent actually reported."""
        found = self.fires("setup.exe. ")
        self.assertEqual(found[0]["evidence"]["filename"], "setup.exe. ")

    def test_ordinary_media_is_unaffected(self):
        self.assertFalse(self.fires("Show.S01E01.1080p.mkv"))

    def test_zero_width_is_still_not_handled(self):
        """Deliberate. We have not confirmed libtorrent surfaces such a name,
        and a homoglyph deserves its own finding rather than being silently
        treated as though it were `.exe`."""
        self.assertFalse(self.fires("setup.e​xe"))


if __name__ == "__main__":
    unittest.main()
