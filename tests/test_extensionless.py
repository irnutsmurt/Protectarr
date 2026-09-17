"""Reconnaissance: what Protectarr does today with an extensionless payload.

Sonarr grabbed several releases whose primary file carries no extension at all,
for example `South Park S29E01 1080p WEB-DL DDP5 1 x265 FLUX`. They failed to
import because nothing downstream could tell what the bytes were.

Nothing in this file changes detection or remediation. Every test pins the
*current* answer, so that the byte-classifier work has an external record of
where the lane stands before anything moves. Several of these tests assert a
gap rather than a guarantee; each one says so in its name, so a future change
that closes the gap fails here deliberately rather than by accident.

The fixtures are the real thing wherever the format has a structure worth
having: the Matroska header is a parseable EBML header with a DocType, and the
MP4 is a well-formed `ftyp` box, because the agreed design replaces magic-byte
matching with structural validation and a fixture that is only four bytes long
could not tell the two approaches apart.

Run with:  venv/bin/python -m unittest tests.test_extensionless -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import logs  # noqa: E402
from protectarr.detectors import archives  # noqa: E402
from protectarr.probe import engine, ledger, paths, validators  # noqa: E402
from protectarr.probe.validators import UNKNOWN  # noqa: E402

logs.configure({"logging": {"level": "critical", "console_level": "critical",
                            "file_enabled": False}})


# ---------------------------------------------------------------------------
# Fixtures. Real headers, not approximations.
# ---------------------------------------------------------------------------

def _ebml_element(element_id, payload):
    """One EBML element with a single-byte VINT size.

    Every element here is well under 127 bytes, so the one-byte form (marker
    bit 0x80 or'd with the length) is the correct encoding rather than a
    shortcut.
    """
    assert len(payload) < 0x80
    return element_id + bytes([0x80 | len(payload)]) + payload


def _matroska_header():
    """A parseable EBML header declaring DocType `matroska`.

    Built rather than copied so the DocType is visibly the thing that makes it
    Matroska: an EBML header alone is also WebM, and is also every other EBML
    document in existence.
    """
    children = b"".join((
        _ebml_element(b"\x42\x86", b"\x01"),        # EBMLVersion 1
        _ebml_element(b"\x42\xf7", b"\x01"),        # EBMLReadVersion 1
        _ebml_element(b"\x42\xf2", b"\x04"),        # EBMLMaxIDLength 4
        _ebml_element(b"\x42\xf3", b"\x08"),        # EBMLMaxSizeLength 8
        _ebml_element(b"\x42\x82", b"matroska"),    # DocType
        _ebml_element(b"\x42\x87", b"\x04"),        # DocTypeVersion 4
        _ebml_element(b"\x42\x85", b"\x02"),        # DocTypeReadVersion 2
    ))
    header = _ebml_element(b"\x1a\x45\xdf\xa3", children)
    # The Segment that follows, with the unknown-size encoding a muxer writes
    # while it is still writing the file.
    return header + b"\x18\x53\x80\x67" + b"\x01\xff\xff\xff\xff\xff\xff\xff"


MKV = _matroska_header()

# A 24-byte ftyp box: size, type, major brand, minor version, two compatible
# brands. The leading size field is the reason `paths.read_head` checks the
# whole read for zeros rather than the first few bytes.
MP4 = (b"\x00\x00\x00\x18" + b"ftyp" + b"mp42"
       + b"\x00\x00\x00\x00" + b"mp42" + b"isom")

# MZ plus a DOS stub whose e_lfanew points at a real PE signature.
PE = (b"MZ" + b"\x90" * 0x3a + (0x80).to_bytes(4, "little")
      + b"\x00" * (0x80 - 0x40) + b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 60)

# MZ with nothing behind it. Not a program as far as anyone can prove, and the
# taxonomy's `ambiguous_format` case rather than a confirmed executable.
MZ_ONLY = b"MZ" + b"\x00\x01\x02\x03" * 16

# ELF64, little-endian, ET_EXEC, x86-64.
ELF = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
       + (2).to_bytes(2, "little") + (0x3e).to_bytes(2, "little")
       + (1).to_bytes(4, "little") + b"\x00" * 40)

# OLE2 compound file: .msi, .doc, and a great many droppers.
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8 + b"\x3e\x00\x03\x00"

ZIP = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 16
RAR = b"Rar!\x1a\x07\x00" + b"\xcf\x90\x73\x00\x00\x0d\x00" + b"\x00" * 16
SEVENZIP = b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 16

# Bytes that are nothing in particular. Deliberately non-zero throughout, so
# this exercises "read it and did not recognise it" and never accidentally
# exercises "could not read it".
RANDOM = bytes(((i * 37 + 11) % 251) + 1 for i in range(64))

# The tiny extensionless companion file that a candidate rule keyed on "no
# extension" would happily probe instead of the feature.
TINY_METADATA = b"tracker=udp://example.invalid:6969\n"

# The names that started this. Two shapes, and the difference matters.
SPACED = "South Park S29E01 1080p WEB-DL DDP5 1 x265 FLUX"
DOTTED = "South.Park.S29E01.1080p.WEB-DL.DDP5.1.x265-FLUX"


def cfg(**probe_over):
    p = dict(engine.DEFAULTS, enabled=True)
    p.update(probe_over)
    return {"detection": {"probe": p}, "dry_run": False,
            "safety": {"mode": "arr_tracked"}, "arrs": []}


class FakeQb:
    """Just enough qBittorrent for `inspect` to run. Records nothing, because
    none of these cases is supposed to reach a mutation."""

    def __init__(self, files, piece_states, torrent=None):
        self.files_list = files
        self.states = list(piece_states)
        self.info = torrent or {}
        self.props = {"piece_size": 1024}
        self.calls = []

    def properties(self, h):
        return dict(self.props)

    def piece_states(self, h):
        return list(self.states)

    def files(self, h):
        return self.files_list

    def torrent(self, h):
        return self.info

    def set_file_priority(self, h, ids, priority):
        self.calls.append(("prio", sorted(ids), priority))

    def set_sequential(self, h, on):
        self.calls.append(("seq", bool(on)))

    def set_first_last_prio(self, h, on):
        self.calls.append(("flp", bool(on)))


# ---------------------------------------------------------------------------
# What the sensor can already do
# ---------------------------------------------------------------------------

class TestSniffNeedsNoExtension(unittest.TestCase):
    """The byte classifier the design asks for is half-built already.

    `sniff` takes bytes and nothing else. Every format in the frozen taxonomy
    is separable from a header today, which is why the classifier is a
    refactor of this function rather than a new subsystem.
    """

    def test_every_taxonomy_format_is_separable_from_bytes_alone(self):
        for head, expected in ((MKV, "matroska"), (MP4, "iso_bmff"),
                               (PE, "windows_pe"), (ELF, "elf"),
                               (OLE, "ole_compound"), (ZIP, "zip"),
                               (RAR, "rar"), (SEVENZIP, "7z")):
            with self.subTest(expected=expected):
                self.assertEqual(validators.sniff(head), expected)

    def test_unrecognised_bytes_return_none_rather_than_a_guess(self):
        self.assertIsNone(validators.sniff(RANDOM))
        self.assertIsNone(validators.sniff(TINY_METADATA))

    def test_an_mz_with_no_pe_signature_is_downgraded_not_cleared(self):
        """Pins the structural check the lane performs on an MZ.

        `dos_mz` is the taxonomy's `ambiguous_format` in all but name, and it
        is currently inside `CONFIDENT`, which is what lets it accuse. That is
        the conflict the report names; this test records the starting point.
        """
        self.assertEqual(validators.sniff(MZ_ONLY), "dos_mz")
        self.assertIn("dos_mz", validators.CONFIDENT)


# ---------------------------------------------------------------------------
# ...and what the lane around it refuses to do with that
# ---------------------------------------------------------------------------

class TestTheValidatorRequiresAClaimedExtension(unittest.TestCase):
    """GAP. `validate` answers "does this match its claim?", so with no claim
    it cannot answer at all - including for bytes it just identified."""

    def test_no_extension_short_circuits_before_the_bytes_are_looked_at(self):
        for head in (MKV, MP4, PE, ELF, OLE, ZIP, RAR, SEVENZIP, RANDOM):
            with self.subTest(head=head[:8]):
                state, detected, note = validators.validate(SPACED, head, True)
                self.assertEqual(state, UNKNOWN)
                self.assertIsNone(detected)
                self.assertEqual(note, "no validator for a file with no extension")

    def test_a_confirmed_executable_is_discarded_for_want_of_an_extension(self):
        """The case that matters: the same PE bytes behind `.mkv` are a
        finding, and behind no extension are silence."""
        self.assertEqual(validators.validate("ep1.mkv", PE, True)[0], "invalid")
        self.assertEqual(validators.validate(SPACED, PE, True)[0], UNKNOWN)


class TestDottedSceneNamesAreNotExtensionless(unittest.TestCase):
    """GAP, and the one most likely to be designed around by accident.

    "Extensionless" is two different file shapes. A spaced release name splits
    to `""`; a dotted one splits to a spurious extension that is not in
    `EXPECTED` and never will be. A candidate rule keyed on `ext == ""` would
    pick up the first and silently miss the second.
    """

    def test_a_spaced_release_name_has_no_extension(self):
        self.assertEqual(validators.ext_of(SPACED), "")

    def test_a_dotted_release_name_yields_a_spurious_extension(self):
        self.assertEqual(validators.ext_of(DOTTED), ".x265-flux")
        self.assertEqual(
            validators.ext_of("Lioness.S03E08.1080p.WEB-DL.DDP5.1.H.265-NTb"),
            ".265-ntb")

    def test_both_shapes_are_equally_invisible_to_the_probe_lane(self):
        for name in (SPACED, DOTTED):
            with self.subTest(name=name):
                self.assertNotIn(validators.ext_of(name), validators.VALIDATABLE)

    def test_neither_shape_reaches_a_verdict_on_real_payload_bytes(self):
        for name in (SPACED, DOTTED):
            for head in (MKV, PE, OLE, ZIP):
                with self.subTest(name=name, head=head[:4]):
                    self.assertEqual(validators.validate(name, head, True)[0],
                                     UNKNOWN)


class TestTargetSelectionSkipsExtensionlessFiles(unittest.TestCase):
    """GAP. `targets` filters on the claimed extension, so an extensionless
    payload is never a probe target and its bytes are never read."""

    def test_an_extensionless_payload_is_not_a_target(self):
        files = [{"name": SPACED, "priority": 1, "size": 2_000_000_000,
                  "piece_range": [0, 900]}]
        self.assertEqual(engine.targets(files), [])

    def test_a_normal_media_file_beside_it_is_still_the_only_target(self):
        files = [
            {"name": SPACED, "priority": 1, "size": 2_000_000_000,
             "piece_range": [0, 900]},
            {"name": "ep1.mkv", "priority": 1, "size": 900, "piece_range": [901, 905]},
        ]
        self.assertEqual([i for i, _ in engine.targets(files)], [1])


class TestTargetSelectionHasNoSizeFloor(unittest.TestCase):
    """Answering "would extensionless handling need new candidate logic?": yes.

    Today tiny companion files are excluded by *extension* - `.nfo`, `.txt` and
    `.jpg` are simply not validatable - and never by size. Nothing in `targets`
    consults `size` at all, so a rule that admitted files by their lack of an
    extension would inherit no protection from that.
    """

    def test_a_twelve_byte_mp4_is_accepted_as_a_target(self):
        files = [{"name": "sample.mp4", "priority": 1, "size": 12,
                  "piece_range": [0, 0]}]
        self.assertEqual([i for i, _ in engine.targets(files)], [0])

    def test_tiny_companion_files_are_excluded_by_extension_not_by_size(self):
        files = [{"name": n, "priority": 1, "size": 40, "piece_range": [0, 0]}
                 for n in ("readme.nfo", "password.txt", "cover.jpg")]
        self.assertEqual(engine.targets(files), [])


class TestUnreadableIsAlreadyDistinctFromUnrecognised(unittest.TestCase):
    """A guarantee, not a gap: the taxonomy's `probe_data_unavailable` and
    `format_unrecognized` are already separate states carried on `Read.ready`.

    This is the distinction the whole lane is built on - "I could not read it"
    must never become evidence - so it is pinned here as the thing the
    classifier has to preserve rather than re-derive.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _read(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return paths.read_head(path, 4096)

    def test_bytes_that_were_read_and_not_recognised_are_ready(self):
        read = self._read("unknown.bin", RANDOM)
        self.assertTrue(read.ready)
        self.assertEqual(validators.sniff(read.data), None)

    def test_an_opening_range_that_is_not_downloaded_reads_back_unready(self):
        """A sparse file returns zeros rather than failing, which is why
        readiness is answered by the reader and not by the validator."""
        read = self._read("sparse.bin", b"\x00" * 4096)
        self.assertFalse(read.ready)
        self.assertIn("zeros", read.why)

    def test_a_file_that_is_not_there_yet_reads_back_unready(self):
        read = paths.read_head(os.path.join(self.dir, "absent.bin"), 4096)
        self.assertFalse(read.ready)
        self.assertFalse(read.data)

    def test_an_empty_file_is_unavailable_rather_than_unrecognised(self):
        read = self._read("empty.bin", b"")
        self.assertFalse(read.ready)
        self.assertIn("empty", read.why)

    def test_unready_data_cannot_produce_a_detected_type(self):
        for head in (b"", b"\x00" * 64):
            with self.subTest(head=head[:4]):
                state, detected, note = validators.validate("ep1.mkv", head, False)
                self.assertEqual(state, UNKNOWN)
                self.assertIsNone(detected)
                self.assertEqual(note, "no readable data yet")


class TestArchiveDetectorCannotAcceptByteEvidence(unittest.TestCase):
    """GAP. The archive detector re-derives everything from the file list.

    It takes `(files, det, ctx)` and reads extensions; there is no parameter
    through which a classification could arrive, and the probe lane builds its
    findings directly rather than through a detector. So "hand an extensionless
    ZIP to the existing archive logic" is not expressible today.
    """

    DET = {"archive_detection": {"enabled": True,
                                 "archive_extensions": [".rar", ".zip", ".7z"],
                                 "indexers": ["ExampleIndexer"]}}
    CTX = {"arr_type": "sonarr", "arr_tracked": True,
           "resolve_indexer": lambda: "ExampleIndexer"}

    def test_a_named_archive_fires(self):
        files = [{"name": "payload.zip", "size": 2_000_000_000}]
        found = archives.detect(files, self.DET, self.CTX)
        self.assertEqual([f["reason"] for f in found], ["archive_no_media"])

    def test_the_same_archive_bytes_without_a_name_find_nothing(self):
        files = [{"name": SPACED, "size": 2_000_000_000}]
        self.assertEqual(archives.detect(files, self.DET, self.CTX), [])

    def test_the_detector_signature_has_no_channel_for_evidence(self):
        """Named so the eventual fix has to change this line on purpose."""
        import inspect as _inspect
        self.assertEqual(
            list(_inspect.signature(archives.detect).parameters),
            ["files", "det", "ctx"])


class TestTheWholeTorrentIsANoOp(unittest.TestCase):
    """End to end: an extensionless torrent costs a candidate slot and returns
    nothing, without reading a byte or touching a single qBittorrent setting."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        ledger._broken = None
        self.content = os.path.join(self.dir, "South.Park.S29E01")
        os.makedirs(self.content, exist_ok=True)
        self.torrent = {"hash": "abc123", "name": "South.Park.S29E01",
                        "content_path": self.content, "state": "downloading",
                        "progress": 0.02, "dlspeed": 5 * 1024 * 1024,
                        "num_seeds": 12, "seq_dl": False, "f_l_piece_prio": False}

    def _write(self, name, data):
        with open(os.path.join(self.content, name), "wb") as fh:
            fh.write(data)

    def test_a_single_file_extensionless_executable_is_not_found(self):
        self._write(SPACED, PE)
        files = [{"name": SPACED, "priority": 1, "size": 2_000_000_000,
                  "piece_range": [0, 4]}]
        qb = FakeQb(files, [2] * 10, self.torrent)
        res = engine.inspect(qb, self.torrent, files, cfg(), {})
        self.assertEqual(res.findings, ())
        self.assertFalse(res.steered)
        self.assertEqual(qb.calls, [])

    def test_a_tiny_metadata_file_beside_the_payload_is_equally_unseen(self):
        """The multi-file shape a candidate rule has to survive: the small
        extensionless file sorts first alphabetically and is 35 bytes."""
        self._write("info", TINY_METADATA)
        self._write(SPACED, MKV)
        files = [
            {"name": "info", "priority": 1, "size": len(TINY_METADATA),
             "piece_range": [0, 0]},
            {"name": SPACED, "priority": 1, "size": 2_000_000_000,
             "piece_range": [0, 900]},
        ]
        qb = FakeQb(files, [2] * 901, self.torrent)
        res = engine.inspect(qb, self.torrent, files, cfg(), {})
        self.assertEqual(engine.targets(files), [])
        self.assertEqual(res.findings, ())
        self.assertEqual(qb.calls, [])

    def test_an_extensionless_payload_beside_real_media_probes_only_the_media(self):
        self._write("ep1.mkv", MKV)
        self._write(SPACED, PE)
        files = [
            {"name": "ep1.mkv", "priority": 1, "size": 900, "piece_range": [0, 4]},
            {"name": SPACED, "priority": 1, "size": 2_000_000_000,
             "piece_range": [5, 900]},
        ]
        qb = FakeQb(files, [2] * 901, self.torrent)
        res = engine.inspect(qb, self.torrent, files, cfg(), {})
        self.assertEqual(res.findings, ())
        self.assertEqual(qb.calls, [])

    def test_an_undownloaded_opening_range_still_reaches_no_target(self):
        """With a `.mkv` this torrent would become a steering candidate. With
        no extension there is nothing to steer at, so the budget is never even
        considered."""
        files = [{"name": SPACED, "priority": 1, "size": 2_000_000_000,
                  "piece_range": [0, 900]}]
        qb = FakeQb(files, [0] * 901, self.torrent)
        res = engine.inspect(qb, self.torrent, files, cfg(), {})
        self.assertEqual(res.findings, ())
        self.assertFalse(res.steered)
        self.assertEqual(qb.calls, [])


if __name__ == "__main__":
    unittest.main()
