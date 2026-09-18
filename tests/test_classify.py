"""What the byte classifier proves, and what it refuses to.

`validators.validate` needs a filename claim before it can answer anything.
`classify.classify` needs nothing but bytes, which is what lets the probe lane
say something about a file named
`South.Park.S29E01.1080p.WEB-DL.DDP5.1.x265-FLUX`.

Every fixture here is a real header built field by field rather than a magic
number and some padding, because the whole point of the rewrite is that magic
is a reason to look and never a verdict. A four-byte fixture could not tell the
two approaches apart.

The promises these tests hold, named because a failure should say which one
broke:

* a short read is never evidence, and a *complete* short file is never
  mistaken for a short read,
* a bound we chose is reported as our limit, not as the file's verdict,
* every parser reaches a decisive structural field before confirming,
* nothing here produces a finding. C1 is a sensor.

Run with:  venv/bin/python -m unittest tests.test_classify -v
"""

import os
import sys
import struct
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

from protectarr import logs  # noqa: E402
from protectarr.probe import classify, engine  # noqa: E402
from protectarr.probe.classify import (  # noqa: E402
    AMBIGUOUS, ARCHIVE_CONFIRMED, EXECUTABLE_CONFIRMED, MEDIA_CONFIRMED,
    OLE_CONFIRMED, UNAVAILABLE, UNRECOGNIZED)

logs.configure({"logging": {"level": "critical", "console_level": "critical",
                            "file_enabled": False}})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def ebml(element_id, payload):
    assert len(payload) < 0x80
    return element_id + bytes([0x80 | len(payload)]) + payload


def matroska(doctype=b"matroska"):
    children = b"".join((
        ebml(b"\x42\x86", b"\x01"),                 # EBMLVersion
        ebml(b"\x42\xf7", b"\x01"),                 # EBMLReadVersion
        ebml(b"\x42\xf2", b"\x04"),                 # EBMLMaxIDLength
        ebml(b"\x42\xf3", b"\x08"),                 # EBMLMaxSizeLength
        ebml(b"\x42\x82", doctype),                 # DocType - the decisive one
        ebml(b"\x42\x87", b"\x04"),                 # DocTypeVersion
    ))
    return ebml(b"\x1a\x45\xdf\xa3", children)


MKV = matroska()
WEBM = matroska(b"webm")
# A valid EBML header that is not a video at all. The magic is identical.
EBML_OTHER = matroska(b"dicom")

MP4 = (struct.pack(">I", 24) + b"ftyp" + b"isom" + struct.pack(">I", 512)
       + b"isom" + b"mp41")
# ftyp behind a free box, which ISO 14496-12 allows and real muxers emit.
MP4_BEHIND_FREE = struct.pack(">I", 32) + b"free" + b"\x00" * 24 + MP4

AVI = b"RIFF" + struct.pack("<I", 0) + b"AVI " + b"LIST" + b"\x00" * 16
WAV = b"RIFF" + struct.pack("<I", 0) + b"WAVE" + b"fmt " + b"\x00" * 16
FLAC = b"fLaC" + b"\x00\x00\x00\x22" + bytes(range(34))


def pe(e_lfanew=0x80, machine=0x8664, optional=0x20b):
    dos = bytearray(b"MZ" + b"\x90" * (max(e_lfanew, 0x40) - 2))
    dos[0x3c:0x40] = struct.pack("<I", e_lfanew)
    coff = (b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 3, 0, 0, 0, 240,
                                        0x22) + struct.pack("<H", optional))
    return bytes(dos) + coff


PE = pe()
# The bounded case: the pointer is a 32-bit field the file chooses, and this
# one leads past anything we are willing to read.
PE_BEYOND_BOUND = pe(0x8000)[:classify.CLASSIFY_BYTES]
# Two bytes of "MZ" and nothing that follows them is a program.
MZ_ONLY = b"MZ" + bytes((i * 7 + 3) % 251 + 1 for i in range(200))

ELF = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
       + struct.pack("<HHI", 2, 0x3e, 1) + b"\x00" * 40)
MACHO = struct.pack("<IiiIIII", 0xfeedfacf, 0x01000007, 3, 2, 16, 1000, 0)
MACHO_FAT = (struct.pack(">II", 0xcafebabe, 2)
             + struct.pack(">iiIII", 0x01000007, 3, 0x4000, 1000, 12))
# Same four bytes, read as a Java class file: minor 0, major 61 (Java 17).
JAVA_CLASS = struct.pack(">IHH", 0xcafebabe, 0, 61) + b"\x00" * 32


def ole():
    head = bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504)
    head[0x18:0x1a] = struct.pack("<H", 0x003e)
    head[0x1a:0x1c] = struct.pack("<H", 0x0003)     # major version
    head[0x1c:0x1e] = b"\xfe\xff"                   # byte-order mark
    head[0x1e:0x20] = struct.pack("<H", 9)          # sector shift
    return bytes(head)


OLE = ole()
ZIP = (b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 8, 0, 0, 0, 0, 0, 8, 0)
       + b"file.txt")
RAR4 = b"Rar!\x1a\x07\x00" + b"\xcf\x90\x73\x00\x00\x0d\x00" + b"\x00" * 6
RAR5 = b"Rar!\x1a\x07\x01\x00" + b"\x00\x00\x00\x00" + b"\x0b\x01\x05" + b"\x00" * 8
SEVENZIP = (b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + b"\x00" * 4
            + struct.pack("<QQI", 0, 0, 0))

# Bytes that are nothing. Non-zero throughout, so this exercises "read it and
# did not recognise it" and never "could not read it".
RANDOM = bytes(((i * 37 + 11) % 251) + 1 for i in range(512))
# A complete file shorter than most parsers' minimums. Twenty bytes, and all
# twenty of them are here.
TINY = b"tracker=udp://x\n\x01\x02\x03\x04"

SPACED = "South Park S29E01 1080p WEB-DL DDP5 1 x265 FLUX"
DOTTED = "South.Park.S29E01.1080p.WEB-DL.DDP5.1.x265-FLUX"


def verdict(head, **kw):
    kw.setdefault("file_size", len(head))
    kw.setdefault("requested", len(head))
    return classify.classify(head, **kw)


# ---------------------------------------------------------------------------
# The fixtures the brief names, one table
# ---------------------------------------------------------------------------

class TestEveryFixtureClassifies(unittest.TestCase):
    """The headline table: what each fixture proves about itself."""

    CASES = [
        ("a literally extensionless Matroska", MKV, MEDIA_CONFIRMED, "matroska"),
        ("a WebM, which shares Matroska's magic", WEBM, MEDIA_CONFIRMED, "webm"),
        ("a valid MP4", MP4, MEDIA_CONFIRMED, "iso_bmff"),
        ("an MP4 whose ftyp sits behind a free box", MP4_BEHIND_FREE,
         MEDIA_CONFIRMED, "iso_bmff"),
        ("an AVI", AVI, MEDIA_CONFIRMED, "avi"),
        ("a WAV", WAV, MEDIA_CONFIRMED, "wav"),
        ("a FLAC", FLAC, MEDIA_CONFIRMED, "flac"),
        ("a verified PE", PE, EXECUTABLE_CONFIRMED, "windows_pe"),
        ("an ELF", ELF, EXECUTABLE_CONFIRMED, "elf"),
        ("a thin Mach-O", MACHO, EXECUTABLE_CONFIRMED, "mach_o"),
        ("a universal Mach-O", MACHO_FAT, EXECUTABLE_CONFIRMED, "mach_o"),
        ("an OLE compound file", OLE, OLE_CONFIRMED, "ole_compound"),
        ("a ZIP", ZIP, ARCHIVE_CONFIRMED, "zip"),
        ("a RAR4", RAR4, ARCHIVE_CONFIRMED, "rar"),
        ("a RAR5", RAR5, ARCHIVE_CONFIRMED, "rar"),
        ("a 7-Zip archive", SEVENZIP, ARCHIVE_CONFIRMED, "7z"),
        # Magic matched, structure did not. Nothing was proved, so nothing is
        # named: the evidence is `format_unrecognized` and the prefix survives
        # only as a hint. See TestARecognisedPrefixIsNotAnInterpretation.
        ("a bare MZ with no reachable PE signature", MZ_ONLY, UNRECOGNIZED,
         None),
        ("a PE pointer past the bounded span", PE_BEYOND_BOUND, UNRECOGNIZED,
         None),
        ("an EBML document that is not Matroska", EBML_OTHER, UNRECOGNIZED,
         None),
        ("a Java class file wearing the fat Mach-O magic", JAVA_CLASS,
         UNRECOGNIZED, None),
        # Nothing matched at all.
        ("random bytes", RANDOM, UNRECOGNIZED, None),
        ("a complete tiny file shorter than most minimums", TINY, UNRECOGNIZED,
         None),
    ]

    def test_every_fixture(self):
        for title, head, evidence, fmt in self.CASES:
            with self.subTest(title):
                v = verdict(head)
                self.assertEqual(v.evidence, evidence, title)
                self.assertEqual(v.format, fmt, title)

    def test_a_format_is_only_ever_set_by_a_confirmation(self):
        """The invariant that stops a hint being read as a format downstream:
        `format` is what was proved, and nothing else may fill it in."""
        for title, head, evidence, _ in self.CASES:
            with self.subTest(title):
                v = verdict(head)
                if v.format is not None:
                    self.assertIn(v.evidence, classify.CONFIRMED, title)

    def test_no_fixture_here_is_ambiguous(self):
        """None of these bytes validate as two things, so none of them may
        claim the state that means they did."""
        for title, head, _, _ in self.CASES:
            with self.subTest(title):
                self.assertNotEqual(verdict(head).evidence, AMBIGUOUS, title)

    def test_no_fixture_produces_an_evidence_class_outside_the_taxonomy(self):
        for title, head, _, _ in self.CASES:
            with self.subTest(title):
                self.assertIn(verdict(head).evidence, classify.EVIDENCE)

    def test_the_filename_never_enters_into_it(self):
        """The premise of the whole module: bytes only.

        `classify` takes no filename, so the same payload answers identically
        whichever of the two extensionless shapes is wrapped around it.
        """
        import inspect
        self.assertNotIn("filename", inspect.signature(classify.classify)
                         .parameters)


# ---------------------------------------------------------------------------
# Availability is not length
# ---------------------------------------------------------------------------

class TestAShortReadIsNeverEvidence(unittest.TestCase):
    """The correction that shaped this module.

    `probe_data_unavailable` describes availability. Bytes that should exist
    and are not readable are unavailable and worth retrying; a file that is
    *complete* at twenty bytes has every byte it will ever have, so the parsers
    that fit run and the answer is terminal.
    """

    def test_unready_bytes_are_unavailable_and_retryable(self):
        v = classify.classify(MKV, ready=False, file_size=len(MKV),
                              requested=len(MKV))
        self.assertEqual(v.evidence, UNAVAILABLE)
        self.assertTrue(v.retryable)
        self.assertIsNone(v.format)

    def test_no_bytes_at_all_are_unavailable_and_retryable(self):
        v = classify.classify(b"", ready=True, file_size=1 << 30, requested=4096)
        self.assertEqual(v.evidence, UNAVAILABLE)
        self.assertTrue(v.retryable)

    def test_a_big_file_that_read_short_is_unavailable_and_retryable(self):
        """Case A: 2 GiB file, 4096 bytes asked for, 100 arrived. Those bytes
        exist somewhere and are simply not here yet."""
        v = classify.classify(PE[:100], ready=True, file_size=2 << 30,
                              requested=4096)
        self.assertEqual(v.evidence, UNAVAILABLE)
        self.assertTrue(v.retryable)
        self.assertIn("100", v.note)

    def test_a_complete_tiny_file_is_terminal_not_unavailable(self):
        """Case B: the whole file is 20 bytes and all 20 are here. Retrying it
        forever would be the same mistake in the opposite direction."""
        v = classify.classify(TINY, ready=True, file_size=len(TINY),
                              requested=4096)
        self.assertEqual(v.evidence, UNRECOGNIZED)
        self.assertFalse(v.retryable)

    def test_a_complete_tiny_file_still_gets_the_parsers_that_fit(self):
        """Shorter than most minimums is not shorter than all of them: a
        complete 12-byte AVI is an AVI."""
        head = AVI[:12]
        v = classify.classify(head, ready=True, file_size=12, requested=4096)
        self.assertEqual(v.evidence, MEDIA_CONFIRMED)
        self.assertEqual(v.format, "avi")
        self.assertFalse(v.retryable)

    def test_an_unknown_size_cannot_excuse_a_short_read(self):
        """With no size to compare against, a read shorter than the request is
        treated as unavailable. Uncertainty fails safe."""
        v = classify.classify(PE[:100], ready=True, file_size=None,
                              requested=4096)
        self.assertEqual(v.evidence, UNAVAILABLE)
        self.assertTrue(v.retryable)

    def test_only_unavailable_is_ever_retryable(self):
        for title, head, evidence, _ in TestEveryFixtureClassifies.CASES:
            with self.subTest(title):
                self.assertFalse(verdict(head).retryable)


class TestABoundWeChoseIsNotTheFilesVerdict(unittest.TestCase):
    """Case C. We read every byte we asked for, so nothing is unavailable, and
    nothing validated, so nothing is ambiguous either. It is unrecognised, and
    the note says whose limit ran out."""

    def test_a_pe_pointer_past_the_span_is_unrecognised_not_unavailable(self):
        v = verdict(PE_BEYOND_BOUND)
        self.assertEqual(v.evidence, UNRECOGNIZED)
        self.assertFalse(v.retryable)

    def test_it_is_not_ambiguous_because_nothing_validated(self):
        self.assertNotEqual(verdict(PE_BEYOND_BOUND).evidence, AMBIGUOUS)

    def test_the_hint_still_records_that_an_mz_was_seen(self):
        self.assertEqual(verdict(PE_BEYOND_BOUND).hint, "dos_mz")

    def test_the_note_says_it_was_our_span_that_ran_out(self):
        self.assertIn(str(classify.CLASSIFY_BYTES), verdict(PE_BEYOND_BOUND).note)

    def test_the_same_bytes_with_a_reachable_pointer_do_confirm(self):
        """Proves the previous tests are about the bound and not about the
        fixture being malformed."""
        self.assertEqual(verdict(pe(0x400)).evidence, EXECUTABLE_CONFIRMED)

    def test_an_iso_bmff_walk_that_runs_out_of_bytes_is_unrecognised(self):
        head = struct.pack(">I", 1 << 20) + b"free" + b"\x00" * 100
        v = verdict(head)
        self.assertEqual(v.evidence, UNRECOGNIZED)
        self.assertIsNone(v.format)
        self.assertEqual(v.hint, "iso_bmff")


class TestARecognisedPrefixIsNotAnInterpretation(unittest.TestCase):
    """The taxonomy correction, stated as tests.

    A prefix that fails structural confirmation proved nothing. It is
    `format_unrecognized` - never `ambiguous_format`, which is reserved for
    bytes that really did validate as more than one thing, and never
    `probe_data_unavailable`, which is about availability.

    What the operator still needs is the difference between "I saw an MZ and
    could not prove a PE" and "these bytes are nothing at all", so that is kept
    in `hint` and in the note, where neither can be acted on.
    """

    CASES = [
        ("a bare MZ", MZ_ONLY, "dos_mz", "MZ"),
        ("a PE pointer past our span", PE_BEYOND_BOUND, "dos_mz", "MZ"),
        ("an EBML document that is not Matroska", EBML_OTHER, "ebml", "EBML"),
        ("a Java class file", JAVA_CLASS, "cafebabe", "Java"),
    ]

    def test_each_is_unrecognised_with_a_hint(self):
        for title, head, hint, _ in self.CASES:
            with self.subTest(title):
                v = verdict(head)
                self.assertEqual(v.evidence, UNRECOGNIZED, title)
                self.assertIsNone(v.format, title)
                self.assertEqual(v.hint, hint, title)
                self.assertFalse(v.retryable, title)

    def test_none_of_them_is_ambiguous_or_unavailable(self):
        for title, head, _, _ in self.CASES:
            with self.subTest(title):
                self.assertNotIn(verdict(head).evidence,
                                 (AMBIGUOUS, UNAVAILABLE), title)

    def test_the_note_still_says_what_was_seen(self):
        """The distinction the operator needs, kept out of the evidence."""
        for title, head, _, word in self.CASES:
            with self.subTest(title):
                self.assertIn(word, verdict(head).note, title)

    def test_random_bytes_are_unrecognised_with_no_hint_at_all(self):
        """The other side of the same distinction: nothing was glimpsed."""
        v = verdict(RANDOM)
        self.assertEqual(v.evidence, UNRECOGNIZED)
        self.assertIsNone(v.hint)

    def test_a_hinted_answer_is_distinguishable_from_a_bare_one(self):
        """Named because this is the whole reason `hint` exists: collapsing
        these two would lose what the taxonomy correction asked us to keep."""
        self.assertNotEqual(verdict(MZ_ONLY).hint, verdict(RANDOM).hint)
        self.assertNotEqual(verdict(MZ_ONLY).note, verdict(RANDOM).note)


# ---------------------------------------------------------------------------
# Magic is a reason to look, not a verdict
# ---------------------------------------------------------------------------

class TestEveryParserReachesAStructuralField(unittest.TestCase):
    """Each parser is given its own magic followed by bytes that do not parse.

    None of them may confirm. This is the mutation-resistant form of "no
    parser returns on magic alone": it fails if any single parser is reduced to
    a prefix check.
    """

    CASES = [
        ("matroska", b"\x1a\x45\xdf\xa3" + b"\xff" * 60),
        ("iso_bmff", struct.pack(">I", 24) + b"ftyp" + b"\x00\x01\x02\x03"
         + b"\x00" * 12),
        ("riff", b"RIFF" + struct.pack("<I", 0) + b"NOPE" + b"\x00" * 16),
        ("flac", b"fLaC" + b"\x05\x00\x00\x10" + b"\x00" * 40),
        ("windows_pe", MZ_ONLY),
        ("elf", b"\x7fELF" + b"\x09\x09\x09\x00" + b"\x00" * 40),
        ("mach_o", struct.pack("<IiiIIII", 0xfeedfacf, 1, 3, 999, 16, 1000, 0)),
        ("ole_compound", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 200),
        ("zip", b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 777, 0, 0, 0,
                                            0, 0, 8, 0) + b"file.txt"),
        ("rar", b"Rar!\x1a\x07\x00" + b"\x00" * 40),
        ("7z", b"7z\xbc\xaf\x27\x1c" + b"\xff\xff" + b"\x00" * 40),
    ]

    def test_magic_alone_never_confirms(self):
        for fmt, head in self.CASES:
            with self.subTest(fmt):
                v = verdict(head)
                self.assertNotIn(v.evidence, classify.CONFIRMED,
                                 f"{fmt} confirmed on magic alone: {v.note}")
                self.assertEqual(v.evidence, UNRECOGNIZED)
                self.assertIsNotNone(v.hint, f"{fmt} lost its prefix hint")

    def test_every_parser_in_the_table_is_exercised_by_a_case(self):
        """A hole in this table would be a parser nobody proved reads a field.

        Named because the table above is the whole guarantee: a format missing
        from it is untested in exactly the way that matters.
        """
        covered = {fmt for fmt, _ in self.CASES}
        self.assertEqual(covered, {name for name, _, _ in classify.MINIMUMS})


def elf(ei_class=2, ei_data=1, ei_version=1, e_type=2, e_machine=0x3e,
        e_version=1):
    return (b"\x7fELF" + bytes([ei_class, ei_data, ei_version]) + b"\x00" * 9
            + struct.pack("<HHI", e_type, e_machine, e_version) + b"\x00" * 40)


def ole_with(bom=b"\xfe\xff", major=3, sector_shift=9):
    head = bytearray(OLE)
    head[0x1a:0x1c] = struct.pack("<H", major)
    head[0x1c:0x1e] = bom
    head[0x1e:0x20] = struct.pack("<H", sector_shift)
    return bytes(head)


class TestEachStructuralCheckIsLoadBearingOnItsOwn(unittest.TestCase):
    """One fixture per check, rejected by that check and nothing else.

    `TestEveryParserReachesAStructuralField` proves the verdict is right; it
    cannot prove *which* check produced it, because these parsers guard the
    same fixture several times over. A mutation run showed that: nine checks
    could be deleted one at a time with every test still green, because a
    sibling check caught the same malformed fixture.

    So each case here is built to satisfy every check in its parser except one.
    Delete that check and this fixture confirms - which is the failure the
    table above could not see.
    """

    # A DOS header and optional header that are entirely in order, with only
    # the four signature bytes wrong. Nothing else in the parser objects.
    PE_NO_SIGNATURE = (pe()[:0x80] + b"XX\x00\x00"
                       + pe()[0x84:])
    # `PE\0\0` at offset 4, inside the DOS header it would have to overlap,
    # with `e_lfanew` genuinely set to 4. This is the self-confirming crafted
    # file the offset floor exists for: every other check in the parser is
    # satisfied, so only the floor can refuse it.
    PE_POINTER_INTO_DOS = bytearray(b"MZ" + b"\x90" * 0x3e)
    PE_POINTER_INTO_DOS[4:8] = b"PE\x00\x00"
    PE_POINTER_INTO_DOS[8:28] = struct.pack("<HHIIIHH", 0x8664, 3, 0, 0, 0,
                                            240, 0x22)
    PE_POINTER_INTO_DOS[28:30] = struct.pack("<H", 0x20b)
    PE_POINTER_INTO_DOS[0x3c:0x40] = struct.pack("<I", 4)
    PE_POINTER_INTO_DOS = bytes(PE_POINTER_INTO_DOS)
    # A PE object file: real signature, real machine, no optional header.
    PE_NO_OPTIONAL = pe(optional=0)

    CASES = [
        ("pe: no PE signature where the pointer leads", PE_NO_SIGNATURE),
        ("pe: pointer into its own DOS header", PE_POINTER_INTO_DOS),
        ("pe: a signature with no optional header", PE_NO_OPTIONAL),
        ("elf: a bad identification header", elf(ei_class=9)),
        ("elf: a good ident and a zero machine", elf(e_machine=0)),
        ("ole: no byte-order mark", ole_with(bom=b"\x00\x00")),
        ("ole: a sector size nothing writes", ole_with(sector_shift=7)),
        # HEAD_SIZE stays a legal 13, so only the block type is wrong.
        ("rar4: a first block that is not the main header",
         b"Rar!\x1a\x07\x00" + b"\xcf\x90\x21\x00\x00\x0d\x00" + b"\x00" * 6),
        # Readable vints throughout; the type is a file header, not an archive
        # header, so a RAR volume cannot confirm off its signature.
        ("rar5: a first block that is not the archive header",
         b"Rar!\x1a\x07\x01\x00" + b"\x00\x00\x00\x00" + b"\x0b\x02\x05"
         + b"\x00" * 8),
    ]

    def test_each_case_is_refused_by_its_own_check(self):
        for title, head in self.CASES:
            with self.subTest(title):
                v = verdict(head)
                self.assertNotIn(v.evidence, classify.CONFIRMED,
                                 f"{title}: confirmed as {v.format} - "
                                 f"{v.note}")

    def test_each_case_differs_from_a_confirming_one_by_that_field_alone(self):
        """Proves the fixtures above are minimal rather than merely broken.

        Every one of them is a small edit away from a header that does confirm,
        so a failure in the test above is about the check being removed and not
        about the fixture being malformed in some other way.
        """
        for title, good in (("pe", pe()), ("elf", elf()), ("ole", ole_with()),
                            ("rar4", RAR4), ("rar5", RAR5)):
            with self.subTest(title):
                self.assertIn(verdict(good).evidence, classify.CONFIRMED)


class TestTheMeasuredMinimumsHold(unittest.TestCase):
    """`CLASSIFY_BYTES` is only defensible while it exceeds every minimum.

    The minimums are the measured byte spans; this checks the constant against
    them rather than against a remembered number.
    """

    FIXTURES = {
        "matroska": MKV, "iso_bmff": MP4, "riff": AVI, "flac": FLAC,
        "windows_pe": pe(0x400), "elf": ELF, "mach_o": MACHO_FAT,
        "ole_compound": OLE, "zip": ZIP, "rar": RAR4, "7z": SEVENZIP,
    }

    def test_the_classify_span_covers_every_parser(self):
        worst = max(n for _, _, n in classify.MINIMUMS)
        self.assertGreaterEqual(classify.CLASSIFY_BYTES, worst)

    def test_each_parser_confirms_at_its_stated_minimum(self):
        for name, _, minimum in classify.MINIMUMS:
            head = self.FIXTURES[name]
            with self.subTest(name):
                v = classify.classify(head[:minimum], ready=True,
                                      file_size=minimum, requested=minimum)
                self.assertIn(v.evidence, classify.CONFIRMED,
                              f"{name} needs more than its stated {minimum}")

    def test_a_byte_short_of_the_minimum_does_not_confirm(self):
        """The minimum is a measurement, so it has to be tight in both
        directions. A parser that confirms a byte earlier has a minimum that is
        written down wrong."""
        for name, _, minimum in classify.MINIMUMS:
            head = self.FIXTURES[name][:minimum - 1]
            with self.subTest(name):
                v = classify.classify(head, ready=True, file_size=len(head),
                                      requested=len(head))
                self.assertNotIn(v.evidence, classify.CONFIRMED,
                                 f"{name} confirmed on {len(head)} bytes, so "
                                 f"its minimum of {minimum} is overstated")


class TestAmbiguityIsReportedRatherThanResolved(unittest.TestCase):
    """Two parsers that both match must not be settled by listing order.

    No offset-0 polyglot exists across this parser set: every magic is anchored
    at byte 0 and no two of them are prefixes of each other, which is itself
    worth pinning. So the resolution rule is exercised directly rather than
    through a fixture that would have to be dishonest to construct.
    """

    def test_no_two_parsers_can_match_the_same_fixture_today(self):
        for title, head, _, _ in TestEveryFixtureClassifies.CASES:
            with self.subTest(title):
                hits = [p for p in classify.PARSERS if p(head) is not None]
                self.assertLessEqual(len(hits), 1, title)

    def test_two_confirmations_are_ambiguous_whatever_they_say(self):
        m = classify._resolve([
            classify.Match(MEDIA_CONFIRMED, "matroska", "a video"),
            classify.Match(EXECUTABLE_CONFIRMED, "windows_pe", "a program"),
        ])
        self.assertEqual(m.evidence, AMBIGUOUS)
        self.assertIn("matroska", m.format)
        self.assertIn("windows_pe", m.format)

    def test_confirmations_that_agree_on_a_kind_are_still_ambiguous(self):
        """"Definitely media, but we cannot say which container" is a question
        we failed to answer, not an answer. A lane that deletes does not get to
        round that up."""
        m = classify._resolve([
            classify.Match(MEDIA_CONFIRMED, "matroska", "a video"),
            classify.Match(MEDIA_CONFIRMED, "iso_bmff", "also a video"),
        ])
        self.assertEqual(m.evidence, AMBIGUOUS)

    def test_a_failed_prefix_is_not_an_interpretation_to_be_ambiguous_with(self):
        """The correction in one test. A confirmation standing beside a prefix
        that proved nothing is still just that confirmation - one thing
        validated, so there is nothing to be ambiguous between."""
        m = classify._resolve([
            classify.Match(MEDIA_CONFIRMED, "matroska", "a video"),
            classify.Match(UNRECOGNIZED, None, "opens like a program", "dos_mz"),
        ])
        self.assertEqual(m.evidence, MEDIA_CONFIRMED)
        self.assertEqual(m.format, "matroska")

    def test_several_failed_prefixes_stay_unrecognised(self):
        """No amount of not-proving-it adds up to ambiguity."""
        m = classify._resolve([
            classify.Match(UNRECOGNIZED, None, "opens like a program", "dos_mz"),
            classify.Match(UNRECOGNIZED, None, "an EBML document", "ebml"),
        ])
        self.assertEqual(m.evidence, UNRECOGNIZED)
        self.assertIsNone(m.format)
        self.assertIn("dos_mz", m.hint)
        self.assertIn("ebml", m.hint)

    def test_a_single_failed_prefix_keeps_its_own_parsers_sentence(self):
        m = classify._resolve([
            classify.Match(UNRECOGNIZED, None, "opens like a program", "dos_mz"),
        ])
        self.assertEqual(m.note, "opens like a program")
        self.assertEqual(m.hint, "dos_mz")

    def test_the_sweep_runs_every_parser_rather_than_stopping_at_the_first(self):
        """Named so that an optimisation which returns early has to change this
        line on purpose."""
        seen = []

        def spy(head, _p=classify.PARSERS):
            seen.append(head)

        original = classify.PARSERS
        try:
            classify.PARSERS = tuple(
                lambda h, p=p: (seen.append(p) or p(h)) for p in original)
            classify.classify(MKV, ready=True, file_size=len(MKV),
                              requested=len(MKV))
        finally:
            classify.PARSERS = original
        self.assertEqual(len(seen), len(original))


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

class TestCandidateSelection(unittest.TestCase):
    """The frozen rule: not padding, and no supported format claim. No floor,
    no cap."""

    def names(self, files):
        return [f["name"] for _, f in engine.untyped(files)]

    def files(self, *names):
        return [{"name": n, "size": 1 << 20, "priority": 1,
                 "piece_range": [0, 0]} for n in names]

    def test_both_extensionless_shapes_are_candidates(self):
        self.assertEqual(self.names(self.files(SPACED, DOTTED)),
                         [SPACED, DOTTED])

    def test_a_dotted_codec_token_is_not_a_format_claim(self):
        for name in ("Show.S01E01.1080p.WEB-DL.DDP5.1.H.264-GRP",
                     "Lioness.S03E08.1080p.WEB-DL.DDP5.1.H.265-NTb"):
            with self.subTest(name):
                self.assertEqual(self.names(self.files(name)), [name])

    def test_real_media_and_sidecars_are_not_candidates(self):
        names = ("ep1.mkv", "ep1.mp4", "ep1.srt", "cover.jpg", "release.nfo",
                 "payload.rar", "payload.r00", "setup.exe", "notes.txt")
        self.assertEqual(self.names(self.files(*names)), [])

    def test_a_split_archive_volume_is_a_claim_but_a_lone_number_is_not(self):
        """Inherits the 0.8.2 predicate rather than re-deriving it."""
        self.assertEqual(self.names(self.files("release.rar", "release.001")), [])
        self.assertEqual(self.names(self.files("Show.S01E01.H.264")),
                         ["Show.S01E01.H.264"])

    def test_padding_files_are_never_candidates(self):
        for pad in ("_____padding_file_0_if you see this", ".pad/512",
                    "Show.S01/_____padding_file_3_x"):
            with self.subTest(pad):
                self.assertEqual(self.names(self.files(pad, SPACED)), [SPACED])

    def test_there_is_no_size_floor(self):
        """The measured decision: a floor is an evasion boundary, and breadth
        on the free pass costs one local read and no API calls."""
        files = [{"name": "tiny", "size": 12, "priority": 1,
                  "piece_range": [0, 0]},
                 {"name": SPACED, "size": 2 << 30, "priority": 1,
                  "piece_range": [0, 900]}]
        self.assertEqual(self.names(files), ["tiny", SPACED])

    def test_there_is_no_candidate_cap(self):
        names = [f"part{i}" for i in range(200)]
        self.assertEqual(len(self.names(self.files(*names))), 200)

    def test_known_claims_without_validators_stay_out_of_the_lane(self):
        """`.ts`, `.iso` and the rest are recognised format claims that the
        probe has no validator for. They are neither untyped candidates nor
        typed targets, and the missing validators are a roadmap item."""
        gap = (".ts", ".iso", ".wmv", ".mpg", ".mpeg", ".m2ts", ".vob",
               ".divx", ".ogm", ".flv")
        files = self.files(*[f"ep1{e}" for e in gap])
        self.assertEqual(self.names(files), [])
        self.assertEqual(engine.targets(files), [])

    def test_candidates_merges_both_lanes_in_index_order(self):
        files = self.files("ep1.mkv", SPACED, "readme.nfo", DOTTED)
        self.assertEqual(
            [(f["name"], kind) for _, f, kind in engine.candidates(files)],
            [("ep1.mkv", engine.TYPED), (SPACED, engine.UNTYPED),
             (DOTTED, engine.UNTYPED)])

    def test_a_typed_file_is_never_also_an_untyped_candidate(self):
        files = self.files("ep1.mkv", SPACED)
        typed = {i for i, _ in engine.targets(files)}
        untyped = {i for i, _ in engine.untyped(files)}
        self.assertFalse(typed & untyped)


class TestTheClassifySpanIsTheClassifiersOwn(unittest.TestCase):
    """`header_bytes` keeps its meaning; the classifier gets its own floor."""

    def span(self, header_bytes, kind):
        return engine.span_for(engine.settings(
            {"detection": {"probe": {"header_bytes": header_bytes}}}), kind)

    def test_a_typed_read_is_exactly_what_the_user_configured(self):
        for n in (64, 512, 4096, 65536):
            with self.subTest(n):
                self.assertEqual(self.span(n, engine.TYPED), n)

    def test_a_lowered_header_bytes_cannot_blind_the_classifier(self):
        self.assertEqual(self.span(64, engine.UNTYPED), classify.CLASSIFY_BYTES)

    def test_a_raised_header_bytes_is_honoured_rather_than_clamped_down(self):
        self.assertEqual(self.span(65536, engine.UNTYPED), 65536)

    def test_a_default_install_reads_exactly_what_it_read_before(self):
        p = engine.settings({})
        self.assertEqual(p["header_bytes"], classify.CLASSIFY_BYTES)
        self.assertEqual(engine.span_for(p, engine.UNTYPED),
                         engine.span_for(p, engine.TYPED))


# ---------------------------------------------------------------------------
# End to end, and still no findings
# ---------------------------------------------------------------------------

class FakeQb:
    def __init__(self, files, piece_states, torrent=None):
        self.files_list = files
        self.states = list(piece_states)
        self.info = torrent or {}
        self.calls = []

    def properties(self, h):
        return {"piece_size": 1024}

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


def cfg(**over):
    p = dict(engine.DEFAULTS, enabled=True)
    p.update(over)
    return {"detection": {"probe": p}, "dry_run": False,
            "safety": {"mode": "arr_tracked"}, "arrs": []}


class TestTheSensorChangesNothingItCanReap(unittest.TestCase):
    """C1's contract: select and classify accurately, act on none of it."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        from protectarr.probe import ledger
        ledger._broken = None
        self.content = os.path.join(self.dir, "release")
        os.makedirs(self.content, exist_ok=True)
        self.torrent = {"hash": "abc123", "name": "release",
                        "content_path": self.content, "state": "downloading",
                        "progress": 0.02, "dlspeed": 5 << 20, "num_seeds": 12,
                        "seq_dl": False, "f_l_piece_prio": False}

    def write(self, name, data):
        path = os.path.join(self.content, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)

    def single(self, name, data):
        """A one-file torrent, whose `content_path` *is* the file.

        Written out rather than reused from the multi-file helper because
        qBittorrent reports the two differently, and a fixture that puts a
        single-file torrent's payload inside a directory produces a probe that
        reads nothing and a test that passes for the wrong reason.
        """
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        torrent = dict(self.torrent, content_path=path, name=name)
        files = [{"name": name, "priority": 1, "size": len(data),
                  "piece_range": [0, 0]}]
        return torrent, files

    def test_a_confirmed_executable_behind_a_scene_name_yields_no_finding(self):
        torrent, files = self.single(SPACED, PE)
        qb = FakeQb(files, [2] * 4, torrent)
        state = {}
        res = engine.inspect(qb, torrent, files, cfg(), state)
        self.assertEqual(res.findings, ())
        self.assertFalse(res.steered)
        self.assertEqual(qb.calls, [])
        # ...and it was genuinely looked at. Without this, "no finding" and
        # "never read the file" are the same passing test, which is how the
        # single-file fixture above got written wrong the first time.
        memo = state["probe_memo"]["abc123"]["resolved"]
        self.assertTrue(memo.get(SPACED))

    def test_the_same_bytes_are_classified_even_so(self):
        """The sensor half of the same case, read directly, so "no finding"
        cannot quietly mean "never looked"."""
        v = verdict(PE)
        self.assertEqual(v.evidence, EXECUTABLE_CONFIRMED)
        self.assertEqual(v.format, "windows_pe")

    def test_tiny_sidecars_beside_an_untyped_payload_are_all_read_free(self):
        for i in range(12):
            self.write("note%02d" % i, TINY)
        self.write(SPACED, MKV)
        files = [{"name": "note%02d" % i, "priority": 1, "size": len(TINY),
                  "piece_range": [0, 0]} for i in range(12)]
        files.append({"name": SPACED, "priority": 1, "size": len(MKV),
                      "piece_range": [0, 0]})
        qb = FakeQb(files, [2] * 4, self.torrent)
        res = engine.inspect(qb, self.torrent, files, cfg(), {})
        self.assertEqual(len(engine.untyped(files)), 13)
        self.assertEqual(res.findings, ())
        # Every one resolved from data already on disk, so nothing was steered
        # and not a single qBittorrent setting moved.
        self.assertEqual(qb.calls, [])

    def test_an_unavailable_candidate_is_not_resolved_and_can_be_retried(self):
        """Required classification pieces are not downloaded. That is
        `probe_data_unavailable`, and it is the one state worth coming back
        for."""
        files = [{"name": SPACED, "priority": 1, "size": 2 << 30,
                  "piece_range": [0, 900]}]
        qb = FakeQb(files, [0] * 901, self.torrent)
        state = {}
        res = engine.inspect(qb, self.torrent, files, cfg(steer=False), state)
        self.assertEqual(res.findings, ())
        self.assertFalse(res.steered)
        # Nothing was marked resolved, so a later pass will look again.
        self.assertEqual(state["probe_memo"]["abc123"]["resolved"], {})

    def test_a_complete_tiny_candidate_is_resolved_and_not_retried(self):
        """The other half of the availability rule, end to end: a 20-byte file
        that is entirely downloaded is answered once and never revisited."""
        torrent, files = self.single("info", TINY)
        qb = FakeQb(files, [2] * 4, torrent)
        state = {}
        engine.inspect(qb, torrent, files, cfg(), state)
        self.assertTrue(state["probe_memo"]["abc123"]["resolved"].get("info"))

    def test_a_typed_file_still_reaches_its_old_verdict(self):
        """The untyped lane must not have changed what the typed one does."""
        torrent, files = self.single("ep1.mkv", PE)
        qb = FakeQb(files, [2] * 4, torrent)
        res = engine.inspect(qb, torrent, files, cfg(), {})
        self.assertEqual([f["reason"] for f in res.findings],
                         ["content_type_mismatch"])


if __name__ == "__main__":
    unittest.main()
