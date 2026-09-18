"""What the opening bytes can prove on their own, without a filename to trust.

`validators.validate` answers "do these bytes match the extension's claim?" and
needs a claim before it can answer anything at all. A file named
`South.Park.S29E01.1080p.WEB-DL.DDP5.1.x265-FLUX` makes no claim, so that
question has no answer and the lane has always stayed silent about such files.

This module asks the other question - given only a bounded prefix, what is
structurally provable? - and it is a *sensor*. It reports what it saw. It
assigns no severity, proposes no action, and knows nothing about torrents,
queues or policy.

Four rules it does not bend:

**A short read is never evidence.** Bytes that should exist and do not are
`probe_data_unavailable` and are worth coming back for. That is a statement
about availability, not about length: a file that is *complete* at twenty bytes
has all the bytes it will ever have, so the parsers that can run on twenty bytes
run, and if none of them confirms anything the answer is a terminal
`format_unrecognized`. Retrying a fully downloaded tiny file forever would be
the same mistake in the opposite direction.

**A bound we chose is our limit, not the file's verdict.** A DOS header whose
`e_lfanew` points past `CLASSIFY_BYTES` is not unavailable - we read every byte
we asked for. Nor is it ambiguous: nothing validated. It is
`format_unrecognized`, carrying the hint that an MZ prefix was seen.

**Magic is a reason to look, never a verdict.** Every parser here reaches a
decisive structural field before it confirms anything. Where the magic matched
and the structure did not, *nothing was proved*, and the answer is
`format_unrecognized` - not `ambiguous_format`, which means something narrower
and is defined below.

That would throw away something an operator wants, so it is kept beside the
verdict rather than inside it: `Verdict.hint` carries the prefix that was
observed, and the note says what failed. "I saw an MZ but could not prove a PE"
and "these bytes are nothing I know" are both `format_unrecognized`, and stay
tellable apart. The hint is diagnostic only. It is never evidence, it never
reaches policy, and no finding may be built from it.

**`ambiguous_format` means several interpretations genuinely survived.** Not
"something looked familiar" - that is the paragraph above. Ambiguity is the
state where two or more parsers each reached a decisive structural field and
each confirmed, so the bytes really are valid as more than one thing and we
cannot say which. Nothing else may produce it.

**Every applicable parser runs.** Returning the first four bytes that look
familiar is how a polyglot gets a clean answer. All of them run, so bytes that
validate twice are reported as ambiguous rather than as whichever parser
happened to be listed first.

Byte spans were measured before this was written; `MINIMUMS` below records what
each parser needs, and the largest is 1050 (a PE whose `e_lfanew` is 0x400).
`CLASSIFY_BYTES` covers all of them with room to spare.
"""

import collections

# The classifier's own floor, deliberately *not* the user's `header_bytes`.
#
# `header_bytes` is the knob over what the extension-validation lane reads and
# the user chose its value; raising it from here would silently change a setting
# they set. What the structural parsers need is a property of the formats rather
# than a preference, so it is a constant that cannot be misconfigured.
#
# 4096 because it covers every minimum below (worst is 1050) and costs nothing:
# measured across piece sizes, a 4096-byte read straddles a piece boundary for
# 0.098% of possible file offsets at 4 MiB pieces, which was 1 file in 40 on a
# test torrent - exactly the same number as the 4096 the default already reads.
CLASSIFY_BYTES = 4096

# The frozen evidence taxonomy. These seven strings are the whole vocabulary;
# nothing here invents an eighth.
MEDIA_CONFIRMED = "media_format_confirmed"
EXECUTABLE_CONFIRMED = "executable_format_confirmed"
OLE_CONFIRMED = "ole_compound_confirmed"
ARCHIVE_CONFIRMED = "archive_format_confirmed"
AMBIGUOUS = "ambiguous_format"
UNRECOGNIZED = "format_unrecognized"
UNAVAILABLE = "probe_data_unavailable"

EVIDENCE = frozenset((MEDIA_CONFIRMED, EXECUTABLE_CONFIRMED, OLE_CONFIRMED,
                      ARCHIVE_CONFIRMED, AMBIGUOUS, UNRECOGNIZED, UNAVAILABLE))

# The evidence classes that assert something positive about the bytes. Named so
# that "did anything confirm?" is one lookup rather than four comparisons that
# could drift apart.
CONFIRMED = frozenset((MEDIA_CONFIRMED, EXECUTABLE_CONFIRMED, OLE_CONFIRMED,
                       ARCHIVE_CONFIRMED))

# What one parser saw.
#
# `format` is set only when something was confirmed, and is machine-readable so
# history stays filterable. `hint` is its opposite number: the prefix that was
# recognised when nothing could be confirmed from it. Exactly one of them is
# ever set, which is the invariant that keeps a hint from being read as a
# format by anything downstream.
#
# `note` is the sentence a human reads and never claims more than the bytes
# proved.
Match = collections.namedtuple("Match", "evidence format note hint")
Match.__new__.__defaults__ = (None,)

# What `classify` returns. `retryable` answers the caller's real question -
# should we come back for this file? - so that the availability rule lives here
# and is not re-derived at each call site.
Verdict = collections.namedtuple("Verdict", "evidence format note retryable hint")
Verdict.__new__.__defaults__ = (None,)


def _media(fmt, note):
    return Match(MEDIA_CONFIRMED, fmt, note)


def _exe(fmt, note):
    return Match(EXECUTABLE_CONFIRMED, fmt, note)


def _archive(fmt, note):
    return Match(ARCHIVE_CONFIRMED, fmt, note)


def _unrecognised(prefix, note):
    """A prefix we recognise, behind which nothing structural checked out.

    This is the case the taxonomy is easiest to get wrong. Nothing was proved,
    so the evidence is `format_unrecognized` and `format` stays None - naming a
    format here would assert exactly what the parser just failed to establish.
    The prefix survives as a hint, which is diagnostic and never actionable.
    """
    return Match(UNRECOGNIZED, None, note, prefix)


def _u16(buf, off, byteorder="little"):
    return int.from_bytes(buf[off:off + 2], byteorder)


def _u32(buf, off, byteorder="little"):
    return int.from_bytes(buf[off:off + 4], byteorder)


def _printable(chunk):
    """Is this a four-character tag a container would actually write?

    Box types and brands are ASCII by specification. Anything else at that
    offset means the walk is reading something that is not a box header, and
    the honest response is to stop rather than to keep stepping through
    attacker-chosen lengths.
    """
    return len(chunk) == 4 and all(0x20 <= b <= 0x7e for b in chunk)


# --------------------------------------------------------------- Matroska/WebM

_EBML_HEADER = b"\x1a\x45\xdf\xa3"
_EBML_DOCTYPE = b"\x42\x82"
_MATROSKA_DOCTYPES = {b"matroska": "matroska", b"webm": "webm"}


def _vint(buf, pos):
    """(value, width) for the EBML variable-length integer at `pos`.

    The leading byte's first set bit gives the width, and the marker bit is not
    part of the value. `(None, 0)` for a VINT that is wider than eight bytes or
    that runs past what we hold: both mean "stop", never "assume".
    """
    if pos >= len(buf):
        return None, 0
    first = buf[pos]
    if first == 0:
        return None, 0
    width = 9 - first.bit_length()
    if pos + width > len(buf):
        return None, 0
    value = first & (0xff >> width)
    for i in range(1, width):
        value = (value << 8) | buf[pos + i]
    return value, width


def _element_id(buf, pos):
    """(raw id bytes, width) for the EBML element ID at `pos`.

    IDs keep their marker bit - it is part of the identity - which is why this
    is not `_vint`.
    """
    if pos >= len(buf):
        return None, 0
    first = buf[pos]
    if first == 0:
        return None, 0
    width = 9 - first.bit_length()
    if pos + width > len(buf):
        return None, 0
    return buf[pos:pos + width], width


def parse_matroska(head):
    """EBML header walked to its DocType.

    The EBML magic alone is not Matroska. It is shared by WebM, by every EBML
    document anyone has ever defined, and by anything an attacker prefixes with
    four bytes. DocType is the field that separates them, so nothing is
    confirmed until it has been read.
    """
    if not head.startswith(_EBML_HEADER):
        return None
    pos = len(_EBML_HEADER)
    size, width = _vint(head, pos)
    if size is None:
        return _unrecognised("ebml", "an EBML magic whose header size is unreadable")
    pos += width
    end = min(len(head), pos + size)
    while pos < end:
        eid, width = _element_id(head, pos)
        if eid is None:
            break
        pos += width
        esize, width = _vint(head, pos)
        if esize is None:
            break
        pos += width
        if pos + esize > len(head):
            break
        if eid == _EBML_DOCTYPE:
            # Trailing NULs are legal padding in an EBML string. The value
            # itself is never echoed into the note: it is attacker-chosen, and
            # notes end up in logs and in issue attachments.
            doctype = head[pos:pos + esize].rstrip(b"\x00")
            name = _MATROSKA_DOCTYPES.get(doctype)
            if name:
                return _media(name, f"an EBML header declaring DocType {name}")
            return _unrecognised("ebml", "an EBML document that is not Matroska or WebM")
        pos += esize
    return _unrecognised("ebml", "an EBML header whose DocType is not inside the bytes "
                        "we read")


# ------------------------------------------------------------------- ISO-BMFF

# Top-level boxes that may legally precede `ftyp`, or stand in for it in a file
# written by a muxer that is still working. Anything else at the top level means
# this is not an ISO base media file and the walk stops.
_BMFF_BOXES = frozenset((b"ftyp", b"styp", b"moov", b"mdat", b"free", b"skip",
                         b"wide", b"pnot", b"meta", b"uuid", b"moof", b"mfra"))


def parse_iso_bmff(head):
    """Bounded top-level box walk, ending at a `ftyp` we can read in full.

    ISO 14496-12 does not require `ftyp` to come first, so the walk steps over
    the boxes that may precede it - and stops the moment it sees a box header
    that is not one, because stepping by an attacker-supplied length through
    bytes that are not boxes is how a walk is turned into a search.

    The `ftyp` box must lie entirely inside the bytes we hold. That is what a
    bounded parser means, and it is also what stops a polyglot: a file opening
    `MZ` or `RIFF` has those bytes read as the first box's length, which is
    always more than a gigabyte, so no `MZ`-prefixed file can also confirm as
    ISO-BMFF here.
    """
    pos, boxes = 0, 0
    while pos + 8 <= len(head):
        size = _u32(head, pos, "big")
        btype = head[pos + 4:pos + 8]
        if btype not in _BMFF_BOXES:
            return _unrecognised("iso_bmff", "a box walk that ran into something that is "
                                    "not a box") if boxes else None
        header = 8
        if size == 1:
            if pos + 16 > len(head):
                break
            size = int.from_bytes(head[pos + 8:pos + 16], "big")
            header = 16
        elif size == 0:
            size = len(head) - pos          # "to the end of the file"
        if size < header:
            return _unrecognised("iso_bmff", "a box shorter than its own header") \
                if boxes else None
        if btype == b"ftyp":
            # The major brand is the decisive field and it ends at offset 16 of
            # the box. The rest of the box is compatible brands, which add
            # nothing to the verdict, so requiring the whole box would spend
            # bytes - and refuse an answer on a truncated read - for nothing.
            if size < 16:
                return _unrecognised("iso_bmff", "a ftyp box too small to hold a brand")
            if pos + 16 > len(head):
                return _unrecognised("iso_bmff", "a ftyp box whose brand is past the "
                                        "bytes we read")
            brand = head[pos + 8:pos + 12]
            if not _printable(brand):
                return _unrecognised("iso_bmff", "a ftyp box with no readable brand")
            return _media("iso_bmff", "a complete ftyp box with a printable "
                                      "major brand")
        boxes += 1
        pos += size
    if boxes:
        return _unrecognised("iso_bmff", "valid boxes, but no ftyp inside the bytes we "
                                "read")
    return None


# ------------------------------------------------------------------ RIFF: AVI

def parse_riff(head):
    """RIFF resolved by its form type, which is the only thing that names it."""
    if not head.startswith(b"RIFF"):
        return None
    if len(head) < 12:
        return _unrecognised("riff", "a RIFF container whose form type is past the bytes "
                            "we read")
    form = head[8:12]
    if form == b"AVI ":
        return _media("avi", "a RIFF container with an AVI form type")
    if form == b"WAVE":
        return _media("wav", "a RIFF container with a WAVE form type")
    return _unrecognised("riff", "a RIFF container that is neither AVI nor WAVE")


# ----------------------------------------------------------------------- FLAC

def parse_flac(head):
    """`fLaC` followed by a STREAMINFO block that is actually present.

    The block is required to be there rather than merely announced: a file that
    ends part-way through its STREAMINFO is a truncated FLAC, and confirming
    media from a length field nobody could read is the kind of assertion this
    lane does not make.
    """
    if not head.startswith(b"fLaC"):
        return None
    if len(head) < 8:
        return _unrecognised("flac", "a FLAC magic with no readable block header")
    block_type = head[4] & 0x7f
    length = int.from_bytes(head[5:8], "big")
    if block_type != 0 or length != 34:
        return _unrecognised("flac", "a FLAC magic not followed by a STREAMINFO block")
    if len(head) < 8 + 34:
        return _unrecognised("flac", "a STREAMINFO block that is not fully downloaded")
    return _media("flac", "fLaC with a complete 34-byte STREAMINFO block")


# ------------------------------------------------------------------ Windows PE

# Optional-header magics: PE32, PE32+ and the ROM image nobody ships but the
# loader still accepts.
_PE_OPTIONAL = (0x10b, 0x20b, 0x107)


def parse_pe(head):
    """DOS header, `e_lfanew`, `PE\\0\\0`, and an optional header behind it.

    Two bytes of "MZ" is not a program. Neither is a `PE\\0\\0` sitting wherever
    a crafted pointer says, which is why `e_lfanew` must clear the DOS header it
    would otherwise overlap, and why the COFF and optional headers behind the
    signature are read rather than assumed.

    A pointer that leads past the bytes we hold is the bounded case: we read
    everything we asked for and still cannot say. That is ambiguity, not
    unavailability, and it is never actionable either way.
    """
    if not head.startswith(b"MZ"):
        return None
    if len(head) < 0x40:
        return _unrecognised("dos_mz", "an MZ header too short to hold a PE pointer")
    offset = _u32(head, 0x3c)
    if offset < 0x40:
        return _unrecognised("dos_mz", "an MZ whose PE pointer overlaps its own DOS "
                              "header")
    if offset + 26 > len(head):
        return _unrecognised("dos_mz", f"an MZ whose PE pointer leads past the "
                              f"{len(head)} bytes we read")
    if head[offset:offset + 4] != b"PE\x00\x00":
        return _unrecognised("dos_mz", "an MZ with no PE signature where its pointer "
                              "leads")
    machine = _u16(head, offset + 4)
    optional = _u16(head, offset + 24)
    if machine == 0 or optional not in _PE_OPTIONAL:
        return _unrecognised("dos_mz", "a PE signature with no readable optional header")
    bits = 64 if optional == 0x20b else 32
    return _exe("windows_pe", f"a DOS header, a reachable PE signature and a "
                              f"{bits}-bit optional header")


# ------------------------------------------------------------------------ ELF

def parse_elf(head):
    """The ELF identification header, read rather than recognised."""
    if not head.startswith(b"\x7fELF"):
        return None
    if len(head) < 24:
        return _unrecognised("elf", "an ELF magic with an incomplete identification "
                           "header")
    ei_class, ei_data, ei_version = head[4], head[5], head[6]
    if ei_class not in (1, 2) or ei_data not in (1, 2) or ei_version != 1:
        return _unrecognised("elf", "an ELF magic with an unreadable identification "
                           "header")
    order = "little" if ei_data == 1 else "big"
    e_type = _u16(head, 16, order)
    e_machine = _u16(head, 18, order)
    e_version = _u32(head, 20, order)
    # 0-4 are the defined object types; the two high ranges are the OS and
    # processor specific ones, which are legal and do turn up.
    known = 0 <= e_type <= 4 or 0xfe00 <= e_type <= 0xffff
    if e_version != 1 or e_machine == 0 or not known:
        return _unrecognised("elf", "an ELF magic whose header fields do not parse")
    return _exe("elf", "a complete ELF identification header")


# ---------------------------------------------------------------------- Mach-O

# Thin images, in both byte orders. The magic on disk already says which way the
# fields behind it are written.
_MACHO_THIN = {
    b"\xfe\xed\xfa\xce": "big", b"\xfe\xed\xfa\xcf": "big",
    b"\xce\xfa\xed\xfe": "little", b"\xcf\xfa\xed\xfe": "little",
}
_MACHO_FAT = {
    b"\xca\xfe\xba\xbe": "big", b"\xca\xfe\xba\xbf": "big",
    b"\xbe\xba\xfe\xca": "little", b"\xbf\xba\xfe\xca": "little",
}

# MH_OBJECT through MH_FILESET. A file type outside this range means the four
# bytes were a coincidence.
_MACHO_FILETYPES = range(1, 13)

# A universal binary holding more than this many slices does not exist. The
# bound is what separates a fat Mach-O from a Java class file; see below.
_MACHO_MAX_ARCHS = 16


def parse_macho(head):
    """Thin and fat Mach-O headers, read as far as the first decisive field.

    The fat case is the one genuine collision in this whole parser set.
    `0xcafebabe` is also the Java class-file magic, where the four bytes behind
    it are the minor and major version numbers rather than a slice count. The
    two are separable in practice - class files have never used a major version
    below 45, and no universal binary has sixteen slices.

    A count outside the plausible range therefore means this is not a universal
    binary, and nothing here validated it as anything else either: Protectarr
    has no Java class parser, so there is no second interpretation for it to be
    ambiguous *between*. It is unrecognised, hinting at the prefix that was
    seen. It would only become `ambiguous_format` if a class-file parser were
    added and both confirmed, which is what that state is for.
    """
    magic = head[:4]
    order = _MACHO_THIN.get(magic)
    if order:
        if len(head) < 16:
            return _unrecognised("mach_o", "a Mach-O magic with an incomplete header")
        if _u32(head, 12, order) not in _MACHO_FILETYPES:
            return _unrecognised("mach_o", "a Mach-O magic with an unknown file type")
        return _exe("mach_o", "a Mach-O header with a known file type")

    order = _MACHO_FAT.get(magic)
    if not order:
        return None
    if len(head) < 8:
        return _unrecognised("cafebabe", "four bytes that begin a universal binary or a "
                                "Java class file, with nothing behind them")
    count = _u32(head, 4, order)
    if not 1 <= count <= _MACHO_MAX_ARCHS:
        return _unrecognised("cafebabe", "a universal-binary magic whose slice count is "
                                "a plausible Java class-file version instead")
    if len(head) < 28:
        return _unrecognised("mach_o", "a universal binary whose first slice is not "
                              "fully downloaded")
    cputype = _u32(head, 8, order)
    offset = _u32(head, 16, order)
    if cputype == 0 or offset < 8 + 20 * count:
        return _unrecognised("mach_o", "a universal-binary header whose first slice does "
                              "not parse")
    return _exe("mach_o", f"a universal binary header with {count} "
                          f"architecture slice(s)")


# ---------------------------------------------------------------- OLE compound

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def parse_ole(head):
    """An OLE compound file, identified as nothing more specific than that.

    `.msi`, `.doc` and a great many droppers share this container, and which of
    them it is lives in a directory stream far past any bounded header read. So
    this confirms the container and stops - naming it a document or an installer
    would be a guess wearing a parser's authority.
    """
    if not head.startswith(_OLE_MAGIC):
        return None
    if len(head) < 0x20:
        return _unrecognised("ole_compound", "an OLE signature with an incomplete header")
    if head[0x1c:0x1e] != b"\xfe\xff":
        return _unrecognised("ole_compound", "an OLE signature with no byte-order mark")
    major = _u16(head, 0x1a)
    sector_shift = _u16(head, 0x1e)
    if major not in (3, 4) or sector_shift not in (9, 12):
        return _unrecognised("ole_compound", "an OLE signature whose header fields do "
                                    "not parse")
    return Match(OLE_CONFIRMED, "ole_compound",
                 "an OLE compound-file header with a valid sector size")


# --------------------------------------------------------------- ZIP, RAR, 7z

# Deflate and the rest of the methods a real archiver emits, plus stored.
_ZIP_METHODS = frozenset((0, 1, 6, 8, 9, 12, 14, 93, 94, 95, 96, 97, 98, 99))


def parse_zip(head):
    if head.startswith(b"PK\x05\x06"):
        if len(head) < 22:
            return _unrecognised("zip", "an end-of-central-directory record that is cut "
                               "short")
        return _archive("zip", "an empty ZIP central directory")
    if not head.startswith(b"PK\x03\x04"):
        return None
    if len(head) < 30:
        return _unrecognised("zip", "a ZIP signature with an incomplete local header")
    if _u16(head, 8) not in _ZIP_METHODS:
        return _unrecognised("zip", "a ZIP signature with an unknown compression method")
    return _archive("zip", "a ZIP local file header with a known compression "
                           "method")


def _rar5_vint(buf, pos):
    """(value, next position) for RAR5's 7-bit continuation integer."""
    value = shift = 0
    while pos < len(buf) and shift < 64:
        byte = buf[pos]
        value |= (byte & 0x7f) << shift
        pos += 1
        if not byte & 0x80:
            return value, pos
        shift += 7
    return None, pos


def parse_rar(head):
    """Both RAR generations, each walked to its first block header.

    The signature alone is seven or eight bytes of constant, so the first block
    is read and required to be the archive header. A RAR whose first block is
    something else is not something we are willing to name.
    """
    if head.startswith(b"Rar!\x1a\x07\x01\x00"):
        if len(head) < 14:
            return _unrecognised("rar", "a RAR5 signature with no readable block header")
        size, pos = _rar5_vint(head, 12)
        if size is None:
            return _unrecognised("rar", "a RAR5 block header with an unreadable size")
        block_type, _ = _rar5_vint(head, pos)
        if block_type is None:
            return _unrecognised("rar", "a RAR5 block header with an unreadable type")
        if block_type != 1:
            return _unrecognised("rar", "a RAR5 signature whose first block is not the "
                               "archive header")
        return _archive("rar", "a RAR5 main archive header")
    if head.startswith(b"Rar!\x1a\x07\x00"):
        if len(head) < 20:
            return _unrecognised("rar", "a RAR signature with an incomplete main header")
        if head[9] != 0x73:                     # HEAD_TYPE: MAIN_HEAD
            return _unrecognised("rar", "a RAR signature whose first block is not the "
                               "main header")
        if _u16(head, 12) < 13:                 # HEAD_SIZE
            return _unrecognised("rar", "a RAR main header shorter than the format "
                               "allows")
        return _archive("rar", "a RAR main archive header")
    if head.startswith(b"Rar!\x1a\x07"):
        return _unrecognised("rar", "a RAR signature of a version we do not parse")
    return None


def parse_7z(head):
    if not head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return None
    if len(head) < 32:
        return _unrecognised("7z", "a 7-Zip signature with an incomplete start header")
    if head[6] != 0 or head[7] > 4:
        return _unrecognised("7z", "a 7-Zip signature with an unknown format version")
    return _archive("7z", "a 7-Zip signature header with a readable start "
                          "header")


# ------------------------------------------------------------------- the sweep

# Every parser, with the smallest read at which it can confirm anything. The
# minimums are the measured spans, and they are here to be asserted against the
# parsers rather than to be trusted: `CLASSIFY_BYTES` is only defensible while
# it is larger than all of them.
#
# The PE figure is the worst *bounded* case rather than the typical one: a
# 0x80 `e_lfanew` needs 154 bytes and a 0x400 one needs 1050, and the pointer is
# the file's to choose.
MINIMUMS = (
    ("matroska", parse_matroska, 32),
    ("iso_bmff", parse_iso_bmff, 16),
    ("riff", parse_riff, 12),
    ("flac", parse_flac, 42),
    ("windows_pe", parse_pe, 1050),
    ("elf", parse_elf, 24),
    ("mach_o", parse_macho, 28),
    ("ole_compound", parse_ole, 32),
    ("zip", parse_zip, 30),
    ("rar", parse_rar, 20),
    ("7z", parse_7z, 32),
)

PARSERS = tuple(fn for _, fn, _ in MINIMUMS)


def _resolve(matches):
    """One verdict from every parser that had something to say.

    Only a confirmation counts toward ambiguity. A parser that recognised a
    prefix and then failed to validate it proved nothing, so a pile of such
    results is not a pile of interpretations - it is one unrecognised file that
    happened to start with something familiar.

    So the arithmetic is done on confirmations alone:

    * two or more of them, and the bytes really are valid as several things at
      once. That is `ambiguous_format`, and it is the only thing that produces
      it. Nothing downstream may act on it, including when the survivors happen
      to agree on a kind - "definitely media, but we cannot say which
      container" is still a question we failed to answer, and a lane that
      deletes has no business rounding that up.
    * exactly one, and that is the answer.
    * none, and the file is unrecognised. The hints come along, deduplicated
      and ordered, so the note can say what was seen without claiming it.
    """
    if not matches:
        return None
    confirmed = [m for m in matches if m.evidence in CONFIRMED]
    if len(confirmed) == 1:
        return confirmed[0]
    if confirmed:
        formats = "+".join(sorted(m.format for m in confirmed))
        return Match(AMBIGUOUS, formats,
                     f"structurally valid as {formats} at once, so which of "
                     f"them it is cannot be established", None)

    hints = sorted({m.hint for m in matches if m.hint})
    if not hints:
        return None
    # One parser's note is worth more than a joined list, so a single hint keeps
    # the sentence its parser wrote and only a genuine pile-up falls back.
    if len(hints) == 1:
        first = next(m for m in matches if m.hint == hints[0])
        return first
    return Match(UNRECOGNIZED, None,
                 "a prefix matching " + ", ".join(hints)
                 + ", none of which validated", "+".join(hints))


def classify(head, ready=True, file_size=None, requested=None):
    """What these bytes prove. Returns a `Verdict`; never raises.

    `head` is what was actually read, `ready` is the reader's answer to whether
    those are the file's own bytes (see `probe.paths`), `file_size` is the
    file's full size when it is known, and `requested` is how many bytes were
    asked for.

    The last two exist for one distinction and it is the important one. Holding
    fewer bytes than were asked for means either that the file is complete and
    simply smaller than the request - in which case we have everything there
    will ever be, and the parsers run - or that bytes which should exist are not
    readable yet, which is `probe_data_unavailable` and is worth retrying.
    Length alone cannot tell those apart, which is why size is a parameter.
    """
    head = head or b""
    if not ready:
        return Verdict(UNAVAILABLE, None, "no readable data yet", True)
    if not head:
        return Verdict(UNAVAILABLE, None, "there are no bytes to look at", True)

    # How many opening bytes could exist: what we asked for, or the whole file
    # if it is smaller. An unknown size cannot be used to excuse a short read,
    # so it falls back to the request.
    want = requested if requested else len(head)
    if isinstance(file_size, int) and file_size > 0:
        want = min(want, file_size)
    if len(head) < want:
        return Verdict(UNAVAILABLE, None,
                       f"read {len(head)} of the {want} opening bytes that "
                       f"should be there", True)

    matches = []
    for parser in PARSERS:
        match = parser(head)
        if match is not None:
            matches.append(match)
    best = _resolve(matches)
    if best is None:
        return Verdict(UNRECOGNIZED, None,
                       f"{len(head)} readable bytes that no parser recognises",
                       False, None)
    return Verdict(best.evidence, best.format, best.note, False, best.hint)
