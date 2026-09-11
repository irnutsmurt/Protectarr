"""Does this file actually parse as what its extension claims?

The deliberate choice here is *positive* validation rather than a blocklist of
bad magic. "Is this an MZ, an ELF, a PK?" is a list that grows forever and that
an attacker iterates against; "does this look like Matroska?" is one question
that stays true however the payload changes.

Three answers, and only one of them is evidence:

    VALID    the bytes match the claim
    INVALID  the bytes are confidently something else, and something a media
             file could never be - this is the only state that makes a finding
    UNKNOWN  we cannot tell

UNKNOWN is returned liberally and on purpose. Over-caution degrades to saying
nothing; the opposite degrades to accusing real downloads, and a false accusation
here means Protectarr deletes and blocklists somebody's legitimate release.

The other half of that caution is `FAMILY` below: an `.mkv` whose bytes are
really an AVI is a bad rename, not an attack, so it is never accused. Only a
payload that is not media *in any container* is.
"""

import posixpath

VALID, INVALID, UNKNOWN = "valid", "invalid", "unknown"

# (magic, type) checked at offset 0, most specific first.
_MAGIC = (
    (b"\x1a\x45\xdf\xa3", "matroska"),      # EBML: mkv / webm
    (b"RIFF", "riff"),                      # refined to avi / wav below
    (b"fLaC", "flac"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3"),
    (b"%PDF", "pdf"),
    (b"MZ", "dos_mz"),                      # refined to windows_pe below
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\xd0\xcf\x11\xe0", "ole_compound"),  # .doc, .msi
    (b"#!", "script"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG", "png"),
    (b"\x1f\x8b", "gzip"),
)

# ISO base media files start with a box header, and `ftyp` is not the only legal
# first box (ISO 14496-12 allows a file to open with moov/mdat/free/...), so a
# missing ftyp is not evidence of anything.
_BMFF_BOXES = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot"}

# What each extension must look like to be considered VALID.
EXPECTED = {
    ".mkv": {"matroska"}, ".webm": {"matroska"},
    ".mp4": {"iso_bmff"}, ".m4v": {"iso_bmff"}, ".mov": {"iso_bmff"},
    ".m4a": {"iso_bmff"}, ".m4b": {"iso_bmff"},
    ".avi": {"avi"},
    ".flac": {"flac"},
    ".ogg": {"ogg"}, ".opus": {"ogg"},
    ".wav": {"wav"},
    ".mp3": {"mp3"},
    ".pdf": {"pdf"},
    ".epub": {"zip"}, ".cbz": {"zip"}, ".cbr": {"rar"},
}

# Extensions the probe lane knows how to reason about at all. Anything else is
# left to the fast lane.
VALIDATABLE = frozenset(EXPECTED)

# What a file could plausibly be if it were merely mislabelled rather than
# malicious. Nothing inside its own family is ever accused: an `.mkv` that is
# really an AVI is someone's bad rename, and deleting a real release over that
# is a worse outcome than missing it.
FAMILY = {
    "video": {"matroska", "iso_bmff", "avi", "riff", "ogg", "mp3", "flac", "wav"},
    "audio": {"flac", "mp3", "ogg", "wav", "riff", "iso_bmff", "matroska"},
    "book": {"zip", "rar", "pdf", "ole_compound", "gzip"},
}
_EXT_FAMILY = {}
for _exts, _fam in ((".mkv .webm .mp4 .m4v .mov .avi", "video"),
                    (".m4a .m4b .flac .ogg .opus .wav .mp3", "audio"),
                    (".pdf .epub .cbz .cbr", "book")):
    for _e in _exts.split():
        _EXT_FAMILY[_e] = _fam

# Types we are willing to call a lie on. A guess that rests on two or three
# ambiguous bytes stays out of this set: being sure enough to accuse is a higher
# bar than being able to guess.
CONFIDENT = {"matroska", "iso_bmff", "avi", "wav", "flac", "ogg", "pdf", "mp3",
             "windows_pe", "dos_mz", "elf", "script", "zip", "rar", "7z",
             "ole_compound", "jpeg", "png", "gzip"}


# How to say a detected type out loud. Evidence stores the machine-readable
# name so history stays filterable; this is only for the sentence a human reads.
LABELS = {
    "windows_pe": "a Windows program", "dos_mz": "a Windows program",
    "elf": "a Linux program", "script": "a shell script",
    "ole_compound": "a Windows installer or Office document",
    "zip": "a ZIP archive", "rar": "a RAR archive", "7z": "a 7-Zip archive",
    "gzip": "a gzip archive", "jpeg": "a JPEG image", "png": "a PNG image",
    "pdf": "a PDF", "matroska": "a Matroska video", "iso_bmff": "an MP4 video",
    "avi": "an AVI video", "wav": "a WAV file", "flac": "a FLAC file",
    "ogg": "an Ogg file", "mp3": "an MP3", "riff": "a RIFF container",
}


def label(detected):
    """Human phrase for a detected type, falling back to the raw name."""
    return LABELS.get(detected, detected or "something unrecognised")


def ext_of(name):
    """Lowercased extension, tolerating anything that is not a usable string."""
    if not isinstance(name, str):
        return ""
    return posixpath.splitext(name)[1].lower()


def _has_pe_header(head):
    """Follow the DOS stub's e_lfanew to the PE signature, when we have the
    bytes to do it. Failing this downgrades the answer to `dos_mz`; it does not
    clear the file, because no media container may begin with "MZ" either."""
    if len(head) < 0x40:
        return False
    off = int.from_bytes(head[0x3c:0x40], "little")
    return head[off:off + 4] == b"PE\x00\x00"


def sniff(head):
    """Best-effort file type from a header. None means unrecognised, which is
    emphatically not the same as wrong."""
    if not head:
        return None
    for magic, name in _MAGIC:
        if head.startswith(magic):
            if name == "riff":
                return {b"AVI ": "avi", b"WAVE": "wav"}.get(head[8:12], "riff")
            if name == "dos_mz":
                return "windows_pe" if _has_pe_header(head) else "dos_mz"
            return name
    if len(head) >= 8 and head[4:8] in _BMFF_BOXES:
        return "iso_bmff"
    return None


def validate(filename, head, ready=True):
    """(state, detected, note) for one file's claimed extension against its
    real opening bytes.

    `ready` comes from the reader (see `probe.paths`) and answers a different
    question from any of these: whether those bytes are the file's data at all,
    rather than the zeros a sparse in-flight file reads back as. Unready data
    never reaches a judgement, because "could not read it" must never turn into
    evidence of badness.
    """
    e = ext_of(filename)
    expected = EXPECTED.get(e)
    if not expected:
        return UNKNOWN, None, f"no validator for {e or 'a file with no extension'}"
    if not ready or not head:
        return UNKNOWN, None, "no readable data yet"
    detected = sniff(head)
    if detected is None:
        return UNKNOWN, None, "unrecognised header"
    if detected in expected:
        return VALID, detected, f"header matches {e}"
    if detected in FAMILY.get(_EXT_FAMILY.get(e, ""), ()):
        return UNKNOWN, detected, (f"{detected} behind {e} looks like a "
                                   f"mislabelled release, not a fake")
    if detected not in CONFIDENT:
        return UNKNOWN, detected, f"header is not conclusive ({detected})"
    return INVALID, detected, f"claims {e} but the bytes are {detected}"
