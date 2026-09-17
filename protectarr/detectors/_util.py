"""Shared file-list helpers for the detectors."""

import re
import posixpath


def finding(detector, reason, **evidence):
    """One observation, plus what was seen. Facts only - no severity, no
    decision; see the note in this package's __init__."""
    return {"detector": detector, "reason": reason,
            "evidence": {k: v for k, v in evidence.items() if v not in (None, "")}}

# Media extensions per *arr type, for "is there any real media in here" checks.
VIDEO_EXTS = {".mkv", ".mp4", ".avi", ".m4v", ".mov", ".wmv", ".ts", ".m2ts",
              ".mpg", ".mpeg", ".flv", ".webm", ".vob", ".iso", ".divx", ".ogm"}
AUDIO_EXTS = {".flac", ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".alac",
              ".ape", ".wma", ".m4b"}
BOOK_EXTS = {".epub", ".mobi", ".azw", ".azw3", ".pdf", ".cbz", ".cbr", ".djvu",
             ".m4b", ".mp3"}
MEDIA_BY_TYPE = {
    "sonarr": VIDEO_EXTS, "radarr": VIDEO_EXTS, "whisparr": VIDEO_EXTS,
    "lidarr": AUDIO_EXTS, "readarr": BOOK_EXTS,
}

# Text-like companion files where fake "lures" live (readme / password / url
# notes). Keyword matching is limited to these, so a legit release simply titled
# "Password.mkv" is never a false positive.
LURE_EXTS = {".txt", ".nfo", ".htm", ".html", ".url", ".rtf", ".md", ".diz", ".doc"}

_RAR_PART = re.compile(r"^\.r\d{2}$")     # .r00 .r01 ...
_NUM_PART = re.compile(r"^\.(\d{3})$")    # .001 .002 ...  (split archives)


def detection_name(name):
    """The filename to derive an extension from, not the name to report.

    Windows silently drops trailing dots and spaces from a path, so `setup.exe `
    and `setup.exe.` both execute as `setup.exe` while reading as extensions
    `.exe ` and `.` to anything doing a literal split. Stripping them from the
    right closes that without touching anything else.

    Right side only: `strip(" .")` would also eat leading characters, and a file
    genuinely named ` .hidden` is not the same file as `hidden`.

    Deliberately NOT done here: homoglyph folding, zero-width removal, fullwidth
    punctuation mapping. Those are real evasions on paper, but we have not yet
    confirmed libtorrent even surfaces such names, and a character that only
    *looks* like `.exe` deserves a finding of its own rather than being quietly
    treated as though it were one.
    """
    if not isinstance(name, str):
        return ""
    return name.rstrip(" .")


def ext(name):
    """Lowercased extension. Tolerates anything that is not a usable string,
    because one malformed entry in a file list must never cost the findings
    from every other file in the torrent."""
    return posixpath.splitext(detection_name(name))[1].lower()


def _volume(name):
    """(stem, volume number) for a three-digit suffix, else (stem, None)."""
    root, e = posixpath.splitext(detection_name(name))
    m = _NUM_PART.match(e.lower())
    return root, (int(m.group(1)) if m else None)


def _is_archive_volume(name, files, archive_exts):
    """Is `.NNN` here a split-archive volume, or just the end of a name?

    "Three digits means split archive" was the rule until it was measured. The
    two commonest tokens in a scene video name are `H.264` and `H.265`, which
    are three digits, so a lone episode named
    `Yellowjackets.S03E02.1080p.WEB-DL.DDP5.1.H.264` read as an archive and
    could earn an `archive_no_media` finding - which `policy.judge` maps to
    block. Naming a file as an archive when it is not one is exactly the kind
    of assertion this codebase is not allowed to make.

    So a bare number proves nothing, and one of three things has to be true:

    * the stem already claims an archive, as in `release.7z.001`,
    * the stem has a contiguous family starting where split sets start. A set
      that begins at 264 is not a set; `.264` beside `.265` is one release
      offered in two codecs,
    * the stem has a sibling that is a real archive, as in `archive.rar`
      beside `archive.001`, where the family is one member long.

    Measured against thirteen cases, including every shape above: this answers
    all of them, where "any three digits" got eleven wrong and every simpler
    predicate got between two and ten wrong. Stems are compared exactly - a
    volume set is written by one tool in one pass, and loosening the comparison
    only ever makes the accusing answer more likely.
    """
    stem, num = _volume(name)
    if num is None:
        return False
    if ext(stem) in archive_exts:
        return True

    family, sibling = set(), False
    for other in files or ():
        oname = other.get("name") if isinstance(other, dict) else other
        oname = oname or ""
        ostem, onum = _volume(oname)
        if ostem != stem:
            continue
        if onum is not None:
            family.add(onum)
        elif ext(oname) in archive_exts:
            sibling = True
    if sibling:
        return True

    nums = sorted(family)
    return (len(nums) >= 2 and nums[0] in (0, 1)
            and nums == list(range(nums[0], nums[0] + len(nums))))


def is_archive(name, files, archive_exts):
    """Is this file an archive? `files` is the torrent's list, for volume sets.

    The file list is needed because a three-digit suffix is only meaningful in
    the company it keeps; see `_is_archive_volume`.
    """
    e = ext(name)
    return (e in archive_exts or bool(_RAR_PART.match(e))
            or _is_archive_volume(name, files, archive_exts))


def media_exts(arr_type):
    """Media extensions for this *arr type; permissive union if unknown."""
    return MEDIA_BY_TYPE.get((arr_type or "").lower(),
                             VIDEO_EXTS | AUDIO_EXTS | BOOK_EXTS)
