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

_RAR_PART = re.compile(r"^\.r\d{2}$")   # .r00 .r01 ...
_NUM_PART = re.compile(r"^\.\d{3}$")    # .001 .002 ...  (split archives)


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


def is_archive(e, archive_exts):
    return e in archive_exts or bool(_RAR_PART.match(e)) or bool(_NUM_PART.match(e))


def media_exts(arr_type):
    """Media extensions for this *arr type; permissive union if unknown."""
    return MEDIA_BY_TYPE.get((arr_type or "").lower(),
                             VIDEO_EXTS | AUDIO_EXTS | BOOK_EXTS)
