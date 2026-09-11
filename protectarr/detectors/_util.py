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


def ext(name):
    return posixpath.splitext(name)[1].lower()


def is_archive(e, archive_exts):
    return e in archive_exts or bool(_RAR_PART.match(e)) or bool(_NUM_PART.match(e))


def media_exts(arr_type):
    """Media extensions for this *arr type; permissive union if unknown."""
    return MEDIA_BY_TYPE.get((arr_type or "").lower(),
                             VIDEO_EXTS | AUDIO_EXTS | BOOK_EXTS)
