"""Finding the bytes on disk, and deciding whether they are real bytes yet.

Two problems, separated on purpose:

*Where is the file?* qBittorrent reports paths from its own filesystem, which in
Docker is rarely the one Protectarr sees, so the user supplies mappings. Files
still downloading may also carry qBittorrent's `.!qB` incomplete suffix.

*Are the bytes there?* A sparse file reads back as zeros rather than failing, so
"I read a header" and "I read the file's header" are different claims. Readiness
is answered here and nowhere else, so that a validator is never handed padding
and never gets the chance to call it a lie.
"""

import collections
import posixpath

INCOMPLETE_SUFFIX = ".!qB"

# data: what was read (may be short). path: what was actually opened, which is
# worth logging because a wrong path mapping is the likeliest failure. ready:
# whether `data` is the file's own bytes. why: for the log when it is not.
Read = collections.namedtuple("Read", "data path ready why")


def parse_mappings(raw):
    """Config -> [(qbittorrent_prefix, local_prefix)], longest prefix first.

    Accepts either form, because both turn up in hand-written YAML:

        path_mappings:
          - {from: /downloads, to: /mnt/dl}
          - "/downloads = /mnt/dl"
    """
    out = []
    for item in raw or []:
        src = dst = ""
        if isinstance(item, dict):
            src = str(item.get("from") or item.get("src") or "")
            dst = str(item.get("to") or item.get("dst") or "")
        elif isinstance(item, str) and "=" in item:
            src, _, dst = item.partition("=")
        src, dst = src.strip().rstrip("/"), dst.strip().rstrip("/")
        if src and dst:
            out.append((src, dst))
    # Longest first, so /downloads/tv wins over /downloads when both are listed.
    return sorted(out, key=lambda m: len(m[0]), reverse=True)


def map_path(path, mappings):
    """Translate a qBittorrent path into one this process can open."""
    if not path:
        return path
    for src, dst in mappings:
        if path == src or path.startswith(src + "/"):
            return dst + path[len(src):]
    return path


def local_path(torrent, file_entry, single, mappings):
    """Where this torrent's file should live on our side of the mapping.

    `content_path` is used rather than `save_path` because qBittorrent has
    already folded the incomplete-downloads directory into it. For a single-file
    torrent it *is* the file; otherwise it is the torrent's root folder and each
    file's `name` is relative to that.
    """
    base = torrent.get("content_path") or torrent.get("save_path") or ""
    if single:
        return map_path(base, mappings)
    name = (file_entry.get("name") or "").replace("\\", "/")
    return map_path(posixpath.join(base, name), mappings)


def read_head(path, nbytes):
    """Read a file's opening bytes, tolerating the incomplete-file suffix.

    Never raises: an unreadable file is a fact about our filesystem access, not
    about the torrent.
    """
    if not path:
        return Read(b"", None, False, "no path could be worked out for this file")
    for candidate in (path, path + INCOMPLETE_SUFFIX):
        try:
            with open(candidate, "rb") as fh:
                data = fh.read(nbytes)
        except OSError:
            continue
        if not data:
            return Read(b"", candidate, False, "file exists but is empty")
        # Checked across the whole read, not the first few bytes: an MP4 legally
        # opens with a four-byte box length that is very often 00 00 00 20.
        if not any(data):
            return Read(data, candidate, False,
                        "reads back as zeros (sparse or not yet flushed)")
        return Read(data, candidate, True, "")
    return Read(b"", None, False,
                f"not readable at {path} (check the probe path mapping)")


def describe_mappings(mappings):
    """One line for the log, so a misconfigured mapping is visible."""
    return ", ".join(f"{s} -> {d}" for s, d in mappings) or "none configured"
