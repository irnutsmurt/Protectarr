"""Is this torrent archives-only, with no media the owning *arr could import?

Structurally suspicious, but risky on its own: plenty of legitimate scene
releases ship as RARs. So it stays opt-in and scoped to named indexers, and it
only applies to *arr-tracked torrents where "what counts as media" is knowable.

Resolving the indexer can cost an HTTP call, so `ctx["resolve_indexer"]` is only
invoked once there is an actual archive candidate to scope.
"""

from ._util import ext, finding, is_archive, media_exts


def detect(files, det, ctx):
    ad = det.get("archive_detection", {})
    if not ad.get("enabled") or not ctx.get("arr_tracked"):
        return []

    archive_exts = {e.lower() for e in ad.get("archive_extensions", [])}
    media = media_exts(ctx.get("arr_type"))
    first_archive = None
    for f in files:
        name = f.get("name") or ""
        if ext(name) in media:
            return []  # real media is present, so this is not that kind of fake
        if first_archive is None and is_archive(name, files, archive_exts):
            first_archive = name
    if not first_archive:
        return []

    # Only now is it worth resolving the indexer.
    resolve = ctx.get("resolve_indexer")
    indexer = resolve() if callable(resolve) else None
    allowed = {i.strip() for i in ad.get("indexers", []) if i.strip()}
    if not indexer or indexer not in allowed:
        return []
    return [finding("archive", "archive_no_media",
                    filename=first_archive, indexer=indexer,
                    arr_type=(ctx.get("arr_type") or "").lower())]
