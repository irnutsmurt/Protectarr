"""Does a text-like companion file carry a lure name?

The fakes ship a `README.txt` / `PASSWORD.url` / `HOW TO PLAY.nfo` next to the
payload telling you where to get the "password" or "codec". Matching is limited
to text-like extensions so a legitimate release simply named `Password.mkv` is
never a false positive.
"""

import posixpath

from ._util import ext, finding, LURE_EXTS


def detect(files, det, ctx):
    keywords = [k.lower() for k in det.get("blocked_name_keywords", [])]
    if not keywords:
        return []
    out = []
    for f in files:
        name = f.get("name") or ""
        if ext(name) not in LURE_EXTS:
            continue
        base = posixpath.basename(name).lower()
        hit = next((k for k in keywords if k in base), None)
        if hit:
            out.append(finding("filename", "lure_filename",
                               filename=name, keyword=hit))
    return out
