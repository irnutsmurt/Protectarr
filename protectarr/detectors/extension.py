"""Does any file's extension appear in the monitored set?

Purely an observation: `extension_match` means the extension is one the user
asked to be told about, not that the file is malicious. Under a Media profile
that is critical; under a Software profile an `.exe` is the release.
"""

from ._util import ext, finding


def detect(files, det, ctx):
    exts = {e.lower() for e in det.get("blocked_extensions", [])}
    if not exts:
        return []
    out = []
    for f in files:
        name = f.get("name") or ""      # a null name must not abort the pass
        e = ext(name)
        if e in exts:
            out.append(finding("extension", "extension_match",
                               filename=name, extension=e))
    return out
