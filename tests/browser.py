"""A headless browser, if this machine actually has a working one.

`shutil.which("chromium")` is not the test, and assuming it was cost a red
master: GitHub's runners have chromium on PATH, it renders nothing when
invoked there, and every browser-backed test failed instead of skipping.

So the capability is probed once, by rendering a page whose marker is written
by a script rather than present in the source. That distinguishes a browser
that ran the page from one that exited, printed its input, or died on a
missing sandbox. Whichever argv survives the probe is the one the tests use,
so a machine that needs `--no-sandbox` gets it without every caller knowing.
"""
import os
import shutil
import tempfile
import subprocess

# The marker is not in the markup. A browser that cannot execute cannot print
# it, however helpfully it echoes the file it was handed.
PROBE_PAGE = """<!doctype html><meta charset="utf-8"><pre id="P"></pre>
<script>document.getElementById('P').textContent = 'headless-ok';</script>"""

DUMP = ["--headless", "--disable-gpu", "--hide-scrollbars", "--dump-dom"]

REASON = "no working headless browser on this machine"


def _candidates():
    for name in ("chromium", "chromium-browser", "chrome",
                 "google-chrome", "google-chrome-stable"):
        found = shutil.which(name)
        if not found:
            continue
        # Sandboxed first. `--no-sandbox` is what containers and root shells
        # need, and it is a real reduction in isolation, so it is the fallback
        # rather than the default.
        yield [found]
        yield [found, "--no-sandbox"]


def _probe():
    tmp = tempfile.mkdtemp(prefix="protectarr-browser-")
    try:
        page = os.path.join(tmp, "probe.html")
        with open(page, "w") as fh:
            fh.write(PROBE_PAGE)
        for argv in _candidates():
            try:
                r = subprocess.run(
                    argv + DUMP + ["--virtual-time-budget=2000",
                                   "file://" + page],
                    capture_output=True, text=True, timeout=120)
            except (OSError, subprocess.SubprocessError):
                continue
            if "headless-ok" in r.stdout:
                return argv
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return None


BROWSER = _probe()


def dom(path, width, height, budget=4000):
    """The rendered DOM of a local file at a given viewport size."""
    r = subprocess.run(
        BROWSER + DUMP + ["--window-size=%d,%d" % (width, height),
                          "--virtual-time-budget=%d" % budget,
                          "file://" + path],
        capture_output=True, text=True)
    return r.stdout
