#!/usr/bin/env python3
"""Measure a rendered Protectarr page in a real browser engine.

Not product code. A layout bug is a claim about what a browser does, and
reasoning about intrinsic table widths from the CSS is exactly the kind of
guess that produces a fix which moves the problem to a different viewport.

Renders a page with the Flask test client, inlines the stylesheet so it works
from `file://`, injects a measuring script, and reads the numbers back out of
chromium's `--dump-dom`.

Usage
-----
    python scripts/layout_probe.py                 # default widths
    python scripts/layout_probe.py 1600 1280
"""

import os
import re
import sys
import json
import shutil
import tempfile
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tests"))

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIDTHS = [1600, 1440, 1366, 1280, 1100, 1024]

# Reported per viewport. `overflow` is the question the bug is about: how far
# the table extends past the box that is allowed to show it.
MEASURE = """
<div id="PROBE_RESULT"></div>
<script>
(function () {
  function box(el) {
    if (!el) return null;
    var r = el.getBoundingClientRect();
    return {left: Math.round(r.left), right: Math.round(r.right),
            width: Math.round(r.width)};
  }
  var wrap = document.querySelector('.card .body [style*="overflow-x"]')
          || document.querySelector('.card .body');
  var table = document.querySelector('table.applist') || document.querySelector('table');
  var out = {
    viewport: window.innerWidth,
    content: box(document.querySelector('.content')),
    card_body: box(document.querySelector('.card .body')),
    wrapper: box(wrap),
    table: box(table),
    table_scroll_width: table ? Math.round(table.scrollWidth) : null,
    wrapper_client_width: wrap ? Math.round(wrap.clientWidth) : null,
    columns: [],
    details: null,
    details_clipped: null,
    page_scrolls_horizontally:
      document.documentElement.scrollWidth > document.documentElement.clientWidth
  };
  var heads = table ? table.querySelectorAll('thead th') : [];
  var firstRow = table ? table.querySelector('tbody tr') : null;
  var cells = firstRow ? firstRow.children : [];
  for (var i = 0; i < heads.length; i++) {
    out.columns.push({
      name: (heads[i].textContent || '').trim() || '(unlabelled)',
      width: Math.round(heads[i].getBoundingClientRect().width),
      cell_scroll: cells[i] ? Math.round(cells[i].scrollWidth) : null
    });
  }
  var btn = document.querySelector('tbody button');
  if (btn) {
    out.details = box(btn);
    var limit = wrap ? wrap.getBoundingClientRect().right : window.innerWidth;
    out.details_clipped = Math.round(out.details.right - limit);
  }
  // Tallest release cell, to show wrapping pressure rather than assert on px.
  var rel = document.querySelectorAll('tbody tr td:nth-child(2)');
  out.release_max_height = 0;
  for (var j = 0; j < rel.length; j++) {
    out.release_max_height = Math.max(out.release_max_height,
                                      Math.round(rel[j].getBoundingClientRect().height));
  }
  document.getElementById('PROBE_RESULT').textContent = JSON.stringify(out);
})();
</script>
"""


# Real release names, because the bug is about content width and a fixture
# called "Rel" measures nothing. These are the ones from the reported
# screenshot plus the two longest shapes the page can produce.
REAL = [
    ("Lioness 2023 S03E07 1080p HD h264-ETHEL", "Lioness", "settled"),
    ("Ted Lasso S04E07 1080p HEVC x265-MeGusta", "Ted Lasso", "settled"),
    ("The Mandalorian S02E07 720p WEB H264-GLHF[rarbg]", "The Mandalorian",
     "failed_unverified"),
    ("Les Murs vagabonds / Drifting Home / Ame wo Tsugeru Hyouryuu Danchi "
     "(2022) [Blu-Ray JPN 1080p-HEVC Multi VF / VOSTFR / English Sub]",
     "Drifting Home", "pending"),
]


def render():
    """The History page with the content shapes that actually occur."""
    from protectarr import config as cfg_mod
    d = tempfile.mkdtemp()
    cfg_mod.CONFIG_PATH = os.path.join(d, "config.yaml")
    import test_audit as ta
    from protectarr import events

    case = ta.TestHistoryPageRenders("test_an_empty_history_still_renders")
    case.setUp()
    for i, (title, media, milestone) in enumerate(REAL):
        events.record({
            "event_type": "detection", "dry_run": False,
            "remediation_id": f"rid{i}",
            "timestamp": "2026-09-12 23:17:45 -0700",
            "torrent": {"hash": f"{i}" * 40, "name": title,
                        "size": 1011654820, "category": "tv",
                        "indexer": "LimeTorrents (Prowlarr)"},
            "owner": {"type": "sonarr", "instance": "Sonarr", "media": media,
                      "release_title": title},
            "findings": [{"detector": "extension", "reason": "extension_match",
                          "evidence": {"filename": title + ".exe",
                                       "extension": ".exe"}}],
            "policy": {"profile": "media", "severity": "critical",
                       "decision": "block", "decisive_finding": 0},
            "peers_harvested": 83,
            "remediation": {
                "milestone": milestone, "source": "live", "recovered": False,
                "verification": ("history event and blocklist row both found"
                                 if milestone != "failed_unverified"
                                 else "no downloadFailed event for this infohash"),
                "history_event": 17725, "blocklist_row": 16,
                "search": {"command_id": 1126125, "state": "completed",
                           "result": "successful",
                           "message": "Completed search for 1 movies. "
                                      "0 reports downloaded."},
                "error": None},
            "action": {"result": "reaped", "decision": "arr_fail", "via": "arr",
                       "removed": True,
                       "blocklisted": milestone != "failed_unverified",
                       "queue_delete": "removed",
                       "verification": "history event and blocklist row both found",
                       "history_event": 17725, "blocklist_row": 16},
            "redownload": {"decision": "held", "reason": "not_yet_aired",
                           "airs": "2026-09-13"},
        })
    return case.client.get("/history").get_data(as_text=True)


def inline_css(html):
    with open(os.path.join(REPO, "protectarr", "static", "style.css")) as fh:
        css = fh.read()
    return re.sub(r'<link rel="stylesheet"[^>]*>',
                  "<style>" + css + "</style>", html, count=1)


def probe(html, width, height=900):
    path = os.path.join(tempfile.mkdtemp(), "page.html")
    with open(path, "w") as fh:
        fh.write(html.replace("</body>", MEASURE + "</body>"))
    out = subprocess.run(
        ["chromium", "--headless", "--disable-gpu", "--no-sandbox",
         f"--window-size={width},{height}", "--virtual-time-budget=3000",
         "--dump-dom", "file://" + path],
        capture_output=True, text=True, timeout=90).stdout
    m = re.search(r'<div id="PROBE_RESULT">(\{.*?\})</div>', out, re.S)
    if not m:
        return None
    return json.loads(m.group(1).replace("&quot;", '"'))


def main():
    widths = [int(a) for a in sys.argv[1:]] or WIDTHS
    if not shutil.which("chromium"):
        print("chromium not found on PATH")
        return 2
    html = inline_css(render())
    for w in widths:
        r = probe(html, w)
        print("=" * 68)
        if not r:
            print(f"viewport {w}: measurement failed")
            continue
        over = (r["table_scroll_width"] or 0) - (r["wrapper_client_width"] or 0)
        print(f"viewport {w}  content={r['content']['width']}  "
              f"wrapper={r['wrapper_client_width']}  "
              f"table={r['table_scroll_width']}  overflow={over:+}")
        if r["details"]:
            print(f"  Details button: right={r['details']['right']} "
                  f"width={r['details']['width']} "
                  f"clipped_by={r['details_clipped']:+}"
                  f"   {'CLIPPED' if r['details_clipped'] > 0 else 'visible'}")
        print(f"  tallest Release cell: {r['release_max_height']}px"
              f"   page scrolls horizontally: {r['page_scrolls_horizontally']}")
        print("  columns:")
        for c in r["columns"]:
            print(f"     {c['name'][:14]:<14} width={c['width']:>5}  "
                  f"cell_min={c['cell_scroll']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
