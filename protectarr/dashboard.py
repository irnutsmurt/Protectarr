"""One bounded pass over events.jsonl, for the whole Dashboard.

The Dashboard asks several questions of the same history: how many remediations
in the last day, which findings and indexers in the last week, and what the most
recent entries were. Asking them separately would walk the file once per card,
and the file is up to 15 MiB across its rotation set.

So there is one newest-first walk and every card reads from its result.

Two limits stop it, whichever comes first:

    the time window   nothing older than 7 days can affect any card, and
                      `events.iter_events` yields newest first, so the first
                      event outside the window ends the walk.

    the parsed-event  the window alone is not a bound. A user who turns
    cap               Protectarr loose on a large backlog can write the whole
                      retained store inside one afternoon, and then "the last
                      24 hours" is every event there is. Measured at the
                      retention ceiling that is 141 ms; capped at 2,000 it is
                      18.5 ms, and the normal case never reaches the cap at all
                      (a 7-day window over a store spread across months stops
                      after about 800 events, in 7 ms).

The cap counts events *parsed*, not events that qualify. Parsing is 91% of the
cost - the same walk without `json.loads` is 12.3 ms against 138.5 ms with it -
so a cap on qualifying events would let a store full of dry runs spend the
whole budget and still claim to be bounded.

When the cap stops the walk the numbers become lower bounds, and they say so.
`truncated` is what the page renders as `643+` rather than `643`. It is never
the cap itself: the count displayed is always events actually counted, so
`2000+` can only appear if 2,000 really were.
"""

import time
import calendar
import itertools
from collections import Counter

from . import events

DAY = 86400
WINDOW_24H = DAY
WINDOW_7D = 7 * DAY

# Measured. See the module docstring; 2,000 is where the worst case lands at
# 18.5 ms while leaving the normal case untouched, because the normal case
# stops on the window long before it gets here.
EVENT_CAP = 2000

# Findings and indexers are ranked lists, not exhaustive ones. Eight is what
# fits a half-width card at desktop widths without the card becoming the page.
TOP_N = 8

# Rows folded for the Recent Activity card and for matching the Triage Queue to
# its History detail. Five are shown; the rest exist so that a `failed_unverified`
# intent opened a few days ago can still find its own history entry and offer a
# Details dialog. Bounded by the same pass, so it costs parses already paid for.
FOLD_ROWS = 60
RECENT_ROWS = 5

# An action that removed something. `partial` belongs here: the destructive half
# went through and the follow-up did not, which is a remediation that needs
# looking at, not a remediation that did not happen. `warned` does not - nothing
# was removed - and neither does `would_reap`, which is a dry run.
REMOVED_RESULTS = ("reaped", "partial")

# Shown when an event records no indexer. The category-fallback delete has no
# owning *arr and therefore no indexer, and that is what this is: a release
# Protectarr acted on whose origin it cannot name. It is deliberately not filled
# in from the torrent's qBittorrent category - `stats.by_indexer` does exactly
# that and is wrong because of it.
UNKNOWN_INDEXER = "Unknown"


def parse_ts(text):
    """`"2026-09-15 14:22:40 -0700"` -> epoch seconds, or None.

    Fixed-width slicing rather than `strptime`, because this runs on every
    parsed event and `strptime` costs 7.9 us against 1.6 us - 15.7 ms of the
    worst-case budget instead of 3.2 ms.

    The offset is applied rather than ignored. Comparing the first 19 bytes
    lexicographically is faster still and is what an earlier draft did, but it
    compares wall clock: across a daylight-saving change the same wall clock
    is two different instants, so an hour of events sorts wrongly twice a year
    and the 24-hour window silently moves.
    """
    if not text or len(text) < 19:
        return None
    try:
        at = calendar.timegm((int(text[0:4]), int(text[5:7]), int(text[8:10]),
                              int(text[11:13]), int(text[14:16]),
                              int(text[17:19]), 0, 1, -1))
    except (ValueError, TypeError):
        return None
    off = text[20:25]
    if len(off) == 5 and off[0] in "+-":
        try:
            delta = int(off[1:3]) * 3600 + int(off[3:5]) * 60
        except ValueError:
            return at
        at -= -delta if off[0] == "-" else delta
    return at


class _Window:
    """Accumulates the windowed counts as events stream past.

    A class rather than a closure because the same instance is wrapped around
    the stream *and* read afterwards: the History fold downstream stops as soon
    as it has its rows, so whoever owns this has to drain the rest of the
    window itself. See `collect`.
    """

    def __init__(self, now, cap):
        self.now = now
        self.cap = cap
        self.cutoff = now - WINDOW_7D
        self.day_cutoff = now - WINDOW_24H
        self.remediations_24h = 0
        self.findings = Counter()
        self.indexers = Counter()
        self.scanned = 0
        self.truncated = False
        self.stopped = False

    def observe(self, ev):
        """Fold one event in. False means the walk should stop here."""
        at = parse_ts(ev.get("timestamp"))
        # A record whose timestamp is unreadable cannot be placed in a window,
        # so it is not counted - but it is not a reason to stop either. One
        # corrupt line must not truncate the history behind it.
        if at is not None and at < self.cutoff:
            self.stopped = True
            return False
        if at is None or ev.get("dry_run"):
            return True
        # Lifecycle events carry no finding, no indexer and no action; they
        # report where an earlier remediation got to. Counting them would make
        # one reap look like three.
        if ev.get("event_type") == "remediation":
            return True
        # Every live detection contributes its finding, whether or not anything
        # was removed: Protectarr looked at this release and found something,
        # and a warn-only deployment reporting "no findings" would be saying the
        # opposite of what it is doing. The decisive finding only - counting all
        # of them would put the total above the number of events and stop it
        # being comparable to the remediation count beside it.
        _, decisive, _, _ = events.normalize(ev)
        if decisive:
            self.findings[events.category(decisive)] += 1
        # The rest is about removal, so it needs one to have happened.
        if (ev.get("action") or {}).get("result") not in REMOVED_RESULTS:
            return True
        if at >= self.day_cutoff:
            self.remediations_24h += 1
        self.indexers[(ev.get("torrent") or {}).get("indexer")
                      or UNKNOWN_INDEXER] += 1
        return True

    def wrap(self, stream):
        """Pass events through, folding each in, stopping on the window."""
        for ev in itertools.islice(stream, self.cap):
            self.scanned += 1
            if not self.observe(ev):
                return
            yield ev

    def ranked(self, counter):
        """Top-N, highest first, ties broken by name so the order is stable.

        Without the name tiebreak two equal counts swap places between loads
        for no reason the reader can see, which reads as data changing.
        """
        return [{"label": k, "count": v}
                for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
                ][:TOP_N]


def collect(now=None, cap=None, fold=None, fold_rows=FOLD_ROWS):
    """Walk the history once and return everything the Dashboard needs.

    `fold` is the History row folder, injected rather than imported so this
    module does not depend on the WebUI. It is given a lazy stream of live
    events and is expected to stop early; the drain afterwards is what finishes
    the window it left unread.

    `cap` defaults to None and is resolved here rather than in the signature.
    A default argument binds once at import, so `cap=EVENT_CAP` would freeze
    the value and leave the module constant looking authoritative while being
    ignored - which is exactly how the truncation path went untested.
    """
    now = time.time() if now is None else now
    cap = EVENT_CAP if cap is None else cap
    win = _Window(now, cap)
    stream = events.iter_events()
    counted = win.wrap(stream)
    # Dry runs are filtered here rather than by `iter_events(dry_run=False)` so
    # that they are still counted against the cap. They cost a parse either way,
    # and a cap that did not count them would not bound anything.
    live = (ev for ev in counted if not ev.get("dry_run"))

    rows = fold(live, limit=fold_rows) if fold else []

    # The fold stopped as soon as it had its rows, which is usually long before
    # the window is exhausted. Finish the walk so the 7-day cards are complete.
    for _ in counted:
        pass

    # Only the cap can truncate. Stopping on the window means everything that
    # could matter was read, however few events that turned out to be.
    if not win.stopped and win.scanned >= cap:
        win.truncated = next(stream, None) is not None

    return {
        "remediations_24h": win.remediations_24h,
        "findings": win.ranked(win.findings),
        "indexers": win.ranked(win.indexers),
        "findings_total": sum(win.findings.values()),
        "indexers_total": sum(win.indexers.values()),
        "truncated": win.truncated,
        "scanned": win.scanned,
        "cap": cap,
        "rows": rows,
    }
