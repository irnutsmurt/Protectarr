#!/usr/bin/env python3
"""PR2 acceptance test: one real release through the whole remediation flow.

This is a validation run, not a redesign exercise. It calls the SAME functions
production calls - `core.apply_actions` for the destructive half and
`intents.reconcile` for the search follow-up - so a pass here is evidence about
the shipped code rather than about a parallel implementation written to agree
with it.

    finding -> intent persisted -> DELETE -> history lookup by UPPERCASE hash
    above the watermark -> blocklist correlation -> removed -> search issued ->
    command id persisted -> polled -> terminal state recorded -> settled

The thing this has to prove, and the reason the before/after snapshots are so
detailed: that the oracle picked the event and blocklist row THIS remediation
produced, and not an older historical record for the same movie. So every
pre-existing downloadFailed event for the infohash and every pre-existing
blocklist row for the media id is captured first, and the selected ids are
checked against both sets afterwards.

Pick a movie that has been blocklisted before if you can. Then "it did not pick
the old row" is a claim with something to be wrong about.

THIS SCRIPT IS DESTRUCTIVE. Against the queue item you point it at, it will
remove it from qBittorrent, blocklist the release, and trigger a search.

No credential is printed or written to the report.

Usage
-----
    # Outside the container the config is not at /config, so point at it:
    PROTECTARR_CONFIG=config/config.yaml \
        python scripts/radarr_e2e_validation.py --list

    PROTECTARR_CONFIG=config/config.yaml \
        python scripts/radarr_e2e_validation.py --arr "Radarr Anime" \
        --queue-id 12 --confirm-destructive

Writes to the real intents.json and stats.json, deliberately. A validation run
that used a scratch directory would be validating the scratch directory.
"""

import os
import sys
import time
import json
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod                        # noqa: E402
from protectarr.arr import build_clients                        # noqa: E402


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def list_queues(clients):
    for c in clients:
        print(f"\n=== {c.name} ({c.type}) ===")
        try:
            q = c.queue_by_hash()
        except Exception as e:                                  # noqa: BLE001
            print(f"  queue unreadable: {e}")
            continue
        if not q:
            print("  queue empty")
            continue
        for h, rec in q.items():
            print(f"  id={rec.get('id'):<8} {rec.get('title')}")
            print(f"           hash={h[:16]} status={rec.get('status')} "
                  f"tracked={rec.get('trackedDownloadStatus')}")


def snapshot(client, thash, media_ids):
    """Everything that already exists, so 'it picked the new one' is checkable."""
    events = client.failed_events(thash)
    rows = client.blocklist_rows()
    mine = [r for r in rows if client._media_ids(r) & media_ids] if media_ids else []
    return {
        "watermark": client.history_watermark(),
        "failed_event_ids": sorted(e.get("id") for e in events),
        "failed_event_titles": [e.get("sourceTitle") for e in events],
        "blocklist_rows_total": len(rows),
        "blocklist_rows_for_this_media": sorted(r.get("id") for r in mine),
        "blocklist_titles_for_this_media": [r.get("sourceTitle") for r in mine],
    }


def run(args):
    cfg = cfg_mod.load()
    clients = build_clients(cfg)
    if args.list or not args.arr:
        list_queues(clients)
        return 0

    client = next((c for c in clients if c.name == args.arr), None)
    if client is None:
        print(f"No *arr called {args.arr!r}. Known: "
              f"{', '.join(c.name for c in clients)}")
        return 2

    queue = client.queue_by_hash()
    rec = next((r for r in queue.values() if r.get("id") == args.queue_id), None)
    if rec is None:
        print(f"Queue id {args.queue_id} not found on {client.name}.")
        return 2

    thash = (rec.get("downloadId") or "").lower()
    media_ids = client._media_ids(rec)

    print("=" * 72)
    print("DESTRUCTIVE. This removes and BLOCKLISTS the following release,")
    print("then triggers a replacement search for it.")
    print("=" * 72)
    print(f"  app         {client.name} ({client.type})")
    print(f"  queue id    {rec.get('id')}")
    print(f"  title       {rec.get('title')}")
    print(f"  hash        {thash}")
    print(f"  media ids   {sorted(media_ids) or 'none on the queue record'}")
    print("=" * 72)
    if not args.confirm_destructive:
        print("\nRefusing: pass --confirm-destructive to proceed.")
        return 1
    try:
        if input('\nType "reap" to continue: ').strip() != "reap":
            print("aborted")
            return 1
    except EOFError:
        print("aborted (no tty)")
        return 1

    # Imported late so the config path above is already settled.
    from protectarr import core, events, intents, detectors
    from protectarr.qbit import QbitClient

    report = {"started": now(), "arr": client.name, "type": client.type,
              "hash": thash, "queue_id": rec.get("id"),
              "title": rec.get("title"), "media_ids": sorted(media_ids),
              "steps": []}

    def step(name, **data):
        print(f"\n--- {name} ---")
        for k, v in data.items():
            print(f"  {k}: {json.dumps(v, default=str)[:400]}")
        report["steps"].append({"at": now(), "step": name, **data})
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=2, default=str)

    # ---- 0. what already exists -------------------------------------------
    before = snapshot(client, thash, media_ids)
    step("BEFORE", **before)

    # ---- 1. the real production path --------------------------------------
    qc = cfg["qbittorrent"]
    qb = QbitClient(qc["url"], qc.get("username", ""), qc.get("password", ""),
                    api_key=qc.get("api_key", ""),
                    verify_ssl=qc.get("verify_ssl", True))
    qb.login()

    find = detectors.finding("extension", "extension_match",
                             filename="PR2-VALIDATION.exe", extension=".exe")
    action = {
        "hash": thash, "name": rec.get("title"), "bad_file": "PR2-VALIDATION.exe",
        "reason": "PR2 end-to-end validation", "finding": find, "findings": [find],
        "policy": {"profile": "media", "severity": "critical",
                   "decision": "block", "decisive_finding": 0},
        "size": rec.get("size") or 0, "category": "", "tags": "",
        "decision": "arr_fail", "safety_mode": "validation", "arr": client.name,
        "_owner": (client, rec), "_qb": qb,
    }
    live = dict(cfg)
    live["dry_run"] = False          # the whole point; the config's own value
                                     # is deliberately not consulted here
    state = {"stats": core.load_stats()}

    started = time.time()
    core.apply_actions([action], state, live)
    step("apply_actions returned", seconds=round(time.time() - started, 2))

    recorded = events.read()[0]
    step("event recorded", action=recorded.get("action"),
         redownload=recorded.get("redownload"))

    intent = intents.get(thash)
    step("intent after the destructive half",
         milestone=(intent or {}).get("milestone"),
         watermark=(intent or {}).get("watermark"),
         evidence=(intent or {}).get("evidence"),
         search=(intent or {}).get("search"),
         error=(intent or {}).get("error"))

    # ---- 2. did it pick the NEW records? ----------------------------------
    ev = ((intent or {}).get("evidence") or {}).get("event") or {}
    row = ((intent or {}).get("evidence") or {}).get("blocklist") or {}
    checks = {
        "event id is above the pre-DELETE watermark":
            bool(ev.get("id")) and ev["id"] > (before["watermark"] or 0),
        "event id did not exist before":
            bool(ev.get("id")) and ev["id"] not in before["failed_event_ids"],
        "blocklist row did not exist before":
            bool(row.get("id"))
            and row["id"] not in before["blocklist_rows_for_this_media"],
        "the *arr attributes the failure to us":
            ev.get("message") == "Manually marked as failed",
    }
    step("ORACLE SELECTED THE NEW RECORDS", checks=checks,
         selected_event=ev, selected_blocklist_row=row,
         pre_existing_event_ids=before["failed_event_ids"],
         pre_existing_row_ids=before["blocklist_rows_for_this_media"])

    # ---- 3. follow the search to a terminal state -------------------------
    for attempt in range(args.search_polls):
        intent = intents.get(thash)
        if (intent or {}).get("milestone") == intents.SETTLED:
            break
        intents.reconcile([client])
        time.sleep(args.poll_seconds)

    intent = intents.get(thash)
    step("intent after the search follow-up",
         milestone=(intent or {}).get("milestone"),
         search=(intent or {}).get("search"))

    after = snapshot(client, thash, media_ids)
    step("AFTER", **after)

    # ---- 4. verdict --------------------------------------------------------
    final = (intent or {}).get("milestone")
    verdict = {
        "milestone reached settled": final == intents.SETTLED,
        "search command id persisted":
            bool(((intent or {}).get("search") or {}).get("command_id")),
        "search reached a terminal state":
            ((intent or {}).get("search") or {}).get("state") in intents.TERMINAL,
        **checks,
    }
    step("VERDICT", final_milestone=final, checks=verdict,
         passed=all(verdict.values()))

    print("\n" + "=" * 72)
    for name, ok in verdict.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print("=" * 72)
    print(f"\nFull report: {args.out}")
    return 0 if all(verdict.values()) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="show every queue and exit")
    ap.add_argument("--arr", help="instance name from config.yaml")
    ap.add_argument("--queue-id", type=int, help="queue record id to reap")
    ap.add_argument("--confirm-destructive", action="store_true")
    ap.add_argument("--search-polls", type=int, default=20)
    ap.add_argument("--poll-seconds", type=float, default=3.0)
    ap.add_argument("--out", default="captures/radarr-e2e-validation.json")
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
