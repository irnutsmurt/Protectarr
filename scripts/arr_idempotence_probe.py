#!/usr/bin/env python3
"""Throwaway probe: what does an *arr actually do when we repeat ourselves?

Not product code. Delete once the answers are written down.

Protectarr's crash-recovery design needs to know how the Servarr API behaves
when an operation is retried, and we have never tested it. The remediation path
currently assumes nothing, which is correct but means recovery cannot be built.
Three unknowns, in the order they block the design:

  1. DELETE /api/vN/queue/{id} for an id that is already gone.
     Blocks: whether a resumed remediation can safely re-issue the delete.

  2. DELETE with blocklist=true for a release that is ALREADY blocklisted.
     Duplicate entry, or no-op?
     Blocks: whether re-issuing is free or pollutes the blocklist.

  3. POST /api/vN/command <Search> issued twice in quick succession.
     Two commands or deduped? And does GET /command/{id} expose a status we
     could poll, which would make "re-search completed" verifiable rather than
     merely issued?
     Blocks: whether the requeue milestone can ever be confirmed.

THIS SCRIPT IS DESTRUCTIVE. Against the queue item you point it at, it will:
  remove it from the download client, blocklist the release, and trigger up to
  two searches for the same item.

Point it at a throwaway grab. It refuses to run without --confirm-destructive,
and it always shows you the target and waits for you to type the word.

No credential is printed or written to the report.

Usage
-----
    python scripts/arr_idempotence_probe.py --list
    python scripts/arr_idempotence_probe.py --arr Sonarr --queue-id 4412 \
        --confirm-destructive
"""

import os
import sys
import json
import time
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod                       # noqa: E402
from protectarr.arr import build_clients, _norm_title          # noqa: E402

QUEUE_FIELDS = ("id", "title", "status", "trackedDownloadStatus",
                "trackedDownloadState", "downloadId", "episodeId", "movieId",
                "seriesId", "albumId", "bookId", "indexer", "protocol",
                "errorMessage")


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def pick(d, keys):
    return {k: d.get(k) for k in keys if k in d}


def raw(resp):
    """Everything about a response that is safe to record."""
    body = None
    try:
        body = resp.json()
    except ValueError:
        body = (resp.text or "")[:2000]
    return {"status": resp.status_code, "reason": resp.reason, "body": body}


def blocklist_page(client, size=50):
    r = client._s.get(client._url("blocklist"),
                      params={"pageSize": size, "sortKey": "date",
                              "sortDirection": "descending"},
                      timeout=client.timeout)
    r.raise_for_status()
    return r.json().get("records", [])


def count_matching(records, title):
    """How many blocklist entries look like this release, exactly and loosely."""
    want, wantn = (title or "").lower(), _norm_title(title)
    exact = sum(1 for b in records if (b.get("sourceTitle") or "").lower() == want)
    norm = sum(1 for b in records if _norm_title(b.get("sourceTitle")) == wantn)
    return {"exact": exact, "normalized": norm}


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


def run(args):
    cfg_mod_cfg = cfg_mod.load()
    clients = build_clients(cfg_mod_cfg)
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

    target = pick(rec, QUEUE_FIELDS)
    _, _, rec_field = client.meta["search"]
    media_id = rec.get(rec_field)

    print("=" * 68)
    print("DESTRUCTIVE. This will remove and BLOCKLIST the following release,")
    print("then trigger up to two searches for it.")
    print("=" * 68)
    print(f"  app      {client.name} ({client.type})")
    print(f"  queue id {target.get('id')}")
    print(f"  title    {target.get('title')}")
    print(f"  hash     {(target.get('downloadId') or '')[:16]}")
    print(f"  {rec_field:<8} {media_id}")
    print("=" * 68)
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

    report = {"started": now(), "arr": client.name, "type": client.type,
              "target": target, "steps": []}

    def step(name, **data):
        print(f"\n--- {name} ---")
        for k, v in data.items():
            print(f"  {k}: {json.dumps(v, default=str)[:300]}")
        report["steps"].append({"at": now(), "step": name, **data})
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=2, default=str)

    title = target.get("title") or ""

    # ---- 0. baseline -------------------------------------------------------
    before = blocklist_page(client)
    step("blocklist before", total_records=len(before),
         matching=count_matching(before, title))

    # ---- 1. the real delete ------------------------------------------------
    r1 = client._s.delete(client._url(f"queue/{target['id']}"),
                          params={"removeFromClient": "true", "blocklist": "true",
                                  "skipRedownload": "true"},
                          timeout=client.timeout)
    step("DELETE queue (first)", response=raw(r1))

    # ---- 2. how long until the blocklist entry shows up --------------------
    appeared, waited = None, 0.0
    for _ in range(10):
        recs = blocklist_page(client)
        m = count_matching(recs, title)
        if m["exact"] or m["normalized"]:
            appeared = m
            break
        time.sleep(1.5)
        waited += 1.5
    step("blocklist after first delete", matching=appeared,
         seconds_waited=waited,
         note="None means it never appeared within 15s")

    # ---- 3. UNKNOWN #1: repeat the delete on a now-missing id --------------
    r2 = client._s.delete(client._url(f"queue/{target['id']}"),
                          params={"removeFromClient": "true", "blocklist": "true",
                                  "skipRedownload": "true"},
                          timeout=client.timeout)
    step("DELETE queue (repeat, id should be gone)", response=raw(r2),
         answers="UNKNOWN 1: is a resumed delete safe to re-issue?")

    # ---- 4. UNKNOWN #2: did the repeat duplicate the blocklist entry? ------
    time.sleep(2)
    after = blocklist_page(client)
    step("blocklist after repeat delete", matching=count_matching(after, title),
         total_records=len(after),
         answers="UNKNOWN 2: compare with 'blocklist after first delete'. "
                 "Same count means re-issuing is free.")

    # ---- 5. UNKNOWN #3: duplicate search commands -------------------------
    if not media_id:
        step("search", skipped=f"queue record carried no {rec_field}")
    else:
        cmd, ids_field, _ = client.meta["search"]
        c1 = client._s.post(client._url("command"),
                            json={"name": cmd, ids_field: [media_id]},
                            timeout=client.timeout)
        first = raw(c1)
        c2 = client._s.post(client._url("command"),
                            json={"name": cmd, ids_field: [media_id]},
                            timeout=client.timeout)
        second = raw(c2)
        id1 = (first.get("body") or {}).get("id") if isinstance(first.get("body"), dict) else None
        id2 = (second.get("body") or {}).get("id") if isinstance(second.get("body"), dict) else None
        step("POST command twice", first=first, second=second,
             same_command_id=(id1 is not None and id1 == id2),
             answers="UNKNOWN 3a: identical ids mean the *arr deduped.")

        statuses = {}
        for label, cid in (("first", id1), ("second", id2)):
            if not cid:
                continue
            time.sleep(2)
            try:
                cr = client._s.get(client._url(f"command/{cid}"),
                                   timeout=client.timeout)
                statuses[label] = raw(cr)
            except Exception as e:                              # noqa: BLE001
                statuses[label] = {"error": str(e)}
        step("GET command/{id}", statuses=statuses,
             answers="UNKNOWN 3b: if this reports a terminal status, the "
                     "requeue milestone can be VERIFIED rather than assumed.")

    report["finished"] = now()
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"\nWritten to {args.out}")
    print("\nSend this file back. It answers all three unknowns.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config")
    ap.add_argument("--list", action="store_true", help="show queues and exit")
    ap.add_argument("--arr", help="instance name, e.g. Sonarr")
    ap.add_argument("--queue-id", type=int, help="queue record id to sacrifice")
    ap.add_argument("--confirm-destructive", action="store_true")
    ap.add_argument("--out", default="captures/arr-idempotence.json")
    args = ap.parse_args()

    if args.config:
        cfg_mod.CONFIG_PATH = args.config
    elif os.environ.get("PROTECTARR_CONFIG"):
        cfg_mod.CONFIG_PATH = os.environ["PROTECTARR_CONFIG"]
    elif os.path.exists("config/config.yaml"):
        cfg_mod.CONFIG_PATH = "config/config.yaml"

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if args.arr and not args.queue_id:
        ap.error("--arr needs --queue-id (use --list to find one)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
