#!/usr/bin/env python3
"""Throwaway capture harness: what happens when we steer a MULTI-FILE torrent.

Not product code. Nothing in `protectarr/` imports this, and it is expected to
be deleted once the question is answered.

The question
------------
The Sep 11 spike steered a SINGLE-file torrent, so "disable every other file"
was a no-op and the interesting risk was never exercised. On a season pack,
steering sets every file except one to priority 0. Does the owning *arr notice,
and if so does it call the download stalled, failed, or nothing at all?

Gemini hypothesised an *arr reacts badly to its main media file being set to
priority 0. That is a hypothesis. This script exists to make it an observation.

What it captures, per your list
-------------------------------
  before      qB torrent record, every file's priority, seq_dl, f_l_piece_prio,
              piece-state summary, and the *arr queue record
  during      the same, sampled on a timer, so *arr health is watched WHILE one
              file is selected and the rest are at priority 0, rather than only
              before and after. That sampling is the whole point: the single-file
              spike only looked either side and therefore proved nothing.
  after       the same again, plus an explicit diff against `before`
  anomalies   anything that changed underneath us mid-run (qB state, *arr status,
              file count) is recorded as an event rather than smoothed over

Everything lands in a timestamped JSON file plus a readable summary.

Safety
------
* Restores in a `finally`, including on Ctrl-C and on an exception.
* Restore is verified by read-back and the script says loudly if it failed.
* `--dry-run` (the default) captures the baseline and steers nothing.
* `--abandon` deliberately exits WITHOUT restoring, so the restart/reconcile
  path can be tested for real. It requires its own flag for obvious reasons.
* No credential is printed, logged or written to the capture file.

Usage
-----
    python scripts/probe_multifile_capture.py --list
    python scripts/probe_multifile_capture.py --hash <infohash> --steer
    python scripts/probe_multifile_capture.py --hash <infohash> --steer --abandon
"""

import os
import sys
import json
import time
import argparse
import datetime
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod                       # noqa: E402
from protectarr.qbit import QbitClient                         # noqa: E402
from protectarr.arr import build_clients                       # noqa: E402
from protectarr.probe import validators                        # noqa: E402

# Fields worth keeping off a qBittorrent torrent record. The whole record is
# noisy and changes between versions; these are the ones that would show an
# *arr or qBittorrent reacting to what we did.
QB_FIELDS = ("hash", "name", "state", "progress", "dlspeed", "upspeed", "eta",
             "num_seeds", "num_leechs", "num_complete", "num_incomplete",
             "seq_dl", "f_l_piece_prio", "priority", "category", "tags",
             "completed", "size", "total_size", "amount_left", "availability",
             "save_path", "content_path", "last_activity", "time_active")

# The *arr queue fields that carry health. trackedDownloadStatus is the one
# Gemini's hypothesis predicts will move.
ARR_FIELDS = ("id", "status", "trackedDownloadStatus", "trackedDownloadState",
              "errorMessage", "downloadId", "title", "sizeleft", "timeleft",
              "estimatedCompletionTime", "protocol", "indexer", "downloadClient")


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def pick(d, keys):
    return {k: d.get(k) for k in keys if k in d}


class Capture:
    """Accumulates samples and anomalies, then writes one JSON file."""

    def __init__(self, path):
        self.path = path
        self.doc = {"started": now(), "samples": [], "anomalies": [],
                    "phases": {}, "restore": None}

    def phase(self, name, data):
        self.doc["phases"][name] = {"at": now(), **data}
        self.save()

    def sample(self, data):
        self.doc["samples"].append({"at": now(), **data})
        self.save()

    def anomaly(self, what, detail):
        print(f"  !! ANOMALY: {what}: {detail}")
        self.doc["anomalies"].append({"at": now(), "what": what, "detail": detail})
        self.save()

    def save(self):
        with open(self.path, "w") as fh:
            json.dump(self.doc, fh, indent=2, default=str)


def piece_summary(states, target_first=None):
    """Piece states compress well: we only care about counts and our target."""
    counts = {0: 0, 1: 0, 2: 0}
    for s in states:
        counts[s] = counts.get(s, 0) + 1
    out = {"total": len(states), "unavailable": counts.get(0, 0),
           "downloading": counts.get(1, 0), "downloaded": counts.get(2, 0)}
    if target_first is not None and 0 <= target_first < len(states):
        out["target_piece"] = target_first
        out["target_state"] = states[target_first]
    return out


def arr_record(clients, torrent_hash):
    """Find this torrent in any *arr queue. Returns (client_name, record|None)."""
    for c in clients:
        try:
            q = c.queue_by_hash()
        except Exception as e:                                  # noqa: BLE001
            return c.name, {"_queue_read_failed": str(e)}
        rec = q.get(torrent_hash.lower())
        if rec:
            return c.name, pick(rec, ARR_FIELDS)
    return None, None


def snapshot(qb, clients, thash, target_first=None):
    """One complete observation of both systems."""
    snap = {}
    try:
        t = qb.torrent(thash)
        snap["qb"] = pick(t, QB_FIELDS) if t else None
    except Exception as e:                                      # noqa: BLE001
        snap["qb"] = {"_error": str(e)}
    try:
        snap["files"] = [{"index": i, "name": f.get("name"),
                          "priority": f.get("priority"),
                          "progress": f.get("progress"),
                          "size": f.get("size"),
                          "piece_range": f.get("piece_range")}
                         for i, f in enumerate(qb.files(thash))]
    except Exception as e:                                      # noqa: BLE001
        snap["files"] = {"_error": str(e)}
    try:
        snap["pieces"] = piece_summary(qb.piece_states(thash), target_first)
    except Exception as e:                                      # noqa: BLE001
        snap["pieces"] = {"_error": str(e)}
    name, rec = arr_record(clients, thash)
    snap["arr_instance"], snap["arr"] = name, rec
    return snap


def describe(snap, label):
    qb = snap.get("qb") or {}
    arr = snap.get("arr") or {}
    prios = [f.get("priority") for f in snap.get("files", [])
             if isinstance(f, dict)]
    # A 460-file season pack would print two kilobytes of "1, 1, 1" per sample
    # and bury the thing we are actually watching. The full list is in the
    # capture file; the console gets the histogram.
    hist = {}
    for p in prios:
        hist[p] = hist.get(p, 0) + 1
    summary = ", ".join(f"prio {p}: {n} file(s)" for p, n in sorted(hist.items()))
    print(f"  [{label}] qB state={qb.get('state')} progress={qb.get('progress'):.6f} "
          f"dl={(qb.get('dlspeed') or 0)//1024}KiB/s seq={qb.get('seq_dl')} "
          f"fl={qb.get('f_l_piece_prio')}")
    print(f"           {summary}")
    pieces = snap.get("pieces") or {}
    if "target_state" in pieces:
        print(f"           target piece {pieces['target_piece']} "
              f"state={pieces['target_state']} "
              f"({pieces.get('downloaded')}/{pieces.get('total')} pieces done)")
    if arr:
        print(f"           arr={snap.get('arr_instance')} "
              f"status={arr.get('status')} "
              f"tracked={arr.get('trackedDownloadStatus')}/"
              f"{arr.get('trackedDownloadState')} "
              f"err={arr.get('errorMessage')!r}")
    else:
        print(f"           arr=NOT IN ANY QUEUE")


# The three candidate steering strategies, as agreed with the PM. They differ
# only in what happens to the files we are NOT probing, which turns out to be
# the whole question: qBittorrent recomputes size/completed/amount_left/progress
# against the WANTED set, and the owning *arr follows that size.
#
#   zero      every other file to 0. Fastest to the target piece, and the one
#             we measured: it collapsed a 160.74 GB torrent to 1.81 GB of
#             "wanted" and armed a state where finishing one file would read as
#             finishing the season.
#   keepone   as zero, but one other INCOMPLETE file stays wanted at priority 1.
#             The torrent can then never reach 100% from the probe alone, which
#             is a structural invariant rather than a timing argument.
#   preserve  every originally-wanted file stays wanted, demoted to 1; the
#             target goes to 7. Nothing leaves the wanted set, so the accounting
#             never moves. Cleanest on paper. Untested until now, because it
#             also means the target competes with every other file for
#             bandwidth, which may defeat the point of steering.
STEER_MODES = {
    "zero": "all other files to priority 0 (current behaviour)",
    "keepone": "all others to 0, except one incomplete file held at 1",
    "preserve": "every originally-wanted file demoted to 1, none dropped",
}


def histogram(values):
    h = {}
    for v in values:
        h[v] = h.get(v, 0) + 1
    return h


def fmt_histogram(values):
    return ", ".join(f"prio {p}: {n} file(s)"
                     for p, n in sorted(histogram(values).items()))


def group_by_priority(plan):
    """{index: priority} -> {priority: [indices]}, so each priority is one call."""
    out = {}
    for i, p in plan.items():
        out.setdefault(p, []).append(i)
    return out


def steer_plan(mode, originals, idx, files):
    """The priority every file should hold during the probe.

    `originals` is {index: priority} as found. A file at 0 was already unwanted
    by the user, and no mode promotes it: we are measuring steering, not
    silently enlarging someone's download.
    """
    plan = {i: 0 for i in originals}
    plan[idx] = 7

    if mode == "zero":
        return plan

    if mode == "preserve":
        for i, p in originals.items():
            if i != idx and p:
                plan[i] = 1
        return plan

    if mode == "keepone":
        # Any other file that is both originally wanted and not yet complete.
        # Complete files cannot hold the torrent below 100%, so they are no use
        # as the invariant even though they are cheap to keep.
        for i, p in originals.items():
            if i == idx or not p:
                continue
            prog = (files[i].get("progress") if i < len(files) else 1.0) or 0.0
            if prog < 1.0:
                plan[i] = 1
                break
        else:
            raise SystemExit(
                "mode 'keepone' needs a second incomplete wanted file and this "
                "torrent has none. That is exactly the case where keepone "
                "degenerates into zero, so the comparison would be meaningless.")
        return plan

    raise SystemExit(f"unknown mode {mode!r}")


def wanted_bytes(files, plan):
    """What qBittorrent will call `size` once `plan` is applied."""
    return sum((f.get("size") or 0) for i, f in enumerate(files)
               if plan.get(i, 0) != 0)


def choose_target(files):
    """The file the probe lane would go for: biggest validatable one."""
    cands = [(i, f) for i, f in enumerate(files)
             if validators.ext_of(f.get("name") or "") in validators.VALIDATABLE]
    if not cands:
        return None, None
    idx, f = max(cands, key=lambda x: x[1].get("size") or 0)
    return idx, f


def list_candidates(qb, clients):
    print("Multi-file torrents currently downloading:\n")
    found = 0
    for t in qb.torrents(state_filter="downloading"):
        h = t.get("hash") or ""
        try:
            files = qb.files(h)
        except Exception as e:                                  # noqa: BLE001
            print(f"  {h[:8]}  {t.get('name')!r}: file list unreadable ({e})")
            continue
        if len(files) < 2:
            continue
        found += 1
        name, rec = arr_record(clients, h)
        idx, tgt = choose_target(files)
        print(f"  {h}")
        print(f"    name      {t.get('name')}")
        print(f"    state     {t.get('state')}  progress={t.get('progress'):.3f} "
              f"dl={(t.get('dlspeed') or 0)//1024} KiB/s seeds={t.get('num_seeds')}")
        print(f"    files     {len(files)}  category={t.get('category') or '-'}")
        print(f"    arr       {name or 'UNTRACKED'}"
              + (f"  tracked={rec.get('trackedDownloadStatus')}" if rec else ""))
        print(f"    target    {tgt.get('name') if tgt else 'NONE VALIDATABLE'}")
        print()
    if not found:
        print("  none. Start a season pack downloading and run this again.")
    return found


def run(args):
    qb = None
    cfg = cfg_mod.load()
    q = cfg["qbittorrent"]
    qb = QbitClient(q["url"], q.get("username", ""), q.get("password", ""),
                    api_key=q.get("api_key", ""),
                    verify_ssl=q.get("verify_ssl", True))
    qb.login()
    clients = build_clients(cfg)
    print(f"qBittorrent: {q['url']}")
    print(f"*arr apps:   {', '.join(c.name for c in clients) or 'none'}\n")

    if args.restore_from:
        return restore_from_capture(qb, args.restore_from)

    if args.list or not args.hash:
        list_candidates(qb, clients)
        if not args.hash:
            return 0

    thash = args.hash.lower()
    files = qb.files(thash)
    if len(files) < 2:
        print(f"ERROR: {thash[:8]} has {len(files)} file(s). This harness exists "
              f"for the MULTI-file case; a single-file torrent tells us nothing "
              f"we do not already know.")
        return 2

    idx, target = choose_target(files)
    if idx is None:
        print("ERROR: no validatable media file in this torrent, so the probe "
              "lane would never steer it and neither will this.")
        return 2
    first_piece = (target.get("piece_range") or [None])[0]

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = os.path.join(args.outdir, f"multifile-capture-{stamp}.json")
    os.makedirs(args.outdir, exist_ok=True)
    cap = Capture(out)
    cap.doc["target"] = {"index": idx, "name": target.get("name"),
                         "size": target.get("size"), "first_piece": first_piece}
    cap.doc["mode"] = ("abandon" if args.abandon else
                       "steer" if args.steer else "observe-only")

    print(f"Torrent  {thash}")
    print(f"Files    {len(files)}")
    print(f"Target   [{idx}] {target.get('name')}  first piece {first_piece}")
    print(f"Capture  {out}\n")

    before = snapshot(qb, clients, thash, first_piece)
    cap.phase("before", before)
    describe(before, "before")

    originals = {i: int(f.get("priority", 1) or 0) for i, f in enumerate(files)}
    orig_seq = bool((before.get("qb") or {}).get("seq_dl"))
    orig_fl = bool((before.get("qb") or {}).get("f_l_piece_prio"))
    cap.doc["originals"] = {"priorities": originals, "seq_dl": orig_seq,
                            "f_l_piece_prio": orig_fl}
    cap.save()

    if not args.steer:
        print("\nObserve-only (no --steer). Baseline captured, nothing changed.")
        return 0

    if (before.get("arr") or {}).get("_queue_read_failed"):
        print("\nREFUSING: an *arr queue could not be read, so *arr health "
              "during the steer would be unobservable, which is the one thing "
              "this run is for.")
        return 2

    steered = False
    try:
        print("\n--- steering ---")
        qb.set_sequential(thash, True)
        qb.set_first_last_prio(thash, True)
        plan = steer_plan(args.mode, originals, idx, files)
        kept, was = wanted_bytes(files, plan), wanted_bytes(files, originals)
        cap.doc["steer_plan"] = {"mode": args.mode,
                                 "histogram": histogram(plan.values()),
                                 "rationale": STEER_MODES[args.mode],
                                 "wanted_bytes_before": was,
                                 "wanted_bytes_predicted": kept}
        print(f"  wanted set {GiB(was):.2f} GiB -> {GiB(kept):.2f} GiB predicted"
              + (f" ({kept / was * 100:.1f}% retained)" if was else ""))
        for prio, ids in group_by_priority(plan).items():
            qb.set_file_priority(thash, ids, prio)
        steered = True
        print(f"  mode {args.mode}: {STEER_MODES[args.mode]}")
        print(f"  {fmt_histogram(plan.values())}, sequential on, first/last on")

        applied = snapshot(qb, clients, thash, first_piece)
        cap.phase("steered", applied)
        describe(applied, "steered")

        deadline = time.time() + args.seconds
        last_arr = json.dumps((applied.get("arr") or {}), sort_keys=True)
        last_state = (applied.get("qb") or {}).get("state")
        last_files = len(applied.get("files") or [])
        got = False
        while time.time() < deadline:
            time.sleep(args.interval)
            s = snapshot(qb, clients, thash, first_piece)
            cap.sample(s)
            describe(s, f"t+{int(time.time() - (deadline - args.seconds))}s")

            if s.get("qb") is None:
                cap.anomaly("torrent disappeared from qBittorrent", "mid-probe")
                break
            cur_state = (s.get("qb") or {}).get("state")
            if cur_state != last_state:
                cap.anomaly("qB state changed mid-probe",
                            f"{last_state} -> {cur_state}")
                last_state = cur_state
            cur_files = len(s.get("files") or [])
            if cur_files != last_files:
                cap.anomaly("file count changed mid-probe",
                            f"{last_files} -> {cur_files}")
                last_files = cur_files
            cur_arr = json.dumps((s.get("arr") or {}), sort_keys=True)
            if cur_arr != last_arr:
                cap.anomaly("*arr queue record changed mid-probe",
                            {"before": json.loads(last_arr),
                             "after": json.loads(cur_arr)})
                last_arr = cur_arr
            if s.get("arr") is None:
                cap.anomaly("*arr dropped the torrent from its queue",
                            "during steering")

            if (s.get("pieces") or {}).get("target_state") == 2:
                print("  target piece arrived")
                cap.phase("target_arrived", s)
                got = True
                break
        cap.doc["target_piece_arrived"] = got
        if not got:
            print(f"  target piece did not arrive within {args.seconds}s "
                  f"(not a failure: it is the starved-torrent case)")
        verdict(cap, idx, args.seconds)

        if args.abandon:
            print("\n--- ABANDONING WITHOUT RESTORING (--abandon) ---")
            print("The torrent is LEFT STEERED on purpose, so Protectarr's")
            print("reconcile path can be tested against a real interruption.")
            print("Restart Protectarr and watch it put this back:")
            print(f"  priorities {originals}")
            print(f"  seq_dl={orig_seq} f_l_piece_prio={orig_fl}")
            cap.doc["restore"] = {"skipped": True, "reason": "--abandon"}
            cap.save()
            steered = False          # stop the finally from undoing the point
            return 0

    except KeyboardInterrupt:
        print("\ninterrupted, restoring")
        cap.anomaly("interrupted by operator", "Ctrl-C")
    except Exception as e:                                      # noqa: BLE001
        cap.anomaly("harness raised", traceback.format_exc())
        print(f"\nERROR: {e}")
    finally:
        if steered:
            print("\n--- restoring ---")
            ok = restore(qb, thash, originals, orig_seq, orig_fl, cap)
            after = snapshot(qb, clients, thash, first_piece)
            cap.phase("after", after)
            describe(after, "after")
            cap.doc["diff"] = diff(before, after)
            cap.save()
            print(f"\nRestore verified: {ok}")
            if not ok:
                print("!! THE TORRENT IS STILL MODIFIED. Original settings:")
                print(f"   priorities {originals}")
                print(f"   seq_dl={orig_seq} f_l_piece_prio={orig_fl}")

    print(f"\nCapture written to {out}")
    return 0


def GiB(n):
    return (n or 0) / (1024.0 ** 3)


def verdict(cap, idx, seconds):
    """The six numbers the B-vs-C decision turns on, computed from the capture.

    Printed and stored, so two runs can be compared without re-reading raw JSON.
    A mode wins on getting the target piece inside the budget while NOT
    collapsing the wanted set; those pull against each other, which is the
    entire reason this has to be measured rather than argued.
    """
    phases, samples = cap.doc.get("phases", {}), cap.doc.get("samples", [])
    before = phases.get("before") or {}
    steered = phases.get("steered") or {}
    last = (phases.get("target_arrived") or (samples[-1] if samples else {}))

    b_qb, s_qb, l_qb = (before.get("qb") or {}), (steered.get("qb") or {}), (last.get("qb") or {})

    # 1. time to the target's opening piece
    t_arrive = None
    if cap.doc.get("target_piece_arrived"):
        t0 = steered.get("at")
        t1 = (phases.get("target_arrived") or {}).get("at")
        if t0 and t1:
            t_arrive = (datetime.datetime.fromisoformat(t1)
                        - datetime.datetime.fromisoformat(t0)).total_seconds()

    # 2/3. wanted size and the accounting that follows it
    acct = {k: {"before": b_qb.get(k), "steered": s_qb.get(k), "last": l_qb.get(k)}
            for k in ("size", "completed", "amount_left", "progress")}
    collapse = None
    if b_qb.get("size") and s_qb.get("size"):
        collapse = s_qb["size"] / b_qb["size"]

    # 4. did the *arr stay healthy for every single sample?
    seen = set()
    for s in [steered] + samples:
        a = s.get("arr")
        if a is None:
            seen.add("ABSENT-FROM-QUEUE")
        elif isinstance(a, dict):
            seen.add(f"{a.get('status')}/{a.get('trackedDownloadStatus')}/"
                     f"{a.get('trackedDownloadState')}/{a.get('errorMessage')!r}")

    # 5. where the bandwidth actually went
    def bytes_done(snap):
        out = {}
        for f in snap.get("files") or []:
            if isinstance(f, dict):
                out[f["index"]] = (f.get("size") or 0) * (f.get("progress") or 0)
        return out
    b0, b1 = bytes_done(steered), bytes_done(last)
    to_target = b1.get(idx, 0) - b0.get(idx, 0)
    to_others = sum(v - b0.get(i, 0) for i, v in b1.items() if i != idx)
    total = to_target + to_others
    share = (to_target / total) if total > 0 else None

    v = {"mode": cap.doc.get("steer_plan", {}).get("mode"),
         "seconds_budget": seconds,
         "target_piece_arrived": cap.doc.get("target_piece_arrived"),
         "seconds_to_target_piece": t_arrive,
         "accounting": acct,
         "wanted_size_ratio_after_steer": collapse,
         "arr_states_observed": sorted(seen),
         "arr_stayed_healthy": seen == {"downloading/ok/downloading/None"},
         "bytes_to_target": to_target,
         "bytes_to_other_files": to_others,
         "target_bandwidth_share": share}
    cap.doc["verdict"] = v
    cap.save()

    print("\n--- verdict ---")
    print(f"  mode                {v['mode']}")
    print(f"  target piece        "
          f"{'arrived in %.1fs' % t_arrive if t_arrive is not None else 'DID NOT ARRIVE'}"
          f"  (budget {seconds}s)")
    print(f"  wanted size         {GiB(b_qb.get('size')):.2f} GiB -> "
          f"{GiB(s_qb.get('size')):.2f} GiB"
          + (f"  ({collapse * 100:.1f}% retained)" if collapse else ""))
    print(f"  amount_left         {GiB(b_qb.get('amount_left')):.2f} GiB -> "
          f"{GiB(s_qb.get('amount_left')):.2f} GiB")
    print(f"  progress            {b_qb.get('progress')} -> {s_qb.get('progress')}")
    print(f"  *arr healthy        {v['arr_stayed_healthy']}  {v['arr_states_observed']}")
    print(f"  bandwidth to target {GiB(to_target) * 1024:.1f} MiB"
          + (f"  ({share * 100:.1f}% of all bytes)" if share is not None
             else "  (no bytes moved)"))
    print(f"  bandwidth elsewhere {GiB(to_others) * 1024:.1f} MiB")
    return v


def restore(qb, thash, originals, seq, fl, cap):
    """Put it back exactly, then read back and prove it."""
    by_prio = {}
    for i, p in originals.items():
        by_prio.setdefault(p, []).append(i)
    try:
        for p, ids in by_prio.items():
            qb.set_file_priority(thash, ids, p)
        qb.set_sequential(thash, seq)
        qb.set_first_last_prio(thash, fl)
    except Exception as e:                                      # noqa: BLE001
        cap.doc["restore"] = {"ok": False, "error": str(e)}
        return False
    try:
        now_prios = {i: f.get("priority") for i, f in enumerate(qb.files(thash))}
        info = qb.torrent(thash) or {}
    except Exception as e:                                      # noqa: BLE001
        cap.doc["restore"] = {"ok": False, "error": f"read-back failed: {e}"}
        return False
    bad = {i: (p, now_prios.get(i)) for i, p in originals.items()
           if now_prios.get(i) != p}
    flags = {}
    if bool(info.get("seq_dl")) != seq:
        flags["seq_dl"] = (seq, bool(info.get("seq_dl")))
    if bool(info.get("f_l_piece_prio")) != fl:
        flags["f_l_piece_prio"] = (fl, bool(info.get("f_l_piece_prio")))
    cap.doc["restore"] = {"ok": not (bad or flags), "priority_mismatch": bad,
                          "flag_mismatch": flags}
    return not (bad or flags)


def restore_from_capture(qb, path):
    """Undo a run that died before its `finally` could.

    The harness does not use Protectarr's probe ledger, so nothing else knows
    how to put this back. On a 460-file season pack "just fix it in the UI" is
    not a real answer, so the originals are written to the capture file BEFORE
    the first mutation and this reads them back.
    """
    with open(path) as fh:
        doc = json.load(fh)
    orig = doc.get("originals")
    thash = ((doc.get("phases", {}).get("before", {}) or {}).get("qb") or {}).get("hash")
    if not orig or not thash:
        print(f"ERROR: {path} has no recorded originals to restore from.")
        return 2
    priorities = {int(i): int(p) for i, p in orig["priorities"].items()}
    print(f"Restoring {thash[:16]} from {path}")
    print(f"  {len(priorities)} file priorities, seq_dl={orig['seq_dl']}, "
          f"f_l_piece_prio={orig['f_l_piece_prio']}")
    cap = Capture(path + ".restore")
    ok = restore(qb, thash, priorities, orig["seq_dl"], orig["f_l_piece_prio"], cap)
    print(f"Restore verified: {ok}")
    if not ok:
        print(json.dumps(cap.doc.get("restore"), indent=2))
    return 0 if ok else 1


def diff(before, after):
    """What is different between the two ends, field by field."""
    out = {}
    for section in ("qb", "arr"):
        b, a = before.get(section) or {}, after.get(section) or {}
        changed = {k: {"before": b.get(k), "after": a.get(k)}
                   for k in set(b) | set(a) if b.get(k) != a.get(k)}
        if changed:
            out[section] = changed
    bp = {f["index"]: f["priority"] for f in before.get("files", [])
          if isinstance(f, dict)}
    ap = {f["index"]: f["priority"] for f in after.get("files", [])
          if isinstance(f, dict)}
    pdiff = {i: {"before": bp.get(i), "after": ap.get(i)}
             for i in set(bp) | set(ap) if bp.get(i) != ap.get(i)}
    if pdiff:
        out["priorities"] = pdiff
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", help="path to config.yaml")
    ap.add_argument("--list", action="store_true",
                    help="show multi-file candidates and exit")
    ap.add_argument("--hash", help="infohash of the torrent to capture")
    ap.add_argument("--steer", action="store_true",
                    help="actually steer. Without this only the baseline is taken")
    ap.add_argument("--mode", choices=sorted(STEER_MODES), default="zero",
                    help="which steering strategy to measure: "
                         + "; ".join(f"{k} = {v}" for k, v in
                                     sorted(STEER_MODES.items())))
    ap.add_argument("--abandon", action="store_true",
                    help="exit WITHOUT restoring, to test reconcile on restart")
    ap.add_argument("--seconds", type=int, default=180,
                    help="how long to hold the steer (default 180)")
    ap.add_argument("--interval", type=int, default=5,
                    help="seconds between samples (default 5)")
    ap.add_argument("--outdir", default="captures",
                    help="where to write the capture (default ./captures)")
    ap.add_argument("--restore-from", metavar="CAPTURE.json",
                    help="undo a run that was killed before it could restore")
    args = ap.parse_args()

    if args.config:
        cfg_mod.CONFIG_PATH = args.config
    elif os.environ.get("PROTECTARR_CONFIG"):
        cfg_mod.CONFIG_PATH = os.environ["PROTECTARR_CONFIG"]
    elif os.path.exists("config/config.yaml"):
        cfg_mod.CONFIG_PATH = "config/config.yaml"

    if args.abandon and not args.steer:
        ap.error("--abandon only means anything together with --steer")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
