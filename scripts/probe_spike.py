#!/usr/bin/env python3
"""Probe-lane spike: can we identify a file's real type without downloading it?

This answers the question the whole probe lane rests on. Protectarr currently
catches fakes from torrent metadata alone, which is why it costs no bandwidth,
but it cannot see a payload wearing a genuine media extension. Closing that gap
needs actual bytes. The bet is that we only need the *first piece* of one file,
not the torrent, which on a 1 GB fake is a couple of MB instead of the lot.

What it does, against one real torrent you nominate:

    1. Snapshot every setting it is about to touch.
    2. Report the piece map: piece size, and which piece holds each file's start.
    3. Read whatever headers are ALREADY on disk. Pieces straddle file
       boundaries and torrents in flight have progress, so some headers come
       free. If the verdict lands here, nothing gets mutated at all.
    4. For anything unresolved: skip every other file, turn on sequential, and
       wait for the target's opening piece.
    5. Read the header and check it against what the extension claims.
    6. Restore everything, and verify the restore.
    7. Watch the owning *arr's queue entry throughout, because the real risk
       here is not the bytes - it is whether Sonarr/Radarr get upset about a
       torrent that sits near 0% with most of its files switched off.

Nothing is deleted and nothing is blocklisted. The worst case is a torrent left
with altered priorities, which step 6 undoes and step 7 reports on. Ctrl-C is
handled: it still restores.

    python scripts/probe_spike.py --list
    python scripts/probe_spike.py --hash <infohash> --map /downloads=/mnt/dl
    python scripts/probe_spike.py --hash <infohash> --observe-only
"""

import os
import sys
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod          # noqa: E402
from protectarr.qbit import QbitClient  # noqa: E402
from protectarr.arr import build_clients           # noqa: E402

# Positive validation: does the file parse as what its extension claims? This is
# the prototype of the PR 2 detector, deliberately tri-state - "cannot tell" is
# a distinct answer from "lying", and only the latter is ever evidence.
VALID, INVALID, UNKNOWN = "VALID", "INVALID", "UNKNOWN"

# Signatures we are confident about. Anything not listed returns UNKNOWN rather
# than guessing.
KNOWN_MAGIC = [
    (b"\x1a\x45\xdf\xa3", "matroska"),      # EBML: mkv / webm
    (b"MZ", "windows_pe"),
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"fLaC", "flac"),
    (b"RIFF", "riff"),
    (b"%PDF", "pdf"),
    (b"ID3", "mp3"),
    (b"#!", "script"),
]


def sniff(head):
    for sig, name in KNOWN_MAGIC:
        if head.startswith(sig):
            if name == "riff":
                return "avi" if head[8:12] == b"AVI " else "riff"
            return name
    if len(head) > 8 and head[4:8] == b"ftyp":
        return "iso_bmff"
    return None


def validate(filename, head):
    """(state, detected, note) for a claimed extension against real bytes."""
    ext = os.path.splitext(filename)[1].lower()
    detected = sniff(head)
    if not head or head == b"\x00" * len(head):
        return UNKNOWN, None, "no data yet (sparse or unwritten)"
    if ext in (".mkv", ".webm"):
        if detected == "matroska":
            return VALID, detected, "EBML header present"
        return (INVALID, detected, "claims Matroska, header says otherwise") \
            if detected else (UNKNOWN, None, "unrecognised header")
    if ext in (".mp4", ".m4v", ".m4a", ".mov"):
        if detected == "iso_bmff":
            return VALID, detected, "ftyp box present"
        # ISO 14496-12 permits older conforming files with no ftyp box, so a
        # missing one is not evidence of anything.
        return (INVALID, detected, "claims MP4, header says otherwise") \
            if detected else (UNKNOWN, None, "no ftyp, but that is legal")
    if ext == ".avi":
        if detected == "avi":
            return VALID, detected, "RIFF/AVI"
        return (INVALID, detected, "claims AVI, header says otherwise") \
            if detected else (UNKNOWN, None, "unrecognised header")
    if ext == ".flac":
        if detected == "flac":
            return VALID, detected, "fLaC"
        return (INVALID, detected, "claims FLAC, header says otherwise") \
            if detected else (UNKNOWN, None, "unrecognised header")
    return UNKNOWN, detected, f"no validator for {ext or 'no extension'}"


VALIDATABLE = {".mkv", ".webm", ".mp4", ".m4v", ".mov", ".avi", ".flac"}


def map_path(path, mappings):
    for src, dst in mappings:
        if path.startswith(src):
            return dst + path[len(src):]
    return path


def read_head(path, n=64):
    """Read a file header, tolerating the incomplete-file suffix. Returns
    (bytes, actual_path) - empty bytes means not readable yet, which is NOT a
    finding."""
    for candidate in (path, path + ".!qB"):
        try:
            with open(candidate, "rb") as fh:
                return fh.read(n), candidate
        except OSError:
            continue
    return b"", None


def arr_queue_entry(clients, thash):
    for c in clients:
        try:
            rec = c.queue_by_hash().get(thash.lower())
        except Exception:
            continue
        if rec:
            return c, rec
    return None, None


def show_arr(clients, thash, when):
    c, rec = arr_queue_entry(clients, thash)
    if not rec:
        print(f"  [{when}] no *arr queue entry for this hash")
        return
    print(f"  [{when}] {c.name}: status={rec.get('status')!r} "
          f"state={rec.get('trackedDownloadState')!r} "
          f"status2={rec.get('trackedDownloadStatus')!r} "
          f"left={rec.get('sizeleft')} err={rec.get('errorMessage') or '-'}")
    for m in rec.get("statusMessages") or []:
        print(f"           ! {m.get('title')}: {'; '.join(m.get('messages') or [])}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hash", help="infohash of the torrent to probe")
    ap.add_argument("--list", action="store_true", help="list candidate torrents")
    ap.add_argument("--map", action="append", default=[], metavar="QBIT=LOCAL",
                    help="path mapping, repeatable (e.g. /downloads=/mnt/dl)")
    ap.add_argument("--timeout", type=int, default=180,
                    help="probe budget in seconds (default 180)")
    ap.add_argument("--observe-only", action="store_true",
                    help="report the piece map and free headers, mutate nothing")
    args = ap.parse_args()

    mappings = []
    for m in args.map:
        src, _, dst = m.partition("=")
        if src and dst:
            mappings.append((src.rstrip("/"), dst.rstrip("/")))

    cfg = cfg_mod.load()
    q = cfg["qbittorrent"]
    qb = QbitClient(q["url"], q.get("username", ""), q.get("password", ""),
                    api_key=q.get("api_key", ""), verify_ssl=q.get("verify_ssl", True))
    ok, msg = qb.test()
    print(f"qBittorrent: {msg}")
    if not ok:
        return 1
    clients = build_clients(cfg)

    if args.list or not args.hash:
        print("\nCandidates (downloading, incomplete):")
        for t in qb.torrents():
            if t.get("progress", 1) >= 1:
                continue
            print(f"  {t['hash']}  {t.get('progress', 0)*100:5.1f}%  "
                  f"{t.get('state'):12}  {t.get('name', '')[:70]}")
        print("\nRe-run with --hash <infohash>")
        return 0

    thash = args.hash.lower()
    info = qb.torrent(thash)
    if not info:
        print(f"No such torrent: {thash}")
        return 1
    props = qb.properties(thash)
    files = qb.files(thash)
    piece_size = props.get("piece_size") or 0

    print(f"\nTorrent : {info.get('name')}")
    print(f"State   : {info.get('state')}  progress={info.get('progress', 0)*100:.2f}%")
    print(f"Pieces  : {props.get('pieces_num')} x {piece_size} bytes "
          f"({piece_size/1048576:.2f} MiB), have={props.get('pieces_have')}")
    print(f"content_path: {info.get('content_path')}")
    print(f"save_path   : {info.get('save_path')}")
    print(f"seq_dl={info.get('seq_dl')}  f_l_piece_prio={info.get('f_l_piece_prio')}")

    if not files or "piece_range" not in files[0]:
        print("\nFATAL: this qBittorrent does not report piece_range per file.")
        print("The probe lane cannot target a file's opening piece without it.")
        return 2

    print("\n*arr queue before:")
    show_arr(clients, thash, "before")

    targets = [(i, f) for i, f in enumerate(files)
               if os.path.splitext(f.get("name", ""))[1].lower() in VALIDATABLE]
    print(f"\nFiles: {len(files)} total, {len(targets)} validatable")
    for i, f in targets:
        pr = f.get("piece_range") or [None, None]
        print(f"  [{i:3}] prio={f.get('priority')} piece_range={pr} "
              f"{f.get('size', 0)/1048576:8.1f} MiB  {f.get('name')}")

    if not targets:
        print("\nNothing with a validatable extension. Pick another torrent.")
        return 0

    # ---- step 3: whatever is already on disk costs nothing ----
    print("\n--- free pass: headers already on disk ---")
    states = qb.piece_states(thash)
    base = info.get("content_path") or info.get("save_path") or ""
    single = len(files) == 1
    unresolved = []
    for i, f in targets:
        first_piece = (f.get("piece_range") or [None])[0]
        have = first_piece is not None and first_piece < len(states) and states[first_piece] == 2
        path = map_path(base if single else os.path.join(base, f.get("name", "")), mappings)
        head, actual = read_head(path)
        if have and head:
            state, detected, note = validate(f.get("name", ""), head)
            print(f"  FREE  [{i}] {state:7} detected={detected or '-':12} {note}")
            print(f"        {head[:16].hex(' ')}  <- {actual}")
        else:
            why = "piece not downloaded" if not have else "piece marked downloaded but unreadable"
            print(f"  need  [{i}] {why}  (piece {first_piece})")
            unresolved.append((i, f, first_piece, path))

    if args.observe_only:
        print("\n--observe-only: stopping before any mutation.")
        return 0
    if not unresolved:
        print("\nEverything resolved for free. No settings were changed.")
        return 0

    # ---- step 4: steer qBittorrent at one file, then put it all back ----
    original_prios = {i: f.get("priority", 1) for i, f in enumerate(files)}
    original_seq = bool(info.get("seq_dl"))
    original_flp = bool(info.get("f_l_piece_prio"))
    idx, target, first_piece, path = unresolved[0]
    print(f"\n--- probing file [{idx}] {target.get('name')} ---")
    print(f"    waiting for piece {first_piece}, budget {args.timeout}s")

    changed = False
    try:
        others = [i for i in original_prios if i != idx and original_prios[i] != 0]
        qb.set_file_priority(thash, others, 0)
        qb.set_file_priority(thash, [idx], 7)
        qb.set_sequential(thash, True)
        changed = True

        started = time.time()
        got = False
        while time.time() - started < args.timeout:
            states = qb.piece_states(thash)
            if first_piece < len(states) and states[first_piece] == 2:
                got = True
                break
            time.sleep(2)
            if int(time.time() - started) % 20 < 2:
                cur = qb.torrent(thash) or {}
                print(f"    {time.time()-started:5.0f}s  piece={states[first_piece] if first_piece < len(states) else '?'}"
                      f"  dl={cur.get('dlspeed', 0)/1024:.0f} KiB/s"
                      f"  progress={cur.get('progress', 0)*100:.2f}%")

        elapsed = time.time() - started
        if not got:
            print(f"    TIMEOUT after {elapsed:.0f}s - no verdict. This is the "
                  f"correct failure: no verdict must never mean 'block'.")
        else:
            print(f"    piece {first_piece} downloaded after {elapsed:.0f}s "
                  f"({piece_size/1048576:.2f} MiB, vs "
                  f"{info.get('size', 0)/1048576:.0f} MiB for the whole torrent)")
            head, actual = read_head(path)
            if not head:
                print(f"    piece is marked downloaded but {path} is not readable.")
                print(f"    -> path mapping is wrong, or the write has not landed "
                      f"where this process can see it. NOT a finding.")
            else:
                state, detected, note = validate(target.get("name", ""), head)
                print(f"    {state}  detected={detected or '-'}  {note}")
                print(f"    {head[:32].hex(' ')}")
                print(f"    read from {actual}")
    except KeyboardInterrupt:
        print("\n    interrupted")
    except Exception as e:  # noqa: BLE001 - restoring matters more than the error
        print(f"    ERROR during probe: {e}")
    finally:
        if changed:
            print("\n--- restoring ---")
            try:
                by_prio = {}
                for i, p in original_prios.items():
                    by_prio.setdefault(p, []).append(i)
                for p, ids in by_prio.items():
                    qb.set_file_priority(thash, ids, p)
                qb.set_sequential(thash, original_seq)
                qb.set_first_last_prio(thash, original_flp)
                after = qb.torrent(thash) or {}
                now = {i: f.get("priority", 1) for i, f in enumerate(qb.files(thash))}
                print(f"    priorities restored: {now == original_prios}")
                print(f"    seq_dl {after.get('seq_dl')} (was {original_seq}), "
                      f"f_l {after.get('f_l_piece_prio')} (was {original_flp})")
                if now != original_prios:
                    print(f"    MISMATCH\n      was: {original_prios}\n      now: {now}")
            except Exception as e:  # noqa: BLE001
                print(f"    RESTORE FAILED: {e}")
                print(f"    original priorities were: {original_prios}")
                print(f"    seq_dl={original_seq} f_l_piece_prio={original_flp}")

    print("\n*arr queue after:")
    show_arr(clients, thash, "after")
    print("\nThe thing to judge: did the *arr entry stay healthy throughout, or "
          "did it start reporting stalled/warning while files were switched off?")
    return 0


if __name__ == "__main__":
    sys.exit(main())
