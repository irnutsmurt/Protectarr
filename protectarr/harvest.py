"""Seeder-IP harvest ledger.

When Protectarr reaps a fake (an extension-list hit), we first enumerate the
torrent's swarm from qBittorrent and record every peer here - BEFORE the torrent
is removed, since the swarm is unqueryable once it's gone.

This is deliberately an *observation ledger*, not a blocklist: it collects who
was sharing confirmed fakes so patterns can be eyeballed (which IPs/subnets show
up across many distinct fakes, whether they were seeding, what client they run)
before any automatic banning is ever wired up. See the watchlist page.

Stored as JSON next to the config/stats files, keyed by IP:
    ips[ip] = {
        first_seen, last_seen, hits, seed_hits, max_progress,
        torrents: { <hash>: {name, ext, indexer, app, last} },  # distinct fakes
        clients: [...], ports: [...], countries: [...],
    }
"""

import os
import json
import threading

from . import config as cfg_mod
from . import logs

log = logs.get("harvest")

# progress at/above this counts the peer as a seeder (the likely fake *source*,
# not an innocent victim still downloading).
SEED_PROGRESS = 0.999
_lock = threading.Lock()


def _path():
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".", "harvest.json")


def load():
    """Read the ledger, filling in missing top-level keys."""
    try:
        with open(_path()) as fh:
            d = json.load(fh)
        if not isinstance(d, dict):
            d = {}
    except (OSError, ValueError):
        d = {}
    d.setdefault("ips", {})
    return d


def _save(ledger):
    path = _path()
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(ledger, fh, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        log.error("Could not persist harvest ledger to %s: %s", path, e)


def _add_unique(lst, val, cap=8):
    if val and val not in lst:
        lst.append(val)
        del lst[cap:]


def record(peers, meta):
    """Fold a torrent's peers into the ledger under the fake they were sharing.

    `meta` = {"hash", "name", "ext", "indexer", "app"}. Returns the number of
    distinct peer IPs recorded for this torrent (0 if none / on error).
    """
    thash = (meta.get("hash") or "").lower()
    if not peers or not thash:
        return 0
    now = logs.now()
    tinfo = {
        "name": meta.get("name", ""),
        "ext": meta.get("ext", ""),
        "indexer": meta.get("indexer") or "unknown",
        "app": meta.get("app", ""),
        "last": now,
    }
    seen_ips = set()
    with _lock:
        ledger = load()
        ips = ledger["ips"]
        for p in peers:
            ip = p.get("ip")
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)
            e = ips.get(ip)
            if e is None:
                e = ips[ip] = {
                    "first_seen": now, "last_seen": now, "hits": 0,
                    "seed_hits": 0, "max_progress": 0,
                    "torrents": {}, "clients": [], "ports": [], "countries": [],
                }
            e["last_seen"] = now
            e["hits"] += 1
            prog = float(p.get("progress") or 0)
            e["max_progress"] = max(e.get("max_progress", 0), prog)
            if prog >= SEED_PROGRESS:
                e["seed_hits"] += 1
            e["torrents"][thash] = tinfo
            _add_unique(e["clients"], p.get("client"))
            _add_unique(e["ports"], p.get("port"))
            _add_unique(e["countries"], p.get("country"))
        _save(ledger)
    return len(seen_ips)


def watchlist(min_fakes=1):
    """Return IP rows sorted by how many distinct fakes they seeded, richest
    first - ready for the watchlist UI. Each row flattens the stored entry."""
    rows = []
    for ip, e in load().get("ips", {}).items():
        torrents = e.get("torrents", {})
        distinct = len(torrents)
        if distinct < min_fakes:
            continue
        rows.append({
            "ip": ip,
            "distinct_fakes": distinct,
            "hits": e.get("hits", 0),
            "seed_hits": e.get("seed_hits", 0),
            "was_seeder": e.get("max_progress", 0) >= SEED_PROGRESS,
            "first_seen": e.get("first_seen"),
            "last_seen": e.get("last_seen"),
            "clients": e.get("clients", []),
            "countries": [c for c in e.get("countries", []) if c],
            "indexers": sorted({t.get("indexer", "") for t in torrents.values() if t.get("indexer")}),
            "samples": [t.get("name", "") for t in torrents.values()][:5],
        })
    rows.sort(key=lambda r: (r["distinct_fakes"], r["seed_hits"], r["hits"]), reverse=True)
    return rows
