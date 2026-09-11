"""Detection + reap loop, wrapped in a service the WebUI can inspect/reload."""

import os
import re
import json
import time
import posixpath
import threading

import requests

from . import config as cfg_mod
from . import harvest
from .qbit import QbitClient, QbitError
from .arr import build_clients

# qBittorrent states where the torrent is still acquiring content.
DOWNLOADING_STATES = {
    "downloading", "forcedDL", "stalledDL", "queuedDL", "checkingDL",
    "metaDL", "forcedMetaDL", "allocating", "pausedDL", "stoppedDL",
}


def _log(state, msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    state["log"].append(line)
    del state["log"][:-200]  # keep last 200 lines


# ---- persistent reap stats (survive restarts; power the dashboard) ----

def _stats_path():
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".", "stats.json")


def load_stats():
    """Read persisted counters, filling in any missing keys."""
    try:
        with open(_stats_path()) as fh:
            s = json.load(fh)
        if not isinstance(s, dict):
            s = {}
    except (OSError, ValueError):
        s = {}
    s.setdefault("reaped_total", 0)
    s.setdefault("by_indexer", {})
    s.setdefault("by_app", {})
    s.setdefault("first_seen", None)
    s.setdefault("last_reap", None)
    return s


def save_stats(stats):
    path = _stats_path()
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(stats, fh, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        print(f"[Protectarr] could not persist stats: {e}", flush=True)


def record_reap(state, app, indexer):
    """Increment counters for one confirmed reap and persist them."""
    s = state["stats"]
    s["reaped_total"] = s.get("reaped_total", 0) + 1
    s["by_app"][app] = s["by_app"].get(app, 0) + 1
    key = indexer or "unknown"
    s["by_indexer"][key] = s["by_indexer"].get(key, 0) + 1
    if not s.get("first_seen"):
        s["first_seen"] = time.strftime("%Y-%m-%d")
    s["last_reap"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_stats(s)


def _harvest_peers(a, indexer, app, state, cfg):
    """Before a fake is removed, enumerate its swarm and log the peers to the
    harvest ledger. Best-effort — never let it break a reap."""
    if not cfg.get("harvest", {}).get("enabled", True):
        return
    try:
        peers = a["_qb"].peers(a["hash"])
        n = harvest.record(peers, {
            "hash": a["hash"], "name": a["name"], "ext": a["bad_file"],
            "indexer": indexer, "app": app,
        })
        if n:
            _log(state, f"Harvested {n} peer IP(s) from {a['name']!r}")
    except Exception as e:  # noqa: BLE001 - harvest must never abort a reap
        _log(state, f"Peer harvest failed for {a['name']!r}: {e}")


# ---- media extensions per arr type (for the archive-with-no-media rule) ----
VIDEO_EXTS = {".mkv", ".mp4", ".avi", ".m4v", ".mov", ".wmv", ".ts", ".m2ts",
              ".mpg", ".mpeg", ".flv", ".webm", ".vob", ".iso", ".divx", ".ogm"}
AUDIO_EXTS = {".flac", ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".alac",
              ".ape", ".wma", ".m4b"}
BOOK_EXTS = {".epub", ".mobi", ".azw", ".azw3", ".pdf", ".cbz", ".cbr", ".djvu",
             ".m4b", ".mp3"}
_MEDIA_BY_TYPE = {
    "sonarr": VIDEO_EXTS, "radarr": VIDEO_EXTS, "whisparr": VIDEO_EXTS,
    "lidarr": AUDIO_EXTS, "readarr": BOOK_EXTS,
}
# Text-like companion files where fake "lures" live (readme / password / url
# notes). Keyword matching is limited to these, so a legit release simply titled
# "Password.mkv" is never a false positive.
LURE_EXTS = {".txt", ".nfo", ".htm", ".html", ".url", ".rtf", ".md", ".diz", ".doc"}
_RAR_PART = re.compile(r"^\.r\d{2}$")   # .r00 .r01 ...
_NUM_PART = re.compile(r"^\.\d{3}$")    # .001 .002 ...  (split archives)


def _ext(name):
    return posixpath.splitext(name)[1].lower()


def _is_archive(ext, archive_exts):
    return ext in archive_exts or bool(_RAR_PART.match(ext)) or bool(_NUM_PART.match(ext))


def detect_basic(files, det):
    """Tier 1 + 2 — universal, high-precision. Returns (bad_name, reason) for the
    first blocked-extension or lure-filename hit, else (None, None)."""
    exts = {e.lower() for e in det.get("blocked_extensions", [])}
    keywords = [k.lower() for k in det.get("blocked_name_keywords", [])]
    for f in files:
        name = f.get("name", "")
        ext = _ext(name)
        if ext in exts:
            return name, f"blocked extension {ext}"
        if keywords and ext in LURE_EXTS:
            base = posixpath.basename(name).lower()
            if any(k in base for k in keywords):
                return name, "suspicious lure filename"
    return None, None


def detect_archive(files, det, arr_type):
    """Tier 3 (structural half) — returns (archive_name, reason) when the torrent
    is archives-only with NO real media for this arr type, else (None, None).
    Indexer scoping is the caller's responsibility (see scan)."""
    ad = det.get("archive_detection", {})
    archive_exts = {e.lower() for e in ad.get("archive_extensions", [])}
    media = _MEDIA_BY_TYPE.get((arr_type or "").lower())
    if media is None:
        media = VIDEO_EXTS | AUDIO_EXTS | BOOK_EXTS  # unknown type: be permissive
    first_archive = None
    for f in files:
        ext = _ext(f.get("name", ""))
        if ext in media:
            return None, None  # a real media file is present — not a fake
        if first_archive is None and _is_archive(ext, archive_exts):
            first_archive = f.get("name", "")
    if first_archive:
        return first_archive, "archive with no media"
    return None, None


def allowlisted(torrent, safety):
    cats = {c.lower() for c in safety.get("allowed_categories", [])}
    tags = {t.lower() for t in safety.get("allowed_tags", [])}
    tcat = (torrent.get("category") or "").lower()
    ttags = {t.strip().lower() for t in (torrent.get("tags") or "").split(",") if t.strip()}
    if cats and tcat in cats:
        return True
    if tags and (ttags & tags):
        return True
    return False


def evaluate(torrent, bad_name, arr_hit, safety):
    """Decide what to do with a torrent that contains a blocked file.

    Returns one of: 'arr_fail' (hand back to the owning arr), 'qbit_delete'
    (remove directly), or None (leave it alone).
    """
    mode = safety.get("mode", "arr_tracked")
    is_allowed = allowlisted(torrent, safety)

    if mode == "arr_tracked":
        return "arr_fail" if arr_hit else None
    if mode == "both":
        if arr_hit and is_allowed:
            return "arr_fail"
        return None
    if mode == "allowlist":
        if not is_allowed:
            return None
        return "arr_fail" if arr_hit else "qbit_delete"
    return None


def scan(cfg, state):
    """One pass over qBittorrent's torrents. Returns list of action dicts
    (used both for live reaping and the WebUI dry-run preview)."""
    qc = cfg["qbittorrent"]
    qb = QbitClient(qc["url"], qc.get("username", ""), qc.get("password", ""),
                    api_key=qc.get("api_key", ""), verify_ssl=qc.get("verify_ssl", True))
    qb.login()

    # Only pull the category we care about when in a category-scoped setup;
    # otherwise inspect everything and let the safety rules filter.
    torrents = qb.torrents()

    arr_clients = build_clients(cfg)
    # hash -> (client, queue_record)
    owner = {}
    for client in arr_clients:
        try:
            for h, rec in client.queue_by_hash().items():
                owner.setdefault(h, (client, rec))
        except requests.RequestException as e:
            _log(state, f"Could not read {client.name} queue: {e}")

    det = cfg["detection"]
    only_active = det.get("only_active", True)
    safety = cfg["safety"]
    actions = []

    for t in torrents:
        thash = t.get("hash", "")
        tstate = t.get("state", "")
        if only_active and tstate not in DOWNLOADING_STATES:
            continue  # finished/seeding — nothing left to prevent
        if tstate in ("metaDL", "forcedMetaDL"):
            continue  # metadata not in yet; catch on a later pass
        try:
            files = qb.files(thash)
        except requests.RequestException:
            continue
        arr_hit = owner.get(thash.lower())
        bad, reason = detect_basic(files, det)
        # Tier 3: indexer-scoped archive rule — only for arr-tracked torrents,
        # and only resolve the (possibly expensive) indexer for real candidates.
        ad = det.get("archive_detection", {})
        if not bad and ad.get("enabled") and arr_hit:
            cand, crs = detect_archive(files, det, arr_hit[0].type)
            if cand:
                client, record = arr_hit
                indexer = record.get("indexer") or client.grab_indexer(record.get("downloadId"))
                allowed = {i.strip() for i in ad.get("indexers", []) if i.strip()}
                if indexer and indexer in allowed:
                    bad, reason = cand, crs
        if not bad:
            continue

        decision = evaluate(t, bad, arr_hit, safety)
        if decision is None:
            continue
        actions.append({
            "hash": thash,
            "name": t.get("name", thash),
            "bad_file": bad,
            "reason": reason,
            "category": t.get("category", ""),
            "tags": t.get("tags", ""),
            "decision": decision,
            "arr": arr_hit[0].name if arr_hit else None,
            "_owner": arr_hit,
            "_qb": qb,
        })
    return actions


def apply_actions(actions, state, cfg):
    dry_run = cfg.get("dry_run", True)
    safety = cfg.get("safety", {})
    requeue_enabled = safety.get("requeue_after_airdate", True)
    grace = safety.get("airdate_grace_hours", 0)
    for a in actions:
        _r = a.get("reason")
        label = f"{a['name']!r} (bad: {a['bad_file']!r}{' — ' + _r if _r else ''})"
        if dry_run:
            _log(state, f"[DRY_RUN] would {a['decision']}: {label}")
            continue
        try:
            if a["decision"] == "arr_fail":
                client, record = a["_owner"]
                source_title = record.get("title", a["name"])
                indexer = record.get("indexer") or client.grab_indexer(record.get("downloadId"))
                _harvest_peers(a, indexer, client.name, state, cfg)  # before removal
                client.fail(record["id"])  # remove + blocklist, no auto-redownload
                blocked = client.is_blocklisted_title(source_title)

                # Requeue only if it has actually aired/released.
                requeue = "disabled"
                if requeue_enabled:
                    aired, when = client.airdate_status(record, grace)
                    whenstr = when.date().isoformat() if when else "unknown"
                    if aired is True:
                        requeue = "requeued (aired)" if client.search(record) else "requeue-failed"
                    elif aired is False:
                        requeue = f"held (airs {whenstr})"
                    else:
                        requeue = "held (airdate unknown)"
                _log(state, f"Reaped via {client.name}: {label} | "
                            f"blocklisted={'yes' if blocked else 'unconfirmed'} | {requeue}")
                record_reap(state, client.name, indexer)
            elif a["decision"] == "qbit_delete":
                _harvest_peers(a, None, "qBittorrent", state, cfg)  # before removal
                a["_qb"].delete(a["hash"], delete_files=True)
                _log(state, f"Deleted from qBittorrent: {label}")
                record_reap(state, "qBittorrent", a.get("category") or None)
        except (requests.RequestException, QbitError) as e:
            _log(state, f"Action failed for {label}: {e}")


class ProtectarrService:
    """Runs the scan loop in a background thread; the WebUI reads `state`."""

    def __init__(self):
        self.state = {"log": [], "stats": load_stats(), "last_scan": None,
                      "last_error": None, "running": False,
                      "blocklist": {"last": None, "entries": 0, "bytes": 0,
                                    "applied": False, "error": None},
                      "banned": {"last": None, "count": 0, "error": None}}
        self._stop = threading.Event()
        self._thread = None
        self._reload = threading.Event()
        self._bl_last = 0.0  # monotonic-ish epoch of last blocklist refresh

    def reload(self):
        self._reload.set()

    def update_blocklist(self, cfg=None, force=False):
        """Refresh the IP blocklist if due (or forced). Records status in state."""
        cfg = cfg or cfg_mod.load()
        bl = cfg.get("ip_blocklist", {})
        if not bl.get("enabled"):
            return
        interval = max(1, int(bl.get("update_interval_hours", 24))) * 3600
        if not force and self._bl_last and (time.time() - self._bl_last) < interval:
            return
        try:
            from . import blocklist as bl_mod
            res = bl_mod.update(cfg)
            self._bl_last = time.time()
            self.state["blocklist"] = {
                "last": time.strftime("%Y-%m-%d %H:%M:%S"),
                "entries": res["entries"], "bytes": res["bytes"],
                "applied": res["applied"], "error": None}
            _log(self.state, f"IP blocklist updated: {res['entries']} entries "
                             f"({res['bytes']//1024} KiB), applied={res['applied']}")
        except (requests.RequestException, QbitError, OSError, ValueError) as e:
            self.state["blocklist"]["error"] = str(e)
            self._bl_last = time.time()  # back off; don't hammer on failure
            _log(self.state, f"IP blocklist update failed: {e}")

    def preview(self):
        """Dry-run scan for the WebUI — returns serializable action rows."""
        cfg = cfg_mod.load()
        actions = scan(cfg, self.state)
        return [{k: v for k, v in a.items() if not k.startswith("_")} for a in actions]

    def apply_banned_ips(self, cfg=None):
        """Push the manual banned-IP list to qBittorrent. Records status."""
        cfg = cfg or cfg_mod.load()
        if not cfg.get("banned_ips", {}).get("enabled"):
            return
        try:
            from . import blocklist as bl_mod
            count = bl_mod.apply_banned_ips(cfg)
            self.state["banned"] = {"last": time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "count": count, "error": None}
            _log(self.state, f"Applied {count} manually banned IP(s) to qBittorrent.")
        except (requests.RequestException, QbitError) as e:
            self.state["banned"]["error"] = str(e)
            _log(self.state, f"Banned-IP apply failed: {e}")

    def _run(self):
        while not self._stop.is_set():
            cfg = cfg_mod.load()
            try:
                actions = scan(cfg, self.state)
                apply_actions(actions, self.state, cfg)
                self.state["last_scan"] = time.strftime("%Y-%m-%d %H:%M:%S")
                self.state["last_error"] = None
            except (QbitError, requests.RequestException) as e:
                self.state["last_error"] = str(e)
                _log(self.state, f"Scan error: {e}")
            self.update_blocklist(cfg)  # refreshes only when due
            # Sleep in small chunks so reload/stop are responsive.
            interval = max(5, int(cfg.get("poll_interval", 20)))
            for _ in range(interval):
                if self._stop.is_set() or self._reload.is_set():
                    self._reload.clear()
                    break
                time.sleep(1)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.state["running"] = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.state["running"] = False

    def scan_now(self):
        """Trigger an immediate scan. If the worker is running, wake it so it
        re-scans without waiting out the poll interval; otherwise run one
        synchronous scan+apply cycle here. Returns a small status dict."""
        if self._thread and self._thread.is_alive():
            self._reload.set()  # breaks the sleep; next loop iteration scans now
            return {"queued": True, "running": True}
        cfg = cfg_mod.load()
        actions = scan(cfg, self.state)
        apply_actions(actions, self.state, cfg)
        self.state["last_scan"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"queued": False, "running": False, "actions": len(actions)}
