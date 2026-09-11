"""Detection + reap loop, wrapped in a service the WebUI can inspect/reload."""

import os
import json
import time
import threading

import requests

from . import config as cfg_mod
from . import harvest
from . import events
from . import detectors
from . import policy
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
    harvest ledger. Best-effort - never let it break a reap. Returns the number
    of distinct peer IPs recorded."""
    if not cfg.get("harvest", {}).get("enabled", True):
        return 0
    try:
        peers = a["_qb"].peers(a["hash"])
        n = harvest.record(peers, {
            "hash": a["hash"], "name": a["name"], "ext": a["bad_file"],
            "indexer": indexer, "app": app,
        })
        if n:
            _log(state, f"Harvested {n} peer IP(s) from {a['name']!r}")
        return n
    except Exception as e:  # noqa: BLE001 - harvest must never abort a reap
        _log(state, f"Peer harvest failed for {a['name']!r}: {e}")
        return 0


# Wording of the existing log lines, keyed by the finding's reason code. The
# history page renders findings its own way (see events.describe); this keeps
# the activity log reading exactly as it always has.
_REASON_TEXT = {
    "extension_match": lambda e: f"blocked extension {e.get('extension', '')}",
    "lure_filename": lambda e: "suspicious lure filename",
    "archive_no_media": lambda e: "archive with no media",
}


def reason_text(find):
    """Legacy one-liner for the activity log."""
    if not find:
        return None
    fn = _REASON_TEXT.get(find.get("reason"))
    return fn(find.get("evidence", {})) if fn else find.get("reason")


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
    # name -> raw config entry, so policy can read a per-*arr `profile`.
    arr_by_name = {a.get("name"): a for a in cfg.get("arrs", []) if a.get("name")}
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
            continue  # finished/seeding - nothing left to prevent
        if tstate in ("metaDL", "forcedMetaDL"):
            continue  # metadata not in yet; catch on a later pass
        try:
            files = qb.files(thash)
        except requests.RequestException:
            continue
        arr_hit = owner.get(thash.lower())

        # Detectors observe. They get a lazy indexer lookup so the archive rule
        # only pays for the HTTP call when it actually has a candidate.
        def _resolve_indexer(hit=arr_hit):
            if not hit:
                return None
            client, record = hit
            return record.get("indexer") or client.grab_indexer(record.get("downloadId"))

        findings = detectors.run(files, det, {
            "arr_type": arr_hit[0].type if arr_hit else None,
            "arr_tracked": bool(arr_hit),
            "resolve_indexer": _resolve_indexer,
        })
        if not findings:
            continue

        # Policy judges. Which profile applies depends on who owns the torrent.
        arr_entry = arr_by_name.get(arr_hit[0].name) if arr_hit else None
        profile = policy.resolve(cfg, arr_entry, t.get("category") or "")
        judged = [(f, policy.judge(cfg, profile, f)) for f in findings]
        verdict = policy.outcome(judged)
        if verdict == "allow":
            continue
        top_find, top_policy = policy.decisive(judged)

        row = {
            "hash": thash,
            "name": t.get("name", thash),
            "bad_file": top_find.get("evidence", {}).get("filename", ""),
            "reason": reason_text(top_find),
            "finding": top_find,
            "policy": top_policy,
            "other_findings": [f for f, _ in judged if f is not top_find],
            "size": t.get("size"),
            "category": t.get("category", ""),
            "tags": t.get("tags", ""),
            "arr": arr_hit[0].name if arr_hit else None,
            "_owner": arr_hit,
            "_qb": qb,
        }

        if verdict == "warn":
            # Worth recording, not worth destroying over. The safety mode still
            # decides whether this torrent was ever ours to touch.
            if evaluate(t, row["bad_file"], arr_hit, safety) is not None:
                row["decision"] = "warn"
                actions.append(row)
            continue

        decision = evaluate(t, row["bad_file"], arr_hit, safety)
        if decision is None:
            continue
        row["decision"] = decision
        actions.append(row)
    return actions


def _media_name(record):
    """Best-effort human name for what the release was *for* (series, movie,
    album, book). Queue records only carry these when the arr includes them, so
    this is decoration - the release title is always recorded separately."""
    for key in ("series", "movie", "artist", "author", "album", "book"):
        obj = record.get(key)
        if isinstance(obj, dict) and obj.get("title"):
            return obj["title"]
    return None


def _event(a, cfg, **over):
    """Common event skeleton for one action. `over` fills in the outcome."""
    ev = {
        "torrent": {
            "hash": a.get("hash"),
            "name": a.get("name"),
            "size": a.get("size"),
            "category": a.get("category") or None,
            "indexer": over.pop("indexer", None),
        },
        "owner": over.pop("owner", None),
        "finding": a.get("finding"),
        "policy": a.get("policy"),
        "peers_harvested": over.pop("peers", 0),
        "dry_run": bool(cfg.get("dry_run", True)),
    }
    if a.get("other_findings"):
        ev["other_findings"] = a["other_findings"]
    ev.update(over)
    return ev


def _owner_block(owner):
    if not owner:
        return None
    client, record = owner
    return {"type": client.type, "instance": client.name,
            "media": _media_name(record), "release_title": record.get("title")}


def apply_actions(actions, state, cfg):
    dry_run = cfg.get("dry_run", True)
    safety = cfg.get("safety", {})
    requeue_enabled = safety.get("requeue_after_airdate", True)
    grace = safety.get("airdate_grace_hours", 0)
    warned = state.setdefault("warned", set())
    for a in actions:
        _r = a.get("reason")
        label = f"{a['name']!r} (bad: {a['bad_file']!r}{' - ' + _r if _r else ''})"

        if a["decision"] == "warn":
            # The profile flagged it without calling for removal. Record it
            # once per torrent so a 20-second poll doesn't fill the history.
            if a["hash"] in warned:
                continue
            warned.add(a["hash"])
            _log(state, f"Flagged (no action, {a['policy']['profile']} profile): {label}")
            events.record(_event(
                a, cfg, owner=_owner_block(a["_owner"]),
                action={"result": "warned", "decision": "warn",
                        "removed": False, "blocklisted": False},
                redownload={"decision": "none", "reason": "not_applicable"}))
            continue

        if dry_run:
            _log(state, f"[DRY_RUN] would {a['decision']}: {label}")
            events.record(_event(
                a, cfg, owner=_owner_block(a["_owner"]),
                action={"result": "would_reap", "decision": a["decision"],
                        "removed": False, "blocklisted": False},
                redownload={"decision": "none", "reason": "not_applicable"}))
            continue
        # Tracks whether the destructive half already went through, so a failure
        # in the verification/requeue half afterwards isn't reported as if
        # nothing happened.
        removed = False
        try:
            if a["decision"] == "arr_fail":
                client, record = a["_owner"]
                source_title = record.get("title", a["name"])
                indexer = record.get("indexer") or client.grab_indexer(record.get("downloadId"))
                peers = _harvest_peers(a, indexer, client.name, state, cfg)  # before removal
                client.fail(record["id"])  # remove + blocklist, no auto-redownload
                removed = True
                blocked = client.is_blocklisted_title(source_title)

                # Requeue only if it has actually aired/released.
                requeue = "disabled"
                rd = {"decision": "none", "reason": "requeue_disabled"}
                if requeue_enabled:
                    aired, when = client.airdate_status(record, grace)
                    whenstr = when.date().isoformat() if when else "unknown"
                    if aired is True:
                        if client.search(record):
                            requeue = "requeued (aired)"
                            rd = {"decision": "searched", "reason": "aired"}
                        else:
                            requeue = "requeue-failed"
                            rd = {"decision": "failed", "reason": "search_failed"}
                    elif aired is False:
                        requeue = f"held (airs {whenstr})"
                        rd = {"decision": "held", "reason": "not_yet_aired",
                              "airs": whenstr}
                    else:
                        requeue = "held (airdate unknown)"
                        rd = {"decision": "held", "reason": "airdate_unknown"}
                _log(state, f"Reaped via {client.name}: {label} | "
                            f"blocklisted={'yes' if blocked else 'unconfirmed'} | {requeue}")
                record_reap(state, client.name, indexer)
                events.record(_event(
                    a, cfg, indexer=indexer, peers=peers,
                    owner={"type": client.type, "instance": client.name,
                           "media": _media_name(record), "release_title": source_title},
                    action={"result": "reaped", "decision": "arr_fail",
                            "removed": True, "blocklisted": bool(blocked)},
                    redownload=rd))
            elif a["decision"] == "qbit_delete":
                peers = _harvest_peers(a, None, "qBittorrent", state, cfg)  # before removal
                a["_qb"].delete(a["hash"], delete_files=True)
                removed = True
                _log(state, f"Deleted from qBittorrent: {label}")
                record_reap(state, "qBittorrent", a.get("category") or None)
                events.record(_event(
                    a, cfg, peers=peers,
                    owner={"type": "qbittorrent", "instance": "qBittorrent",
                           "media": None, "release_title": a.get("name")},
                    action={"result": "reaped", "decision": "qbit_delete",
                            "removed": True, "blocklisted": False},
                    redownload={"decision": "none", "reason": "not_applicable"}))
        except (requests.RequestException, QbitError) as e:
            # If the removal already succeeded, the fake really is gone and
            # blocklisted; only the confirmation or requeue half broke. Calling
            # that "failed" would be factually wrong, so it's recorded as
            # partial with the outcome left unknown rather than asserted.
            if removed:
                _log(state, f"Removed, but the follow-up check failed for {label}: {e}")
                result, rd = "partial", {"decision": "unknown",
                                         "reason": "verification_failed"}
            else:
                _log(state, f"Action failed for {label}: {e}")
                result, rd = "failed", {"decision": "none",
                                        "reason": "not_applicable"}
            events.record(_event(
                a, cfg, owner=_owner_block(a["_owner"]),
                action={"result": result, "decision": a["decision"],
                        "removed": removed, "blocklisted": None if removed else False,
                        "error": str(e)},
                redownload=rd))


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
        """Dry-run scan for the WebUI - returns serializable action rows."""
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
