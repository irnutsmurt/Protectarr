"""Detection + reap loop, wrapped in a service the WebUI can inspect/reload."""

import os
import json
import time
import logging
import threading

import requests

from . import config as cfg_mod
from . import harvest
from . import events
from . import detectors
from . import policy
from . import probe
from . import intents
from . import logs
from .qbit import QbitClient, QbitError
from .arr import build_clients

# qBittorrent states where the torrent is still acquiring content.
DOWNLOADING_STATES = {
    "downloading", "forcedDL", "stalledDL", "queuedDL", "checkingDL",
    "metaDL", "forcedMetaDL", "allocating", "pausedDL", "stoppedDL",
}


log = logs.get("core")


def _log(state, msg, level=logging.INFO):
    """Operator-facing activity line. Kept as a wrapper so every existing call
    site still reads the same; the ring buffer now lives in logs.py."""
    log.log(level, "%s", msg)


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
        log.error("Could not persist stats to %s: %s", path, e)


def record_reap(state, app, indexer):
    """Increment counters for one confirmed reap and persist them."""
    s = state["stats"]
    s["reaped_total"] = s.get("reaped_total", 0) + 1
    s["by_app"][app] = s["by_app"].get(app, 0) + 1
    key = indexer or "unknown"
    s["by_indexer"][key] = s["by_indexer"].get(key, 0) + 1
    if not s.get("first_seen"):
        s["first_seen"] = time.strftime("%Y-%m-%d")
    s["last_reap"] = logs.now()
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
        _log(state, f"Peer harvest failed for {a['name']!r}: {e}", logging.WARNING)
        return 0


# Wording of the existing log lines, keyed by the finding's reason code. The
# history page renders findings its own way (see events.describe); this keeps
# the activity log reading exactly as it always has.
_REASON_TEXT = {
    "extension_match": lambda e: f"blocked extension {e.get('extension', '')}",
    "lure_filename": lambda e: "suspicious lure filename",
    "archive_no_media": lambda e: "archive with no media",
    "content_type_mismatch": lambda e: (
        f"claims {e.get('claimed_type', 'media')} but the bytes are "
        f"{probe.validators.label(e.get('detected_type'))}"),
}


def reason_text(find):
    """Legacy one-liner for the activity log."""
    if not find:
        return None
    fn = _REASON_TEXT.get(find.get("reason"))
    return fn(find.get("evidence", {})) if fn else find.get("reason")


def allowlisted(torrent, safety):
    # Blank entries are dropped deliberately. A stray empty line in the config
    # would otherwise match every torrent with no category, which is exactly
    # the hand-added downloads this is supposed to protect.
    cats = {c.strip().lower() for c in safety.get("allowed_categories", []) if c and c.strip()}
    tags = {t.strip().lower() for t in safety.get("allowed_tags", []) if t and t.strip()}
    tcat = (torrent.get("category") or "").lower()
    ttags = {t.strip().lower() for t in (torrent.get("tags") or "").split(",") if t.strip()}
    if cats and tcat in cats:
        return True
    if tags and (ttags & tags):
        return True
    return False


def evaluate(torrent, bad_name, arr_hit, safety, ownership_known=True):
    """Decide what to do with a torrent that contains a blocked file.

    Returns one of: 'arr_fail' (hand back to the owning arr), 'qbit_delete'
    (remove directly), or None (leave it alone).

    `ownership_known` is False when an *arr queue could not be read. Absence
    from a queue we never managed to fetch is not evidence that nothing owns
    the torrent, and treating it as such would delete real downloads the moment
    Sonarr restarts. Uncertainty fails safe: no direct deletion.

    Each mode has a different blind spot, which is why `either` exists:

        arr_tracked  misses orphans - a download an *arr grabbed and then
                     abandoned (it failed the release and dropped it from its
                     queue) is owned by nobody, so nothing reaps it while
                     qBittorrent keeps pulling the payload.
        allowlist    misses *arr-tracked torrents in a category you did not list.
        both         is an AND, so it is narrower than either half.
        either       the union: let the *arr handle it whenever it can, and fall
                     back to deleting orphans in categories you trust.
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
        if arr_hit:
            return "arr_fail"
        return "qbit_delete" if ownership_known else None
    if mode == "either":
        # An *arr owning it always wins: that path blocklists the release and
        # decides about requeueing, which deleting from qBittorrent cannot do.
        if arr_hit:
            return "arr_fail"
        if not ownership_known:
            return None
        return "qbit_delete" if is_allowed else None
    return None


def _assess(t, findings, arr_hit, arr_by_name, cfg, safety, ownership_known, qb):
    """Findings about one torrent -> an action row, or None to leave it alone.

    Shared by both detection lanes, so a probe finding is judged by exactly the
    same profile and safety rules as an extension match. The lane a finding came
    from decides nothing about what happens to it.
    """
    arr_entry = arr_by_name.get(arr_hit[0].name) if arr_hit else None
    profile = policy.resolve(cfg, arr_entry, t.get("category") or "")
    judged = [(f, policy.judge(cfg, profile, f)) for f in findings]
    verdict = policy.outcome(judged)
    log.debug("Policy %r on %s -> %s (%s)", profile, t.get("name"), verdict,
              "; ".join(f"{f['reason']}={p['severity']}/{p['decision']}"
                        for f, p in judged))
    if verdict == "allow":
        log.info("Allowed by the %s profile, no action: %s", profile, t.get("name"))
        return None
    top_find, top_policy = policy.decisive(judged)

    row = {
        "hash": t.get("hash", ""),
        "name": t.get("name", t.get("hash", "")),
        "bad_file": top_find.get("evidence", {}).get("filename", ""),
        "reason": reason_text(top_find),
        # Every observation is kept, with policy pointing at the one that drove
        # the outcome. The rest is corroborating evidence, which is worth a lot
        # more now that the probe lane adds to it.
        "findings": findings,
        "finding": top_find,        # internal convenience; not stored
        "policy": dict(top_policy, decisive_finding=findings.index(top_find)),
        "size": t.get("size"),
        "category": t.get("category", ""),
        "tags": t.get("tags", ""),
        "arr": arr_hit[0].name if arr_hit else None,
        "_owner": arr_hit,
        "_qb": qb,
    }

    decision = evaluate(t, row["bad_file"], arr_hit, safety, ownership_known)
    if verdict == "warn":
        # Worth recording, not worth destroying over. The safety mode still
        # decides whether this torrent was ever ours to touch.
        if decision is None:
            return None
        row["decision"] = "warn"
        return row
    if decision is None:
        log.info("Blocked by the %s profile but safety mode %r does not cover "
                 "it, leaving alone: %s", profile,
                 safety.get("mode", "arr_tracked"), t.get("name"))
        return None
    row["decision"] = decision
    row["safety_mode"] = safety.get("mode", "arr_tracked")
    return row


def _probe_pass(qb, candidates, cfg, state, safety, ownership_known, arr_by_name,
                side_effects=True):
    """Second lane: the torrents the fast lane had nothing to say about.

    Reading headers that are already on disk is free, so every candidate gets
    that. Steering costs bandwidth and mutates settings, so it is rationed by
    `max_torrents_per_scan` and a wall-clock budget for the whole pass.

    `side_effects=False` keeps the free pass and refuses the steered one. That
    is what the WebUI preview asks for, and it is asked for explicitly rather
    than inferred from `dry_run`: preview has to be observational whatever the
    configured mode happens to be.
    """
    p = probe.settings(cfg)
    deadline = time.time() + p["scan_budget_seconds"]
    steers_left = p["max_torrents_per_scan"] if side_effects else 0
    rows, checked = [], 0
    log.debug("Probe lane: %d candidate(s), %d steering slot(s), %ds budget",
              len(candidates), steers_left, p["scan_budget_seconds"])
    for t, files, arr_hit in candidates:
        if time.time() >= deadline:
            log.debug("Probe lane: scan budget spent, %d of %d candidate(s) "
                      "not reached this pass", len(candidates) - checked,
                      len(candidates))
            break
        checked += 1
        try:
            res = probe.inspect(qb, t, files, cfg, state, deadline,
                                allow_steer=steers_left > 0)
        except Exception:  # noqa: BLE001 - the probe lane must never be able to
            # take down a scan; the fast lane has already had its say.
            log.exception("Probe failed on %s", t.get("name"))
            continue
        if res.steered:
            steers_left -= 1
        if not res.findings:
            continue
        log.info("Probe findings for %s: %s", t.get("name"),
                 ", ".join(f"{f['reason']}({f.get('evidence', {}).get('filename', '?')})"
                           for f in res.findings))
        row = _assess(t, list(res.findings), arr_hit, arr_by_name, cfg, safety,
                      ownership_known, qb)
        if row:
            rows.append(row)
    return rows


def scan(cfg, state, side_effects=True):
    """One pass over qBittorrent's torrents. Returns list of action dicts
    (used both for live reaping and the WebUI dry-run preview).

    `side_effects=False` makes the pass observational: no steering, no ledger
    writes, nothing in qBittorrent changed. The probe lane's free pass still
    runs, because reading bytes already on disk changes nothing and a preview
    that could not see probe findings would be lying by omission.

    This is a parameter rather than a reading of `cfg["dry_run"]` because the
    two answer different questions. `dry_run` is the user's standing policy on
    whether Protectarr may reap; `side_effects` is this caller's statement about
    whether it is allowed to touch anything at all. Preview needs the second,
    and inferring it from the first is how the preview button ended up steering
    live torrents whenever dry_run was off.
    """
    started = time.time()
    qc = cfg["qbittorrent"]
    log.debug("Scan starting: qbittorrent=%s dry_run=%s safety_mode=%s",
              qc.get("url"), cfg.get("dry_run"), cfg.get("safety", {}).get("mode"))
    qb = QbitClient(qc["url"], qc.get("username", ""), qc.get("password", ""),
                    api_key=qc.get("api_key", ""), verify_ssl=qc.get("verify_ssl", True))
    qb.login()

    det = cfg["detection"]
    only_active = det.get("only_active", True)

    # Ask qBittorrent to do the filtering. On a large library the unfiltered
    # list is megabytes of seeding torrents fetched every poll and discarded
    # immediately; the state check below still has the final say.
    torrents = qb.torrents(state_filter="downloading" if only_active else None)
    log.debug("qBittorrent returned %d torrent(s)%s", len(torrents),
              " (server-side filter=downloading)" if only_active else "")

    arr_clients = build_clients(cfg)
    # name -> raw config entry, so policy can read a per-*arr `profile`.
    arr_by_name = {a.get("name"): a for a in cfg.get("arrs", []) if a.get("name")}
    # hash -> (client, queue_record)
    owner = {}
    # If any queue read fails we cannot tell an orphan from a torrent whose
    # owner we simply could not reach, so direct deletion is suppressed below.
    ownership_known = True
    for client in arr_clients:
        try:
            queue = client.queue_by_hash()
            log.debug("%s queue: %d item(s)", client.name, len(queue))
            for h, rec in queue.items():
                owner.setdefault(h, (client, rec))
        except requests.RequestException as e:
            ownership_known = False
            _log(state, f"Could not read {client.name} queue: {e}", logging.ERROR)
    if not ownership_known:
        log.warning("At least one application queue could not be read, so "
                    "ownership is unknown this pass. Torrents will not be "
                    "deleted directly from qBittorrent.")

    safety = cfg["safety"]
    actions = []
    inspected = skipped = 0
    probe_on = probe.enabled(cfg)
    probe_candidates = []

    # Unconditional, and deliberately not gated on the probe being enabled: a
    # process that died mid-probe left a torrent with most of its files switched
    # off, and turning the feature off afterwards must not strand it. Runs every
    # pass rather than once, because a restore that fails has to be retried by a
    # running Protectarr; ledger.reconcile() backs off per entry and returns
    # immediately when there is nothing due.
    # Skipped entirely on an observational pass. Restoring is repair rather than
    # damage, but it is still a write to qBittorrent, and "preview changes
    # nothing" is worth more than making a repair a few seconds earlier.
    if side_effects:
        first_reconcile = not state.get("probe_reconciled")
        state["probe_reconciled"] = True
        try:
            probe.reconcile(qb, announce=first_reconcile)
        except Exception:  # noqa: BLE001 - never let cleanup break a scan
            log.exception("Probe ledger reconcile failed")

        # Before anything is detected or acted on, so a torrent whose previous
        # remediation is still outstanding is settled rather than remediated a
        # second time.
        try:
            summary = intents.reconcile(arr_clients)
            if summary["removed"] or summary["unverified"]:
                _log(state, f"Reconciled remediations from an earlier run: "
                            f"{summary['removed']} confirmed, "
                            f"{summary['unverified']} unverified",
                     logging.WARNING if summary["unverified"] else logging.INFO)
        except Exception:  # noqa: BLE001 - never let cleanup break a scan
            log.exception("Remediation intent reconcile failed")

    for t in torrents:
        thash = t.get("hash", "")
        tstate = t.get("state", "")
        if only_active and tstate not in DOWNLOADING_STATES:
            skipped += 1
            continue  # finished/seeding - nothing left to prevent
        if tstate in ("metaDL", "forcedMetaDL"):
            skipped += 1
            log.debug("Skipping %s: metadata not in yet (%s)", t.get("name"), tstate)
            continue  # metadata not in yet; catch on a later pass
        try:
            files = qb.files(thash)
        except requests.RequestException as e:
            log.warning("Could not read file list for %s: %s", t.get("name"), e)
            continue
        if not isinstance(files, list):
            log.warning("Unexpected file list for %s (%s), skipping",
                        t.get("name"), type(files).__name__)
            continue
        inspected += 1
        arr_hit = owner.get(thash.lower())
        log.debug("Inspecting %s: state=%s files=%d category=%s arr=%s",
                  t.get("name"), tstate, len(files), t.get("category") or "-",
                  arr_hit[0].name if arr_hit else "untracked")

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
            # Nothing in the metadata. The probe lane may still find a payload
            # wearing a real media extension - but only for torrents the safety
            # mode would have let us act on. Nothing else is worth the bytes,
            # and steering a torrent Protectarr may never touch would be a
            # change made for no possible outcome.
            if probe_on and evaluate(t, "", arr_hit, safety,
                                     ownership_known) is not None:
                probe_candidates.append((t, files, arr_hit))
            continue

        log.info("Findings for %s: %s", t.get("name"),
                 ", ".join(f"{f['detector']}/{f['reason']}"
                           f"({f.get('evidence', {}).get('filename', '?')})"
                           for f in findings))

        row = _assess(t, findings, arr_hit, arr_by_name, cfg, safety,
                      ownership_known, qb)
        if row:
            actions.append(row)

    # The probe lane waits its turn. A known fake already queued for removal is
    # worth more than a suspected one, and probing blocks this pass for as long
    # as its budget allows, so a pass with something to reap reaps it now and
    # probes on the next one.
    if probe_candidates:
        pending = any(a.get("decision") != "warn" for a in actions)
        if pending:
            log.debug("Probe lane: skipped this pass, %d reap(s) queued first",
                      sum(1 for a in actions if a.get("decision") != "warn"))
        else:
            actions.extend(_probe_pass(qb, probe_candidates, cfg, state, safety,
                                       ownership_known, arr_by_name,
                                       side_effects=side_effects))

    log.debug("Scan finished in %.2fs: %d inspected, %d skipped, %d action(s)",
              time.time() - started, inspected, skipped, len(actions))
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
        "findings": a.get("findings") or [],
        "policy": a.get("policy"),
        "peers_harvested": over.pop("peers", 0),
        "dry_run": bool(cfg.get("dry_run", True)),
    }
    ev.update(over)
    return ev


def _warn_fingerprint(a):
    """Identity of a warning: the torrent plus everything observed about it.

    Hash alone is too coarse - a torrent can legitimately acquire a new finding
    later (the probe lane will make that routine), and that deserves a fresh
    entry rather than being swallowed as a repeat.
    """
    return (a["hash"], json.dumps(a.get("findings") or [],
                                  sort_keys=True, separators=(",", ":")))


def _owner_block(owner):
    if not owner:
        return None
    client, record = owner
    return {"type": client.type, "instance": client.name,
            "media": _media_name(record), "release_title": record.get("title")}


def apply_actions(actions, state, cfg):
    dry_run = cfg.get("dry_run", True)
    if actions:
        log.debug("Applying %d action(s), dry_run=%s", len(actions), dry_run)
    safety = cfg.get("safety", {})
    requeue_enabled = safety.get("requeue_after_airdate", True)
    grace = safety.get("airdate_grace_hours", 0)
    warned = state.setdefault("warned", set())
    # A torrent whose previous remediation has not been accounted for is not
    # remediated again. Reconciliation is what resolves those, and acting on
    # one in the meantime would be a second irreversible step taken without
    # knowing the outcome of the first.
    outstanding = set() if dry_run else set(intents.blocked())
    for a in actions:
        _r = a.get("reason")
        label = f"{a['name']!r} (bad: {a['bad_file']!r}{' - ' + _r if _r else ''})"

        if a["decision"] != "warn" and (a["hash"] or "").lower() in outstanding:
            log.debug("Skipping %s: an earlier remediation is still "
                      "unaccounted for.", label)
            continue

        if a["decision"] == "warn":
            # The profile flagged it without calling for removal. Recorded once
            # per distinct set of observations, so a 20-second poll doesn't fill
            # the history but a genuinely new finding still surfaces.
            key = _warn_fingerprint(a)
            if key in warned:
                continue
            if len(warned) > 5000:      # long uptimes shouldn't leak memory
                warned.clear()
            warned.add(key)
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
                log.debug("Failing queue item %s on %s (indexer=%s, title=%r)",
                          record.get("id"), client.name, indexer or "unknown", source_title)
                peers = _harvest_peers(a, indexer, client.name, state, cfg)  # before removal

                # Write-ahead. Everything past this point is irreversible, and
                # a crash in the middle of it leaves a queue item that is
                # absent for reasons we would otherwise have no way to
                # establish. The watermark is read first so the intent records
                # the *arr's history as it was before we touched it.
                watermark = client.history_watermark()
                if not intents.open_intent(a["hash"], client, record,
                                           indexer=indexer, watermark=watermark):
                    _log(state, f"Not reaping {label}: the remediation could not "
                                f"be written down first.", logging.ERROR)
                    events.record(_event(
                        a, cfg, owner=_owner_block(a["_owner"]),
                        action={"result": "failed", "decision": "arr_fail",
                                "removed": False, "blocklisted": False,
                                "error": "remediation intent could not be persisted"},
                        redownload={"decision": "none", "reason": "not_applicable"}))
                    continue

                outcome = client.fail(record["id"])  # remove + blocklist
                removed = True
                evidence = client.verify_remediation(a["hash"],
                                                     after_id=watermark)
                blocked = evidence["verified"]
                if blocked:
                    intents.update(a["hash"], milestone=intents.REMOVED,
                                   evidence=evidence, error=None)
                    log.debug("Remediation verified: history event %s, "
                              "blocklist row %s",
                              (evidence["event"] or {}).get("id"),
                              (evidence["blocklist"] or {}).get("id"))
                elif not evidence.get("reachable", True):
                    # We could not ask. The intent stays pending so the next
                    # reconcile asks again; an *arr that was briefly down is
                    # not evidence that the remediation failed.
                    intents.update(a["hash"], evidence=evidence,
                                   error=evidence["why"])
                else:
                    intents.update(a["hash"],
                                   milestone=intents.FAILED_UNVERIFIED,
                                   evidence=evidence, error=evidence["why"])

                # Requeue only if the removal is verified AND it has aired.
                # Unverified is not a reason to try harder: if we cannot show
                # the release was blocklisted, a search is an invitation to the
                # *arr to grab the same condemned release again.
                requeue = "disabled"
                rd = {"decision": "none", "reason": "requeue_disabled"}
                if not blocked:
                    requeue = "held (removal unverified)"
                    rd = {"decision": "held", "reason": "remediation_unverified",
                          "detail": evidence["why"]}
                    log.error(
                        "REMEDIATION UNVERIFIED for %r on %s: %s. Protectarr "
                        "will not search for a replacement. The intent is kept "
                        "in intents.json for diagnosis.",
                        source_title, client.name, evidence["why"])
                elif requeue_enabled:
                    aired, when = client.airdate_status(record, grace)
                    whenstr = when.date().isoformat() if when else "unknown"
                    log.debug("Air-date gate: aired=%s date=%s grace=%sh",
                              aired, whenstr, grace)
                    if aired is True:
                        command_id = client.search(record)
                        if command_id:
                            requeue = "requeued (aired)"
                            rd = {"decision": "searched", "reason": "aired",
                                  "command_id": command_id}
                            # Not settled yet. A search that has been issued is
                            # not a search that has finished, and the two are
                            # only distinguishable by following the command.
                            intents.update(a["hash"], search={
                                "command_id": command_id, "issued": time.time(),
                                "state": None, "result": None, "message": None})
                        else:
                            requeue = "requeue-failed"
                            rd = {"decision": "failed", "reason": "search_failed"}
                            intents.update(a["hash"], milestone=intents.SETTLED)
                    elif aired is False:
                        requeue = f"held (airs {whenstr})"
                        rd = {"decision": "held", "reason": "not_yet_aired",
                              "airs": whenstr}
                        intents.update(a["hash"], milestone=intents.SETTLED)
                    else:
                        requeue = "held (airdate unknown)"
                        rd = {"decision": "held", "reason": "airdate_unknown"}
                        intents.update(a["hash"], milestone=intents.SETTLED)
                else:
                    intents.update(a["hash"], milestone=intents.SETTLED)

                _log(state, f"Reaped via {client.name}: {label} | "
                            f"blocklisted={'yes' if blocked else 'UNVERIFIED'} | {requeue}")
                record_reap(state, client.name, indexer)
                events.record(_event(
                    a, cfg, indexer=indexer, peers=peers,
                    owner={"type": client.type, "instance": client.name,
                           "media": _media_name(record), "release_title": source_title},
                    action={"result": "reaped", "decision": "arr_fail",
                            "via": "arr", "safety_mode": a.get("safety_mode"),
                            "removed": True, "blocklisted": bool(blocked),
                            # What the queue DELETE itself reported. "absent"
                            # means the record was already gone, which proves
                            # nothing on its own - the oracle below is what
                            # decides whether the remediation happened.
                            "queue_delete": outcome,
                            "verification": evidence["why"],
                            "history_event": (evidence["event"] or {}).get("id"),
                            "blocklist_row": (evidence["blocklist"] or {}).get("id")},
                    redownload=rd))
            elif a["decision"] == "qbit_delete":
                peers = _harvest_peers(a, None, "qBittorrent", state, cfg)  # before removal
                a["_qb"].delete(a["hash"], delete_files=True)
                removed = True
                _log(state, f"Deleted from qBittorrent via category fallback "
                            f"(no *arr owns it): {label}")
                record_reap(state, "qBittorrent", a.get("category") or None)
                events.record(_event(
                    a, cfg, peers=peers,
                    owner={"type": "qbittorrent", "instance": "qBittorrent",
                           "media": None, "release_title": a.get("name")},
                    action={"result": "reaped", "decision": "qbit_delete",
                            # No owning *arr, so there is no release blocklist
                            # and no requeue decision - worth saying plainly
                            # rather than rendering this like an *arr reap.
                            "via": "category_fallback",
                            "safety_mode": a.get("safety_mode"),
                            "removed": True, "blocklisted": False},
                    redownload={"decision": "none", "reason": "not_applicable"}))
        except (requests.RequestException, QbitError) as e:
            # If the removal already succeeded, the fake really is gone and
            # blocklisted; only the confirmation or requeue half broke. Calling
            # that "failed" would be factually wrong, so it's recorded as
            # partial with the outcome left unknown rather than asserted.
            if removed:
                _log(state, f"Removed, but the follow-up check failed for {label}: {e}", logging.WARNING)
                result, rd = "partial", {"decision": "unknown",
                                         "reason": "verification_failed"}
            else:
                _log(state, f"Action failed for {label}: {e}", logging.ERROR)
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
        self.state = {"stats": load_stats(), "last_scan": None,
                      "last_error": None, "running": False,
                      "blocklist": {"last": None, "entries": 0, "bytes": 0,
                                    "applied": False, "error": None},
                      "banned": {"last": None, "count": 0, "error": None}}
        self._stop = threading.Event()
        self._thread = None
        self._reload = threading.Event()
        self._bl_last = 0.0  # monotonic-ish epoch of last blocklist refresh
        # One scan at a time, whichever thread asks. The WebUI runs in this
        # process, so a preview or a "scan now" from a request thread used to be
        # able to run a whole second pass alongside the worker: two probes on
        # one torrent, and the second one recording the first one's steered
        # priorities as the originals.
        self._scan_lock = threading.Lock()

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
                "last": logs.now(),
                "entries": res["entries"], "bytes": res["bytes"],
                "applied": res["applied"], "error": None}
            _log(self.state, f"IP blocklist updated: {res['entries']} entries "
                             f"({res['bytes']//1024} KiB), applied={res['applied']}")
        except (requests.RequestException, QbitError, OSError, ValueError) as e:
            self.state["blocklist"]["error"] = str(e)
            self._bl_last = time.time()  # back off; don't hammer on failure
            _log(self.state, f"IP blocklist update failed: {e}")

    def preview(self):
        """Observational scan for the WebUI - returns serializable action rows.

        Changes nothing: not qBittorrent, not the probe ledger, not the event
        history. It reports what Protectarr would decide from what it can see.

        Does not wait for a running scan. A probe pass can hold the worker for
        its full budget, and a preview request that hangs for two minutes is
        worse than one that says the scanner is busy.
        """
        if not self._scan_lock.acquire(blocking=False):
            raise RuntimeError("A scan is already running. Try again in a moment.")
        try:
            cfg = cfg_mod.load()
            actions = scan(cfg, self.state, side_effects=False)
        finally:
            self._scan_lock.release()
        return [{k: v for k, v in a.items() if not k.startswith("_")} for a in actions]

    def apply_banned_ips(self, cfg=None):
        """Push the manual banned-IP list to qBittorrent. Records status."""
        cfg = cfg or cfg_mod.load()
        if not cfg.get("banned_ips", {}).get("enabled"):
            return
        try:
            from . import blocklist as bl_mod
            count = bl_mod.apply_banned_ips(cfg)
            self.state["banned"] = {"last": logs.now(),
                                    "count": count, "error": None}
            _log(self.state, f"Applied {count} manually banned IP(s) to qBittorrent.")
        except (requests.RequestException, QbitError) as e:
            self.state["banned"]["error"] = str(e)
            _log(self.state, f"Banned-IP apply failed: {e}", logging.ERROR)

    def _run(self):
        try:
            self._loop()
        finally:
            # Never leave the UI claiming it is running when it is not.
            self.state["running"] = False

    def _loop(self):
        while not self._stop.is_set():
            cfg = cfg_mod.load()
            try:
                with self._scan_lock:
                    actions = scan(cfg, self.state)
                    apply_actions(actions, self.state, cfg)
                self.state["last_scan"] = logs.now()
                self.state["last_error"] = None
            except (QbitError, requests.RequestException) as e:
                self.state["last_error"] = str(e)
                _log(self.state, f"Scan error: {e}", logging.ERROR)
            except Exception as e:  # noqa: BLE001 - one bad pass must not end
                # the loop. Dying here used to leave running=True forever, so
                # Protectarr looked healthy while silently scanning nothing.
                self.state["last_error"] = f"{type(e).__name__}: {e}"
                log.exception("Unexpected error during scan; continuing")
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
        if not self._scan_lock.acquire(blocking=False):
            return {"queued": False, "running": True, "busy": True}
        try:
            cfg = cfg_mod.load()
            actions = scan(cfg, self.state)
            apply_actions(actions, self.state, cfg)
        finally:
            self._scan_lock.release()
        self.state["last_scan"] = logs.now()
        return {"queued": False, "running": False, "actions": len(actions)}
