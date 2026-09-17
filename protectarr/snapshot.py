"""What the scan believed, projected once so a page can read it.

The engine already works all of this out. `core.scan()` resolves ownership from
every queue it managed to read, resolves a profile per torrent, asks `explain`
whether policy covers it, and then returns only the torrents that produced a
finding *and* passed policy *and* passed safety. A healthy torrent never
appears anywhere, which is why there has never been a view of one.

So this is a projection, not a second source of truth. Nothing here calls
qBittorrent, nothing here calls an *arr, and nothing here decides anything: it
takes the facts one pass established and flattens them into rows. The rules
that follow from that are worth stating, because each of them was a way to get
this wrong:

*The spine is the torrent list, never `ownership.json`.* Ownership records
outlive the torrents they describe by up to `ownership_prune_minutes`, and a
page that iterated the store would render an hour of ghosts. Iterating the
torrent list means a stale record simply has nothing to attach to.

*Publication is a single rebind.* The snapshot is built complete and then
assigned in one statement. A reader in a request thread sees the previous
snapshot or the next one, never a half-filled one, and never a row being
updated underneath it.

*A failed pass publishes nothing.* The previous snapshot stays, and its age is
what tells the operator it is stale. Replacing it with an empty list would make
an unreachable qBittorrent look exactly like a qBittorrent with nothing to do,
and those need opposite reactions.

*Absence of a measurement is not zero.* `absent_for` is None whenever the pass
could not verify an absence, and that travels all the way to the template
rather than being rounded into a progress bar starting at zero.
"""

import time

from . import logs
from . import policy

log = logs.get("snapshot")

# Torrents the detection loop cannot inspect yet, and why. Keyed on the
# qBittorrent state so the reason survives into the row rather than being
# inferred again in a template.
UNINSPECTABLE = {
    "metaDL": "awaiting_metadata",
    "forcedMetaDL": "awaiting_metadata",
}


def _tags(raw):
    return [t.strip() for t in (raw or "").split(",") if t.strip()]


def _remediation(intent):
    """The part of a remediation intent an operator can act on.

    A projection, like `intents.audit` is: queue ids, watermarks and attempt
    counters are recovery state and belong nowhere near a page. What is left is
    the milestone, when it started, and why it is stuck if it is.

    Note what is *not* here. Whether a replacement search is being held until a
    release airs lives in `events.jsonl`, not on the intent, so it cannot be
    read from this. In practice that combination barely exists: an intent that
    reached the air-date decision has already had its torrent removed from
    qBittorrent, so it has no row on this page to appear in.
    """
    if not intent:
        return None
    search = intent.get("search") or {}
    return {
        "milestone": intent.get("milestone"),
        "remediation_id": intent.get("remediation_id"),
        "opened": intent.get("opened"),
        "arr": intent.get("arr"),
        "error": intent.get("error"),
        "search_state": search.get("state"),
        "search_result": search.get("result"),
        "search_message": search.get("message"),
    }


def _probe(thash, probe_on, steered, candidates):
    """What the probe lane is doing with this torrent, if anything."""
    if not probe_on:
        return {"enabled": False, "candidate": False, "steered": False,
                "opened": None}
    entry = steered.get(thash) or {}
    return {
        "enabled": True,
        # Selected for the probe lane this pass: the fast lane had nothing to
        # say and policy covers it. Not a promise that it was reached - the
        # lane is budgeted and defers to a pass that has something to reap.
        "candidate": thash in candidates,
        # An open ledger entry means its priorities are currently altered and
        # Protectarr owes it a restore.
        "steered": bool(entry),
        "opened": entry.get("opened"),
    }


def build(torrents, taken_at, resolved, owner, ownership_known, unreadable,
          cfg, arr_by_name, actions=(), intents_by_hash=None,
          probe_on=False, steered=None, candidates=(), explain=None):
    """One pass's beliefs as a plain dict. Pure; safe to call anywhere.

    `explain` is injected rather than imported so this module does not import
    `core` while `core` imports it. It is always `core.explain`.
    """
    steered = steered or {}
    intents_by_hash = intents_by_hash or {}
    candidates = set(candidates)
    safety = cfg.get("safety", {})
    by_hash = {(a.get("hash") or "").lower(): a for a in actions}

    rows = []
    for t in torrents:
        thash = (t.get("hash") or "").lower()
        qstate = t.get("state") or ""
        own = resolved.get(thash)
        arr_hit = owner.get(thash)
        category = t.get("category") or ""
        arr_entry = arr_by_name.get(arr_hit[0].name) if arr_hit else None
        profile, profile_source = policy.resolve_with_source(
            cfg, arr_entry, category)
        judgement = explain(t, arr_hit, safety, ownership_known, own)
        action = by_hash.get(thash)

        rows.append({
            "hash": thash,
            "name": t.get("name") or thash[:8],
            "qstate": qstate,
            "progress": t.get("progress"),
            "size": t.get("size"),
            "dlspeed": t.get("dlspeed"),
            "eta": t.get("eta"),
            "category": category,
            "tags": _tags(t.get("tags")),

            # Whether the detection lanes actually got to look at it. A torrent
            # still pulling its metadata has no file list to read, so it is
            # neither clean nor flagged, and saying either would be a guess.
            "inspected": qstate not in UNINSPECTABLE,
            "skip_reason": UNINSPECTABLE.get(qstate),

            "ownership": own.state if own else "untracked",
            "owner": own.owner if own else None,
            # From the pass, not from disk. The stored record carries no
            # rationale at all, and for a conflict it deliberately carries no
            # claimants either, because recording one would turn an unresolved
            # situation into a decision on the next pass.
            "ownership_why": own.why if own else None,
            "absent_for": own.absent_for if own else None,
            "owner_type": _owner_type(own, arr_hit),

            "profile": profile,
            "profile_source": profile_source,

            "policy_state": judgement.state,
            "policy_reason": judgement.reason,
            "policy_detail": judgement.detail,
            # What would happen if something were found here. Never a statement
            # that anything is going to happen.
            "would": judgement.action,

            "probe": _probe(thash, probe_on, steered, candidates),
            "remediation": _remediation(intents_by_hash.get(thash)),

            # Only for torrents this pass actually flagged. The overwhelming
            # majority are None, and that is the normal, healthy state.
            "finding": _finding(action),
        })

    return {
        "taken_at": taken_at,
        "rows": rows,
        "ownership_known": ownership_known,
        "unreadable": sorted(unreadable),
        "safety_mode": safety.get("mode", "arr_tracked"),
        "dry_run": bool(cfg.get("dry_run", True)),
        "probe_enabled": bool(probe_on),
    }


def _owner_type(own, arr_hit):
    """The owning application's type, preferring this pass's own evidence."""
    if arr_hit:
        return arr_hit[0].type
    return None


def _finding(action):
    if not action:
        return None
    return {
        "reason": action.get("reason"),
        "file": action.get("bad_file"),
        "decision": action.get("decision"),
        "severity": (action.get("policy") or {}).get("severity"),
        "count": len(action.get("findings") or []),
    }


def publish(state, snap):
    """Swap the published snapshot for a newer one, atomically.

    One rebind of one key. Readers hold whatever they read; nothing is mutated
    in place, so a request thread rendering the previous snapshot keeps a
    coherent one for as long as it needs it.
    """
    state["active"] = snap
    log.debug("Published an active-downloads snapshot: %d row(s)",
              len(snap["rows"]))
    return snap


def published(state):
    """The current snapshot, or None if no pass has completed yet.

    None is not "nothing is downloading". It means Protectarr has not managed a
    full pass since it started, and the page has to say that rather than
    render an empty table.
    """
    return state.get("active")


def age(snap, now=None):
    """How long ago the snapshot's torrent list was read, in seconds."""
    if not snap or not snap.get("taken_at"):
        return None
    return max(0.0, (time.time() if now is None else now) - snap["taken_at"])
