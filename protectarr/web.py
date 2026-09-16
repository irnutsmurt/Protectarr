"""Flask WebUI: Servarr-style settings page + Forms login server."""

import io
import os
import time
import hmac
import zipfile
import base64
import secrets
import threading
from datetime import timedelta

import requests
from flask import (Flask, render_template, request, redirect, url_for,
                   jsonify, flash, session, Response, send_file, g)
from werkzeug.security import generate_password_hash, check_password_hash

from . import config as cfg_mod
from . import dashboard as dash
from . import events
from . import evidence
from . import intents
from . import logs
from . import __version__
from .netauth import resolve_client_ip, is_local
from . import probe
from .qbit import QbitClient, QbitError
from .arr import ArrClient, ARR_TYPES, build_clients

# Endpoints reachable without a session (login form + static assets + health).
PUBLIC_ENDPOINTS = {"login", "static", "ping"}
# JSON endpoints - respond 401 rather than redirecting to the login page.
API_ENDPOINTS = {"test_qbit", "test_arr", "preview", "dashboard_data",
                 "api_index", "api_status", "api_stats", "api_watchlist",
                 "api_log", "api_preview", "api_command", "api_history",
                 "api_logfiles", "qbit_taxonomy", "probe_check", "reveal_api_key"}
BASIC_REALM = 'Basic realm="Protectarr", charset="UTF-8"'

# Two tables, deliberately separate, because they answer different questions.
#
# SAVE_SECTIONS is the set of persistence boundaries. Each one is a <form>, a
# POST, one branch of `save_section()`, and one set of config keys that branch
# overwrites wholesale. `save_section()` validates against this and nothing
# else: it has no idea which page a section is rendered on, and it must stay
# that way, or rearranging the navigation becomes a way to move a config key
# into a different transaction. tests/test_save_boundaries.py pins what each
# one owns and what an omitted field does to it.
#
# SETTINGS_PAGES is a layout decision: which of those boundaries appear
# together, in what order, under what heading. Changing it moves cards around
# and changes URLs. It cannot change what any Save writes.
#
# qBittorrent + the *arr apps live on their own top-level "Applications" page,
# not under Settings.
SAVE_SECTIONS = ("detection", "safety", "probe", "blocklist", "bannedips",
                 "security", "logging")

# (key, label, description, [save sections, in render order])
SETTINGS_PAGES = [
    ("detection-remediation", "Detection & Remediation",
     "What flags a download, what Protectarr may do about it, and the optional "
     "content probe.",
     ["detection", "safety", "probe"]),
    ("network", "Network Controls",
     "Peer filtering applied to qBittorrent: the bulk blocklist, and your own "
     "banned addresses.",
     ["blocklist", "bannedips"]),
    ("administration", "Administration",
     "Authentication for this WebUI, and logging.",
     ["security", "logging"]),
]
SETTINGS_PAGE_KEYS = {k for k, *_ in SETTINGS_PAGES}
# Which page a save section renders on, for the in-page anchor and for sending
# the pre-0.7.0 URLs somewhere useful instead of 404ing a bookmark.
SECTION_PAGE = {s: k for k, _, _, sections in SETTINGS_PAGES for s in sections}


def section_url(section):
    """Where the card for `section` lives now.

    One helper, used by the page redirect and by the post-save redirect, so
    neither `settings_page()` nor `save_section()` carries its own copy of the
    grouping. `save_section()` calling this is not the same as knowing about
    pages: it asks where to send the browser afterwards, which is the one
    presentation question a POST handler cannot avoid.
    """
    return url_for("settings_page", key=SECTION_PAGE[section]) + f"#section-{section}"

# Pages whose content is tables and charts, which read better with more width
# than the 1320px cap that keeps forms readable. Keyed on the page rather than
# the template so the decision is "what kind of page is this", made once, and
# a new data page opts in by being added here rather than by copying a style
# attribute.
#
# Deliberately absent, despite all three containing tables:
#   settings      every section under it is a form.
#   applications  a configuration surface. It holds structured lists, but they
#                 are URLs, API keys and path mappings, and stretching a
#                 credential field across an ultrawide display helps nobody.
#   system        its main element is a seven-row key/value table with a fixed
#                 220px label column and short values, which gets worse with
#                 width, not better: the label ends up an inch from its value.
#                 The log box below it benefits slightly, but it is
#                 height-capped and scrolls, so it is the lesser half.
WIDE_PAGES = {"dashboard", "history", "watchlist"}


def _mappings_from_form(form):
    """Paired path inputs -> (mappings, half-filled rows).

    Two labelled fields rather than one "a = b" text box, so that "a mapping is
    two paths" is something the form shows rather than something an error
    message has to explain after the fact.
    """
    out, partial = [], []
    for src, dst in zip(form.getlist("map_from"), form.getlist("map_to")):
        src, dst = src.strip(), dst.strip()
        if src and dst:
            out.append({"from": src, "to": dst})
        elif src or dst:
            partial.append(src or dst)
    return out, partial


def _arrs_for_browser(cfg):
    """The *arr fields the settings UI needs, and nothing else.

    Built by naming what goes out rather than by deleting `api_key` from a copy
    of the config. An allowlist fails closed: add a credential to an *arr entry
    later and it simply is not in this dict. A denylist fails open, silently, on
    exactly the day someone adds the field and forgets this function exists.

    `has_key` carries whether a key is stored, which is all the browser needs to
    choose between "(unchanged)" and "required" on the input.
    """
    out = []
    for i, a in enumerate(cfg.get("arrs") or []):
        out.append({
            "index": i,
            "name": a.get("name", ""),
            "type": a.get("type", ""),
            "url": a.get("url", ""),
            "web_url": a.get("web_url", ""),
            "has_key": bool(a.get("api_key")),
        })
    return out


# Milestone -> (pill label, pill class, one line of explanation). The backend
# has four milestones and this shows three labels: `pending` and `removed` are
# both "not finished yet" to an operator, and `removed` is normally transient -
# the destructive half is verified and the replacement search has not reported
# back. The distinction is not lost, it moves to the line underneath and to the
# Details dialog, where it can be stated precisely instead of compressed into
# one word.
_MILESTONES = {
    "pending": ("Pending", "off",
                "the removal has not been verified yet"),
    "removed": ("Pending", "off",
                "removal verified; waiting for the replacement search to finish"),
    "settled": ("Settled", "on",
                "Protectarr finished the workflow. This does not mean a "
                "replacement was downloaded"),
    "failed_unverified": ("Failed Unverified", "bad",
                          "Protectarr could not prove the release was "
                          "blocklisted, so it stopped rather than searching "
                          "for a replacement"),
}


HISTORY_LIMIT = 250

# Swarm Observations shows one row per IP, and an IP is only here because
# Protectarr acted on a torrent it was in. Deeper than this is a job for the
# API, not for a page the operator is meant to read.
WATCHLIST_LIMIT = 500

# How often the System page re-reads the activity log while Live is on. A scan
# runs on a multi-second cycle and the log is prose about what it did, so
# anything faster is a request per second that returns the same bytes.
LOG_POLL_MS = 5000

# Encounter outcome -> (label, pill class). The four milestone keys reuse
# _MILESTONES' wording exactly, because this is the same fact about the same
# remediation seen from the other end, and two names for it would be two
# things to keep in step. Everything here describes what Protectarr's action
# did. None of it describes the peer.
_OUTCOMES = {
    "pending": ("Pending", "off"),
    "removed": ("Pending", "off"),
    "settled": ("Settled", "on"),
    "failed_unverified": ("Failed Unverified", "bad"),
    "deleted_no_arr": ("Deleted (no *arr)", "on"),
    "not_attempted": ("Not Attempted", "off"),
    "failed": ("Failed", "bad"),
    "partial": ("Partial", "off"),
}
# Migrated rows and encounters still in flight both land here. "Unknown" is a
# real answer and gets the same neutral pill as any other unfinished state
# rather than a class of its own.
_OUTCOME_UNKNOWN = ("Outcome Unknown", "off")


def _outcome(token):
    """(label, pill class) for an encounter outcome, never None."""
    return _OUTCOMES.get(token, _OUTCOME_UNKNOWN) if token else _OUTCOME_UNKNOWN


def _swarm_view(row):
    """One Swarm Observations table row, ready to render.

    `encounters` and `distinct_torrents` are both here and both plain counts.
    An encounter is one action Protectarr took; a distinct torrent is one
    infohash. Ten encounters against one torrent and ten against ten torrents
    are very different evidence, and collapsing them into a single "distinct
    fakes" number - which is what this page used to show - hid the difference.
    """
    label, cls = _outcome(row.get("latest_outcome"))
    out = dict(row)
    out["outcome_label"] = label
    out["outcome_class"] = cls
    # A lower bound is shown as "6+" rather than "6". Migration can prove an IP
    # was in more encounters than it can place, and printing the placeable
    # count alone would state a number we know to be too low.
    out["encounters_display"] = (f"{row['encounters']}+"
                                 if row.get("encounters_lower_bound")
                                 else str(row["encounters"]))
    return out


def _swarm_detail(p):
    """The Peer Profile Details payload for one IP.

    The two notices are separate facts and are computed separately. Detail can
    be missing because retention expired it, or because the legacy ledger
    overwrote it and never recorded which encounter it belonged to. Calling
    both "pruned" would blame the retention policy for data the old harvest
    ledger lost years before any policy existed.
    """
    if not p:
        return {}
    history = []
    for h in p.get("history") or []:
        label, cls = _outcome(h.get("outcome"))
        row = dict(h)
        row["outcome_label"] = label
        row["outcome_class"] = cls
        history.append(row)
    expired = max(0, p["encounters"] - (p.get("retained_details") or 0))
    return {
        "ip": p["ip"],
        "first_observed": p.get("first_observed"),
        "last_observed": p.get("last_observed"),
        "encounters": p["encounters"],
        "encounters_display": (f"{p['encounters']}+"
                               if p.get("encounters_lower_bound")
                               else str(p["encounters"])),
        "distinct_torrents": p.get("distinct_torrents"),
        "retained_details": p.get("retained_details"),
        "details_expired": expired,
        "legacy_unattributed": p.get("legacy_unattributed") or 0,
        "ever_seeder": p.get("ever_seeder"),
        "history": history,
    }


def _history_rows(evs, limit=None):
    """Fold a remediation's lifecycle events into one row each.

    A single reap now writes several events over its life: the reap itself,
    then whatever a later scan or a restart discovers about it. Listing those
    separately would make one release look like several incidents, and the
    newest row would be the one with the least context - a bare "settled" with
    no finding attached.

    So events sharing a `remediation_id` collapse into one row whose status
    comes from the newest and whose detail comes from the detection event.
    `evs` must be newest first, which is what `events.iter_events` yields. The
    join is equality on an id minted when the intent was opened; nothing here
    matches on hash, title or time.

    `limit` bounds *rows*, not events, and is what lets this consume a lazy
    stream. The page used to read a fixed 400 events and fold whatever came
    back, which had two faults: three events per remediation meant 400 events
    were only ~134 rows, so lifecycle logging quietly cut the page's depth to a
    third of what 0.2.x showed; and a remediation straddling the cutoff was
    built from its lifecycle event alone, producing a row asserting "Settled"
    with no finding and no action behind it. Bounding rows instead fixes both,
    because the stream can always be pulled one event further.

    Once `limit` rows exist no older group is admitted - those are already off
    the page and cannot affect it. Reading continues only while an admitted row
    is still missing the detection event that carries its evidence.
    """
    rows, by_id, pending = [], {}, set()
    for e in evs:
        rid = e.get("remediation_id")
        if rid and rid in by_id:
            row = by_id[rid]
            row["timeline"].append(e)
            # The detection event carries the findings, the policy and the
            # torrent record. A lifecycle event carries none of that, so when
            # the richer one turns up it becomes the row's base.
            if e.get("event_type") != "remediation":
                row["ev"] = e
                _base(row, e)
                pending.discard(rid)
                if limit is not None and len(rows) >= limit and not pending:
                    break
            continue
        if limit is not None and len(rows) >= limit:
            if not pending:
                break
            continue
        row = {"ev": e, "latest": e, "timeline": [e]}
        _base(row, e)
        if rid:
            by_id[rid] = row
            # Opened by a lifecycle event, so its evidence is older than this
            # point in the stream and has not been read yet.
            if e.get("event_type") == "remediation":
                pending.add(rid)
        rows.append(row)
        if limit is not None and len(rows) >= limit and not pending:
            break
    # Anything still pending ran out of retained history. Say so on the row
    # rather than rendering a milestone next to blanks, which reads as evidence
    # that Protectarr acted without detecting anything.
    for rid in pending:
        by_id[rid]["base_missing"] = True
    for row in rows:
        row.setdefault("base_missing", False)
        row["status"] = _history_status(row)
    return rows


def _detail(row):
    """What the Details dialog may show, named field by field.

    An allowlist, for the same reason `_arrs_for_browser` is one: this goes
    into the page as JSON, so serialising the raw event would publish whatever
    a future field happens to contain. Nothing here is a credential today, and
    naming the fields is what keeps that true when someone adds one.
    """
    e, latest = row["ev"], row["latest"]
    t = e.get("torrent") or {}
    o = e.get("owner") or {}
    act = e.get("action") or {}
    rd = e.get("redownload") or {}
    rem = (latest.get("remediation") or e.get("remediation") or {})
    search = rem.get("search") or {}
    return {
        "release": t.get("name") or o.get("release_title"),
        "media": o.get("media"),
        "app": f"{o.get('instance')} ({o.get('type')})" if o.get("instance") else None,
        "indexer": t.get("indexer"),
        "size": row.get("size"),
        "category": t.get("category"),
        "hash": t.get("hash"),
        # The dialog says it too. Someone who opens a row precisely because it
        # looks wrong should find the explanation there, not just in the cell
        # that sent them looking.
        "why": ("Detection event no longer retained" if row.get("base_missing")
                else row.get("why")),
        "base_missing": bool(row.get("base_missing")),
        "also": row.get("also") or [],
        "severity": row.get("severity"),
        "profile": row.get("profile"),
        "decision": act.get("decision"),
        "status": row.get("status"),
        "recovered": any((x.get("remediation") or {}).get("recovered")
                         for x in row["timeline"]),
        "queue_delete": act.get("queue_delete"),
        "verification": rem.get("verification") or act.get("verification"),
        "history_event": rem.get("history_event") or act.get("history_event"),
        "blocklist_row": rem.get("blocklist_row") or act.get("blocklist_row"),
        "error": rem.get("error") or act.get("error"),
        "requeue": row.get("requeue"),
        "search_command": search.get("command_id") or rd.get("command_id"),
        "search_state": search.get("state"),
        "search_result": search.get("result"),
        "search_message": search.get("message"),
        # Oldest first here: a timeline that runs backwards is a puzzle.
        "timeline": [{
            "when": x.get("timestamp"),
            "what": _timeline_label(x),
            "note": (x.get("remediation") or {}).get("note"),
        } for x in reversed(row["timeline"])],
    }


def _timeline_label(e):
    rem = e.get("remediation") or {}
    if e.get("event_type") == "remediation":
        milestone = rem.get("milestone") or "updated"
        return _MILESTONES.get(milestone, (milestone,))[0]
    return (e.get("action") or {}).get("result") or "recorded"


def _base(row, e):
    """Everything a row takes from its base event.

    One function rather than a few assignments because the base is replaced
    when the richer detection event turns up later in the fold. The first
    version of this only re-derived the finding, so a folded row silently lost
    its release size and its requeue decision to the lifecycle event that
    happened to be newest.
    """
    findings, decisive, severity, profile = events.normalize(e)
    row["why"] = events.describe(decisive)
    row["also"] = [events.describe(f) for f in findings if f is not decisive]
    row["severity"] = severity
    row["profile"] = profile
    row["requeue"] = events.describe_requeue(e.get("redownload"))
    row["size"] = _human_size((e.get("torrent") or {}).get("size"))


def _history_status(row):
    """(label, pill class, explanation) for a folded row.

    Only remediations have a milestone. A warn, a dry run and a category
    fallback delete never opened one, so they keep the older action-based
    wording rather than being given a lifecycle they do not have.
    """
    rem = (row["latest"].get("remediation")
           or row["ev"].get("remediation") or {})
    milestone = rem.get("milestone")
    if not milestone:
        return None
    label, cls, why = _MILESTONES.get(
        milestone, (milestone.replace("_", " ").title(), "off", ""))
    # "Recovering" says this process is finishing work an earlier one left
    # behind, which is worth saying out loud: the operator did not ask for it
    # and may be wondering why History changed on its own. It is keyed on the
    # intent outliving its process, not on which code path made the
    # transition - reconcile runs every scan, so that would label routine
    # follow-up as a crash recovery.
    if rem.get("recovered") and milestone in ("pending", "removed"):
        label = "Recovering"
    return {"label": label, "cls": cls, "why": why,
            "milestone": milestone, "source": rem.get("source")}


def _relative(ts, now=None):
    """A stored timestamp as "3 hours ago", or None if it is unreadable.

    The Dashboard's question is "was this recent", and an absolute timestamp
    makes the reader do the subtraction. The absolute value is still rendered
    beside it, because "2 days ago" is the wrong thing to quote in a bug
    report.

    Deliberately coarse. Nothing here is precise enough to justify "3 hours 12
    minutes", and rounding down is the honest direction: something that
    happened 119 minutes ago is reported as an hour ago, never as two.
    """
    at = dash.parse_ts(ts)
    if at is None:
        return None
    delta = (time.time() if now is None else now) - at
    if delta < 0:
        # A clock change, or a container whose timezone moved under a file
        # written by the previous one. "In the future" is not a thing this can
        # usefully say, so it declines rather than printing a negative age.
        return None
    if delta < 90:
        return "just now"
    # (upper bound, seconds per unit, name). The bound and the divisor are
    # stated separately because deriving one from the other is how this went
    # wrong the first time: a day is not sixty times an hour.
    for bound, per, unit in ((3600, 60, "minute"),
                             (86400, 3600, "hour"),
                             (2592000, 86400, "day")):
        if delta < bound:
            n = int(delta // per)
            return f"{n} {unit}{'' if n == 1 else 's'} ago"
    # Past a month the age has stopped being the interesting part and the date
    # is what someone would actually use. The caller still has the absolute
    # timestamp, so this declines rather than printing "63 days ago".
    return None


def _when(ts):
    """`{"abs": ..., "rel": ...}` for a timestamp, or None if there isn't one."""
    if not ts:
        return None
    return {"abs": ts, "rel": _relative(ts)}


def _triage(records):
    """Remediations a human has to look at, oldest first.

    Only `failed_unverified`. It is the one milestone the code itself treats as
    terminal-and-wrong: Protectarr could not prove the release was blocklisted,
    so it stopped, and it will not retry on its own or let the same torrent be
    remediated again. Everything else resolves without anyone being told.

    `pending` and `removed` are deliberately not here. They are transient by
    design - a reconcile finishes them on the next scan - and listing them
    would turn the normal few seconds between a reap and its verification into
    a queue of things that look broken.

    Oldest first because this is a work queue, not a feed. The one that has
    been waiting longest is the one to deal with.
    """
    rows = [r for r in (records or {}).values()
            if r.get("milestone") == intents.FAILED_UNVERIFIED]
    rows.sort(key=lambda r: r.get("opened") or 0)
    out = []
    for r in rows:
        ev = r.get("evidence") or {}
        out.append({
            "when": logs.stamp(r.get("opened")),
            "rel": _relative(logs.stamp(r.get("opened"))),
            "release": r.get("release_title") or r.get("hash"),
            "app": r.get("arr"),
            # The verification narrative if there is one, the exception if the
            # attempt threw, and a plain statement of the milestone if neither
            # was recorded. Never blank: a triage row with no issue named is a
            # row nobody can act on.
            "issue": (ev.get("why") or r.get("error")
                      or "Removal could not be verified"),
            "remediation_id": r.get("remediation_id"),
        })
    return out


def _attention(state, triage, evidence_health, intents_broken):
    """Current problems that need an operator, counted and named.

    Two classes, kept apart on purpose. A remediation problem is one release
    that needs a decision and belongs in the Triage Queue. A system problem is
    Protectarr itself being unable to work and belongs on the System page.
    Merging them would either invent History rows for a broken database or
    bury a failed remediation in a list of connection errors.

    Connectivity is not here. It is established by `/api/dashboard`, which the
    browser calls after this page is rendered, and the count is topped up
    there. Blocking the page on N network round trips to render a number would
    cost more than the number is worth.
    """
    system = []
    if state.get("last_error"):
        system.append({"what": "Last scan failed", "detail": state["last_error"]})
    if evidence_health.get("broken"):
        system.append({"what": "Evidence store unusable",
                       "detail": evidence_health["broken"]})
    elif evidence_health.get("failures"):
        # Not "broken", but writes are being lost, so the swarm evidence is
        # quietly incomplete. Worth saying; not worth the same alarm.
        system.append({"what": "Evidence writes lost",
                       "detail": f"{evidence_health['failures']} since start"})
    if intents_broken:
        system.append({"what": "Remediation intents unusable",
                       "detail": intents_broken})
    # `problems`, not `items`. Jinja resolves `attention.items` to the dict's
    # own `.items` method and renders a bound builtin, so the list silently
    # never appears - it fails as a TypeError at `{% for %}`, not as a blank.
    return {"remediation": len(triage), "system": len(system),
            "total": len(triage) + len(system), "problems": system}


def _mapping_rows(raw):
    """Stored mappings -> rows for the form, tolerating the hand-edited YAML
    forms (`{from, to}` or `"a = b"`) that config.example.yaml documents."""
    rows = []
    for item in raw or []:
        if isinstance(item, dict):
            src = item.get("from") or item.get("src") or ""
            dst = item.get("to") or item.get("dst") or ""
        elif isinstance(item, str):
            src, _, dst = item.partition("=")
        else:
            continue
        src, dst = str(src).strip(), str(dst).strip()
        if src and dst:
            rows.append({"from": src, "to": dst})
    return rows


# ---------------------------------------------------------------------------
# Saved-state summaries.
#
# Everything below reads `cfg` and nothing else. That is the whole design: a
# header chip has to describe what is *saved*, and the reliable way to promise
# that is for the browser to have no way of changing it. Nothing here is
# recomputed in JavaScript, and the dirty-state code deliberately leaves these
# alone, so a card with unsaved edits keeps showing the state it would have if
# you navigated away.
#
# The hard part is not the booleans, it is the configurations that are switched
# on and still do nothing. "Enabled" on a feature that cannot fire is worse
# than no chip at all, because it answers the operator's question wrongly.
# ---------------------------------------------------------------------------

# (text, tone). `tone` is on | off | warn, and `warn` means "switched on but
# not actually doing anything", which is the state worth catching the eye.
def _chip(text, tone):
    return {"text": text, "tone": tone}


def _summaries(cfg):
    """Header chips, keyed by the card (or subsection) they sit on."""
    det = cfg.get("detection") or {}
    ad = det.get("archive_detection") or {}
    pr = det.get("probe") or {}
    bl = cfg.get("ip_blocklist") or {}
    bip = cfg.get("banned_ips") or {}
    auth = (cfg.get("web") or {}).get("auth") or {}
    lg = cfg.get("logging") or {}
    out = {}

    # Archive detection scoped to an empty indexer list returns [] without ever
    # looking at the files. Enabled and inert.
    if not ad.get("enabled"):
        out["archive"] = _chip("Disabled", "off")
    elif not [i for i in (ad.get("indexers") or []) if str(i).strip()]:
        out["archive"] = _chip("Enabled, no indexers", "warn")
    else:
        out["archive"] = _chip("Enabled", "on")

    # The probe cannot steer in a dry run (engine.inspect refuses), so an
    # operator who switched it on while testing gets the free pass only.
    if not pr.get("enabled"):
        out["probe"] = _chip("Disabled", "off")
    elif cfg.get("dry_run", True):
        out["probe"] = _chip("Enabled, read-only in dry run", "warn")
    elif not pr.get("steer", True):
        out["probe"] = _chip("Enabled, no steering", "warn")
    else:
        out["probe"] = _chip("Enabled", "on")

    if not bl.get("enabled"):
        out["blocklist"] = _chip("Disabled", "off")
    elif not bl.get("apply_to_qbit"):
        out["blocklist"] = _chip("Enabled, not applied", "warn")
    else:
        out["blocklist"] = _chip("Enabled", "on")

    ips = [i for i in (bip.get("ips") or []) if str(i).strip()]
    if not bip.get("enabled"):
        out["bannedips"] = _chip("Disabled", "off")
    elif not ips:
        out["bannedips"] = _chip("Enabled, list empty", "warn")
    else:
        out["bannedips"] = _chip(f"Enabled, {len(ips)} address"
                                 f"{'' if len(ips) == 1 else 'es'}", "on")

    exts = [e for e in (det.get("blocked_extensions") or []) if str(e).strip()]
    out["detection"] = _chip(f"{len(exts)} extension"
                             f"{'' if len(exts) == 1 else 's'} monitored",
                             "on" if exts else "warn")

    method = auth.get("method", "none")
    if method == "none":
        out["security"] = _chip("No authentication", "off")
    else:
        label = {"basic": "Basic", "forms": "Forms"}.get(method, method)
        if auth.get("required") == "local_disabled":
            out["security"] = _chip(f"{label}, not for local addresses", "warn")
        else:
            out["security"] = _chip(label, "on")

    level = str(lg.get("level", "info")).capitalize()
    if lg.get("file_enabled"):
        out["logging"] = _chip(f"{level}, writing a file", "on")
    else:
        out["logging"] = _chip(f"{level}, no file", "off")

    out["safety"] = _chip(_policy_scope(cfg)[0],
                          "off" if cfg.get("dry_run", True) else "on")
    return out


def _policy_scope(cfg):
    """(short scope label, whether the allowlist is consulted at all)."""
    mode = (cfg.get("safety") or {}).get("mode", "arr_tracked")
    return {
        "arr_tracked": ("Arr-tracked only", False),
        "either": ("Arr + category fallback", True),
        "both": ("Arr and category matched", True),
        "allowlist": ("Category matched only", True),
    }.get(mode, (f"Unknown mode {mode!r}", True))


def _airdate_capable(cfg):
    """Do any configured applications have a release date to gate on?

    Lidarr and Readarr have no air-date resource at all, so `airdate_status()`
    can only ever answer "unknown" for them, and every replacement search is
    held. On an install with only those two, "Replacement search: enabled" is
    true and useless, which is exactly the kind of accurate-but-misleading row
    this box is supposed to avoid.

    Returns None when nothing is configured yet, so the row can say that
    instead of guessing.
    """
    arrs = cfg.get("arrs") or []
    if not arrs:
        return None
    for a in arrs:
        meta = ARR_TYPES.get(str(a.get("type", "")).lower())
        if meta and (meta.get("airdate") or (None,))[0]:
            return True
    return False


def _current_policy(cfg):
    """The firewall-style summary, as ordered (label, value, muted) rows.

    `muted` marks a row the current mode makes inapplicable. Those rows are
    kept and labelled rather than dropped: "not used in this mode" is an answer,
    and a row that silently disappears looks like a setting that was lost.
    """
    safety = cfg.get("safety") or {}
    mode = safety.get("mode", "arr_tracked")
    dry = cfg.get("dry_run", True)
    scope, uses_allowlist = _policy_scope(cfg)
    cats = [c for c in (safety.get("allowed_categories") or []) if str(c).strip()]
    tags = [t for t in (safety.get("allowed_tags") or []) if str(t).strip()]
    requeue = safety.get("requeue_after_airdate", True)
    grace = safety.get("airdate_grace_hours", 0)
    dwell = safety.get("orphan_dwell_minutes", 10)
    rows = []

    rows.append(("Mode",
                 "Dry run, nothing is removed" if dry
                 else "Live, fakes are removed for real", False))
    rows.append(("Scope", scope, False))

    # The allowlist matches on category OR tag, so naming only one of them
    # would describe a narrower rule than the one in force.
    if not uses_allowlist:
        rows.append(("Category fallback",
                     "Not used in this mode. Your selection is kept.", True))
    elif not cats and not tags:
        rows.append(("Category fallback",
                     "Nothing selected, so nothing matches", False))
    else:
        parts = []
        if cats:
            parts.append("Categories: " + ", ".join(cats))
        if tags:
            parts.append("Tags: " + ", ".join(tags))
        rows.append(("Category fallback", " · ".join(parts), False))

    # The dwell only gates the direct-delete path, and only `either` and
    # `allowlist` have one. Under `arr_tracked` and `both` an orphan has no
    # owning application, so nothing reaches the dwell at all.
    if mode in ("arr_tracked", "both"):
        rows.append(("Orphan handling",
                     "Not used in this mode. Only an application can act.", True))
    elif dwell <= 0:
        rows.append(("Orphan handling",
                     "Act as soon as absence is confirmed", False))
    else:
        rows.append(("Orphan handling",
                     f"Act after {dwell} minute{'' if dwell == 1 else 's'} "
                     f"of confirmed absence", False))

    # Never unconditional: it needs the removal to have been verified, and a
    # category-fallback delete has no application to search with.
    if not requeue:
        rows.append(("Replacement search", "Never. Blocklist only.", False))
    else:
        capable = _airdate_capable(cfg)
        if capable is None:
            value = ("After a verified removal, once the release is out. "
                     "No applications configured yet.")
        elif capable is False:
            value = ("Always held: the configured application types have no "
                     "release date to check.")
        else:
            value = "After a verified removal, once the release is out"
        if mode in ("either", "allowlist"):
            value += (". Downloads deleted by category fallback are never "
                      "replaced, because no application owns them.")
        rows.append(("Replacement search", value, False))

    if not requeue:
        rows.append(("Air-date constraint",
                     "Not used while the replacement search is off", True))
    elif grace <= 0:
        rows.append(("Air-date constraint", "As soon as it has aired", False))
    else:
        rows.append(("Air-date constraint",
                     f"{grace} hour{'' if grace == 1 else 's'} after it has "
                     f"aired", False))

    # Profiles can turn a blocking finding into a warn or an allow, and none of
    # the four places they can be set is in this UI. Shown only when something
    # is actually set, so the usual case stays quiet.
    det = cfg.get("detection") or {}
    custom = (det.get("profile") and det["profile"] != "media"
              or det.get("profiles")
              or safety.get("category_profiles")
              or any(a.get("profile") for a in (cfg.get("arrs") or [])))
    if custom:
        rows.append(("Judgement",
                     "Custom profiles are set in config.yaml, so some findings "
                     "may be downgraded to a warning or allowed.", False))
    return rows


def _human_size(n):
    """Bytes -> the sizes people recognise from a torrent client."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return None
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return None


def _safe_next(nxt):
    """Only allow same-site relative paths as post-login redirect targets."""
    if nxt and nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt:
        return nxt
    return None


def create_app(service):
    app = Flask(__name__)
    app.secret_key = cfg_mod.ensure_secret_key()
    cfg_mod.ensure_api_key()  # auto-generate a web API key on first run
    app.permanent_session_lifetime = timedelta(days=30)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    # login brute-force throttle (per client IP, in-memory)
    login_fails, login_lock = {}, threading.Lock()
    MAX_FAILS, FAIL_WINDOW = 10, 300

    def login_blocked(ip):
        now = time.time()
        with login_lock:
            recent = [t for t in login_fails.get(ip, []) if now - t < FAIL_WINDOW]
            login_fails[ip] = recent
            return len(recent) >= MAX_FAILS

    def record_login_fail(ip):
        with login_lock:
            login_fails.setdefault(ip, []).append(time.time())

    def clear_login_fails(ip):
        with login_lock:
            login_fails.pop(ip, None)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    @app.context_processor
    def inject_csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf"]}

    def auth_cfg():
        return cfg_mod.load()["web"].get("auth", {})

    def valid_api_key(cfg):
        key = cfg["web"].get("api_key", "")
        given = request.headers.get("X-Api-Key") or request.args.get("apikey")
        return bool(key) and bool(given) and hmac.compare_digest(given, key)

    def csrf_ok():
        token = session.get("csrf")
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        return bool(token) and bool(sent) and hmac.compare_digest(token, sent)

    def check_password(auth, username, password):
        return (username == auth.get("username")
                and auth.get("password_hash")
                and check_password_hash(auth["password_hash"], password))

    def check_basic(auth):
        hdr = request.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(hdr[6:]).decode("utf-8")
            user, _, pw = raw.partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        if check_password(auth, user, pw):
            g.auth_user = user
            return True
        return False

    def request_is_local(auth):
        ip = resolve_client_ip(request.remote_addr,
                               request.headers.get("X-Forwarded-For"),
                               auth.get("trusted_proxies", []))
        return is_local(ip)

    @app.before_request
    def guard():
        cfg = cfg_mod.load()
        # CSRF: cookie-authenticated state changes must carry a valid token.
        # API-key callers are exempt (no cookies, not browser-driven).
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not valid_api_key(cfg):
            if not csrf_ok():
                return Response("CSRF token missing or invalid", 400)
        if request.endpoint in PUBLIC_ENDPOINTS:
            return
        auth = cfg["web"].get("auth", {})
        method = auth.get("method", "none")
        if method == "none":
            return
        if valid_api_key(cfg):
            return
        # "Disabled for Local Addresses" - bypass auth for LAN/private clients.
        if auth.get("required") == "local_disabled" and request_is_local(auth):
            return
        if method == "basic":
            if check_basic(auth):
                return
            return Response("Authentication required", 401,
                            {"WWW-Authenticate": BASIC_REALM})
        # forms
        if session.get("authed"):
            return
        if request.endpoint in API_ENDPOINTS:
            return Response("Unauthorized", 401)
        return redirect(url_for("login", next=request.path))

    # ---- auth ----
    @app.route("/login", methods=["GET", "POST"])
    def login():
        auth = auth_cfg()
        if auth.get("method") != "forms":
            return redirect(url_for("applications"))
        nxt = _safe_next(request.values.get("next")) or url_for("applications")
        ip = request.remote_addr or "?"
        if request.method == "POST":
            if login_blocked(ip):
                return render_template("login.html",
                                       error="Too many attempts. Try again later.", next=nxt), 429
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            if check_password(auth, u, p):
                clear_login_fails(ip)
                session["authed"] = True
                session["user"] = u
                session.permanent = request.form.get("remember") == "on"
                return redirect(nxt)
            record_login_fail(ip)
            return render_template("login.html", error="Incorrect username or password.", next=nxt)
        return render_template("login.html", next=nxt)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- pages ----
    def page(template, active, active_sub=None, **ctx):
        return render_template(
            template, active=active, active_sub=active_sub,
            wide=active in WIDE_PAGES,
            cfg=cfg_mod.load(), state=service.state,
            arr_types=sorted(ARR_TYPES.keys()),
            settings_pages=SETTINGS_PAGES,
            version=__version__, config_path=cfg_mod.CONFIG_PATH,
            user=session.get("user"), basic_user=getattr(g, "auth_user", None),
            api_key_from_env=cfg_mod.api_key_is_from_env(),
            log_lines=logs.ring(), log_levels=logs.LEVELS,
            timezones=logs.available_timezones(),
            current_tz=time.strftime("%Z %z"),
            **ctx)

    @app.route("/")
    def applications():
        return page("applications.html", active="applications",
                    apps_view=_arrs_for_browser(cfg_mod.load()))

    @app.route("/dashboard")
    def dashboard():
        """Four questions, in order: healthy, anything to do, what happened,
        what patterns.

        Everything derived from history comes out of one bounded walk. The
        cards are not allowed to ask the file separately - see
        `protectarr/dashboard.py` for why, and for what the bound is.
        """
        agg = dash.collect(fold=_history_rows)
        rows = agg["rows"]
        health = evidence.health()
        triage = _triage(intents.records())

        # The Triage Queue reuses History's Details dialog, which needs a
        # folded row, not an intent. They are matched on `remediation_id`,
        # which both sides mint from the same place. A `failed_unverified`
        # older than the fold - or one whose detection event has rotated out -
        # simply has no Details button rather than a dialog full of blanks.
        by_rid = {}
        for i, r in enumerate(rows):
            rid = (r["latest"].get("remediation_id")
                   or r["ev"].get("remediation_id"))
            if rid and rid not in by_rid:
                by_rid[rid] = i
        for t in triage:
            t["detail"] = by_rid.get(t.get("remediation_id"))

        return page(
            "dashboard.html", active="dashboard",
            remediations_24h=agg["remediations_24h"],
            truncated=agg["truncated"], scanned=agg["scanned"],
            findings=agg["findings"], indexers=agg["indexers"],
            last_remediation=_when(
                (service.state.get("stats") or {}).get("last_reap")),
            last_scan=_when(service.state.get("last_scan")),
            triage=triage[:dash.RECENT_ROWS],
            triage_total=len(triage),
            recent=rows[:dash.RECENT_ROWS],
            attention=_attention(service.state, triage, health,
                                 intents.broken()),
            evidence_health=health,
            # Every folded row, not just the five shown: a Triage row's dialog
            # can point past the end of Recent Activity.
            detail_rows=[_detail(r) for r in rows])

    @app.route("/system")
    def system():
        return page("system.html", active="system",
                    swarm_health=evidence.health(),
                    swarm_totals=evidence.counts(),
                    # Live mode re-reads the same ring the page was rendered
                    # from, so it asks for exactly as much as the ring holds.
                    # Taken from logs rather than written twice, or a change to
                    # RING_SIZE would silently start truncating the live view.
                    log_limit=logs.RING_SIZE, log_poll_ms=LOG_POLL_MS)

    @app.route("/watchlist")
    def watchlist():
        rows = evidence.observations(limit=WATCHLIST_LIMIT) or []
        details = evidence.profiles([r["ip"] for r in rows])
        return page("watchlist.html", active="watchlist",
                    rows=[_swarm_view(r) for r in rows],
                    broken=evidence.broken(), totals=evidence.counts(),
                    detail_rows=[_swarm_detail(details.get(r["ip"]))
                                 for r in rows])

    @app.route("/history")
    def history():
        # Default to Live so a burst of dry-run testing can't make the page look
        # like Protectarr stopped three hundred attacks.
        show = (request.args.get("show") or "live").lower()
        if show not in ("live", "dry", "all"):
            show = "live"
        dry = {"live": False, "dry": True, "all": None}[show]
        # Streamed, not read-then-truncated: page depth is a row count now, so
        # it no longer shrinks when a release accumulates lifecycle events.
        rows = _history_rows(events.iter_events(dry_run=dry),
                             limit=HISTORY_LIMIT)
        return page("history.html", active="history", rows=rows, show=show,
                    folded_from=sum(len(r["timeline"]) for r in rows),
                    scope={"live": "live only", "dry": "dry run only",
                           "all": None}[show],
                    detail_rows=[_detail(r) for r in rows])

    @app.route("/settings")
    def settings_index():
        return page("settings_index.html", active="settings")

    @app.route("/settings/<key>")
    def settings_page(key):
        """One route for pages and for the old per-section URLs.

        `/settings/administration` and `/settings/security` are the same URL
        shape, so they cannot be separate rules. A page renders; a section is a
        bookmark from before 0.7.0 and gets sent to the card it became, anchor
        and all, rather than to a 404 or to the top of a page it has to be
        hunted down in.
        """
        if key in SECTION_PAGE:
            return redirect(section_url(key))
        if key not in SETTINGS_PAGE_KEYS:
            return redirect(url_for("settings_index"))
        sections = next(s for k, _, _, s in SETTINGS_PAGES if k == key)
        # Context is gathered per section present, not per page, so moving a
        # card to another page cannot leave its data behind.
        saved = cfg_mod.load()
        extra = {"summaries": _summaries(saved)}
        if "safety" in sections:
            extra["current_policy"] = _current_policy(saved)
        if "logging" in sections:
            files = logs.list_files(cfg_mod.load())
            for f in files:
                f["size_h"] = _human_size(f["size"])
                f["modified_h"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                                time.localtime(f["modified"]))
            extra["log_files"] = files
            extra["log_total_h"] = _human_size(sum(f["size"] for f in files))
        if "probe" in sections:
            extra["mapping_rows"] = _mapping_rows(
                (cfg_mod.load().get("detection") or {}).get("probe", {})
                .get("path_mappings"))
        return page("settings_page.html", active="settings", active_sub=key,
                    sections=sections, **extra)

    @app.route("/settings/<section>/save", methods=["POST"])
    def save_section(section):
        if section not in SAVE_SECTIONS:
            return redirect(url_for("settings_index"))
        cfg = cfg_mod.load()
        f = request.form

        if section == "detection":
            exts = []
            for raw in f.get("blocked_extensions", "").replace(",", "\n").splitlines():
                e = raw.strip().lower()
                if e:
                    exts.append(e if e.startswith(".") else "." + e)
            if exts:
                cfg["detection"]["blocked_extensions"] = exts
            cfg["detection"]["only_active"] = f.get("only_active") == "on"
            # Tier 2 - filename lure keywords
            cfg["detection"]["blocked_name_keywords"] = [
                k.strip().lower() for k in
                f.get("blocked_name_keywords", "").replace(",", "\n").splitlines()
                if k.strip()]
            # Tier 3 - indexer-scoped archive detection
            ad = cfg["detection"].setdefault("archive_detection", {})
            ad["enabled"] = f.get("archive_enabled") == "on"
            ad["indexers"] = [i.strip() for i in f.getlist("archive_indexers") if i.strip()]

        elif section == "safety":
            cfg["dry_run"] = f.get("dry_run") == "on"
            s = cfg["safety"]
            s["mode"] = f.get("safety_mode", "arr_tracked")
            # Checkbox lists now, sourced from qBittorrent. The page always
            # renders a box for an already-saved value, even one qBittorrent no
            # longer reports, so saving cannot quietly drop a choice made when
            # the category still existed.
            s["allowed_categories"] = [c.strip() for c in
                                       f.getlist("allowed_categories") if c.strip()]
            s["allowed_tags"] = [t.strip() for t in
                                 f.getlist("allowed_tags") if t.strip()]
            s["requeue_after_airdate"] = f.get("requeue_after_airdate") == "on"
            # Parsed through float() and guarded, like every other numeric
            # setting here. `int("1e9")` raises, and an `<input type=number>`
            # considers `1e9` a valid value and submits it, so the unguarded
            # version was a 500 anybody could reach by typing. The ceiling is a
            # year: a grace period past that is a typo, not a policy.
            try:
                s["airdate_grace_hours"] = min(8760, max(0, int(float(
                    f.get("airdate_grace_hours") or 0))))
            except (TypeError, ValueError):
                pass
            # Clamped like every other numeric setting. 0 is allowed and means
            # "act as soon as absence is confirmed", which is a legitimate
            # choice; the upper bound just stops a typo turning the fallback
            # off for a year.
            try:
                s["orphan_dwell_minutes"] = min(1440, max(0, int(float(
                    f.get("orphan_dwell_minutes") or 0))))
            except (TypeError, ValueError):
                pass

        elif section == "probe":
            pr = cfg["detection"].setdefault("probe", {})
            pr["enabled"] = f.get("probe_enabled") == "on"
            pr["steer"] = f.get("probe_steer") == "on"
            pr["path_mappings"], partial = _mappings_from_form(f)
            if partial:
                flash(f"A mapping needs both paths, so the row containing "
                      f"{partial[0]!r} was left out.")
            # Clamped rather than trusted: these bound how long a scan can block
            # and how much bandwidth a probe may spend.
            for key, field, lo, hi in (("max_torrents_per_scan", "probe_max", 0, 20),
                                       ("torrent_timeout_seconds", "probe_timeout", 5, 900),
                                       ("scan_budget_seconds", "probe_budget", 5, 1800),
                                       ("min_speed_kib", "probe_minspeed", 0, 1048576),
                                       ("recheck_minutes", "probe_recheck", 1, 1440),
                                       ("no_progress_seconds", "probe_noprogress", 0, 900)):
                try:
                    pr[key] = min(hi, max(lo, int(float(f.get(field) or 0))))
                except (TypeError, ValueError):
                    pass

        elif section == "blocklist":
            bl = cfg.setdefault("ip_blocklist", {})
            bl["enabled"] = f.get("bl_enabled") == "on"
            bl["url"] = f.get("bl_url", "").strip()
            bl["path"] = f.get("bl_path", "").strip()
            # Guarded like the rest; blank still means the 24-hour default.
            try:
                bl["update_interval_hours"] = min(8760, max(1, int(float(
                    f.get("bl_interval") or 24))))
            except (TypeError, ValueError):
                pass
            bl["apply_to_qbit"] = f.get("bl_apply") == "on"
            bl["block_trackers"] = f.get("bl_trackers") == "on"

        elif section == "bannedips":
            bip = cfg.setdefault("banned_ips", {})
            bip["enabled"] = f.get("bip_enabled") == "on"
            bip["ips"] = [x.strip() for x in
                f.get("bip_ips", "").replace(",", "\n").splitlines() if x.strip()]
            bip["merge_existing"] = f.get("bip_merge") == "on"

        elif section == "logging":
            lg = cfg.setdefault("logging", {})
            for key, field in (("level", "log_level"),
                               ("console_level", "log_console_level")):
                val = (f.get(field) or "").strip().lower()
                if val in logs.LEVELS:
                    lg[key] = val
            lg["file_enabled"] = f.get("log_file_enabled") == "on"
            lg["path"] = f.get("log_path", "").strip()
            # Guarded like the rest. The ceiling is the one the form has always
            # declared (max="365"); blank still means 0, which is "keep
            # everything" rather than the 14-day default.
            try:
                lg["retention_days"] = min(365, max(0, int(float(
                    f.get("log_retention") or 0))))
            except (TypeError, ValueError):
                pass
            tz = (f.get("timezone") or "").strip()
            if tz and tz not in logs.available_timezones():
                flash(f"Unknown timezone {tz!r}, leaving it unchanged.")
            else:
                cfg["timezone"] = tz

        elif section == "security":
            auth = cfg["web"].setdefault("auth", {})
            # A save that would leave nobody able to log in is refused outright
            # rather than half-applied. Choosing Forms with both fields empty
            # was three clicks from here and cost the operator their instance:
            # `check_password` needs a truthy `password_hash`, so no credential
            # could ever succeed, and the only way back was editing the YAML by
            # hand.
            #
            # This asks whether a hash would EXIST afterwards, not whether one
            # was typed, so blank-means-unchanged is untouched: an existing
            # setup can still save a username change without retyping the
            # password. `method = none` is never checked, so turning
            # authentication off is always available.
            #
            # `local_disabled` is deliberately not an exemption. It only
            # bypasses auth for addresses that look local, that judgement
            # depends on `trusted_proxies` being right, and one proxy change
            # later the instance would be unreachable with no way back.
            method = f.get("auth_method", "none")
            if method in ("basic", "forms"):
                username = f.get("auth_username", "").strip()
                has_password = bool(f.get("auth_password")
                                    or auth.get("password_hash"))
                if not username or not has_password:
                    missing = ("a username and a password"
                               if not username and not has_password
                               else "a username" if not username else "a password")
                    flash(f"{method.capitalize()} authentication needs "
                          f"{missing}. Nothing was saved.")
                    return redirect(section_url(section))
            auth["method"] = method
            auth["required"] = f.get("auth_required", "enabled")
            auth["username"] = f.get("auth_username", "").strip()
            if f.get("auth_password", ""):
                auth["password_hash"] = generate_password_hash(f["auth_password"])
            auth["trusted_proxies"] = [c.strip() for c in
                f.get("trusted_proxies", "").replace(",", "\n").splitlines() if c.strip()]

        cfg_mod.save(cfg)
        if section == "logging":
            logs.configure(cfg)   # new level/rotation takes effect immediately
        service.reload()
        # Optional "…and apply/update now" - runs against the just-saved config
        # so the action reflects the current form values (not stale ones).
        if section == "bannedips":
            service.apply_banned_ips(cfg)
        elif section == "blocklist" and f.get("do_update"):
            service.update_blocklist(cfg, force=True)
        flash("Settings saved.")
        return redirect(section_url(section))

    # ---- applications (qBittorrent + the *arr apps live together) ----
    @app.route("/applications/qbit/save", methods=["POST"])
    def save_qbit():
        cfg = cfg_mod.load()
        f = request.form
        q = cfg["qbittorrent"]
        q["url"] = f.get("qbit_url", "").strip()
        q["username"] = f.get("qbit_username", "").strip()
        # Blank means "leave it alone", matching the password field beside it,
        # because the stored value is no longer sent to the browser to be
        # resubmitted. The API key is optional here (username/password is the
        # alternative), so blank alone cannot mean "remove it" without being
        # ambiguous. Clearing is an explicit checkbox instead.
        if f.get("qbit_api_key_clear") == "on":
            q["api_key"] = ""
        elif f.get("qbit_api_key", "").strip():
            q["api_key"] = f["qbit_api_key"].strip()
        if f.get("qbit_password_clear") == "on":
            q["password"] = ""
        elif f.get("qbit_password", ""):
            q["password"] = f["qbit_password"]
        q["verify_ssl"] = f.get("qbit_verify_ssl") == "on"
        cfg["qbittorrent"]["web_url"] = f.get("qbit_web_url", "").strip()
        cfg_mod.save(cfg)
        service.reload()
        flash("qBittorrent settings saved.")
        return redirect(url_for("applications"))

    @app.route("/applications/app/save", methods=["POST"])
    def save_app():
        cfg = cfg_mod.load()
        f = request.form
        name = f.get("arr_name", "").strip()
        url = f.get("arr_url", "").strip()
        atype = f.get("arr_type", "").strip().lower()
        if not name or not url or atype not in ARR_TYPES:
            flash("Name, a valid type, and URL are required.")
            return redirect(url_for("applications"))
        arrs = cfg.get("arrs", [])
        idx = f.get("arr_index", "")
        editing = idx.isdigit() and int(idx) < len(arrs)
        # An *arr is useless without a key, so this one is a required credential:
        # blank while editing means "keep the stored key", and there is no clear
        # action because clearing it would only break the app. Deleting the
        # application is the way to get rid of its key.
        key = f.get("arr_key", "").strip()
        if not key:
            if not editing:
                flash("An API key is required.")
                return redirect(url_for("applications"))
            key = arrs[int(idx)].get("api_key", "")
        entry = {"name": name, "type": atype, "url": url, "api_key": key}
        web_url = f.get("arr_web_url", "").strip()
        if web_url:
            entry["web_url"] = web_url
        if editing:
            arrs[int(idx)] = entry
        else:
            arrs.append(entry)
        cfg["arrs"] = arrs
        cfg_mod.save(cfg)
        service.reload()
        flash("Application saved.")
        return redirect(url_for("applications"))

    @app.route("/applications/app/delete", methods=["POST"])
    def delete_app():
        cfg = cfg_mod.load()
        arrs = cfg.get("arrs", [])
        idx = request.form.get("arr_index", "")
        if idx.isdigit() and int(idx) < len(arrs):
            removed = arrs.pop(int(idx))
            cfg["arrs"] = arrs
            cfg_mod.save(cfg)
            service.reload()
            flash(f"Removed {removed.get('name', 'application')}.")
        return redirect(url_for("applications"))

    # ---- dashboard service health ----
    @app.route("/api/dashboard", endpoint="dashboard_data")
    def dashboard_data():
        """Can Protectarr reach the things it needs? Nothing else.

        This used to be the Dashboard's whole data feed and made roughly 3N+2
        serialised round trips for it: per *arr a status call, an indexer
        enumeration and a full library fetch, plus a qBittorrent login and a
        complete torrent list. Two of those three per-app calls existed only to
        fill surfaces the Dashboard no longer has, and the library fetch pulled
        every movie or series an app knows about, with every field, to compute
        two integers nobody was acting on.

        What is left is one reachability check per service - N+1 calls - each of
        which is the cheapest question that actually establishes connectivity:
        `system/status` for an *arr and `app/version` for qBittorrent. Neither
        is a new request; both are what the existing Test buttons already use.

        Reachability only. Whether a *arr is *correctly configured* is not
        something a health dot can assert, and the page does not pretend to.
        """
        cfg = cfg_mod.load()
        services, errors = [], []

        qc = cfg.get("qbittorrent") or {}
        row = {"name": "qBittorrent", "type": "qbittorrent",
               "ok": False, "detail": ""}
        if not qc.get("url"):
            row["ok"], row["detail"] = None, "not configured"
        else:
            try:
                qb = QbitClient(qc["url"], qc.get("username", ""),
                                qc.get("password", ""),
                                api_key=qc.get("api_key", ""),
                                verify_ssl=qc.get("verify_ssl", True))
                row["ok"], row["detail"] = qb.test()
            except (QbitError, requests.RequestException, ValueError) as e:
                row["ok"], row["detail"] = False, str(e)
        services.append(row)
        if row["ok"] is False:
            errors.append(f"qBittorrent: {row['detail']}")

        for client in build_clients(cfg):
            row = {"name": client.name, "type": client.type,
                   "ok": False, "detail": ""}
            try:
                row["ok"], row["detail"] = client.test()
            except (requests.RequestException, ValueError) as e:
                row["ok"], row["detail"] = False, str(e)
            services.append(row)
            if not row["ok"]:
                errors.append(f"{client.name}: {row['detail']}")

        return jsonify(ok=True, data={"services": services, "errors": errors})

    # ---- test / preview / control ----
    @app.route("/test/qbit", methods=["POST"], endpoint="test_qbit")
    def test_qbit():
        d = request.json or {}
        stored = cfg_mod.load()["qbittorrent"]
        qb = QbitClient(d.get("url", ""), d.get("username", ""),
                        d.get("password", "") or stored["password"],
                        api_key=d.get("api_key", "") or stored.get("api_key", ""),
                        verify_ssl=d.get("verify_ssl", True))
        ok, msg = qb.test()
        return jsonify(ok=ok, message=msg)

    @app.route("/qbit/taxonomy", endpoint="qbit_taxonomy")
    def qbit_taxonomy():
        """Categories and tags as qBittorrent currently defines them.

        Feeds the Reaping Rules pickers so nobody has to retype a category name
        and get it subtly wrong. A failure here is reported rather than papered
        over: the page keeps whatever is already saved, because an unreachable
        qBittorrent is not evidence that a category stopped existing.
        """
        qc = cfg_mod.load()["qbittorrent"]
        try:
            qb = QbitClient(qc["url"], qc.get("username", ""), qc.get("password", ""),
                            api_key=qc.get("api_key", ""),
                            verify_ssl=qc.get("verify_ssl", True))
            qb.login()
            cats = [{"name": name, "meta": (rec or {}).get("savePath") or ""}
                    for name, rec in (qb.categories() or {}).items()]
            tags = [{"name": t, "meta": ""} for t in (qb.tags() or []) if t]
        except (QbitError, requests.RequestException, ValueError) as e:
            return jsonify(ok=False, message=str(e))
        return jsonify(ok=True, data={"categories": cats, "tags": tags})

    @app.route("/probe/check", methods=["POST"], endpoint="probe_check")
    def probe_check():
        """Dry-run a path mapping against whatever is downloading right now.

        The probe lane's one hard prerequisite is that this process can read the
        files qBittorrent is writing, and when it cannot the symptom is simply
        that nothing ever happens. This turns that into an answer, and it takes
        the mapping from the form so it can be tested before it is saved.
        """
        mappings = probe.paths.parse_mappings(
            (request.json or {}).get("mappings") or [])
        cfg = cfg_mod.load()
        qc = cfg["qbittorrent"]
        try:
            qb = QbitClient(qc["url"], qc.get("username", ""), qc.get("password", ""),
                            api_key=qc.get("api_key", ""),
                            verify_ssl=qc.get("verify_ssl", True))
            qb.login()
            torrents = qb.torrents(state_filter="downloading")
        except (QbitError, requests.RequestException, ValueError) as e:
            return jsonify(ok=False, message=f"Could not reach qBittorrent: {e}")

        rows, readable = [], 0
        for t in torrents[:25]:
            try:
                files = qb.files(t.get("hash", ""))
            except requests.RequestException:
                continue
            targets = probe.targets(files)
            if not targets:
                continue
            _, entry = targets[0]
            local = probe.paths.local_path(t, entry, len(files) == 1, mappings)
            read = probe.paths.read_head(local, 64)
            # "Not readable" and "not downloaded yet" are different problems and
            # only the first one is the mapping's fault.
            exists = os.path.exists(local) or os.path.exists(
                local + probe.paths.INCOMPLETE_SUFFIX)
            if exists:
                readable += 1
            rows.append({"torrent": t.get("name", ""), "file": entry.get("name", ""),
                         "qbit_path": t.get("content_path") or t.get("save_path") or "",
                         "local_path": local, "found": exists,
                         "note": "" if exists else read.why})
            if len(rows) >= 8:
                break

        if not rows:
            return jsonify(ok=True, data={"rows": [], "message":
                           "Nothing is downloading with a media file to check. "
                           "Start a download and try again."})
        msg = (f"{readable} of {len(rows)} checked file(s) are readable here."
               if readable else
               "None of the checked files are readable here - the probe lane "
               "would find nothing. Add or correct a path mapping below.")
        return jsonify(ok=True, data={"rows": rows, "message": msg})

    @app.route("/test/arr", methods=["POST"], endpoint="test_arr")
    def test_arr():
        d = request.json or {}
        # The edit form no longer holds the stored key, so a Test with the field
        # left blank has to look it up rather than fail as "no key". Resolved by
        # index server-side: the browser never learns the value either way.
        key = (d.get("api_key") or "").strip()
        if not key:
            arrs = cfg_mod.load().get("arrs") or []
            idx = d.get("index")
            if isinstance(idx, int) and 0 <= idx < len(arrs):
                key = arrs[idx].get("api_key", "")
        try:
            client = ArrClient(d.get("name", "arr"), d.get("type", ""),
                               d.get("url", ""), key)
        except ValueError as e:
            return jsonify(ok=False, message=str(e))
        ok, msg = client.test()
        return jsonify(ok=ok, message=msg)

    @app.route("/preview", endpoint="preview")
    def preview():
        try:
            return jsonify(ok=True, **service.preview())
        except Exception as e:
            return jsonify(ok=False, message=str(e))

    @app.route("/blocklist/update", methods=["POST"])
    def blocklist_update():
        service.update_blocklist(cfg_mod.load(), force=True)
        flash("IP blocklist update triggered.")
        return redirect(section_url("blocklist"))

    @app.route("/settings/security/apikey", endpoint="reveal_api_key")
    def reveal_api_key():
        """Protectarr's own API key, handed over only when asked for.

        The security page used to render the key into its HTML on every visit,
        so it sat in the DOM, in the browser cache and in any saved page for as
        long as the tab was open. Fetching it on Reveal or Copy narrows that to
        the moment the user asked.

        Be accurate about what this buys: the key still reaches the browser, so
        anything with script access to the page (an extension, an XSS) can call
        this endpoint just as easily. What it removes is the passive copy lying
        around when nobody asked for it, not an attacker who is already inside.
        """
        key = cfg_mod.load()["web"].get("api_key", "")
        if not key:
            return jsonify(ok=False, message="No API key is configured."), 404
        resp = jsonify(ok=True, key=key)
        # Not in a shared cache, not on disk, not in the back/forward buffer.
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp

    @app.route("/settings/security/apikey/regenerate", methods=["POST"])
    def regenerate_api_key():
        new = cfg_mod.regenerate_api_key()
        if new is None:
            flash("The API key comes from PROTECTARR_WEB_API_KEY; change it there.")
        else:
            # Auth reads the key per request, so the old one is already dead.
            flash("New API key generated. The previous key no longer works.")
        return redirect(section_url("security"))

    @app.route("/logs/download/<path:name>")
    def download_log(name):
        # resolve_file validates by membership in the real listing, so a
        # traversal attempt is simply not in the set.
        path = logs.resolve_file(cfg_mod.load(), name)
        if not path:
            return Response("No such log file", 404)
        return send_file(path, as_attachment=True, download_name=name)

    @app.route("/logs/download-all")
    def download_all_logs():
        cfg = cfg_mod.load()
        files = logs.list_files(cfg)
        if not files:
            return Response("No log files", 404)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for entry in files:
                path = logs.resolve_file(cfg, entry["name"])
                if path:
                    z.write(path, arcname=entry["name"])
        buf.seek(0)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return send_file(buf, mimetype="application/zip", as_attachment=True,
                         download_name=f"protectarr-logs-{stamp}.zip")

    @app.route("/bannedips/apply", methods=["POST"])
    def bannedips_apply():
        service.apply_banned_ips(cfg_mod.load())
        flash("Manually banned IPs applied to qBittorrent.")
        return redirect(section_url("bannedips"))

    @app.route("/control/<action>", methods=["POST"])
    def control(action):
        if action == "start":
            service.start()
        elif action == "stop":
            service.stop()
        return redirect(url_for("applications"))

    # ---- public HTTP API (v1) - authenticate with the X-Api-Key header ----
    # (or ?apikey=). Same key shown in Settings > Security. Callers are exempt
    # from CSRF; forms-auth returns 401 JSON rather than redirecting.
    @app.route("/ping")
    def ping():
        return jsonify(status="ok", app="Protectarr", version=__version__)

    @app.route("/api/v1")
    def api_index():
        return jsonify(app="Protectarr", version=__version__, endpoints=[
            "GET  /api/v1/system/status", "GET  /api/v1/stats",
            "GET  /api/v1/watchlist", "GET  /api/v1/log?limit=N",
            "GET  /api/v1/history?limit=N&show=all|live|dry",
            "GET  /api/v1/logfiles",
            "GET  /api/v1/preview",
            "POST /api/v1/command {name: start|stop|scan|blocklistUpdate}",
        ])

    @app.route("/api/v1/system/status")
    def api_status():
        cfg = cfg_mod.load()
        st = service.state
        return jsonify(app="Protectarr", version=__version__,
                       running=st.get("running", False),
                       dryRun=bool(cfg.get("dry_run", True)),
                       lastScan=st.get("last_scan"), lastError=st.get("last_error"))

    @app.route("/api/v1/stats")
    def api_stats():
        st = service.state
        return jsonify(reaped=st.get("stats", {}),
                       blocklist=st.get("blocklist", {}),
                       banned=st.get("banned", {}))

    @app.route("/api/v1/watchlist")
    def api_watchlist():
        # `min_encounters` replaces the old `min_fakes`, which was never the
        # number it claimed: it counted distinct infohashes, not fakes, and an
        # IP in one torrent reaped three times scored 1. Both filters are
        # offered because they answer different questions, and the old name is
        # still accepted so an existing caller keeps working.
        if evidence.broken():
            # 503, not an empty list. A caller polling this must be able to
            # tell "no IPs have been observed" from "the evidence is
            # unreadable", and 200 with [] says the first while meaning the
            # second.
            return jsonify(error="evidence store unavailable",
                           detail=evidence.broken()), 503
        args = request.args
        if args.get("ip"):
            return jsonify(evidence.profile(args["ip"]) or {})
        min_enc = args.get("min_encounters", type=int) or 0
        min_tor = (args.get("min_torrents", type=int)
                   or args.get("min_fakes", type=int) or 0)
        n = min(max(args.get("limit", type=int) or WATCHLIST_LIMIT, 1), 5000)
        return jsonify([r for r in (evidence.observations(limit=n) or [])
                        if r["encounters"] >= min_enc
                        and r["distinct_torrents"] >= min_tor])

    @app.route("/api/v1/history")
    def api_history():
        n = min(max(request.args.get("limit", type=int) or 100, 1), 1000)
        dry = {"live": False, "dry": True}.get(
            (request.args.get("show") or "all").lower())
        return jsonify(events.read(limit=n, dry_run=dry))

    @app.route("/api/v1/logfiles")
    def api_logfiles():
        return jsonify(logs.list_files(cfg_mod.load()))

    @app.route("/api/v1/log")
    def api_log():
        n = request.args.get("limit", type=int) or 100
        return jsonify(logs.ring(n))

    @app.route("/api/v1/preview")
    def api_preview():
        try:
            return jsonify(ok=True, **service.preview())
        except Exception as e:
            return jsonify(ok=False, message=str(e)), 500

    @app.route("/api/v1/command", methods=["POST"])
    def api_command():
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or request.form.get("name") or "").strip().lower()
        if name == "start":
            service.start()
            return jsonify(ok=True, command="start", running=True)
        if name == "stop":
            service.stop()
            return jsonify(ok=True, command="stop", running=False)
        if name in ("scan", "scannow"):
            try:
                return jsonify(ok=True, command="scan", result=service.scan_now())
            except Exception as e:
                return jsonify(ok=False, command="scan", message=str(e)), 502
        if name == "blocklistupdate":
            service.update_blocklist(cfg_mod.load(), force=True)
            return jsonify(ok=True, command="blocklistUpdate")
        return jsonify(ok=False, message="unknown command; valid: "
                       "start, stop, scan, blocklistUpdate"), 400

    return app
