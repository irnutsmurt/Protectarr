"""Policy: how dangerous is an observation *here*, and what do we do about it?

Detectors report facts (see `protectarr/detectors`). This layer turns a fact
into a judgement, and the judgement depends entirely on what the download is
supposed to be:

    extension_match on game.exe   under Media    -> critical, block
    extension_match on setup.exe  under Software -> info, allow

Same finding, opposite verdict. That is why severity lives here and not on the
Finding.

Profiles are orthogonal to `safety.mode`:

    safety.mode -> WHAT Protectarr is allowed to touch
    profile     -> HOW Protectarr judges what it touched

A profile is resolved per torrent: the owning *arr's `profile` if it has one,
else a category mapping, else the global default. Everything defaults to
`media`, which reproduces the behaviour Protectarr has always had, so existing
configs are unaffected.
"""

SEVERITIES = ("info", "low", "medium", "high", "critical")
DECISIONS = ("allow", "warn", "block")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Built-in profiles: reason -> (severity, decision).
BUILTIN = {
    # Reproduces today's behaviour exactly: every observation blocks.
    "media": {
        "extension_match": ("critical", "block"),
        "lure_filename": ("high", "block"),
        "archive_no_media": ("high", "block"),
        # Written by the probe engine in PR 2; wired now so that landing it is
        # a detector plus one line here, not a schema change.
        "content_type_mismatch": ("critical", "block"),
    },
    # An executable is the point of a software release, and software ships in
    # archives. What stays suspicious is the lure note and a file lying about
    # what it is.
    "software": {
        "extension_match": ("info", "allow"),
        "lure_filename": ("high", "warn"),
        "archive_no_media": ("info", "allow"),
        "content_type_mismatch": ("high", "warn"),
    },
}

# A reason no profile knows about. Record it, never destroy on it: a detector
# that arrives without policy wired up must not be able to delete downloads.
UNKNOWN = ("medium", "warn")


def profiles(cfg):
    """Built-in profiles with any user overrides merged per reason."""
    out = {name: dict(rules) for name, rules in BUILTIN.items()}
    for name, rules in (cfg.get("detection", {}).get("profiles") or {}).items():
        base = out.setdefault(name, {})
        for reason, spec in (rules or {}).items():
            if isinstance(spec, dict):
                sev = spec.get("severity", UNKNOWN[0])
                dec = spec.get("decision", UNKNOWN[1])
            else:  # allow the terse "reason: block" form
                sev, dec = UNKNOWN[0], str(spec)
            if sev in SEVERITIES and dec in DECISIONS:
                base[reason] = (sev, dec)
    return out


def resolve_with_source(cfg, arr_entry, category):
    """Which profile applies, and which rule chose it. `(name, source)`.

    Most specific wins: the owning *arr's own setting, then a category mapping,
    then the global default, then `media`.

    The source exists because "media" on its own does not tell an operator
    whether that came from their Sonarr entry, from a category mapping, or from
    nobody having set anything. Those have three different places to go and
    change it, and the Details dossier is where that question gets asked.
    """
    if arr_entry and arr_entry.get("profile"):
        return arr_entry["profile"], "application"
    cat_map = cfg.get("safety", {}).get("category_profiles") or {}
    if category and cat_map.get(category):
        return cat_map[category], "category"
    configured = cfg.get("detection", {}).get("profile")
    if configured:
        return configured, "default"
    return "media", "builtin"


def resolve(cfg, arr_entry, category):
    """Which profile applies to this torrent. A projection of
    `resolve_with_source`, for the callers that only need the name."""
    return resolve_with_source(cfg, arr_entry, category)[0]


def judge(cfg, profile_name, find):
    """Turn one finding into {profile, severity, decision}."""
    rules = profiles(cfg).get(profile_name)
    if rules is None:  # profile named in config but never defined
        profile_name, rules = "media", BUILTIN["media"]
    severity, decision = rules.get(find.get("reason"), UNKNOWN)
    return {"profile": profile_name, "severity": severity, "decision": decision}


def decisive(judged):
    """Pick the finding that drives the outcome.

    Blocks outrank warns outrank allows; within a tier the most severe wins.
    Ties keep detector order, which runs cheapest and most precise first.
    """
    if not judged:
        return None
    return max(judged, key=lambda jp: (DECISIONS.index(jp[1]["decision"]),
                                       _RANK.get(jp[1]["severity"], 0)))


def outcome(judged):
    """The strongest decision across all findings: block | warn | allow."""
    top = decisive(judged)
    return top[1]["decision"] if top else "allow"
