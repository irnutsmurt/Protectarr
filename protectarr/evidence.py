"""Swarm-observation evidence: who was in a swarm, and what happened next.

Protectarr enumerates a torrent's peers immediately before removing it, because
once qBittorrent has dropped the torrent the swarm is no longer queryable. That
observation is evidence of one thing only: this IP was connected to this
torrent at this moment. It is not a claim about the IP.

The claim, when there is one, lives on the *encounter*. An encounter is one
harvest pass - one torrent, one moment, one peer list - and it carries the
torrent evidence and, once it is known, the outcome of the action we took. So
the model the UI reads is:

    IP -> observations -> encounters -> torrent evidence + outcome

and never "IP observed in torrent == malicious IP". A remediation that failed
still has its peers recorded, and those peers hang off an encounter whose
outcome says it failed.

Why SQLite rather than another JSON file beside the config. Both JSON shapes
were measured against real captured swarm data before this was written. One
document rewritten per harvest costs 60 ms at 300 encounters and grows with
total history (210 s of write time at 1,000 encounters). An append-only log
writes in 3 ms but the observations table needs per-IP aggregation, so the page
costs a full scan: 5.1 s and 168 MiB at 10,000 encounters, and `run.py` serves
threaded, so that is per concurrent request. SQLite writes in 1.15 ms with a
bounded p95, answers the per-IP detail query in 0.2 ms at every size tested,
and `sqlite3` is in the standard library, so it is not a new dependency.

Durability follows the same rule as `store.py`: a file that turns out to be
corrupt is moved aside rather than replaced, and the store reports itself
broken from then on. Evidence that cannot be read is not the same as evidence
that says nothing, and quietly substituting an empty database would turn "we
lost the record" into "there was nothing to record" - which is exactly the bug
this module replaces, since `harvest.load()` returned `{}` on a parse error and
let the next write overwrite the file.

Writing evidence is best effort and never blocks a remediation. Every entry
point swallows its own failures, counts them, and lets the caller proceed: the
security action matters more than the audit trail of it. The cost is real and
is stated rather than hidden - a failed write loses that observation for good,
because the swarm is gone once the torrent is.
"""

import os
import time
import sqlite3
import threading

from . import config as cfg_mod
from . import logs

log = logs.get("evidence")

SCHEMA_VERSION = 1

# Progress at or above this counts the peer as a seeder. A seeder of a fake is
# a materially different observation from a victim still downloading it, and it
# is the one distinction worth drawing from progress alone.
SEED_PROGRESS = 0.999

# Sources of an encounter. `legacy` rows came from the old harvest.json and
# carry no outcome, ever - see migrate_legacy().
ARR = "arr"
QBIT = "qbit_category"
LEGACY = "legacy"

_lock = threading.Lock()
_broken = None
_failures = 0
_last_failure = None
# The database the schema has been verified against, not a boolean. `path()`
# is derived from `cfg_mod.CONFIG_PATH`, so a plain "already initialised" flag
# would go on claiming a schema exists after the config directory moved, and
# every query would then fail against a real but empty file.
_ready_path = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS encounters (
    encounter_id   TEXT PRIMARY KEY,
    observed_at    REAL,
    infohash       TEXT NOT NULL,
    release_title  TEXT,
    trigger_file   TEXT,
    source         TEXT NOT NULL,
    remediation_id TEXT,
    arr_instance   TEXT,
    arr_type       TEXT,
    indexer        TEXT,
    category       TEXT,
    finding        TEXT,
    severity       TEXT,
    profile        TEXT,
    decision       TEXT,
    outcome        TEXT,
    outcome_at     REAL,
    outcome_detail TEXT,
    peer_count     INTEGER NOT NULL DEFAULT 0,
    legacy         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS enc_hash ON encounters(infohash);
CREATE INDEX IF NOT EXISTS enc_at   ON encounters(observed_at);
CREATE INDEX IF NOT EXISTS enc_rid  ON encounters(remediation_id);

CREATE TABLE IF NOT EXISTS peer_observations (
    encounter_id TEXT NOT NULL,
    ip           TEXT NOT NULL,
    progress     REAL,
    is_seeder    INTEGER NOT NULL DEFAULT 0,
    port         INTEGER,
    client       TEXT,
    country      TEXT,
    flags        TEXT,
    conn_type    TEXT,
    PRIMARY KEY (encounter_id, ip)
);
CREATE INDEX IF NOT EXISTS obs_ip ON peer_observations(ip);

CREATE TABLE IF NOT EXISTS ip_profile (
    ip                  TEXT PRIMARY KEY,
    first_seen          REAL,
    last_seen           REAL,
    encounters          INTEGER NOT NULL DEFAULT 0,
    distinct_torrents   INTEGER NOT NULL DEFAULT 0,
    latest_encounter_id TEXT,
    legacy_unattributed INTEGER NOT NULL DEFAULT 0,
    ever_seeder         INTEGER NOT NULL DEFAULT 0,
    max_progress        REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS prof_last ON ip_profile(last_seen);
CREATE INDEX IF NOT EXISTS prof_enc  ON ip_profile(encounters);

-- Which torrents an IP has been seen in, independent of whether the detailed
-- observations still exist. `ip_profile.distinct_torrents` cannot be recomputed
-- from peer_observations once retention has pruned the old rows, and recurrence
-- across unrelated torrents is the single most valuable thing this store holds,
-- so the pair itself is durable even when the detail behind it is not.
CREATE TABLE IF NOT EXISTS ip_torrent (
    ip         TEXT NOT NULL,
    infohash   TEXT NOT NULL,
    first_seen REAL,
    last_seen  REAL,
    encounters INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, infohash)
);
"""


def path():
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".",
                        "evidence.db")


def broken():
    """Why the evidence store is unusable, or None if it is healthy."""
    return _broken


def health():
    """What the System page shows about this store."""
    return {"broken": _broken, "failures": _failures,
            "last_failure": _last_failure, "path": path()}


def reset():
    """Forget the broken flag and the failure counters. For tests."""
    global _broken, _failures, _last_failure, _ready_path
    _broken, _failures, _last_failure, _ready_path = None, 0, None, None


def _disable(reason):
    global _broken
    if _broken:
        return
    _broken = reason
    log.critical(
        "Swarm observation evidence store unusable: %s. Protectarr will keep "
        "reaping fakes, but it will not record or show peer evidence until "
        "this is resolved. Check %s and any quarantined copy beside it, then "
        "restart Protectarr.", reason, path())


def _fail(what, exc):
    """Record a best-effort failure without ever raising."""
    global _failures, _last_failure
    _failures += 1
    _last_failure = f"{logs.now()}: {what}: {exc}"
    log.error("Evidence store: %s: %s", what, exc)


def _quarantine(reason):
    """Move the database aside, including its WAL and shared-memory files.

    Renaming only the main file would leave a WAL belonging to a database that
    no longer exists, and SQLite would apply it to the fresh one.
    """
    p = path()
    keep = f"{p}.corrupt-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        for suffix in ("", "-wal", "-shm"):
            src = p + suffix
            if os.path.exists(src):
                os.replace(src, keep + suffix)
        _disable(f"{reason} (kept as {keep})")
    except OSError as e:
        _disable(f"{reason}, and it could not be moved aside either ({e})")


def _connect():
    """A connection with durability turned up, or None if the store is broken.

    One connection per operation. The worker and every web request run in
    different threads, and a connection per operation sidesteps SQLite's
    same-thread rule entirely for the sake of roughly a tenth of a millisecond.
    """
    if _broken:
        return None
    p = path()
    try:
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    except OSError as e:
        _fail("could not create the directory for the database", e)
        return None
    db = None
    try:
        db = sqlite3.connect(p, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        return db
    except sqlite3.DatabaseError as e:
        # Separated from OSError deliberately. A DatabaseError here is not a
        # transient write problem, it is a file that is not a database, and
        # `sqlite3.connect` is lazy enough that this is where that first
        # surfaces. Counting it as an ordinary failure and returning None would
        # leave the bad file in place for the next call to open, fail on, and
        # eventually replace - which is the silent-reset behaviour this store
        # exists to stop.
        if db is not None:
            try:
                db.close()
            except sqlite3.Error:
                pass
        _quarantine(f"{p} is not a usable database ({e})")
        return None
    except OSError as e:
        _fail("could not open the database", e)
        return None


def init():
    """Create or verify the schema. Returns True if the store is usable.

    The integrity check runs here rather than lazily so a corrupt database is
    found at startup, when the System page can say so, instead of at the moment
    a reap is trying to record its evidence.
    """
    global _ready_path
    here = path()
    with _lock:
        if _broken:
            return False
        if _ready_path == here:
            return True
        db = _connect()
        if db is None:
            return False
        try:
            with db:
                row = db.execute("PRAGMA integrity_check").fetchone()
                if row and row[0] != "ok":
                    db.close()
                    _quarantine(f"{path()} failed its integrity check ({row[0]})")
                    return False
                db.executescript(SCHEMA)
                db.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(SCHEMA_VERSION),))
            _ready_path = here
            return True
        except sqlite3.DatabaseError as e:
            # A malformed file raises here rather than failing integrity_check,
            # so this path has to quarantine too or the next write recreates it.
            _quarantine(f"{path()} is not a usable database ({e})")
            return False
        finally:
            try:
                db.close()
            except sqlite3.Error:
                pass


def _new_id():
    return os.urandom(16).hex()


def _apply_observation(db, ip, enc_id, infohash, at, progress, seeder, new_torrent_ok=True):
    """Fold one peer sighting into the durable profile and pair tables."""
    prof = db.execute("SELECT first_seen, last_seen, encounters, "
                      "distinct_torrents, max_progress FROM ip_profile "
                      "WHERE ip = ?", (ip,)).fetchone()
    pair = db.execute("SELECT encounters FROM ip_torrent WHERE ip = ? AND "
                      "infohash = ?", (ip, infohash)).fetchone()
    is_new_torrent = pair is None
    if pair is None:
        db.execute("INSERT INTO ip_torrent (ip, infohash, first_seen, "
                   "last_seen, encounters) VALUES (?, ?, ?, ?, 1)",
                   (ip, infohash, at, at))
    else:
        db.execute("UPDATE ip_torrent SET encounters = encounters + 1, "
                   "last_seen = MAX(COALESCE(last_seen, 0), COALESCE(?, 0)), "
                   "first_seen = MIN(COALESCE(first_seen, ?), COALESCE(?, first_seen)) "
                   "WHERE ip = ? AND infohash = ?", (at, at, at, ip, infohash))
    if prof is None:
        db.execute(
            "INSERT INTO ip_profile (ip, first_seen, last_seen, encounters, "
            "distinct_torrents, latest_encounter_id, ever_seeder, max_progress)"
            " VALUES (?, ?, ?, 1, 1, ?, ?, ?)",
            (ip, at, at, enc_id, int(bool(seeder)), progress or 0))
        return
    # `latest_encounter_id` only moves forward in time. Migration inserts older
    # encounters after newer ones, so "the last one written" is not "the newest".
    newer = at is not None and (prof["last_seen"] is None or at >= prof["last_seen"])
    db.execute(
        "UPDATE ip_profile SET "
        "  first_seen = CASE WHEN first_seen IS NULL OR (? IS NOT NULL AND ? < first_seen) THEN ? ELSE first_seen END,"
        "  last_seen  = CASE WHEN last_seen IS NULL OR (? IS NOT NULL AND ? > last_seen) THEN ? ELSE last_seen END,"
        "  encounters = encounters + 1,"
        "  distinct_torrents = distinct_torrents + ?,"
        "  latest_encounter_id = CASE WHEN ? THEN ? ELSE latest_encounter_id END,"
        "  ever_seeder = CASE WHEN ? THEN 1 ELSE ever_seeder END,"
        "  max_progress = MAX(max_progress, ?)"
        " WHERE ip = ?",
        (at, at, at, at, at, at, 1 if is_new_torrent else 0,
         1 if newer else 0, enc_id, 1 if seeder else 0, progress or 0, ip))


def record_encounter(peers, meta):
    """Persist one harvest pass. Returns the encounter id, or None.

    Never raises. A None return means the evidence was lost, not that the
    caller should stop: the remediation this belongs to must go ahead either
    way, and the loss is counted into health() so the System page can show it.

    An empty swarm is deliberately not stored. "We looked and found nobody" is
    operational telemetry, already carried by `peers_harvested` on the history
    event, and a row here with no observations would inflate every encounter
    count for no evidential gain.
    """
    infohash = (meta.get("infohash") or "").lower()
    if not peers or not infohash:
        return None
    if not init():
        return None
    enc_id = _new_id()
    at = meta.get("observed_at")
    if at is None:
        at = time.time()
    seen, rows = set(), []
    for p in peers:
        ip = p.get("ip")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        progress = float(p.get("progress") or 0)
        rows.append((enc_id, ip, progress, int(progress >= SEED_PROGRESS),
                     p.get("port"), (p.get("client") or "").strip() or None,
                     (p.get("country") or "").strip() or None,
                     (p.get("flags") or "").strip() or None,
                     (p.get("connection") or "").strip() or None))
    if not rows:
        return None
    db = _connect()
    if db is None:
        return None
    try:
        with _lock, db:
            db.execute(
                "INSERT INTO encounters (encounter_id, observed_at, infohash, "
                "release_title, trigger_file, source, remediation_id, "
                "arr_instance, arr_type, indexer, category, finding, severity, "
                "profile, decision, peer_count, legacy) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (enc_id, at, infohash, meta.get("release_title"),
                 meta.get("trigger_file"), meta.get("source") or ARR,
                 meta.get("remediation_id"), meta.get("arr_instance"),
                 meta.get("arr_type"), meta.get("indexer"),
                 meta.get("category"), meta.get("finding"),
                 meta.get("severity"), meta.get("profile"),
                 meta.get("decision"), len(rows)))
            db.executemany(
                "INSERT INTO peer_observations (encounter_id, ip, progress, "
                "is_seeder, port, client, country, flags, conn_type) "
                "VALUES (?,?,?,?,?,?,?,?,?)", rows)
            for r in rows:
                _apply_observation(db, r[1], enc_id, infohash, at, r[2], r[3])
        return enc_id
    except sqlite3.DatabaseError as e:
        _fail("could not record an encounter", e)
        return None
    finally:
        try:
            db.close()
        except sqlite3.Error:
            pass


def attach_remediation(enc_id, remediation_id):
    """Link an encounter to the *arr remediation that followed it.

    Harvesting happens before the write-ahead intent exists, so the id is not
    known when the encounter is written. This is a separate call rather than a
    reordering because `open_intent` can legitimately refuse, and an encounter
    that never became a remediation must keep a NULL here rather than pointing
    at an intent that was never opened.
    """
    if not enc_id or not remediation_id:
        return False
    return _update(enc_id, "remediation_id = ?", (remediation_id,),
                   "could not attach a remediation id")


def set_outcome(enc_id, outcome, detail=None, at=None):
    """Snapshot what happened, once it is known.

    Copied onto the encounter rather than joined to events.jsonl at read time,
    because that file rotates: at ~1,179 bytes an event and 5 MB x 3 files it
    holds roughly 13,300 events, so a live join would silently turn old
    encounters back into "unknown" as history aged out.
    """
    if not enc_id or not outcome:
        return False
    return _update(enc_id, "outcome = ?, outcome_at = ?, outcome_detail = ?",
                   (outcome, at if at is not None else time.time(), detail),
                   "could not record an outcome")


def _update(enc_id, setclause, params, what):
    if not init():
        return False
    db = _connect()
    if db is None:
        return False
    try:
        with _lock, db:
            db.execute(f"UPDATE encounters SET {setclause} WHERE encounter_id = ?",
                       tuple(params) + (enc_id,))
        return True
    except sqlite3.DatabaseError as e:
        _fail(what, e)
        return False
    finally:
        try:
            db.close()
        except sqlite3.Error:
            pass


# ---------------------------------------------------------------- reading

def _rows(sql, params=()):
    if not init():
        return None
    db = _connect()
    if db is None:
        return None
    try:
        return db.execute(sql, params).fetchall()
    except sqlite3.DatabaseError as e:
        _fail("could not read evidence", e)
        return None
    finally:
        try:
            db.close()
        except sqlite3.Error:
            pass


def observations(limit=500, offset=0):
    """Rows for the Swarm Observations table, strongest evidence first.

    Read straight off `ip_profile` rather than aggregated from the observation
    rows. The aggregate was measured at 0.6 s over 350,000 rows, which is a
    page load, and it would be wrong anyway once retention has pruned the
    detail out from under it.

    `encounters` and `distinct_torrents` are both returned because they are
    different evidence. Ten encounters with one torrent is Protectarr acting on
    the same release repeatedly; ten encounters across ten torrents is an IP
    that keeps turning up in unrelated fakes.
    """
    rows = _rows(
        "SELECT p.ip, p.encounters, p.distinct_torrents, p.first_seen, "
        "       p.last_seen, p.legacy_unattributed, p.ever_seeder, "
        "       e.finding, e.trigger_file, e.release_title, e.outcome, "
        "       e.legacy AS latest_legacy "
        "FROM ip_profile p "
        "LEFT JOIN encounters e ON e.encounter_id = p.latest_encounter_id "
        "ORDER BY p.encounters DESC, p.distinct_torrents DESC, p.last_seen DESC "
        "LIMIT ? OFFSET ?", (limit, offset))
    if rows is None:
        return None
    return [_observation_row(r) for r in rows]


def _observation_row(r):
    return {
        "ip": r["ip"],
        "encounters": r["encounters"],
        "distinct_torrents": r["distinct_torrents"],
        # True when we know the real count is higher than we can show. Rendered
        # as "6+" so the number is never quietly wrong.
        "encounters_lower_bound": bool(r["legacy_unattributed"]),
        "latest_finding": _finding_label(r["finding"], r["trigger_file"],
                                         r["latest_legacy"]),
        "latest_release": r["release_title"],
        "latest_outcome": r["outcome"],
        "first_observed": logs.stamp(r["first_seen"]),
        "last_observed": logs.stamp(r["last_seen"]),
        "ever_seeder": bool(r["ever_seeder"]),
    }


def _finding_label(finding, trigger_file, legacy):
    """What the detector said, or the honest substitute when it was not stored.

    The old ledger kept the offending filename but never the finding type, so a
    migrated row can show the evidence without being able to name the rule that
    fired. Saying "extension match" here would be a guess dressed as a record.
    """
    if finding:
        return finding
    if trigger_file:
        return (f"{trigger_file} (finding type not recorded)" if legacy
                else trigger_file)
    return None


def profile(ip):
    """Everything known about one IP, for the Peer Profile Details modal."""
    if not ip:
        return None
    head = _rows("SELECT * FROM ip_profile WHERE ip = ?", (ip,))
    if not head:
        return None
    p = head[0]
    seen = _rows(
        "SELECT e.encounter_id, e.observed_at, e.release_title, e.infohash, "
        "       e.trigger_file, e.finding, e.severity, e.outcome, "
        "       e.outcome_detail, e.source, e.legacy, e.indexer, "
        "       e.arr_instance, e.decision, o.progress, o.is_seeder, "
        "       o.client, o.country, o.port, o.flags "
        "FROM peer_observations o "
        "JOIN encounters e ON e.encounter_id = o.encounter_id "
        "WHERE o.ip = ? ORDER BY e.observed_at DESC", (ip,)) or []
    torrents = _rows("SELECT COUNT(*) AS n FROM ip_torrent WHERE ip = ?", (ip,))
    return {
        "ip": ip,
        "first_observed": logs.stamp(p["first_seen"]),
        "last_observed": logs.stamp(p["last_seen"]),
        "encounters": p["encounters"],
        "distinct_torrents": (torrents[0]["n"] if torrents
                              else p["distinct_torrents"]),
        "encounters_lower_bound": bool(p["legacy_unattributed"]),
        "legacy_unattributed": p["legacy_unattributed"],
        # How many of those encounters we can still show the detail for. Lower
        # than `encounters` once retention has pruned the observation rows, and
        # the modal has to say which of the two reasons applies.
        "retained_details": len(seen),
        "ever_seeder": bool(p["ever_seeder"]),
        "history": [_encounter_row(r) for r in seen],
    }


def _encounter_row(r):
    return {
        "observed_at": logs.stamp(r["observed_at"]),
        "release": r["release_title"],
        "infohash": r["infohash"],
        "finding": _finding_label(r["finding"], r["trigger_file"], r["legacy"]),
        "severity": r["severity"],
        "outcome": r["outcome"],
        "outcome_detail": r["outcome_detail"],
        "source": r["source"],
        "legacy": bool(r["legacy"]),
        "indexer": r["indexer"],
        "app": r["arr_instance"],
        "progress": r["progress"],
        "is_seeder": bool(r["is_seeder"]),
        "client": r["client"],
        "country": r["country"],
        "port": r["port"],
    }


def profiles(ips):
    """`profile()` for many IPs in two queries rather than two per IP.

    The Swarm Observations page renders every row's modal content up front,
    the way History does. Doing that one IP at a time is several hundred round
    trips per page load for no reason - the rows are already known, so the
    encounter history for all of them is one indexed read.
    """
    ips = [i for i in (ips or []) if i]
    if not ips:
        return {}
    marks = ",".join("?" * len(ips))
    heads = _rows(f"SELECT * FROM ip_profile WHERE ip IN ({marks})",
                  tuple(ips)) or []
    pairs = _rows("SELECT ip, COUNT(*) AS n FROM ip_torrent "
                  f"WHERE ip IN ({marks}) GROUP BY ip", tuple(ips)) or []
    seen = _rows(
        "SELECT o.ip, e.encounter_id, e.observed_at, e.release_title, "
        "       e.infohash, e.trigger_file, e.finding, e.severity, e.outcome, "
        "       e.outcome_detail, e.source, e.legacy, e.indexer, "
        "       e.arr_instance, e.decision, o.progress, o.is_seeder, "
        "       o.client, o.country, o.port, o.flags "
        "FROM peer_observations o "
        "JOIN encounters e ON e.encounter_id = o.encounter_id "
        f"WHERE o.ip IN ({marks}) "
        "ORDER BY e.observed_at IS NULL, e.observed_at DESC", tuple(ips)) or []
    history = {}
    for r in seen:
        history.setdefault(r["ip"], []).append(_encounter_row(r))
    torrents = {r["ip"]: r["n"] for r in pairs}
    out = {}
    for p in heads:
        rows = history.get(p["ip"], [])
        out[p["ip"]] = {
            "ip": p["ip"],
            "first_observed": logs.stamp(p["first_seen"]),
            "last_observed": logs.stamp(p["last_seen"]),
            "encounters": p["encounters"],
            "distinct_torrents": torrents.get(p["ip"], p["distinct_torrents"]),
            "encounters_lower_bound": bool(p["legacy_unattributed"]),
            "legacy_unattributed": p["legacy_unattributed"],
            "retained_details": len(rows),
            "ever_seeder": bool(p["ever_seeder"]),
            "history": rows,
        }
    return out


def counts():
    """Totals for the page footer."""
    rows = _rows("SELECT (SELECT COUNT(*) FROM ip_profile) AS ips, "
                 "(SELECT COUNT(*) FROM encounters) AS encounters, "
                 "(SELECT COUNT(*) FROM peer_observations) AS observations")
    if not rows:
        return {"ips": 0, "encounters": 0, "observations": 0}
    return dict(rows[0])


# ---------------------------------------------------------------- retention

# Config-only for now, deliberately. These are the three numbers the measured
# growth model turned on, and none of them is a decision a user can make well
# from a Settings form without the growth curve in front of them.
DEFAULTS = {
    # Detail for the newest N encounters. At a typical 35-peer swarm that is
    # roughly 11 MiB of observation rows; at qBittorrent's 100-connection
    # per-torrent ceiling, roughly 32 MiB.
    "detail_encounters": 2000,
    # An IP seen in exactly one encounter is the overwhelming majority - 90.5%
    # of the real captured sample - and carries the least evidence. Expiring
    # those is what bounds the profile table, and it costs no recurrence
    # evidence at all, because recurrence is precisely what it does not have.
    "single_profile_days": 90,
    "recurring_profile_days": 365,
}


def settings(cfg):
    h = (cfg or {}).get("harvest", {}) or {}
    out = dict(DEFAULTS)
    for k in DEFAULTS:
        v = h.get(k)
        if isinstance(v, int) and v > 0:
            out[k] = v
    return out


def prune(cfg=None):
    """Apply retention. Returns what it removed, or None if it could not run.

    Encounter headers are never pruned: they are the action history, they cost
    about 470 bytes each, and the newest one is where an IP's latest finding is
    read from. Only the per-peer detail expires, and only after the profile has
    already absorbed the part of it that is durable evidence.
    """
    if not init():
        return None
    s = settings(cfg if cfg is not None else cfg_mod.load())
    now = time.time()
    single_cut = now - s["single_profile_days"] * 86400
    recur_cut = now - s["recurring_profile_days"] * 86400
    db = _connect()
    if db is None:
        return None
    try:
        with _lock, db:
            cur = db.execute(
                "DELETE FROM peer_observations WHERE encounter_id IN ("
                "  SELECT encounter_id FROM encounters"
                "  ORDER BY observed_at IS NULL, observed_at DESC"
                "  LIMIT -1 OFFSET ?)", (s["detail_encounters"],))
            details = cur.rowcount or 0
            # A profile and its detail go together. Dropping the profile alone
            # would leave observation rows the table can no longer reach, and
            # dropping the detail alone would leave a profile claiming
            # encounters nothing can show.
            gone = [r["ip"] for r in db.execute(
                "SELECT ip FROM ip_profile WHERE last_seen IS NOT NULL AND ("
                "  (encounters <= 1 AND last_seen < ?) OR"
                "  (encounters >  1 AND last_seen < ?))",
                (single_cut, recur_cut)).fetchall()]
            for ip in gone:
                db.execute("DELETE FROM peer_observations WHERE ip = ?", (ip,))
                db.execute("DELETE FROM ip_torrent WHERE ip = ?", (ip,))
                db.execute("DELETE FROM ip_profile WHERE ip = ?", (ip,))
        return {"details_expired": details, "profiles_expired": len(gone)}
    except sqlite3.DatabaseError as e:
        _fail("could not apply retention", e)
        return None
    finally:
        try:
            db.close()
        except sqlite3.Error:
            pass


# ---------------------------------------------------------------- migration

def _legacy_path():
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".",
                        "harvest.json")


def migrate_legacy():
    """Fold an old harvest.json into the evidence store, once.

    The old ledger stored one record per IP with a `torrents` map, and it
    overwrote that map entry every time the same hash was harvested again. What
    survived is still worth keeping, and what did not must not be invented.

    Encounter identity comes from `(infohash, last)`. `record()` built one
    `tinfo` per call from a single `logs.now()` and assigned that same value to
    every IP it touched, so an identical `last` across IPs means one harvest
    pass and a differing `last` for the same hash means separate passes. That
    makes the grouping the original pass structure rather than a guess, and it
    recovers more encounters than keying on the hash alone: the live ledger
    this was built against yields three encounters, not two.

    What is deliberately not reconstructed: the outcome (never recorded, so it
    stays NULL and renders as Outcome Unknown), and the sightings lost to the
    overwrite. Those are counted onto the profile as `legacy_unattributed`
    rather than being placed into an encounter they cannot be proved to belong
    to. An IP with two hashes and three hits gives no way to say which hash saw
    it twice, so no row is written that claims to know.
    """
    import json

    if not init():
        return None
    src = _legacy_path()
    if not os.path.exists(src):
        return None
    db = _connect()
    if db is None:
        return None
    try:
        done = db.execute("SELECT value FROM meta WHERE key = 'legacy_migrated'"
                          ).fetchone()
        if done:
            return None
        try:
            with open(src) as fh:
                ledger = json.load(fh)
            ips = (ledger or {}).get("ips") or {}
        except (OSError, ValueError) as e:
            # Unreadable legacy data is not a reason to refuse to start, but it
            # is a reason not to mark the migration done and silently move on.
            _fail(f"could not read the legacy ledger at {src}", e)
            return None

        groups, legacy_aggr = {}, {}
        for ip, e in ips.items():
            torrents = e.get("torrents") or {}
            for thash, t in torrents.items():
                groups.setdefault(((thash or "").lower(), t.get("last")),
                                  []).append((ip, t, e))
            unplaced = max(0, int(e.get("hits") or 0) - len(torrents))
            legacy_aggr[ip] = {
                "unattributed": unplaced,
                "max_progress": float(e.get("max_progress") or 0),
                "seeder": float(e.get("max_progress") or 0) >= SEED_PROGRESS,
            }

        # Oldest first, so `latest_encounter_id` ends up on the newest one.
        ordered = sorted(groups.items(),
                         key=lambda kv: (logs.parse_stamp(kv[0][1]) or 0))
        encounters = observations_written = 0
        with _lock, db:
            for (thash, last), members in ordered:
                at = logs.parse_stamp(last)
                if at is None:
                    for _ip, _t, entry in members:
                        at = (logs.parse_stamp(entry.get("last_seen"))
                              or logs.parse_stamp(entry.get("first_seen")))
                        if at is not None:
                            break
                enc_id = _new_id()
                sample = members[0][1]
                db.execute(
                    "INSERT INTO encounters (encounter_id, observed_at, "
                    "infohash, release_title, trigger_file, source, indexer, "
                    "arr_instance, peer_count, legacy) "
                    "VALUES (?,?,?,?,?,?,?,?,?,1)",
                    (enc_id, at, thash, sample.get("name"), sample.get("ext"),
                     LEGACY, sample.get("indexer"), sample.get("app"),
                     len(members)))
                encounters += 1
                for ip, _t, _entry in members:
                    # Progress, client, port and country were per-IP aggregates
                    # across every torrent, never per pass, so none of them can
                    # be attached to this encounter without inventing a
                    # measurement that was never taken.
                    db.execute(
                        "INSERT OR IGNORE INTO peer_observations "
                        "(encounter_id, ip, progress, is_seeder) "
                        "VALUES (?, ?, NULL, 0)", (enc_id, ip))
                    _apply_observation(db, ip, enc_id, thash, at, None, False)
                    observations_written += 1
            for ip, aggr in legacy_aggr.items():
                db.execute(
                    "UPDATE ip_profile SET legacy_unattributed = ?, "
                    "ever_seeder = CASE WHEN ? THEN 1 ELSE ever_seeder END, "
                    "max_progress = MAX(max_progress, ?) WHERE ip = ?",
                    (aggr["unattributed"], 1 if aggr["seeder"] else 0,
                     aggr["max_progress"], ip))
            db.execute("INSERT INTO meta (key, value) VALUES "
                       "('legacy_migrated', ?)", (logs.now(),))

        kept = f"{src}.migrated-{time.strftime('%Y%m%d-%H%M%S')}"
        try:
            os.replace(src, kept)
        except OSError as e:
            # Not fatal: the migration is recorded as done in `meta`, so it
            # will not run twice even if the old file is still sitting there.
            log.warning("Migrated the legacy harvest ledger but could not "
                        "rename %s: %s", src, e)
            kept = None
        unattributed = sum(a["unattributed"] for a in legacy_aggr.values())
        log.info("Migrated legacy harvest ledger: %d encounter(s), %d "
                 "observation(s), %d IP(s), %d sighting(s) that could not be "
                 "attributed to a specific encounter.%s",
                 encounters, observations_written, len(legacy_aggr),
                 unattributed, f" Original kept as {kept}." if kept else "")
        return {"encounters": encounters, "observations": observations_written,
                "ips": len(legacy_aggr), "unattributed": unattributed,
                "kept": kept}
    except sqlite3.DatabaseError as e:
        _fail("could not migrate the legacy ledger", e)
        return None
    finally:
        try:
            db.close()
        except sqlite3.Error:
            pass
