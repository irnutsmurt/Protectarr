"""The whole of `core.evaluate`, as a table, before anything refactors it.

`evaluate` is about to be reduced to a thin mapping over `core.explain`, which
is the function the Active Downloads page will read. That refactor must not
change a single answer, and "the existing tests still pass" is not the same
claim: the existing tests cover the interesting cells, not all of them.

So this enumerates every combination the function can be called with - five
modes by six ownership states by tracked/untracked by allowlisted/not by
ownership-known/not, 240 cells - and pins the answer to each.

The expected answers are written out below as a literal. That is deliberate.
A table computed from `core` would move whenever `core` moved and would agree
with it by construction, which is exactly how a page-composition mutant
survived during the 0.7.0 work. This one is an external fact: it was read off
the running code before the refactor, and from here on it only changes when a
human decides behaviour should change.

Note what the tables show that is easy to miss in the source:

  * ownership alters the outcome for exactly the states that carry evidence
    about an owner: `conflicted` (never actionable), an orphan inside its
    dwell (never actionable), `owned` (never deleted *directly*), and
    `provisional_grabbed` (an exact grab-history owner, likewise).
  * an unrecognised mode is a refusal, not a default. `bogus` is all dashes.
  * direct deletion needs a fresh synchronisation. That is the difference
    between the two tables, and it is an argument rather than a stored fact,
    so it cannot be a column of the ownership record.

The `owned` row changed in the 0.9.1 ownership safety fix, and `untracked`,
`provisional` and the second table arrived with the 0.9.3 first-pass race fix.
Both tables were re-derived from the fixed code and checked cell by cell.
"""

import unittest

from protectarr import core
from protectarr import ownership


# The eight columns of each row, in order. Read as three nested binary axes:
# tracked by an *arr, allowlisted by category, ownership fully known.
COLUMNS = [
    (hit, allowed, known)
    for hit in (False, True)
    for allowed in (False, True)
    for known in (False, True)
]

# `-` leave it alone, `A` hand back to the owning *arr, `Q` delete from
# qBittorrent directly. Rows are (mode, ownership state).
#                        hit=F                    hit=T
#                   allow=F    allow=T       allow=F    allow=T
#                  known F T   known F T    known F T   known F T
#
# Direct deletion is refused until a synchronisation run for THIS attempt has
# established that every application was reachable, every refresh completed,
# and neither a live claim nor a retained grab event names the hash. This is
# the table for an attempt that has NOT been cleared, which is the default and
# the state every attempt starts in.
TABLE = """
arr_tracked    none                 - -  - -    A A  A A
arr_tracked    untracked            - -  - -    A A  A A
arr_tracked    provisional          - -  - -    A A  A A
arr_tracked    provisional_grabbed  - -  - -    A A  A A
arr_tracked    owned                - -  - -    A A  A A
arr_tracked    orphan_fresh         - -  - -    - -  - -
arr_tracked    orphan_dwelled       - -  - -    A A  A A
arr_tracked    conflicted           - -  - -    - -  - -

both           none                 - -  - -    - -  A A
both           untracked            - -  - -    - -  A A
both           provisional          - -  - -    - -  A A
both           provisional_grabbed  - -  - -    - -  A A
both           owned                - -  - -    - -  A A
both           orphan_fresh         - -  - -    - -  - -
both           orphan_dwelled       - -  - -    - -  A A
both           conflicted           - -  - -    - -  - -

allowlist      none                 - -  - -    - -  A A
allowlist      untracked            - -  - -    - -  A A
allowlist      provisional          - -  - -    - -  A A
allowlist      provisional_grabbed  - -  - -    - -  A A
allowlist      owned                - -  - -    - -  A A
allowlist      orphan_fresh         - -  - -    - -  - -
allowlist      orphan_dwelled       - -  - Q    - -  A A
allowlist      conflicted           - -  - -    - -  - -

either         none                 - -  - -    A A  A A
either         untracked            - -  - -    A A  A A
either         provisional          - -  - -    A A  A A
either         provisional_grabbed  - -  - -    A A  A A
either         owned                - -  - -    A A  A A
either         orphan_fresh         - -  - -    - -  - -
either         orphan_dwelled       - -  - Q    A A  A A
either         conflicted           - -  - -    - -  - -

bogus          none                 - -  - -    - -  - -
bogus          untracked            - -  - -    - -  - -
bogus          provisional          - -  - -    - -  - -
bogus          provisional_grabbed  - -  - -    - -  - -
bogus          owned                - -  - -    - -  - -
bogus          orphan_fresh         - -  - -    - -  - -
bogus          orphan_dwelled       - -  - -    - -  - -
bogus          conflicted           - -  - -    - -  - -
"""

# The same table for an attempt that HAS been cleared. Only three rows move,
# and the two that do not are the point: a stored owner and an exact
# grab-history owner both outrank a clearance, because a synchronisation that
# found no evidence has not disproved evidence we already have. Retained
# history is deleted when a series or movie is, while the torrent keeps
# downloading, so absence genuinely is not evidence here.
CLEARED_TABLE = """
arr_tracked    none                 - -  - -    A A  A A
arr_tracked    untracked            - -  - -    A A  A A
arr_tracked    provisional          - -  - -    A A  A A
arr_tracked    provisional_grabbed  - -  - -    A A  A A
arr_tracked    owned                - -  - -    A A  A A
arr_tracked    orphan_fresh         - -  - -    - -  - -
arr_tracked    orphan_dwelled       - -  - -    A A  A A
arr_tracked    conflicted           - -  - -    - -  - -

both           none                 - -  - -    - -  A A
both           untracked            - -  - -    - -  A A
both           provisional          - -  - -    - -  A A
both           provisional_grabbed  - -  - -    - -  A A
both           owned                - -  - -    - -  A A
both           orphan_fresh         - -  - -    - -  - -
both           orphan_dwelled       - -  - -    - -  A A
both           conflicted           - -  - -    - -  - -

allowlist      none                 - -  - Q    - -  A A
allowlist      untracked            - -  - Q    - -  A A
allowlist      provisional          - -  - Q    - -  A A
allowlist      provisional_grabbed  - -  - -    - -  A A
allowlist      owned                - -  - -    - -  A A
allowlist      orphan_fresh         - -  - -    - -  - -
allowlist      orphan_dwelled       - -  - Q    - -  A A
allowlist      conflicted           - -  - -    - -  - -

either         none                 - -  - Q    A A  A A
either         untracked            - -  - Q    A A  A A
either         provisional          - -  - Q    A A  A A
either         provisional_grabbed  - -  - -    A A  A A
either         owned                - -  - -    A A  A A
either         orphan_fresh         - -  - -    - -  - -
either         orphan_dwelled       - -  - Q    A A  A A
either         conflicted           - -  - -    - -  - -

bogus          none                 - -  - -    - -  - -
bogus          untracked            - -  - -    - -  - -
bogus          provisional          - -  - -    - -  - -
bogus          provisional_grabbed  - -  - -    - -  - -
bogus          owned                - -  - -    - -  - -
bogus          orphan_fresh         - -  - -    - -  - -
bogus          orphan_dwelled       - -  - -    - -  - -
bogus          conflicted           - -  - -    - -  - -
"""

VERDICT = {"-": None, "A": "arr_fail", "Q": "qbit_delete"}

DWELL_MINUTES = 10

# The ownership states, built the way `ownership.resolve` builds them. The two
# orphans differ only in `absent_for`, which is the field the dwell is measured
# from and the only thing separating "wait" from "act".
OWNERSHIPS = {
    "none": None,
    "untracked": ownership.Ownership(
        ownership.UNTRACKED, None, None, None, None, "never claimed"),
    "owned": ownership.Ownership(
        ownership.OWNED, "Sonarr", None, {}, None, "claimed by its owner"),
    "orphan_fresh": ownership.Ownership(
        ownership.ORPHANED, "Sonarr", None, None, 60, "absent 1m"),
    "orphan_dwelled": ownership.Ownership(
        ownership.ORPHANED, "Sonarr", None, None, (DWELL_MINUTES + 1) * 60,
        "absent 11m"),
    "conflicted": ownership.Ownership(
        ownership.CONFLICTED, None, None, None, None, "two claims"),
    # Written on first sight, before anything is decided about the torrent.
    "provisional": ownership.Ownership(
        ownership.PROVISIONAL, None, None, None, None, "first sight"),
    # The same state carrying an exact grab-history owner. The difference is
    # the whole reason positive evidence outranks a clearance.
    "provisional_grabbed": ownership.Ownership(
        ownership.PROVISIONAL, "Sonarr", None, None, None,
        "grabbed by Sonarr according to its history"),
}

SAFETY = {"allowed_categories": ["tv"], "allowed_tags": [],
          "orphan_dwell_minutes": DWELL_MINUTES}

# Stands in for (client, record). `evaluate` only ever tests it for truth.
TRACKED = ("client", {})


def parse_table(text):
    """The literal above as {(mode, ownership): [verdict x 8]}."""
    out = {}
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        mode, own, *cells = line.split()
        assert len(cells) == len(COLUMNS), (mode, own, cells)
        out[(mode, own)] = [VERDICT[c] for c in cells]
    return out


EXPECTED = parse_table(TABLE)
EXPECTED_CLEARED = parse_table(CLEARED_TABLE)


class TestTheDecisionTableIsPinned(unittest.TestCase):
    """Every cell, by name, so a refactor cannot quietly move one."""

    def verdict(self, mode, own_key, hit, allowed, known, cleared=False):
        safety = dict(SAFETY, mode=mode)
        torrent = {"category": "tv" if allowed else "other", "tags": ""}
        return core.evaluate(torrent, "", TRACKED if hit else None, safety,
                             known, own=OWNERSHIPS[own_key],
                             fallback_cleared=cleared)

    def test_every_cell_matches_the_recorded_table(self):
        checked = 0
        for (mode, own_key), row in sorted(EXPECTED.items()):
            for (hit, allowed, known), want in zip(COLUMNS, row):
                got = self.verdict(mode, own_key, hit, allowed, known)
                self.assertEqual(
                    got, want,
                    f"mode={mode} ownership={own_key} arr_tracked={hit} "
                    f"allowlisted={allowed} ownership_known={known}: "
                    f"expected {want!r}, got {got!r}")
                checked += 1
        self.assertEqual(checked, 320)

    def test_every_cleared_cell_matches_the_recorded_table(self):
        """The second table: the same inputs with a synchronisation clearance
        for this attempt. Pinned separately because a clearance is an argument,
        not a property of the torrent, and must not leak into the first."""
        checked = 0
        for (mode, own_key), row in sorted(EXPECTED_CLEARED.items()):
            for (hit, allowed, known), want in zip(COLUMNS, row):
                got = self.verdict(mode, own_key, hit, allowed, known,
                                   cleared=True)
                self.assertEqual(
                    got, want,
                    f"[cleared] mode={mode} ownership={own_key} "
                    f"arr_tracked={hit} allowlisted={allowed} "
                    f"ownership_known={known}: expected {want!r}, got {got!r}")
                checked += 1
        self.assertEqual(checked, 320)

    def test_a_clearance_only_ever_permits_direct_deletion(self):
        """It may turn a refusal into `qbit_delete` and nothing else. If a
        clearance could change an `arr_fail` into something else, or withdraw
        one, it would be deciding ownership rather than authorising a fallback.
        """
        for key in EXPECTED:
            for plain, cleared in zip(EXPECTED[key], EXPECTED_CLEARED[key]):
                if plain != cleared:
                    self.assertIsNone(plain, f"{key}: clearance withdrew {plain!r}")
                    self.assertEqual(cleared, "qbit_delete", f"{key}")

    def test_without_a_clearance_only_a_dwelled_orphan_is_deletable(self):
        """Everything else has to synchronise first. The orphan is exempt
        because its evidence was earned by watching the torrent leave a queue
        we read, and the dwell already aged it."""
        for (mode, own), row in EXPECTED.items():
            if "qbit_delete" in row:
                self.assertEqual(own, "orphan_dwelled",
                                 f"{mode}/{own} deletes without synchronising")

    def test_the_table_covers_every_mode_the_code_can_take(self):
        """A mode added to `evaluate` without a row here would go unpinned."""
        modes = {mode for mode, _ in EXPECTED}
        self.assertEqual(modes, {"arr_tracked", "both", "allowlist", "either",
                                 "bogus"})

    def test_the_table_covers_every_ownership_state(self):
        states = {own for _, own in EXPECTED}
        self.assertEqual(
            {ownership.UNTRACKED, ownership.OWNED, ownership.ORPHANED,
             ownership.CONFLICTED},
            {"untracked", "owned", "orphaned", "conflicted"},
            "the ownership vocabulary moved; the table below needs revisiting")
        self.assertEqual(states, {"none", "untracked", "provisional",
                                  "provisional_grabbed", "owned",
                                  "orphan_fresh", "orphan_dwelled",
                                  "conflicted"})
        self.assertEqual(set(EXPECTED), set(EXPECTED_CLEARED),
                         "the two tables must cover the same ground")


class TestTheInvariantsBehindTheTable(unittest.TestCase):
    """The shape of the table, stated as the rules it is supposed to encode.

    These would all pass against a table that had been regenerated from a
    broken `core`, which is why they are in addition to the cell-by-cell pin
    rather than instead of it. What they add is a name for each rule, so a
    failure says which promise broke rather than which of 240 cells moved.
    """

    def rows_for(self, own_key):
        return {mode: row for (mode, own), row in EXPECTED.items()
                if own == own_key}

    def test_a_conflict_is_never_actionable_in_any_mode(self):
        for mode, row in self.rows_for("conflicted").items():
            self.assertEqual(row, [None] * 8, f"mode {mode} acted on a conflict")

    def test_an_orphan_inside_its_dwell_is_never_actionable(self):
        for mode, row in self.rows_for("orphan_fresh").items():
            self.assertEqual(row, [None] * 8,
                             f"mode {mode} acted inside the dwell")

    def test_an_exact_grab_history_owner_is_never_deleted_directly(self):
        """Positive evidence from the *arr's own history. It outranks a
        clearance, because a later synchronisation finding no row has not
        retracted the row we already saw."""
        for table, label in ((EXPECTED, "uncleared"),
                             (EXPECTED_CLEARED, "cleared")):
            for (mode, own), row in table.items():
                if own == "provisional_grabbed":
                    self.assertNotIn("qbit_delete", row,
                                     f"[{label}] {mode} deleted a torrent "
                                     f"whose grab history names an owner")

    def test_ownership_is_invisible_only_where_it_carries_no_evidence(self):
        """No record, never claimed, and an orphan that has served its dwell
        are the same input as far as the mode dispatch is concerned.

        `owned` is deliberately not in this list. It used to be, which is what
        made the direct-delete cell unsafe: a stored owner counted for exactly
        nothing once the pass itself saw no claim.
        """
        for mode in ("arr_tracked", "both", "allowlist", "either", "bogus"):
            rows = [EXPECTED_CLEARED[(mode, k)] for k in
                    ("none", "untracked", "provisional", "orphan_dwelled")]
            self.assertEqual(rows[1:], rows[:-1], f"mode {mode} diverged")

    def test_a_stored_owner_is_never_deleted_directly_in_any_mode(self):
        """The invariant the fix exists to enforce, read off the table.

        Direct deletion is the one verdict that bypasses the owning *arr
        entirely - no blocklist, no replacement search, files removed. It may
        not be reached for a torrent Protectarr has durable OWNED evidence
        about, whatever the mode and whatever the allowlist says.
        """
        for mode, row in self.rows_for("owned").items():
            self.assertNotIn("qbit_delete", row,
                             f"mode {mode} deleted a torrent with a stored owner")

    def test_a_dwelled_orphan_is_still_reapable_where_the_mode_allows_it(self):
        """The other half, so the fix cannot be "protect everything".

        ORPHANED was earned by reading the owner's queue and watching the
        torrent leave it while it was still downloading. That is a positive
        observation, the dwell ages it, and catching those is the whole reason
        `either` exists.
        """
        for mode in ("allowlist", "either"):
            self.assertIn("qbit_delete", EXPECTED[(mode, "orphan_dwelled")],
                          f"mode {mode} stopped reaping dwelled orphans")

    def test_an_unknown_mode_refuses_rather_than_defaulting(self):
        """A typo in `safety.mode` must do nothing, not fall back to a mode
        that deletes things."""
        for (mode, own), row in EXPECTED.items():
            if mode == "bogus":
                self.assertEqual(row, [None] * 8,
                                 f"an unknown mode acted on {own}")

    def test_direct_deletion_requires_known_ownership(self):
        """The one verdict that bypasses an *arr is also the one that must
        never fire while a queue is unreadable."""
        for (mode, own), row in EXPECTED.items():
            for (hit, allowed, known), verdict in zip(COLUMNS, row):
                if verdict == "qbit_delete":
                    self.assertTrue(known, f"{mode}/{own} deleted blind")
                    self.assertFalse(hit, f"{mode}/{own} bypassed its *arr")
                    self.assertTrue(allowed, f"{mode}/{own} deleted unlisted")

    def test_an_arr_that_owns_it_is_never_deleted_directly(self):
        for (mode, own), row in EXPECTED.items():
            for (hit, _, _), verdict in zip(COLUMNS, row):
                if hit:
                    self.assertNotEqual(verdict, "qbit_delete",
                                        f"{mode}/{own} deleted a tracked item")


class TestTheParametersEvaluateActuallyReads(unittest.TestCase):
    """Pins which inputs matter, so the refactor keeps the same signature
    honest rather than quietly starting or stopping reading one."""

    def base(self, **over):
        kw = {"torrent": {"category": "tv", "tags": ""}, "bad_name": "",
              "arr_hit": None,
              "safety": dict(SAFETY, mode="allowlist"),
              "ownership_known": True, "own": None, "cleared": True}
        kw.update(over)
        # Cleared by default: these pin which *parameters* are read, and a
        # refusal to delete without synchronising would mask all of them.
        return core.evaluate(kw["torrent"], kw["bad_name"], kw["arr_hit"],
                             kw["safety"], kw["ownership_known"], own=kw["own"],
                             fallback_cleared=kw["cleared"])

    def test_bad_name_is_not_read(self):
        """It has been a dead parameter since ownership landed; `core` itself
        passes "" at the probe-candidate call site. Pinned so the refactor
        neither starts depending on it nor drops it from the signature
        without someone deciding to."""
        self.assertEqual(self.base(bad_name=""), "qbit_delete")
        self.assertEqual(self.base(bad_name="anything.exe"), "qbit_delete")
        self.assertEqual(self.base(bad_name=None), "qbit_delete")

    def test_tags_can_allowlist_as_well_as_categories(self):
        safety = {"mode": "allowlist", "allowed_categories": [],
                  "allowed_tags": ["keep"], "orphan_dwell_minutes": 10}
        self.assertEqual(
            self.base(torrent={"category": "other", "tags": "keep,other"},
                      safety=safety), "qbit_delete")

    def test_a_blank_allowlist_entry_matches_nothing(self):
        """A stray empty line must not allowlist every uncategorised torrent,
        which is precisely the hand-added download the mode protects."""
        safety = {"mode": "allowlist", "allowed_categories": ["", "  "],
                  "allowed_tags": [""], "orphan_dwell_minutes": 10}
        self.assertIsNone(
            self.base(torrent={"category": "", "tags": ""}, safety=safety))

    def test_the_dwell_is_read_from_safety_not_hardcoded(self):
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  5 * 60, "absent 5m")
        safety = dict(SAFETY, mode="allowlist", orphan_dwell_minutes=10)
        self.assertIsNone(self.base(own=own, safety=safety))
        safety = dict(SAFETY, mode="allowlist", orphan_dwell_minutes=1)
        self.assertEqual(self.base(own=own, safety=safety), "qbit_delete")

    def test_a_missing_mode_defaults_to_the_safest_one(self):
        safety = {"allowed_categories": ["tv"], "allowed_tags": []}
        self.assertIsNone(self.base(safety=safety))
        self.assertEqual(self.base(arr_hit=TRACKED, safety=safety), "arr_fail")

    def test_a_missing_dwell_still_makes_a_fresh_orphan_wait(self):
        """The in-code fallback, not the one config.py fills in.

        Every other test here passes `orphan_dwell_minutes` explicitly, so the
        literal in `evaluate` was unpinned: a mutation changing it from 10 to 0
        survived the whole suite. Zero would mean a torrent that left its
        *arr's queue one second ago is immediately deletable, which is the
        brief absence the dwell exists to absorb.
        """
        own = ownership.Ownership(ownership.ORPHANED, "Sonarr", None, None,
                                  60, "absent 1m")
        safety = {"mode": "allowlist", "allowed_categories": ["tv"],
                  "allowed_tags": []}
        self.assertIsNone(self.base(own=own, safety=safety))

    def test_the_three_copies_of_the_dwell_default_agree(self):
        """`core`, `config` and the Current Policy box each carry the literal
        10. They are three copies of one promise, and a config written before
        the key existed reads all three."""
        from protectarr import config as cfg_mod
        from protectarr import web

        self.assertEqual(
            cfg_mod.DEFAULTS["safety"]["orphan_dwell_minutes"], 10)
        # What the settings page would tell the operator is in force when the
        # key is absent, which must be what `evaluate` actually applies.
        rows = dict((label, value) for label, value, _ in
                    web._current_policy({"safety": {"mode": "allowlist"},
                                         "detection": {}, "arrs": []}))
        self.assertIn("10 minutes", rows["Orphan handling"])


if __name__ == "__main__":
    unittest.main()
