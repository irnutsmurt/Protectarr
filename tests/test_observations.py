"""The sensor's own store: bounded, best-effort, and read by nothing.

`observations.jsonl` exists because the audit store was measured and could not
host it. What these tests hold is that it stays cheap and stays safe:

* a record's size does not depend on what an attacker names a file,
* nothing a filename contains can forge a second record,
* a write that fails costs the write and nothing else,
* only a terminal classification is ever written, so retries cannot fill it,
* `requested_span` and `bytes_examined` are not the same number.

Run with:  venv/bin/python -m unittest tests.test_observations -v
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402

cfg_mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), "config.yaml")

import protectarr  # noqa: E402
from protectarr import logs  # noqa: E402
from protectarr.probe import classify, engine, observations  # noqa: E402

logs.configure({"logging": {"level": "critical", "console_level": "critical",
                            "file_enabled": False}})

HASH = "a" * 40
SPACED = "South Park S29E01 1080p WEB-DL DDP5 1 x265 FLUX"

CONFIRMED = classify.Verdict(classify.EXECUTABLE_CONFIRMED, "windows_pe",
                             "a DOS header and a reachable PE signature",
                             False, None)
HINTED = classify.Verdict(classify.UNRECOGNIZED, None,
                          "an MZ with no PE signature", False, "dos_mz")
UNAVAILABLE = classify.Verdict(classify.UNAVAILABLE, None,
                               "read 100 of the 4096 opening bytes", True, None)


def build(name=SPACED, verdict=CONFIRMED, size=2 << 30, span=4096,
          examined=4096, **over):
    kw = dict(first_seen="2026-09-17T16:00:00-0700",
              resolved="2026-09-17T16:02:11-0700", attempts=1, piece_waits=0,
              steered=False, requested_span=span, bytes_examined=examined)
    kw.update(over)
    return observations.build(HASH, name, size, verdict, **kw)


class StoreCase(unittest.TestCase):
    """Each test gets its own store, so rotation is never shared."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")

    def lines(self, path=None):
        path = path or observations._path()
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [l for l in fh.read().split("\n") if l]


# ---------------------------------------------------------------------------
# Size, and what an attacker can do to it
# ---------------------------------------------------------------------------

class TestARecordHasABoundedSize(StoreCase):
    """A filename is chosen by whoever published the torrent, so the retention
    model is only worth anything if it cannot be stretched by one."""

    def size(self, name):
        return len(json.dumps(build(name), separators=(",", ":"))) + 1

    def test_an_ordinary_record_is_around_six_hundred_bytes(self):
        """Measured, and pinned because the retention table was computed from
        it. A field added later that pushes this up should have to move the
        number on purpose."""
        self.assertLess(self.size(SPACED), 650)

    def test_a_pathological_filename_does_not_inflate_the_record(self):
        for length in (500, 5_000, 100_000):
            with self.subTest(length=length):
                self.assertLess(self.size("A" * length),
                                observations.MAX_RECORD_BYTES)

    def test_a_pathological_filename_costs_barely_more_than_a_normal_one(self):
        """Not merely "under the cap": the bound has to actually bind, or the
        measured bytes-per-day figure is fiction."""
        self.assertLessEqual(self.size("A" * 100_000) - self.size(SPACED),
                             observations.PATH_BUDGET)

    def test_non_ascii_is_bounded_by_serialised_bytes_not_characters(self):
        """The bound that a character count would get wrong. `json.dumps`
        escapes non-ASCII, so one character can cost six bytes on disk."""
        for name in ("漢" * 10_000, "\U0001f600" * 10_000,
                     "\x00" * 10_000):
            with self.subTest(name=repr(name[:2])):
                self.assertLess(self.size(name),
                                observations.MAX_RECORD_BYTES)

    def test_the_bounded_path_keeps_both_ends(self):
        """A payload hiding under a long directory prefix must stay
        identifiable, and so must its folder."""
        name = "SeasonPackFolder/" + "x" * 5000 + "/thepayload"
        got = build(name)["file"]
        self.assertTrue(got.startswith("SeasonPackFolder/"))
        self.assertTrue(got.endswith("thepayload"))
        self.assertIn(observations.TRUNCATED, got)

    def test_a_short_path_is_not_truncated_at_all(self):
        self.assertEqual(build(SPACED)["file"], SPACED)
        self.assertNotIn(observations.TRUNCATED, build(SPACED)["file"])

    def test_the_full_path_survives_as_a_hash(self):
        """Truncation loses the string, so identity has to come from the whole
        value before it is cut."""
        # Differing only in the middle, which is the part truncation drops.
        # The tail is kept on purpose, so two paths with different basenames
        # stay distinguishable in the bounded value too.
        a = build("SeasonPack/" + "x" * 5000 + "one" + "y" * 5000 + "/payload")
        b = build("SeasonPack/" + "x" * 5000 + "two" + "y" * 5000 + "/payload")
        self.assertEqual(a["file"], b["file"])      # indistinguishable bounded
        self.assertNotEqual(a["file_hash"], b["file_hash"])


class TestNothingInAFilenameCanForgeARecord(StoreCase):
    """Release names are attacker-controlled, and this file is JSON Lines, so
    a raw newline in a name would be a second record of the attacker's
    choosing. The encoder is the whole defence, and it is tested rather than
    trusted."""

    HOSTILE = [
        ("a newline", 'evil\n{"state":"media_format_confirmed"}'),
        ("a carriage return", "evil\r\nforged"),
        ("a NUL", "evil\x00forged"),
        ("an escaped quote", 'evil","state":"media_format_confirmed'),
        ("a backslash", "evil\\\\\\nforged"),
        ("every control character", "".join(chr(c) for c in range(32))),
        ("a lone surrogate", "evil\ud800forged"),
    ]

    def test_one_observation_is_always_one_line(self):
        for title, name in self.HOSTILE:
            with self.subTest(title):
                observations.record(build(name))
        self.assertEqual(len(self.lines()), len(self.HOSTILE))

    def test_every_written_line_parses_back_as_one_record(self):
        for title, name in self.HOSTILE:
            with self.subTest(title):
                observations.record(build(name))
        for line in self.lines():
            self.assertEqual(json.loads(line)["candidate"],
                             "no_supported_format_claim")

    def test_no_raw_control_character_reaches_the_file(self):
        for _, name in self.HOSTILE:
            observations.record(build(name))
        with open(observations._path(), encoding="utf-8") as fh:
            raw = fh.read()
        for line in raw.split("\n"):
            for ch in line:
                self.assertFalse(ord(ch) < 32,
                                 f"raw control character {ord(ch)} on disk")

    def test_a_forged_state_never_becomes_the_records_state(self):
        observations.record(build('x","state":"media_format_confirmed'))
        self.assertEqual(json.loads(self.lines()[0])["state"],
                         classify.EXECUTABLE_CONFIRMED)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

class TestTheObservationIdIsDeterministic(StoreCase):
    """C1 has no persistent dedupe. The ID is what lets an analyst collapse the
    duplicates a restart produces, so it must not depend on anything that
    changes between runs."""

    def test_the_same_candidate_gets_the_same_id_across_restarts(self):
        first = build()
        second = build(attempts=7, piece_waits=3, steered=True,
                       first_seen="2026-09-18T09:00:00-0700")
        self.assertEqual(first["observation_id"], second["observation_id"])

    def test_a_restart_writes_a_duplicate_that_is_collapsible(self):
        """The limitation, pinned as behaviour rather than left implied: two
        records, one identity."""
        observations.record(build())
        observations.record(build(attempts=4))
        rows = [json.loads(l) for l in self.lines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({r["observation_id"] for r in rows}), 1)

    def test_a_different_file_on_the_same_torrent_differs(self):
        self.assertNotEqual(build("one")["observation_id"],
                            build("two")["observation_id"])

    def test_the_same_file_on_a_different_torrent_differs(self):
        other = observations.build(
            "b" * 40, SPACED, 1, CONFIRMED, first_seen="x", resolved="y",
            attempts=1, piece_waits=0, steered=False, requested_span=4096,
            bytes_examined=4096)
        self.assertNotEqual(build()["observation_id"], other["observation_id"])

    def test_the_id_is_taken_from_the_full_path_not_the_bounded_one(self):
        a = build("SeasonPack/" + "x" * 5000 + "one" + "y" * 5000 + "/payload")
        b = build("SeasonPack/" + "x" * 5000 + "two" + "y" * 5000 + "/payload")
        self.assertEqual(a["file"], b["file"])
        self.assertNotEqual(a["observation_id"], b["observation_id"])

    def test_the_id_cannot_be_forged_by_splitting_the_parts_differently(self):
        """NUL-joined, so a path that begins with the tail of a hash cannot
        collide with a different pairing."""
        self.assertNotEqual(observations.observation_id("ab", "c"),
                            observations.observation_id("a", "bc"))

    def test_records_are_attributable_to_a_build(self):
        rec = build()
        self.assertEqual(rec["protectarr_version"], protectarr.__version__)
        self.assertEqual(rec["classifier_version"], classify.VERSION)
        self.assertEqual(rec["schema_version"], observations.SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# What is measured, and what is merely asked for
# ---------------------------------------------------------------------------

class TestTheSpanAskedForIsNotTheBytesRead(StoreCase):
    """Reporting the requested span as though it were read would claim a
    measurement nobody took, which is the one thing this codebase keeps
    getting told not to do."""

    def test_a_complete_tiny_file_reports_what_was_actually_there(self):
        rec = build(size=20, span=4096, examined=20)
        self.assertEqual(rec["requested_span"], 4096)
        self.assertEqual(rec["bytes_examined"], 20)

    def test_a_full_read_reports_both_the_same(self):
        rec = build(size=2 << 30, span=4096, examined=4096)
        self.assertEqual(rec["requested_span"], rec["bytes_examined"])

    def test_zero_bytes_examined_is_recorded_rather_than_omitted(self):
        """0 is a measurement. Dropping it with the other empty fields would
        make "read nothing" indistinguishable from "did not record it"."""
        rec = build(examined=0)
        self.assertIn("bytes_examined", rec)
        self.assertEqual(rec["bytes_examined"], 0)

    def test_null_fields_are_omitted_but_false_and_zero_are_kept(self):
        rec = build(verdict=HINTED, attempts=0, piece_waits=0, steered=False)
        self.assertNotIn("format", rec)             # nothing was confirmed
        self.assertEqual(rec["hint"], "dos_mz")
        self.assertIs(rec["steered"], False)
        self.assertEqual(rec["piece_waits"], 0)


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

class TestRotationIsBounded(StoreCase):
    def test_the_store_never_exceeds_its_budget(self):
        big = "B" * 400
        for _ in range(4000):
            observations.record(build(big))
        total = sum(os.path.getsize(p) for p in observations._files()
                    if os.path.exists(p))
        self.assertLessEqual(total, observations.KEEP_FILES
                             * observations.MAX_BYTES + 2048)

    def test_it_keeps_exactly_the_configured_number_of_files(self):
        observations.MAX_BYTES, real = 4096, observations.MAX_BYTES
        try:
            for _ in range(400):
                observations.record(build())
            present = [p for p in observations._files() if os.path.exists(p)]
            self.assertEqual(len(present), observations.KEEP_FILES)
            self.assertFalse(os.path.exists(
                f"{observations._path()}.{observations.KEEP_FILES}"))
        finally:
            observations.MAX_BYTES = real

    def test_the_newest_records_are_the_ones_kept(self):
        observations.MAX_BYTES, real = 4096, observations.MAX_BYTES
        try:
            for i in range(400):
                observations.record(build(f"file{i:04d}"))
            last = json.loads(self.lines()[-1])
            self.assertEqual(last["file"], "file0399")
        finally:
            observations.MAX_BYTES = real

    def test_the_budget_is_the_one_that_was_measured(self):
        """Named so that changing it has to be deliberate: the retention table
        in the design report was computed from these two numbers."""
        self.assertEqual(observations.MAX_BYTES, 2 * 1024 * 1024)
        self.assertEqual(observations.KEEP_FILES, 4)


# ---------------------------------------------------------------------------
# Failing safe
# ---------------------------------------------------------------------------

class TestAFailedWriteCostsOnlyTheWrite(StoreCase):
    """This is a diagnostic file on a lane that deletes torrents and has
    qBittorrent settings to put back. Nothing here may raise."""

    def test_an_unwritable_directory_is_swallowed(self):
        cfg_mod.CONFIG_PATH = "/proc/nonexistent/config.yaml"
        self.assertFalse(observations.record(build()))

    def test_a_disk_failure_mid_write_is_swallowed(self):
        def boom(*a, **k):
            raise OSError(28, "No space left on device")

        real = observations.open if hasattr(observations, "open") else None
        import builtins
        original = builtins.open
        builtins.open = boom
        try:
            self.assertFalse(observations.record(build()))
        finally:
            builtins.open = original
            if real is None and hasattr(observations, "open"):
                del observations.open

    def test_an_unserialisable_record_is_dropped_not_raised(self):
        self.assertFalse(observations.record({"bad": object()}))

    def test_a_record_over_the_cap_is_dropped_rather_than_written(self):
        oversized = dict(build(), padding="Z" * observations.MAX_RECORD_BYTES)
        self.assertFalse(observations.record(oversized))
        self.assertEqual(self.lines(), [])

    def test_a_rotation_failure_does_not_lose_the_write(self):
        """Rotation is best-effort too; a store that cannot rotate should keep
        appending rather than start throwing."""
        observations.record(build())
        real = os.replace
        os.replace = lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
        try:
            observations.MAX_BYTES, keep = 1, observations.MAX_BYTES
            self.assertTrue(observations.record(build()))
        finally:
            os.replace = real
            observations.MAX_BYTES = keep
        self.assertEqual(len(self.lines()), 2)


# ---------------------------------------------------------------------------
# Lifecycle, through the engine
# ---------------------------------------------------------------------------

class FakeQb:
    def __init__(self, files, piece_states, torrent=None):
        self.files_list = files
        self.states = list(piece_states)
        self.info = torrent or {}
        self.calls = []

    def properties(self, h):
        return {"piece_size": 1024}

    def piece_states(self, h):
        return list(self.states)

    def files(self, h):
        return self.files_list

    def torrent(self, h):
        return self.info

    def set_file_priority(self, h, ids, priority):
        self.calls.append(("prio", sorted(ids), priority))

    def set_sequential(self, h, on):
        self.calls.append(("seq", bool(on)))

    def set_first_last_prio(self, h, on):
        self.calls.append(("flp", bool(on)))


def cfg(**over):
    p = dict(engine.DEFAULTS, enabled=True)
    p.update(over)
    return {"detection": {"probe": p}, "dry_run": False,
            "safety": {"mode": "arr_tracked"}, "arrs": []}


PE = (b"MZ" + b"\x90" * 0x3a + (0x80).to_bytes(4, "little")
      + b"\x00" * (0x80 - 0x40) + b"PE\x00\x00" + b"\x4c\x01" + b"\x03\x00"
      + b"\x00" * 12 + b"\xe0\x00" + b"\x02\x01" + b"\x0b\x01" + b"\x00" * 60)
TINY = b"tracker=udp://example.invalid:6969\n"


class TestOnlyATerminalClassificationIsWritten(StoreCase):
    """The anti-firehose rule, end to end. `probe_data_unavailable` is the one
    state that repeats, so it is the one state never recorded."""

    def setUp(self):
        super().setUp()
        from protectarr.probe import ledger
        ledger._broken = None
        self.torrent = {"hash": HASH, "name": "release", "state": "downloading",
                        "progress": 0.02, "dlspeed": 5 << 20, "num_seeds": 12,
                        "seq_dl": False, "f_l_piece_prio": False}

    def single(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return (dict(self.torrent, content_path=path),
                [{"name": name, "priority": 1, "size": len(data),
                  "piece_range": [0, 0]}])

    def test_a_confirmed_executable_writes_exactly_one_record(self):
        torrent, files = self.single(SPACED, PE)
        qb = FakeQb(files, [2] * 4, torrent)
        engine.inspect(qb, torrent, files, cfg(), {})
        rows = [json.loads(l) for l in self.lines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], classify.EXECUTABLE_CONFIRMED)
        self.assertEqual(rows[0]["format"], "windows_pe")
        self.assertEqual(rows[0]["file"], SPACED)
        self.assertEqual(rows[0]["infohash"], HASH)

    def test_a_complete_tiny_file_records_what_was_read_not_what_was_asked(self):
        torrent, files = self.single("info", TINY)
        qb = FakeQb(files, [2] * 4, torrent)
        engine.inspect(qb, torrent, files, cfg(), {})
        row = json.loads(self.lines()[0])
        self.assertEqual(row["state"], classify.UNRECOGNIZED)
        self.assertEqual(row["requested_span"], classify.CLASSIFY_BYTES)
        self.assertEqual(row["bytes_examined"], len(TINY))

    def test_an_unavailable_candidate_writes_nothing_however_often_it_runs(self):
        files = [{"name": SPACED, "priority": 1, "size": 2 << 30,
                  "piece_range": [0, 900]}]
        qb = FakeQb(files, [0] * 901, self.torrent)
        state = {}
        for _ in range(5):
            engine.inspect(qb, self.torrent, files, cfg(steer=False), state)
        self.assertEqual(self.lines(), [])

    def test_a_resolved_candidate_is_not_rewritten_on_the_next_scan(self):
        """The memo already stops the re-read; this pins that it also stops the
        re-write, so a long-lived torrent cannot accumulate records."""
        torrent, files = self.single(SPACED, PE)
        qb = FakeQb(files, [2] * 4, torrent)
        state = {}
        for _ in range(5):
            engine.inspect(qb, torrent, files, cfg(), state)
        self.assertEqual(len(self.lines()), 1)

    def test_a_typed_file_writes_no_observation_at_all(self):
        """C1 telemetry is the untyped lane's. The validator lane is unchanged
        and silent."""
        torrent, files = self.single("ep1.mkv", PE)
        qb = FakeQb(files, [2] * 4, torrent)
        engine.inspect(qb, torrent, files, cfg(), {})
        self.assertEqual(self.lines(), [])

    def test_the_record_carries_the_accumulated_counters(self):
        torrent, files = self.single(SPACED, PE)
        qb = FakeQb(files, [2] * 4, torrent)
        engine.inspect(qb, torrent, files, cfg(), {})
        row = json.loads(self.lines()[0])
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(row["piece_waits"], 0)
        self.assertIs(row["steered"], False)
        self.assertIn("first_seen", row)
        self.assertIn("resolved", row)

    def test_a_failing_store_does_not_stop_the_probe_resolving(self):
        """The fail-safe rule where it matters: the scan finishes and the
        candidate still resolves, with nothing on disk."""
        torrent, files = self.single(SPACED, PE)
        qb = FakeQb(files, [2] * 4, torrent)
        state = {}
        real = observations.record
        observations.record = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("store is broken"))
        try:
            res = engine.inspect(qb, torrent, files, cfg(), state)
        finally:
            observations.record = real
        self.assertEqual(res.findings, ())
        self.assertTrue(state["probe_memo"][HASH]["resolved"].get(SPACED))
        self.assertEqual(self.lines(), [])


class Clock:
    """A `logs.now` that returns a new, ordered timestamp on every call.

    Real timestamps have one-second resolution, so two passes inside one test
    produce identical strings and a counter that resets looks exactly like one
    that accumulated. This makes the difference visible.
    """

    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return "2026-09-17T16:%02d:00-0700" % self.n


class TestTheWriteDecisionReachesTheRetryablePath(StoreCase):
    """The tests above never exercised the decision itself.

    An undownloaded candidate never reaches `_classified` at all - it is put
    aside in the free pass - so "unavailable writes nothing" was passing
    without the branch that enforces it ever running. A mutation run found
    that. These cases drive a *readable* candidate to a retryable verdict, so
    the branch is actually taken.
    """

    def setUp(self):
        super().setUp()
        from protectarr.probe import ledger
        ledger._broken = None
        self.torrent = {"hash": HASH, "name": "release", "state": "downloading",
                        "progress": 0.02, "dlspeed": 5 << 20, "num_seeds": 12,
                        "seq_dl": False, "f_l_piece_prio": False}

    def files(self, name, size):
        return [{"name": name, "priority": 1, "size": size,
                 "piece_range": [0, 0]}]

    def test_a_verified_piece_whose_file_is_not_readable_writes_nothing(self):
        """Pieces say the bytes are there; the filesystem disagrees. That is
        `probe_data_unavailable`, it reaches the write decision, and it is
        still not written."""
        torrent = dict(self.torrent,
                       content_path=os.path.join(self.dir, "absent"))
        files = self.files("absent", 4096)
        qb = FakeQb(files, [2] * 4, torrent)
        state = {}
        engine.inspect(qb, torrent, files, cfg(steer=False), state)
        self.assertEqual(self.lines(), [])
        # It reached the classifier, rather than being set aside beforehand.
        self.assertEqual(state["probe_memo"][HASH]["seen"]["absent"]["attempts"],
                         1)

    def test_a_short_read_of_a_big_file_writes_nothing(self):
        """The other retryable shape: the file is readable but holds fewer
        bytes than a file that size should have here yet."""
        path = os.path.join(self.dir, "partial")
        with open(path, "wb") as fh:
            fh.write(PE[:100])
        torrent = dict(self.torrent, content_path=path)
        files = self.files("partial", 2 << 30)
        qb = FakeQb(files, [2] * 4, torrent)
        state = {}
        engine.inspect(qb, torrent, files, cfg(steer=False), state)
        self.assertEqual(self.lines(), [])
        self.assertFalse(state["probe_memo"][HASH]["resolved"].get("partial"))

    def test_counters_accumulate_across_passes_rather_than_resetting(self):
        """`first_seen` means the first time this process looked, so a second
        pass must not restart it - nor the attempt count it sits beside."""
        path = os.path.join(self.dir, "late")
        torrent = dict(self.torrent, content_path=path)
        files = self.files("late", len(PE))
        qb = FakeQb(files, [2] * 4, torrent)
        state = {}

        clock = Clock()
        real = engine.logs.now
        engine.logs.now = clock
        try:
            # Pass one: nothing on disk yet, so unavailable and unwritten.
            engine.inspect(qb, torrent, files, cfg(steer=False), state)
            first = state["probe_memo"][HASH]["seen"]["late"]["first"]
            self.assertEqual(self.lines(), [])
            # Pass two: the bytes turn up.
            with open(path, "wb") as fh:
                fh.write(PE)
            engine.inspect(qb, torrent, files, cfg(steer=False), state)
        finally:
            engine.logs.now = real

        row = json.loads(self.lines()[0])
        self.assertEqual(row["attempts"], 2)
        self.assertEqual(row["first_seen"], first)
        self.assertLess(row["first_seen"], row["resolved"])


class FlippingQb(FakeQb):
    """Piece states that go from missing to verified after the first poll.

    What a steer looks like when it works. The free pass finds nothing, the
    wait is entered, and the piece arrives.
    """

    def __init__(self, files, torrent, flip_after=1):
        super().__init__(files, [0] * 4, torrent)
        self.polls = 0
        self.flip_after = flip_after

    def piece_states(self, h):
        self.polls += 1
        return [2] * 4 if self.polls > self.flip_after else [0] * 4


class TestASuccessfulSteerIsRecorded(StoreCase):
    """A steer that pays off has to show up in the record, or the store cannot
    answer what the answer cost."""

    def setUp(self):
        super().setUp()
        from protectarr.probe import ledger
        ledger._broken = None
        self.path = os.path.join(self.dir, SPACED)
        with open(self.path, "wb") as fh:
            fh.write(PE)
        self.torrent = {"hash": HASH, "name": "release",
                        "content_path": self.path, "state": "downloading",
                        "progress": 0.02, "dlspeed": 5 << 20, "num_seeds": 12,
                        "seq_dl": False, "f_l_piece_prio": False}
        self.files = [{"name": SPACED, "priority": 1, "size": len(PE),
                       "piece_range": [0, 0]}]

    def test_the_record_says_it_was_steered_and_how_many_waits_it_took(self):
        qb = FlippingQb(self.files, self.torrent)
        res = engine.inspect(qb, self.torrent, self.files,
                             cfg(poll_seconds=1), {})
        self.assertTrue(res.steered)
        row = json.loads(self.lines()[0])
        self.assertIs(row["steered"], True)
        self.assertEqual(row["piece_waits"], 1)
        self.assertEqual(row["state"], classify.EXECUTABLE_CONFIRMED)

    def test_a_free_pass_verdict_records_neither(self):
        """The contrast that makes the previous test mean something."""
        qb = FakeQb(self.files, [2] * 4, self.torrent)
        engine.inspect(qb, self.torrent, self.files, cfg(), {})
        row = json.loads(self.lines()[0])
        self.assertIs(row["steered"], False)
        self.assertEqual(row["piece_waits"], 0)

    def test_steering_is_counted_even_when_the_piece_never_arrives(self):
        """A wait that times out still spent the budget. Counting only
        successful waits would understate what a verdict cost, and this is the
        candidate an operator is most likely to be asking about."""
        qb = FlippingQb(self.files, self.torrent, flip_after=99)
        engine.inspect(qb, self.torrent, self.files,
                       cfg(poll_seconds=1, no_progress_seconds=2), {})
        track = {}
        # Nothing terminal happened, so nothing is written - but the counters
        # are there for whenever it does resolve.
        self.assertEqual(self.lines(), [])


class TestOnlyTheUntypedLaneIsObserved(StoreCase):
    """The gate is `kind`, and it is the only thing keeping the validator lane
    out of a store built for the sensor."""

    def setUp(self):
        super().setUp()
        from protectarr.probe import ledger
        ledger._broken = None

    def single(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return ({"hash": HASH, "name": name, "content_path": path,
                 "state": "downloading", "progress": 0.02, "dlspeed": 5 << 20,
                 "num_seeds": 12, "seq_dl": False, "f_l_piece_prio": False},
                [{"name": name, "priority": 1, "size": len(data),
                  "piece_range": [0, 0]}])

    def test_a_typed_file_is_judged_by_the_validator_and_not_observed(self):
        torrent, files = self.single("ep1.mkv", PE)
        qb = FakeQb(files, [2] * 4, torrent)
        res = engine.inspect(qb, torrent, files, cfg(), {})
        # The typed lane still reaches its own verdict...
        self.assertEqual([f["reason"] for f in res.findings],
                         ["content_type_mismatch"])
        # ...and writes nothing here.
        self.assertEqual(self.lines(), [])

    def test_an_untyped_file_with_the_same_bytes_is_observed_and_finds_nothing(self):
        torrent, files = self.single(SPACED, PE)
        qb = FakeQb(files, [2] * 4, torrent)
        res = engine.inspect(qb, torrent, files, cfg(), {})
        self.assertEqual(res.findings, ())
        self.assertEqual(len(self.lines()), 1)

    def test_a_mixed_torrent_observes_only_the_untyped_half(self):
        content = os.path.join(self.dir, "mixed")
        os.makedirs(content, exist_ok=True)
        for name, data in (("ep1.mkv", PE), (SPACED, PE), ("info", TINY)):
            with open(os.path.join(content, name), "wb") as fh:
                fh.write(data)
        torrent = {"hash": HASH, "name": "mixed", "content_path": content,
                   "state": "downloading", "progress": 0.02,
                   "dlspeed": 5 << 20, "num_seeds": 12}
        files = [{"name": "ep1.mkv", "priority": 1, "size": len(PE),
                  "piece_range": [0, 0]},
                 {"name": SPACED, "priority": 1, "size": len(PE),
                  "piece_range": [0, 0]},
                 {"name": "info", "priority": 1, "size": len(TINY),
                  "piece_range": [0, 0]}]
        qb = FakeQb(files, [2] * 4, torrent)
        engine.inspect(qb, torrent, files, cfg(), {})
        observed = {json.loads(l)["file"] for l in self.lines()}
        self.assertEqual(observed, {SPACED, "info"})


class TestNothingReadsTheStore(unittest.TestCase):
    """C1 requirement, pinned so that wiring it into a page has to be
    deliberate."""

    def test_no_module_outside_the_probe_lane_imports_observations(self):
        root = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "protectarr")
        offenders = []
        for dirpath, _, names in os.walk(root):
            for n in names:
                if not n.endswith(".py"):
                    continue
                path = os.path.join(dirpath, n)
                if os.path.basename(dirpath) == "probe":
                    continue
                # Import statements only. The word itself is unrelated prose
                # in several modules, and `evidence.observations` is the swarm
                # peer table, which predates this file and is not it.
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                if ("from .probe import observations" in text
                        or "from ..probe import observations" in text
                        or "probe.observations" in text):
                    offenders.append(os.path.relpath(path, root))
        self.assertEqual(offenders, [])

    def test_the_store_has_no_reader(self):
        """There is deliberately no `read`, `iter_observations` or equivalent.
        The file is for `jq` while C1 is evaluated, and giving it a reader is
        the first step toward giving it a page."""
        for name in ("read", "iter_events", "iter_observations", "normalize"):
            self.assertFalse(hasattr(observations, name), name)


if __name__ == "__main__":
    unittest.main()
