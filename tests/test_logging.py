"""Logging tests.

The one that matters most is redaction. These logs exist partly so people can
attach them to GitHub issues, so a leaked API key here is a leaked API key in
public. Everything else is rotation, compression and retention behaving.

Run with:  python -m unittest discover -s tests
"""

import os
import sys
import gzip
import time
import shutil
import logging
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protectarr import config as cfg_mod  # noqa: E402
from protectarr import logs  # noqa: E402

# Shaped like a real Protectarr key (64 hex chars) so redaction is tested against
# something realistic. Never put an actual key here: this repo is public, and the
# tests would then leak exactly what they exist to prove never leaks.
REAL_KEY = "0123456789abcdef" * 4


class LogTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfg_mod.CONFIG_PATH = os.path.join(self.dir, "config.yaml")
        self.cfg = {
            "logging": {"level": "debug", "console_level": "error",
                        "file_enabled": True, "path": os.path.join(self.dir, "logs"),
                        "retention_days": 3},
            "web": {"api_key": REAL_KEY, "secret_key": "s" * 40},
            "qbittorrent": {"password": "hunter2hunter2", "api_key": "qbt_abcdefgh12345678"},
            "arrs": [{"name": "Sonarr", "api_key": "a" * 32}],
        }
        logs._ring.clear()
        logs.configure(self.cfg)
        self.log = logs.get("test")

    def tearDown(self):
        for h in list(logging.getLogger(logs.LOGGER_NAME).handlers):
            logging.getLogger(logs.LOGGER_NAME).removeHandler(h)
            h.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def file_text(self):
        p = os.path.join(self.cfg["logging"]["path"], "protectarr.log")
        with open(p) as fh:
            return fh.read()


class TestRedaction(LogTestCase):
    def test_config_api_key_never_reaches_any_sink(self):
        self.log.info("calling http://host/api/v1/stats?apikey=%s", REAL_KEY)
        text, ring = self.file_text(), "\n".join(logs.ring())
        for where, blob in (("file", text), ("ring", ring)):
            with self.subTest(sink=where):
                self.assertNotIn(REAL_KEY, blob)
                self.assertIn(logs.MASK, blob)

    def test_qbittorrent_password_is_redacted(self):
        self.log.info("login as admin password=hunter2hunter2")
        self.assertNotIn("hunter2hunter2", self.file_text())

    def test_arr_key_is_redacted(self):
        self.log.warning("Sonarr rejected key %s", "a" * 32)
        self.assertNotIn("a" * 32, self.file_text())

    def test_unknown_key_still_caught_by_shape(self):
        # A key we were never told about, in a URL.
        self.log.info("GET http://host/api?apikey=zzzTOTALLYSECRETzzz&x=1")
        text = self.file_text()
        self.assertNotIn("zzzTOTALLYSECRETzzz", text)
        self.assertIn("x=1", text, "redaction must not eat the rest of the line")

    def test_qbt_token_shape(self):
        self.log.info("using qbt_ABCdef1234567890 for auth")
        self.assertNotIn("qbt_ABCdef1234567890", self.file_text())

    def test_bearer_header_shape(self):
        self.log.info("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdef")
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9abcdef", self.file_text())

    def test_exception_text_is_redacted_too(self):
        try:
            raise ValueError(f"connection to http://h/api?apikey={REAL_KEY} failed")
        except ValueError:
            self.log.exception("request blew up")
        self.assertNotIn(REAL_KEY, self.file_text())

    def test_short_values_are_not_treated_as_secrets(self):
        # A 3-char password would otherwise shred unrelated text.
        cfg = dict(self.cfg)
        cfg["qbittorrent"] = {"password": "abc"}
        r = logs.Redactor()
        r.update(cfg)
        self.assertEqual(r.scrub("abc is a normal word"), "abc is a normal word")

    def test_ordinary_lines_pass_through_intact(self):
        self.log.info("Reaped via Sonarr: 'Ted Lasso S04E07' | blocklisted=yes")
        self.assertIn("Reaped via Sonarr: 'Ted Lasso S04E07' | blocklisted=yes",
                      self.file_text())


class TestLevels(LogTestCase):
    def test_debug_reaches_the_file_when_level_is_debug(self):
        self.log.debug("a debug line")
        self.assertIn("a debug line", self.file_text())

    def test_debug_suppressed_at_info(self):
        self.cfg["logging"]["level"] = "info"
        logs.configure(self.cfg)
        logs.get("test").debug("should not appear")
        logs.get("test").info("should appear")
        text = self.file_text()
        self.assertNotIn("should not appear", text)
        self.assertIn("should appear", text)

    def test_console_and_file_thresholds_are_independent(self):
        handlers = logging.getLogger(logs.LOGGER_NAME).handlers
        console = [h for h in handlers if type(h) is logging.StreamHandler]
        files = [h for h in handlers
                 if isinstance(h, logs.CompressingTimedRotatingFileHandler)]
        self.assertEqual(console[0].level, logging.ERROR)
        self.assertEqual(files[0].level, logging.DEBUG)

    def test_all_levels_are_recorded(self):
        for lvl in ("debug", "info", "warning", "error"):
            getattr(self.log, lvl)("marker-%s" % lvl)
        text = self.file_text()
        for lvl in ("DEBUG", "INFO", "WARNING", "ERROR"):
            self.assertIn(lvl, text)


class TestRotation(LogTestCase):
    def rotate_now(self):
        h = [x for x in logging.getLogger(logs.LOGGER_NAME).handlers
             if isinstance(x, logs.CompressingTimedRotatingFileHandler)][0]
        h.rolloverAt = time.time() - 1     # pretend midnight passed
        self.log.info("triggering rollover")
        return h

    def test_rotated_file_is_gzipped_and_readable(self):
        self.log.info("yesterday's line")
        self.rotate_now()
        d = self.cfg["logging"]["path"]
        gzs = [f for f in os.listdir(d) if f.endswith(".gz")]
        self.assertEqual(len(gzs), 1, os.listdir(d))
        with gzip.open(os.path.join(d, gzs[0]), "rt") as fh:
            self.assertIn("yesterday's line", fh.read())

    def test_rotated_name_carries_the_date(self):
        self.rotate_now()
        d = self.cfg["logging"]["path"]
        name = [f for f in os.listdir(d) if f.endswith(".gz")][0]
        # protectarr.log.YYYY-MM-DD.gz
        stamp = name[len("protectarr.log."):-len(".gz")]
        time.strptime(stamp, "%Y-%m-%d")

    def test_the_live_file_is_not_compressed(self):
        self.rotate_now()
        self.log.info("today's line")
        self.assertIn("today's line", self.file_text())

    def test_retention_deletes_beyond_the_limit(self):
        """backupCount stops working when a .gz suffix is appended, which is why
        getFilesToDelete is overridden. This is that regression."""
        d = self.cfg["logging"]["path"]
        h = [x for x in logging.getLogger(logs.LOGGER_NAME).handlers
             if isinstance(x, logs.CompressingTimedRotatingFileHandler)][0]
        for day in range(1, 7):
            open(os.path.join(d, f"protectarr.log.2026-09-0{day}.gz"), "w").close()
        doomed = h.getFilesToDelete()
        self.assertTrue(doomed, "retention found nothing to delete")
        # 6 old + retention 3 -> delete the 3 oldest
        self.assertEqual(len(doomed), 3)
        self.assertTrue(all("2026-09-0" in f for f in doomed))
        self.assertIn("2026-09-01.gz", doomed[0])

    def test_retention_of_zero_keeps_everything(self):
        d = self.cfg["logging"]["path"]
        self.cfg["logging"]["retention_days"] = 0
        logs.configure(self.cfg)
        h = [x for x in logging.getLogger(logs.LOGGER_NAME).handlers
             if isinstance(x, logs.CompressingTimedRotatingFileHandler)][0]
        for day in range(1, 7):
            open(os.path.join(d, f"protectarr.log.2026-09-0{day}.gz"), "w").close()
        self.assertEqual(h.getFilesToDelete(), [])


class TestFileListingAndDownload(LogTestCase):
    def test_listing_is_newest_first_and_names_only(self):
        self.log.info("x")
        d = self.cfg["logging"]["path"]
        open(os.path.join(d, "protectarr.log.2026-09-01.gz"), "w").close()
        files = logs.list_files(self.cfg)
        self.assertTrue(files)
        for f in files:
            self.assertEqual(f["name"], os.path.basename(f["name"]))
        self.assertGreaterEqual(files[0]["modified"], files[-1]["modified"])

    def test_unrelated_files_are_not_listed(self):
        d = self.cfg["logging"]["path"]
        open(os.path.join(d, "secrets.txt"), "w").close()
        self.assertNotIn("secrets.txt", [f["name"] for f in logs.list_files(self.cfg)])

    def test_traversal_is_refused(self):
        self.log.info("x")
        for bad in ("../config.yaml", "/etc/passwd", "..",
                    "protectarr.log/../../config.yaml", "", None):
            with self.subTest(name=bad):
                self.assertIsNone(logs.resolve_file(self.cfg, bad))

    def test_a_real_file_resolves(self):
        self.log.info("x")
        p = logs.resolve_file(self.cfg, "protectarr.log")
        self.assertTrue(p and os.path.isfile(p))


class TestRing(LogTestCase):
    def test_ring_is_capped(self):
        for i in range(logs.RING_SIZE + 50):
            self.log.info("line %d", i)
        self.assertEqual(len(logs.ring()), logs.RING_SIZE)

    def test_ring_limit_returns_the_tail(self):
        for i in range(20):
            self.log.info("line %d", i)
        tail = logs.ring(5)
        self.assertEqual(len(tail), 5)
        self.assertIn("line 19", tail[-1])

    def test_file_failure_does_not_crash_configure(self):
        cfg = dict(self.cfg)
        cfg["logging"] = dict(self.cfg["logging"], path="/proc/cannot/write/here")
        logs.configure(cfg)          # must not raise
        logs.get("test").info("still logging")
        self.assertTrue(any("still logging" in l for l in logs.ring()))


if __name__ == "__main__":
    unittest.main()


class TestTimezone(LogTestCase):
    """A container defaults to UTC while its owner reads local time, and nothing
    in a bare timestamp says which is which. These pin both halves of the fix."""

    def test_every_timestamp_carries_its_offset(self):
        self.log.info("a line")
        text = self.file_text()
        self.assertRegex(text, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}")

    def test_ring_lines_carry_the_offset_too(self):
        self.log.info("a line")
        self.assertRegex(logs.ring()[-1],
                         r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}")

    def test_now_matches_the_log_format(self):
        self.assertRegex(logs.now(),
                         r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$")

    def test_setting_a_zone_changes_the_offset(self):
        import time as _t
        logs.apply_timezone({"timezone": "Etc/UTC"})
        utc = _t.strftime("%z")
        logs.apply_timezone({"timezone": "Asia/Tokyo"})
        tokyo = _t.strftime("%z")
        self.assertEqual(utc, "+0000")
        self.assertEqual(tokyo, "+0900")

    def test_events_and_harvest_share_the_format(self):
        import os as _os, tempfile as _tf
        from protectarr import config as _cfg, events
        d = _tf.mkdtemp()
        _cfg.CONFIG_PATH = _os.path.join(d, "config.yaml")
        ev = events.record({"dry_run": False, "torrent": {"name": "x"}})
        self.assertRegex(ev["timestamp"],
                         r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$")

    def test_unknown_zone_is_ignored_rather_than_fatal(self):
        before = logs.apply_timezone({"timezone": "Etc/UTC"})
        after = logs.apply_timezone({"timezone": "Mars/Olympus_Mons"})
        self.assertTrue(after)          # did not raise
        self.assertNotEqual(after, "Mars/Olympus_Mons")

    def test_blank_zone_leaves_the_env_alone(self):
        import os as _os
        _os.environ["TZ"] = "Asia/Tokyo"
        logs.apply_timezone({"timezone": ""})
        self.assertEqual(_os.environ.get("TZ"), "Asia/Tokyo")

    def test_zone_list_is_available_for_the_dropdown(self):
        zones = logs.available_timezones()
        self.assertIn("America/Los_Angeles", zones)
        self.assertIn("Etc/UTC", zones)
        self.assertEqual(zones, sorted(zones))
