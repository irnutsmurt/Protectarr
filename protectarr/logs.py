"""Application logging: levels, daily rotation with compression, retention,
an in-memory ring for the WebUI, and redaction of anything secret.

Everything goes through the stdlib `logging` module under the `protectarr`
logger, so any module can log without being handed a state dict. Three sinks:

    console   stdout, which is what `docker logs` shows
    file      <log dir>/protectarr.log, rotated at midnight and gzipped
    ring      last N records in memory, for the System page and /api/v1/log

Redaction is not optional. These logs are meant to be attachable to a GitHub
issue, and verbose logging plus `?apikey=` in a URL plus a `requests` exception
that quotes that URL is exactly how someone pastes their Sonarr key in public.
Every record passes through `Redactor` before it reaches any sink.
"""

import os
import re
import time
import gzip
import shutil
import logging
import datetime
import logging.handlers
from collections import deque

LOGGER_NAME = "protectarr"

# Every timestamp Protectarr writes carries its UTC offset. Without it a log is
# ambiguous the moment it leaves the machine that produced it: a container
# defaults to UTC while its owner reads it in local time, and nothing in the
# file says which is which.
TS_FORMAT = "%Y-%m-%d %H:%M:%S %z"


def now():
    """Current local time as a string, offset included."""
    return time.strftime(TS_FORMAT)


def stamp(epoch):
    """An epoch as a display string in the same format, or None.

    None in, None out. A record whose timestamp was never captured has to stay
    visibly absent rather than being rendered as the epoch or as "now".
    """
    if epoch is None:
        return None
    try:
        return time.strftime(TS_FORMAT, time.localtime(float(epoch)))
    except (TypeError, ValueError, OSError):
        return None


def parse_stamp(text):
    """A timestamp written by `now()` back into an epoch, or None."""
    if not text:
        return None
    try:
        return datetime.datetime.strptime(text, TS_FORMAT).timestamp()
    except (TypeError, ValueError):
        return None


def apply_timezone(cfg):
    """Point the process at the configured timezone.

    Everything here uses `time.localtime` under the hood, so setting TZ once
    covers log lines, event history, the harvest ledger and stats together.
    A blank setting leaves the TZ environment variable alone, which is what
    `TZ=America/Los_Angeles` in docker-compose sets. Returns the zone in effect.
    """
    name = (cfg.get("timezone") or "").strip()
    if name:
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(name)          # raises if the zone is not real
        except Exception as e:      # noqa: BLE001 - bad zone must not stop startup
            logging.getLogger(LOGGER_NAME).warning(
                "Ignoring unknown timezone %r: %s", name, e)
            name = ""
    if name:
        os.environ["TZ"] = name
    if hasattr(time, "tzset"):      # Unix only, which is where this runs
        time.tzset()
    return name or os.environ.get("TZ") or time.strftime("%Z")


def available_timezones():
    """Sorted IANA zone names for the settings dropdown."""
    try:
        from zoneinfo import available_timezones as _az
        return sorted(_az())
    except Exception:  # noqa: BLE001
        return []


RING_SIZE = 500
LEVELS = ("debug", "info", "warning", "error")

_ring = deque(maxlen=RING_SIZE)
_redactor = None
_file_handler = None

MASK = "***REDACTED***"

# Libraries whose output we take ownership of so it goes through the redactor.
THIRD_PARTY_LOGGERS = ("urllib3", "requests", "werkzeug")

# Secrets recognisable by shape, whatever config says.
_PATTERNS = [
    re.compile(r"(?i)\b(apikey|api_key|x-api-key)\s*[=:]\s*([^\s&'\"]+)"),
    re.compile(r"(?i)\b(password|passwd|pwd)\s*[=:]\s*([^\s&'\"]+)"),
    re.compile(r"\bqbt_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]{8,}"),
]


class Redactor(logging.Filter):
    """Strip credentials from every record before it is written anywhere.

    Two layers: literal values pulled from the running config (so a key that
    appears in a URL or an exception is caught even when it looks like nothing
    in particular), and shape-based patterns (so a key we were never told about
    is still caught).
    """

    def __init__(self):
        super().__init__()
        self.secrets = set()

    def update(self, cfg):
        """Refresh the literal secrets from config. Call on load and reload."""
        found = set()

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(v, (dict, list)):
                        walk(v)
                    elif isinstance(v, str) and v.strip():
                        kl = k.lower()
                        if any(s in kl for s in
                               ("api_key", "apikey", "password", "secret", "token")):
                            # Short values would shred unrelated text.
                            if len(v.strip()) >= 8:
                                found.add(v.strip())
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(cfg)
        self.secrets = found

    def scrub(self, text):
        if not text:
            return text
        # A filename can contain newlines, and a log line is newline delimited.
        # Left alone, a crafted release name could forge entries that look like
        # Protectarr wrote them.
        if "\n" in text or "\r" in text:
            text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")
        for s in self.secrets:
            if s in text:
                text = text.replace(s, MASK)
        for pat in _PATTERNS:
            if pat.groups >= 2:
                text = pat.sub(lambda m: f"{m.group(1)}={MASK}", text)
            else:
                text = pat.sub(MASK, text)
        return text

    def filter(self, record):
        # Render args in now, so the scrubbed text is what handlers emit.
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - never let logging break the app
            return True
        record.msg = self.scrub(msg)
        record.args = ()
        if record.exc_info:
            record.exc_text = self.scrub(
                logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


class RingHandler(logging.Handler):
    """Keeps the last N formatted lines for the WebUI. deque is thread-safe."""

    def emit(self, record):
        try:
            _ring.append(self.format(record))
        except Exception:  # noqa: BLE001
            pass


def _namer(name):
    return name + ".gz"


def _rotator(source, dest):
    with open(source, "rb") as sf, gzip.open(dest, "wb") as df:
        shutil.copyfileobj(sf, df)
    os.remove(source)


class CompressingTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """Daily rotation that gzips the closed file.

    The stdlib handler's retention sweep matches rotated names against a date
    regex, and the `.gz` our namer appends stops that matching, so retention
    silently stops working. Hence the override.
    """

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.namer = _namer
        self.rotator = _rotator

    def getFilesToDelete(self):
        dir_name, base_name = os.path.split(self.baseFilename)
        prefix = base_name + "."
        result = []
        try:
            names = os.listdir(dir_name)
        except OSError:
            return []
        for name in names:
            if not name.startswith(prefix):
                continue
            suffix = name[len(prefix):]
            if suffix.endswith(".gz"):
                suffix = suffix[:-3]
            if self.extMatch.match(suffix):
                result.append(os.path.join(dir_name, name))
        result.sort()
        if self.backupCount <= 0 or len(result) <= self.backupCount:
            return []
        return result[:len(result) - self.backupCount]


# ---- configuration ----

def log_dir(cfg):
    """Where log files live. Defaults next to the config file."""
    from . import config as cfg_mod
    path = (cfg.get("logging", {}).get("path") or "").strip()
    if path:
        return path
    return os.path.join(os.path.dirname(cfg_mod.CONFIG_PATH) or ".", "logs")


def _level(name, default=logging.INFO):
    return getattr(logging, str(name or "").upper(), default)


def configure(cfg):
    """(Re)build handlers from config. Safe to call again on a settings save."""
    global _redactor, _file_handler
    lg = cfg.get("logging", {})
    root = logging.getLogger(LOGGER_NAME)

    apply_timezone(cfg)

    if _redactor is None:
        _redactor = Redactor()
    _redactor.update(cfg)

    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        except Exception:  # noqa: BLE001
            pass
    _file_handler = None

    # The logger passes everything; each handler picks its own threshold, so
    # the file can be verbose while the console stays readable.
    root.setLevel(logging.DEBUG)
    root.propagate = False

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                            datefmt=TS_FORMAT)
    ui_fmt = logging.Formatter("[%(asctime)s] %(levelname)-7s %(message)s",
                               datefmt=TS_FORMAT)

    # The redactor goes on every HANDLER, not on the logger. A filter attached
    # to a logger is only consulted for records logged directly through it, and
    # every module here logs through a child (protectarr.core, protectarr.qbit,
    # ...) whose records propagate straight to these handlers. On the logger it
    # would silently never run, which is the worst possible failure for this.
    def attach(handler, level, formatter):
        handler.setLevel(level)
        handler.setFormatter(formatter)
        handler.addFilter(_redactor)
        root.addHandler(handler)
        return handler

    attach(logging.StreamHandler(),
           _level(lg.get("console_level", "info")), fmt)
    attach(RingHandler(), _level(lg.get("level", "info")), ui_fmt)

    if lg.get("file_enabled", True):
        d = log_dir(cfg)
        try:
            os.makedirs(d, exist_ok=True)
            fh = CompressingTimedRotatingFileHandler(
                os.path.join(d, "protectarr.log"),
                when="midnight", interval=1,
                backupCount=max(0, int(lg.get("retention_days", 14) or 0)),
                encoding="utf-8", utc=False, delay=False)
            _file_handler = attach(fh, _level(lg.get("level", "info")), fmt)
        except OSError as e:
            root.warning("File logging disabled, cannot write to %s: %s", d, e)

    # Third-party chatter is noise at anything above debug, and urllib3 in
    # particular logs full URLs.
    noisy = logging.WARNING if _level(lg.get("level", "info")) > logging.DEBUG else logging.INFO
    handlers = list(root.handlers)
    for name in THIRD_PARTY_LOGGERS:
        tp = logging.getLogger(name)
        tp.setLevel(noisy)
        # Route their records through OUR handlers and stop them propagating to
        # the root logger. Otherwise they reach the root's handlers, which the
        # redactor is not attached to: werkzeug's access line contains the full
        # request target, so a caller using the documented `?apikey=` form would
        # have printed their key in clear text at debug level. Taking ownership
        # of the handler is the only fix that also covers child loggers such as
        # urllib3.connectionpool, whose records a filter on `urllib3` would
        # never be consulted for.
        for h in list(tp.handlers):
            tp.removeHandler(h)
        for h in handlers:
            tp.addHandler(h)
        tp.propagate = False
    return root


def get(name=None):
    """A logger under the protectarr namespace."""
    return logging.getLogger(LOGGER_NAME if not name else f"{LOGGER_NAME}.{name}")


def ring(limit=None):
    """Recent formatted lines, oldest first (what the UI and API show)."""
    lines = list(_ring)
    return lines[-limit:] if limit else lines


# ---- files, for the download UI ----

def list_files(cfg):
    """Log files newest first: [{name, size, modified}]. Names only, never
    paths, so nothing the caller sends back can escape the directory."""
    d = log_dir(cfg)
    out = []
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for name in names:
        if not name.startswith("protectarr.log"):
            continue
        full = os.path.join(d, name)
        if not os.path.isfile(full):
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        out.append({"name": name, "size": st.st_size, "modified": st.st_mtime})
    out.sort(key=lambda r: r["modified"], reverse=True)
    return out


def resolve_file(cfg, name):
    """Absolute path for a log file, or None.

    Validated by membership in the listing rather than by string checks, so a
    traversal attempt simply is not in the set and gets None.
    """
    if not name or name != os.path.basename(name):
        return None
    if name not in {f["name"] for f in list_files(cfg)}:
        return None
    return os.path.join(log_dir(cfg), name)
