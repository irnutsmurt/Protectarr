"""A tiny shared client for the *arr apps (Sonarr/Radarr/Lidarr/Readarr/…).

They all speak the same Servarr API shape; only the version segment, the
'include unknown' query param, the search command, and the air/release-date
lookup differ. This is the reused 'login/connection' logic the WebUI's Test
button and Protectarr rely on.
"""

import time
from datetime import datetime, timezone, timedelta

import requests

# Per app type:
#   version       - API version segment
#   unknown_param - queue "include unknown items" flag
#   search        - (command name, ids field on command, id field on queue rec)
#   airdate       - (resource, id field on queue rec, [date fields on resource]).
#                   resource=None means the type has no meaningful "aired" concept.
ARR_TYPES = {
    "sonarr":   {"version": "v3", "unknown_param": "includeUnknownSeriesItems",
                 "search": ("EpisodeSearch", "episodeIds", "episodeId"),
                 "airdate": ("episode", "episodeId", ["airDateUtc"]),
                 "library": ("series", "Series")},
    "radarr":   {"version": "v3", "unknown_param": "includeUnknownMovieItems",
                 "search": ("MoviesSearch", "movieIds", "movieId"),
                 "airdate": ("movie", "movieId", ["digitalRelease", "physicalRelease"]),
                 "library": ("movie", "Movies")},
    "whisparr": {"version": "v3", "unknown_param": "includeUnknownMovieItems",
                 "search": ("MoviesSearch", "movieIds", "movieId"),
                 "airdate": ("movie", "movieId", ["digitalRelease", "physicalRelease"]),
                 "library": ("movie", "Items")},
    "lidarr":   {"version": "v1", "unknown_param": "includeUnknownArtistItems",
                 "search": ("AlbumSearch", "albumIds", "albumId"),
                 "airdate": (None, "albumId", []),
                 "library": ("artist", "Artists")},
    "readarr":  {"version": "v1", "unknown_param": "includeUnknownAuthorItems",
                 "search": ("BookSearch", "bookIds", "bookId"),
                 "airdate": (None, "bookId", []),
                 "library": ("author", "Authors")},
}


def _parse_dt(value):
    """Parse a Servarr date/datetime string into an aware UTC datetime, or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class ArrClient:
    def __init__(self, name, arr_type, url, api_key, timeout=15):
        self.name = name
        self.type = (arr_type or "").lower()
        if self.type not in ARR_TYPES:
            raise ValueError(f"Unknown arr type: {arr_type!r}")
        self.base = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.meta = ARR_TYPES[self.type]
        self._s = requests.Session()
        self._s.headers.update({"X-Api-Key": api_key})

    def _url(self, path):
        return f"{self.base}/api/{self.meta['version']}/{path.lstrip('/')}"

    def test(self):
        """Return (ok, message) - mirrors the arr apps' 'Test' button."""
        try:
            r = self._s.get(self._url("system/status"), timeout=self.timeout)
        except requests.RequestException as e:
            return False, f"Connection error: {e}"
        if r.status_code == 401:
            return False, "Unauthorized (bad API key)"
        if not r.ok:
            return False, f"HTTP {r.status_code}"
        data = r.json()
        return True, f"{data.get('appName', 'Arr')} {data.get('version', '')}".strip()

    def library_stats(self):
        """Count items in this app's library (Series / Movies / Artists / …),
        total and monitored. Powers the dashboard 'monitored' figures."""
        endpoint, noun = self.meta["library"]
        r = self._s.get(self._url(endpoint), timeout=self.timeout)
        r.raise_for_status()
        items = r.json()
        total = len(items)
        monitored = sum(1 for it in items if it.get("monitored"))
        return {"noun": noun, "total": total, "monitored": monitored}

    def indexers(self):
        """List the indexers configured on this arr instance.

        Returns [{name, protocol, priority, enabled}], mirroring the arr's
        Settings > Indexers page - used by Protectarr's dashboard to show which
        indexers each app can pull from.
        """
        r = self._s.get(self._url("indexer"), timeout=self.timeout)
        r.raise_for_status()
        out = []
        for ix in r.json():
            out.append({
                "name": ix.get("name", ""),
                "protocol": ix.get("protocol", ""),
                "priority": ix.get("priority"),
                "enabled": bool(ix.get("enableRss") or ix.get("enableAutomaticSearch")
                                or ix.get("enableInteractiveSearch")),
            })
        return out

    def queue_by_hash(self):
        """Map lowercased torrent hash -> full queue record for this instance."""
        params = {"pageSize": 2000, self.meta["unknown_param"]: "true"}
        r = self._s.get(self._url("queue"), params=params, timeout=self.timeout)
        r.raise_for_status()
        out = {}
        for rec in r.json().get("records", []):
            dlid = (rec.get("downloadId") or "").lower()
            if dlid:
                out[dlid] = rec
        return out

    def fail(self, queue_id):
        """Remove from client + blocklist, and DON'T let the arr auto-redownload
        (skipRedownload). We decide whether to requeue ourselves, based on the
        air/release date - see `airdate_status` and the caller."""
        r = self._s.delete(
            self._url(f"queue/{queue_id}"),
            params={"removeFromClient": "true", "blocklist": "true",
                    "skipRedownload": "true"},
            timeout=self.timeout,
        )
        r.raise_for_status()

    def search(self, record):
        """Trigger a search for the item behind a queue record. Returns True if
        a command was issued."""
        cmd, ids_field, rec_field = self.meta["search"]
        target = record.get(rec_field)
        if not target:
            return False
        r = self._s.post(
            self._url("command"),
            json={"name": cmd, ids_field: [target]},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return True

    def airdate_status(self, record, grace_hours=0):
        """Has the item behind this queue record aired / been released yet?

        Returns (status, date):
          status True  -> aired/released (grace elapsed) - safe to requeue
          status False -> not out yet - a legit release can't exist; hold
          status None  -> unknown (no date, or type has no air concept)
        `date` is the earliest known air/release datetime (UTC) or None.
        """
        resource, id_field, date_fields = self.meta["airdate"]
        if not resource or not date_fields:
            return None, None
        rid = record.get(id_field)
        if not rid:
            return None, None
        try:
            r = self._s.get(self._url(f"{resource}/{rid}"), timeout=self.timeout)
            r.raise_for_status()
            obj = r.json()
        except requests.RequestException:
            return None, None
        dates = [d for d in (_parse_dt(obj.get(f)) for f in date_fields) if d]
        if not dates:
            return None, None
        earliest = min(dates)
        aired = datetime.now(timezone.utc) >= earliest + timedelta(hours=grace_hours)
        return aired, earliest

    def is_blocklisted_title(self, source_title, retries=4, delay=1.0):
        """Check that a release title made it into the blocklist. Sonarr writes
        the entry a moment after the queue delete returns, so we poll briefly."""
        want = (source_title or "").lower()
        if not want:
            return False
        for attempt in range(retries):
            r = self._s.get(self._url("blocklist"),
                            params={"pageSize": 50, "sortKey": "date",
                                    "sortDirection": "descending"},
                            timeout=self.timeout)
            r.raise_for_status()
            if any((b.get("sourceTitle") or "").lower() == want
                   for b in r.json().get("records", [])):
                return True
            if attempt < retries - 1:
                time.sleep(delay)
        return False

    def grab_indexer(self, download_id):
        """Best-effort: which indexer grabbed this download. Queue records don't
        reliably carry `indexer` for public-tracker grabs, so fall back to the
        grabbed history event keyed by downloadId."""
        if not download_id:
            return None
        did = download_id.lower()
        try:
            r = self._s.get(self._url("history"),
                            params={"downloadId": download_id, "pageSize": 50,
                                    "sortKey": "date", "sortDirection": "descending"},
                            timeout=self.timeout)
            r.raise_for_status()
        except requests.RequestException:
            return None
        for rec in r.json().get("records", []):
            # Filter client-side too, in case the server ignores downloadId.
            if (rec.get("downloadId") or "").lower() != did:
                continue
            data = rec.get("data") or {}
            ix = data.get("indexer") or rec.get("indexer")
            if ix:
                return ix
        return None


def build_clients(cfg):
    """Instantiate clients from config, skipping malformed entries."""
    clients = []
    for a in cfg.get("arrs", []):
        try:
            clients.append(ArrClient(a["name"], a["type"], a["url"], a.get("api_key", "")))
        except (KeyError, ValueError):
            continue
    return clients
