"""A tiny shared client for the *arr apps (Sonarr/Radarr/Lidarr/Readarr/…).

They all speak the same Servarr API shape; only the version segment, the
'include unknown' query param, the search command, and the air/release-date
lookup differ. This is the reused 'login/connection' logic the WebUI's Test
button and Protectarr rely on.
"""

import time
from datetime import datetime, timezone, timedelta

import requests

from . import logs

log = logs.get("arr")

# History eventTypes are a numeric enum on the wire. Passing the name - which is
# what the *response* calls it - returns HTTP 400 on both Sonarr and Radarr.
EVENT_DOWNLOAD_FAILED = 4
_FAILED_NAMES = {"4", "downloadfailed"}

# `eventType` must be the number on the wire: `eventType=grabbed` is HTTP
# 400 on both apps even though the *response* spells it that way. The
# response is matched by name or number, because only the request is picky.
EVENT_GRABBED = 1
_GRABBED_NAMES = {"1", "grabbed"}

# Per app type:
#   version       - API version segment
#   unknown_param - queue "include unknown items" flag
#   search        - (command name, ids field on command, id field on queue rec)
#   airdate       - (resource, id field on queue rec, [date fields on resource]).
#                   resource=None means the type has no meaningful "aired" concept.
#   queue_includes- queue params that nest the media object into each record, so
#                   History can name what a release was FOR without a second
#                   lookup. Unknown params are ignored by older *arrs.
#   media_keys    - the fields naming the media item, singular and plural. A
#                   history record uses the singular (`episodeId`) and a
#                   blocklist record the plural (`episodeIds`), so reading both
#                   lets one function identify either.
ARR_TYPES = {
    "sonarr":   {"version": "v3", "unknown_param": "includeUnknownSeriesItems",
                 "search": ("EpisodeSearch", "episodeIds", "episodeId"),
                 "airdate": ("episode", "episodeId", ["airDateUtc"]),
                 "library": ("series", "Series"),
                 "queue_includes": ["includeSeries", "includeEpisode"],
                 "media_keys": ("episodeId", "episodeIds")},
    "radarr":   {"version": "v3", "unknown_param": "includeUnknownMovieItems",
                 "search": ("MoviesSearch", "movieIds", "movieId"),
                 "airdate": ("movie", "movieId", ["digitalRelease", "physicalRelease"]),
                 "library": ("movie", "Movies"),
                 "queue_includes": ["includeMovie"],
                 "media_keys": ("movieId", "movieIds")},
    "whisparr": {"version": "v3", "unknown_param": "includeUnknownMovieItems",
                 "search": ("MoviesSearch", "movieIds", "movieId"),
                 "airdate": ("movie", "movieId", ["digitalRelease", "physicalRelease"]),
                 "library": ("movie", "Items"),
                 "queue_includes": ["includeMovie"],
                 "media_keys": ("movieId", "movieIds")},
    "lidarr":   {"version": "v1", "unknown_param": "includeUnknownArtistItems",
                 "search": ("AlbumSearch", "albumIds", "albumId"),
                 "airdate": (None, "albumId", []),
                 "library": ("artist", "Artists"),
                 "queue_includes": ["includeArtist", "includeAlbum"],
                 "media_keys": ("albumId", "albumIds")},
    "readarr":  {"version": "v1", "unknown_param": "includeUnknownAuthorItems",
                 "search": ("BookSearch", "bookIds", "bookId"),
                 "airdate": (None, "bookId", []),
                 "library": ("author", "Authors"),
                 "queue_includes": ["includeAuthor", "includeBook"],
                 "media_keys": ("bookId", "bookIds")},
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
        """Map lowercased torrent hash -> full queue record for this instance.

        Deliberately includes the *arr's "unknown" items - downloads it can see
        in its own category but has no media record for. They are not ownership
        (see `has_remediation_identity`), but they are real queue entries, and
        `intents` needs to know an entry is still sitting there before it
        retries a removal. Visibility and ownership are different questions;
        this answers the first and `ownership` decides the second.
        """
        params = {"pageSize": 2000, self.meta["unknown_param"]: "true"}
        for inc in self.meta.get("queue_includes", []):
            params[inc] = "true"
        r = self._s.get(self._url("queue"), params=params, timeout=self.timeout)
        r.raise_for_status()
        out = {}
        for rec in r.json().get("records", []):
            dlid = (rec.get("downloadId") or "").lower()
            if dlid:
                out[dlid] = rec
        return out

    def remediation_identity(self, record):
        """The *arr-native media id this queue record carries, or None.

        Read from `search`'s own declaration rather than a second list, because
        this is precisely the field `search()` needs: `search` returns None
        without it, so "has an identity" and "a replacement search is possible"
        cannot drift apart. `airdate` keys on the same field in every supported
        type, and `_media_ids` reads its singular form, so the blocklist oracle
        agrees too.

            sonarr   episodeId      lidarr   albumId
            radarr   movieId        readarr  bookId
            whisparr movieId
        """
        return record.get(self.meta["search"][2])

    def has_remediation_identity(self, record):
        """Can Protectarr's *arr-aware remediation actually operate on this?

        A queue record with no media id is an "unknown" item: the *arr can see
        the download sitting in its category but has no idea what it is for.
        Measured against Sonarr 4.0.20 and Radarr 6.4.4, asking such a record
        to be failed is accepted - HTTP 200, `"removed"`, the data really is
        deleted - and then produces no blocklist row, no downloadFailed history
        event and no replacement search, because a blocklist row is keyed on
        the media id there is none of. The remediation oracle correctly reports
        it unverified, which is terminal, so the intent sits in the triage
        queue forever with nothing able to resolve it.

        So this is not a capability check bolted onto ownership. It is the
        question of whether the *arr is claiming the download at all.
        """
        return bool(record) and self.remediation_identity(record) is not None

    def fail(self, queue_id):  # noqa: D401
        """Remove from client + blocklist, and DON'T let the arr auto-redownload
        (skipRedownload). We decide whether to requeue ourselves, based on the
        air/release date - see `airdate_status` and the caller.

        Returns "removed" or "absent". A 404 is not an error and is not a
        success either: it says the queue record is not there, which is equally
        true of a delete that already worked, a delete someone else did, and a
        delete that never happened. Only the oracle can tell those apart, so
        this reports what it saw and leaves the conclusion to the caller.
        """
        r = self._s.delete(
            self._url(f"queue/{queue_id}"),
            params={"removeFromClient": "true", "blocklist": "true",
                    "skipRedownload": "true"},
            timeout=self.timeout,
        )
        log.debug("%s DELETE queue/%s -> %s", self.name, queue_id, r.status_code)
        if r.status_code == 404:
            return "absent"
        r.raise_for_status()
        return "removed"

    def search(self, record):
        """Trigger a search for the item behind a queue record.

        Returns the *arr's command id, or None if there was nothing to search
        for. The id is what makes the search followable after a restart; "we
        asked for a search" is not a fact that survives a process, and without
        the id there is no way to tell an unfinished search from one that
        finished having found nothing.
        """
        cmd, ids_field, rec_field = self.meta["search"]
        target = record.get(rec_field)
        if not target:
            return None
        r = self._s.post(
            self._url("command"),
            json={"name": cmd, ids_field: [target]},
            timeout=self.timeout,
        )
        log.debug("%s command %s %s=%s -> %s", self.name, cmd, ids_field,
                  target, r.status_code)
        r.raise_for_status()
        try:
            return r.json().get("id")
        except ValueError:
            return None

    def command_status(self, command_id):
        """(state, result, message) for a command we issued earlier.

        `state` reaching a terminal value says the *arr finished running the
        search. It says nothing at all about whether a replacement was found:
        a search that downloaded nothing reports `completed` / `successful`
        with the message "0 reports downloaded", which is why the message is
        returned rather than thrown away.

        A state of None means we could not look: unreachable, or a reply we
        could not read. "unknown" is different and terminal - the *arr has no
        such command, which after a restart usually means it aged out of the
        command list. Waiting for that one to finish would wait forever.
        """
        try:
            r = self._s.get(self._url(f"command/{command_id}"),
                            timeout=self.timeout)
            if r.status_code == 404:
                return "unknown", None, None
            r.raise_for_status()
            body = r.json()
        except (requests.RequestException, ValueError) as e:
            log.debug("%s command %s unreadable: %s", self.name, command_id, e)
            return None, None, None
        return (body.get("status"), body.get("result"),
                body.get("message") or (body.get("body") or {}).get("completionMessage"))

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

    def _media_ids(self, record):
        """Every media id a history or blocklist record names, as a set.

        History uses the singular key and the blocklist the plural, which is
        why both are read. Sonarr's blocklist carries `episodeIds: [16801]`
        against the history event's `episodeId: 16801`; Radarr uses `movieId`
        on both sides.
        """
        out = set()
        for key in self.meta.get("media_keys", ()):
            value = record.get(key)
            if isinstance(value, (list, tuple)):
                out.update(v for v in value if v is not None)
            elif value is not None:
                out.add(value)
        return out

    def history_watermark(self):
        """The newest history id on this instance, or None if unreadable.

        Read *before* the destructive call and stored with the intent, so
        afterwards we can require the downloadFailed event to be newer than
        anything that existed before we acted. History ids are an
        autoincrement: verified on both apps that ordering by id descending is
        exactly ordering by date descending, across 200 Sonarr and 29 Radarr
        records.

        That makes this a clock-free "since". A timestamp window is not one -
        our clock and the *arr's are two different clocks, and a window wide
        enough to survive the skew is also wide enough to admit an unrelated
        event.
        """
        try:
            r = self._s.get(self._url("history"),
                            params={"pageSize": 1}, timeout=self.timeout)
            r.raise_for_status()
        except requests.RequestException as e:
            log.debug("%s history watermark unavailable: %s", self.name, e)
            return None
        records = r.json().get("records", [])
        return records[0].get("id") if records else None

    def failed_events(self, download_id, after_id=None, pages=4):
        """downloadFailed history events for one infohash, newest first.

        This is the exact identity we spent a long time assuming did not exist.
        The blocklist carries no hash, but every history record does - non-null
        on all 50 Sonarr and 1 Radarr downloadFailed records measured - so one
        query names the events belonging to one torrent and nothing else.

        The server-side `downloadId` filter is CASE SENSITIVE, and a case that
        does not match returns HTTP 200 with zero records rather than an error.
        Servarr stores the 40-character SHA-1 uppercased; qBittorrent reports
        it lowercased, and `queue_by_hash` lowercases it again. Querying with
        the hash as handed to us therefore finds nothing, silently, for a
        remediation that worked perfectly - so the uppercase form is asked for
        first and the original spelling is only tried if that comes back empty.

        Raises on a read failure rather than returning an empty list. "The *arr
        has no such event" and "we could not ask the *arr" must not reach the
        caller looking identical: only the first is evidence, and treating the
        second as evidence is how an outage becomes a permanent verdict.
        """
        return self._history_events(download_id, EVENT_DOWNLOAD_FAILED,
                                    _FAILED_NAMES, after_id, pages)

    def grab_events(self, download_id, after_id=None, pages=4):
        """`grabbed` history events for one infohash, newest first.

        The positive half of the same identity. A grabbed row is this *arr
        saying it asked for this exact torrent, and it is written at grab time:
        measured on Sonarr 4.0.20 and Radarr 6.4.4, it is queryable within
        2.9-33.3 ms of the grab, roughly 5 seconds before the download reaches
        the *arr's queue. That gap is the first-pass race, and this is the
        evidence that closes it.

        Two things it is *not*. It is not proof of current ownership: a grabbed
        row outlives the download, and the *arr may have finished with it long
        ago. And its absence is not proof of anything at all - deleting a
        series or movie cascade-deletes its history rows while the torrent
        carries on downloading, measured on both apps. So this is read as
        positive evidence only, never as a negative.

        Raises on a read failure, for the same reason `failed_events` does.
        """
        return self._history_events(download_id, EVENT_GRABBED, _GRABBED_NAMES,
                                    after_id, pages)

    def _history_events(self, download_id, event_type, names, after_id, pages):
        """History rows for one infohash and one event type, newest first.

        The server-side `downloadId` filter is CASE SENSITIVE, and a case that
        does not match returns HTTP 200 with zero records rather than an error.
        Servarr stores the 40-character SHA-1 uppercased; qBittorrent reports
        it lowercased, and `queue_by_hash` lowercases it again. Querying with
        the hash as handed to us therefore finds nothing, silently - so the
        uppercase form is asked for first and the original spelling is only
        tried if that comes back empty.

        Measured on both apps: the filter searches the whole retained history
        rather than a recent window - a row buried well off page 1 of an
        unfiltered query comes back with `pageSize=1` - and `totalRecords`
        reflects the filter. Paging is kept anyway, because a parameter the
        server does not understand is ignored rather than refused.

        Raises on a read failure rather than returning an empty list. "The *arr
        has no such event" and "we could not ask the *arr" must not reach the
        caller looking identical: only the first is evidence, and treating the
        second as evidence is how an outage becomes a permanent verdict.
        """
        did = (download_id or "").lower()
        if not did:
            return []
        spellings = [download_id.upper()]
        if download_id not in spellings:
            spellings.append(download_id)

        out = []
        for spelling in spellings:
            for page in range(1, pages + 1):
                r = self._s.get(
                    self._url("history"),
                    params={"downloadId": spelling, "page": page,
                            "pageSize": 100, "eventType": event_type},
                    timeout=self.timeout)
                r.raise_for_status()
                body = r.json()
                records = body.get("records") or []
                for rec in records:
                    # Filtered again here because neither filter can be trusted
                    # to have been applied: `sortKey=wibble` returns HTTP 200
                    # with normal ordering on both apps, so a parameter the
                    # server does not understand is ignored, not refused.
                    if (rec.get("downloadId") or "").lower() != did:
                        continue
                    if str(rec.get("eventType", "")).lower() not in names:
                        continue
                    if after_id is not None and (rec.get("id") or 0) <= after_id:
                        continue
                    out.append(rec)
                if len(records) < 100 or page * 100 >= (body.get("totalRecords") or 0):
                    break
            if out:
                break
        out.sort(key=lambda rec: rec.get("id") or 0, reverse=True)
        return out

    def refresh_monitored_downloads(self, timeout=90, poll=0.25):
        """Force the *arr to re-read its download client. (ok, why).

        The *arr builds its queue from a scheduled poll of the download client,
        not from the grab: measured, `RefreshMonitoredDownloads` runs on a
        one-minute timer on both Sonarr 4.0.20 and Radarr 6.4.4, and a torrent
        takes 21.7-73.6 s to appear if nothing forces it. Forcing it completes
        in 0.06-1.06 s, which turns "wait and hope" into a synchronisation
        barrier that can be waited on.

        `ok` is True only for a command that reached `completed`. A timeout, a
        failed command and an unreachable *arr are all False with a reason,
        because an unfinished refresh says nothing about ownership and must
        never be read as one that found nothing.
        """
        deadline = time.monotonic() + timeout
        try:
            r = self._s.post(self._url("command"),
                             json={"name": "RefreshMonitoredDownloads"},
                             timeout=self.timeout)
            r.raise_for_status()
            command_id = r.json().get("id")
        except (requests.RequestException, ValueError) as e:
            return False, f"could not ask {self.name} to refresh: {e}"
        if command_id is None:
            return False, f"{self.name} accepted the refresh but named no command"

        while time.monotonic() < deadline:
            state, result, _ = self.command_status(command_id)
            if state is None:
                return False, (f"{self.name} stopped answering while its "
                               f"refresh was running")
            if state == "completed":
                return True, f"{self.name} refreshed"
            if state in ("failed", "aborted", "unknown"):
                return False, (f"{self.name}'s refresh {state}"
                               f"{f' ({result})' if result else ''}")
            time.sleep(poll)
        return False, (f"{self.name}'s refresh did not finish within "
                       f"{timeout:.0f}s")

    def blocklist_rows(self, pages=4):
        """Every blocklist record this instance holds, newest first.

        Paged rather than trusting the first page to hold the newest, because
        `sortKey` is silently ignored: a key the server does not understand
        returns HTTP 200 with default ordering rather than an error, so no
        ordering we ask for can be assumed to have been applied. Raises on a
        read failure, for the reason `failed_events` does.
        """
        out = []
        for page in range(1, pages + 1):
            r = self._s.get(self._url("blocklist"),
                            params={"page": page, "pageSize": 100},
                            timeout=self.timeout)
            r.raise_for_status()
            body = r.json()
            records = body.get("records") or []
            out.extend(records)
            if len(records) < 100 or page * 100 >= (body.get("totalRecords") or 0):
                break
        out.sort(key=lambda rec: rec.get("id") or 0, reverse=True)
        return out

    def blocklist_row_for(self, event, rows):
        """The blocklist record a given history event produced, or None.

        Three exact comparisons, no normalisation of any kind:

          sourceTitle  compared against the *history event's* title, not
                       against qBittorrent's name for the torrent. Both strings
                       are the *arr's own rendering of the release, so they are
                       byte-identical - including Radarr's doubled year, which
                       appears the same way in both. 50/50 on Sonarr and 1/1 on
                       Radarr, zero misses.
          date         the tie-breaker. Six Sonarr titles appear on two
                       blocklist rows each, from re-grabbing the same release;
                       every one of them resolves to exactly one row on date,
                       which matched the history event's to the second on all
                       51 records.
          media id     corroboration, and only when both sides state one. On
                       its own it is not identity - episode 19135 is on four
                       separate blocklist rows.
        """
        title = event.get("sourceTitle") or ""
        date = event.get("date")
        want = self._media_ids(event)
        if not title or not date:
            return None
        for row in rows:
            if (row.get("sourceTitle") or "") != title:
                continue
            if row.get("date") != date:
                continue
            have = self._media_ids(row)
            if want and have and not (want & have):
                continue
            return row
        return None

    def verify_remediation(self, download_id, after_id=None, retries=6,
                           delay=1.5):
        """Did our removal actually land? Returns a dict, never raises.

        Two separate proofs, both required:

          history    a downloadFailed event carrying this exact infohash. Proof
                     that the *arr processed the failed-download action for
                     this torrent, and the only place either app exposes the
                     hash at all.
          blocklist  the row that event produced.

        Both, because `blocklist=true` is a distinct query parameter from the
        removal. The two records are written with the same timestamp and are
        evidently one transaction, but we have not tested whether a
        downloadFailed event can occur without a blocklist row, so the oracle
        checks both endpoints rather than inferring either from the other.

        The keys are `verified` (the only thing a caller should branch on),
        `reachable`, `event`, `blocklist` and `why`. A partial result is
        reported rather than flattened to a failure: "the *arr failed the
        download but wrote no blocklist row" and "the *arr never saw the
        delete" are different problems and should not read the same in a bug
        report.

        `reachable` is False when we could not ask at all. That is not a
        verdict about the release and a caller must not turn it into one - an
        *arr that was down for ten seconds is not evidence that a remediation
        failed.
        """
        result = {"verified": False, "reachable": True, "event": None,
                  "blocklist": None,
                  "why": "no downloadFailed event for this infohash"}
        if not download_id:
            return dict(result, why="no infohash to look the remediation up by")

        for attempt in range(retries):
            try:
                events = self.failed_events(download_id, after_id=after_id)
            except requests.RequestException as e:
                result["reachable"] = False
                result["why"] = f"could not read {self.name}'s history ({e})"
                events = []
            if events:
                event = events[0]
                result["event"] = {
                    "id": event.get("id"),
                    "date": event.get("date"),
                    "source_title": event.get("sourceTitle"),
                    # Two values observed: "Manually marked as failed" for our
                    # own delete and "Failed download detected" for the *arr
                    # acting on its own. Corroborating detail for a bug report,
                    # never identity - it cannot tell us apart from a human
                    # clicking blocklist in the UI.
                    "message": (event.get("data") or {}).get("message"),
                }
                try:
                    rows = self.blocklist_rows()
                except requests.RequestException as e:
                    result["reachable"] = False
                    result["why"] = f"could not read {self.name}'s blocklist ({e})"
                    rows = []
                row = self.blocklist_row_for(event, rows)
                if row:
                    result["blocklist"] = {"id": row.get("id"),
                                           "date": row.get("date"),
                                           "indexer": row.get("indexer")}
                    result["verified"] = True
                    result["reachable"] = True
                    result["why"] = "history event and blocklist row both found"
                    return result
                if result["reachable"]:
                    result["why"] = ("the *arr failed the download but no "
                                     "blocklist row matches that event")
            if attempt < retries - 1:
                # Both records land a moment after the delete returns.
                time.sleep(delay)
        log.debug("%s could not verify remediation for %s: %s",
                  self.name, (download_id or "")[:8], result["why"])
        return result

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
