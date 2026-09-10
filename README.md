# Protectarr

Public torrent trackers seed fake "releases" whose file list is a video-sized
executable, e.g.:

```
Ted.Lasso.S04E07.1080p.ATVP.WEB-DL.DDP5.1.H.264-NTb.exe   1.06 GB
```

qBittorrent learns a torrent's **file list from its metadata within seconds of
adding it — before the content downloads.** Protectarr watches that list and, on
a hit, hands the release back to the owning *arr's queue API with
`blocklist=true`, so the *arr removes it and blocklists it. Protectarr then
decides whether to requeue based on the air/release date (see below).

Handing it back to the *arr — instead of just deleting it in qBittorrent — is
the whole trick: deleting it directly leaves the *arr's queue stuck and it never
searches again.

## Why not just use qBittorrent's "Excluded file names" or Sonarr's "Fail Downloads"?

- **qBittorrent excluded files** stop the download but leave the torrent in a
  limbo state the *arr doesn't recognise as failed, so it never grabs a
  replacement.
- **Sonarr/Radarr "Fail Downloads → Executables"** works, but only *after* the
  full file downloads (it inspects at import time). You still pull the whole
  ~1 GB fake.

Protectarr catches it up front *and* keeps the *arr self-healing.

## Run it

### Docker (recommended)

```bash
mkdir config
cp config.example.yaml config/config.yaml   # then edit it
QBIT_PASSWORD='your-qbit-password' docker compose up -d --build
```

Open the WebUI at `http://<host>:8090` to configure connections, test them, and
watch a live dry-run preview.

Two Docker gotchas:

- **Port clash:** if qBittorrent already uses `8090` on the same host, publish
  Protectarr on another port, e.g. `-> "8099:8090"`.
- **Reaching your services:** set `qbittorrent.url` (and the *arr URLs) to
  addresses reachable *from inside the container* — use the host's LAN IP
  (`http://192.168.1.100:8090`), **not** `localhost`, which points at the
  Protectarr container itself.

### Bare Python

```bash
pip install -r requirements.txt
export PROTECTARR_CONFIG=./config.yaml          # defaults to /config/config.yaml
cp config.example.yaml config.yaml          # edit it
python run.py            # worker + WebUI
python run.py --no-web   # headless worker only
```

## Configuration

Everything lives in `config.yaml` (editable by hand or through the WebUI).
Secrets can come from env vars instead: `PROTECTARR_QBIT_API_KEY`,
`PROTECTARR_QBIT_PASSWORD`, `PROTECTARR_QBIT_URL`, `PROTECTARR_QBIT_USERNAME`,
`PROTECTARR_WEB_API_KEY`, `PROTECTARR_DRY_RUN`.

### WebUI authentication

Modelled on the *arr apps (Settings → Security):

- **Method:** `none`, `basic` (browser popup), or `forms` (login page). Forms and
  Basic both check a username + hashed password; the **API key bypasses** auth.
- **Authentication required:** `enabled`, or `local_disabled` to skip auth for
  LAN/private clients.

⚠️ `local_disabled` trusts the client's address. If Protectarr sits behind a
reverse proxy, set `auth.trusted_proxies` to the proxy's CIDR(s) so
`X-Forwarded-For` is honoured only from the proxy — otherwise a client can spoof
that header to look local. If you don't run a trusted proxy, keep it `enabled`.

### qBittorrent auth

qBittorrent **≥ 5.2.0** supports API keys (Web UI → Options → Web UI → generate a
key, `qbt_…`). Set `qbittorrent.api_key` and it's used instead of the
username/password. Older versions fall back to the Web UI username/password.

### Safety modes

| mode          | reaps                                                                 |
|---------------|-----------------------------------------------------------------------|
| `arr_tracked` | only torrents a configured *arr has in its queue (**safest** — your hand-added downloads like Linux ISOs are never touched) |
| `allowlist`   | any torrent whose category/tag is in your allowlist                   |
| `both`        | must be *arr-tracked **and** allowlisted                              |

When a reaped torrent is *arr-tracked, it's failed+blocklisted via that *arr.
In `allowlist` mode a matching torrent that no *arr owns is deleted straight
from qBittorrent.

### Requeue behaviour (air-date aware)

Reaping removes + blocklists the fake and tells the *arr **not** to
auto-redownload, so Protectarr controls requeueing itself:

- **Aired/released already** → requeue (search for a clean release).
- **Not out yet** → hold. For an episode that hasn't aired, every public-tracker
  "release" is necessarily a fake, so requeueing would just pull the next one.
  The reaper blocklists what it sees and lets the *arr's normal RSS grab the real
  release once it actually drops.

Controlled by `safety.requeue_after_airdate` (default true) and
`safety.airdate_grace_hours` (wait N hours past the air time before requeuing,
since web releases often land a little after the broadcast slot). Air/release
dates come from Sonarr (`airDateUtc`) and Radarr (`digitalRelease` /
`physicalRelease`); types without a meaningful "aired" concept are held.

## Optional: peer IP blocklist

Protectarr can also maintain a peer **IP blocklist** for qBittorrent (default
source: [Naunter/BT_BlockLists](https://github.com/Naunter/BT_BlockLists)). It
downloads the list, writes it to `ip_blocklist.path`, and (if `apply_to_qbit`)
enables qBittorrent's IP filter pointed at that file, refreshing on a schedule.
There's an **Update now** button in the WebUI.

Because qBittorrent loads the filter from its **own** filesystem, `path` must be
readable by qBittorrent — and Protectarr sends **one** path value to both sides,
so that path has to resolve to the same file inside *both* containers.

- **Same host / bare metal (Protectarr and qBittorrent on one machine, no
  Docker):** point `path` at any location both can reach, e.g.
  `/var/lib/protectarr/ipfilter.p2p`. Because there's no container boundary the
  path is literally the same for both, and `qbittorrent.url` can just be
  `http://localhost:8080`. The one requirement is **permissions**: Protectarr
  writes the file, and the qBittorrent process (often a different service user)
  must be able to *read* it — put both users in a shared group, or write it
  world-readable (`chmod 644`), and make sure the containing directory is
  traversable by qBittorrent's user.
- **Docker:** the reliable trick is to keep the blocklist **inside qBittorrent's
  existing `/config` mount**. qBittorrent already sees anything under `/config`,
  so you only mount that subfolder into *Protectarr*, and both agree on one path.

Worked example with a `linuxserver/qbittorrent` container whose config lives at
`/volume1/docker/qbittorrent` (mounted `-> /config`):

1. Make the folder and give it to qBittorrent's user (its `PUID:PGID`, e.g.
   `1028:100`), so Protectarr can write and qBittorrent can read:

   ```bash
   mkdir -p /volume1/docker/qbittorrent/blocklist
   chown 1028:100 /volume1/docker/qbittorrent/blocklist
   ```

2. In **Protectarr's** compose, run as that same user and mount the folder at
   `/config/blocklist`:

   ```yaml
   protectarr:
     user: "1028:100"                 # match qBittorrent's PUID:PGID
     ports:
       - "8099:8090"                  # avoid clashing if qBittorrent is on 8090
     volumes:
       - ./config:/config
       - /volume1/docker/qbittorrent/blocklist:/config/blocklist
   ```

3. Set `ip_blocklist.path: /config/blocklist/ipfilter.p2p`.

qBittorrent reads that file through its own `/config` mount; Protectarr writes it
through the subfolder mount — **same path string, same file.** You do **not**
need to add any blocklist mount to the qBittorrent container itself; the folder
is already under its `/config`. (If qBittorrent uses `network_mode: service:...`
for a VPN, that's fine — the blocklist is a filesystem concern, unaffected by the
network mode.)

The list is P2P format (`label:startIP-endIP`), which qBittorrent's IP filtering
accepts natively.

### Manually banned IPs

For a small, hand-curated set of individual IPs there's a separate
`banned_ips` option that Protectarr pushes to qBittorrent's *manually banned IPs*
via the API — **no file or shared volume needed** (works cleanly across
containers). It can merge with qBittorrent's existing banned list rather than
overwrite it. Use this for one-off bans; use the IP filter above for bulk lists.

## Important: leave qBittorrent's "Excluded file names" empty

Protectarr replaces that feature. If both are active, qBittorrent's exclusion
jams the download into a state Protectarr (and the *arr) can't cleanly fail.

## Detection scope

Detection is by **file extension** in the torrent's file list — which is exactly
how these fakes are named. It does **not** catch a payload disguised with a
genuine media extension (an `.mkv` that's actually a PE binary); that needs
content/magic-byte inspection and a partial download.

## Requires

- qBittorrent Web UI enabled (Options → Web UI).
- API access to each *arr (URL + API key).

Protectarr requeues by triggering a search itself (only after air/release), so
you do **not** need the *arr's "Redownload Failed" setting for this to work.
