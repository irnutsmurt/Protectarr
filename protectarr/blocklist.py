"""Optional peer IP blocklist — downloads Naunter/BT_BlockLists (or any P2P/dat
list), writes it where qBittorrent can read it, and points qBittorrent's IP
filter at it. The list format (`label:startIP-endIP`) is what qBittorrent's IP
filtering natively accepts.
"""

import os
import zlib
import ipaddress
from urllib.parse import urlparse

import requests

from .qbit import QbitClient

MAX_DOWNLOAD = 200 * 1024 * 1024      # cap on the fetched (compressed) bytes
MAX_DECOMPRESSED = 512 * 1024 * 1024  # cap on the decompressed output


def _gunzip_limited(data, limit):
    """Decompress gzip data, refusing to expand past `limit` (gzip-bomb guard)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    chunk = d.decompress(data, 1 << 20)
    while chunk:
        out += chunk
        if len(out) > limit:
            raise ValueError("decompressed blocklist exceeds size limit")
        chunk = d.decompress(d.unconsumed_tail, 1 << 20)
    out += d.flush()
    return bytes(out)


def download_and_write(url, path, timeout=120):
    """Fetch the list (gunzipping if needed) and write it atomically to `path`.
    Returns (entries, bytes)."""
    scheme = urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported blocklist URL scheme: {scheme!r}")
    with requests.get(url, timeout=timeout, stream=True) as r:
        r.raise_for_status()
        raw = bytearray()
        for chunk in r.iter_content(65536):
            raw += chunk
            if len(raw) > MAX_DOWNLOAD:
                raise ValueError("blocklist download exceeds size limit")
    data = bytes(raw)
    if url.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = _gunzip_limited(data, MAX_DECOMPRESSED)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)
    entries = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
    return entries, len(data)


def _client(cfg):
    qc = cfg["qbittorrent"]
    qb = QbitClient(qc["url"], qc.get("username", ""), qc.get("password", ""),
                    api_key=qc.get("api_key", ""), verify_ssl=qc.get("verify_ssl", True))
    qb.login()
    return qb


def apply_to_qbit(cfg, path, block_trackers=False):
    """Enable qBittorrent's IP filter pointed at `path` (as qBittorrent sees it)."""
    _client(cfg).set_preferences({
        "ip_filter_enabled": True,
        "ip_filter_path": path,
        "ip_filter_trackers": bool(block_trackers),
    })


def apply_banned_ips(cfg):
    """Push the manual banned-IP list to qBittorrent's `banned_IPs` preference
    (no file needed). Returns the resulting count. Optionally merges with
    whatever is already banned in qBittorrent."""
    b = cfg.get("banned_ips", {})
    ips = [ip.strip() for ip in b.get("ips", []) if ip.strip()]
    qb = _client(cfg)
    if b.get("merge_existing", True):
        existing = (qb.get_preferences().get("banned_IPs", "") or "").split("\n")
        ips = existing + ips
    # Keep only valid individual IPs (qBittorrent's banned_IPs doesn't take ranges).
    valid = []
    for ip in ips:
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        valid.append(ip)
    merged = list(dict.fromkeys(valid))  # dedup, keep order
    qb.set_preferences({"banned_IPs": "\n".join(merged)})
    return len(merged)


def update(cfg):
    """Run one blocklist refresh per config. Returns a status dict; raises on
    download/network errors so the caller can record them."""
    bl = cfg.get("ip_blocklist", {})
    entries, size = download_and_write(bl["url"], bl["path"])
    applied = False
    if bl.get("apply_to_qbit", True):
        apply_to_qbit(cfg, bl["path"], bl.get("block_trackers", False))
        applied = True
    return {"entries": entries, "bytes": size, "applied": applied}
