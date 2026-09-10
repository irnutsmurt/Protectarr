"""Client-IP resolution + local-address detection for the 'Disabled for Local
Addresses' auth mode. Mirrors how the arr apps treat private/loopback ranges,
and only trusts X-Forwarded-For when the immediate peer is a configured proxy.
"""

import ipaddress

# Private / loopback / link-local ranges considered "local".
LOCAL_NETS = [
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]


def _parse(ip):
    try:
        return ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return None


def _in_nets(ip, nets):
    addr = _parse(ip) if isinstance(ip, str) else ip
    if addr is None:
        return False
    for net in nets:
        try:
            if addr in net:
                return True
        except TypeError:  # v4 addr vs v6 net etc.
            continue
    return False


def is_local(ip):
    """True if ip is a private/loopback/link-local address."""
    return _in_nets(ip, LOCAL_NETS)


def resolve_client_ip(remote_addr, xff_header, trusted_proxies):
    """Return the effective client IP.

    Only honour X-Forwarded-For when the direct peer (remote_addr) is a trusted
    proxy; otherwise a client could spoof XFF to look local. When trusted, take
    the left-most XFF entry (the original client).
    """
    nets = []
    for cidr in trusted_proxies or []:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    if xff_header and nets and _in_nets(remote_addr, nets):
        first = xff_header.split(",")[0].strip()
        if _parse(first):
            return first
    return remote_addr
