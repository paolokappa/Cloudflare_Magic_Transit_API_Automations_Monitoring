"""
Happy Eyeballs (RFC 8305) - IPv6-first with fast IPv4 fallback.

Monkey-patches urllib3 to try IPv6 first with a 2-second timeout,
then falls back to IPv4 immediately. This avoids 30+ second delays
when IPv6 connectivity is broken.

Usage: Simply import this module before making HTTP requests.
    import happy_eyeballs

All subsequent requests.get/post calls will use the patched connection logic.

Author: GOLINE SOC
Version: 1.0.0
"""

import socket
import urllib3.util.connection

# Save the original function
_original_create_connection = urllib3.util.connection.create_connection

# IPv6 attempt timeout in seconds
IPV6_TIMEOUT = 2.0


def _happy_eyeballs_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                                       source_address=None, socket_options=None):
    """
    Happy Eyeballs connection: try IPv6 first (2s timeout), fallback to IPv4.
    Thread-safe - uses only local variables.
    """
    host, port = address

    # Resolve all addresses for the host
    try:
        addrinfos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise

    if not addrinfos:
        raise OSError(f"getaddrinfo returns an empty list for {host!r}")

    # Separate IPv6 and IPv4 addresses
    ipv6_addrs = [ai for ai in addrinfos if ai[0] == socket.AF_INET6]
    ipv4_addrs = [ai for ai in addrinfos if ai[0] == socket.AF_INET]

    # If only one family available, use it directly (no Happy Eyeballs needed)
    if ipv6_addrs and not ipv4_addrs:
        return _try_connect(ipv6_addrs, timeout, source_address, socket_options)
    if ipv4_addrs and not ipv6_addrs:
        return _try_connect(ipv4_addrs, timeout, source_address, socket_options)

    # Happy Eyeballs: try IPv6 first with short timeout
    ipv6_timeout = min(IPV6_TIMEOUT, timeout) if timeout != socket._GLOBAL_DEFAULT_TIMEOUT else IPV6_TIMEOUT

    try:
        return _try_connect(ipv6_addrs, ipv6_timeout, source_address, socket_options)
    except OSError:
        pass

    # IPv6 failed, fall back to IPv4 with remaining/full timeout
    return _try_connect(ipv4_addrs, timeout, source_address, socket_options)


def _try_connect(addrinfos, timeout, source_address, socket_options):
    """Try connecting to the first available address in the list."""
    last_err = None

    for af, socktype, proto, canonname, sa in addrinfos:
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)

            if timeout != socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)

            if source_address:
                sock.bind(source_address)

            if socket_options:
                for opt in socket_options:
                    sock.setsockopt(*opt)

            sock.connect(sa)
            return sock

        except OSError as e:
            last_err = e
            if sock is not None:
                sock.close()

    if last_err is not None:
        raise last_err
    raise OSError("getaddrinfo returns an empty list")


# Apply the monkey-patch on import
urllib3.util.connection.create_connection = _happy_eyeballs_create_connection
