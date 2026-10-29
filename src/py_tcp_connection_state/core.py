"""Parser for the Linux kernel's /proc/net/tcp and /proc/net/tcp6 files.

The kernel writes these files as space-aligned columns of hex values.
We split on whitespace (not fixed offsets) because the kernel's own
seq_file formatter emits single spaces between fields and variable-width
hex padding. Fixed-width slicing would be brittle if field widths ever
change; whitespace splitting is robust to that and matches how tools
like netstat historically parsed this file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


# The Linux kernel defines TCP state constants in include/net/tcp_states.h.
# We map the integer that appears in the 'st' column of /proc/net/tcp
# to the name a user would recognise from netstat output.
STATE_NAMES: dict[int, str] = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}


def decode_state(state: int) -> str:
    """Return the human-readable name for a TCP state integer.

    Returns "UNKNOWN" for any integer not in the kernel's defined set.
    This is safer than raising: a future kernel could add a state before
    this library is updated, and a parse failure would be worse than a
    clearly-labelled unknown.
    """
    return STATE_NAMES.get(state, "UNKNOWN")


# The kernel computes timer durations in clock ticks. On virtually every
# Linux/x86 system USER_HZ is 100. We expose it as a constant so tests
# can assert the exact arithmetic rather than a float that depends on
# system configuration. See the README for the caveat about other arches.
USER_HZ: int = 100


@dataclass(frozen=True)
class TcpConnection:
    """A single decoded row from /proc/net/tcp or /proc/net/tcp6.

    Fields are eagerly decoded to their human-meaningful forms so that
    callers never need to touch hex. IPv6 scope IDs are left as integers
    because resolving them to interface names requires reading a second
    proc file, which is out of scope for this parser.
    """

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: int
    state_name: str
    tx_queue: int
    rx_queue: int
    timer_active: int
    timer_duration: float
    uid: int
    inode: int
    ipv6_scope: Optional[int] = None


def _parse_ipv4(hex_addr: str) -> str:
    """Decode the kernel's little-endian hex IPv4 encoding.

    /proc/net/tcp prints IPv4 as 8 hex chars in little-endian byte
    order (e.g. "0100007F" is 127.0.0.1). We must reverse the bytes,
    not just the hex digits.
    """
    raw = bytes.fromhex(hex_addr)
    if len(raw) != 4:
        raise ValueError(f"expected 4 bytes for IPv4, got {len(raw)}: {hex_addr!r}")
    # The kernel writes the address in little-endian, so byte 0 is the
    # highest octet of the dotted-quad. Reverse to get network order.
    b = raw[::-1]
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def _parse_ipv6(hex_addr: str) -> str:
    """Decode the kernel's IPv6 hex encoding to a canonical colon string.

    The kernel writes 16 raw bytes as 32 hex chars in network byte order.
    We use stdlib ipaddress for canonical compression (e.g. collapsing
    runs of zeros with '::').
    """
    import ipaddress

    raw = bytes.fromhex(hex_addr)
    if len(raw) != 16:
        raise ValueError(f"expected 16 bytes for IPv6, got {len(raw)}: {hex_addr!r}")
    # bytes.fromhex preserves byte order; the kernel already writes
    # network order, so no reversal is needed.
    return str(ipaddress.IPv6Address(raw))


def _split_address_port(addr_port: str) -> tuple[str, int]:
    """Split a 'HEXADDR:HEXPORT' token into its address and port pieces.

    The port is always 4 hex chars, big-endian. We locate the colon by
    scanning from the right rather than splitting on ':' because the
    address portion itself contains colons only in the IPv6 hex form
    — which it does not, since the kernel uses a flat hex string with
    a single colon separator before the port. Still, rsplit is defensive.
    """
    idx = addr_port.rfind(":")
    if idx == -1:
        raise ValueError(f"missing ':' separator in address/port token: {addr_port!r}")
    addr = addr_port[:idx]
    port = int(addr_port[idx + 1:], 16)
    return addr, port


def parse_line(line: str, ipv6: bool = False) -> Optional[TcpConnection]:
    """Parse a single data line from /proc/net/tcp or /proc/net/tcp6.

    Returns None for the header line or any line that does not have
    enough columns to be a valid record. This silent-skip behaviour is
    intentional: /proc files can be read mid-update by the kernel,
    producing a truncated final line. Raising on a short line would make
    the parser unusable in monitoring loops. See the README.

    The expected column layout (1-indexed) for both files is:
      1: entry index (e.g. "0:")
      2: local_address:port
      3: remote_address:port
      4: st (state integer, hex)
      5: tx_queue:rx_queue
      6: tr:tm->when (timer active and duration)
      7: retrnsmt
      8: uid
      9: timeout
     10: inode

    For tcp6, the local_address and remote_address tokens carry an
    embedded scope id as a trailing hex integer after another colon.
    """
    parts = line.split()
    # 10 columns minimum for a well-formed row. We need fields up to
    # index 9 (inode). Fewer means a truncated/incomplete row — skip it.
    if len(parts) < 10:
        return None
    if parts[0] == "sl:" or parts[0] == "sl":
        return None

    local_token = parts[1]
    remote_token = parts[2]
    state_hex = parts[3]
    queues = parts[4]
    timer = parts[5]
    uid_str = parts[7]
    inode_str = parts[9]

    ipv6_scope: Optional[int] = None

    if ipv6:
        # For tcp6, the token is HEXADDR:HEXPORT:HEXSCOPE.
        # The scope is the interface index for link-local addresses.
        local_addr, rest = local_token.split(":", 1)
        local_port_hex, _, scope_hex = rest.partition(":")
        local_port = int(local_port_hex, 16)
        ipv6_scope = int(scope_hex, 16) if scope_hex else 0
        local_ip = _parse_ipv6(local_addr)

        remote_addr, rest = remote_token.split(":", 1)
        remote_port_hex = rest.split(":", 1)[0]
        remote_port = int(remote_port_hex, 16)
        remote_ip = _parse_ipv6(remote_addr)
    else:
        local_addr, local_port = _split_address_port(local_token)
        local_ip = _parse_ipv4(local_addr)
        remote_addr, remote_port = _split_address_port(remote_token)
        remote_ip = _parse_ipv4(remote_addr)

    state = int(state_hex, 16)

    # The tx/rx queue column is formatted as "HEX:HEX" (tx:rx).
    # The kernel writes these as zero-padded hex.
    tx_str, _, rx_str = queues.partition(":")
    tx_queue = int(tx_str, 16)
    rx_queue = int(rx_str, 16)

    # The timer column is "HEX:HEX" where the first nibble is the timer
    # type (0 = none) and the second is the expiry time in clock ticks.
    timer_str, _, when_str = timer.partition(":")
    timer_active = int(timer_str, 16)
    timer_ticks = int(when_str, 16)
    # Convert ticks to seconds using USER_HZ. The kernel formula is
    # (ticks * 100) / HZ / 100, simplified to ticks / HZ.
    timer_duration = timer_ticks / USER_HZ

    # The kernel prints uid and inode as decimal, not hex.
    uid = int(uid_str)
    inode = int(inode_str)

    return TcpConnection(
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        state=state,
        state_name=decode_state(state),
        tx_queue=tx_queue,
        rx_queue=rx_queue,
        timer_active=timer_active,
        timer_duration=timer_duration,
        uid=uid,
        inode=inode,
        ipv6_scope=ipv6_scope,
    )


def _iter_data_lines(text: str):
    """Yield non-empty, stripped lines from the raw proc file contents."""
    for line in text.splitlines():
        s = line.strip()
        if s:
            yield s


def parse_tcp(text: str) -> List[TcpConnection]:
    """Parse the full contents of /proc/net/tcp.

    Returns a list of TcpConnection records. Header and truncated
    lines are silently skipped.
    """
    out: List[TcpConnection] = []
    for line in _iter_data_lines(text):
        conn = parse_line(line, ipv6=False)
        if conn is not None:
            out.append(conn)
    return out


def parse_tcp6(text: str) -> List[TcpConnection]:
    """Parse the full contents of /proc/net/tcp6.

    Returns a list of TcpConnection records with the ipv6_scope field
    populated.
    """
    out: List[TcpConnection] = []
    for line in _iter_data_lines(text):
        conn = parse_line(line, ipv6=True)
        if conn is not None:
            out.append(conn)
    return out


def parse_file(path: str) -> List[TcpConnection]:
    """Read and parse a proc tcp file, auto-detecting ipv4 vs ipv6.

    The detection is based on the filename: paths ending in 'tcp6' are
    treated as IPv6, everything else as IPv4. This is simpler and more
    predictable than sniffing the address field width.
    """
    with open(path, "r", encoding="ascii") as f:
        text = f.read()
    if path.endswith("tcp6"):
        return parse_tcp6(text)
    return parse_tcp(text)
