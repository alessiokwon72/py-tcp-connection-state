# py-tcp-connection-state

Parses `/proc/net/tcp` and `/proc/net/tcp6` into a list of structured `TcpConnection` records with decoded state names and timer information.

```python
from py_tcp_connection_state import parse_tcp, parse_file

for conn in parse_file("/proc/net/tcp"):
    print(f"{conn.local_ip}:{conn.local_port} -> {conn.remote_ip}:{conn.remote_port} [{conn.state_name}]")
```

## Why this exists

Reading `/proc/net/tcp` by hand means dealing with hex-encoded IPv4 addresses, little-endian port numbers, integer state codes, and a packed `timer_*` column. This library does that decoding once, correctly, so consumers get a plain list of named records.

## Design choices

- **IPv6 scope IDs are not resolved.** The `ipv6_scope` field holds the raw integer; translating it to a device name requires a second kernel query (`/proc/net/if_inet6`), which would make this library do two jobs.
- **uid is always an int.** If `/proc/net/tcp` is ever read in a context where the column is missing, the field is set to `-1` rather than raising — a missing uid is a data quality issue, not a parse failure.
- **Incomplete trailing rows are skipped.** A short final line (which can happen if the file is read mid-update by the kernel) does not raise an error; it is omitted from the results.

## Awkward edge

The timer column encodes a duration as `(value * ticks_per_sec) / 100` seconds, where `ticks_per_sec` comes from `USER_HZ`. On almost all x86 Linux systems `USER_HZ` is 100. If this library runs on an architecture with a different tick rate, the `timer_duration` field will be wrong. We do not detect this at runtime because doing so portably requires sysconf, and this is a procfs parser, not a system introspection tool.
