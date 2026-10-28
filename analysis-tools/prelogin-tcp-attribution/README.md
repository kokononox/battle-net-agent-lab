# Owned TCP attribution calibration

No Battle.net/Agent launch. No external transfer. A native fixture sends exactly
1MiB to an owned client and 64KiB back over IPv4 loopback. It enables only DATA
EStats collection on its own unique established client rows, checks successful
Set calls and returned EnableCollection at each read, then verifies independent
application byte counts/content against DataBytes and ThruBytes deltas. An idle
second connection, same owning process, must remain unchanged. Adapter aggregate
is diagnostic only and cannot substitute for per-connection ownership/evidence.
Sockets have two-second send/receive timeouts; native execution timeout is20s.
Only counts, fixed labels, error codes, source SHA and run number leave the job.
No endpoint/PID/payload/raw log is published. Production Job limits are untouched.

This validates only IPv4 loopback data counters while sockets remain established.
It does not validate IPv6, UDP, TLS plaintext, new/short-lived sockets, complete
process coverage, game downloads or hardware transmission. Enabling EStats is
an observational collection change on the fixture's own connections, not a
read-only API operation and not a firewall/security change.

Official contracts:
- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getpertcpconnectionestats
- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-setpertcpconnectionestats
- https://learn.microsoft.com/en-us/windows/win32/api/tcpestats/ns-tcpestats-tcp_estats_data_rod_v0

The first contract explicitly warns that ignoring a failed enable or FALSE
EnableCollection can expose undefined/random counters. We fail closed on both.
DataBytes includes retransmissions, excludes TCP headers; ThruBytes counters are
separate cumulative-ACK measures. Exact-match is required for this local control;
a mismatch is a failed calibration, never rounded into a pass.
