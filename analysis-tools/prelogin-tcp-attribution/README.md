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

## Owned Agent baseline observer T2

Each target run first repeats the native known-transfer fixture using the shared
`estats_common.h` read/enable implementation. Only then is the meter compiled and
the unchanged guarded target allowed. The worker supplies the already-verified
Agent listener's owner. The meter holds that original process object open, checks
its continued existence and unique listener ownership, enables collection on up
to128 established non-loopback IPv4 TCP rows of exactly that PID, and checkpoints
25ms samples for at most200 iterations. Changed connection sets, failed reads,
disabled collection or decreased counters stop observation; they are never zeros.
No new endpoints are followed and the meter makes no socket connections.

The baseline is established BEFORE phase arming. Its observation window is
explicitly `pre_arm_baseline_to_last_checkpoint`, not a claim that every byte
occurred after finalization. Existing/new/closed IPv6, UDP, short-lived TCP and
other processes remain outside scope. An interrupted current checkpoint proves
only its reported bounded interval, never later activity. Zero is not proof of
zero total Agent traffic. Production Job killing includes the meter child.
