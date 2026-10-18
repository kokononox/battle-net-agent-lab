"""F2: parse known-host HTTP before PID filtering; count every discard stage."""
import base64
import collections
import ipaddress
import struct
from http_capture import Stream, parse_requests, MAX_TOTAL, MAX_EXPORTED, MAX_REQUESTS

DIAG_KEYS = {
    "ethernet_packets", "raw_ip_packets", "unsupported_link", "bad_ethernet",
    "unsupported_ethertype", "unsupported_ip_version", "bad_ipv4_header",
    "ipv4_zero_total_length", "ipv4_total_smaller_than_header",
    "ipv4_fragmented", "ipv4_declared_longer_than_capture",
    "bad_ipv6_header", "ipv6_zero_payload_length", "ipv6_extension_or_other_protocol",
    "ipv6_declared_longer_than_capture", "tcp_packets", "tcp_too_short",
    "non_tcp_packets", "outgoing_public_tcp80_observations",
    "outgoing_tcp80_payload_observations", "outgoing_tcp80_zero_payload_observations",
    "outgoing_tcp80_payload_observed_bytes", "tcp80_flows", "tcp80_flows_with_syn",
    "tcp80_flows_with_payload", "tcp80_flows_in_sampler", "tcp80_flows_not_in_sampler",
    "known_host_flows", "known_host_requests", "known_host_requests_without_pid",
    "known_host_requests_with_pid", "flows_no_known_host_request",
    "tcp80_flow_limit_hit", "tcp80_memory_limit_hit", "export_limit_hit",
}

def network_checked(link, packet, diag):
    data = packet
    if link == 1:
        diag["ethernet_packets"] += 1
        if len(data) < 14:
            diag["bad_ethernet"] += 1
            return None
        kind = int.from_bytes(data[12:14], "big")
        data = data[14:]
        for _ in range(2):
            if kind in (0x8100, 0x88a8) and len(data) >= 4:
                kind = int.from_bytes(data[2:4], "big")
                data = data[4:]
        if kind not in (0x0800, 0x86dd):
            diag["unsupported_ethertype"] += 1
            return None
    elif link in (101, 228, 229):
        diag["raw_ip_packets"] += 1
    else:
        diag["unsupported_link"] += 1
        return None
    version = data[0] >> 4 if data else 0
    if version == 4:
        if len(data) < 20:
            diag["bad_ipv4_header"] += 1
            return None
        offset = (data[0] & 15) * 4
        total = int.from_bytes(data[2:4], "big")
        if offset < 20 or offset > len(data):
            diag["bad_ipv4_header"] += 1
            return None
        if total == 0:
            # Possibly a capture/offload artifact; do not silently fabricate an IP length.
            diag["ipv4_zero_total_length"] += 1
            return None
        if total < offset:
            diag["ipv4_total_smaller_than_header"] += 1
            return None
        if int.from_bytes(data[6:8], "big") & 0x3fff:
            diag["ipv4_fragmented"] += 1
            return None
        if total > len(data):
            diag["ipv4_declared_longer_than_capture"] += 1
        return (str(ipaddress.ip_address(bytes(data[12:16]))),
                str(ipaddress.ip_address(bytes(data[16:20]))), data[9], data[offset:min(total, len(data))])
    if version == 6:
        if len(data) < 40:
            diag["bad_ipv6_header"] += 1
            return None
        length = int.from_bytes(data[4:6], "big")
        if length == 0:
            diag["ipv6_zero_payload_length"] += 1
            return None
        if data[6] not in (6, 17):
            diag["ipv6_extension_or_other_protocol"] += 1
            return None
        if length + 40 > len(data):
            diag["ipv6_declared_longer_than_capture"] += 1
        return (str(ipaddress.ip_address(bytes(data[8:24]))),
                str(ipaddress.ip_address(bytes(data[24:40]))), data[6], data[40:min(40+length, len(data))])
    diag["unsupported_ip_version"] += 1
    return None

def analyze_capture(path, watched):
    from packet_meta import packets
    stats = collections.Counter()
    diag = collections.Counter()
    streams = {}
    retained = 0
    for link, packet in packets(path, stats):
        net = network_checked(link, packet, diag)
        if net is None:
            continue
        src, dst, proto, tcp = net
        if proto != 6:
            diag["non_tcp_packets"] += 1
            continue
        diag["tcp_packets"] += 1
        if len(tcp) < 20:
            diag["tcp_too_short"] += 1
            continue
        sport, dport, seq = struct.unpack_from("!HHI", tcp)
        if dport != 80 or not ipaddress.ip_address(dst).is_global:
            continue
        diag["outgoing_public_tcp80_observations"] += 1
        offset = (tcp[12] >> 4) * 4
        if not 20 <= offset <= len(tcp):
            stats["tcp_parse_errors"] += 1
            continue
        payload = tcp[offset:]
        diag["outgoing_tcp80_payload_observations" if payload else "outgoing_tcp80_zero_payload_observations"] += 1
        diag["outgoing_tcp80_payload_observed_bytes"] += len(payload)
        key = (src, sport, dst, dport)
        if key not in streams:
            if len(streams) >= 128:
                diag["tcp80_flow_limit_hit"] += 1
                continue
            streams[key] = Stream()
        if retained + len(payload) > MAX_TOTAL:
            diag["tcp80_memory_limit_hit"] += 1
            streams[key].limit = True
            continue
        retained += streams[key].add(seq, payload, bool(tcp[13] & 2))
    diag["tcp80_flows"] = len(streams)
    diag["tcp80_flows_with_syn"] = sum(x.syn is not None for x in streams.values())
    diag["tcp80_flows_with_payload"] = sum(bool(x.segments) for x in streams.values())
    diag["tcp80_flows_in_sampler"] = sum(key in watched for key in streams)
    diag["tcp80_flows_not_in_sampler"] = sum(key not in watched for key in streams)
    requests, flows = [], []
    stream_statuses, parse_statuses = collections.Counter(), collections.Counter()
    exported = 0
    for key, stream in streams.items():
        data, stream_status = stream.finish()
        rows, parse_status = parse_requests(data)
        stream_statuses[stream_status] += 1
        parse_statuses[parse_status] += 1
        if not rows:
            diag["flows_no_known_host_request"] += 1
            continue
        identity = watched.get(key)
        flow_id = len(flows) + 1
        flows.append({
            "flow_id": flow_id,
            "process_name": identity["process_name"] if identity else None,
            "pid": identity["pid"] if identity else None,
            "remote_address": key[2], "stream_status": stream_status,
            "parse_status": parse_status,
            "attribution": "sampled_tcp_tuple" if identity else "unattributed",
        })
        for row in rows:
            cost = len(base64.b64decode(row["body_sample_base64"])) + len(str(row["headers"])) + len(row["target"])
            if len(requests) >= MAX_REQUESTS or exported + cost > MAX_EXPORTED:
                diag["export_limit_hit"] += 1
                continue
            exported += cost
            requests.append({"flow_id": flow_id, **row})
            diag["known_host_requests"] += 1
            diag["known_host_requests_with_pid" if identity else "known_host_requests_without_pid"] += 1
    diag["known_host_flows"] = len(flows)
    assert set(diag) <= DIAG_KEYS
    return {
        "packet_stats": dict(stats), "flows": flows, "requests": requests,
        "diagnostics": {
            "counts": dict(diag), "stream_statuses": dict(stream_statuses),
            "parse_statuses": dict(parse_statuses),
        },
    }