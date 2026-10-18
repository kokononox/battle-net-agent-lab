import base64
import collections
import ipaddress
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "privacy-network"))
from http_capture import Stream, parse_requests, analyze_capture, MAX_STREAM
from validate_http import validate
from test_packet_meta import block

def request(body=b"", extra=b"", host=b"level3.blizzard.com"):
    return b"POST /file?x=1 HTTP/1.1\r\nHost: " + host + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n" + extra + b"\r\n" + body

def segment(seq, data, syn=False):
    tcp = struct.pack("!HHIIBBHHH", 12345, 80, seq, 0, 0x50, 2 if syn else 0x18, 1000, 0, 0) + data
    ip = b"\x45\x00" + (20+len(tcp)).to_bytes(2, "big") + b"\0\0\0\0\x40\x06\0\0" + ipaddress.ip_address("10.0.0.2").packed + ipaddress.ip_address("8.8.8.8").packed
    frame = b"\0"*12 + b"\x08\x00" + ip + tcp
    return block(6, struct.pack("<IIIII", 0, 0, 1, len(frame), len(frame)) + frame)

class HTTPTests(unittest.TestCase):
    def test_body(self):
        rows, status = parse_requests(request(b"test"))
        self.assertEqual(status, "parsed_to_end")
        self.assertEqual(base64.b64decode(rows[0]["body_sample_base64"]), b"test")
        self.assertTrue(rows[0]["body_complete"])

    def test_redaction(self):
        rows, _ = parse_requests(request(extra=b"Authorization: abc\r\nCookie: secret\r\n"))
        self.assertNotIn("secret", str(rows))
        self.assertIn(["authorization", "[REDACTED]"], rows[0]["headers"])

    def test_unapproved_host(self):
        self.assertEqual(parse_requests(request(host=b"other.example"))[0], [])

    def test_pipeline(self):
        rows, status = parse_requests(request(b"a") + request(b"bc"))
        self.assertEqual(status, "parsed_to_end")
        self.assertEqual(len(rows), 2)

    def test_embedded_http_not_request(self):
        rows, _ = parse_requests(request(request()))
        self.assertEqual(len(rows), 1)

    def test_partial(self):
        rows, status = parse_requests(request(b"abc")[:-1])
        self.assertFalse(rows[0]["body_complete"])
        self.assertEqual(status, "incomplete_body")

    def test_chunked(self):
        raw = b"POST /x HTTP/1.1\r\nHost: nydus.battle.net\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        rows, status = parse_requests(raw)
        self.assertEqual(status, "parsed_to_end")
        self.assertEqual(base64.b64decode(rows[0]["body_sample_base64"]), b"abc")

    def test_ambiguous(self):
        rows, status = parse_requests(request(extra=b"Transfer-Encoding: chunked\r\n"))
        self.assertFalse(rows)
        self.assertEqual(status, "ambiguous_body_framing")

    def test_duplicate_host(self):
        rows, status = parse_requests(request(extra=b"Host: other.example\r\n"))
        self.assertFalse(rows)
        self.assertEqual(status, "invalid_host")

    def test_duplicate_length(self):
        self.assertEqual(parse_requests(request(extra=b"Content-Length: 0\r\n"))[1], "invalid_content_length")

    def test_no_scan_midstream(self):
        self.assertFalse(parse_requests(b"junk\r\n" + request())[0])

    def test_out_of_order(self):
        s = Stream()
        s.add(100, b"", True)
        s.add(104, b"def")
        s.add(101, b"abc")
        self.assertEqual(s.finish(), (b"abcdef", "contiguous"))

    def test_out_of_order_without_syn(self):
        s = Stream()
        s.add(104, b"def")
        s.add(101, b"abc")
        self.assertEqual(s.finish()[0], b"abcdef")

    def test_duplicates(self):
        s = Stream()
        s.add(100, b"abc")
        s.add(100, b"abc")
        s.add(102, b"cdef")
        self.assertEqual(s.finish()[0], b"abcdef")

    def test_conflict(self):
        s = Stream()
        s.add(100, b"abc")
        s.add(101, b"ZZ")
        self.assertEqual(s.finish(), (b"", "conflicting_overlap"))

    def test_gap(self):
        s = Stream()
        s.add(100, b"", True)
        s.add(101, b"abc")
        s.add(108, b"xyz")
        self.assertEqual(s.finish(), (b"abc", "gap"))

    def test_wrap(self):
        s = Stream()
        s.add(0xfffffffd, b"abc")
        s.add(0, b"def")
        self.assertEqual(s.finish()[0], b"abcdef")

    def test_tuple_reuse(self):
        s = Stream()
        s.add(100, b"", True)
        s.add(101, b"abc")
        s.add(999, b"", True)
        self.assertEqual(s.finish()[1], "tuple_reused")

    def test_stream_cap(self):
        s = Stream()
        s.add(1, b"x" * (MAX_STREAM + 1))
        self.assertTrue(s.limit)
        self.assertEqual(s.size, 0)

    def test_body_export_cap(self):
        rows, _ = parse_requests(request(b"x" * 70000))
        self.assertTrue(rows[0]["body_sample_truncated"])
        self.assertTrue(rows[0]["body_complete"])
        self.assertEqual(len(base64.b64decode(rows[0]["body_sample_base64"])), 65536)

    def test_end_to_end_pcap_reorder(self):
        raw = request(b"CPU fixture, not real client")
        pcap = block(0x0a0d0d0a, struct.pack("<IHHq", 0x1a2b3c4d, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 65535))
        pcap += segment(100, b"", True) + segment(131, raw[30:]) + segment(101, raw[:30]) + segment(131, raw[30:])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "owned.pcapng"
            path.write_bytes(pcap)
            watched = {("10.0.0.2", 12345, "8.8.8.8", 80): {"pid": 5, "process_name": "agent.exe"}}
            result = analyze_capture(path, watched)
            self.assertEqual(result["flows"][0]["stream_status"], "contiguous")
            self.assertEqual(len(result["requests"]), 1)
            self.assertEqual(base64.b64decode(result["requests"][0]["body_sample_base64"]), b"CPU fixture, not real client")
            self.assertFalse(analyze_capture(path, {})["requests"])

class ValidationTests(unittest.TestCase):
    def fixture(self):
        row = parse_requests(request(b"fixture"))[0][0]
        return {
            "schema": "bnet-outgoing-http-1", "source_commit": "a"*40, "run_id": "1",
            "scope": "fresh_vm_startup_language_only_no_account_game_install_action",
            "reference": {"cpu_model": "Synthetic", "windows_build": 1, "total_physical_memory_bytes": 1, "logical_processors": 1},
            "bootstrap_pin_match": True,
            "capture": {"start_code": 0, "stop_code": 0, "convert_code": 0, "etl_bytes": 1, "pcapng_bytes": 1, "packet_size_requested": 0, "raw_packet_files_exported": False},
            "sampler": {"samples": 1, "errors": 0, "flow_limit_hit": False},
            "status": "capture_parsed", "bootstrap_status": "agent_process_observed", "error_code": None,
            "packet_stats": {"packets": 1},
            "flows": [{"flow_id": 1, "pid": 5, "process_name": "agent.exe", "remote_address": "8.8.8.8", "stream_status": "contiguous", "parse_status": "parsed_to_end"}],
            "requests": [{"flow_id": 1, **row}],
            "limits": {
                "server_receipt_proven": False, "user_pc_observed": False,
                "full_game_update_test": False, "responses_exported": False,
                "outgoing_known_hosts_only": True, "credential_headers_redacted": True,
                "tuple_pid_link_not_cryptographic_proof": True,
                "circular_capture_and_sampling_can_miss_data": True, "child_network_hard_byte_cap": False,
            },
        }

    def test_roundtrip(self):
        import json
        r = self.fixture()
        self.assertEqual(validate(json.loads(json.dumps(r))), r)

    def test_no_extra_raw_field(self):
        r = self.fixture()
        r["raw_packets"] = "not allowed"
        with self.assertRaises(ValueError):
            validate(r)

    def test_credentials_rejected(self):
        r = self.fixture()
        r["requests"][0]["headers"].append(["authorization", "secret"])
        with self.assertRaises(ValueError):
            validate(r)

    def test_unknown_host_rejected(self):
        r = self.fixture()
        r["requests"][0]["host"] = "other.example"
        with self.assertRaises(ValueError):
            validate(r)

    def test_corrupt_sample_rejected(self):
        r = self.fixture()
        r["requests"][0]["body_sample_base64"] = "AAAA"
        with self.assertRaises(ValueError):
            validate(r)

if __name__ == "__main__":
    unittest.main()