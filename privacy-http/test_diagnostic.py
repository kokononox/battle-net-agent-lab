import collections
from pathlib import Path
import struct
import tempfile
import unittest
import test_http
from http_capture import analyze_capture as old_analyze
from capture_diagnostic import analyze_capture, network_checked
from validate_http import validate_diagnostic, validate_capture_bounds

def pcap(payload):
    return test_http.block(0x0a0d0d0a, struct.pack("<IHHq", 0x1a2b3c4d, 1, 0, -1)) + test_http.block(1, struct.pack("<HHI", 1, 0, 65535)) + test_http.segment(100, b"", True) + test_http.segment(101, payload)

def frame(payload):
    block = test_http.segment(101, payload)
    cap = struct.unpack_from("<I", block, 20)[0]
    return bytearray(block[28:28+cap])

class DiagnosticTests(unittest.TestCase):
    def analyze(self, payload, watched=None):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.pcapng"
            path.write_bytes(pcap(payload))
            old = old_analyze(path, watched or {})
            new = analyze_capture(path, watched or {})
            return old, new

    def test_previously_lost_unattributed_request(self):
        old, new = self.analyze(test_http.request())
        self.assertEqual(old["requests"], [])
        self.assertEqual(len(new["requests"]), 1)
        self.assertEqual(new["flows"][0]["attribution"], "unattributed")
        self.assertIsNone(new["flows"][0]["pid"])
        self.assertEqual(new["diagnostics"]["counts"]["known_host_requests_without_pid"], 1)

    def test_sampled_pid_preserved_not_invented(self):
        watched = {("10.0.0.2", 12345, "8.8.8.8", 80): {"pid": 5, "process_name": "agent.exe"}}
        _, new = self.analyze(test_http.request(), watched)
        self.assertEqual(new["flows"][0]["pid"], 5)
        self.assertEqual(new["flows"][0]["attribution"], "sampled_tcp_tuple")
        self.assertEqual(new["diagnostics"]["counts"]["known_host_requests_with_pid"], 1)

    def test_foreign_host_content_never_exported(self):
        _, new = self.analyze(test_http.request(b"foreign private body", host=b"other.example"))
        self.assertFalse(new["requests"])
        self.assertFalse(new["flows"])
        self.assertNotIn("foreign private body", str(new))
        self.assertEqual(new["diagnostics"]["counts"]["flows_no_known_host_request"], 1)

    def test_zero_ip_length_counted_not_guessed(self):
        packet = frame(test_http.request())
        packet[16:18] = b"\0\0"
        diag = collections.Counter()
        self.assertIsNone(network_checked(1, packet, diag))
        self.assertEqual(diag["ipv4_zero_total_length"], 1)

    def test_fragment_counted(self):
        packet = frame(test_http.request())
        packet[20:22] = b"\x20\x00"
        diag = collections.Counter()
        self.assertIsNone(network_checked(1, packet, diag))
        self.assertEqual(diag["ipv4_fragmented"], 1)

    def test_normal_frame_payload_length(self):
        payload = test_http.request()
        diag = collections.Counter()
        parsed = network_checked(1, frame(payload), diag)
        self.assertEqual(parsed[3][20:], payload)
        self.assertNotIn("ipv4_zero_total_length", diag)

    def report(self):
        r = test_http.ValidationTests().fixture()
        r["schema"] = "bnet-outgoing-http-2"
        r["limits"]["unattributed_known_host_requests_included"] = True
        _, parsed = self.analyze(test_http.request())
        r.update(parsed)
        return r

    def test_schema_roundtrip(self):
        r = self.report()
        self.assertEqual(validate_diagnostic(r), r)

    def test_unknown_pid_must_remain_null(self):
        r = self.report()
        r["flows"][0]["pid"] = 999
        with self.assertRaises(ValueError):
            validate_diagnostic(r)

    def test_diagnostic_counts_must_reconcile(self):
        r = self.report()
        r["diagnostics"]["counts"]["known_host_requests"] += 1
        with self.assertRaises(ValueError):
            validate_diagnostic(r)

    def test_no_unknown_diagnostic_text(self):
        r = self.report()
        r["diagnostics"]["counts"]["arbitrary_field"] = 1
        with self.assertRaises(ValueError):
            validate_diagnostic(r)

    def test_capture_boundary_recovery_explicit_only(self):
        packet = frame(test_http.request(b"owned fixture"))
        packet[16:18] = b"\0\0"
        diag = collections.Counter()
        self.assertIsNone(network_checked(1, packet, diag))
        parsed = network_checked(1, packet, diag, allow_zero_length_capture=True)
        self.assertEqual(parsed[3][20:], test_http.request(b"owned fixture"))
        self.assertEqual(diag["ipv4_zero_length_capture_bound_used"], 1)

    def inferred(self):
        packet = frame(test_http.request())
        packet[16:18] = b"\0\0"
        raw = test_http.block(0x0a0d0d0a, struct.pack("<IHHq", 0x1a2b3c4d, 1, 0, -1)) + test_http.block(1, struct.pack("<HHI", 1, 0, 65535))
        raw += test_http.block(6, struct.pack("<IIIII", 0, 0, 1, len(packet), len(packet)) + bytes(packet))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "owned.pcapng"
            path.write_bytes(raw)
            self.assertFalse(analyze_capture(path, {})["requests"])
            return analyze_capture(path, {}, allow_zero_length_capture=True)

    def test_inferred_stream_is_marked(self):
        r = self.inferred()
        self.assertEqual(len(r["requests"]), 1)
        self.assertEqual(r["flows"][0]["stream_status"], "contiguous_capture_bounds")
        self.assertEqual(r["diagnostics"]["counts"]["known_host_requests_using_capture_bounds"], 1)

    def test_inference_needs_schema_and_flag(self):
        r = self.report()
        r.update(self.inferred())
        with self.assertRaises(ValueError):
            validate_diagnostic(r)
        r["schema"] = "bnet-outgoing-http-3"
        r["limits"]["zero_ip_length_capture_bounds_inference"] = True
        self.assertEqual(validate_capture_bounds(r), r)

    def test_inference_counter_not_forgeable(self):
        r = self.report()
        r.update(self.inferred())
        r["schema"] = "bnet-outgoing-http-3"
        r["limits"]["zero_ip_length_capture_bounds_inference"] = True
        r["diagnostics"]["counts"]["known_host_requests_using_capture_bounds"] = 0
        with self.assertRaises(ValueError):
            validate_capture_bounds(r)

if __name__ == "__main__":
    unittest.main()