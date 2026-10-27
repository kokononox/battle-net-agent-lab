import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
import guard_report as g
from test_guard_report import rec


def blank():
    return dict({k:0 for k in g.DIAG_NUMS}, **{k:False for k in g.DIAG_FLAGS})


class Diagnostics(unittest.TestCase):
    def test_old_receipt_remains_readable(self):
        g.receipt(rec())

    def test_new_empty_receipt(self):
        r = rec()
        r.update(schema='bnet-retail-supervisor-3', network_diagnostics=blank())
        g.receipt(r)

    def test_unknown_and_private_fields_refused(self):
        for key in ('address', 'interface_luid', 'private_pid'):
            d = blank()
            d[key] = 'private'
            with self.assertRaises(ValueError):
                g.validate_diagnostics(d)

    def test_strict_count_types(self):
        for k in g.DIAG_NUMS:
            for v in (True, -1, 2**64, '1'):
                d = blank()
                d[k] = v
                with self.assertRaises(ValueError):
                    g.validate_diagnostics(d)

    def test_strict_boolean_types(self):
        for k in g.DIAG_FLAGS:
            d = blank()
            d[k] = 1
            with self.assertRaises(ValueError):
                g.validate_diagnostics(d)

    def test_phase_boundary_needs_two_samples(self):
        d = blank()
        d['phase_boundary_observed'] = True
        with self.assertRaises(ValueError):
            g.validate_diagnostics(d)

    def test_unobserved_boundary_cannot_contain_values(self):
        for k in ('phase_boundary_gap_ms', 'phase_boundary_delta_bytes'):
            d = blank()
            d.update(samples=2, max_sample_gap_ms=1000, max_sample_delta_bytes=1000)
            d[k] = 1
            with self.assertRaises(ValueError):
                g.validate_diagnostics(d)

    def test_maximum_cannot_be_lower_than_last(self):
        d = blank()
        d.update(samples=2, last_sample_gap_ms=251, max_sample_gap_ms=250)
        with self.assertRaises(ValueError):
            g.validate_diagnostics(d)

    def test_diagnostics_cannot_change_guard_limits(self):
        r = rec('observe')
        r.update(schema='bnet-retail-supervisor-3', network_diagnostics=blank())
        r['phase_network_threshold_bytes'] += 1
        with self.assertRaises(ValueError):
            g.receipt(r)

    @unittest.skipUnless(shutil.which('g++'), 'portable C++ compiler not installed')
    def test_production_header_with_synthetic_cpp_samples(self):
        here = Path(__file__).parent
        with tempfile.TemporaryDirectory() as d:
            exe = Path(d)/'counter-test'
            build = subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                str(here/'counter_diagnostics_test.cpp'), '-o', str(exe)],
                capture_output=True, timeout=60)
            self.assertEqual(build.returncode, 0)
            run = subprocess.run([str(exe)], capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0)

    def test_native_guard_preserves_limits_and_previous_sample_baseline(self):
        # Text contract supplements C++ tests; not a claim of a Windows native run.
        text = Path(__file__).with_name('guard.cpp').read_text()
        for contract in ('phase_net0=arm.baseline;', 'r.phase_delta>=67108864ULL',
                         'r.phase_elapsed>=30000', 'r.delta>=r.byte_limit',
                         'r.min_free<r.reserve', 'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE'):
            self.assertIn(contract, text)


if __name__ == '__main__':
    unittest.main()
