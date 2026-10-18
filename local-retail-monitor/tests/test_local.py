import ast
import base64
from collections import Counter
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from hosts_guard import HostsGuard,target_entry
from core import Collector,hostname,versions,decoded_cpu_match
from monitor import LIMITS
from validate import validate

class HostTests(unittest.TestCase):
    def setup_guard(self,root,**kw):
        path=root/'hosts';path.write_bytes(b'# keep\r\n127.0.0.1 localhost\r\n')
        return HostsGuard(path,root/'private'/'journal.json',flush_fn=lambda:True,resolve_fn=lambda:'loopback_only',**kw)
    def test_roundtrip_exact_bytes(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.setup_guard(Path(x));original=g.hosts.read_bytes();g.apply()
            self.assertTrue(target_entry(g.hosts.read_bytes()));self.assertEqual(g.restore(),'restored_exactly')
            self.assertEqual(g.hosts.read_bytes(),original);self.assertFalse(g.journal.exists())
    def test_existing_entry_not_changed(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.setup_guard(Path(x));g.hosts.write_bytes(b'127.0.0.1 telemetry-in.battle.net\r\n');before=g.hosts.read_bytes()
            with self.assertRaises(ValueError):g.apply()
            self.assertEqual(g.hosts.read_bytes(),before);self.assertFalse(g.journal.exists())
    def test_existing_backup_never_overwritten(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.setup_guard(Path(x));g.journal.parent.mkdir();g.journal.write_text('existing')
            with self.assertRaises(ValueError):g.apply()
            self.assertEqual(g.journal.read_text(),'existing')
    def test_external_changes_preserved(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.setup_guard(Path(x));g.apply();edited=g.hosts.read_bytes()+b'# someone else\n';g.hosts.write_bytes(edited)
            self.assertEqual(g.restore(),'needs_manual_attention_journal_kept');self.assertEqual(g.hosts.read_bytes(),edited);self.assertTrue(g.journal.exists())
    def test_crash_recovery_fresh_guard(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.setup_guard(Path(x));original=g.hosts.read_bytes();g.apply()
            recovery=HostsGuard(g.hosts,g.journal,flush_fn=lambda:True)
            self.assertEqual(recovery.restore(),'restored_exactly');self.assertEqual(g.hosts.read_bytes(),original)
    def test_failed_resolution_restorable(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.setup_guard(Path(x));g.resolve=lambda:'public_only';original=g.hosts.read_bytes()
            with self.assertRaises(ValueError):g.apply()
            self.assertEqual(g.restore(),'restored_exactly');self.assertEqual(g.hosts.read_bytes(),original)
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);target=root/'real';target.write_bytes(b'hello');path=root/'hosts'
            try:path.symlink_to(target)
            except OSError:self.skipTest('symlinks not permitted')
            g=HostsGuard(path,root/'journal',flush_fn=lambda:True)
            with self.assertRaises(ValueError):g.apply()
    def test_backup_tampering_not_restored(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.setup_guard(Path(x));g.apply();d=json.loads(g.journal.read_text());d['original_base64']=base64.b64encode(b'bad').decode();g.journal.write_text(json.dumps(d));modified=g.hosts.read_bytes()
            self.assertEqual(g.restore(),'needs_manual_attention_journal_kept');self.assertEqual(g.hosts.read_bytes(),modified)
    def test_utf16_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.setup_guard(Path(x));b='# original'.encode('utf-16');g.hosts.write_bytes(b)
            with self.assertRaises(UnicodeError):g.apply()
            self.assertEqual(g.hosts.read_bytes(),b)

class MetadataTests(unittest.TestCase):
    def collector(self):
        c=object.__new__(Collector);c.needle=b'SYNTHETIC_CPU';c.rows={1:{'script_errors':0,'input_events':0}};c.clock=time.monotonic();c.phase='user_update_window';c.lock=threading.RLock();c.carry={};c.counts=Counter();c.events=[];c.event_limit=False
        return c
    def emit(self,c,raw,api='EncryptMessage',code=0,accepted=None):
        e=dict(kind='input',api=api,socket='ctx1',declared_bytes=len(raw),sequence=1,return_code=code,accepted_bytes=len(raw) if accepted is None and code==0 else accepted,truncated=False)
        c.message(1,{'type':'send','payload':e},raw)
    def test_never_exports_payload_query_headers(self):
        c=self.collector();raw=b'POST /path?private=never_export HTTP/1.1\r\nHost: telemetry-in.battle.net\r\nAuthorization: local_secret\r\nContent-Length: 13\r\n\r\nSYNTHETIC_CPU'
        self.emit(c,raw);s=json.dumps(c.events)
        for private in ('never_export','local_secret','SYNTHETIC_CPU','/path'):self.assertNotIn(private,s)
        self.assertTrue(c.events[0]['reference_cpu_literal_match']);self.assertEqual(c.events[0]['host_hint'],'telemetry-in.battle.net')
    def test_negative_sspi_is_not_delivery_or_success(self):
        c=self.collector();self.emit(c,b'SYNTHETIC_CPU',code=-1)
        self.assertTrue(c.events[0]['reference_cpu_literal_match']);self.assertFalse(c.events[0]['local_api_success'])
    def test_split_literal_metadata_only(self):
        c=self.collector();self.emit(c,b'SYNTHETIC_');self.emit(c,b'CPU');self.assertTrue(c.events[-1]['reference_cpu_literal_match'])
    def test_no_reference_not_false_absence(self):
        c=self.collector();c.needle=None;self.emit(c,b'anything');self.assertIsNone(c.events[0]['reference_cpu_literal_match'])
    def test_host_validation(self):
        self.assertIsNone(hostname('bad/path'));self.assertIsNone(hostname('user@host'));self.assertEqual(hostname('x.battle.net:443'),'x.battle.net')
    def test_channel_hint_is_marked(self):
        c=self.collector();self.emit(c,b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n');self.emit(c,b'body');self.assertEqual(c.events[-1]['host_evidence'],'channel_history_hint')
    def test_read_only_version_extract(self):
        with tempfile.TemporaryDirectory() as x:
            p=Path(x);b=b'Product!STRING:0|Version!STRING:0|private!STRING:0\nwow|12.1.0.69933|DO_NOT_EXPORT\n';(p/'.build.info').write_bytes(b)
            r=versions(p);self.assertEqual(r['retail_versions'],['12.1.0.69933']);self.assertNotIn('DO_NOT_EXPORT',str(r));self.assertEqual((p/'.build.info').read_bytes(),b)
    def test_detail_cap_aggregates_continue(self):
        c=self.collector();c.events=[{}]*2048;self.emit(c,b'SYNTHETIC_CPU');self.assertTrue(c.event_limit);self.assertEqual(sum(c.counts.values()),1)

class SafetyTests(unittest.TestCase):
    def test_no_user_process_lifecycle_apis(self):
        root=Path(__file__).resolve().parents[1]/'app'
        for filename in ('core.py','monitor.py'):
            tree=ast.parse((root/filename).read_text())
            forbidden={'kill','terminate','resume','suspend','spawn','enable_child_gating','CreateProcess','WriteProcessMemory'}
            for n in ast.walk(tree):
                if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute):self.assertNotIn(n.func.attr,forbidden)
    def test_no_hook_argument_or_return_modifications(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'hook.js').read_text()
        for bad in ('Interceptor.replace','Memory.write','retval.replace','this.context='):self.assertNotIn(bad,s)
    def test_no_automatic_network_upload_or_download(self):
        root=Path(__file__).resolve().parents[1]/'app'
        for f in ('core.py','monitor.py','hosts_guard.py'):
            s=(root/f).read_text()
            for bad in ('requests.post','urlopen','urllib.request','pip install','Invoke-WebRequest'):self.assertNotIn(bad,s)
    def test_limits_never_claim_zero_telemetry(self):
        self.assertFalse(LIMITS['zero_telemetry_guaranteed']);self.assertFalse(LIMITS['whole_update_completion_proven']);self.assertFalse(LIMITS['automatic_report_upload'])
    def test_failed_aggregate_api_not_accepted_as_success(self):
        from unittest.mock import patch
        c=MetadataTests().collector();MetadataTests().emit(c,b'body',code=-1)
        self.assertEqual(next(iter(c.counts))[2],False)

if __name__=='__main__':unittest.main()

class CompletionSafetyTests(unittest.TestCase):
    def test_selftest_filename_cannot_overwrite_previous_run(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'monitor.py').read_text()
        self.assertIn("'selftest-to-share-'+str(time.time_ns())",s)
    def test_hosts_restore_precedes_final_version_read(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'monitor.py').read_text()
        tail=s[s.index('    finally:\n        # Restoration'):]
        self.assertLess(tail.index('restore=guard.restore()'),tail.index("report['final_versions']=versions(root)"))
    def test_single_instance_protects_recovery(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'monitor.py').read_text();self.assertIn('CreateMutexW',s);self.assertIn('monitor_already_running_do_not_restore_hosts',s)
    def test_ready_rechecks_live_process_creation(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'core.py').read_text();ready=s[s.index('    def ready(self):'):s.index('    def close(self):')]
        self.assertIn("identity(pid)['creation']==creation",ready)

class NativeTrustTests(unittest.TestCase):
    def test_policy_matches_existing_strict_native_verification(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'authenticode_native.cs').read_text()
        self.assertIn('revocationChecks=1',s);self.assertIn('providerFlags=0x2080',s)
        self.assertIn('if(status==0) publisher=ExpectedPublisher(data.stateData)',s)
        self.assertIn('WTHelperGetProvSignerFromChain',s)
        self.assertNotIn('providerFlags=0x1000',s)
    def test_no_powershell_signature_dependency(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'core.py').read_text()
        self.assertNotIn('Get-AuthenticodeSignature',s);self.assertIn("with_name('AuthVerify.exe')",s)
