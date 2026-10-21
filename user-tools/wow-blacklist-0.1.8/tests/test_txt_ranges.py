import ipaddress,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import backend
from backend import Manager,parse_list,format_list,BlacklistError,BASE,spec
import test_manager as tm
import test_real_powershell as tp
from test_real_powershell import MOCKS,quoted,PS

class NetworkParsing(unittest.TestCase):
 def test_public_cidr_roundtrip(self):
  r=parse_list('2.0.0.0/8:80 TCP\n1.1.1.0/24:443 UDP\n[2606:4700::/32]:53 TCP')
  self.assertEqual(parse_list(format_list(r)),r);self.assertEqual(r[0]['ip'],'2.0.0.0/8')
 def test_host_prefix_preserves_existing_rule_identity(self):
  self.assertEqual(parse_list('1.1.1.1/32:443 TCP'),parse_list('1.1.1.1:443 TCP'))
  self.assertEqual(parse_list('[2606:4700::1111/128]:80 TCP'),parse_list('[2606:4700::1111]:80 TCP'))
 def test_no_silent_network_expansion(self):
  for value in ('2.19.198.11/8','1.1.1.1/24','[2606:4700::1111/32]'):
   with self.subTest(value=value),self.assertRaises(BlacklistError):parse_list(value+':80 TCP')
 def test_special_use_overlap_rejected(self):
  for value in ('0.0.0.0/0','8.0.0.0/6','100.0.0.0/8','192.0.0.0/8','224.0.0.0/4','[::/0]','[2000::/3]','[2001:db8::/32]'):
   with self.subTest(value=value),self.assertRaises(BlacklistError):parse_list(value+':80 TCP')
 def test_invalid_prefix_or_syntax_rejected(self):
  for value in ('2.0.0.0/33','2.0.0.0/-1','2.*.*.*','2.0.0.0-2.255.255.255','[2606:4700::/129]'):
   with self.subTest(value=value),self.assertRaises(BlacklistError):parse_list(value+':80 TCP')
 def test_network_exact_host_not_deduplicated_incorrectly(self):
  self.assertEqual(len(parse_list('2.0.0.0/8:80 TCP\n2.0.0.0:80 TCP\n2.0.0.0/8:80 tcp')),2)

class TxtAndRangeManager(unittest.TestCase):
 setUp=tm.ManagerTests.setUp
 tearDown=tm.ManagerTests.tearDown
 def test_first_load_creates_real_txt(self):
  self.assertTrue(self.m.text_path.exists());self.assertEqual(parse_list(self.m.text_path.read_text()),parse_list(self.m.config()['text']))
 def test_save_apply_delete_and_restore_write_txt(self):
  self.m.run('save',self.payload);self.assertEqual(parse_list(self.m.text_path.read_text()),parse_list(self.payload['text']));self.assertFalse(self.actual)
  self.m.run('apply',{**self.payload,'text':'1.1.1.1:443 TCP'});self.assertEqual(self.m.text_path.read_text(),'1.1.1.1:443 TCP\n')
  self.m.run('restore');self.assertEqual(self.m.text_path.read_text(),'1.1.1.1:443 TCP\n')
 def test_empty_explicit_restore_clears_txt(self):
  self.m.run('apply',{**self.payload,'text':'','empty_restore_consent':True});self.assertEqual(self.m.text_path.read_text(),'')
 def test_legacy_json_migrates_without_rule_changes(self):
  self.m.run('save',self.payload);owner=self.m.owner();self.m.text_path.unlink();self.calls.clear();self.m.run('load')
  self.assertEqual(self.m.owner(),owner);self.assertEqual(parse_list(self.m.text_path.read_text()),parse_list(self.payload['text']));self.assertEqual([p['action'] for p in self.calls],['status'])
 def test_external_txt_edits_loaded_but_not_applied(self):
  self.m.text_path.write_text('\ufeff2.0.0.0/8:80 TCP\n');self.calls.clear();result=self.m.run('load')
  self.assertEqual(result['config']['text'],'2.0.0.0/8:80 TCP');self.assertEqual(self.actual,{});self.assertEqual([p['action'] for p in self.calls],['status'])
 def test_invalid_txt_fails_without_mutating_firewall(self):
  self.m.text_path.write_text('bad entry');self.calls.clear()
  with self.assertRaises(BlacklistError):self.m.run('load')
  self.assertEqual(self.calls,[]);self.assertEqual(self.m.text_path.read_text(),'bad entry')
 def test_restore_available_with_invalid_txt_and_preserves_it(self):
  self.m.run('apply',self.payload);self.m.text_path.write_text('bad entry');r=self.m.run('restore')
  self.assertEqual(self.actual,{});self.assertTrue(r['settings_preserved']);self.assertEqual(self.m.text_path.read_text(),'bad entry')
 def test_backup_txt_preserved(self):
  before=self.m.text_path.read_text();self.m.run('save',self.payload);self.assertEqual((self.m.private/'blacklist.previous.txt').read_text(),before)
 def test_apply_keeps_previous_different_txt_backup(self):
  before=self.m.text_path.read_text();self.m.run('apply',self.payload)
  self.assertEqual((self.m.private/'blacklist.previous.txt').read_text(),before)
 def test_write_failure_prevents_firewall_mutation(self):
  self.calls.clear()
  with patch.object(backend,'atomic_text',side_effect=OSError('fixture')),self.assertRaises(OSError):self.m.run('apply',self.payload)
  self.assertEqual(self.calls,[])
 def test_network_requires_exact_true_extra_consent(self):
  p={**self.payload,'text':'2.0.0.0/8:80 TCP'}
  for value in (None,False,1,'yes'):
   with self.subTest(value=value),self.assertRaises(BlacklistError):self.m.run('apply',{**p,'range_consent':value})
  self.assertEqual(self.calls,[]);self.m.run('apply',{**p,'range_consent':True});self.assertEqual(next(iter(self.actual.values()))['ip'],'2.0.0.0/8')
 def test_network_can_be_saved_without_applying(self):
  self.m.run('save',{**self.payload,'text':'2.0.0.0/8:80 TCP'});self.assertFalse(self.calls);self.assertEqual(self.m.text_path.read_text(),'2.0.0.0/8:80 TCP\n')
 def test_range_cannot_bypass_known_login_warning(self):
  p={**self.payload,'text':'37.244.29.0/24:3724 TCP','range_consent':True}
  with self.assertRaisesRegex(BlacklistError,'known_login'):self.m.run('apply',p)
  self.assertFalse(self.calls);self.m.run('apply',{**p,'critical_consent':True});self.assertEqual(len(self.actual),1)

@unittest.skipUnless(PS,'PowerShell runtime required')
class RealRangePowerShell(unittest.TestCase):
 env=tp.RealPowerShell.env
 runps=tp.RealPowerShell.runps
 def test_ui_cidr_roundtrip_boundary_and_contains(self):
  model=quoted(BASE/'app/ui-model.ps1')
  code=". ([scriptblock]::Create([IO.File]::ReadAllText('"+model+"')));$rows=@(Ui-Parse ('2.0.0.0/8:80 TCP`n[2606:4700::/32]:53 UDP'.Replace('`n',[Environment]::NewLine)));if($rows.Count -ne 2 -or (Ui-Text $rows) -notlike '*2.0.0.0/8:80 TCP*'){throw 'roundtrip'};if(!(Ui-Contains $rows[0] '2.19.198.11') -or (Ui-Contains $rows[0] '3.19.198.11')){throw 'contains'};$bad=$false;try{Ui-Parse '2.19.198.11/8:80 TCP'}catch{$bad=$true};if(!$bad){throw 'boundary'}"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'))
 def test_firewall_cidr_apply_readback_update_and_restore(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');owner='d'*32
   entries=parse_list('2.0.0.0/8:80 TCP\n[2606:4700::/32]:53 UDP');plans=[]
   for action,items in [('apply',entries),('status',entries),('apply',entries[1:]),('restore',[])]:
    p=root/(str(len(plans))+'.json');p.write_text(json.dumps(dict(owner=owner,program=str(exe),action=action,entries=[spec(owner,str(exe),e) for e in items])));plans.append(p)
   code=MOCKS+"\n$global:store['Unrelated']=[pscustomobject]@{Name='Unrelated';Group='Unrelated'}\n"
   for i,p in enumerate(plans):
    if i==1:code+="$global:store['"+spec(owner,str(exe),entries[0])['name']+"'].IP='2.0.0.0/255.0.0.0'\n"
    code+="$env:WOW_BL_REQUEST='"+quoted(p)+"';& ([scriptblock]::Create([IO.File]::ReadAllText('"+quoted(BASE/'app/firewall.ps1')+"')))\n"
   code+="if($global:store.Count -ne 1 -or $global:adds -ne 2 -or $global:removes -ne 2){throw 'restore_invariant'}"
   r=self.runps(code);self.assertEqual(r.returncode,0,r.stdout.decode(errors='replace')+r.stderr.decode(errors='replace'));rows=[json.loads(x) for x in r.stdout.decode('utf-8-sig').splitlines() if x.startswith('{')];self.assertTrue(rows[1]['entries'][0]['active_verified']);self.assertTrue(rows[3]['absence_verified'])

if __name__=='__main__':unittest.main()
