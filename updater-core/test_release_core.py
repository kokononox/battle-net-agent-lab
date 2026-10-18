import dataclasses,hashlib,json,unittest
from unittest.mock import patch
import release_core as c

def fixture_baseline(v='1.0.0.100',region='eu'):
 parts=v.split('.');config=('build-uid = wow\nbuild-name = WOW-'+parts[-1]+'patch'+'.'.join(parts[:3])+'_Retail\n').encode();key=hashlib.md5(config).hexdigest();info=('Active!DEC:1|Build Key!HEX:16|Version!STRING:0|Tags!STRING:0|Product!STRING:0\n1|'+key+'|'+v+'|Windows x86_64 '+region.upper()+' enUS code speech text|wow\n').encode();return c.read_baseline_bytes(info,config,c.Scope(region=region))
def tables(v='1.1.0.200',region='eu',build=None,extra=''):
 bid=v.split('.')[-1];build=build or hashlib.md5(v.encode()).hexdigest();vr=('Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16|BuildId!DEC:4|VersionsName!STRING:0\n'+region+'|'+build+'|'+'b'*32+'|'+bid+'|'+v+'\n'+extra).encode();cdn=('Name!STRING:0|Path!STRING:0|Servers!STRING:0\n'+region+'|tpr/wow|https://us.cdn.blizzard.com/?maxhosts=8&fallback=1\n').encode();return vr,cdn
def target(v='1.1.0.200',region='eu',build=None):return c.resolve(*tables(v,region,build),c.Scope(region=region))
class CoreTests(unittest.TestCase):
 def bad(self,fn,*args):
  with self.assertRaises(c.InvalidRelease):fn(*args)
 def test_new_release(self):self.assertEqual(c.decision(fixture_baseline(),target()),'new_release_detected')
 def test_future_release_not_constant(self):self.assertEqual(c.decision(fixture_baseline('18.3.0.90001'),target('18.4.0.91000')),'new_release_detected')
 def test_same_code_two_baselines(self):
  t=target('7.2.0.5000')
  for v in ['2.1.0.1200','7.1.0.4999']:self.assertEqual(c.decision(fixture_baseline(v),t),'new_release_detected')
 def test_current_build(self):
  b=fixture_baseline();self.assertEqual(c.decision(b,target(b.version,build=b.build_config)),'up_to_date_metadata_only')
 def test_current_not_health_proof(self):
  b=fixture_baseline();r=c.metadata_report(b,target(b.version,build=b.build_config),'synthetic_fixture');self.assertFalse(r['installation_ready']);self.assertIsNone(r['required_download_bytes'])
 def test_lower_build_blocked(self):self.assertEqual(c.decision(fixture_baseline('2.0.0.300'),target('2.0.0.299')),'downgrade_blocked')
 def test_lower_semver_blocked(self):self.assertEqual(c.decision(fixture_baseline('3.0.0.300'),target('2.9.0.999')),'downgrade_blocked')
 def test_same_build_other_key(self):self.assertEqual(c.decision(fixture_baseline('2.0.0.300'),target('2.0.0.300')),'same_build_republication_requires_review')
 def test_same_key_wrong_version(self):
  b=fixture_baseline();self.bad(c.decision,b,target('2.0.0.400',build=b.build_config))
 def test_other_region_rejected(self):self.bad(c.decision,fixture_baseline(),target(region='us'))
 def test_region_selection_not_largest_version(self):
  v,cdn=tables(extra='us|'+'c'*32+'|'+'d'*32+'|99999|99.0.0.99999\n');self.assertEqual(c.resolve(v,cdn,c.Scope()).version,'1.1.0.200')
 def test_us_supported_identity(self):self.assertEqual(c.decision(fixture_baseline(region='us'),target(region='us')),'new_release_detected')
 def test_other_product_rejected(self):self.bad(c.Scope,'wowt','retail','eu')
 def test_other_branch_rejected(self):self.bad(c.Scope,'wow','ptr','eu')
 def test_unknown_region_rejected(self):self.bad(c.Scope,'wow','retail','xx')
 def test_duplicate_region(self):
  v,d=tables();self.bad(c.resolve,v+v.splitlines()[-1]+b'\n',d,c.Scope())
 def test_missing_region(self):self.bad(c.resolve,*tables(region='us'),c.Scope())
 def test_build_id_conflict(self):
  v,d=tables();self.bad(c.resolve,v.replace(b'|200|',b'|201|'),d,c.Scope())
 def test_bad_key(self):
  v,d=tables(build='bad');self.bad(c.resolve,v,d,c.Scope())
 def test_bad_row_width(self):
  v,d=tables();self.bad(c.resolve,v+b'bad|row\n',d,c.Scope())
 def test_duplicate_column(self):self.bad(c.table,b'Region|Region\neu|eu\n')
 def test_table_cap(self):self.bad(c.table,b'x'*(c.CAP+1))
 def test_invalid_utf8(self):self.bad(c.table,b'\xff')
 def test_http_origin_no_fallback(self):
  v,d=tables();self.bad(c.resolve,v,d.replace(b'https:',b'http:'),c.Scope())
 def test_bad_origin_query(self):
  v,d=tables();self.bad(c.resolve,v,d.replace(b'fallback=1',b'evil=1'),c.Scope())
 def test_localhost_origin_rejected(self):self.bad(c.advertised_origins,{'Path':'tpr/wow','Servers':'https://127.0.0.1/'})
 def test_wrong_product_path(self):self.bad(c.advertised_origins,{'Path':'tpr/wowt','Servers':'https://us.cdn.blizzard.com/'})
 def test_immutable_target(self):
  t=target()
  with self.assertRaises(dataclasses.FrozenInstanceError):t.version='99.0.0.99999'
 def test_checkpoint_roundtrip(self):
  r=c.RunCheckpoint(fixture_baseline(),target());self.assertEqual(c.RunCheckpoint.restore(r.serialize()),r)
 def test_new_release_during_resume_not_retargeted(self):
  r=c.RunCheckpoint(fixture_baseline(),target());q=r.resume(r.baseline,target('1.2.0.300'));self.assertTrue(q['different_release_advertised']);self.assertFalse(q['target_automatically_replaced']);self.assertEqual(q['pinned_target']['version'],'1.1.0.200')
 def test_resume_changed_baseline_blocked(self):
  r=c.RunCheckpoint(fixture_baseline(),target());self.bad(r.resume,fixture_baseline('1.0.1.101'))
 def test_resume_same_version_changed_evidence_blocked(self):
  r=c.RunCheckpoint(fixture_baseline(),target());b=dataclasses.replace(r.baseline,info_sha256='f'*64);self.bad(r.resume,b)
 def test_checkpoint_no_downgrade(self):self.bad(c.RunCheckpoint,fixture_baseline('2.0.0.300'),target())
 def test_checkpoint_noop_not_started(self):
  b=fixture_baseline();self.bad(c.RunCheckpoint,b,target(b.version,build=b.build_config))
 def test_resume_other_scope(self):
  r=c.RunCheckpoint(fixture_baseline(),target());self.bad(r.resume,r.baseline,target(region='us'))
 def test_checkpoint_duplicate_json_key(self):self.bad(c.RunCheckpoint.restore,b'{"format":1,"format":2}')
 def test_checkpoint_unknown_format(self):
  r=c.RunCheckpoint(fixture_baseline(),target());self.bad(c.RunCheckpoint.restore,r.serialize().replace(b'dynamic-release-checkpoint-1',b'dynamic-release-checkpoint-2'))
 def test_checkpoint_extra_action_not_accepted(self):
  r=c.RunCheckpoint(fixture_baseline(),target());x=json.loads(r.serialize());x['apply']=True;self.bad(c.RunCheckpoint.restore,json.dumps(x).encode())
 def test_checkpoint_huge(self):self.bad(c.RunCheckpoint.restore,b'x'*65537)
 def test_checkpoint_invalid_json(self):self.bad(c.RunCheckpoint.restore,b'not json')
 def test_checkpoint_bad_target_key(self):
  r=c.RunCheckpoint(fixture_baseline(),target());x=json.loads(r.serialize());x['target']['build_config']='invalid';self.bad(c.RunCheckpoint.restore,json.dumps(x).encode())
 def test_transport_rejects_asset_url(self):self.bad(c.OfficialTableTransport().fetch,'https://us.cdn.blizzard.com/tpr/wow/data/aa/bb/key')
 def test_transport_redirect_rejected(self):self.bad(c.NoRedirect().redirect_request,None,None,302,'redirect',{},'https://other.example/')
 def test_private_qualifiers_not_exposed(self):
  b=fixture_baseline();self.assertNotIn('tags',b.public());self.assertNotIn('account',json.dumps(b.public()))
 def test_report_no_apply_permission(self):
  r=c.metadata_report(fixture_baseline(),target(),'synthetic_fixture');self.assertFalse(r['apply_authorized']);self.assertEqual(r['asset_requests'],0);self.assertFalse(r['target_build_config_fetched_and_verified'])
if __name__=='__main__':unittest.main()
