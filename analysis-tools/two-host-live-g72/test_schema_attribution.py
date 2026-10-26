import unittest,json,base64
from pathlib import Path
from schema_attribution import typed_header,table,load_extra_refs,products_from_refs,route_info,schemas,public_config_paths
from response_origin import locate,ResponseOrigin
BASE=Path(__file__).parent
K='0123456789abcdef0123456789abcdef'
class SchemaTests(unittest.TestCase):
 def test_real_pinned_versions_detect_case_variation(self):
  f=json.loads((BASE/'public-reference-fixtures.json').read_text())
  for p in ('agent','bna'):
   text=base64.b64decode(f[p+'-versions']).decode();t=table(text);self.assertIsNotNone(t);self.assertEqual(t[0][5],('VersionsName','STRING',0));key=t[1][0]['ProductConfig'];loc=locate(key,{},text.encode());self.assertTrue(any(x['field']=='ProductConfig' and x['match']=='exact_value' for x in loc))
 def test_extra_receipts_schema_and_public_names(self):
  r=load_extra_refs(BASE);self.assertEqual(len(r),5);self.assertTrue({'agent_beta','agent_redist'}<=products_from_refs(r));self.assertTrue(all(table(x['text']) is not None for x in r))
 def test_mixed_case_marker(self):
  self.assertEqual(typed_header('Region!string:0|VersionsName!String:0|Hash!hEx:16'),[('Region','STRING',0),('VersionsName','STRING',0),('Hash','HEX',16)])
 def test_unknown_type_rejected(self):
  self.assertEqual(typed_header('Region!STRING:0|Private!SECRET:1'),[])
 def test_public_product_route(self):
  d=route_info('/v1/products/agent_beta/versions',{'agent_beta'});self.assertEqual(d['route'],'/v1/products/agent_beta/versions')
 def test_absolute_form(self):
  d=route_info('https://us.version.battle.net/v1/products/agent_beta/versions',{'agent_beta'});self.assertEqual(d['request_target_form'],'absolute_selected_host');self.assertEqual(d['route'],'/v1/products/agent_beta/versions')
 def test_private_route_atom_not_exported(self):
  d=route_info('/v1/products/private_user_value/versions',{'agent_beta'});self.assertNotIn('private_user_value',json.dumps(d));self.assertEqual(d['route'],'<other_route>')
 def test_config_path_from_public_ProductConfig_only(self):
  refs=load_extra_refs(BASE);paths=public_config_paths(refs);self.assertTrue(paths)
  versions=next(x for x in refs if x['route']=='/v2/products/agent_beta/versions');v=table(versions['text'])[1][0];cdns=next(x for x in refs if x['route']=='/v2/products/agent_beta/cdns');c=next(x for x in table(cdns['text'])[1] if x['Name']==v['Region']);key=v['ProductConfig'];path='/'+c['ConfigPath']+'/'+key[:2]+'/'+key[2:4]+'/'+key
  self.assertTrue(any(x['version_field']=='ProductConfig' for x in paths[path]));a=ResponseOrigin(refs);a.target(key,path);self.assertTrue(a.rows[0]['whole_CDN_path_independently_public']);self.assertNotIn(key,json.dumps(a.report()))
 def test_query_is_not_same_public_path(self):
  refs=load_extra_refs(BASE);paths=public_config_paths(refs);path=next(iter(paths));key=path.rsplit('/',1)[1];a=ResponseOrigin(refs);a.target(key,path+'?private=1');self.assertFalse(a.rows[0]['whole_CDN_path_independently_public'])
 def test_schema_names_sanitized(self):
  x=schemas(b'Region!STRING:0|PrivateUserName!HEX:16\nus|'+K.encode());self.assertNotIn('PrivateUserName',json.dumps(x));self.assertNotIn(K,json.dumps(x))
 def test_fanout_mismatch_does_not_match(self):
  refs=load_extra_refs(BASE);paths=public_config_paths(refs);path=next(iter(paths));key=path.rsplit('/',1)[1];bad=path.rsplit('/',3)[0]+'/ff/ff/'+key;a=ResponseOrigin(refs);a.target(key,bad);self.assertFalse(a.rows[0]['whole_CDN_path_independently_public'])
 def test_table_hex_size_validation(self):
  self.assertIsNone(table('Region!STRING:0|Hash!HEX:16\nus|abc\n'))
 def test_marker_case_is_not_field_name_guessing(self):
  x=locate(K,{},('Region!STRING:0|VersionsName!String:0|UnknownField!HEX:16\nus|v|'+K).encode());self.assertEqual(x[0]['field'],'<other_column>')
