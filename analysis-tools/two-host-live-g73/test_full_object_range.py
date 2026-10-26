import unittest,json,base64,hashlib
from pathlib import Path
from download_path_audit import Reference,range_semantics,classify,load_reference,full_object_size

DL='public_download_manifest_entry'; EN='public_encoding_EKey_entry'
class T(unittest.TestCase):
 def setUp(self):
  self.path='/tpr/agent/data/ab/cd/abcdef0123456789abcdef0123456789'
  self.refs=Reference({self.path:[{'kind':k,'product':'agent','public_encoded_bytes':100} for k in (DL,EN)]})
 def result(self,value='bytes=0-99',path=None,refs=None):
  return range_semantics(path or self.path,[value],refs if refs is not None else self.refs)
 def test_exact_whole_object_no_raw_value(self):
  r=self.result();self.assertTrue(r['exact_public_boundary_match'])
  self.assertEqual(r['public_boundary_basis'],['entire_public_object_DL_EN_size_agreement'])
  self.assertFalse(r['fingerprinting_absence_proven']);self.assertNotIn('bytes=0-99',json.dumps(r))
 def test_prefix_suffix_overrun_and_unsupported_negative(self):
  for v in ['bytes=0-98','bytes=1-99','bytes=0-100','bytes=0-','bytes=-100','bytes=0-99,101-102','bytes=99-0']:
   self.assertFalse(self.result(v)['exact_public_boundary_match'],v)
  self.assertFalse(range_semantics(self.path,['bytes=0-99']*2,self.refs)['exact_public_boundary_match'])
 def test_bad_or_conflicting_sizes_negative(self):
  for bad in [True,100.0,'100',0,-1,101,2**63,None]:
   r=Reference({self.path:[dict(x) for x in self.refs[self.path]]});r[self.path][1]['public_encoded_bytes']=bad
   self.assertFalse(self.result(refs=r)['exact_public_boundary_match'],repr(bad))
 def test_both_formats_same_product_required(self):
  for rows in [self.refs[self.path][:1],self.refs[self.path][1:],
               [self.refs[self.path][0],dict(self.refs[self.path][1],product='bna')]]:
   self.assertFalse(self.result(refs={self.path:rows})['exact_public_boundary_match'])
 def test_exact_path_and_query_required(self):
  for path in [self.path+'?id=SECRET',self.path+'/',self.path.replace('/ab/','/ef/'),self.path.replace('/data/','/%64ata/')]:
   out=classify(path,'GET',{'range':['bytes=0-99']},b'',self.refs)
   self.assertFalse(out['range_semantics']['exact_public_boundary_match']);self.assertNotIn('SECRET',json.dumps(out))
 def test_existing_structural_reference_has_precedence(self):
  self.refs.ranges={self.path:{'ranges':[{'start':0,'end':7,'basis':'BLTE_complete_header_and_chunk_table'}]}}
  self.assertFalse(self.result()['exact_public_boundary_match'])
  self.assertTrue(self.result('bytes=0-7')['exact_public_boundary_match'])
  out=classify(self.path+'?x=SECRET','GET',{'range':['bytes=0-7']},b'',self.refs)
  self.assertFalse(out['range_semantics']['exact_public_boundary_match'])
 def test_public_DL_EN_bytes_independently_reconstructed(self):
  from public_codecs import decode_blte,parse_download
  from reference_encoding import parse_encoding
  base=Path(__file__).parent;refs,_=load_reference(base)
  fixtures={k:base64.b64decode(v) for k,v in json.loads((base/'public-reference-fixtures.json').read_text()).items()}
  common_total=0
  for product in ('agent','bna'):
   build=dict(line.split(' = ',1) for line in fixtures[product+'-build'].decode().splitlines() if line and not line.startswith('#'))
   lines=[x for x in fixtures[product+'-cdns'].decode().splitlines() if x and not x.startswith('#')]
   names=[x.split('!')[0] for x in lines[0].split('|')]
   cdn=next(dict(zip(names,line.split('|'))) for line in lines[1:] if line.split('|')[0]=='us')
   parsed={}
   for field,parser,label in [('download',parse_download,'entries'),('encoding',parse_encoding,'ekey_specs')]:
    ck,ek=build[field].split();decoded_size,encoded_size=map(int,build[field+'-size'].split())
    blob=fixtures[product+'-'+field+'-manifest'];self.assertEqual(len(blob),encoded_size)
    decoded=decode_blte(blob,decoded_size,ek);self.assertEqual(hashlib.md5(decoded).hexdigest(),ck)
    parsed[field]={r['ekey']:r['encoded_bytes'] for r in parser(decoded)[label]}
   for key in parsed['download'].keys() & parsed['encoding'].keys():
    size=parsed['download'][key];self.assertEqual(size,parsed['encoding'][key])
    path='/'+cdn['Path']+'/data/'+key[:2]+'/'+key[2:4]+'/'+key
    self.assertEqual(full_object_size(path,refs),size)
    for kind in (DL,EN):
     values={r['public_encoded_bytes'] for r in refs[path] if r['kind']==kind and r['product']==product}
     self.assertEqual(values,{size})
    if not getattr(refs,'ranges',{}).get(path):
     self.assertTrue(range_semantics(path,['bytes=0-'+str(size-1)],refs)['exact_public_boundary_match'])
    common_total+=1
  self.assertEqual(common_total,993)
