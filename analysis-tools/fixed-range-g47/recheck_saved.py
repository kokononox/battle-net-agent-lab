"""Offline-only second review of the two saved headerless Z BLTE samples.
Requires private local bytes; published hashes alone cannot reproduce payload checks.
"""
import hashlib,json,stat,zlib
from pathlib import Path
BASE=Path(__file__).resolve().parents[2];SRC=Path(__file__).resolve().parent;OUT=BASE/'reports/fixed-range-g47'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 receipt=json.loads((OUT/'fetch-evidence.json').read_text());pre=json.loads((OUT/'preflight.json').read_text());plan=json.loads((SRC/'plan.review-only.json').read_text())
 assert sha((SRC/'fetch_ranges.py').read_bytes())==receipt['source_sha256']==pre['fetch_source_sha256']
 assert sha((SRC/'codec.py').read_bytes())==receipt['codec_sha256']==pre['codec_sha256']
 assert sha((SRC/'plan.review-only.json').read_bytes())==receipt['plan_sha256']==pre['plan_sha256']
 checks=[]
 for e,r in zip(plan['entries'],receipt['results'],strict=True):
  assert r['sample_id']==e['sample_id'] and r['verified'] and r['http_status']==206
  path=BASE/'private'/(e['sample_id']+'.encoded.bin');decoded_path=BASE/'private'/(e['sample_id']+'.decoded.bin')
  for p in [path,decoded_path]:assert stat.S_IMODE(p.stat().st_mode)==0o600 and not p.is_symlink()
  b=path.read_bytes();assert len(b)==e['expected_encoded_bytes'] and b[:9]==b'BLTE\0\0\0\0Z'
  assert hashlib.md5(b).hexdigest()==e['ekey'] and sha(b)==r['encoded_sha256']
  # Deliberately independent of codec.decode_blte: only the two observed Z/no-table objects.
  z=zlib.decompressobj();d=z.decompress(b[9:],e['expected_decoded_bytes']+1)
  assert z.eof and not z.unused_data and not z.unconsumed_tail and len(d)==e['expected_decoded_bytes']
  assert hashlib.md5(d).hexdigest()==e['ckey'] and sha(d)==r['decoded_sha256'] and d==decoded_path.read_bytes()
  checks.append({'sample_id':e['sample_id'],'independent_observed_z_format_check':True,'encoded_sha256':sha(b),'decoded_sha256':sha(d),'posix_private_file_mode_0600':True})
 baseline=json.loads(Path('/data/g46/reports/archive-index-g46/runtime-catalog-unchanged.json').read_text()) if Path('/data/g46/reports/archive-index-g46/runtime-catalog-unchanged.json').exists() else json.loads((BASE/'reports/archive-index-g46/runtime-catalog-unchanged.json').read_text())
 catalog=Path('/data/g37/analysis-tools/download-broker-g37/catalog.deny-all.json')
 if not catalog.exists():catalog=BASE/'analysis-tools/download-broker-g37/catalog.deny-all.json'
 digest=sha(catalog.read_bytes());assert digest==baseline['catalog_sha256']
 out={'schema':'independent_local_recheck_g47_v1','network_requests_issued':False,'checks':checks,'source_and_plan_hashes_match_preflight':True,'production_catalog_sha256':digest,'catalog_matches_g46_baseline':True,'runtime_approved_entries':0,'payloads_executed':False,'public_payload_fixtures_published':False}
 (OUT/'independent-recheck.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
if __name__=='__main__':main()
