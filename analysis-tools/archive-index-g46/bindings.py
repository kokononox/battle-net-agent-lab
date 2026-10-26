"""Offline receipt/plan/source bindings. No network fallback."""
import hashlib,json,base64
from pathlib import Path
from pins import PLAN_SHA256
SAMPLE_PLAN_SHA256='7c29f72b27d00e8f82304c2a6b528811ebd54d40a3f06c78cabfdaaeaab7da47'
def sha(b):return hashlib.sha256(b).hexdigest()
def validate(base,root,receipt):
 src=base/'analysis-tools/archive-index-g46';out=base/'reports/archive-index-g46'
 raw=(src/'index-plan.review-only.json').read_bytes();sample=(root/'analysis-tools/sample-download-g45/plan.review-only.json').read_bytes()
 pre=json.loads((out/'preflight.json').read_text());plan=json.loads(raw)
 if sha(raw)!=PLAN_SHA256 or sha(sample)!=SAMPLE_PLAN_SHA256 or receipt['plan_sha256']!=PLAN_SHA256 or pre['plan_sha256']!=PLAN_SHA256:raise ValueError('plan_binding')
 if receipt['source_sha256']!=pre['fetch_source_sha256'] or sha((src/'fetch_indices.py').read_bytes())!=receipt['source_sha256'] or sha((src/'http_contract.py').read_bytes())!=pre['http_contract_sha256']:raise ValueError('source_binding')
 if len(receipt['results'])!=46 or receipt['reserved_attempts']!=46 or receipt['reserved_expected_bytes']!=623408 or sum(x['expected_bytes'] for x in plan['entries'])!=623408:raise ValueError('budget_binding')
 for r,p in zip(receipt['results'],plan['entries'],strict=True):
  if any(r[k]!=p[k] for k in ('id','kind','archive_or_index_key','expected_bytes')) or r['url']!=p['proposed_url']:raise ValueError('row_binding')
 return json.loads(sample)['entries']
def snapshot(base,r):
 name=r['snapshot_name']
 if Path(name).name!=name or name!=r['id']+'.bin':raise ValueError('snapshot_name')
 path=base/'public-indices'/name
 if path.exists():b=path.read_bytes()
 else:
  f=json.loads((base/'reports/archive-index-g46/public-index-fixtures.json').read_text())['objects'][r['id']]
  if f['key']!=r['archive_or_index_key'] or f['kind']!=r['kind'] or f['sha256']!=r['sha256']:raise ValueError('fixture_binding')
  b=base64.b64decode(f['base64'],validate=True)
 if len(b)!=r['expected_bytes'] or len(b)!=r['bytes'] or sha(b)!=r['sha256']:raise ValueError('receipt_binding')
 return b
