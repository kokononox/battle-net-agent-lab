"""Local diagnostics I/O only. No firewall, VPN or route operations."""
from pathlib import Path
import hashlib,json,os,uuid
ROOT=Path(__file__).resolve().parents[1]
def safe(path):
 p=Path(path).absolute()
 for x in (p,*p.parents):
  if x.exists() or x.is_symlink():
   st=x.lstat()
   if x.is_symlink() or getattr(st,'st_file_attributes',0)&0x400:raise ValueError('symlink_or_reparse_path_rejected')
 return p
def atomic(path,value):
 path=safe(path);tmp=path.with_name(path.name+'.next-'+uuid.uuid4().hex)
 try:
  with tmp.open('x',encoding='utf-8') as f:
   json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
 finally:
  if tmp.exists():tmp.unlink()
EXPECTED_081_MANIFEST_SHA256='a1a2ba91e2361308fc5cc15254caa4fe5180f48fa9becc492a626dfae03a70cd'
def verify():
 base=safe(ROOT/'MANIFEST-SHA256.json')
 if not base.is_file() or hashlib.sha256(base.read_bytes()).hexdigest()!=EXPECTED_081_MANIFEST_SHA256:
  raise ValueError('extract_addon_into_original_081_folder_beside_runtime_and_lab; do_not_move_or_replace_081_files')
 for manifest in (base,safe(ROOT/'DIAGNOSTIC081-SHA256.json')):
  for name,want in json.loads(manifest.read_text()).items():
   q=Path(name)
   if q.is_absolute() or '..' in q.parts:raise ValueError('invalid_manifest_path')
   if hashlib.sha256(safe(ROOT/q).read_bytes()).hexdigest()!=want:raise ValueError('package_changed:'+name)

def previous_test(config):
 # Bind to the latest non-read-only test in THIS directory. Do not search for an
 # older successful Restore when a newer unfinished/drifted test exists.
 candidates=sorted((ROOT/'private-state/coexistence-jobs').glob('*/result.json'),key=lambda p:p.stat().st_mtime,reverse=True)
 for result in candidates:
  result=safe(result)
  if result.stat().st_size>33554432:raise ValueError('previous_result_size_limit')
  value=json.loads(result.read_text('utf-8-sig'))
  if value.get('read_only') is True:continue
  if value.get('schema')!='unifiedfw-coexistence-result-1' or 'https_pacing' not in value:raise ValueError('latest_test_is_not_081_paced_coexistence')
  phases=value.get('phases',[])
  if value.get('restore_verified') is not True or not phases or not all(p.get('restored') is True and p.get('baseline_strict_equal') is True for p in phases):
   raise ValueError('previous_restore_not_verified_do_not_run_diagnostic_or_delete_journal')
  endpoint=value.get('endpoint',{})
  if endpoint.get('https_url')!=config['url'] or endpoint.get('address')!=config['address'] or endpoint.get('port')!=443:raise ValueError('use_same_endpoint_as_latest_081_test')
  request=safe(result.parent/'request.json')
  if request.stat().st_size>4194304:raise ValueError('previous_request_size_limit')
  q=json.loads(request.read_text('utf-8-sig'));programs=q.get('programs',[])
  def norm(path):return str(Path(path)).replace('/','\\').casefold()
  expected_paths={role:norm(ROOT/'runtime'/name) for role,name in [('A','python.exe'),('B','pythonw.exe')]}
  if len(programs)!=2 or {p.get('role'):norm(p.get('path','')) for p in programs}!=expected_paths:raise ValueError('runtime_paths_differ_from_previous_081_test_do_not_move_folder')
  for p in programs:
   actual=ROOT/'runtime'/('python.exe' if p['role']=='A' else 'pythonw.exe')
   if hashlib.sha256(safe(actual).read_bytes()).hexdigest()!=p.get('sha256'):raise ValueError('previous_runtime_hash_mismatch')
  return {'same_runtime_paths_as_latest_081_test':True,'same_endpoint_as_latest_081_test':True,'previous_report_sha256':hashlib.sha256(result.read_bytes()).hexdigest(),'previous_policy_restoration_verified_at_test_end':True,'previous_restoration_record_is_not_a_live_policy_check':True}
 raise ValueError('no_previous_081_coexistence_test_here; extract_addon_into_tested_081_folder')

def admit(request,output):
 request=safe(request);output=safe(output);base=safe(ROOT/'private-state/connectivity081-jobs')
 if base not in request.parents or base not in output.parents or request.parent!=output.parent or request.stat().st_size>8192:raise ValueError('request_scope_or_size')
 q=json.loads(request.read_text('utf-8-sig'))
 from https_common import https_endpoint
 from traffic_common import challenge
 if set(q)!={'url','address','challenge'}:raise ValueError('request_keys')
 https_endpoint(q['url'],q['address']);challenge(q['challenge'])
 return q,output
