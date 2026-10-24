"""Explicit fixed-subcategory audit changes. No firewall/hosts/payload/log deletion. Mutations never killed."""
import json,os,subprocess,sys,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from state import assert_local_tree,atomic_json,Store
from policy import PolicyError
BASE=Path(__file__).resolve().parents[1]
CONSENTS={'audit_enable':'ENABLE BLOCKED CONNECTION LOGGING','audit_restore':'RESTORE PREVIOUS AUDIT POLICY'}
def handle(store,action,payload,job):
 if action not in ('audit_status','audit_enable','audit_restore'):raise PolicyError('audit_action')
 if action in CONSENTS and payload.get('confirmation')!=CONSENTS[action]:raise PolicyError('explicit_audit_confirmation_required')
 if os.name!='nt':raise PolicyError('audit_requires_Windows_explicit_Administrator')
 lab=str(BASE/'lab')
 if lab not in sys.path:sys.path.insert(0,lab)
 from console import verify_package
 verify_package()
 request=assert_local_tree(job/'audit-request.json');out=assert_local_tree(job/'audit-result.json')
 atomic_json(request,dict(action=action[6:],confirmation=payload.get('confirmation','')))
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 args=[str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/audit-worker.ps1'),'-Action',action[6:],'-Output',str(out)]
 if action in CONSENTS:args+=['-Confirmation',CONSENTS[action]]
 with (job/'audit-stdout.txt').open('wb') as stdout,(job/'audit-error.txt').open('wb') as stderr:
  code=subprocess.run(args,stdout=stdout,stderr=stderr,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)).returncode
 if not out.is_file() or out.stat().st_size>65536:raise PolicyError('audit_response_missing_or_large; change_unknown_use_audit_recovery_no_retry')
 result=json.loads(out.read_text('utf-8-sig'))
 if code or result.get('ok') is not True:raise PolicyError(str(result.get('error','audit_worker_failed'))+'; audit_change_unknown_use_status_not_retry')
 return dict(audit=result['audit'],firewall_changed=False,hosts_changed=False)
def recovery():
 print('Explicit Administrator. Audit policy only; native rules/hosts unchanged. No automatic changes.')
 action=input('Type STATUS, RESTOREAUDIT, or EXIT: ').strip()
 if action=='EXIT':return
 a={'STATUS':'audit_status','RESTOREAUDIT':'audit_restore'}.get(action)
 if not a:raise PolicyError('unknown_command')
 p={}
 if a in CONSENTS:
  print('System-wide logging may stop. Restore only previous receipt; external identical writes cannot be detected.')
  p['confirmation']=input('Type '+CONSENTS[a]+': ')
 job=assert_local_tree(BASE/'private-state/jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
 print(json.dumps(handle(Store(BASE/'private-state'),a,p,job),ensure_ascii=False,indent=2))
if __name__=='__main__':
 try:recovery()
 except Exception as e:print('ERROR:',e)
 input('Press Enter to close. Keep protected audit receipt.')
