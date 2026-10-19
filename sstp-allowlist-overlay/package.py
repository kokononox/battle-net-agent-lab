import hashlib,json,pathlib,zipfile
p=pathlib.Path(__file__).resolve().parent
receipt=json.loads((p/'final-build-receipt.json').read_text())
assert receipt['passed'] is True and receipt['ui_outcome']=='success'
assert receipt['source_commit']=='885cdea9622e68dbfde86ed744880efd23f4561c'
assert receipt['native']['remaining_objects']==0
payload=json.loads((p/'fourth-push.json').read_text())
source={pathlib.Path(x['path']).name:x['content'].encode() for x in payload['files'] if x['path'].startswith('sstp-allowlist-overlay/')}
runtime=['Start.cmd','Disable.cmd','Launcher.ps1','Run.ps1','ConfigCore.ps1','Policy.ps1','Preflight.ps1','Overlay.ps1','Ranges.ps1','Journal.ps1','Inventory.ps1']
files={}
for name in runtime:
 b=(p/name).read_bytes();assert b==source[name],name
 files[name]=b
files['README.fa.md']=(p/'README.fa.md').read_bytes()
files['Windows-build-receipt.json']=(p/'final-build-receipt.json').read_bytes()
manifest={'schema':'sstp-overlay-user-test-package-1','version':'0.1-test','qualified_source_commit':receipt['source_commit'],'ci_run':'https://github.com/kokononox/battle-net-agent-lab/actions/runs/'+receipt['run_id'],'files_sha256':{n:hashlib.sha256(b).hexdigest() for n,b in files.items()},'only_adds_owned_Block_rules':True,'existing_kill_switch_not_modified':True,'custom_resident_component':False,'scope':'all_RemoteAccess_interfaces','real_sstp_packet_tested':False,'outside_tunnel_protection_certified':False,'ready_for_production':False}
files['PACKAGE-MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
out=pathlib.Path('/data/Sstp-Whitelist-Test-0.1.zip')
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
 for name,b in files.items():
  info=zipfile.ZipInfo('Sstp-Whitelist-Test-0.1/'+name,date_time=(2026,10,19,19,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,b)
with zipfile.ZipFile(out) as z:
 assert len(z.namelist())==len(files)
 for name,b in files.items():assert z.read('Sstp-Whitelist-Test-0.1/'+name)==b
metadata={'filename':out.name,'size':out.stat().st_size,'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'files':len(files),'source':receipt['source_commit'],'run':receipt['run_id'],'ready_for_production':False}
(p/'package-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
print(json.dumps(metadata))
