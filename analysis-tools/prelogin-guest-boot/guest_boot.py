"""Owned ephemeral Windows guest install/reboot control. No Battle.net or NIC.
Only typed challenge-validated booleans escape the temporary guest directory.
"""
import json,os,re,secrets,shutil,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'prelogin-windows-guest'))
import prepare_guest as media
STAGES={'guard','capacity','tools','media','seed','qemu','monitor','completed'}
ERRORS={None,'guard_failed','capacity_insufficient','apt_failed','download_failed','media_hash_mismatch','media_size_mismatch','firmware_missing','guest_timeout','qemu_failed','guest_control_failed','media_boot_catalog_failed','firmware_boot_failed','bounded_guest_failed'}
BOOLEANS={'full_windows','baseline_saved','boot_changed','same_profile','dpapi_ok','marker_equal','error'}
MIN_FREE=50*1024**3

def blank(source,run):
 return dict(schema='bnet-owned-guest-boot-3',source_commit=source,run_id=run,status='stopped',stage='guard',error_code=None,official_media_pinned=False,kvm_enabled=False,first_signal=False,second_signal=False,full_windows_boot_verified=False,same_guest_reboot_verified=False,same_profile_verified=False,dpapi_roundtrip_verified=False,owned_marker_preserved=False,serial_challenge_verified=False,disk_free_before_bytes=0,disk_free_after_cleanup_bytes=0,disk_free_final_bytes=0,disk_virtual_bytes=media.DISK_BYTES,disk_actual_bytes=None,winpe_signal=False,boot_catalog_checked=False,uefi_catalog_entry_seen=False,bios_catalog_entry_seen=False,efi_launch_attempts=0,firmware_observations=[],visual_checks=[],cleanup_labels=[],target_launched=False,battle_net_uuid_reboot_tested=False,network_after_reboot_verified=False,guest_nic_present=False,remote_access_enabled=False,private_disks_exported=False,private_identifiers_exported=False,disk_persisted=False)

def validate(r):
 if type(r) is not dict or set(r)!=set(blank('','')) or r['schema']!='bnet-owned-guest-boot-3':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if r['stage'] not in STAGES or r['error_code'] not in ERRORS or r['status'] not in {'stopped','owned_windows_reboot_verified'}:raise ValueError('enums')
 for key,value in blank('','').items():
  if type(value) is bool and type(r[key]) is not bool:raise ValueError('boolean')
 for key in ('disk_free_before_bytes','disk_free_after_cleanup_bytes','disk_free_final_bytes','disk_virtual_bytes'):media.number(r[key])
 if r['disk_actual_bytes'] is not None:media.number(r['disk_actual_bytes'])
 media.number(r['efi_launch_attempts'],4)
 if type(r['firmware_observations']) is not list or len(r['firmware_observations'])>len(FIRMWARE_OBSERVATIONS) or len(r['firmware_observations'])!=len(set(r['firmware_observations'])) or not set(r['firmware_observations'])<=FIRMWARE_OBSERVATIONS:raise ValueError('firmware_observations')
 if type(r['visual_checks']) is not list or len(r['visual_checks'])>8:raise ValueError('visual_checks')
 for v in r['visual_checks']:
  if type(v) is not dict or set(v)!={'second','state'} or type(v['second']) is not int or not 0<=v['second']<=2600 or v['state'] not in VISUAL_STATES:raise ValueError('visual_state')
 if r['disk_virtual_bytes']!=media.DISK_BYTES or type(r['cleanup_labels']) is not list or len(r['cleanup_labels'])!=len(set(r['cleanup_labels'])) or not set(r['cleanup_labels'])<=set(media.CLEANUP):raise ValueError('capacity')
 for key in ('target_launched','battle_net_uuid_reboot_tested','network_after_reboot_verified','guest_nic_present','remote_access_enabled','private_disks_exported','private_identifiers_exported','disk_persisted'):
  if r[key] is not False:raise ValueError('scope')
 if r['same_guest_reboot_verified'] and not all(r[key] for key in ('first_signal','second_signal','full_windows_boot_verified','same_profile_verified','dpapi_roundtrip_verified','owned_marker_preserved','serial_challenge_verified')):raise ValueError('reboot_gate')
 if r['status']=='owned_windows_reboot_verified' and not(r['stage']=='completed' and r['error_code'] is None and r['official_media_pinned'] and r['kvm_enabled'] and r['same_guest_reboot_verified']):raise ValueError('ready_gate')
 return r

def signal(line,challenge):
 if len(line)>8192 or not line.startswith('LABGUEST:'):return None
 try:r=json.loads(line[len('LABGUEST:'):])
 except (ValueError,TypeError):return None
 if type(r) is not dict or set(r)!={'schema','challenge','phase'}|BOOLEANS or r['schema']!='owned-guest-signal-1' or r['phase'] not in {'first','second'}:return None
 if not isinstance(r['challenge'],str) or not secrets.compare_digest(r['challenge'],challenge) or any(type(r[k]) is not bool for k in BOOLEANS):return None
 return {key:r[key] for key in BOOLEANS|{'phase'}}

def receipt(source,run,phase,tests='unknown',prepare='unknown',sanitize='unknown'):
 if not re.fullmatch('[a-f0-9]{40}',source) or not re.fullmatch('[0-9]{1,30}',run) or phase not in {'dispatched','completed'} or any(x not in {'unknown','success','failure','cancelled','skipped'} for x in (tests,prepare,sanitize)):raise ValueError('receipt')
 return dict(schema='bnet-owned-guest-ci-1',source_commit=source,run_id=run,phase=phase,tests=tests,preparation=prepare,sanitization=sanitize)

def answer(password,challenge="a"*64):
 from xml.sax.saxutils import escape
 first="powershell.exe -NoProfile -Command \"$d=(Get-Volume | Where-Object {$_.FileSystemLabel -eq 'LABSEED'} | Select-Object -First 1).DriveLetter; & ($d+':\\probe.ps1')\""
 pe = 'cmd /c "mode com1: baud=115200 parity=n data=8 stop=1 >nul 2>&1 & echo LABPE:'+challenge+r' >\\.\COM1"'
 return '''<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
<settings pass="windowsPE"><component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage><InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component>
<component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>'''+escape(pe)+'''</Path></RunSynchronousCommand></RunSynchronous><DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk><CreatePartitions><CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition><CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition><CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition></CreatePartitions><ModifyPartitions><ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition><ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition></ModifyPartitions></Disk><WillShowUI>OnError</WillShowUI></DiskConfiguration><ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>2</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI></OSImage></ImageInstall><UserData><AcceptEula>true</AcceptEula><FullName>Owned Guest Lab</FullName><Organization>Local Evaluation</Organization></UserData></component></settings>
<settings pass="specialize"><component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><ComputerName>OWNED-GUEST</ComputerName><TimeZone>UTC</TimeZone></component></settings>
<settings pass="oobeSystem"><component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component><component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>1</ProtectYourPC></OOBE><UserAccounts><AdministratorPassword><Value>'''+escape(password)+'''</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts><AutoLogon><Password><Value>'''+escape(password)+'''</Value><PlainText>true</PlainText></Password><Username>Administrator</Username><Enabled>true</Enabled><LogonCount>3</LogonCount></AutoLogon><FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><Description>Owned guest reboot control</Description><CommandLine>'''+escape(first)+'''</CommandLine></SynchronousCommand></FirstLogonCommands></component></settings></unattend>'''

def guard():
 return sys.platform.startswith('linux') and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')=='refs/heads/research/prelogin-telemetry-wow-data-provenance' and os.environ.get('BNET_GUEST_BOOT')=='owned-guest-boot-e4'

VISUAL_STATES={'blank_or_unknown','boot_prompt','uefi_shell','boot_failure','setup_error','edition_picker','license_page','disk_picker','setup_start','install_progress','oobe_or_logon','desktop','capture_failed'}
def classify(text):
 t=' '.join(text.lower().split())
 rules=[('boot_prompt',('press any key',)),('uefi_shell',('uefi interactive shell','shell>')),('boot_failure',('no bootable','boot failed','failed to load boot','start pxe')),('setup_error',('windows could not','windows cannot','error code','encountered an unexpected error')),('edition_picker',('operating system you want','select the operating system')),('license_page',('license terms','applicable notices')),('disk_picker',('where do you want to install','select location to install')),('setup_start',('install now',)),('install_progress',('installing windows','getting files ready','copying windows files','getting ready')),('oobe_or_logon',('administrator','customize settings')),('desktop',('server manager','recycle bin'))]
 for state,terms in rules:
  if any(term in t for term in terms):return state
 return 'blank_or_unknown'
FIRMWARE_OBSERVATIONS={'security_violation','unsupported','not_found','no_mapping','fs_mapping_seen'}
def observe_firmware(text):
 t=' '.join(text.lower().split());result=set()
 for label,phrase in [('security_violation','security violation'),('unsupported','unsupported'),('not_found','not found'),('no_mapping','no mapping')]:
  if phrase in t:result.add(label)
 if re.search(r'\bfs[0-7]\s*:',t):result.add('fs_mapping_seen')
 return result

def check_catalog(iso,r):
 try:
  raw=subprocess.check_output(['xorriso','-indev',str(iso),'-report_el_torito','plain'],stderr=subprocess.STDOUT,timeout=60)
  if len(raw)>65536:raise ValueError('large')
  text=raw.decode('utf-8',errors='replace');platforms=set(re.findall(r'El Torito boot img\s*:\s*\d+\s+(BIOS|UEFI)\s+y\b',text))
  r['boot_catalog_checked']=True;r['uefi_catalog_entry_seen']='UEFI' in platforms;r['bios_catalog_entry_seen']='BIOS' in platforms
 except Exception:raise media.ProbeError('media_boot_catalog_failed')

def send_codes(q,codes):
 q.stream.write((json.dumps({'execute':'send-key','arguments':{'keys':[{'type':'qcode','data':x} for x in codes],'hold-time':10}})+'\n').encode())
 for _ in range(32):
  reply=q.read()
  if 'error' in reply:raise media.ProbeError('qemu_failed')
  if 'return' in reply:time.sleep(.04);return
 raise media.ProbeError('qemu_failed')
def shell_command(q,text):
 # Internal fixed commands only; no user or OCR input is executed.
 for char in text:
  if char==':':codes=['shift','semicolon']
  elif char in {'\\','.', ' ', '-'}:codes=[{'\\':'backslash','.':'dot',' ':'spc','-':'minus'}[char]]
  elif char in 'abcdefghijklmnopqrstuvwxyz0123456789':codes=[char]
  else:raise ValueError('fixed_shell_alphabet')
  send_codes(q,codes)
 send_codes(q,['ret'])
def launch_efi(q,index):
 if type(index) is not int or not 0<=index<=3:raise ValueError('fixed_efi_index')
 send_codes(q,['ret'])
 if index==0:shell_command(q,'map -r');time.sleep(1)
 shell_command(q,'fs'+str(index)+r':\efi\boot\bootx64.efi')
 for _ in range(3):time.sleep(1);send_space(q)

def visual(q,work,log,r=None):
 # Never publish the screenshot or OCR text; fixed, conservative UI labels only.
 image=work/'screen.private.ppm'
 try:
  q.stream.write((json.dumps({'execute':'screendump','arguments':{'filename':str(image)}})+'\n').encode())
  for _ in range(32):
   reply=q.read()
   if 'error' in reply:raise ValueError('capture')
   if 'return' in reply:break
  else:raise ValueError('capture')
  raw=subprocess.check_output(['tesseract',str(image),'stdout','-l','eng'],stderr=log,timeout=30)
  if len(raw)>65536:return 'capture_failed'
  text=raw.decode('utf-8',errors='replace')
  if r is not None:r['firmware_observations']=sorted(set(r['firmware_observations'])|observe_firmware(text))
  return classify(text)
 except Exception:return 'capture_failed'
 finally:
  if image.exists():image.unlink()

def send_space(q):
 q.stream.write(b'{"execute":"send-key","arguments":{"keys":[{"type":"qcode","data":"spc"}]}}\n')
 for _ in range(32):
  reply=q.read()
  if 'error' in reply:raise media.ProbeError('qemu_failed')
  if 'return' in reply:return
 raise media.ProbeError('qemu_failed')

def qemu_args(code,vars,disk,iso,seed,serial,qmp):
 return ['qemu-system-x86_64','-accel','kvm','-machine','q35','-cpu','host','-smp','2','-m','4096','-display','none','-nic','none',
 '-drive',f'if=pflash,format=raw,readonly=on,file={code}','-drive',f'if=pflash,format=raw,file={vars}',
 '-drive',f'file={disk},format=qcow2,if=none,id=owned_disk','-device','ide-hd,drive=owned_disk,bus=ide.0,bootindex=2',
 '-drive',f'file={iso},format=raw,media=cdrom,readonly=on,if=none,id=owned_setup','-device','ide-cd,drive=owned_setup,bus=ide.1,bootindex=1',
 '-drive',f'file={seed},format=raw,media=cdrom,readonly=on,if=none,id=owned_seed','-device','ide-cd,drive=owned_seed,bus=ide.2',
 '-serial',f'file:{serial}','-qmp',f'unix:{qmp},server=on,wait=off']

def guest(work,iso,seed,disk,challenge,r,log):
 code=Path('/usr/share/OVMF/OVMF_CODE_4M.fd');template=Path('/usr/share/OVMF/OVMF_VARS_4M.fd')
 if not code.is_file() or not template.is_file():raise media.ProbeError('firmware_missing')
 vars=work/'vars.fd';shutil.copyfile(template,vars)
 qmp=work/'qmp.sock';serial=work/'serial.private';p=None;q=None
 try:
  args=qemu_args(code,vars,disk,iso,seed,serial,qmp)
  p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
  for _ in range(200):
   if qmp.exists():break
   if p.poll() is not None:raise media.ProbeError('qemu_failed')
   time.sleep(.1)
  q=media.QMP(qmp);r['kvm_enabled']=q.execute('query-kvm').get('enabled') is True
  if not r['kvm_enabled']:raise media.ProbeError('qemu_failed')
  r['stage']='monitor';started=time.monotonic();offset=0;buffer='';first=None;second=None;keys_sent=set();views_done=set()
  while time.monotonic()-started<2400:
   elapsed=time.monotonic()-started
   # Only early firmware "press a key to boot DVD"; no subsequent UI automation.
   for moment in (5,10,15):
    if elapsed>=moment and moment not in keys_sent:
     send_space(q);keys_sent.add(moment)
   for moment in (30,60,90,120,300,600,1200,2300):
    if elapsed>=moment and moment not in views_done:
     state=visual(q,work,log,r);r['visual_checks'].append({'second':int(elapsed),'state':state});views_done.add(moment)
     if state=='uefi_shell' and r['efi_launch_attempts']<4 and not r['winpe_signal']:
      launch_efi(q,r['efi_launch_attempts']);r['efi_launch_attempts']+=1
     if elapsed>=180 and r['efi_launch_attempts']==4 and len(r['visual_checks'])>=2 and all(x['state']=='uefi_shell' for x in r['visual_checks'][-2:]) and not r['winpe_signal']:raise media.ProbeError('firmware_boot_failed')
   if serial.exists():
    if serial.stat().st_size>1048576:raise media.ProbeError('guest_control_failed')
    with serial.open('rb') as incoming:incoming.seek(offset);chunk=incoming.read(65536);offset=incoming.tell()
    buffer+=chunk.decode('utf-8',errors='replace')
    lines=buffer.split('\n');buffer=lines.pop()[-8192:]
    for line in lines:
     if line.strip()=='LABPE:'+challenge:r['winpe_signal']=True
     s=signal(line.strip(),challenge)
     if s is None:continue
     r['serial_challenge_verified']=True
     if s['error']:raise media.ProbeError('guest_control_failed')
     if s['phase']=='first':first=s;r['first_signal']=True;r['full_windows_boot_verified']=s['full_windows']
     if s['phase']=='second':second=s;r['second_signal']=True
   if first and second:
    r.update(same_profile_verified=second['same_profile'],dpapi_roundtrip_verified=second['dpapi_ok'],owned_marker_preserved=second['marker_equal'])
    r['same_guest_reboot_verified']=all(first[k] for k in ('full_windows','baseline_saved')) and all(second[k] for k in ('full_windows','baseline_saved','boot_changed','same_profile','dpapi_ok','marker_equal'))
    if not r['same_guest_reboot_verified']:raise media.ProbeError('guest_control_failed')
    return
   if p.poll() is not None:raise media.ProbeError('guest_control_failed')
   time.sleep(2)
  raise media.ProbeError('guest_timeout')
 finally:
  if q:
   try:q.execute('quit')
   except Exception:pass
   q.close()
  if p and p.poll() is None:
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)

def main():
 r=blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);out=Path('output');out.mkdir(exist_ok=True);workspace=Path(os.environ['GITHUB_WORKSPACE']).resolve()
 try:
  if not guard():raise media.ProbeError('guard_failed')
  r['stage']='capacity';media.MIN_FREE=MIN_FREE;media.cleanup(r,workspace)
  with tempfile.TemporaryDirectory(prefix='owned-guest-boot-',dir=os.environ['RUNNER_TEMP']) as tmp:
   work=Path(tmp)
   with (work/'private.log').open('wb') as log:
    r['stage']='tools'
    try:
     media.command(['apt-get','update','-qq'],log,timeout=180)
     media.command(['apt-get','install','-y','--no-install-recommends','qemu-system-x86','qemu-utils','ovmf','xorriso','tesseract-ocr'],log,timeout=300,env=dict(os.environ,DEBIAN_FRONTEND='noninteractive'))
    except media.ProbeError:raise media.ProbeError('apt_failed')
    iso=work/'official.iso';r['stage']='media';download=media.blank(r['source_commit'],r['run_id']);media.download(iso,download);r['official_media_pinned']=download['image']['download_complete'] and download['image']['sha256']==media.ISO_SHA256;check_catalog(iso,r)
    r['stage']='seed';seed_dir=work/'seed';seed_dir.mkdir();password='Aa9!'+secrets.token_hex(16);challenge=secrets.token_hex(32)
    (seed_dir/'autounattend.xml').write_text(answer(password,challenge));(seed_dir/'config.json').write_text(json.dumps({'challenge':challenge}));shutil.copyfile(Path(__file__).with_name('probe.ps1'),seed_dir/'probe.ps1')
    seed=work/'seed.iso';media.command(['xorriso','-as','mkisofs','-J','-r','-V','LABSEED','-o',str(seed),str(seed_dir)],log,timeout=60)
    disk=work/'guest.qcow2';media.command(['qemu-img','create','-f','qcow2',str(disk),str(media.DISK_BYTES)],log,timeout=30)
    r['stage']='qemu'
    try:guest(work,iso,seed,disk,challenge,r,log)
    finally:
     try:r['disk_actual_bytes']=json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(disk)],timeout=10))['actual-size']
     except Exception:pass
    r['stage']='completed';r['status']='owned_windows_reboot_verified'
 except media.ProbeError as exc:r['error_code']=str(exc) if str(exc) in ERRORS else 'bounded_guest_failed'
 except Exception:r['error_code']='bounded_guest_failed'
 finally:
  r['disk_free_final_bytes']=shutil.disk_usage(workspace).free
  validate(r);(out/'guest-boot.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'stage':r['stage'],'error_code':r['error_code']}))
if __name__=='__main__':
 if len(sys.argv)==4 and sys.argv[1]=='validate':
  r=validate(json.loads(Path(sys.argv[2]).read_text()));dest=Path(sys.argv[3]);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(r,indent=2)+'\n')
 elif len(sys.argv)>2 and sys.argv[1]=='receipt':
  r=receipt(*sys.argv[3:]);dest=Path(sys.argv[2]);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(r,indent=2)+'\n')
 else:main()
