"""End-to-end orchestration contract. No apt, download, cleanup or VM executed."""
import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare_guest as p
from test_prepare import xml
class Tests(unittest.TestCase):
 def test_complete_pipeline_writes_report(self):
  with tempfile.TemporaryDirectory() as tmp:
   cwd=os.getcwd();os.chdir(tmp)
   try:
    def cleanup(r,workspace):r.update(disk_free_before_bytes=p.MIN_FREE,disk_free_after_cleanup_bytes=p.MIN_FREE)
    def download(dest,r):dest.touch();r['image'].update(downloaded_bytes=p.ISO_BYTES,sha256=p.ISO_SHA256,download_complete=True)
    def command(argv,log,**kw):
     if argv[:2]==['wimlib-imagex','info']:Path(argv[-1].split('=',1)[1]).write_bytes(xml())
     if argv[:2]==['qemu-img','create']:Path(argv[4]).touch()
    def run(argv,**kw):
     self.assertEqual(argv[:2],['7z','e']);kw['stdout'].truncate(2*1024**3)
    def check(argv,**kw):return b'QEMU emulator version 8.2.2\n' if argv[0]=='qemu-system-x86_64' else json.dumps({'format':'qcow2','virtual-size':p.DISK_BYTES,'actual-size':0}).encode()
    def qmp(work,iso,disk,r,log):r['qemu']={key:True for key in r['qemu']}
    env={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'1','GITHUB_WORKSPACE':tmp,'RUNNER_TEMP':tmp}
    with patch.dict(os.environ,env),patch.object(p,'guard',return_value=True),patch.object(p,'cleanup',side_effect=cleanup),patch.object(p,'download',side_effect=download),patch.object(p,'command',side_effect=command),patch.object(p.subprocess,'run',side_effect=run),patch.object(p.subprocess,'check_output',side_effect=check),patch.object(p,'paused_qemu',side_effect=qmp):p.main()
    r=p.validate(json.loads(Path('output/windows-guest-preparation.json').read_text()));self.assertEqual(r['status'],'prepared_paused_no_windows_boot')
   finally:os.chdir(cwd)
