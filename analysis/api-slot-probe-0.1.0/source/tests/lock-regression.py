"""Exercise actual capture-lock helper in separate owned PowerShell processes.
Linux .NET results are regression evidence, NOT a real Windows UI/capture test.
"""
import json,subprocess,sys,time,tempfile
from pathlib import Path
pwsh,helper=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve()
def quote(s):return "'"+str(s).replace("'","''")+"'"
with tempfile.TemporaryDirectory() as td:
 root=Path(td);ready=root/'ready'
 prefix="$ErrorActionPreference='Stop';. "+quote(helper)+";"
 acquire=prefix+"$f=Acquire-WLabCaptureLock "+quote(root)+";Release-WLabCaptureLock $f"
 def attempt():return subprocess.run([str(pwsh),'-NoProfile','-Command',acquire],capture_output=True,text=True)
 # Idle UI equivalent: no lock is acquired at startup. A pre-existing file is not a held lock.
 (root/'capture.lock').write_text('old file with no live holder')
 r=attempt();assert r.returncode==0,(r.stdout,r.stderr)
 holder=prefix+"$f=Acquire-WLabCaptureLock "+quote(root)+";[IO.File]::WriteAllText("+quote(ready)+",'ready');[void][Console]::ReadLine();Release-WLabCaptureLock $f"
 def start():
  if ready.exists():ready.unlink()
  p=subprocess.Popen([str(pwsh),'-NoProfile','-Command',holder],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  until=time.monotonic()+20
  while not ready.exists():
   if p.poll() is not None:raise AssertionError(p.communicate())
   if time.monotonic()>until:p.kill();p.wait();raise AssertionError('holder timeout')
   time.sleep(.05)
  return p
 h=start()
 try:
  blocked=attempt();assert blocked.returncode!=0,'simultaneous capture lock accepted'
  h.stdin.write('\n');h.stdin.flush();h.wait(timeout=10)
 finally:
  if h.poll() is None:h.kill();h.wait()
 assert attempt().returncode==0,'graceful release did not unlock'
 h=start()
 try:
  assert attempt().returncode!=0
 finally:h.kill();h.wait(timeout=10) # Only this test's owned helper, never a user process.
 assert attempt().returncode==0,'dead holder left an effective stale lock'
 assert (root/'capture.lock').exists(),'test did not retain stale file'
 results={'platform':'Linux PowerShell/.NET','preexisting_file_without_handle_accepted':True,'second_live_holder_rejected':True,'graceful_release_reacquires':True,'terminated_owned_test_holder_reacquires':True,'windows_ui_runtime_tested':False,'game_capture_tested':False}
 print(json.dumps(results))
