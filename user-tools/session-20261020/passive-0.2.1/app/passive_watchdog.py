"""Bounded safety stop of this tool's verified Pktmon session only, no targets touched."""
import sys,time
from pathlib import Path
from capture_platform import Capture,pktmon_sessions,sessions
from safepaths import safe_path

def main():
 if len(sys.argv)!=4:return
 folder=safe_path(sys.argv[1]);name=sys.argv[2];handle=int(sys.argv[3])
 if len(name)>256 or not folder.name.startswith('run-'):return
 cap=Capture(folder);cap.started=True;cap.owner={'name':name,'handle':handle}
 deadline=time.monotonic()+90
 while time.monotonic()<deadline:
  if (folder/'stop.flag').exists():return
  time.sleep(.5)
 try:
  cap.stop();(folder/'watchdog-stopped.flag').write_text('verified_owned_capture_stopped\n')
 except Exception:
  (folder/'watchdog-attention.flag').write_text('could_not_verify_or_stop_owned_capture; review pktmon status\n')
if __name__=='__main__':main()
