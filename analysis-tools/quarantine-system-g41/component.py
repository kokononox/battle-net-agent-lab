"""Trusted synthetic client/server. No installer or external application payload."""
import json,os,socket,sys,threading,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import context,save,read
MARKER='SYNTHETIC-G41-DEVICE'
RAW=('GET /synthetic-fixture?device='+MARKER+' HTTP/1.1\r\nHost: level3.blizzard.com\r\nCookie: SYNTHETIC-SECRET\r\nX-Device: '+MARKER+'\r\n\r\n').encode()
role,root=sys.argv[1:];c=context(root);root=Path(root)
# Controller assigns Job BEFORE permitting even a loopback/external connect.
sys.stdin.buffer.read(1)
if role=='server':
 from windows_store import WindowsStore
 from quarantine import QuarantineGate
 from quarantine_handler import LoopbackServer
 store=WindowsStore(root/'quarantine',c['helper'])
 with LoopbackServer(('127.0.0.1',0),QuarantineGate(store),str(root/'peers.json')) as server:
  save(root/'endpoint.json',{'port':server.server_address[1]})
  def receipts():
   while True:
    if server.receipts:save(root/'capture-receipt.json',server.receipts[-1]);return
    time.sleep(.02)
  threading.Thread(target=receipts,daemon=True).start();server.serve_forever(poll_interval=.1)
elif role=='client':
 print('{"ready":true}',flush=True)
 for line in sys.stdin.buffer:
  value=json.loads(line);op=value.get('op')
  if op=='probe':
   connected=False
   try:
    with socket.create_connection((c['canary_ip'],443),3):connected=True
   except OSError:pass
   print(json.dumps({'connected':connected}),flush=True)
  elif op=='capture':
   port=read(root/'endpoint.json')['port']
   with socket.create_connection(('127.0.0.1',port),5) as s:
    s.sendall(RAW);reply=s.recv(4096)
   print(json.dumps({'blocked':reply.startswith(b'HTTP/1.1 403')}),flush=True)
  elif op=='exit':break
  else:raise RuntimeError('fixture_command_rejected')
else:raise RuntimeError('fixture_role_rejected')
