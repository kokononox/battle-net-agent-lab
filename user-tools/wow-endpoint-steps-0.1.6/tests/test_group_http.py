import contextlib,http.client,io,json,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from group import GroupSession
import main
class GroupHTTP(unittest.TestCase):
 def test_group_consent_start_observe_restore_baseline_over_http(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);exe=root/'Wow.exe';exe.write_bytes(b'mock');present=set();urls=[]
   def fw(action,p):
    j=json.loads(p.read_text())
    if action=='add':present.add(j['name'])
    if action=='remove':present.discard(j['name'])
    return {'ok':True}
   s=GroupSession(exe,root,fw,lambda p:None,lambda p:None,lambda p:{'status':'sample_finished'})
   with patch.object(main.webbrowser,'open',side_effect=lambda u:urls.append(u)),contextlib.redirect_stdout(io.StringIO()):
    t=threading.Thread(target=main.serve,args=(s,),daemon=True);t.start()
    for _ in range(100):
     if urls:break
     time.sleep(.01)
    self.assertTrue(urls);u=urlsplit(urls[0])
    def req(path,data):
     c=http.client.HTTPConnection('127.0.0.1',u.port,timeout=10);c.request('POST',path,json.dumps(data),{'X-WoW-Token':u.fragment,'Host':u.netloc});r=c.getresponse();body=json.loads(r.read());status=r.status;c.close();return status,body
    try:
     self.assertEqual(req('/start-group',{'consent':False})[0],400)
     code,state=req('/start-group',{'consent':True});self.assertEqual(code,200);self.assertEqual(state['mode'],'group');self.assertEqual(len(present),10)
     self.assertEqual(req('/start',{'index':0,'consent':True})[0],400)
     code,state=req('/observe',{'value':'world_ok','fresh_launch_reported':True});self.assertEqual(code,200);self.assertFalse(present);self.assertEqual(state['phase'],'baseline');self.assertTrue(state['records'][-1]['fresh_launch_user_reported'])
     self.assertEqual(req('/baseline',{'value':'yes'})[0],200)
    finally:req('/exit',{});t.join(5)
    self.assertFalse(t.is_alive())
if __name__=='__main__':unittest.main()
