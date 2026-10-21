import contextlib,http.client,io,json,secrets,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from core import Session
import main

class HttpIntegration(unittest.TestCase):
 def test_authenticated_mock_workflow_and_csrf(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);program=root/'Wow.exe';program.write_bytes(b'mock')
   def fw(action,p):return {'ok':True,'present':action=='add'}
   s=Session(program,root,fw,lambda p:None);captured=[]
   with patch.object(main.webbrowser,'open',side_effect=lambda u:captured.append(u)),contextlib.redirect_stdout(io.StringIO()):
    t=threading.Thread(target=main.serve,args=(s,),daemon=True);t.start()
    for _ in range(100):
     if captured:break
     time.sleep(.01)
    self.assertTrue(captured);u=urlsplit(captured[0]);token=u.fragment
    def req(method,path,body=None,auth=True,origin=None,host=None):
     c=http.client.HTTPConnection('127.0.0.1',u.port,timeout=5);headers={'X-WoW-Token':token if auth else 'wrong','Host':host or u.netloc}
     if origin:headers['Origin']=origin
     raw=json.dumps(body) if body is not None else None;c.request(method,path,raw,headers);r=c.getresponse();b=r.read();code=r.status;c.close();return code,b
    try:
     self.assertEqual(req('GET','/')[0],200)
     self.assertEqual(req('GET','/status',auth=False)[0],403)
     self.assertEqual(req('GET','/status',host='evil.example')[0],403)
     self.assertEqual(req('POST','/start',{'index':0,'consent':True},origin='https://evil.example')[0],403)
     self.assertEqual(req('GET','/status')[0],200)
     self.assertEqual(req('POST','/start',{'index':0,'consent':False})[0],400)
     self.assertEqual(req('POST','/start',{'index':0,'consent':True})[0],200)
     self.assertEqual(req('POST','/start',{'index':1,'consent':True})[0],400)
     self.assertEqual(req('POST','/observe',{'value':'world_ok'})[0],200)
     self.assertEqual(req('POST','/baseline',{'value':'yes'})[0],200)
    finally:
     req('POST','/exit',{});t.join(5)
    self.assertFalse(t.is_alive())
    self.assertTrue(next((root/'output').glob('*.json')).is_file())
if __name__=='__main__':unittest.main()
