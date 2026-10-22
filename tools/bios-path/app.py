"""Token-protected, loopback-only UI. No uploads, external requests or input execution."""
import argparse,ctypes,datetime,json,os,secrets,sys,threading,time,webbrowser
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from analyzer import analyze,write_outputs,VERSION
ROOT=Path(__file__).resolve().parent
STATE={'state':'idle','progress':0,'message':'آمادهٔ انتخاب فایل','selected_name':None,'summary':None,'error':None}
LOCK=threading.Lock();SELECTED=None;OUT=None;TOKEN=secrets.token_urlsafe(32);PREFIX='/'+TOKEN+'/'

def pick_file():
 if sys.platform!='win32':raise RuntimeError('Native file picker is only available on Windows. Use app.py --input for local QA.')
 from ctypes import wintypes as w
 class OFN(ctypes.Structure):
  _fields_=[('lStructSize',w.DWORD),('hwndOwner',w.HWND),('hInstance',w.HINSTANCE),('lpstrFilter',w.LPCWSTR),('lpstrCustomFilter',w.LPWSTR),('nMaxCustFilter',w.DWORD),('nFilterIndex',w.DWORD),('lpstrFile',w.LPWSTR),('nMaxFile',w.DWORD),('lpstrFileTitle',w.LPWSTR),('nMaxFileTitle',w.DWORD),('lpstrInitialDir',w.LPCWSTR),('lpstrTitle',w.LPCWSTR),('Flags',w.DWORD),('nFileOffset',w.WORD),('nFileExtension',w.WORD),('lpstrDefExt',w.LPCWSTR),('lCustData',ctypes.c_ssize_t),('lpfnHook',ctypes.c_void_p),('lpTemplateName',w.LPCWSTR),('pvReserved',ctypes.c_void_p),('dwReserved',w.DWORD),('FlagsEx',w.DWORD)]
 buf=ctypes.create_unicode_buffer(32768);f=OFN();f.lStructSize=ctypes.sizeof(f);f.lpstrFilter='PE images\0*.exe;*.dll\0All files\0*.*\0\0'
 f.lpstrFile=ctypes.cast(buf,w.LPWSTR);f.nMaxFile=len(buf);f.lpstrTitle='Select Wow.exe — read-only analysis';f.Flags=0x1000|0x800|0x80000|0x8
 dll=ctypes.WinDLL('comdlg32',use_last_error=True);dll.GetOpenFileNameW.argtypes=[ctypes.POINTER(OFN)];dll.GetOpenFileNameW.restype=w.BOOL
 if dll.GetOpenFileNameW(ctypes.byref(f)):return Path(buf.value)
 err=dll.CommDlgExtendedError()
 if err:raise RuntimeError('Windows file dialog error: '+hex(err))
 return None

def update(p,msg):
 with LOCK:STATE.update(progress=p,message=msg)

def work(path):
 global OUT
 try:
  r=analyze(path,update)
  parent=Path(os.environ.get('LOCALAPPDATA',str(ROOT)))/'WLab-BIOS-Path'/'output'
  out=parent/(datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3))
  write_outputs(r,out);OUT=out
  with LOCK:STATE.update(state='done',progress=100,message='گزارش آماده است؛ نتیجهٔ ارسال روی 3724 همچنان نامشخص است.',
   summary={'sha256':r['input']['sha256'],'profile':r['profile']['matched'],'references':len(r['code_candidates']),
    'functions':len(r['functions']),'warnings':len(r['coverage']['warnings'])+len(r['coverage']['budget_limits_hit'])+sum(len(f['issues']) for f in r['functions']),
    'output_dir':str(out)},error=None)
 except Exception as e:
  with LOCK:STATE.update(state='error',error=str(e),message='تحلیل متوقف شد؛ فایل ورودی اجرا نشد.')

class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def send(self,code,body,kind='application/json; charset=utf-8',extra=None):
  body=body.encode('utf-8') if isinstance(body,str) else body
  self.send_response(code);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)))
  self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
  self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
  for k,v in (extra or {}).items():self.send_header(k,v)
  self.end_headers();self.wfile.write(body)
 def valid(self,post=False):
  host='127.0.0.1:'+str(self.server.server_port)
  okay=self.headers.get('Host')==host and self.path.startswith(PREFIX)
  if post:okay=okay and self.headers.get('X-WLab-Token')==TOKEN and self.headers.get('Origin')=='http://'+host
  if not okay:self.send(403,'{"error":"Forbidden"}')
  return okay
 def do_GET(self):
  if not self.valid():return
  action=self.path[len(PREFIX):]
  if action=='':return self.send(200,(ROOT/'ui.html').read_bytes(),'text/html; charset=utf-8')
  if action=='status':
   with LOCK:body=json.dumps(STATE,ensure_ascii=False)
   return self.send(200,body)
  if action=='download' and OUT and (OUT/'evidence.zip').is_file():
   return self.send(200,(OUT/'evidence.zip').read_bytes(),'application/zip',{'Content-Disposition':'attachment; filename="WLab-BIOS-evidence.zip"'})
  return self.send(404,'{"error":"Not found"}')
 def do_POST(self):
  global SELECTED
  if not self.valid(True):return
  try:
   if int(self.headers.get('Content-Length','0'))>1024:return self.send(413,'{}')
  except ValueError:return self.send(400,'{}')
  action=self.path[len(PREFIX):]
  if action=='pick':
   with LOCK:
    if STATE['state'] in ('running','picking'):return self.send(409,'{}')
    STATE['state']='picking'
   try:
    p=pick_file()
    with LOCK:
     if p:SELECTED=p;STATE.update(selected_name=p.name,summary=None,error=None,progress=0,message='فایل انتخاب شد؛ آمادهٔ تحلیل آفلاین')
     STATE['state']='idle'
    return self.send(200,'{}')
   except Exception as e:
    with LOCK:STATE.update(state='error',error=str(e),progress=0,message='انتخاب فایل انجام نشد؛ دوباره تلاش کن.')
    return self.send(500,json.dumps({'error':str(e)}))
  if action=='run':
   with LOCK:
    if STATE['state'] in ('running','picking') or not SELECTED:return self.send(409,'{}')
    STATE.update(state='running',progress=0,error=None,summary=None,message='شروع تحلیل');path=SELECTED
   threading.Thread(target=work,args=(path,),daemon=True).start();return self.send(202,'{}')
  if action=='folder' and OUT:
   if sys.platform=='win32':os.startfile(str(OUT))
   return self.send(200,'{}')
  if action=='close':
   with LOCK:
    if STATE['state'] in ('running','picking'):return self.send(409,'{}')
   self.send(200,'{}');threading.Thread(target=self.server.shutdown,daemon=True).start();return
  return self.send(404,'{}')

def main():
 global SELECTED
 ap=argparse.ArgumentParser();ap.add_argument('--input');ap.add_argument('--no-browser',action='store_true');args=ap.parse_args()
 if args.input:SELECTED=Path(args.input);STATE['selected_name']=SELECTED.name
 server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
 url='http://127.0.0.1:'+str(server.server_port)+PREFIX
 if args.no_browser:print(url,flush=True)
 else:webbrowser.open(url)
 try:server.serve_forever(poll_interval=.25)
 finally:server.server_close()
if __name__=='__main__':
 try:main()
 except Exception as e:
  if sys.platform=='win32':ctypes.windll.user32.MessageBoxW(None,str(e),'WLab BIOS Path',0x10)
  else:raise
