"""Windows offline Phase 1 UI. Private snapshots never displayed in the report pane."""
import io,json,sys

def selftest(destination):
 import unittest,test_phase1
 suite=unittest.defaultTestLoader.loadTestsFromModule(test_phase1)
 r=unittest.TextTestRunner(stream=io.StringIO()).run(suite)
 from pathlib import Path
 Path(destination).write_text(json.dumps(dict(schema='casc-phase1-selftest-1',tests_run=r.testsRun,failures=len(r.failures),errors=len(r.errors),skipped=len(r.skipped),passed=r.wasSuccessful()),indent=2)+'\n')
 return 0 if r.wasSuccessful()else 1

def ui(smoke_destination=None):
 import tkinter as tk
 from tkinter import ttk,filedialog,messagebox
 import os,queue,threading
 import phase1_core as c
 app=tk.Tk();app.title('CASC Phase 1 Compare - Offline');app.geometry('960x820');app.minsize(800,720)
 box=ttk.Frame(app,padding=15);box.pack(fill='both',expand=True)
 ttk.Label(box,text='CASC Phase 1 - A1 / A2 / B1',font=('Segoe UI',18,'bold')).pack(anchor='w')
 ttk.Label(box,text='Offline | Read-only game access | 128 MiB max per capture | No game execution').pack(anchor='w')
 ttk.Label(box,text='Private snapshots + shared key stay with you. Only Copy public JSON may be shared.',wraplength=900).pack(anchor='w',pady=8)
 folder=tk.StringVar();sample=tk.StringVar(value='A1');confirmed=tk.BooleanVar(value=False)
 ttk.Label(box,text='1. Choose existing WoW folder (.build.info and Data/data)').pack(anchor='w')
 row=ttk.Frame(box);row.pack(fill='x');ttk.Entry(row,textvariable=folder).pack(side='left',fill='x',expand=True)
 def browse():
  p=filedialog.askdirectory(title='Existing WoW installation')
  if p:folder.set(p)
 ttk.Button(row,text='Browse...',command=browse).pack(side='left')
 state={'key':None,'report':None,'busy':False};q=queue.Queue();buttons=[]
 status=tk.StringVar(value='Select game folder. Generate ONE shared key, then reuse it on both systems.')
 def fail(e):
  code=str(e)if isinstance(e,c.Refused)else'io_or_environment_error'
  status.set('Refused: '+code);messagebox.showerror('Action refused',code)
 def keygen():
  try:
   c.resolve(folder.get());p=filedialog.asksaveasfilename(title='Save NEW shared key OUTSIDE game folder',defaultextension='.key',initialfile='phase1-shared.key')
   if not p:return
   key=os.urandom(32);c.write_new(p,key,folder.get());state['key']=key;status.set('Shared key generated. Keep private; copy this SAME key to system B. Do not generate another.')
  except Exception as e:fail(e)
 def keyload():
  try:
   p=filedialog.askopenfilename(title='Load the SAME shared key used for all samples')
   if not p:return
   state['key']=c.key_ok(c.read_small(p,32));status.set('Shared comparison key loaded. No key value is displayed.')
  except Exception as e:fail(e)
 row=ttk.Frame(box);row.pack(fill='x',pady=8)
 for label,fn in(('2a. Generate shared key ONCE',keygen),('2b. Load existing shared key',keyload)):
  b=ttk.Button(row,text=label,command=fn);b.pack(side='left',padx=(0,8));buttons.append(b)
 row=ttk.Frame(box);row.pack(fill='x',pady=4);ttk.Label(row,text='3. Sample label:').pack(side='left');ttk.Combobox(row,textvariable=sample,values=c.LABELS,state='readonly',width=8).pack(side='left',padx=8)
 ttk.Checkbutton(box,text='I used the same build/language/components/relative path; paused download; closed Battle.net + Agent + WoW.',variable=confirmed).pack(anchor='w')
 ttk.Label(box,text='A1=first download on A; A2=FRESH independent download on A; B1=independent download on B.\nDo not delete A1 until its private snapshot is saved. Copying A1 is NOT a fresh A2.',wraplength=910).pack(anchor='w',pady=6)
 def start_job(fn,kind):
  if state['busy']:return
  state['busy']=True
  for b in buttons:b.configure(state='disabled')
  status.set('Reading bounded local data. Keep Battle.net and Agent closed...')
  def worker():
   try:q.put((kind,fn(),None))
   except Exception as e:q.put((kind,None,e))
  threading.Thread(target=worker,daemon=True).start()
 def capture():
  if state['key']is None:messagebox.showinfo('Key required','Generate one shared key or load the existing one.');return
  selected=folder.get();label=sample.get();key=state['key'];attest=confirmed.get()
  start_job(lambda:(c.capture(selected,label,key,attest),selected),'capture')
 def compare():
  if state['key']is None:messagebox.showinfo('Key required','Load the shared comparison key first.');return
  ps=filedialog.askopenfilenames(title='Select private A1 + B1 snapshots, optionally A2',filetypes=[('Private snapshots','*.snapshot'),('All files','*')])
  if not ps:return
  if len(ps)not in(2,3):messagebox.showerror('Choose 2 or 3','Select A1 and B1; optionally include A2.');return
  key=state['key']
  start_job(lambda:c.compare([c.parse_snapshot(c.read_small(p,c.MAX_MANIFEST),key)for p in ps],key),'compare')
 row=ttk.Frame(box);row.pack(fill='x',pady=8)
 for label,fn in(('4. Capture private snapshot',capture),('5. Compare A1 / B1 (+ A2)',compare)):
  b=ttk.Button(row,text=label,command=fn);b.pack(side='left',padx=(0,8));buttons.append(b)
 ttk.Label(box,textvariable=status,wraplength=910).pack(anchor='w',pady=4)
 view=tk.Text(box,wrap='word',font=('Consolas',10));view.pack(fill='both',expand=True)
 def show(report):
  state['report']=json.dumps(report,indent=2);view.configure(state='normal');view.delete('1.0','end');view.insert('1.0',state['report']);view.configure(state='disabled')
 def copy():
  if state['report']is not None:app.clipboard_clear();app.clipboard_append(state['report']);status.set('Public summary copied. Do NOT send the shared key or private snapshots.')
 def save():
  if state['report']is None:return
  p=filedialog.asksaveasfilename(title='Save PUBLIC summary outside game folder',defaultextension='.json',initialfile='phase1-public-report.json')
  if not p:return
  try:c.write_new(p,(state['report']+'\n').encode(),folder.get()if folder.get()else None);status.set('Public report saved.')
  except Exception as e:fail(e)
 row=ttk.Frame(box);row.pack(fill='x',pady=8)
 for label,fn in(('Copy public JSON',copy),('Save public JSON',save)):
  b=ttk.Button(row,text=label,command=fn);b.pack(side='left',padx=(0,8));buttons.append(b)
 ttk.Label(box,text='Not a whole-game scan. Candidates are NOT proof of machine identity. No decoded-payload comparison.',wraplength=910).pack(anchor='w')
 view.insert('1.0','Only public summaries appear here.\nKey and private comparison tokens are never printed.');view.configure(state='disabled')
 def poll():
  try:
   kind,result,error=q.get_nowait();state['busy']=False
   for b in buttons:b.configure(state='normal')
   if error is not None:fail(error)
   elif kind=='capture':
    envelope,selected=result;doc=envelope['document'];p=filedialog.asksaveasfilename(title='Save PRIVATE snapshot OUTSIDE game folder; do NOT upload',defaultextension='.snapshot',initialfile=doc['label']+'.snapshot')
    if p:
     try:c.write_new(p,c.canonical(envelope)+b'\n',selected);show(c.public_capture(doc));status.set('Private snapshot saved. Share ONLY the public JSON displayed below.')
     except Exception as e:fail(e)
    else:status.set('Save cancelled. Snapshot discarded; capture again before replacing this installation.')
   else:show(result);status.set('Comparison completed. Share only this public JSON. Read assessment and coverage counts.')
  except queue.Empty:pass
  app.after(150,poll)
 def close():
  if state['busy']and not messagebox.askyesno('Stop capture?','Exit now? The incomplete capture will be discarded.'):return
  app.destroy()
 app.protocol('WM_DELETE_WINDOW',close);poll()
 if smoke_destination:
  def smoke():
   from pathlib import Path
   app.update_idletasks();r=dict(schema='casc-phase1-ui-smoke-1',passed=app.winfo_width()>=800 and app.winfo_height()>=720 and view.winfo_height()>=100 and len(buttons)==6,window_width=app.winfo_width(),window_height=app.winfo_height(),report_pane_height=view.winfo_height(),action_buttons=len(buttons))
   Path(smoke_destination).write_text(json.dumps(r,indent=2)+'\n');state['smoke_ok']=r['passed'];app.destroy()
  app.after(1000,smoke)
 app.mainloop();return 0 if not smoke_destination or state.get('smoke_ok')else 1
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--self-test':raise SystemExit(selftest(sys.argv[2]))
 if len(sys.argv)==3 and sys.argv[1]=='--ui-smoke-test':raise SystemExit(ui(sys.argv[2]))
 if len(sys.argv)!=1:raise SystemExit(2)
 raise SystemExit(ui())
