"""Standalone Windows UI for the existing read-only checker. No game writes."""
import io,json,sys
from contextlib import redirect_stdout

def selftest(destination):
 import unittest,test_origin_check
 suite=unittest.defaultTestLoader.loadTestsFromModule(test_origin_check)
 result=unittest.TextTestRunner(stream=io.StringIO(),verbosity=0).run(suite)
 receipt=dict(schema='casc-origin-exe-selftest-1',tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),passed=result.wasSuccessful())
 from pathlib import Path
 Path(destination).write_text(json.dumps(receipt,indent=2)+'\n')
 return 0 if result.wasSuccessful()else 1

def ui():
 import tkinter as tk
 from tkinter import ttk,filedialog,messagebox
 import queue,threading,origin_check
 app=tk.Tk();app.title('CASC Origin Check - Offline');app.geometry('860x650');app.minsize(700,500)
 root=ttk.Frame(app,padding=18);root.pack(fill='both',expand=True)
 ttk.Label(root,text='CASC Origin Check',font=('Segoe UI',18,'bold')).pack(anchor='w')
 ttk.Label(root,text='Read-only | No network | No login | Does not launch or change the game').pack(anchor='w',pady=(4,14))
 paths=[tk.StringVar(),tk.StringVar()]
 def choose(index):
  selected=filedialog.askdirectory(title='Choose WoW folder or Data/data folder')
  if selected:paths[index].set(selected)
 for index,label in enumerate(('WoW folder (or Data/data folder)','Second copy - optional')):
  ttk.Label(root,text=label).pack(anchor='w');row=ttk.Frame(root);row.pack(fill='x',pady=(3,10))
  ttk.Entry(row,textvariable=paths[index]).pack(side='left',fill='x',expand=True)
  ttk.Button(row,text='Browse...',command=lambda i=index:choose(i)).pack(side='left',padx=(8,0))
 ttk.Label(root,text='Close Battle.net and WoW first. A missing match is NOT proof that all game files are unmarked.',wraplength=790).pack(anchor='w',pady=(0,8))
 controls=ttk.Frame(root);controls.pack(fill='x',pady=6)
 status=tk.StringVar(value='Ready. Select an existing local folder.');ttk.Label(root,textvariable=status).pack(anchor='w',pady=6)
 view=tk.Text(root,wrap='word',font=('Consolas',10));view.pack(fill='both',expand=True)
 view.insert('1.0','Results contain counts and booleans only.\nYour hostname, marker digest and folder paths will not be included.');view.configure(state='disabled')
 results=queue.Queue();latest={'text':None};busy={'value':False}
 def run():
  if busy['value']:return
  args=[v.get().strip()for v in paths]
  if not args[0]:messagebox.showinfo('Select a folder','Choose the existing WoW folder first.');return
  if not args[1]:args=args[:1]
  busy['value']=True;start.configure(state='disabled');status.set('Checking bounded local archive prefixes...')
  def work():
   try:
    stream=io.StringIO()
    with redirect_stdout(stream):origin_check.main(args)
    result=json.loads(stream.getvalue());results.put(result)
   except Exception:results.put(dict(status='refused',error_kind='local_check_failed'))
  threading.Thread(target=work,daemon=True).start()
 def copy():
  if latest['text']is None:return
  app.clipboard_clear();app.clipboard_append(latest['text']);status.set('JSON copied. Only this result is needed for review.')
 def poll():
  try:
   result=results.get_nowait();text=json.dumps(result,indent=2);latest['text']=text;view.configure(state='normal');view.delete('1.0','end');view.insert('1.0',text);view.configure(state='disabled');busy['value']=False;start.configure(state='normal');status.set('Completed - this is a bounded-prefix test, not proof of personal identity.'if result.get('status')=='completed'else'Check refused. See the fixed error code below.')
  except queue.Empty:pass
  app.after(150,poll)
 start=ttk.Button(controls,text='Check offline',command=run);start.pack(side='left')
 ttk.Button(controls,text='Copy JSON result',command=copy).pack(side='left',padx=8)
 ttk.Label(root,text='No whole-game scan. No account identification. No claim of an unforgeable origin.',wraplength=790).pack(anchor='w',pady=(10,0))
 poll();app.mainloop();return 0
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--self-test':raise SystemExit(selftest(sys.argv[2]))
 if len(sys.argv)!=1:raise SystemExit(2)
 raise SystemExit(ui())
