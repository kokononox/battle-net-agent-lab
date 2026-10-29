"""Standalone Windows UI for the existing read-only checker. No game writes."""
import io,json,sys
from contextlib import redirect_stdout

def selftest(destination):
 import unittest,test_origin_check,test_format_diagnostics,test_key_diagnostics,test_build_check,test_main_files_check
 suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(test_origin_check),unittest.defaultTestLoader.loadTestsFromModule(test_format_diagnostics),unittest.defaultTestLoader.loadTestsFromModule(test_key_diagnostics),unittest.defaultTestLoader.loadTestsFromModule(test_build_check),unittest.defaultTestLoader.loadTestsFromModule(test_main_files_check)])
 result=unittest.TextTestRunner(stream=io.StringIO(),verbosity=0).run(suite)
 receipt=dict(schema='casc-origin-exe-selftest-1',tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),passed=result.wasSuccessful())
 from pathlib import Path
 Path(destination).write_text(json.dumps(receipt,indent=2)+'\n')
 return 0 if result.wasSuccessful()else 1

def ui():
 import tkinter as tk
 from tkinter import ttk,filedialog,messagebox
 import queue,threading,origin_check,build_check,main_files_check
 app=tk.Tk();app.title('CASC Origin Check v6 - Offline');app.geometry('900x720');app.minsize(760,560)
 root=ttk.Frame(app,padding=18);root.pack(fill='both',expand=True)
 ttk.Label(root,text='CASC Origin Check v6',font=('Segoe UI',18,'bold')).pack(anchor='w')
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
 main_controls=ttk.Frame(root);main_controls.pack(fill='x',pady=6)
 build_controls=ttk.Frame(root);build_controls.pack(fill='x',pady=6)
 controls=ttk.Frame(root);controls.pack(fill='x',pady=6)
 status=tk.StringVar(value='Ready. Select an existing local folder.');ttk.Label(root,textvariable=status).pack(anchor='w',pady=6)
 view=tk.Text(root,wrap='word',font=('Consolas',10));view.pack(fill='both',expand=True)
 view.insert('1.0','Results contain counts and booleans only.\nYour hostname, marker digest and folder paths will not be included.');view.configure(state='disabled')
 results=queue.Queue();latest={'text':None};busy={'value':False,'last_args':None,'next_batch':None}
 def run(batch_start=0):
  if busy['value']:return
  args=[v.get().strip()for v in paths]
  if not args[0]:messagebox.showinfo('Select a folder','Choose the existing WoW folder first.');return
  if not args[1]:args=args[:1]
  if batch_start and tuple(args)!=busy['last_args']:
   messagebox.showinfo('Folder changed','Click Check offline to start the newly selected folders.');return
  busy['value']=True;start.configure(state='disabled');verify_button.configure(state='disabled');main_button.configure(state='disabled');next_button.configure(state='disabled');status.set('Checking archive batch starting at '+str(batch_start)+' (at most 64 archives)...')
  def work():
   try:
    stream=io.StringIO()
    with redirect_stdout(stream):origin_check.main(args,batch_start=batch_start)
    result=json.loads(stream.getvalue());results.put((result,tuple(args)))
   except Exception:results.put((dict(status='refused',error_kind='local_check_failed'),tuple(args)))
  threading.Thread(target=work,daemon=True).start()
 def verify_build():
  if busy['value']:return
  selected=paths[0].get().strip()
  if not selected:messagebox.showinfo('Select a folder','Choose the main WoW folder first.');return
  if paths[1].get().strip():messagebox.showinfo('One installation only','Clear the optional second-copy folder for this same-build file check.');return
  busy['value']=True;start.configure(state='disabled');next_button.configure(state='disabled');verify_button.configure(state='disabled');main_button.configure(state='disabled');status.set('Verifying active build and TWO small official components. No archive scan...')
  def work():
   try:results.put((build_check.assess(selected),(selected,)))
   except Exception:results.put((dict(schema='wow-official-component-check-1',status='refused',error_kind='local_check_failed'),(selected,)))
  threading.Thread(target=work,daemon=True).start()
 def verify_main():
  if busy['value']:return
  selected=paths[0].get().strip()
  if not selected:messagebox.showinfo('Select a folder','Choose the main WoW folder first.');return
  if paths[1].get().strip():messagebox.showinfo('One installation only','Clear the optional second-copy folder for this file check.');return
  busy['value']=True;start.configure(state='disabled');next_button.configure(state='disabled');verify_button.configure(state='disabled');main_button.configure(state='disabled');status.set('Hashing Wow.exe and wow_loader.dll only. Up to 160 MiB local reads; no execution. Please wait...')
  def work():
   try:results.put((main_files_check.assess(selected),(selected,)))
   except Exception:results.put((dict(schema='wow-official-main-files-check-1',status='refused',error_kind='local_check_failed'),(selected,)))
  threading.Thread(target=work,daemon=True).start()
 def copy():
  if latest['text']is None:return
  app.clipboard_clear();app.clipboard_append(latest['text']);status.set('JSON copied. Only this result is needed for review.')
 def poll():
  try:
   result,used_args=results.get_nowait();text=json.dumps(result,indent=2);latest['text']=text;view.configure(state='normal');view.delete('1.0','end');view.insert('1.0',text);view.configure(state='disabled');busy['value']=False;start.configure(state='normal');verify_button.configure(state='normal');main_button.configure(state='normal');busy['last_args']=used_args
   next_values=[result[k]['next_batch_start']for k in ('first','second')if isinstance(result.get(k),dict)and result[k].get('next_batch_start')is not None]
   busy['next_batch']=max(next_values)if next_values else None
   next_button.configure(state='normal'if busy['next_batch']is not None else'disabled')
   if result.get('status')!='completed':status.set('Check refused. See the fixed error code below.')
   elif result.get('schema')=='wow-official-main-files-check-1':status.set('Official main file matches: '+str(result.get('verified_components',0))+'/2. NOT a whole-game or copy-origin verdict.')
   elif result.get('schema')=='wow-official-component-check-1':status.set('Official reference matches: '+str(result.get('verified_components',0))+'/2 selected small files. NOT a whole-game verdict.')
   elif busy['next_batch']is not None:status.set('This batch completed. More archives remain: use Next batch (64 max).')
   else:status.set('This batch completed. No later eligible batch. This is NOT a whole-game scan.')
  except queue.Empty:pass
  app.after(150,poll)
 main_button=ttk.Button(main_controls,text='Verify Wow.exe + loader',command=verify_main);main_button.pack(side='left')
 ttk.Label(main_controls,text='Build 70448 only | 160 MiB max | Read-only').pack(side='left',padx=10)
 verify_button=ttk.Button(build_controls,text='Verify build 70448 files',command=verify_build);verify_button.pack(side='left')
 ttk.Label(build_controls,text='Two small files only | 4 MiB max | Does not execute them').pack(side='left',padx=10)
 start=ttk.Button(controls,text='Archive diagnostics',command=run);start.pack(side='left')
 next_button=ttk.Button(controls,text='Next batch (64 max)',command=lambda:run(busy['next_batch']or 0),state='disabled');next_button.pack(side='left',padx=8)
 ttk.Button(controls,text='Copy JSON result',command=copy).pack(side='left',padx=8)
 ttk.Label(root,text='No whole-game scan. No account identification. No claim of an unforgeable origin.',wraplength=790).pack(anchor='w',pady=(10,0))
 poll();app.mainloop();return 0
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--self-test':raise SystemExit(selftest(sys.argv[2]))
 if len(sys.argv)!=1:raise SystemExit(2)
 raise SystemExit(ui())
