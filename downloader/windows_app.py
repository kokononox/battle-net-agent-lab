"""Tk Windows preview. Read-only optional sources; explicit network consent; no install."""
import json
from pathlib import Path
import queue
import sys
import threading
import acquisition_runner as runner
import downloader_controller as controller
import legacy_reuse
import local_review
import update_scope
import repair_core as core


def main():
    if sys.version_info<(3,9):
        print('Python 3.9+ required.');return 1
    try:
        import tkinter as tk
        from tkinter import filedialog,messagebox,ttk
    except ImportError:
        print('Tcl/Tk is required. Use standard Python for Windows with Tcl/Tk installed.');return 1
    root=tk.Tk();root.title('WoW Retail — Queue Cache Downloader Preview — NO INSTALL')
    root.geometry('1020x'+str(min(940,max(650,root.winfo_screenheight()-80))));events=queue.Queue();cancel=threading.Event()
    state={'lab':None,'plan':None,'queue':None,'busy':False,'closing':False}
    paths={name:tk.StringVar() for name in ('lab','local','manifest','legacy_root')}
    kind=tk.StringVar(value='download_v025');locales=tk.StringVar(value='')
    object_limit=tk.StringVar(value='3');byte_limit=tk.StringVar(value='16');review_batches=tk.StringVar(value='32')
    acknowledge=tk.BooleanVar(value=False)
    tk.Label(root,text='فقط دریافت در Lab جدا از بازی — هیچ نصب، اجرای فایل یا نوشتن CASC وجود ندارد.',fg='#a32121',font=('Segoe UI',12,'bold')).pack(pady=9)
    panel=ttk.Frame(root,padding=8);panel.pack(fill='x')
    controls=[]
    def entry_row(row,label,var,command):
        ttk.Label(panel,text=label).grid(row=row,column=0,sticky='w',padx=4,pady=4)
        e=ttk.Entry(panel,textvariable=var,width=80);e.grid(row=row,column=1,sticky='ew')
        e.configure(state='readonly')
        b=ttk.Button(panel,text='انتخاب',command=command);b.grid(row=row,column=2,padx=5);controls.append(b)
    output=tk.Text(root,height=10,wrap='word',font=('Segoe UI',10));output.pack(fill='both',expand=True,padx=12,pady=6)
    def show(text):
        output.configure(state='normal');output.delete('1.0','end');output.insert('end',text);output.configure(state='disabled')
    def set_busy(busy):
        state['busy']=busy
        for c in controls:c.configure(state='disabled' if busy else 'normal')
        dirty=False
        if state['lab'] is not None:
            try:dirty=local_review.queue_needs_refresh(state['lab'])
            except (OSError,core.RepairError):dirty=True
        start_button.configure(state='disabled' if busy or state['queue'] is None or dirty else 'normal')
        stop_button.configure(state='normal' if busy else 'disabled')
    def select_lab(existing=False):
        try:
            name=(filedialog.askdirectory(title='Open existing owned Lab') if existing else
                  filedialog.asksaveasfilename(title='Choose NEW Lab folder name OUTSIDE game (must not exist)',initialfile='WoW-Downloader-Lab'))
            if not name:return
            lab=controller.open_lab(Path(name)) if existing else controller.new_lab(Path(name))
            state.update(lab=lab,plan=None,queue=None);paths['lab'].set(str(lab.root))
            saved=controller.load_state(lab)
            if saved:state['plan'],state['queue']=saved
            set_busy(False)
            show('Lab باز شد. ورودی‌های اختیاری لازم نیست دوباره پر شوند. اگر اسکن تمام و صف به‌روز است، فقط «تفکیک آپدیت — بدون اینترنت» را بزن؛ اسکن را تکرار نکن.\n'
                 'پوشهٔ بازی، Lab قبلی یا پوشهٔ حاوی فایل شخصی را برای ساخت Lab جدید انتخاب نکن.')
        except Exception as exc:messagebox.showerror('Lab',json.dumps(runner.error_info(exc),ensure_ascii=False))
    entry_row(0,'Lab — بیرون بازی و ترجیحاً دیسک محلی NTFS',paths['lab'],lambda:select_lab(False))
    open_button=ttk.Button(panel,text='بازکردن Lab قبلی',command=lambda:select_lab(True));open_button.grid(row=1,column=2);controls.append(open_button)
    def choose_dir(var,title):
        value=filedialog.askdirectory(title=title)
        if value:var.set(value)
    entry_row(2,'اختیاری: پوشهٔ دقیق Data/data (فقط خواندن)',paths['local'],lambda:choose_dir(paths['local'],'Select game Data/data; close game and updater first'))
    def choose_manifest():
        value=filedialog.askopenfilename(title='Select old PRIVATE manifest/receipt LOCALLY; do not send it',filetypes=[('JSON','*.json')])
        if value:paths['manifest'].set(value)
    entry_row(3,'اختیاری: PRIVATE manifest/receipt قبلی',paths['manifest'],choose_manifest)
    entry_row(4,'root صریح همان کش یا staging قبلی',paths['legacy_root'],lambda:choose_dir(paths['legacy_root'],'Select explicit old cache/staging root; never inferred from JSON'))
    ttk.Label(panel,text='قالب فایل قبلی').grid(row=5,column=0,sticky='w')
    box=ttk.Combobox(panel,textvariable=kind,values=('download_v025','decoded_v030','supply_cache'),state='readonly');box.grid(row=5,column=1,sticky='w');controls.append(box)
    ttk.Label(panel,text='زبان‌ها با کاما؛ خالی = کاتالوگ کامل، نه آپدیت دقیق').grid(row=6,column=0,sticky='w')
    language_entry=ttk.Entry(panel,textvariable=locales,width=30);language_entry.grid(row=6,column=1,sticky='w');controls.append(language_entry)
    panel.columnconfigure(1,weight=1)
    def clear_optional():
        for name in ('local','manifest','legacy_root'):paths[name].set('')
    clear_button=ttk.Button(panel,text='پاک‌کردن ورودی‌های اختیاری',command=clear_optional);clear_button.grid(row=7,column=1,sticky='w');controls.append(clear_button)
    def progress(e):
        # Drop nonessential progress when the main UI falls behind. Results and
        # errors are never dropped; stop/close remain responsive.
        if events.qsize()<16:events.put(('progress',e))
    def launch(fn):
        cancel.clear();set_busy(True)
        def work():
            try:events.put(('result',fn()))
            except Exception as exc:
                try:info=controller.report_error(state['lab'],exc)
                except Exception:info=runner.error_info(exc)
                events.put(('error',info))
        threading.Thread(target=work,daemon=False).start()
    def prepare():
        if state['lab'] is None:messagebox.showwarning('Lab','اول Lab جدید بساز یا Lab قبلی را باز کن.');return
        if bool(paths['manifest'].get())!=bool(paths['legacy_root'].get()):
            messagebox.showwarning('ورودی قبلی','manifest و root قبلی باید هر دو مشخص باشند.');return
        if not messagebox.askyesno('دانلود metadata — جدا از سقف فایل‌های بازی',
            'این مرحله metadata رسمی EU را دریافت می‌کند؛ ممکن است چندصد MiB و در سقف محافظه‌کارانه تا حدود 1.5 GiB شبکه مصرف کند.\n'
            'حداقل 5 GiB فضای آزاد Lab لازم است. سقف 16 MiB پایین شامل metadata نیست.\n'
            'اگر Data/data انتخاب شده، بازی و Battle.net/updater را ببند. هیچ فایل منبع تغییر نمی‌کند. ادامه؟'):return
        lab=state['lab'];local=Path(paths['local'].get()) if paths['local'].get() else None
        source=legacy_reuse.Import(kind.get(),Path(paths['manifest'].get()),Path(paths['legacy_root'].get())) if paths['manifest'].get() else None
        langs=tuple(s.strip() for s in locales.get().split(',') if s.strip())
        def task():
            report,p,q=controller.prepare(lab,local,source,langs,cancel=cancel,notify=progress)
            return ('prepared',report,p,q)
        launch(task)
    actions=ttk.Frame(root,padding=8);actions.pack(fill='x')
    prepare_button=ttk.Button(actions,text='۱. آماده‌سازی صف (metadata رسمی)',command=prepare);prepare_button.pack(side='left',padx=4);controls.append(prepare_button)
    def inspect():
        if state['queue'] is None:return
        launch(lambda:('preview',runner.preview(state['lab'],state['plan'],state['queue'])))
    inspect_button=ttk.Button(actions,text='نمایش صف موجود — بدون شبکه',command=inspect);inspect_button.pack(side='left',padx=4);controls.append(inspect_button)
    def update_scope_plan():
        if state['lab'] is None or state['plan'] is None or state['queue'] is None:
            messagebox.showwarning('Lab','اول Lab قبلیِ دارای صف و مسیر بازی ثبت‌شده را باز کن.');return
        if not messagebox.askyesno('تفکیک آپدیت — بدون اینترنت',
            'اختلاف نسخه با پروفایل Windows/زبان نصب و شواهد محلیِ ادغام‌شده تفکیک می‌شود؛ اسکن کامل بازی تکرار نمی‌شود.\n'
            'ممکن است manifest قدیمی از archive محلی خوانده شود. چند دقیقه پردازش metadata و فضای دیسک اضافه لازم است؛ ترجیحاً ۵ GiB آزاد داشته باش.\n'
            'بازی، Battle.net و ابزار قبلی بسته باشند. صف دریافت فعلی عوض نمی‌شود و نتیجه هنوز مجوز دانلود/نصب یا حجم قطعی آپدیت نیست. ادامه؟'):return
        lab,p,q=state['lab'],state['plan'],state['queue']
        launch(lambda:('update_scope',update_scope.plan_from_queue(lab,p,q,cancel=cancel,notify=progress)))
    mp_button=ttk.Button(actions,text='تفکیک آپدیت — بدون اینترنت',command=update_scope_plan);mp_button.pack(side='left',padx=4);controls.append(mp_button)
    offline_panel=ttk.Frame(root,padding=8);offline_panel.pack(fill='x')
    def review_status():
        if state['lab'] is None or state['plan'] is None:
            messagebox.showwarning('Lab','اول Lab قبلیِ دارای صف آماده را باز کن.');return
        launch(lambda:('local_review',local_review.status(state['lab'])))
    def continue_local():
        if state['lab'] is None or state['plan'] is None:
            messagebox.showwarning('Lab','اول Lab قبلیِ دارای صف آماده را باز کن.');return
        value=review_batches.get()
        if not value.isascii() or not value.isdigit() or not 1<=int(value)<=512:
            messagebox.showwarning('نوبت‌ها','تعداد نوبت محلی باید عدد صحیح ۱ تا ۵۱۲ باشد.');return
        n=int(value)
        if not messagebox.askyesno('ادامه بررسی محلی — صفر درخواست شبکه',
            f'بازی و Battle.net/updater باید بسته باشند. حداکثر {n} نوبت، هر نوبت تا ۲۵۶ MiB خواندن دیسک و ۴۰۹۶ نامزد.\n'
            'این دانلود نیست؛ ممکن است زمان و فضای دیسک قابل‌توجهی بخواهد. بعد از هر نوبت checkpoint ذخیره می‌شود.\n'
            'از منبع ذخیره‌شدهٔ Lab استفاده می‌شود، نه مسیر تازهٔ فیلد بالا. فایل بازی تغییر نمی‌کند. ادامه؟'):return
        lab=state['lab'];launch(lambda:('local_review',local_review.continue_review(lab,max_batches=n,cancel=cancel,notify=progress)))
    def refresh_local_queue():
        if state['lab'] is None or state['plan'] is None:return
        if not messagebox.askyesno('بازسازی صف — بدون اینترنت',
            'صف از شواهد ذخیره‌شده دوباره ساخته می‌شود؛ metadata دانلود نمی‌شود.\n'
            'این کار ممکن است چند دقیقه طول بکشد و فضای دیسک اضافه بخواهد. برای هر نوبت بررسی لازم نیست؛ بعد از چند نوبت یا پایان بررسی انجام بده. ادامه؟'):return
        lab=state['lab']
        def task():
            report,p,q=local_review.refresh_queue(lab,cancel=cancel,notify=progress)
            return ('refreshed',report,p,q)
        launch(task)
    for label,fn in [('وضعیت بررسی محلی',review_status),('ادامه بررسی محلی — بدون اینترنت',continue_local),('به‌روزرسانی صف — بدون اینترنت',refresh_local_queue)]:
        b=ttk.Button(offline_panel,text=label,command=fn);b.pack(side='left',padx=3);controls.append(b)
    ttk.Label(offline_panel,text='حداکثر نوبت محلی:').pack(side='left',padx=4)
    e=ttk.Entry(offline_panel,textvariable=review_batches,width=5);e.pack(side='left');controls.append(e)
    limits_panel=ttk.Frame(root,padding=8);limits_panel.pack(fill='x')
    ttk.Label(limits_panel,text='حداکثر شیء در این نوبت:').pack(side='left')
    e=ttk.Entry(limits_panel,textvariable=object_limit,width=5);e.pack(side='left',padx=4);controls.append(e)
    ttk.Label(limits_panel,text='سقف بدنهٔ دریافت asset (MiB):').pack(side='left')
    e=ttk.Entry(limits_panel,textvariable=byte_limit,width=7);e.pack(side='left',padx=4);controls.append(e)
    ack=ttk.Checkbutton(root,text='می‌دانم این دریافت آزمایشی از صف مشروط است؛ نه حجم قطعی آپدیت و نه نصب کامل.',variable=acknowledge);ack.pack(anchor='w',padx=12);controls.append(ack)
    bottom=ttk.Frame(root,padding=10);bottom.pack(fill='x')
    def start():
        if local_review.queue_needs_refresh(state['lab']):
            messagebox.showwarning('صف قدیمی','ابتدا صف را با شواهد بررسی محلی به‌روزرسانی کن.');return
        if not acknowledge.get():messagebox.showwarning('تأیید','تأیید صف مشروط را فعال کن.');return
        try:limits=controller.parse_limits(object_limit.get(),byte_limit.get())
        except Exception as exc:messagebox.showwarning('سقف‌ها',runner.error_info(exc)['error_code']);return
        if not messagebox.askyesno('دریافت محدود در Lab',
            f'حداکثر {limits.max_objects} شیء و {limits.payload_bytes//runner.MiB} MiB بدنهٔ asset.\n'
            'بررسی نسخه چند درخواست کوچک metadata جدا دارد؛ TLS/سربار شبکه در سقف payload نیست.\n'
            'داده فقط در Lab ذخیره می‌شود؛ نصب/اجرا/تعمیر بازی انجام نمی‌شود. ادامه؟'):return
        lab,p,q=state['lab'],state['plan'],state['queue']
        launch(lambda:('download',runner.run_batch(lab,p,q,limits,cancel=cancel,notify=progress)[0]))
    start_button=ttk.Button(bottom,text='۲. دریافت محدود / ادامهٔ قبلی — بدون نصب',command=start,state='disabled');start_button.pack(side='left',padx=5)
    stop_button=ttk.Button(bottom,text='توقف امن',command=cancel.set,state='disabled');stop_button.pack(side='left')
    def poll():
        try:
            while True:
                typ,data=events.get_nowait()
                if typ=='progress':
                    hint=('خواندن/پردازش محلی — بدون اینترنت. هیچ فایل بازی تغییر نمی‌کند.' if data.get('network_requests')==0 else
                          'توقف شبکه ممکن است تا timeout اتصال طول بکشد. هیچ فایل بازی تغییر نمی‌کند.')
                    show(json.dumps(data,ensure_ascii=False,indent=2)+'\n\n'+hint)
                elif typ=='error':set_busy(False);show(json.dumps(data,ensure_ascii=False,indent=2)+'\nفقط گزارش‌های Retail با to-share را ارسال کن؛ PRIVATE/DB/فایل بازی را نفرست.')
                else:
                    if data[0] in ('prepared','refreshed'):
                        state['plan'],state['queue']=data[2],data[3]
                        show(json.dumps(data[1],ensure_ascii=False,indent=2))
                    elif data[0]=='update_scope':show('تفکیک پروفایل و اختلاف نسخه با شواهد محلی تمام شد؛ اسکن کامل تکرار نشد.\nاین پیش‌نمایش هنوز حجم قطعی آپدیت یا مجوز دریافت/نصب نیست؛ صف قبلی تغییر نکرده.\nفعلاً آماده‌سازی/اسکن/دریافت را نزن.\n\n'+json.dumps(data[1],ensure_ascii=False,indent=2)+'\n\nفقط گزارش عمومی Lab/objects را بفرست: Retail-Update-Scope-to-share-*.json')
                    elif data[0]=='preview':show(controller.display_preview(data[1]))
                    elif data[0]=='local_review':show(json.dumps(data[1],ensure_ascii=False,indent=2)+'\n\nاین مرحله بدون اینترنت است؛ بایت‌های خوانده‌شده مربوط به دیسک‌اند، نه دانلود. گزارش در Lab/objects: Retail-Local-Review-to-share-*.json\nاگر نامزد pending مانده، دوباره ادامه بررسی محلی را بزن؛ آماده‌سازی metadata را تکرار نکن.')
                    else:show(json.dumps(data[1],ensure_ascii=False,indent=2)+'\n\nگزارش عمومی در Lab/objects: Retail-Queue-Download-to-share-*.json\nPRIVATE، DB، blte یا فایل بازی را نفرست.')
                    set_busy(False)
                if state['closing'] and not state['busy']:root.destroy();return
        except queue.Empty:pass
        root.after(100,poll)
    def close():
        if state['busy']:
            if messagebox.askyesno('توقف','کار در حال اجراست. توقف امن و بستن پس از پایان worker؟'):
                state['closing']=True;cancel.set();show('در انتظار توقف امن؛ فایل‌های کامل و prefix ناتمام نگه داشته می‌شوند.')
        else:root.destroy()
    root.protocol('WM_DELETE_WINDOW',close)
    show('نسخهٔ Preview — شبکه خودکار شروع نمی‌شود.\n۱) Lab جدید بیرون بازی بساز یا Lab قبلی را باز کن.\n'
         '۲) آماده‌سازی metadata تأیید جداگانه می‌خواهد.\n۳) دریافت پیش‌فرض فقط ۳ شیء / ۱۶ MiB است.\n'
         'برای Lab با اسکن تمام‌شده و صف به‌روز: بازکردن Lab قبلی ← تفکیک آپدیت — بدون اینترنت.\n'
         'این برنامه هنوز نصب‌کننده/تعمیرکنندهٔ بازی نیست. دکمه‌های تازهٔ Windows در محیط سازنده آزموده نشده‌اند.')
    root.after(100,poll);root.mainloop();return 0


if __name__=='__main__':raise SystemExit(main())
