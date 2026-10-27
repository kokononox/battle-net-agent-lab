from pathlib import Path
import json, hashlib, subprocess, zipfile
r=Path('/data/ufd-normal-exit-runner-v01');d=r/'package/NORMAL-EXIT-REVIEW-01';c=Path('/data/ufd-normal-exit-hf124/candidate');pw='/data/ufd-isolation-hf1/pwsh/pwsh'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mods=['session-core.ps1','native.ps1','isolation-core.ps1','isolation-native.ps1','normal-exit-record.ps1','Qualification.ps1']
s=(d/'Run-Exit.ps1').read_text();start=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");end=s.index("\n'@",start);s=s[:start]+json.dumps({n:sha(d/n) for n in mods},indent=2)+s[end:];(d/'Run-Exit.ps1').write_text(s,newline='\r\n')
def run(path,*args,code=0):
 p=subprocess.run([pw,'-NoProfile','-File',str(path),*map(str,args)],capture_output=True,text=True,timeout=180)
 (r/(Path(path).name+'.log')).write_text(p.stdout+'\n'+p.stderr);assert p.returncode==code,(path,p.stdout[-2500:],p.stderr[-2500:])
run(r/'Test-Runner.ps1');run(c/'tests/Test-NormalExitRecord124.ps1','-Root',c)
model=json.loads((r/'MODEL-RESULTS.json').read_text());library=json.loads((c/'evidence/normal-exit-hf124-tests.json').read_text('utf-8-sig'));assert model['passed'] and model['assertions']==47;assert library['passed'] and library['assertions']==72
mapping={'session-core.ps1':'lab/session-core.ps1','native.ps1':'lab/native.ps1','isolation-core.ps1':'app/isolation-core.ps1','isolation-native.ps1':'app/isolation-native.ps1','normal-exit-record.ps1':'app/normal-exit-record.ps1'}
for n,src in mapping.items():assert (d/n).read_bytes()==(c/src).read_bytes(),n
check="""$ErrorActionPreference='Stop';$root='ROOT';$n=0;foreach($f in Get-ChildItem $root -Filter *.ps1){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e);if($e.Count){throw ('parse '+$f.Name)};$n++};if($n -ne 7){throw 'file_count'};Write-Host 'Seven package PS files parsed.'
""".replace('ROOT',str(d));(r/'Check-Source.ps1').write_text(check);run(r/'Check-Source.ps1');run(d/'Run-Exit.ps1',code=1)
reports=list(d.glob('NORMAL-EXIT-REVIEW-01-*.json'));assert len(reports)==1
v=json.loads(reports[0].read_text('utf-8-sig'));assert v['code']=='exit_runner_windows_required' and v['storage_qualification'] is None and not v['payload_verified'] and not v['diagnostic_completed'];reports[0].replace(r/'linux-platform-guard.json')
(d/'README-FA.md').write_text('''# بازبینی خروج عادی — نسخهٔ ۰٫۱

این بسته برای بررسی ذخیره‌سازی محافظت‌شده و ثبت **اختیاریِ انتخاب فعلی شبکهٔ عادی** است، نه روشن‌کردن ایزولاسیون یا اصلاح فایروال. اینترنت و VPN را در همان وضعیت فعلی نگه دارید؛ روشن‌کردن SSTP، ری‌استارت یا اجرای Apply/Restore لازم نیست. روی پوشهٔ برنامهٔ قبلی کپی نکنید.

## اجرا

1. ZIP را در پوشهٔ محلی تازه Extract کنید.
2. `Run-Exit.cmd` را با Run as administrator و همان حساب ویندوز قبلی اجرا کنید. Windows PowerShell 5.1 نسخهٔ ۶۴بیتی لازم است.
3. ابتدا یک پوشهٔ آزمایشی منحصربه‌فرد در ProgramData ساخته می‌شود. فقط با اطلاعات ساختگی، مالکیت/DACL محافظت‌شدهٔ admin و SYSTEM، نوشتن و بازخوانی، جلوگیری از overwrite و قفل انحصاری بررسی می‌شوند. پاک‌سازی فقط فایل‌های شناخته‌شدهٔ همان پوشه را حذف می‌کند، نه زیرشاخه‌ها. شکست این مرحله، مرحلهٔ واقعی را متوقف می‌کند؛ پوشهٔ مشکوک خودکار حذف نمی‌شود.
4. سپس ژورنال قدیمی و قواعد و وضعیت واقعی فقط خوانده می‌شوند. بررسی before-image حدود صد قاعده ممکن است طول بکشد؛ فرمان را دوباره اجرا نکنید. هیچ زمان اجرای تضمین‌شده‌ای نداریم.
5. تنها اگر بررسی واقعی موفق باشد، جدول پروفایل‌ها و عبارت تصادفی `RECORD NORMAL ...` نشان داده می‌شود. تایپ دقیق آن، رضایت برای **ایجاد یا بازتأیید یک رکورد جداگانهٔ محافظت‌شده** است. Enter خالی یا هر پاسخ دیگری لغو می‌کند؛ لغو هم نتیجهٔ مفید دارد و نوشتن رکورد واقعی درخواست نمی‌شود.
6. فقط فایل تازهٔ `NORMAL-EXIT-REVIEW-01-*.json` را برگردانید، حتی در لغو یا شکست. ژورنال اصلی، رکورد محافظت‌شده، backup، transcript یا عکس پنجره را نفرستید. اگر JSON ساخته نشد، متن کوتاه stage/code خطا را بدون مسیر و اطلاعات شخصی بفرستید.

## چه چیزی تغییر نمی‌کند؟

هیچ فرمان تغییر فایروال، قاعده، VPN، route، DNS، task یا controller اجرا نمی‌شود؛ درخواست DNS و probe شبکه تولید نمی‌شود. ژورنال واقعی `session.json` بازنویسی نمی‌شود و hash آن قبل/بعد کنترل می‌شود. علاوه بر فایل گزارش، فایل‌های fixture موقت و قفل هماهنگی `operation.lock` ممکن است ساخته شوند. در صورت رضایت، فقط رکورد جداگانهٔ normal-mode در ریشهٔ محافظت‌شدهٔ موجود نوشته می‌شود؛ فایل موجود overwrite نمی‌شود.

اگر نوشتن درخواست شود و بازخوانی یا بررسی بعدی شکست بخورد، ممکن است رکورد ایجاد شده باشد. مقدار `live_record_write_status=attempted_inspect_protected_record_if_failed` یعنی نتیجه را بفرستید و خودسرانه تکرار/حذف نکنید، نه اینکه قطعاً هیچ فایلی نوشته نشده است. لغو پیش از Record، رکورد موجود احتمالی را حذف نمی‌کند.

این رکورد نشان‌دهندهٔ انتخاب صریح شبکهٔ عادی فعلی است؛ **بازگردانی دقیق baseline اصلی، رفع علت Block پس از reboot، مجوز Apply یا migration ژورنال قدیمی نیست**. همهٔ مسیرهای قدیمی Apply/Restore و آزمون قطع‌و‌وصل ایزولاسیون همچنان متوقف‌اند. هیچ تضمین no-leak یا جلوگیری از fingerprint وجود ندارد.

## مرز آزمون و امنیت

۴۷ assertion راه‌انداز/رضایت/مرزبندی و ۷۲ assertion کتابخانه روی Linux گذشتند. آزمون prompt و ACL metadata در این مدل mock هستند؛ آزمون واقعی Windows این بسته هنوز انجام نشده است. مرحلهٔ Windows فقط metadata مجوزها و عملیات واقعی فایل و قفل fixture را می‌سنجد، نه دسترسی مؤثر تمام کاربران با impersonation، نه امنیت در برابر administrator مخرب. قفل cooperative است؛ مشاهدهٔ وضعیت سیستم اتمیک نیست. صحت بازیابی بعد reboot سنجیده نمی‌شود.

پنج وابستگی تولیدی HF1.2.4 بدون تغییر بایت بسته‌بندی شده‌اند. وجود تعریف تابع mutator در وابستگی‌ها به معنی فراخوانی آن نیست؛ راه‌انداز فقط مسیر Review/Record و fixture را فراخوانی می‌کند. بسته controller برنامه را ارتقا نمی‌دهد.

راه‌انداز ابتدا SHA256 manifest و همهٔ payload را بررسی می‌کند و فقط هفت PS1 همین بسته را Unblock می‌کند. RemoteSigned فقط برای پردازش فرزند است؛ سیاست دائمی یا GPO تغییر نمی‌کند. CMD امضای ناشر ندارد؛ hash کل ZIP را با مقدار تحویل مقایسه کنید. گزارش خروجی فاقد شناسهٔ ژورنال، نام/IP سرور، نام قواعد، digest و challenge است؛ مسیر فایل گزارش فقط در پنجرهٔ محلی چاپ می‌شود.
''')
(d/'evidence').mkdir(exist_ok=True)
for src,name in [(r/'MODEL-RESULTS.json','runner-model.json'),(c/'evidence/normal-exit-hf124-tests.json','library-model.json'),(r/'linux-platform-guard.json','linux-platform-guard.json')]: (d/'evidence'/name).write_bytes(src.read_bytes())
prov=dict(production_dependencies_byte_unchanged={n:dict(source=src,sha256=sha(d/n)) for n,src in mapping.items()},new_files=['Qualification.ps1','Run-Exit.ps1','Run-Exit.cmd'],runner_assertions=47,library_assertions=72,Windows_native_storage_qualification_executed=False,real_user_record_created=False,real_human_prompt_tested=False,firewall_changed=False,controller_upgraded=False,ready_for_apply=False)
(d/'PROVENANCE.json').write_text(json.dumps(prov,indent=2))
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Exit.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
old=Path('/data/sstp-observer-v02/package/SSTP-READONLY-OBSERVER-02');cmd=(old/'Run-Observer.cmd').read_text().replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('SSTP_OBS_ROOT','NORMAL_EXIT_ROOT').replace('SSTP Observer 0.2 - READ ONLY. Do not change the current VPN state.','Normal Exit Review 0.1 - NO FIREWALL CHANGES. Keep VPN and network as they are.').replace("'IdentityPolicy.ps1','Identity.ps1','Observer.ps1','Run-Observer.ps1'",','.join(repr(n) for n in mods+['Run-Exit.ps1'])).replace('Run-Observer.ps1','Run-Exit.ps1').replace('Four package scripts','Seven package scripts').replace('Observation not confirmed.','Review or record not confirmed.');(d/'Run-Exit.cmd').write_text(cmd,newline='\r\n')
s=Path('/data/sstp-observer-v02/Check-Bootstrap.ps1').read_text().replace(str(old),str(d)).replace('Run-Observer.cmd','Run-Exit.cmd');(r/'Check-Bootstrap.ps1').write_text(s);run(r/'Check-Bootstrap.ps1')
z=r/'NORMAL-EXIT-REVIEW-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 assert out.testzip() is None
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,runner_assertions=47,library_assertions=72,package_PS_files_parsed=7,bootstrap_parsed_and_payload_hashes_verified=True,production_dependencies_byte_unchanged=True,Windows_storage_qualification_executed=False,user_action='new package only; keep current internet and VPN state; optional separate record consent',ready_for_apply=False);(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
