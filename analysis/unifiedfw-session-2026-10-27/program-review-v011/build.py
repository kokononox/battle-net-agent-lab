from pathlib import Path
import hashlib,json,subprocess,zipfile
r=Path('/data/ufw-program-review-v011');d=r/'package/UFW-PROGRAM-REVIEW-011';old=Path('/data/ufw-program-review-v01/package/UFW-PROGRAM-REVIEW-01');pw='/data/ufd-isolation-hf1/pwsh/pwsh';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert (d/'ProgramReader.cs').read_bytes()==(old/'ProgramReader.cs').read_bytes()
for n in ['ProgramReview.ps1','Run-Review.ps1']:(d/n).write_text((d/n).read_text(),newline='\r\n')
s=(d/'Run-Review.ps1').read_text();a=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");b=s.index("\n'@",a);s=s[:a]+json.dumps({n:sha(d/n) for n in ['ProgramReader.cs','ProgramReview.ps1']},indent=2)+s[b:];(d/'Run-Review.ps1').write_text(s,newline='\r\n')
def run(p,expected=0):
 v=subprocess.run([pw,'-NoProfile','-File',str(p)],capture_output=True,text=True,timeout=180);(r/'evidence'/(Path(p).name+'.log')).write_text(v.stdout+'\n'+v.stderr);assert v.returncode==expected,(str(p),v.stdout[-1000:],v.stderr[-1000:])
run('/data/ufw-program-review-v01/Test-ProgramReview.ps1');run(r/'Test-FilePickerReview.ps1');run(d/'Run-Review.ps1',1)
reports=list(d.glob('UFW-PROGRAM-REVIEW-011-*.json'));assert len(reports)==1;v=json.loads(reports[0].read_text('utf-8-sig'));assert v['code']=='ufw_program_windows_required' and v['review'] is None and not v['payload_verified'];reports[0].replace(r/'evidence/linux-platform-guard.json')
a=json.loads((r/'evidence/model-tests.json').read_text('utf-8-sig'));b=json.loads(Path('/data/ufw-program-review-v01/evidence/model-tests.json').read_text('utf-8-sig'));assert a['passed'] and a['assertions']==260 and b['passed'] and b['assertions']==147
(d/'README-FA.md').write_text('''# انتخاب فایل با پنجره — UFW-PROGRAM-REVIEW-011

در این نسخه دیگر تایپ مسیر لازم نیست؛ پنجرهٔ انتخاب فایل Windows باز می‌شود. هستهٔ C# مشاهدهٔ EXE بدون تغییر بایت از نسخهٔ قبل است. این ابزار **فایل انتخابی را اجرا نمی‌کند**، program config ذخیره نمی‌کند و به firewall/VPN/journal دسترسی نمی‌خواهد.

## اجرا

1. ZIP را در پوشهٔ محلی تازه و جدا Extract کنید. شبکه و SSTP همان وضعیت فعلی بمانند؛ نه reboot و نه اجرای نصاب لازم است.
2. `Run-Review.cmd` را با دوبارکلیک معمولی اجرا کنید؛ **ادمین لازم نیست**. Windows PowerShell 5.1 x64 لازم است و CMD آن را با `-STA` برای پنجره باز می‌کند.
3. در پنجرهٔ انتخاب فایل، به پوشهٔ نصاب موجود خودتان بروید، EXE را انتخاب و **Open** را بزنید. Open در این پنجره یعنی انتخاب برای خواندن، نه اجرای نصاب. فعلاً یک فایل کافی است. اگر helper مشخص و موردنظر دیگری دارید با Ctrl چند EXE انتخاب کنید؛ حداکثر ۱۶ فایل. برنامه‌های child/helper/service خودکار انتخاب یا مجاز نمی‌شوند.
4. مسیر باید روی دیسک ثابت محلی باشد، نه Network/UNC/OneDrive reparse یا shortcut. پوشهٔ شبکه را مرور نکنید و preview را فعال نکنید. اگر فایل موجود ندارید، **Cancel** کنید؛ فایل نامربوط انتخاب نکنید.
5. پس از انتخاب، به پنجرهٔ CMD برگردید و تا نتیجه صبر کنید. فقط فایل تازهٔ `UFW-PROGRAM-REVIEW-011-*.json` را بفرستید، حتی در لغو/شکست. pause آخر CMD فقط برای بستن پنجره است؛ دیگر پرسش تایپ مسیر نداریم.

**مسیر، هش، شناسهٔ فایل، خود EXE یا عکس/متن کامل پنجره را نفرستید.** اطلاعات خصوصی فقط در پنجرهٔ محلی نمایش داده می‌شوند، نه گزارش. اگر JSON ساخته نشد فقط stage/code کوتاه را بدون مسیر خصوصی بفرستید. در شکست فایل یا تنظیمات را خودسرانه عوض نکنید.

## انتخاب و لغو

Cancel یعنی بدون فراخوانی observer هویت EXE پایان می‌یابد؛ completed=true در cancellation، موفقیت بررسی فایل نیست. خود پنجرهٔ Windows برای نمایش فهرست فایل‌ها، metadata یا icon ممکن است filesystem/shell را بخواند، مسیرهای اخیر را نگه دارد و در صورت رفتن به Network دسترسی شبکه‌ای ایجاد کند. AutoUpgrade=false، DereferenceLinks=false، ValidateNames/CheckFileExists/CheckPathExists=true و RestoreDirectory=true تنظیم شده‌اند؛ این تنظیم‌ها sandbox یا تضمین صفر شبکهٔ shell نیستند. ابزار خودش resolver/درخواست HTTP یا اجرای EXE منتخب ندارد، اما نبود ترافیک کل سیستم/handlerهای ثبت‌شده با packet capture اثبات نشده است.

تعداد نامعتبر، انتخاب بیش از ۱۶ فایل، مسیر نامعتبر یا تکراری پیش از اجرای observer روی هر EXE رد می‌شود؛ truncation خودکار نداریم. تکرار identity پس از observation هم رد می‌شود. خطای فایل میانی، ادامهٔ خواندن بقیه و ساخت config انجام نمی‌دهد؛ observed_count فقط تعداد قبلی را نشان می‌دهد و completed=false است.

## هستهٔ مشاهدهٔ بدون تغییر

local absolute exe path؛ fixed drive؛ pin والدها از root به leaf با OPEN_REPARSE_POINT و handle بدون write/delete sharing؛ رد junction/symlink/reparse/UNC/ADS/wildcard/مسیر غیرcanonical؛ فایل OPEN_EXISTING/GENERIC_READ/share READ. یک hardlink، size حداکثر ۵۱۲ MiB، PE header offset حداکثر ۱ MiB، header EXE x86/x64 و subsystem GUI/CUI. DLL و shared-hostهای شناخته‌شدهٔ svchost/rundll32/dllhost پذیرفته نمی‌شوند؛ این denylist تشخیص کامل broker نیست. PE header بررسی اولیه است، نه loader کامل یا اثبات سالم‌بودن کد.

دو SHA256 روی یک handle و مقایسهٔ file ID/volume/metadata/final path انجام می‌شود؛ handleها در using/finally آزاد می‌شوند. هم‌زمان نصاب/update روی همان فایل/مسیر اجرا نکنید؛ عملیات متعارض ممکن است موقتاً رد شود. پس از آزادسازی فایل قابل تغییر است و در Apply آینده بازبینی تازه لازم است. effective ACL/ناشر/Authenticode/ابطال/اعتماد برنامه بررسی نشده‌اند؛ hash و هویت مشاهده‌شده approval یا consent نیستند. دفاع در برابر admin/درایور مخرب یا تغییرات پیشرفتهٔ namespace تضمین نشده است.

نام و ID/hash برنامه محلی‌اند؛ پیکربندی یا مجوز دائمی ساخته نمی‌شود. picker به معنی دادن مجوز شبکه نیست. recorder، destination review، native Apply/recovery، binding/reconnect SSTP، mode switch، reboot، no-leak و fingerprint همچنان qualified نشده‌اند. آزمون‌های storage/preparation/reopen قبلی را تکرار نکنید و ژورنال محافظت‌شده را تغییر ندهید.

## شواهد و بسته

۲۶۰ assertion انتخاب/لغو/چندفایلی/حریم‌خصوصی در ۱۶ سناریوی mock پاس شدند؛ ۱۴۷ assertion نسخهٔ قبلی reader/review دوباره پاس شدند. C# همان نسخهٔ قبل است و روی Linux کامپایل شده؛ dialog واقعی Windows و Windows file API در این تست‌ها اجرا نشده‌اند. دو PS1 و bootstrap/manifest/ZIP کنترل شدند. receipt قبلی Windows فقط cancellation بدون انتخاب بود، نه موفقیت native file observation؛ این فاصله هنوز باقی است.

CMD ابتدا SHA256 manifest و payload را بررسی، فقط دو PS1 همین بسته را Unblock و RemoteSigned را فقط برای process فرزند اعمال می‌کند؛ نه policy دائمی/GPO. امضای ناشر یا sandbox نداریم؛ SHA256 ZIP را با مقدار تحویل تطبیق دهید. Add-Type از helper همین بسته استفاده می‌کند و compiler ممکن است Temp/cache بسازد؛ گزارش کنار بسته هم فایل جدید است. مشاهدهٔ محلی داخل console/memory می‌ماند و پاک‌سازی متغیرها تضمین پاک‌کردن امن حافظه/scrollback نیست.
''')
(d/'evidence').mkdir(exist_ok=True)
for p,n in [(r/'evidence/model-tests.json','picker-model.json'),(Path('/data/ufw-program-review-v01/evidence/model-tests.json'),'prior-reader-review-regression.json'),(r/'evidence/linux-platform-guard.json','linux-platform-guard.json')]:(d/'evidence'/n).write_bytes(p.read_bytes())
check="$ErrorActionPreference='Stop';$root='ROOT';$files=@(Get-ChildItem $root -Filter *.ps1);if($files.Count -ne 2){throw 'file_count'};foreach($f in $files){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e);if($e.Count){throw 'parse'}};Write-Host 'Two package PS files parsed.'".replace('ROOT',str(d));(r/'Check-Source.ps1').write_text(check);run(r/'Check-Source.ps1')
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Review.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Review.cmd').read_text().replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('Local Program Review 0.1 - READ EXE ONLY, NEVER EXECUTE. Keep VPN and network as they are.','Local Program Review 0.1.1 - CHOOSE EXE IN FILE WINDOW; NEVER EXECUTE.').replace('-NoLogo -NoProfile','-NoLogo -NoProfile -STA');(d/'Run-Review.cmd').write_text(cmd,newline='\r\n');assert '-STA' in cmd
s=Path('/data/ufw-program-review-v01/Check-Bootstrap.ps1').read_text().replace(str(old),str(d));(r/'Check-Bootstrap.ps1').write_text(s);run(r/'Check-Bootstrap.ps1')
z=r/'UFW-PROGRAM-REVIEW-011.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 assert out.testzip() is None
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,new_picker_assertions=260,picker_mock_scenarios=16,prior_reader_review_assertions_rerun=147,native_reader_sha256=sha(d/'ProgramReader.cs'),native_reader_byte_unchanged=True,real_Windows_dialog_executed=False,Windows_file_API_executed=False,package_PS_files_parsed=2,bootstrap_parsed_payload_verified=True,STA_command=True,administrator_required=False,user_action='normal double-click Run-Review.cmd, choose existing installer EXE in file window and Open; Cancel if absent; return new diagnostic only',program_config_saved=False,ready_for_apply=False);(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
