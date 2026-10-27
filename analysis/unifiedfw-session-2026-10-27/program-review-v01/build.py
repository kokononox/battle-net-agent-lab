from pathlib import Path
import hashlib,json,subprocess,zipfile
r=Path('/data/ufw-program-review-v01');d=r/'package/UFW-PROGRAM-REVIEW-01';old=Path('/data/ufw-reopen-session-v01/package/UFW-REOPEN-SESSION-01');pw='/data/ufd-isolation-hf1/pwsh/pwsh';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n in ['ProgramReader.cs','ProgramReview.ps1','Run-Review.ps1']:(d/n).write_text((d/n).read_text(),newline='\r\n')
s=(d/'Run-Review.ps1').read_text();a=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");b=s.index("\n'@",a);s=s[:a]+json.dumps({n:sha(d/n) for n in ['ProgramReader.cs','ProgramReview.ps1']},indent=2)+s[b:];(d/'Run-Review.ps1').write_text(s,newline='\r\n')
def run(p,expected=0):
 v=subprocess.run([pw,'-NoProfile','-File',str(p)],capture_output=True,text=True,timeout=180);(r/'evidence'/(Path(p).name+'.log')).write_text(v.stdout+'\n'+v.stderr);assert v.returncode==expected,(str(p),v.stdout[-1000:],v.stderr[-1000:])
run(r/'Test-ProgramReview.ps1');run(d/'Run-Review.ps1',1)
reports=list(d.glob('UFW-PROGRAM-REVIEW-01-*.json'));assert len(reports)==1;v=json.loads(reports[0].read_text('utf-8-sig'));assert v['code']=='ufw_program_windows_required' and v['review'] is None and not v['payload_verified'];reports[0].replace(r/'evidence/linux-platform-guard.json')
v=json.loads((r/'evidence/model-tests.json').read_text('utf-8-sig'));assert v['passed'] and v['assertions']==147
(d/'README-FA.md').write_text('''# مشاهدهٔ محلی فایل برنامه — UFW-PROGRAM-REVIEW-01

این بسته مسیرهای EXE را از خود شما می‌گیرد و فقط فایل را می‌خواند. هیچ‌یک از فایل‌های انتخاب‌شده اجرا نمی‌شوند؛ هیچ firewall/VPN/DNS/route/rule/task یا journal خوانده/تغییر داده نمی‌شود. **این انتخاب یا نمایش، مجوز اعتماد/Apply نیست و config برنامه هم ذخیره نمی‌شود.** هدف این گام، آزمودن مشاهدهٔ بومی فایل‌های واقعی پیش از اتصال آن به پلن برنامه‌محور است.

## اجرا

1. در پوشهٔ محلی تازه و جدا از برنامهٔ قدیمی/بسته‌های قبلی Extract کنید. شبکه/SSTP همان وضعیت بمانند؛ reboot یا اجرای برنامهٔ نصاب لازم نیست.
2. `Run-Review.cmd` را با دوبارکلیک معمولی اجرا کنید. **Run as administrator لازم نیست**؛ Windows PowerShell 5.1 x64 لازم است. همان حسابی که به فایل نصاب دسترسی دارد کافی است.
3. وقتی مسیر خواست، مسیر کامل EXE نصاب موجود روی سیستم آزمایشی را وارد کنید، مثلاً فایل واقعی Battle.net-Setup.exe خودتان؛ مسیر نمونهٔ فرضی وارد نکنید و فایل را اجرا نکنید. اگر مسیر را در گیومه وارد کنید فقط جفت گیومهٔ بیرونی حذف می‌شود؛ whitespace اضافی/متغیر محیطی یا مسیر نسبی اصلاح نمی‌شوند.
4. فعلاً یک EXE شناخته‌شدهٔ نصاب کافی است. فقط اگر helper مشخص و موردنظر دیگری دارید مسیرش را جدا وارد کنید؛ child/helper/service خودکار شناسایی یا مجاز نمی‌شود. حداکثر ۱۶ فایل؛ Enter خالی انتخاب را تمام می‌کند. Enter در ابتدای کار بدون خواندن EXE لغو می‌کند.
5. جدول خصوصی مسیر/هش/شناسهٔ فایل را فقط محلی ببینید. تا نمایش نتیجه صبر کنید و فقط JSON تازهٔ `UFW-PROGRAM-REVIEW-01-*.json` را بفرستید، حتی در لغو/شکست. پنجرهٔ CMD در پایان فقط pause دارد.

**مسیر، هش، شناسهٔ فایل، خود EXE و عکس/متن کامل پنجره را نفرستید.** اگر JSON ساخته نشد، فقط stage/code کوتاه را بدون مسیر خصوصی بفرستید. در شکست، فایل یا تنظیمات را تغییر ندهید؛ کد خطا کافی است. اگر نصاب موجود/مسیرش را ندارید Enter بزنید؛ برای pass فایل ساختگی یا برنامه‌ای نامربوط انتخاب نکنید.

## کنترل‌های پیاده‌شده

- ورودی local absolute با drive uppercase، exe، بدون UNC/device path/ADS/wildcard/environment expansion، segment نقطه/فضای انتهایی یا نام رزروشده؛ fixed local drive. فایل ابری reparse، junction، symbolic link و مسیر alias غیرcanonical در نسخهٔ فعلی رد می‌شوند، نه اینکه خودکار دنبال/کپی شوند. نام‌های shared-host شناخته‌شدهٔ svchost/rundll32/dllhost به طراحی service-scoped جدا نیاز دارند و رد می‌شوند؛ این فهرست تشخیص کامل broker نیست.
- parent directory handleها از root به leaf با OPEN_REPARSE_POINT و BACKUP_SEMANTICS باز می‌شوند؛ reparse پیش از پایین‌رفتن رد می‌شود و handleها تا پایان مشاهده بدون write/delete sharing نگه داشته می‌شوند. اگر pin ممکن نباشد توقف می‌کند. فایل هم OPEN_EXISTING با GENERIC_READ و share READ، بدون write/delete sharing، باز می‌شود. همهٔ handleها در finally/using بسته می‌شوند. در مدت خواندن، عملیات متعارض روی همان فایل/پوشه ممکن است موقتاً رد شود؛ هم‌زمان installer/update روی این مسیر اجرا نکنید.
- final path باید با مسیر انتخابی برابر باشد؛ directory/reparse و بیش از یک hardlink رد می‌شوند. size حداکثر ۵۱۲ MiB، PE header offset حداکثر ۱ MiB؛ EXE header x86/x64 و subsystem GUI/CUI پذیرفته می‌شود. DLL/native subsystem/معماری دیگر/ساختار نامعتبر رد می‌شود. بررسی PE فقط کنترل اولیهٔ header است، نه loader کامل یا اثبات قابل‌اجرابودن/سلامت کد.
- دو SHA256 روی همان handle، همراه با تطبیق file index/volume/size/mtime/creation/attributes/link count و final path. parentها در تمام مشاهده pinned هستند؛ مشاهدهٔ تغییر باعث توقف است. هویت و hash داخل حافظه و پنجرهٔ محلی‌اند؛ report فقط شمارنده، معماری header و flags محدود دارد. actual ACL/effective write authority و Authenticode/trust بررسی نمی‌شوند؛ revalidation هنگام Apply آینده الزامی است.

## مرزها

فایل درست و دو هش مساوی **به معنی معتبر/ایمن‌بودن ناشر یا برنامه نیست**. ابزار Get-AuthenticodeSignature/WinVerifyTrust یا اعتبارسنجی آنلاین امضا/ابطال را صدا نمی‌زند، تا این گام درخواست عمدی شبکه نداشته باشد؛ absence ترافیک سیستم با packet capture اثبات نشده است. درایور مخرب/admin مخرب یا تغییر namespace پیشرفته خارج از ضمانت این مشاهده‌اند. پس از آزادشدن handle فایل می‌تواند تغییر کند؛ output، pin دائمی یا consent نیست.

بررسی native API به خودی خود گزارش شبکه یا تشخیص فرآیندهای فرزند نیست. برنامه‌های مورد نیاز واقعی، destination review و recorder هنوز باید به مسیر بعدی متصل شوند. private config ساخته نمی‌شود؛ انتخاب path در مرحلهٔ بعد ممکن است دوباره لازم شود و در هر Apply آینده هویت فایل باید تازه بررسی شود. این نسخه صرفاً observer است، نه تکمیل recorder یا پروفایل قابل‌اعمال.

CMD manifest و payload را با SHA256 کنترل و فقط دو PS1 همین بسته را Unblock می‌کند؛ .cs فقط به‌صورت متن خوانده می‌شود. RemoteSigned فقط process فرزند است، نه policy دائمی/GPO. هیچ بسته‌ای sandbox یا امضاشدهٔ ناشر نیست؛ SHA256 ZIP را با مقدار تحویل تطبیق دهید. Add-Type helper همین بسته را با کامپایلر .NET می‌سازد و ممکن است فایل‌های موقت compiler/cache در Temp ایجاد کند؛ EXE انتخابی شما اجرا نمی‌شود. گزارش کنار بسته هم یک فایل جدید است. پاک‌کردن متغیرها تضمین پاک‌شدن فیزیکی حافظه/console نیست؛ از screenshot/transcript خودداری کنید.

## شواهد

۱۴۷ assertion روی Linux/PowerShell7 پاس شده: کامپایل واقعی C# با ساختار سازگار C# قدیمی، fixtureهای path/PE، metadata-drift شبیه‌سازی‌شده، review/prompt/native observation mock، لغو/حداکثر/duplicate/failure/privacy و static boundary. این آزمون‌ها API واقعی Windows یا parent pin/هویت فایل واقعی/سازگاری runtime WinPS5.1 را اجرا نکرده‌اند. package guard روی Linux پیش از انتخاب متوقف شد؛ دو PS1 و CMD parse و hashها کنترل شده‌اند. نتیجهٔ Windows این observer هنوز pending است؛ نه native firewall write، SSTP، mode-switch، reboot، no-leak یا جلوگیری از fingerprint تأیید نشده‌اند.

آزمون‌های قبلی storage/preparation/reopen موفق‌اند و تکرار نمی‌شوند. فقط این مرحلهٔ جدید به هویت فایل برنامه مربوط است. ژورنال محافظت‌شدهٔ قبلی را نگه دارید؛ هیچ Apply/Restore/تغییر Allow لازم نیست.
''')
(d/'evidence').mkdir(exist_ok=True)
for n in ['model-tests.json','linux-platform-guard.json']:(d/'evidence'/n).write_bytes((r/'evidence'/n).read_bytes())
check="$ErrorActionPreference='Stop';$root='ROOT';$files=@(Get-ChildItem $root -Filter *.ps1);if($files.Count -ne 2){throw 'file_count'};foreach($f in $files){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e);if($e.Count){throw 'parse'}};Write-Host 'Two package PS files parsed.'".replace('ROOT',str(d));(r/'Check-Source.ps1').write_text(check);run(r/'Check-Source.ps1')
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Review.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Reopen.cmd').read_text().replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('UFW_REOPEN_ROOT','UFW_PROGRAM_ROOT').replace('Read-only Journal Reopen 0.1 - NO JOURNAL OR FIREWALL CHANGES. Keep VPN and network as they are.','Local Program Review 0.1 - READ EXE ONLY, NEVER EXECUTE. Keep VPN and network as they are.')
a=cmd.index(';$who=New-Object');b=cmd.index(';$m=Join-Path',a);cmd=cmd[:a]+cmd[b:]
cmd=cmd.replace("'Ufw.ProfileReader.psm1','Ufw.InstallerCore.psm1','Ufw.SessionJournal.psm1','ReopenEntry.ps1','Run-Reopen.ps1'","'ProgramReview.ps1','Run-Review.ps1'").replace('Run-Reopen.ps1','Run-Review.ps1').replace('Five package scripts/modules unblocked.','Two package scripts unblocked.').replace('Read-only validation not confirmed.','Program observation not confirmed.')
a=cmd.index("catch{Write-Host ('STARTUP ERROR:");b=cmd.index(';exit 1}',a);cmd=cmd[:a]+"catch{Write-Host 'STARTUP ERROR: package startup checks stopped; no review completed.';Write-Host 'If no new JSON exists, return this short message without private paths.'"+cmd[b:]
assert '$who' not in cmd and 'Run-Reopen' not in cmd and 'Two package' in cmd;(d/'Run-Review.cmd').write_text(cmd,newline='\r\n')
s=Path('/data/ufw-reopen-session-v01/Check-Bootstrap.ps1').read_text().replace(str(old),str(d)).replace('Run-Reopen.cmd','Run-Review.cmd');(r/'Check-Bootstrap.ps1').write_text(s);run(r/'Check-Bootstrap.ps1')
z=r/'UFW-PROGRAM-REVIEW-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 assert out.testzip() is None
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,model_assertions=147,CSharp_compiled_on_Linux=True,Windows_file_API_executed=False,package_PS_files_parsed=2,bootstrap_parsed_payload_verified=True,administrator_required=False,user_action='normal double-click Run-Review.cmd; select existing installer EXE full local path, Enter finishes; do not execute it; return diagnostic only, not paths/hashes/screenshots',program_config_saved=False,firewall_change_requested=False,ready_for_apply=False);(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
