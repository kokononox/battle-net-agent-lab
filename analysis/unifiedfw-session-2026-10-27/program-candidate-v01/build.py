from pathlib import Path
import json,hashlib,subprocess,zipfile
r=Path('/data/ufw-program-candidate-v01');d=r/'package/UFW-PROGRAM-CANDIDATE-01';old=Path('/data/ufw-program-review-v011/package/UFW-PROGRAM-REVIEW-011');pw='/data/ufd-isolation-hf1/pwsh/pwsh';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();mods=['Ufw.ProfileReader.psm1','Ufw.InstallerCore.psm1','Ufw.SessionJournal.psm1']
for n in mods:assert (d/n).read_bytes()==(Path('/data/ufw-session-journal-v01/source')/n).read_bytes()
for n in ['ProgramReader.cs','ProgramReview.ps1']:assert (d/n).read_bytes()==(old/n).read_bytes()
for n in ['CandidateEntry.ps1','Run-Candidate.ps1']:(d/n).write_text((d/n).read_text(),newline='\r\n')
deps=mods+['ProgramReader.cs','ProgramReview.ps1','CandidateEntry.ps1'];s=(d/'Run-Candidate.ps1').read_text();a=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");b=s.index("\n'@",a);s=s[:a]+json.dumps({n:sha(d/n) for n in deps},indent=2)+s[b:];(d/'Run-Candidate.ps1').write_text(s,newline='\r\n')
def run(p,expected=0):
 v=subprocess.run([pw,'-NoProfile','-File',str(p)],capture_output=True,text=True,timeout=180);(r/'evidence'/(Path(p).name+'.log')).write_text(v.stdout+'\n'+v.stderr);assert v.returncode==expected,(str(p),v.stdout[-1000:],v.stderr[-1000:])
run(r/'Test-ProgramCandidate.ps1');run('/data/ufw-session-journal-v01/tests/Test-SessionJournal.ps1');run('/data/ufw-program-review-v011/Test-FilePickerReview.ps1');run(d/'Run-Candidate.ps1',1)
reports=list(d.glob('UFW-PROGRAM-CANDIDATE-01-*.json'));assert len(reports)==1;v=json.loads(reports[0].read_text('utf-8-sig'));assert v['code']=='ufw_candidate_windows_required' and v['candidate'] is None and not v['payload_verified'];reports[0].replace(r/'evidence/linux-platform-guard.json')
m=json.loads((r/'evidence/model-tests.json').read_text('utf-8-sig'));assert m['passed'] and m['assertions']==236
(d/'README-FA.md').write_text('''# ثبت پیش‌نویس برنامه‌های نصاب — UFW-PROGRAM-CANDIDATE-01

این مرحله برای اولین بار **فهرست خصوصی برنامه‌های انتخابی را محلی و محافظت‌شده ذخیره می‌کند**؛ فقط پس از بازبینی و کلیک صریح Save candidate. هنوز مقصدی ندارد و پروفایل کامل/قابل‌اعمال نیست. هیچ EXE اجرا، trust/Authenticode بررسی، یا firewall/VPN/DNS/route/rule/task/baseline journal خوانده/تغییر داده نمی‌شود. ماژول‌های storage فقط برای helperهای مسیر/ACL/فایل reuse شده‌اند، نه اجرای session یا Apply.

## اجرا روی همان سیستم آزمایشی

1. ZIP را در پوشهٔ محلی تازه و جدا Extract کنید؛ روی برنامهٔ قبلی یا بسته‌های قبلی کپی نکنید. شبکه/SSTP و ژورنال baseline قبلی همان وضعیت بمانند؛ نه reboot و نه تکرار آزمون قبلی لازم است.
2. `Run-Candidate.cmd` را **با Run as administrator و همان حساب ویندوز** اجرا کنید. برخلاف نسخهٔ مشاهده، این بار ادمین برای ایجاد پوشهٔ محافظت‌شدهٔ Administrators/SYSTEM در ProgramData لازم است، نه برای خواندن یا اجرای نصاب. Windows PowerShell 5.1 x64/STA لازم است.
3. در پنجرهٔ انتخاب فایل، همان EXE واقعی نصاب موجود را انتخاب و Open بزنید؛ فایل اجرا نمی‌شود. فعلاً یک فایل کافی است. Ctrl فقط برای helper مشخص و صریح موردنظر، حداکثر۱۶؛ فرزندان یا سرویس‌ها خودکار مجاز نمی‌شوند. فایل‌ها فقط روی fixed local drive؛ Network/UNC/OneDrive reparse/shortcut یا preview استفاده نکنید.
4. پس از خواندن فایل، پنجرهٔ خصوصی بازبینی باز می‌شود. **همین برنامه‌ها و مسیرها را بررسی کنید**. اگر می‌خواهید فهرستشان فقط به‌عنوان پیش‌نویس نصاب ثبت شود، در حداکثر دو دقیقه Save candidate را کلیک کنید. Cancel/بستن پنجره/ESC بدون ثبت candidate لغو می‌کند؛ گزارش کنار بسته همچنان ساخته می‌شود. Save به معنی مجوز اجرای فایل یا Apply نیست و default/focus روی Cancel است؛ Enter خودکار Save نیست.
5. تا نتیجه صبر کنید و هم‌زمان دوباره اجرا نکنید. فقط JSON تازهٔ `UFW-PROGRAM-CANDIDATE-01-*.json` را بفرستید، حتی در لغو/شکست. اگر JSON ساخته نشد فقط stage/code کوتاه را بدون مسیر خصوصی بفرستید.

**مسیر، هش، شناسهٔ فایل، خود EXE، فایل candidate.json یا عکس/متن پنجرهٔ خصوصی را نفرستید.** در write_status=attempted_may_exist_inspect_if_failed ممکن است رکورد وجود داشته باشد؛ حذف، جابجایی، ویرایش یا تکرار خودکار نکنید و فقط گزارش را بفرستید.

## چه چیزی ثبت می‌شود؟

Root جداگانهٔ `CommonApplicationData/UnifiedFW-ProgramCandidates-01` و یک پوشهٔ تازهٔ `UfwProgramCandidate-...`، با owner Administrators و DACL محافظت‌شدهٔ فقط Administrators/SYSTEM. هر candidate فقط یک candidate.json دارد؛ ACL در زمان ایجاد فایل/پوشه تنظیم می‌شود، نه با پنجرهٔ بعدی Set-Acl. root موجود با ACL/reparse نامعتبر اصلاح نمی‌شود و بازنویسی پوشه/فایل موجود مجاز نیست. فایل با CreateNew/FileShare.None و Flush(true) نوشته، readback/قالب/receipt/checksum دوباره بررسی می‌شود. محافظت ACL به معنی رمزگذاری، امضای ناشر یا دفاع در برابر administrator مخرب نیست؛ hash هم external trust/anti-rollback نیست و Flush تضمین عمومی قطع برق نیست.

دادهٔ خصوصی شامل مسیر و hash و file ID/volume/اندازه/معماری برنامه‌ها، شناسهٔ candidate، SID حساب تأییدکننده، زمان/هش nonce و digest محتواست. receipt فقط اجازهٔ ثبت انتخاب برنامه برای installer است؛ authorizes_program_execution و authorizes_firewall_change=false. phase=`programs_reviewed_destinations_pending`، destinations خالی و ready_for_apply=false؛ این فایل ورودی کامل compiler grantها نیست، نباید با افزودن approved=true به policy تبدیل شود. این root به ژورنال baseline قبلی یا root قدیمی برنامه دسترسی ندارد و baseline_linked=false باقی می‌ماند.

موفقیت سه نوبت مشاهدهٔ تازهٔ تمام EXEها دارد: پیش از بازبینی، بعد از Save محلی و قبل از نوشتن، بعد از نوشتن. هر نوبت از reader قبلی با دو SHA روی همان handle استفاده می‌کند. تغییر path/hash/identity/size/architecture، تغییر actor یا انقضای دو دقیقه باعث توقف می‌شود؛ پس از write ممکن است فایل باقی بماند و خودکار rollback/delete نمی‌شود. success یعنی ثبت و بررسی همان اجرا، نه هویت دائمی یا بستن تغییر بعدی فایل. هیچ انتخاب خودکار «آخرین candidate» یا جمع‌کردن مجوز چند candidate نداریم.

## کنترل‌های قبلی و مرز UI

ProgramReader.cs و ProgramReview.ps1 انتخاب فایل، و سه ماژول storage بایت‌به‌بایت از milestoneهای قبلی‌اند. reader fixed local path، parent pin root-to-leaf و رد reparse/چند hardlink، EXE header x86/x64، ۵۱۲MiB max و final path/metadata/two-hash دارد. این‌ها امنیت کد/ناشر یا ACL موثر فایل برنامه را اثبات نمی‌کنند. input_valid، hash و receipt اجازهٔ اجرای فایروال نیستند. بعد از آزادشدن handle فایل می‌تواند تغییر کند؛ هنگام استفادهٔ بعدی بازبینی تازه لازم است. هم‌زمان installer/update روی همان مسیر اجرا نکنید؛ pinها ممکن است عملیات متعارض را موقتاً رد کنند.

پنجرهٔ Windows ممکن است metadata/icon/recents و در صورت مرور Network دسترسی shell/شبکه داشته باشد؛ از شبکه و preview دوری کنید. ابزار خودش resolver/HTTP/WinVerifyTrust/اجرای EXE منتخب ندارد، اما صفر ترافیک سیستم با packet capture ثابت نشده است. compiler .NET ممکن است Temp/cache بنویسد و گزارش کنار بسته هم خروجی جدید است؛ پاک‌سازی متغیرها پاک‌کردن امن console/memory نیست.

## شواهد

۲۳۶ assertion ثبت/لغو، تغییر فایل پیش/پس از ثبت، انقضا/actor change، save failure/wrong head/uncertain write، فایل واقعی Linux، عدم بازنویسی، checksum/قالب/authority/partial refusal، privacy و قرارداد شبیه‌سازی‌شدهٔ JSON PS5.1 پاس شد. ۷۳ assertion ژورنال و۲۶۰ assertion picker قبلی نیز دوباره پاس شدند. فرم تأیید، file picker، Windows API فایل برنامه و ACL بومی در مدل این مرحله mock/اجرا‌نشده‌اند؛ این کد روی Windows هنوز اجرا نشده است. شش PS source و bootstrap/manifest/ZIP کنترل شده‌اند.

receipt قبلی Windows انتخاب و مشاهدهٔ یک EXE با header x86 پاس شده بود؛ storage helpers هم در fixture قبلی پاس بودند. آن‌ها اجرای این فرم/ثبت candidate یا policy اجرایی نیستند. آزمون‌های موفق قبلی را تکرار نکنید. recorder، مقصدهای هر برنامه، native Apply/recovery، SSTP binding/bootstrap/reconnect، mode switch، packet/reboot/no-leak/fingerprint همچنان آماده یا certified نیستند. ابتدا candidate نصاب، سپس destination review و گیت‌های native ادامه می‌یابند.

CMD manifest/payload را با SHA256 می‌سنجد و فقط شش PS1/PSM1 همین بسته را Unblock می‌کند؛ RemoteSigned فقط process فرزند، نه policy دائمی/GPO. -STA برای پنجره‌هاست. امضای ناشر/sandbox وجود ندارد؛ SHA256 ZIP را با مقدار تحویل مقایسه کنید.
''')
(d/'evidence').mkdir(exist_ok=True)
for p,n in [(r/'evidence/model-tests.json','candidate-model.json'),(r/'evidence/linux-platform-guard.json','linux-platform-guard.json'),(Path('/data/ufw-session-journal-v01/evidence/model-tests.json'),'journal-regression.json'),(Path('/data/ufw-program-review-v011/evidence/model-tests.json'),'picker-regression.json')]:(d/'evidence'/n).write_bytes(p.read_bytes())
prior=json.loads(Path('/data/ufw-program-review-v011/Windows-pass-push-arguments.json').read_text());receipt=next(f['content'] for f in prior['files'] if f['path'].endswith('Windows-program-review-011-one-file-observed.json'));(d/'evidence/prior-Windows-one-file-observation.json').write_text(receipt)
(d/'PROVENANCE.json').write_text(json.dumps(dict(byte_unchanged_dependencies={n:sha(d/n) for n in mods+['ProgramReader.cs','ProgramReview.ps1']},prior_Windows_observation_commit='6b0d9c861ae39058064bcad3a1f679f3f22a2812',new_assertions=236,journal_assertions_rerun=73,picker_assertions_rerun=260,new_confirmation_UI_Windows_executed=False,new_program_candidate_Windows_store_executed=False,ready_for_apply=False),indent=2))
check="$ErrorActionPreference='Stop';$root='ROOT';$files=@(Get-ChildItem $root -Filter *.ps1)+@(Get-ChildItem $root -Filter *.psm1);if($files.Count -ne 6){throw 'file_count'};foreach($f in $files){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e);if($e.Count){throw 'parse'}};Write-Host 'Six package PS files parsed.'".replace('ROOT',str(d));(r/'Check-Source.ps1').write_text(check);run(r/'Check-Source.ps1')
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Candidate.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Review.cmd').read_text().replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('UFW_PROGRAM_ROOT','UFW_CANDIDATE_ROOT').replace('Local Program Review 0.1.1 - CHOOSE EXE IN FILE WINDOW; NEVER EXECUTE.','Installer Program Candidate 0.1 - ADMIN for protected storage; no execution/firewall change.').replace("'ProgramReview.ps1','Run-Review.ps1'",','.join(repr(n) for n in mods+['ProgramReview.ps1','CandidateEntry.ps1','Run-Candidate.ps1'])).replace('Run-Review.ps1','Run-Candidate.ps1').replace('Two package scripts unblocked.','Six package scripts/modules unblocked.').replace('Program observation not confirmed.','Candidate recording not confirmed.');cmd=cmd.replace(";$m=Join-Path $root 'PAYLOAD-SHA256.json'", ";$who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run as administrator using the same Windows account'};$m=Join-Path $root 'PAYLOAD-SHA256.json'")
assert 'Run-Candidate.ps1' in cmd and 'Run-Review.ps1' not in cmd and '-STA' in cmd and '$who' in cmd;(d/'Run-Candidate.cmd').write_text(cmd,newline='\r\n')
s=Path('/data/ufw-program-review-v011/Check-Bootstrap.ps1').read_text().replace(str(old),str(d)).replace('Run-Review.cmd','Run-Candidate.cmd');(r/'Check-Bootstrap.ps1').write_text(s);run(r/'Check-Bootstrap.ps1')
z=r/'UFW-PROGRAM-CANDIDATE-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 assert out.testzip() is None
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,new_assertions=236,journal_assertions_rerun=73,picker_assertions_rerun=260,package_PS_files_parsed=6,bootstrap_parsed_payload_verified=True,byte_unchanged_reader_picker_and_modules=True,Windows_candidate_store_and_confirmation_executed=False,administrator_required=True,user_action='same account admin Run-Candidate.cmd; choose installer EXE, review exact local content and optionally Save candidate within 120 seconds; Cancel writes no candidate; return diagnostic only',phase='programs_reviewed_destinations_pending',destinations_empty=True,ready_for_apply=False);(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
