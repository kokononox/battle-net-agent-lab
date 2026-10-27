from pathlib import Path
import hashlib,json,subprocess,zipfile
r=Path('/data/ufw-prepare-session-v01');d=r/'package/UFW-PREPARE-SESSION-01';old=Path('/data/ufw-journal-storage-test-v011/package/UFW-JOURNAL-STORAGE-011');src=Path('/data/ufw-session-journal-v01/source');pw='/data/ufd-isolation-hf1/pwsh/pwsh'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mods=['Ufw.ProfileReader.psm1','Ufw.InstallerCore.psm1','Ufw.SessionJournal.psm1'];deps=mods+['PreparationEntry.ps1']
for n in mods:assert (d/n).read_bytes()==(src/n).read_bytes(),n
# Normalize only newly authored scripts before pinning.
for n in ['PreparationEntry.ps1','Run-Prepare.ps1']:
 s=(d/n).read_text();(d/n).write_text(s,newline='\r\n')
s=(d/'Run-Prepare.ps1').read_text();a=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");b=s.index("\n'@",a);s=s[:a]+json.dumps({n:sha(d/n) for n in deps},indent=2)+s[b:];(d/'Run-Prepare.ps1').write_text(s,newline='\r\n')
def run(p,expected=0):
 v=subprocess.run([pw,'-NoProfile','-File',str(p)],capture_output=True,text=True,timeout=180);(r/(Path(p).name+'.log')).write_text(v.stdout+'\n'+v.stderr);assert v.returncode==expected,(str(p),v.stdout[-1200:],v.stderr[-1200:])
run(r/'Test-PreparationEntry.ps1');run('/data/ufw-session-journal-v01/tests/Test-SessionJournal.ps1');run(d/'Run-Prepare.ps1',1)
reports=list(d.glob('UFW-PREPARE-SESSION-01-*.json'));assert len(reports)==1
v=json.loads(reports[0].read_text('utf-8-sig'));assert v['code']=='ufw_prepare_windows_required' and v['preparation'] is None and not v['payload_verified'];reports[0].replace(r/'linux-platform-guard.json')
m=json.loads((r/'MODEL-RESULTS.json').read_text('utf-8-sig'));j=json.loads(Path('/data/ufw-session-journal-v01/evidence/model-tests.json').read_text('utf-8-sig'));assert m['passed'] and m['assertions']==60 and j['passed'] and j['assertions']==73
(d/'README-FA.md').write_text('''# ثبت مستقل وضعیت مبنا — UFW-PREPARE-SESSION-01

این مرحله فقط تنظیمات واقعی فعلی سه پروفایل فایروال را می‌خواند و **تنها بعد از تأیید دقیق دستی** یک ژورنال مستقل preparation می‌سازد. هیچ Apply/Restore، تغییر Block/Allow، rule، task، VPN، route یا DNS انجام نمی‌دهد. این بسته نصاب نهایی بتل‌نت یا ایزولاسیون آماده نیست؛ یک گام محدود برای پایهٔ بازیابی آن است.

## اجرا روی همان سیستم آزمایش

1. ZIP را در پوشهٔ محلی تازه، جدا از برنامهٔ قدیمی، Extract کنید. روی پوشهٔ قدیمی کپی نکنید.
2. شبکه و SSTP را در وضعیت فعلی نگه دارید؛ ری‌استارت، قطع VPN یا اجرای بستهٔ قدیمی لازم نیست. هم‌زمان برنامه‌ای که فایروال را تغییر می‌دهد اجرا نکنید.
3. `Run-Prepare.cmd` را با Run as administrator و همان حساب ویندوز اجرا کنید. Windows PowerShell 5.1 x64 لازم است.
4. جدول وضعیت مبنای فعلی را بخوانید. اگر می‌خواهید همین وضعیت در یک نشست جدید ثبت شود، عبارت اختصاصی `PREPARE JOURNAL ... ...` را **دقیقاً مطابق prompt همان پنجره**، حداکثر ظرف دو دقیقه وارد کنید. این تأیید فقط برای ثبت فایل است، نه اجازهٔ تغییر فایروال یا ایزولاسیون. Enter خالی یا هر پاسخ متفاوت بدون نوشتن ژورنال نشست لغو می‌کند؛ گزارش تشخیصی کنار بسته همچنان ساخته می‌شود.
5. تا نمایش نتیجه صبر کنید؛ دوباره/هم‌زمان اجرا نکنید. فقط فایل جدید `UFW-PREPARE-SESSION-01-*.json` را بفرستید، حتی در لغو/شکست. اگر فایل ساخته نشد، فقط متن کوتاه stage/code را بدون مسیر خصوصی بفرستید.

**عبارت تأیید، عکس/متن پنجرهٔ تأیید، فایل‌های محافظت‌شدهٔ ProgramData و ژورنال قدیمی را نفرستید.** نام/IP سرور، رمز VPN و backup لازم نیستند.

## معنی Block و نتیجه

وجود outbound صریح Block می‌تواند برای ثبت preparation پذیرفته شود. این به معنی ایزولاسیون درست یا اینترنت عادی نیست؛ Block به Allow تبدیل نمی‌شود. در آینده بازیابی همین baseline هم باید Block را حفظ کند و نباید «برگشت اینترنت عادی» نامیده شود. علت Block تاریخی هنوز تعیین نشده است.

در موفقیت، سه preflight کامل انجام می‌شود: پیش از تأیید، پس از تأیید و پس از نوشتن. هر preflight شامل دو مشاهدهٔ PersistentStore/ActiveStore، مجموعاً چهار query است؛ موفقیت کامل ۱۲ query دارد. drift، baseline مبهم/NotConfigured یا ناهمخوان، تنظیمات ناسازگار، مهلت منقضی و platform نامناسب باعث توقف می‌شوند. مشاهده‌ها اتمیک نیستند و گذراهای بین آن‌ها را اثبات نمی‌کنند. برای pass شدن، تنظیمات را خودسرانه تغییر ندهید؛ گزارش را بفرستید.

پس از رضایت، root مستقل `CommonApplicationData\\UnifiedFW-InstallerSessions-01` و یک پوشهٔ تازهٔ `UfwInstaller-Session-...` با دسترسی محدود Administrators/SYSTEM ساخته/اعتبارسنجی می‌شود. فقط یک checkpoint prepared و فایل lock ثبت می‌شوند. root قدیمی خوانده، اصلاح یا مهاجرت نمی‌شود. شناسه، nonce و digest محافظت‌شده در گزارش اشتراکی نمی‌آیند.

اگر وضعیت `attempted_may_exist_inspect_if_failed` آمد، ممکن است رکورد نوشته شده ولی تأیید بعدی شکست خورده باشد. خودسرانه حذف، تکرار یا Restore نکنید؛ گزارش را بفرستید. فایل ناقص/نامطمئن خودکار بازنویسی یا حذف نمی‌شود. موفقیت با `prepared_and_revalidated_no_firewall_authority` یعنی ثبت و بازخوانی preparation، **نه authority برای تغییر فایروال**.

## بررسی‌ها و محدودیت‌ها

۶۰ بررسی راه‌انداز با profile getter و prompt شبیه‌سازی‌شده، فایل واقعی Linux و سناریوهای لغو/تأیید/تغییر baseline/انقضا/شکست ثبت گذشتند؛ ۷۳ بررسی ژورنال هم دوباره گذشتند. ۵ فایل PS و فرمان bootstrap parse شده‌اند. قرارداد JSON آرایهٔ PS5.1 در آزمون شبیه‌سازی شده است؛ اجرای Linux جای اجرای واقعی Windows نیست.

آزمون مستقل STORAGE-011 قبلاً روی Windows PS5.1 x64 کاربر، ACL root/session/record/lock، CreateNew، lock، chain، corruption/partial refusal و recovery حافظه‌ای با ۱۱ checkpoint فایل و cleanup را پاس کرده است. evidence آن در این بسته فقط سابقهٔ qualification ذخیره‌سازی است؛ آن آزمون root واقعی preparation، consent انسانی یا خواندن profile واقعی این راه‌انداز را اجرا نکرده بود. نیازی به تکرار fixture قبلی نیست.

سه ماژول تولیدی بایت‌به‌بایت همان milestone ژورنال‌اند. native firewall writer وجود ندارد. خواندن واقعی profile، prompt انسانی و ساخت نشست واقعی با **این راه‌انداز** هنوز روی Windows اجرا نشده‌اند؛ نتیجهٔ شما این فاصله را بررسی می‌کند. native recovery، rules/SSTP binding، reconnect تحت isolation، WFP، reboot، fingerprint و no-leak آزموده/تأیید نشده‌اند؛ ready_for_apply=false است. ACL/hash-chain دفاع در برابر administrator مخرب یا کشف قطعی حذف tail نیست؛ Flush تضمین عمومی قطع برق نیست.

CMD ابتدا manifest و تمام payload را با SHA256 بررسی و سپس فقط پنج PS1/PSM1 همین بسته را Unblock می‌کند. RemoteSigned فقط برای پردازش فرزند است؛ policy دائمی و GPO تغییر نمی‌کنند. بسته امضای ناشر ندارد؛ SHA256 کل ZIP را با مقدار تحویل مقایسه کنید. بازشدن script با دسترسی admin به معنی sandbox بودن آن نیست.
''')
check="$ErrorActionPreference='Stop';$root='ROOT';$files=@(Get-ChildItem $root -Filter *.ps1)+@(Get-ChildItem $root -Filter *.psm1);if($files.Count -ne 5){throw 'file_count'};foreach($f in $files){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e);if($e.Count){throw 'parse'}};Write-Host 'Five package PS files parsed.'".replace('ROOT',str(d));(r/'Check-Source.ps1').write_text(check);run(r/'Check-Source.ps1')
(d/'evidence').mkdir(exist_ok=True)
prior=json.loads(Path('/data/ufw-journal-storage-test-v011/Windows-pass-push-arguments.json').read_text());receipt=next(f['content'] for f in prior['files'] if f['path'].endswith('Windows-storage-011-passed-result.json'))
(d/'evidence/prior-Windows-storage-011-passed-result.json').write_text(receipt)
for p,n in [(r/'MODEL-RESULTS.json','preparation-entry-model.json'),(Path('/data/ufw-session-journal-v01/evidence/model-tests.json'),'journal-model-rerun.json'),(r/'linux-platform-guard.json','linux-platform-guard.json')]: (d/'evidence'/n).write_bytes(p.read_bytes())
(d/'PROVENANCE.json').write_text(json.dumps(dict(byte_unchanged_modules={n:sha(d/n) for n in mods},source_milestone_commit='f29e8e8f15dd92be105cda25248803a174591f57',prior_Windows_storage_receipt_commit='266cc4bdd0bdc95acd4092f0b3c8d5a7a7c379d0',new_entry_assertions=60,journal_assertions_rerun=73,prior_Windows_storage_fixture_passed=True,real_preparation_entry_Windows_executed=False,real_human_prompt_executed=False,real_preparation_record_created_on_user_PC=False,real_legacy_journal_access_requested=False,firewall_change_requested=False,ready_for_apply=False),indent=2))
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Prepare.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Test.cmd').read_text().replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('UFW_STORAGE_ROOT','UFW_PREP_ROOT').replace('Journal Storage Test 0.1.1 - SYNTHETIC FILES ONLY. Keep VPN and network as they are.','Preparation Journal 0.1 - NO FIREWALL CHANGES. Keep VPN and network as they are.').replace('StorageFixture.ps1','PreparationEntry.ps1').replace('Run-Test.ps1','Run-Prepare.ps1').replace('Storage fixture not confirmed.','Preparation not confirmed.');(d/'Run-Prepare.cmd').write_text(cmd,newline='\r\n')
s=Path('/data/ufw-journal-storage-test-v011/Check-Bootstrap.ps1').read_text().replace(str(old),str(d)).replace('Run-Test.cmd','Run-Prepare.cmd');(r/'Check-Bootstrap.ps1').write_text(s);run(r/'Check-Bootstrap.ps1')
z=r/'UFW-PREPARE-SESSION-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 assert out.testzip() is None
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,new_entry_assertions=60,journal_assertions_rerun=73,package_PS_files_parsed=5,bootstrap_parsed_and_manifest_payload_verified=True,production_dependencies_byte_unchanged=True,prior_Windows_storage_fixture_passed=True,real_preparation_entry_Windows_executed=False,user_action='same-account administrator; keep SSTP/network unchanged; exact manual consent ONLY if current preparation baseline should be recorded, Enter cancels; return new diagnostic JSON only',firewall_change_requested=False,ready_for_apply=False);(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
