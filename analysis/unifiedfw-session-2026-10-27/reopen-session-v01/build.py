from pathlib import Path
import hashlib,json,subprocess,zipfile
r=Path('/data/ufw-reopen-session-v01');d=r/'package/UFW-REOPEN-SESSION-01';old=Path('/data/ufw-prepare-session-v01/package/UFW-PREPARE-SESSION-01');src=Path('/data/ufw-session-journal-v01/source');pw='/data/ufd-isolation-hf1/pwsh/pwsh';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mods=['Ufw.ProfileReader.psm1','Ufw.InstallerCore.psm1','Ufw.SessionJournal.psm1'];deps=mods+['ReopenEntry.ps1']
for n in mods:assert (d/n).read_bytes()==(src/n).read_bytes()
for n in ['ReopenEntry.ps1','Run-Reopen.ps1']:(d/n).write_text((d/n).read_text(),newline='\r\n')
s=(d/'Run-Reopen.ps1').read_text().replace('including cancel/failure.','including failure.').replace('protected files, challenge, screenshot, or transcript.','protected journal files, screenshots, or transcripts.');a=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");b=s.index("\n'@",a);s=s[:a]+json.dumps({n:sha(d/n) for n in deps},indent=2)+s[b:];(d/'Run-Reopen.ps1').write_text(s,newline='\r\n')
def run(p,expected=0):
 v=subprocess.run([pw,'-NoProfile','-File',str(p)],capture_output=True,text=True,timeout=180);(r/(Path(p).name+'.log')).write_text(v.stdout+'\n'+v.stderr);assert v.returncode==expected,(str(p),v.stdout[-1400:],v.stderr[-1400:])
run(r/'Test-ReopenEntry.ps1');run('/data/ufw-session-journal-v01/tests/Test-SessionJournal.ps1');run(d/'Run-Reopen.ps1',1)
reports=list(d.glob('UFW-REOPEN-SESSION-01-*.json'));assert len(reports)==1;v=json.loads(reports[0].read_text('utf-8-sig'));assert v['code']=='ufw_reopen_windows_required' and v['validation'] is None and not v['payload_verified'];reports[0].replace(r/'linux-platform-guard.json')
m=json.loads((r/'MODEL-RESULTS.json').read_text('utf-8-sig'));j=json.loads(Path('/data/ufw-session-journal-v01/evidence/model-tests.json').read_text('utf-8-sig'));assert m['passed'] and m['assertions']==388 and j['passed'] and j['assertions']==73
(d/'README-FA.md').write_text('''# بازخوان مستقل نشست — UFW-REOPEN-SESSION-01

این بسته **همان ژورنال preparation موجود** را در اجرای تازه بازخوانی می‌کند و با تنظیمات فعلی سه پروفایل فایروال مقایسه می‌کند. فایل نشست جدید نمی‌سازد، consent جدید نمی‌گیرد، ژورنال را اصلاح/مهاجرت نمی‌کند و هیچ Apply/Restore یا تغییر Block/Allow، rule/task/VPN/DNS/route ندارد. تنها فایل جدید برنامه، گزارش تشخیصی کنار بسته است؛ خواندن فایل ممکن است metadata دسترسی فایل‌سیستم را به‌روز کند.

## اجرا

1. ZIP را در پوشهٔ محلی تازه و جدا Extract کنید؛ روی برنامهٔ قدیمی یا بستهٔ preparation کپی نکنید.
2. شبکه و SSTP همان وضعیت فعلی بمانند. ری‌استارت، قطع VPN و تکرار Run-Prepare لازم نیست. هم‌زمان بسته/برنامهٔ دیگری که ژورنال یا فایروال را تغییر می‌دهد اجرا نکنید.
3. `Run-Reopen.cmd` را با **Run as administrator** و همان حساب ویندوز اجرا کنید؛ Windows PowerShell 5.1 x64 لازم است.
4. عبارت تأیید وجود ندارد. تا نتیجه صبر کنید و فقط فایل تازهٔ `UFW-REOPEN-SESSION-01-*.json` را بفرستید، حتی در شکست. اگر JSON ایجاد نشد فقط stage/code کوتاه را بدون مسیر خصوصی بفرستید.

ژورنال ProgramData، ID نشست، receipt، hash/nonce، عکس پنجره، backup و تنظیمات خصوصی VPN را نفرستید. در خطا یا چندنشستی بودن، فایل‌ها را حذف/جابجا/اصلاح نکنید، تنظیمات را عوض نکنید و preparation را تکرار نکنید؛ گزارش کافی است.

## چه چیزی کنترل می‌شود؟

- فقط root ثابت CommonApplicationData/UnifiedFW-InstallerSessions-01؛ بدون دسترسی به root قدیمی، جست‌وجوی recursive یا انتخاب «آخرین» نشست.
- root باید موجود باشد و دقیقاً یک پوشهٔ نشست با نام معتبر و ACL محافظت‌شدهٔ Administrators/SYSTEM داشته باشد. root/نشست/فایل reparse یا child ناشناخته رد می‌شود. صفر یا چند نشست متوقف می‌کند؛ چیزی ساخته/پاک نمی‌شود.
- operation.lock باید از قبل موجود و خالی باشد. قفل با FileMode.Open و FileAccess.Read و FileShare.None باز می‌شود؛ نه Create/OpenOrCreate، نه write و نه repair. قفل مشغول رد می‌شود و قفل این اجرا در پایان آزاد می‌شود.
- فقط یک 00000001.json با kind/phase=prepared و intent/restored/execution-authorized=false پذیرفته می‌شود. schema/receipt/baseline/checksum/chain و ACL با توابع ژورنال قبلی اعتبارسنجی می‌شوند؛ فایل اضافی یا رکورد ناقص/بزرگ/مغایر رد می‌شود.
- دو preflight تازه، هرکدام دو مشاهدهٔ local/effective و چهار query، جمعاً هشت getter در موفقیت. هر دو باید با baseline ثبت‌شده یکسان باشند. جزئیات امن baseline و مشاهده‌ها در JSON می‌آید؛ ID/digest/path نمی‌آید.
- در پایان ژورنال دوباره اعتبارسنجی و hash بایت‌ها/اندازه/head/receipt با خواندن نخست مقایسه می‌شود؛ root هم مجدداً باید همان تک‌نشست باشد. هر تغییر باعث توقف می‌شود، نه اصلاح خودکار.

موفقیت با code=ufw_reopen_prepared_matches_current_no_authority یعنی **در این اجرای بازخوان، رکورد prepared معتبر و با وضعیت مشاهده‌شده سازگار بود**. baseline Block به Allow تبدیل نمی‌شود و موفقیت آن اثبات اینترنت عادی یا ایزولاسیون سالم نیست. فایل lock مانع writerهای همکار می‌شود، نه administrator مخرب یا تمام تغییرات هم‌زمان. نمونه‌برداری‌ها اتمیک نیستند؛ دورهٔ بین مشاهده‌ها، حفظ وضعیت بعد از اتمام، crash/power-loss/reboot، نبود فایل‌های حذف‌شده و انتساب به دقیقاً همان نشست تاریخی بدون anchor خارجی اثبات نمی‌شوند. hash-chain امضای رمزنگاری‌شده یا WORM نیست.

## شواهد و مرز آماده‌بودن

آزمون‌های Linux: ۳۸۸ assertion در ۲۴ سناریوی پایه/شکست به‌همراه قرارداد شبیه‌سازی‌شدهٔ JSON در PS5.1، بازکردن رکورد در child process تازه، کنترل عدم تغییر محتوا/ساختار فایل‌ها، و parse/مرزبندی؛ ۷۳ assertion ژورنال نیز دوباره پاس شد. getterهای Windows و guardهای platform در model جایگزین شده‌اند؛ ACL واقعی Windows در این آزمون‌ها اجرا نشده است. سه ماژول تولیدی بدون تغییر بایت هستند. بستهٔ جدید **هنوز روی Windows اجرا نشده** و نتیجهٔ شما این گام را بررسی می‌کند.

receiptهای قبلی داخل evidence نشان می‌دهند STORAGE-011 روی Windows و سپس PREPARE-SESSION-01 با consent/ثبت/بازخوانی درون همان اجرا و سه preflight واقعی موفق بودند. این شواهد، اجرای Windows بازخوان جدید یا reboot qualification نیستند. اجرای قبلی را تکرار نکنید.

این هنوز محصول نهایی نصاب بتل‌نت نیست. native recovery، برنامه‌ریزی/اعمال rules، binding معتبر SSTP، اتصال سرد/reconnect تحت isolation، packet/no-leak و جلوگیری از fingerprint تأیید نشده‌اند. ready_for_apply=false؛ هیچ authority جدیدی از خواندن رکورد به دست نمی‌آید.

CMD ابتدا manifest و تمام payload را با SHA256 بررسی و فقط پنج PS1/PSM1 همین بسته را Unblock می‌کند. RemoteSigned فقط در پردازش فرزند است؛ policy دائمی/GPO تغییر نمی‌کند. امضای ناشر وجود ندارد؛ SHA256 ZIP را با مقدار تحویل مقایسه کنید. با دسترسی admin اجرا می‌شود و sandbox نیست.
''')
check="$ErrorActionPreference='Stop';$root='ROOT';$files=@(Get-ChildItem $root -Filter *.ps1)+@(Get-ChildItem $root -Filter *.psm1);if($files.Count -ne 5){throw 'file_count'};foreach($f in $files){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e);if($e.Count){throw 'parse'}};Write-Host 'Five package PS files parsed.'".replace('ROOT',str(d));(r/'Check-Source.ps1').write_text(check);run(r/'Check-Source.ps1')
(d/'evidence').mkdir(exist_ok=True)
p=json.loads(Path('/data/ufw-prepare-session-v01/Windows-pass-push-arguments.json').read_text());receipt=next(f['content'] for f in p['files'] if f['path'].endswith('Windows-preparation-01-passed-result.json'));(d/'evidence/prior-Windows-preparation-01-passed-result.json').write_text(receipt)
(d/'evidence/prior-Windows-storage-011-passed-result.json').write_bytes((old/'evidence/prior-Windows-storage-011-passed-result.json').read_bytes())
for p,n in [(r/'MODEL-RESULTS.json','reopen-entry-model.json'),(Path('/data/ufw-session-journal-v01/evidence/model-tests.json'),'journal-model-rerun.json'),(r/'linux-platform-guard.json','linux-platform-guard.json')]:(d/'evidence'/n).write_bytes(p.read_bytes())
(d/'PROVENANCE.json').write_text(json.dumps(dict(byte_unchanged_modules={n:sha(d/n) for n in mods},source_milestone_commit='f29e8e8f15dd92be105cda25248803a174591f57',prior_Windows_preparation_receipt_commit='9621280942d9d23f0e8bb4cb899659662eee4b62',reopen_entry_assertions=388,base_scenarios=24,journal_assertions_rerun=73,fresh_Linux_child_process_reopen_tested=True,Windows_getters_mocked_in_model=True,real_Windows_reopen_entry_executed=False,journal_write_requested=False,firewall_change_requested=False,ready_for_apply=False),indent=2))
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Reopen.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Prepare.cmd').read_text().replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('UFW_PREP_ROOT','UFW_REOPEN_ROOT').replace('Preparation Journal 0.1 - NO FIREWALL CHANGES. Keep VPN and network as they are.','Read-only Journal Reopen 0.1 - NO JOURNAL OR FIREWALL CHANGES. Keep VPN and network as they are.').replace('PreparationEntry.ps1','ReopenEntry.ps1').replace('Run-Prepare.ps1','Run-Reopen.ps1').replace('Preparation not confirmed.','Read-only validation not confirmed.');(d/'Run-Reopen.cmd').write_text(cmd,newline='\r\n')
s=Path('/data/ufw-prepare-session-v01/Check-Bootstrap.ps1').read_text().replace(str(old),str(d)).replace('Run-Prepare.cmd','Run-Reopen.cmd');(r/'Check-Bootstrap.ps1').write_text(s);run(r/'Check-Bootstrap.ps1')
z=r/'UFW-REOPEN-SESSION-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 assert out.testzip() is None
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,reopen_entry_assertions=388,base_scenarios=24,journal_assertions_rerun=73,package_PS_files_parsed=5,bootstrap_parsed_and_manifest_payload_verified=True,production_dependencies_byte_unchanged=True,fresh_Linux_child_process_reopen_tested=True,real_Windows_reopen_entry_executed=False,user_action='same-account admin Run-Reopen.cmd once from new separate local folder, keep network/SSTP, no consent or new preparation, return diagnostic JSON',journal_write_requested=False,firewall_change_requested=False,ready_for_apply=False);(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
