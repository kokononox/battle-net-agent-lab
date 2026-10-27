from pathlib import Path
import hashlib,json,subprocess,zipfile
r=Path('/data/ufw-journal-storage-test-v011');d=r/'package/UFW-JOURNAL-STORAGE-011';src=Path('/data/ufw-session-journal-v01/source');pw='/data/ufd-isolation-hf1/pwsh/pwsh';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mods=['Ufw.ProfileReader.psm1','Ufw.InstallerCore.psm1','Ufw.SessionJournal.psm1'];deps=mods+['StorageFixture.ps1']
for n in mods:assert (d/n).read_bytes()==(src/n).read_bytes(),n
s=(d/'Run-Test.ps1').read_text();a=s.index("$hashes=ConvertFrom-Json @'\n")+len("$hashes=ConvertFrom-Json @'\n");b=s.index("\n'@",a);s=s[:a]+json.dumps({n:sha(d/n) for n in deps},indent=2)+s[b:];(d/'Run-Test.ps1').write_text(s,newline='\r\n')
def run(p,*args,code=0):
 v=subprocess.run([pw,'-NoProfile','-File',str(p),*map(str,args)],capture_output=True,text=True,timeout=180);(r/(Path(p).name+'.log')).write_text(v.stdout+'\n'+v.stderr);assert v.returncode==code,(str(p),v.stdout[-1600:],v.stderr[-1600:])
run(r/'Test-StorageFixture.ps1');run(r/'Test-PS51ArrayContract.ps1');run('/data/ufw-session-journal-v01/tests/Test-SessionJournal.ps1');run(d/'Run-Test.ps1',code=1)
reports=list(d.glob('UFW-JOURNAL-STORAGE-011-*.json'));assert len(reports)==1;v=json.loads(reports[0].read_text('utf-8-sig'));assert v['code']=='ufw_storage_windows_required' and v['qualification'] is None and not v['payload_verified'];reports[0].replace(r/'linux-platform-guard.json')
fixture=json.loads((r/'MODEL-RESULTS.json').read_text('utf-8-sig'));journal=json.loads(Path('/data/ufw-session-journal-v01/evidence/model-tests.json').read_text('utf-8-sig'));assert fixture['passed'] and fixture['assertions']==36 and journal['passed'] and journal['assertions']==73
(d/'README-FA.md').write_text('''# آزمون مستقل ذخیره‌سازی ژورنال — ۰٫۱٫۱

این بسته فقط با **دادهٔ ساختگی** در یک پوشهٔ آزمایشی منحصربه‌فرد در ProgramData کار می‌کند. به ژورنال قدیمی برنامه دسترسی نمی‌خواهد؛ هیچ profile/rule/task/VPN/DNS/route را نمی‌خواند یا تغییر نمی‌دهد. profileهای Allow/Block در آزمون، objectهای حافظه‌ای ساختگی‌اند، نه تنظیمات ویندوز. هیچ رضایتی برای ایزولاسیون یا ایجاد نشست واقعی گرفته نمی‌شود.

## اصلاح نسخهٔ ۰٫۱٫۱

نسخهٔ قبلی روی Windows در append_and_memory_recovery با ufw_core_profile_coverage متوقف شد؛ ACL، roundtrip اولیه، collision، stale head، lock و cleanup آن پاس شدند. کپی JSON کل آرایه در PowerShell 5.1 ممکن است یک آرایهٔ تو‌در‌تو بدهد. در این نسخه فقط کپی سه object ساختگی به صورت سطر‌به‌سطر اصلاح شده؛ guard دقیق سه profile و همهٔ سه module تولیدی بدون تغییرند. شبیه‌ساز قرارداد JSON پاورشل ۵٫۱ روی PS7 همان خطای نسخهٔ قبلی را بازتولید کرد و نسخهٔ اصلاح‌شده در همان شرایط همهٔ fixture را گذراند؛ این شبیه‌سازی جای اجرای واقعی Windows نیست. ۱۰ بررسی سازگاری اضافه شده است.

## اجرا

1. ZIP را در پوشهٔ محلی تازه و جدا از برنامهٔ قبلی Extract کنید.
2. اینترنت و SSTP را **در همین وضعیت فعلی** نگه دارید؛ ری‌استارت یا قطع VPN لازم نیست.
3. `Run-Test.cmd` را با Run as administrator و همان حساب ویندوز اجرا کنید. Windows PowerShell 5.1 نسخهٔ ۶۴بیتی لازم است.
4. تا نمایش نتیجه صبر کنید و هم‌زمان دوباره اجرا نکنید. prompt تأیید نشست وجود ندارد؛ CMD در پایان فقط pause دارد.
5. فقط فایل تازهٔ `UFW-JOURNAL-STORAGE-011-*.json` را بفرستید، **حتی اگر آزمون شکست خورد**. اگر JSON ساخته نشد، متن کوتاه خطای stage/code را بدون مسیر شخصی بفرستید. فایل‌های ProgramData، ژورنال قدیمی، backup یا عکس/متن کامل محیط را نفرستید.

## چه چیزی بررسی می‌شود؟

مالکیت و DACL محافظت‌شدهٔ root/session/record/lock برای Administrators و SYSTEM؛ ایجاد و بازخوانی رکورد؛ CreateNew بدون overwrite؛ stale head و قفل انحصاری؛ زنجیرهٔ checkpointها؛ بازیابی فقط در حافظه با ۱۱ checkpoint واقعی فایل؛ رد baseline تغییرکرده؛ رد checksum خراب و JSON ناقص، و باقی‌ماندن فایل خراب تا پاک‌سازی محدود fixture.

پوشهٔ آزمایشی نام `UnifiedFW-JournalQualification-...` دارد و با root نشست واقعی جدید یا root برنامهٔ قدیمی متفاوت است. سه زیرپوشهٔ session آن فقط اطلاعات ساختگی دارند. پاک‌سازی ابتدا تمام ساختار و ACL را کنترل می‌کند؛ فقط نام‌های شناخته‌شده را، بدون حذف recursive، پاک می‌کند. وجود فایل/پوشهٔ ناشناخته، reparse یا ACL نامطمئن باعث توقف پاک‌سازی می‌شود؛ پوشه برای بررسی باقی می‌ماند. در cleanup failure، خودسرانه حذف یا آزمون را تکرار نکنید؛ فقط JSON را بفرستید.

فایل گزارش در کنار بسته باقی می‌ماند؛ فاقد نام کاربر، مسیر خصوصی، ID نشست، hash زنجیره، نام/IP سرور، PID و nonce است. مسیر خود گزارش فقط در پنجرهٔ محلی چاپ می‌شود.

## مرز نتیجه

موفقیت فقط storage fixture همین اجرای Windows را تأیید می‌کند؛ نه رفتار WFP، ایزولاسیون، original Restore، حفظ حفاظت بعد reboot، اتصال سرد/reconnect SSTP یا جلوگیری از fingerprint. ACL metadata و رفتار فایل/قفل بررسی می‌شوند، نه impersonation همهٔ کاربران یا دفاع در برابر administrator مخرب. مشاهده اتمیک نیست و Flush فایل تضمین کامل قطع برق نیست. hash-chain به‌تنهایی کشف حذف tail یا امضای cryptographic نمی‌دهد.

سه ماژول از milestone ژورنال بدون تغییر بایت هستند. در این بسته فقط توابع fixture و توابع داده/فایل آن‌ها فراخوانی می‌شوند؛ توابع profile reader، consent واقعی و native store واقعی اجرا نمی‌شوند. CMD hash manifest و تمام payload را بررسی و فقط پنج فایل PS1/PSM1 همین بسته را Unblock می‌کند. RemoteSigned فقط برای پردازش فرزند است؛ policy دائمی/GPO تغییر نمی‌کند. CMD امضای ناشر ندارد؛ SHA256 کل ZIP را با مقدار تحویل مقایسه کنید.

۳۶ بررسی بسته/مرزبندی/پاک‌سازی و ۷۳ بررسی ژورنال روی Linux گذشتند؛ full fixture با فایل واقعی Linux و guard واقعی platform آزموده شد، اما native Windows API/ACL این بسته **هنوز اجرا نشده است**. گزارش‌های evidence داخل ZIP فقط نتایج آفلاین‌اند و گواهی Windows نیستند.

این بسته جایگزین برنامهٔ قبلی نیست؛ روی پوشهٔ آن کپی نشود. هیچ Apply/Restore یا تغییر Allow برای pass کردن آزمون انجام ندهید.
''')
check="$ErrorActionPreference='Stop';$root='ROOT';$files=@(Get-ChildItem $root -Filter *.ps1)+@(Get-ChildItem $root -Filter *.psm1);if($files.Count -ne 5){throw 'file_count'};foreach($f in $files){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e);if($e.Count){throw 'parse'}};Write-Host 'Five package PS files parsed.'".replace('ROOT',str(d));(r/'Check-Source.ps1').write_text(check);run(r/'Check-Source.ps1')
(d/'evidence').mkdir(exist_ok=True)
for p,n in [(r/'MODEL-RESULTS.json','fixture-model.json'),(Path('/data/ufw-session-journal-v01/evidence/model-tests.json'),'journal-model.json'),(r/'linux-platform-guard.json','linux-platform-guard.json'),(r/'PS51-COMPAT-RESULTS.json','PS51-compat-model.json')]: (d/'evidence'/n).write_bytes(p.read_bytes())
(d/'PROVENANCE.json').write_text(json.dumps(dict(byte_unchanged_modules={n:sha(d/n) for n in mods},source_milestone_commit='f29e8e8f15dd92be105cda25248803a174591f57',new_files=['StorageFixture.ps1','Run-Test.ps1','Run-Test.cmd'],fixture_assertions=36,journal_assertions=73,PS51_array_contract_assertions=10,old_fixture_error_reproduced_by_shim=True,Windows_storage_fixture_executed=False,real_preparation_record_created=False,real_legacy_journal_access_requested=False,profile_queries_requested=False,firewall_change_requested=False,ready_for_apply=False),indent=2))
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Test.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
old=Path('/data/ufd-normal-exit-runner-v01/package/NORMAL-EXIT-REVIEW-01');cmd=(old/'Run-Exit.cmd').read_text().replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('NORMAL_EXIT_ROOT','UFW_STORAGE_ROOT').replace('Normal Exit Review 0.1 - NO FIREWALL CHANGES. Keep VPN and network as they are.','Journal Storage Test 0.1.1 - SYNTHETIC FILES ONLY. Keep VPN and network as they are.').replace("'session-core.ps1','native.ps1','isolation-core.ps1','isolation-native.ps1','normal-exit-record.ps1','Qualification.ps1','Run-Exit.ps1'",','.join(repr(n) for n in deps+['Run-Test.ps1'])).replace('Run-Exit.ps1','Run-Test.ps1').replace('Seven package scripts','Five package scripts/modules').replace('Review or record not confirmed.','Storage fixture not confirmed.');(d/'Run-Test.cmd').write_text(cmd,newline='\r\n')
s=Path('/data/ufd-normal-exit-runner-v01/Check-Bootstrap.ps1').read_text().replace(str(old),str(d)).replace('Run-Exit.cmd','Run-Test.cmd');(r/'Check-Bootstrap.ps1').write_text(s);run(r/'Check-Bootstrap.ps1')
z=r/'UFW-JOURNAL-STORAGE-011.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 assert out.testzip() is None
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,fixture_assertions=36,journal_assertions_rerun=73,PS51_array_contract_assertions=10,package_PS_files_parsed=5,bootstrap_parsed_and_manifest_payload_verified=True,production_dependencies_byte_unchanged=True,Windows_storage_fixture_executed=False,user_action='new storage-only fixture package, same-account admin; leave network/VPN unchanged; return only diagnostic JSON',ready_for_apply=False);(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
