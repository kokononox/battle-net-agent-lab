from pathlib import Path
import json,hashlib,subprocess,zipfile
r=Path('/data/sstp-local-review-v01');d=r/'package/SSTP-LOCAL-REVIEW-01';old=Path('/data/sstp-observer-v02/package/SSTP-READONLY-OBSERVER-02');v031=Path('/data/sstp-endpoint-v031/package/SSTP-ENDPOINT-OBSERVER-031');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mods=['Observer.ps1','Identity.ps1','IdentityPolicy.ps1','RasIdentity.cs','Endpoint.ps1','Sstp.TransportPlan.ps1','LocalReview.ps1']
s=(old/'Run-Observer.ps1').read_text().replace('sstp-observer-diagnostic-02','sstp-local-review-diagnostic-01').replace('SSTP-OBSERVER-02','SSTP-LOCAL-REVIEW-01')
a=s.index(" $hashes=ConvertFrom-Json @'\n")+len(" $hashes=ConvertFrom-Json @'\n");b=s.index("\n'@",a);s=s[:a]+json.dumps({n:sha(d/n) for n in mods},indent=2)+s[b:]
s=s.replace(". (Join-Path $root 'Observer.ps1')",". (Join-Path $root 'LocalReview.ps1')").replace("$report.stage='lifecycle_observation';$binding=$null","$report.stage='local_review';$binding=$null").replace('Invoke-SstpLifecycleObservation $expected ([ref]$binding)','Invoke-SstpLocalEndpointReview $expected').replace("Write-Host ('Observed state: '+$report.observation.vpn_state)","Write-Host ('Draft review acknowledged: '+$report.observation.draft_review_acknowledged)").replace("Write-Host ('Live identity chain verified: '+$report.observation.identity_chain_verified)","Write-Host ('Fresh revalidation passed: '+$report.observation.fresh_revalidation_passed)")
s=s.replace('single_visible_SSTP_for_observation_only','single_visible_SSTP_for_memory_only_draft_review').replace('Observing one SSTP candidate in the current Windows account. This is NOT firewall approval.','Reviewing one SSTP candidate locally. This is NOT firewall approval.').replace('Return only the new SSTP-LOCAL-REVIEW-01-*.json file, even if the observation failed.','Return only the new SSTP-LOCAL-REVIEW-01-*.json file. Do NOT send the local review screen.')
(d/'Run-Observer.ps1').write_text(s,newline='\r\n')
(d/'README-FA.md').write_text('''# بازبینی محلی مقصد SSTP — ۰٫۱

این بسته مستقل، فقط‌خواندنی نسبت به شبکه/فایروال است؛ روی برنامه یا نسخهٔ قبلی کپی نشود. VPN در وضعیت فعلی متصل و full-tunnel بماند؛ Apply/Restore/قطع‌و‌وصل لازم نیست. فقط یک پروفایل SSTP از نوع CurrentUser پشتیبانی می‌شود؛ AllUsers عمداً blocked است.

## اجرا

1. ZIP را در پوشهٔ محلی تازه Extract کنید.
2. `Run-Observer.cmd` را با Run as administrator و همان حساب صاحب VPN اجرا کنید.
3. ابزار مشخصات پروفایل، hostname و **یک IP پیشنهادی** را فقط در همان پنجرهٔ محلی نمایش می‌دهد. **این قسمت را عکس نگیرید یا برای کسی نفرستید.**
4. اگر پروفایل/سرور همان مورد موردنظر شماست و می‌خواهید همین IP پیشنهادی را صرفاً برای draft بازبینی کنید، عبارت تصادفی `REVIEW ...` نمایش‌داده‌شده را دقیقاً تایپ کنید. ابزار از شما نمی‌خواهد هویت مستقل یا مالکیت IP را تضمین کنید؛ اگر مورد نامنتظره است یا نمی‌خواهید تأیید کنید، Enter خالی بزنید تا لغو شود.
5. پس از تأیید، هویت و اتصال دوباره خوانده می‌شوند. تغییر binding/IP/flow/PID/زمان ایجاد پردازش/hash فایل تأیید draft را نامعتبر می‌کند. مشاهده‌ها اتمیک نیستند.
6. فقط JSON تازهٔ `SSTP-LOCAL-REVIEW-01-*.json` را برگردانید، حتی اگر لغو یا failure باشد. در خطای راه‌انداز و نبود JSON فقط متن خطای بدون مشخصات شخصی را بفرستید.

## دامنهٔ واقعی

این «تأیید محلیِ بازبینی draft» است؛ **pin مصوب فایروال یا مجوز Apply ذخیره نمی‌شود**. رضایت همین invocation پس از پایان مصرف اجرایی ندارد. نه authority محافظت‌شدهٔ approval ساخته شده، نه guardian/executor. `persistent_approval_created`، `endpoint_pin_approved_for_firewall` و `ready_for_apply` همیشه false هستند. cache و host تک‌سرویس هنوز هویت cryptographic سرور را ثابت نمی‌کنند؛ TLS/service-tag/امضا/bootstrap تأیید نشده‌اند.

چهار مشاهدهٔ lifecycle و چهار snapshot بومی در مسیر موفق، قبل/بعد از prompt انجام می‌شوند. تأیید خودکار یا فایل approved=true پذیرفته نمی‌شود. raw مشخصات فقط در حافظه و صفحهٔ محلی‌اند؛ گزارش خروجی نام/IP/PID/SID/GUID/digest/raw binding یا challenge ندارد. host history محیط و ابزارهای screen capture خارج از کنترل این بسته‌اند؛ پنجره را خصوصی نگه دارید. transcript یا screenshot این بخش را ارسال نکنید.

هیچ DNS lookup/probe/اتصال یا قطع VPN/تغییر فایروال درخواست نمی‌شود. JSON نوشته می‌شود و Add-Type ممکن است فایل موقت ایجاد کند؛ hash فایل svchost خوانده می‌شود، Authenticode با احتمال retrieval شبکه‌ای عمداً اجرا نمی‌شود. هیچ ادعای no-leak، جلوگیری از fingerprint، cold-start یا reconnect نداریم. وابستگی به alias/index کارت فیزیکی ندارد؛ تست زیر ایزولاسیون یا تعویض Ethernet/Wi-Fi انجام نشده است.

## کنترل بسته و آزمون

راه‌انداز SHA256 manifest و تمام payload را پیش از اجرا بررسی می‌کند؛ فقط هفت PS1 همین بسته Unblock می‌شوند. RemoteSigned فقط برای پردازش فرزند است؛ سیاست دائمی یا GPO تغییر/دور زده نمی‌شود. hash بسته را با مقدار اعلام‌شده مقایسه کنید؛ خود CMD امضای ناشر ندارد.

۶۴ assertion مدل بازبینی محلی، ۶۱ endpoint، ۸۴ lifecycle و ۸۶ طرح حمل دقیق روی Linux گذشتند. input/prompt و native adapter در آزمون جدید mock هستند؛ نمایش و تأیید واقعی Windows این بسته هنوز آزموده نشده است. native readerهای موجود بدون تغییر بایت استفاده شده‌اند و اجرای قبلی v0.3.1 فقط مشاهدهٔ connected endpoint را تأیید کرده است.
''')
def run(path,*args,code=0):
 p=subprocess.run(['/data/ufd-isolation-hf1/pwsh/pwsh','-NoProfile','-File',str(path),*map(str,args)],capture_output=True,text=True,timeout=120)
 (r/(Path(path).name+'.log')).write_text(p.stdout+'\n'+p.stderr);assert p.returncode==code,(p.stdout,p.stderr)
run(r/'Test-LocalReview.ps1')
run('/data/sstp-observer-v02/Test-Observer.ps1','-Root',d)
run('/data/sstp-endpoint-v031/Test-Endpoint.ps1','-Root',d)
run('/data/sstp-exact-transport-plan-v01/Test-TransportPlan.ps1')
for n in ['Check-Source.ps1','Check-Bootstrap.ps1']:
 t=(Path('/data/sstp-observer-v02')/n).read_text().replace('/data/sstp-observer-v02/package/SSTP-READONLY-OBSERVER-02',str(d)).replace('/data/sstp-observer-v02/source-checks.json',str(r/'source-checks.json'));(r/n).write_text(t)
run(r/'Check-Source.ps1');run(d/'Run-Observer.ps1',code=1)
reports=list(d.glob('SSTP-LOCAL-REVIEW-01-*.json'));assert len(reports)==1
v=json.loads(reports[0].read_text('utf-8-sig'));assert v['error_code']=='observer_windows_required' and not v['native_API_attempted'];reports[0].replace(r/'linux-platform-guard.json')
(d/'evidence').mkdir(exist_ok=True)
for name in ['MODEL-RESULTS.json','source-checks.json','linux-platform-guard.json']:(d/'evidence'/name).write_bytes((r/name).read_bytes())
for src,dest in [('/data/sstp-observer-v02/model-results.json','lifecycle-model.json'),('/data/sstp-endpoint-v031/model-results.json','endpoint-model.json'),('/data/sstp-exact-transport-plan-v01/MODEL-RESULTS.json','transport-model.json')]: (d/'evidence'/dest).write_bytes(Path(src).read_bytes())
unchanged={n:sha(d/n) for n in ['Observer.ps1','Identity.ps1','IdentityPolicy.ps1','RasIdentity.cs','Endpoint.ps1']}
assert all((d/n).read_bytes()==(v031/n).read_bytes() for n in unchanged)
assert (d/'Sstp.TransportPlan.ps1').read_bytes()==Path('/data/sstp-exact-transport-plan-v01/Sstp.TransportPlan.ps1').read_bytes()
(d/'PROVENANCE.json').write_text(json.dumps(dict(unchanged_v031_modules=unchanged,transport_draft_byte_unchanged=True,new_module='LocalReview.ps1',Windows_local_review_tested=False,persistent_approval_implemented=False,ready_for_apply=False),indent=2))
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['Run-Observer.cmd','PAYLOAD-SHA256.json']};(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Observer.cmd').read_text().replace(sha(old/'PAYLOAD-SHA256.json'),pin).replace('SSTP Observer 0.2','SSTP Local Review 0.1').replace("'Observer.ps1','Run-Observer.ps1'","'Observer.ps1','Endpoint.ps1','Sstp.TransportPlan.ps1','LocalReview.ps1','Run-Observer.ps1'").replace('Four package scripts','Seven package scripts')
(d/'Run-Observer.cmd').write_text(cmd,newline='\r\n');run(r/'Check-Bootstrap.ps1')
z=r/'SSTP-LOCAL-REVIEW-01.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
v=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,manifest_sha256=pin,local_review_assertions=64,endpoint_assertions=61,lifecycle_assertions=84,transport_assertions=86,Windows_local_review_tested=False,persistent_approval_implemented=False,ready_for_apply=False);(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
