from pathlib import Path
import json,hashlib,subprocess,zipfile
r=Path('/data/sstp-endpoint-v03');d=r/'package/SSTP-ENDPOINT-OBSERVER-03';old=Path('/data/sstp-observer-v02/package/SSTP-READONLY-OBSERVER-02');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
runner=(old/'Run-Observer.ps1').read_text().replace('sstp-observer-diagnostic-02','sstp-endpoint-diagnostic-03').replace('SSTP-OBSERVER-02','SSTP-ENDPOINT-03')
a=runner.index(" $hashes=ConvertFrom-Json @'\n")+len(" $hashes=ConvertFrom-Json @'\n");b=runner.index("\n'@",a)
mods=['Observer.ps1','Identity.ps1','IdentityPolicy.ps1','RasIdentity.cs','Endpoint.ps1']
runner=runner[:a]+json.dumps({n:sha(d/n) for n in mods},indent=2)+runner[b:]
runner=runner.replace(". (Join-Path $root 'Observer.ps1')",". (Join-Path $root 'Endpoint.ps1')").replace("$report.stage='lifecycle_observation';$binding=$null","$report.stage='endpoint_observation';$binding=$null").replace('Invoke-SstpLifecycleObservation $expected ([ref]$binding)','Invoke-SstpEndpointObservation $expected').replace('$report.observation.identity_chain_verified','$report.observation.identity_stable_within_run').replace('Live identity chain verified: ','Live identity stable within run: ')
(d/'Run-Observer.ps1').write_text(runner,newline='\r\n')
(d/'README-FA.md').write_text('''# مشاهده‌گر مقصد SSTP — نسخهٔ ۰٫۳

این بسته مستقل است؛ داخل برنامهٔ فایروال جایگزین نشود. VPN را در وضعیت فعلی نگه دارید؛ Apply، Restore، قطع یا وصل نکنید.

## اجرا

1. ZIP را در یک پوشهٔ محلی تازه Extract کنید، نه داخل ZIP یا مسیر شبکه‌ای.
2. روی `Run-Observer.cmd` راست‌کلیک و Run as administrator بزنید؛ با همان حساب Windows صاحب VPN، نه حساب دیگری.
3. صبر کنید تا Report نمایش داده شود؛ فقط فایل تازهٔ `SSTP-ENDPOINT-03-*.json` را برگردانید، حتی اگر false باشد. در خطای راه‌انداز و نبود JSON، فقط متن خطا را بفرستید.

راه‌انداز ابتدا manifest و همهٔ payload را با SHA256 بررسی می‌کند، سپس فقط پنج PS1 همین بسته را Unblock می‌کند. RemoteSigned فقط برای پردازش فرزند است؛ سیاست دائمی تغییر نمی‌کند، Bypass استفاده نمی‌شود و سیاست سازمانی دور زده نمی‌شود. CMD خودامضاشده نیست؛ هش ZIP ارسالی را با هش اعلام‌شده تطبیق دهید. این ابزار گزارش JSON می‌نویسد و Add-Type ممکن است فایل موقت کامپایل بسازد؛ منظور از فقط‌خواندنی، عدم تغییر شبکه، فایروال و اعتبارنامه‌هاست.

## دامنهٔ مشاهده

- از مشاهده‌گر v0.2 بدون تغییر بایت استفاده می‌کند؛ هویت پروفایل/RAS/interface در همین اجرا دوباره بررسی و مقایسه می‌شود.
- فقط وضعیت سرویس‌ها و پردازش، مسیر و hash فایل svchost سیستم، زمان ایجاد پردازش، cache محلی DNS و اتصال‌های TCP موجود را می‌خواند. هیچ DNS lookup، probe، dial یا hangup انجام نمی‌دهد.
- نام سرور تنظیم‌شده یا IP literal با peer موجود TCP/443 همان PID تطبیق داده می‌شود. CNAME به‌صورت محدود دنبال می‌شود. cache خالی، منقضی یا ناسازگار به معنی نبود شواهد است؛ درخواست DNS خودکار ندارد.
- اشتراک svchost صریح گزارش می‌شود. OwningProcess فقط PID است: همبستگی یک flow با پردازش مشترک، اثبات مالکیت SstpSvc نیست. حتی در host تک‌سرویس، service tag و TLS تأیید نمی‌شوند.
- tuple و زمان ایجاد flow، PID/زمان ایجاد پردازش/hash فایل/عضویت سرویس و هویت تونل در snapshotهای متوالی مقایسه می‌شوند؛ مشاهده اتمیک نیست و امکان race از بین نمی‌رود. مسیر/hash فایل اثبات اعتماد یا سلامت حافظهٔ پردازش نیست. بررسی امضای Authenticode عمداً اجرا نمی‌شود، چون اعتبارسنجی زنجیره/ابطال ممکن است بازیابی شبکه‌ای ضمنی ایجاد کند؛ `service_host_signature_valid=false` باقی می‌ماند.
- نام/IP/PID/پورت محلی/مسیر/GUID/شناسهٔ نشست و hash خام در JSON نوشته نمی‌شوند. شمارنده‌ها و نتیجهٔ محدود مشاهده نوشته می‌شوند.

این بسته نه روی دانگل وای‌فای قفل می‌شود نه روی نام/شمارهٔ کارت فیزیکی. این استقلال طراحی، تأیید عملی تغییر Wi-Fi به Ethernet، مسیرها، DHCP یا reconnect نیست.

## مرزهای تأیید

`ready_for_apply`، مجوز فایروال، pin تأییدشده، bootstrap DNS/TLS، service-tag و no-leak همیشه false می‌مانند. cache محلی منبع اعتماد یا pin مصوب نیست. این بسته ترافیک fingerprint را فیلتر نمی‌کند و اثبات عدم ارسال آن نیست.

۵۸ assertion مدل/adapter در Linux گذشت؛ lifecycle قبلی نیز ۸۴ assertion دارد. این اعداد آزمون واقعی endpoint روی Windows نیستند. دو اجرای Windows قبلی صرفاً v0.2 و حالت connected را تأیید کرده‌اند. هیچ تست زندهٔ endpoint/reconnect/Ethernet یا اعمال فایروال توسط سازنده اجرا نشده است.

## منابع فنی

- https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/dnsclientcimprov/msft-dnsclientcache
- https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientcache
- https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection
''')
for name in ['Check-Source.ps1','Check-Bootstrap.ps1']:
 s=(Path('/data/sstp-observer-v02')/name).read_text().replace('/data/sstp-observer-v02/package/SSTP-READONLY-OBSERVER-02',str(d)).replace('/data/sstp-observer-v02/source-checks.json',str(r/'source-checks.json'))
 (r/name).write_text(s)
def run(args,code=0):
 p=subprocess.run(['/data/ufd-isolation-hf1/pwsh/pwsh','-NoProfile','-File',*args],capture_output=True,text=True,timeout=120)
 (r/(Path(args[0]).name+'.log')).write_text(p.stdout+'\n'+p.stderr)
 assert p.returncode==code,(p.stdout,p.stderr)
run([str(r/'Test-Endpoint.ps1')]);run(['/data/sstp-observer-v02/Test-Observer.ps1','-Root',str(d)]);run([str(r/'Check-Source.ps1')])
run([str(d/'Run-Observer.ps1')],1)
reports=list(d.glob('SSTP-ENDPOINT-03-*.json'));assert len(reports)==1
v=json.loads(reports[0].read_text('utf-8-sig'));assert v['error_code']=='observer_windows_required' and not v['native_API_attempted'];reports[0].replace(r/'linux-platform-guard.json')
(d/'evidence').mkdir(exist_ok=True)
for n in ['model-results.json','source-checks.json','linux-platform-guard.json']:(d/'evidence'/n).write_bytes((r/n).read_bytes())
(d/'evidence/lifecycle-model-results.json').write_bytes(Path('/data/sstp-observer-v02/model-results.json').read_bytes())
(d/'PROVENANCE.json').write_text(json.dumps(dict(unchanged_v02_modules={n:sha(d/n) for n in mods if n!='Endpoint.ps1'},v02_byte_unchanged=all((old/n).read_bytes()==(d/n).read_bytes() for n in mods if n!='Endpoint.ps1'),new_module='Endpoint.ps1',Windows_endpoint_tested=False,read_only=True,ready_for_apply=False),indent=2))
manifest={str(p.relative_to(d)):sha(p) for p in sorted(d.rglob('*')) if p.is_file() and p.name not in ['PAYLOAD-SHA256.json','Run-Observer.cmd']}
(d/'PAYLOAD-SHA256.json').write_text(json.dumps(manifest,indent=2));pin=sha(d/'PAYLOAD-SHA256.json')
oldpin=sha(old/'PAYLOAD-SHA256.json')
cmd=(old/'Run-Observer.cmd').read_text().replace(oldpin,pin).replace('Observer 0.2','Endpoint Observer 0.3').replace("'Observer.ps1','Run-Observer.ps1'","'Observer.ps1','Endpoint.ps1','Run-Observer.ps1'").replace('Four package scripts','Five package scripts')
(d/'Run-Observer.cmd').write_text(cmd,newline='\r\n');run([str(r/'Check-Bootstrap.ps1')])
z=r/'SSTP-ENDPOINT-OBSERVER-03.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
 for p in sorted(d.rglob('*')):
  if p.is_file():out.write(p,str(p.relative_to(d.parent)))
with zipfile.ZipFile(z) as out:
 for n,h in manifest.items():assert hashlib.sha256(out.read(d.name+'/'+n)).hexdigest()==h
summary=dict(filename=z.name,sha256=sha(z),bytes=z.stat().st_size,endpoint_model_assertions=58,lifecycle_model_assertions=84,manifest_sha256=pin,Windows_endpoint_tested=False,ready_for_apply=False)
(r/'PACKAGE-SUMMARY.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
