# G40 — مخزن خصوصی ویندوز و endpoint قرنطینه با مالک/Job واقعی

## وضعیت
نسخهٔ پژوهشیِ synthetic است: helper بومی ویندوز کامپایل و17آزمون روی Windows2025 موفق شد.30آزمون POSIX هم جداگانه روی Linux موفق است. این دو عدد را به‌عنوان یک اجرای47تستی یا پذیرش محصول نهایی جمع نمی‌کنیم. نصاب، حساب، دانلود فایل واقعی یا ترافیک Battle.net اجرا نشد.

endpoint قرنطینهٔ جدید، جایگزینِ فعالِ پراکسی یا فایروال محصول نیست. هیچ allowlist یا پورت خارجی تغییر نکرد. نسخه‌های قبلی و main تغییر نکرده‌اند.

## مخزن Windows
`PrivateStore.cs` یک helper محلی .NET Framework است. ریشه فقط `%ProgramData%\BNetOnlineG40\<32hex>\quarantine` است. هر سه پوشهٔ base/session/quarantine با DACL محافظت‌شده و دقیقاً SYSTEM و Administrators با FullControl ساخته/بررسی می‌شوند؛ owner باید SYSTEM یا Administrators باشد. دسترسی به اطلاعات خصوصی مستلزم کنترلر مورد اعتماد و elevated است؛ دفاع علیه مدیر سیستم نیست.

پوشه‌ها با handle باز و بدون share-delete نگه‌داشته می‌شوند؛ مسیر نهایی، reparse flag، نوع فایل، owner و DACL از handle بررسی می‌شوند. فایل capture با CreateNew، DACL خصوصیِ مستقل، نام تصادفی و بدون share ساخته می‌شود؛ hardlink با شمار لینک غیر1 و reparse رد می‌شوند. تغییر مجوز existing file/root fail-closed است.

Mutex با نام scoped به session و ACL محدود SYSTEM/Administrators، رزرو و موجودی را بین helperهای هم‌زمان سری می‌کند. سقف16رکورد،1MiB کل و262144بایت هررکورد بعد از بازکردن دوباره هم از موجودی دیسک اعمال می‌شود. فقط فایل‌های capture با نام32hex.json در پوشهٔ quarantine پذیرفته می‌شوند. write با Flush(true) انجام می‌شود؛ اثبات کامل بازیابی power-loss یا حذف امن نداریم.

`windows_store.py` دادهٔ خصوصی را فقط از stdin به helper می‌دهد، نه command line. مسیر helper و root ورودی مورد اعتمادِ کنترلرند، نه تنظیمات کلاینت. read_for_local_review عمداً محتوای خصوصی را در حافظه برمی‌گرداند؛ آن را به log/CI/chat نفرستید. stdout عادی write/init فقط شناسه/وضعیت دارد. stderr حذف و خطاها enum هستند. متغیرهای محیطی child فقط مسیرهای ثابت لازم سیستم‌اند؛ در VM ثابت شد حذف SystemDrive آماده‌سازی .NET/root را مختل می‌کرد. اجازهٔ شبکه/ACL به‌خاطر آن بازتر نشد.

مقادیر credential شناخته‌شده حذف می‌شوند و raw request/body ذخیره نمی‌شوند. path/query/header ناشناخته می‌تواند حساس باشد و فقط خصوصی می‌ماند. ACL جای رمزگذاری دیسک نیست. انقضا/حذف خودکار و امنیت مقابل همان Admin، تزریق کد و reader بدرفتار هنوز ادعا نمی‌شوند.

## hook پیش از ارسال
`quarantine_handler.py` یک endpoint فقط-loopback جداست. ترتیب:
1. `peer_guard.admit` بومی: مالک reverse TCP tuple، process زنده، Job نام‌دار، controller identity، expiry و lease.
2. revalidate، خواندن bounded header/body و revalidate دوباره پیش از capture.
3. ثبت خصوصیِ درخواست قابل‌مشاهده با `QuarantineGate`، همیشه blocked/pending.
4. فقط403 به همان اتصال loopback؛ هیچ مسیر dial یا forwarding بالادست در handler نیست.

`peer_guard.py` و `domain_proxy.py` از G34 تنها با تغییر نام namespace به G40 کپی شده‌اند؛ منطق owner/Job/lease یا قواعد شبکهٔ آن‌ها ضعیف نشده است. endpoint جدید از توابع خواندن و admission استفاده می‌کند، نه Handler قدیمیِ عبوردهنده. import شدن domain_proxy به‌معنی راه‌اندازی آن نیست. در آزمون، connect بالادست نیز به failure sentinel متصل و عدم فراخوانی آن assert شد.

کنترلر تست، child پایتون با درخواست ساختگی را پیش از اجازهٔ اتصالش به Job می‌گذارد. هیچ Setup یا native CreateProcess نصاب اجرا نمی‌شود. این روش fixture جایگزین مسیر production launch-suspended نیست.

## بازتولید Windows
با elevated PowerShell و Python، از ریشهٔ مخزن:

```powershell
$src=(Resolve-Path 'analysis-tools/request-quarantine-g40/PrivateStore.cs').Path
$csc="$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$exe=Join-Path $env:TEMP 'G40PrivateStore.exe'
& $csc @('/nologo','/target:exe','/platform:x64','/r:System.Web.Extensions.dll',('/out:'+$exe),$src)
if($LASTEXITCODE -ne 0){throw 'build_failed'}
$env:G40_STORE_HELPER=$exe
python -I analysis-tools/request-quarantine-g40/run_windows_tests.py --report g40-evidence-local.json
```

تست‌ها فقط ACL و فایل/Job مربوط به fixture خودشان را ایجاد/تغییر/پاک می‌کنند. فایروال، Windows task، CA یا diagnostic channel دست نمی‌خورد. یک تست reparse از junction ساختگی و یک تست hardlink ساختگی استفاده می‌کند؛ همه زیر sessionهای تصادفی آزمایش‌اند. نیاز به اینترنتِ برنامهٔ هدف ندارند؛ CI خودش ارتباط مدیریتی عادی دارد و فایروال کل VM در این تست ایزوله نمی‌شود.

برای آزمون POSIX:

```bash
python -I analysis-tools/request-quarantine-g40/test_posix.py
```

## محدودیت‌های باقی‌مانده
- آزمایش low-privilege token مستقل انجام نشده؛ شکل/owner/DACL واقعی و رد drift/junction/hardlink آزموده شده است.
- header خوانده‌شده برای ثبت بازسازی و نام هدرها normalize می‌شود؛ این byte-for-byte trace کل درخواست نیست. محدودهٔ خصوصی هنوز برای بررسی path/query/fieldها کافی است، نه اثبات جامع privacy.
- فایل واقعی، پاسخ HTTP، اندازهٔ خالص payload، TLS، Range/resume و سازگاری نصب آزموده نشده‌اند.
- endpoint تحت فشار محصول، client disconnect/slowloris، توقف کامل سرویس، دست‌کاری privileged و عمر محدود capture نیازمند پذیرش بیشتر است.
- firewall system gate، recovery و کنترلر محصول به endpoint جدید وصل نشده‌اند؛ نمی‌توان گفت تمام ترافیک سیستم از آن عبور می‌کند.
- هیچ request ثبت‌شده خودکار وارد کاتالوگ approved نمی‌شود. HTTPS ناشناخته همچنان اثبات محتوایی ندارد.
