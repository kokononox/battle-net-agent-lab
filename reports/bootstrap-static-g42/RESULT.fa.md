# G42 — بررسی استاتیک bootstrap رسمی، بدون اجرای نصاب

## نتیجه
فایل نسخه1.0.68 از لینک دقیق صفحهٔ رسمی Windows دریافت شد. اندازه4700880بایت و SHA-256 زیر، با pin تاریخی یکسان است:

```
f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6
```

یک Windows2025 تازه همان URL نسخه‌دار و همان hash را مستقل دریافت کرد؛ Get-AuthenticodeSignature وضعیت Valid و ناشر Blizzard Entertainment, Inc. را برگرداند. source بررسی ویندوز `a76e635c31e7666fae17ab0c271774c01bf2295f`، run `40242794593`، job `121318005628` است. بررسی امضا، خواندن دادهٔ فایل بود؛ هیچ دستور اجرای نصاب، DLL load از آن، نصب یا ورود به حساب وجود نداشت. امضای معتبر به معنیِ بی‌خطر بودن همهٔ رفتارها یا نبود fingerprinting نیست.

## آنچه واقعاً استخراج شد
- ساختار PE32، جدول بخش‌ها و51منبع داخلی با offset/اندازه/hash استخراج شد. فایل با archive-list معمولی 7za باز نشد؛ منابع از جدول resource خود PE خوانده شدند. این شکستِ archive-list، اثبات رمزگذاری یا نبود دادهٔ دیگر نیست.
- SETTINGS.JSON به اندازه410بایت، ProductCode=bna، ClientProductCode=Bna و PatchProductCode=BBNR را دارد. ProductUid=battle.net نام محصول است، نه مقدار شناسهٔ واقعی کاربر.
- رشته‌های مربوط به دریافت versions، cdns، config و TACT/NGDP در فایل وجود دارند؛ از این‌ها هنوز فهرست کامل و قابل‌تأیید payloadها با URL/اندازه/hash به دست نیامده است.
- برای هر رشتهٔ endpoint گزارش‌شده، offset واقعی در باینری ثبت شد. رشته‌های قالب‌دار مثل `%s`، URL کاملِ مشاهده‌شده در شبکه نیستند؛ ترکیب خودکار قطعهٔ hostname/path با product نیز درخواست تأییدشده محسوب نمی‌شود.
- هفت FileDescriptorProto تعبیه‌شده به‌صورت آفلاین decode شدند؛ شش تای آن‌ها پیام‌های Bootstrapper و یکی metadata مربوط به extensionهاست. offset، اندازه، hash و نام/شماره/نوع فیلدها در static-evidence.json ثبت شده است.

## سرنخ مهم حریم خصوصی — نه اثبات ارسال
دو رشتهٔ زیر در بایت‌های همین فایل وجود دارند:

```
https://telemetry-in.battle.net/data
https://telemetry-in.battlenet.com.cn/data
```

ساختار پیام‌های decodeشده شامل موارد زیر است:
- ClientRunOnStartup: فیلد client_id شماره3 از نوع string؛ دو فیلد checked_value/default_checked_value از نوع bool.
- SessionGenerate: فیلد uuid شماره1 از نوع string.
- SessionUpdate: فیلد uuid شماره2، به‌علاوه game_uid، game_locale و bootstrapper_version.
- Error: فیلدهای error_message، context و bootstrapper_state.

همچنین importهای GetComputerNameW، GetSystemInfo، GetVolumeInformationW و RegQueryValueEx دیده شدند. این‌ها صرفاً قابلیت‌های قابل‌دسترس‌اند؛ اتصالشان به پیام ارسالی، مقدار واقعی، پایداری شناسه، وابستگی به سخت‌افزار، رسیدن داده به مقصد یا هدف پردازش سمت سرور از این بررسی ثابت نشده است. client_id/uuid ممکن است شناسهٔ برنامه یا session باشند؛ نامشان به‌تنهایی اثباتِ fingerprint سخت‌افزاری نیست. وجود پیام خطا هم به‌تنهایی ثابت نمی‌کند context حاوی اطلاعات سیستم است.

نتیجهٔ عملی مطابق هدف پروژه: این سرنخ‌ها «بی‌ارتباطی با fingerprinting» را ثابت نمی‌کنند و هیچ‌کدام مجوز عبور نگرفتند. به endpointهای کشف‌شده درخواست نفرستادیم. تشخیص download/telemetry نباید فقط بر نام میزبان یا متد GET متکی باشد.

## حدود شبکه و دسترسی
در Linux فقط صفحهٔ عمومی Windows و لینک رسمی bootstrap از download.battle.net/downloader.battle.net خوانده شدند؛ HTTPS با اعتبارسنجی عادی، حداکثر پنج hop با میزبان‌های ثابت، بدون cookie jar، حساب، body، query پویا یا credential. درخواست Windows به URL نسخه‌دار ثابت، بدون redirect/cookie/proxy و با User-Agent ثابت بود. trust check بومی می‌تواند طبق سیاست معمول Windows بررسی زنجیره/ابطال را انجام دهد؛ CA وارد نشد و TLS/revocation غیرفعال نشد.

این دریافت‌های پژوهشیِ بیرون از گیت کاربر، همچنان IP/TCP/TLS metadata عادی محیط آزمایش را به سرور نشان می‌دهند؛ ادعای «فقط دریافت بیت بدون هیچ خروج شبکه» نداریم. سرنخ‌های telemetry/nydus/version کشف‌شده عمداً فراخوانی نشدند. هیچ اجازهٔ شبکه‌ای در محصول اضافه نشد؛ production catalog، main و Unified Firewall Desktop0.9.10 تغییر نکردند. تعداد resourceهای واقعی approved همچنان صفر است. خود نصاب به repo/artifact یا کاربر به‌عنوان محصول نهایی تحویل داده نشده است.

## اعتبارسنجی و محدودیت‌ها
شش آزمون آفلاین مستقل موفق شدند: hash/اندازهٔ دریافت، تطبیق منابع JSON با بایت واقعی، تطبیق offset رشته‌ها، decode مستقل descriptorها، اتصال گزارش امضای Windows به همان hash، و ثابت‌ماندن ادعاهای fail-closed. اجرای بومی امضای ویندوز یک بررسی جداست؛ آن را با شش آزمون آفلاین جمع نمی‌کنیم.

گواهی‌های PKCS#7 در Linux صرفاً parse شدند، نه trust-verify. چهار بایت padding صفر WIN_CERTIFICATE پس از بررسی طول ASN.1 جدا شدند؛ بایت غیرصفر نادیده گرفته نشد. نتیجهٔ Valid فقط به بررسی مستقل Windows نسبت داده شده است.

strings و resource/protobuf parsing، پوشش کامل مسیرهای اجرایی نیستند؛ محتوا می‌تواند دینامیک، فشرده یا ساخته‌شده از قطعات دیگر باشد. نبود literal خاص، نبود قابلیت را ثابت نمی‌کند. manifest کامل بازیابی نشد، هیچ payload دانلود نشده و سازگاری broker واقعی هنوز ثابت نیست.

## قدم بعد
از ProductCode=bna و سرنخ‌های version/config برای شناسایی منبع عمومی manifest استفاده شود؛ فقط درخواست ثابتِ بازسازی‌شده توسط ابزار مورد اعتماد، بدون شناسه یا دادهٔ نصاب، بررسی شود. پیش از تأیید هر resource باید URL دقیق، اندازهٔ خالص، hash/اصالت، محتوای لازم و مسیر وابستگی‌ها مشخص شوند. ناشناختهٔ HTTPS بسته می‌ماند. این مسیر باید دانلودِ نصب دستی کاربر را پشتیبانی کند؛ پروژه به installer خودکار تغییر هدف نداده است.
