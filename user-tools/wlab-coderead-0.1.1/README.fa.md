# WLab CodeRead 0.1.1

**یک تلاش فقط‌خواندنی برای سه صفحهٔ ثابتِ نامزد کد** در همان build تأییدشدهٔ Wow. این ابزار ProcDump نیست: dump کامل، PSS clone، debugger attach، تزریق، patch یا تغییر protection درخواست نمی‌کند. اگر Windows دسترسی ندهد یا صفحه guard/no-access باشد، تلاش متوقف و خطا ثبت می‌شود؛ دورزدن یا retry دسترسی ندارد.

## اصلاح این نسخه بر اساس گزارش واقعی

در 0.1.0، SHA256 دیسک، PID/creation time و ماژول تطبیق یافتند. VirtualQueryEx برای header، state=MEM_COMMIT و protection=PAGE_READONLY گزارش کرد، اما نوع region برابر **MEM_MAPPED (0x40000)** بود، نه MEM_IMAGE. AllocationBase هم با پایهٔ ماژول تطبیق داشت. ابزار به‌خاطر شرط داخلی سخت‌گیرانه، پیش از نخستین ReadProcessMemory متوقف شد؛ این گزارش access denied یا guard نیست و علت remap شدن را مشخص نمی‌کند.

0.1.1 فقط در چهارچوب همین هویت/محدوده، **MEM_IMAGE یا MEM_MAPPED قابل‌خواندن** را می‌پذیرد. الزام allocation base، state=committed، bounds کامل، protection خواندنی و هویت/PE قبل و بعد برقرار است. MEM_PRIVATE، guard/no-access، خطای API، partial read و تغییر هویت همچنان رد می‌شوند؛ هیچ protection change یا access-denied bypass اضافه نشده است.

پیش از اولین خواندن حافظه، metadata چهار محدودهٔ از پیش ثابت (header و سه صفحهٔ هدف) در planned_region_census ثبت می‌شود. این فقط query است، نه scan یا خواندن اضافهٔ محتوا. خطای query متوقف می‌کند و تکرار نمی‌شود؛ قبل از هر خواندن هم query و gate همان محدوده دوباره اعمال می‌شوند تا وضعیت لحظه‌ای بررسی شود. سقف خواندن صریح حافظه همچنان ۲۰ KiB است. اگر policy یک محدوده را نپذیرد، تلاش خواندن همان محدوده انجام نمی‌شود.

## اجرای کاربر

1. ZIP را در پوشه‌ای تازه Extract و **WLab-CodeRead-0.1.1.exe** را اجرا کن. درخواست Administrator را اگر نمایش داده شد تأیید کن.
2. بازی آزمایشی را با همان build باز نگه دار؛ Wow.exe درست و مرحلهٔ واقعی خودت را انتخاب کن: Character selection یا In world. این مرحله گزارش کاربر است، نه تشخیص برنامه.
3. تیک تأیید تلاش فقط‌خواندنی را بزن و **Read code once** را فقط یک بار فشار بده. این تیک، EULA مربوط به ProcDump نیست؛ ProcDump در این ابزار استفاده/دریافت نمی‌شود.
4. پس از پایان، فقط **READY-TO-SEND.zip** را بفرست و بگو بازی عادی ماند، فریز شد یا بسته شد. اگر خطا داشت هم همان گزارش را بفرست و فعلاً تکرار نکن.

خروجی کوچک روی همان درایو Wow.exe ساخته می‌شود؛ مثلاً **G:\WLabCodeRead\TIMESTAMP-ID**. چند گیگ فضای C برای خروجی بزرگ لازم نیست؛ فقط launcher log و قفل مشترک نسخه‌ها همچنان در LocalAppData هستند. هیچ fallback پنهان به C وجود ندارد. نصب Python یا debugger یا دانلود Microsoft لازم نیست. WLab امضای ناشر تجاری ندارد و هیچ آپلود خودکاری انجام نمی‌دهد.

## محدودهٔ فنی دقیق

- OpenProcess فقط با `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`؛ نه دسترسی نوشتن، all-access، debug-token adjustment یا درایور. Administrator در شروع ابزار ممکن است با تأیید کاربر درخواست شود؛ پس از access denied هیچ تلاش برای افزایش دسترسی یا عبور از آن انجام نمی‌شود.
- هویت PID و creation FILETIME با انتخاب رابط تطبیق می‌یابد. مسیر image، مسیر/پایه/اندازهٔ ماژول از APIهای Windows خوانده می‌شوند. Toolhelp فقط **فهرست metadata ماژول** است؛ PSS/process clone نمی‌گیرد.
- فایل دیسک باید SHA256 دقیق `1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a`، build `12.1.5.70448` و PE AMD64 باشد. آدرس‌ها روی build متفاوت استفاده نمی‌شوند.
- پیش از هر ReadProcessMemory، VirtualQueryEx باید منطقهٔ committed MEM_IMAGE یا MEM_MAPPED متعلق به همان allocation base، پوشش کامل range و protection قابل‌خواندن بدون guard/no-access نشان دهد. protection هیچ‌گاه تغییر نمی‌کند؛ خواندن ناقص/خطا retry یا صفرگذاری نمی‌شود.
- اولین صفحهٔ PE فقط برای تطبیق AMD64/timestamp/image-size خوانده می‌شود. سپس هر کدام از این سه صفحه دقیقاً یک بار درخواست می‌شوند:
  - RVA `0x01b11000`؛ نامزد creator در `0x01b11190`، 110 بایت.
  - RVA `0x01b14000`؛ نامزد merge در `0x01b14120`، 24 بایت.
  - RVA `0x03306000`؛ نامزد parse/fallback در `0x033068c0`، 244 بایت.
- پس از آن، هویت دوباره کنترل و صفحهٔ PE برای ثبات header دوباره خوانده می‌شود. حداکثر **۵ درخواست ۴ KiB = ۲۰ KiB خواندن صریح حافظه** است: سه صفحهٔ هدف و دو header. headerها صادر نمی‌شوند. APIهای metadata جدا از این سقف دادهٔ ReadProcessMemory هستند.
- ASLR با پایهٔ واقعی ماژول لحاظ می‌شود. فقط اگر همهٔ خواندن‌ها و تطبیق‌های قبل/بعد موفق باشند، سه صفحه و سه پنجرهٔ نامزد در `.bin` صادر می‌شوند؛ روی خطای دسترسی/guard/خواندن ناقص/تغییر هویت، دادهٔ staged صادر نمی‌شود.
- یک marker مانع اجرای دوبارهٔ CLI روی همان پوشهٔ گزارش می‌شود. رابط نیز هر بار فقط یک تلاش دارد و از قفل مشترک با Snapshot/Control استفاده می‌کند. ابزارهای قبلی را هم‌زمان اجرا نکن.
- self-test خروج 0 و 7 فقط دو پردازش متعلق به خود WLab است؛ 7 در این آزمون عمدی است. کد خروج helper و وضعیت معنایی analysis جدا ثبت می‌شوند؛ هیچ فرضی دربارهٔ کد خروج ProcDump در این ابزار وجود ندارد.
- پس از پایان، سه نمونهٔ metadata از همان فرایند/Responding طی حدود ۱۰ ثانیه ثبت می‌شوند. این‌ها پایداری کامل را ثابت نمی‌کنند؛ پاسخ کاربر لازم است.
- لغو یا timeout فقط helper ساخته‌شده توسط WLab را متوقف می‌کند؛ نه بازی. خود خواندن‌های Windows هم تضمین بی‌اثر بودن یا نبود واکنش نرم‌افزار هدف نیستند.

## چه چیزی ثابت نمی‌کند؟

این خواندن‌ها **زنده و پشت سر هم** هستند، نه snapshot اتمیک. یکسان‌بودن هویت و header قبل/بعد ثابت نمی‌کند کد در فاصلهٔ خواندن‌ها هیچ تغییری نکرده است. تطبیق هویت، هش کامل همهٔ حافظهٔ image نیست.

مقایسهٔ بایت‌ها raw است؛ relocationها normalize نمی‌شوند. تفاوت کد نسبت به دیسک به‌تنهایی اثبات decrypt شدن، اجرا، population، serialization یا ارسال شبکه نیست. نقش سه تابع همچنان «نامزد» است. ارسال یا عدم ارسال CPU/BIOS روی TCP/3724 هنوز **نامشخص** است. خروجی صفحات محدود نیز نباید به‌عنوان تضمین نبود دادهٔ حساس در هر بایت تلقی شود؛ گزارش خودکار آپلود نمی‌شود.

موفقیت کنترل قبلی فقط نشان داد ProcDump روی هدف کوچکِ WLab در هر دو مسیر فایل ساخت؛ علت شکست روی بازی همچنان قطعی نیست. این ابزار راه متفاوتی برای گرفتن شواهد محدود است، نه ادعای دورزدن anti-cheat یا حل قطعی capture.

## خروجی و آزمون

در `report/`، `analysis.json` شامل هویت، query/protectionها، خطاهای Win32، هش‌ها و مقایسهٔ raw است؛ `run.json` مراحل رابط را نگه می‌دارد. فقط در موفقیت کامل، شش فایل `.bin` با مجموع 12,666 بایت اضافه می‌شوند. ZIP کوچک، allowlist مشخص دارد؛ dump کامل، arbitrary .bin یا فایل بازی داخل آن نیست.

آزمون‌های fake reader شامل صفحهٔ guard، access denied، partial read، تغییر هویت/header، metadata failure و raw bytes تغییرکرده است. fixture دیسک واقعاً با هش build پین‌شده تطبیق می‌یابد، اما این آزمون runtime نیست. Go/PowerShell و build Windows x64 در Linux بررسی می‌شوند؛ **WinForms و API خواندن حافظهٔ بازی روی Windows در محیط ساخت اجرا نشده‌اند.** جزئیات در QA.json است؛ اولین اجرای واقعی این روش هنوز نیاز به تأیید دارد.

منبع کامل در `source/` است. برای بازسازی با Go منطبق با PROVENANCE.json:

```sh
cd source
sh build.sh
```

APIها: OpenProcess، GetProcessTimes، QueryFullProcessImageNameW، module-list Toolhelp، VirtualQueryEx و ReadProcessMemory. main مخزن و GUI BIOS Path 0.2 تغییر نکرده‌اند.
