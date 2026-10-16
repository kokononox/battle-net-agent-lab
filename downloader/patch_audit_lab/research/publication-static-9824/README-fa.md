# Agent 9824: انتشار sequence و مرز قفل‌ها

> checkpoint بعدی [binding/extension](../binding-extension-9824/README-fa.md) منبع نام و predicate انتخاب حالت را ردیابی کرده و برداشت header قبلی را اصلاح می‌کند؛ suite جاری ۳۳۸ است. این گزارش و receiptهای ۳۱۸تایی تاریخی‌اند.


## نتیجه

بعد از checkpoint قبلی، مسیر caller نوشتن header و reader مصرف‌کنندهٔ sequence دنبال شد. ممیزی تازه روی Agent واقعی با SHA256 ثابت اجرا شد: **۳۲ byte anchor، ۱۷ فراخوانی مستقیم، ۱۳ یال branch/jump و ۶ import/API** تطبیق یافتند. ممیزی mapping/flush قبلی نیز پیش‌شرط است و دوباره اجرا می‌شود. این اعداد فقط دسته‌های ممیزی تازه‌اند؛ با اعداد قبلی جمع نمی‌شوند.

**۳۱۸ آزمون، صفر failure/error/skip**: ده test method تازه برای verifier، همراه مجموعهٔ ۳۰۸تایی قبلی. آزمون‌های تازه علاوه بر حالت سالم، تغییر تک‌تک anchorها، مقصد callها، opcode و مقصد branchها و هویت/دستور importها را روی image ساختگی رد می‌کنند. اجرای ممیزی روی Agent واقعی جدا از suite ثبت شده است. هیچ executable اجرا نشده و shmem واقعی کاربر در دسترس نیست.

## ۱. محل واقعی ثبت sequence

در caller `0x71c119`، آدرس متغیر محلی خروجی به orchestrator `0x71e887` داده می‌شود. orchestrator مسیر ساخت/نوشتن جدول و helper sync/rename را طی می‌کند. پس از بازگشت صفر از helper، sequence در cache شیء داخلی ثبت می‌شود (`0x71e95a`)؛ سپس handle منتقل/بسته و جدول از مسیر `0x72b84f` bind می‌شود. شرط نتیجهٔ bind در `0x71e984` است.

در caller، **فقط اگر نتیجهٔ orchestrator صفر باشد**، بلوک `0x71c178..0x71c185` اجرا می‌شود:

```text
control = object[0x38]
control[0x110 + bucket * 4] = output_sequence
```

خطای orchestrator از این store عبور نمی‌کند. اتصال object+0x38 به خروجی control-open در `0x71c620` و forwarding در `0x71e0a2` دیده و با audit قبلیِ pointer نگاشت متصل شده است. این یک store معمولی DWORD در مسیر بررسی‌شده است؛ از آن durable commit یا هماهنگی همهٔ readerها نتیجه نمی‌گیریم.

**نتیجهٔ طراحی:** «فایل جدید ساخته/rename شد» با «sequence در header منتشر شد» یک رویداد نیست. حتی cache داخلی قبل از bind به sequence جدید تغییر می‌کند؛ اگر bind خطا دهد، در این مسیر header هنوز به آن مقدار به‌روز نشده است. recovery سراسری این وضعیت هنوز اثبات نشده؛ writer مستقل نباید این فاصله را نادیده بگیرد.

شواهد: `header-publish.asm`، `flush-bind-return.asm`، `control-open-output.asm` و `control-bind-forwarder.asm`.

## ۲. reader واقعاً header را مصرف می‌کند، نه فقط نام بیشینه را

`0x71c555`، به‌جز modeهای عددی ۲/۴/۵ در شاخهٔ خودش، sequence همان bucket را از `object[0x38] + 0x110 + bucket*4` می‌خواند و به `0x71ec75` می‌دهد. **این modeها لزوماً protocol فایل نیستند؛ عدد ۵ در این دو زمینه را یکی نگیرید.**

در `0x71ec75`:

- cache == header: بازگشت صفر بدون بازکردن مجدد در این تابع.
- cache > header با مقایسهٔ unsigned: مسیر diagnostic و بازگشت ۱.
- cache < header: نام‌سازی با sequence داده‌شده، بازکردن فایل، تغییر cache و bind.

این شاهد مصرف مستقیم header توسط یک مسیر Agent است؛ نتیجهٔ قبلی را تقویت می‌کند که انتخاب max filename قرارداد عمومی قابل‌قبول برای writer نیست. این تابع به‌تنهایی سیاست همهٔ modeها، wraparound یا اجرای بازی را اثبات نمی‌کند.

شواهد: `header-reader.asm` و `sequence-refresh.asm`.

## ۳. قفل‌های مشاهده‌شده دو سطح دارند

مسیر bulk در `0x71bb82` ابتدا guard شیء در offset `0x70` را می‌گیرد؛ سپس ۱۶ bucket را از آرایهٔ `object + 0x620 + bucket*4` قفل می‌کند، refresh انجام می‌دهد و بعد caller انتشار را برای bucketهای دارای ورودی صدا می‌زند. در پایان مسیر معمول، helper `0x71b87a` قفل‌های ۱۶ bucket را آزاد می‌کند و guard بیرونی آزاد می‌شود. unwind و تمام مسیرهای خطای خارج از این ناحیه کامل بازیابی نشده‌اند.

importهای واقعی برای bucketها **AcquireSRWLockExclusive / ReleaseSRWLockExclusive** هستند؛ آن‌ها را قفل بین‌پردازه‌ای معرفی نمی‌کنیم.

guard بیرونی وابسته به یک byte حالت runtime است:

- حالت صفر: **EnterCriticalSection / LeaveCriticalSection**.
- حالت غیرصفر: انتظار روی handle با **WaitForSingleObject(INFINITE)** و آزادسازی با **ReleaseMutex**.

این ممیزی ثابت نمی‌کند نصب واقعی کاربر کدام حالت و کدام نام/هویت mutex را استفاده می‌کند. مسیر ساخت/اتصال نام mutex و binding آن به نصب هنوز استخراج و اعتبارسنجی نشده‌اند. بنابراین این یافته مجوز نوشتن هم‌زمان کنار Agent نیست.

در انتظار mutex، نتیجهٔ صفر موفق است؛ مقدار `0x80` (abandoned) diagnostic دارد و سپس true برمی‌گرداند. به معنی اثبات repair/recovery بعد از رهاشدن mutex نیست؛ timeout/failure در شاخه‌های بررسی‌شده false می‌دهند.

شواهد: `bulk-publish.asm`، `bulk-unlock.asm`، `outer-*.asm`، `srw-enter-leave.asm`، `critical-section-*.asm` و `mutex-release.asm`.

## ۴. نکتهٔ ظریف retry: rename موفق لزوماً helper موفق نیست

در helper `0x71f1f1`، خروجی sequence پیش از تلاش rename نوشته می‌شود (`0x71f284`). مقدار EDI ابتدا صفر است؛ پس از شکست rename، نتیجهٔ تبدیل خطا در EDI می‌نشیند (`0x71f305`). موفق‌شدن یک rename بعدی به بلوک `0x71f342` می‌رود که **همان EDI را برمی‌گرداند**؛ در این شاخه reset صریح به صفر دیده نمی‌شود.

بنابراین شاخهٔ موفقیت آخرین MoveFileExW به‌تنهایی برای نتیجهٔ کل helper کافی نیست. مقدار دقیق تبدیل خطا و قرارداد کامل این رفتار هنوز بازیابی نشده؛ آن را «باگ قطعی Agent» نمی‌نامیم. اما سیاست «هر rename موفق شد، header را تغییر بده» از این مسیر پشتیبانی نمی‌شود.

شواهد: `rename-return-accumulator.asm` و سه anchor accumulator، به‌همراه یال branch موفقیت rename در JSON ممیزی.

## مرز اثبات و شرط‌های لازم قبل از writer واقعی

| نیاز | وضعیت این checkpoint |
| --- | --- |
| محل و gate ثبت sequence در یک مسیر | به باینری ثابت و branchها متصل شد |
| مصرف sequence توسط reader | یک مسیر واقعی و modeهای skip مشخص شد |
| نوع قفل bucket و دو حالت guard | importها و dispatch مشخص شدند |
| انتخاب حالت/نام mutex برای نصب واقعی | اثبات نشده |
| layout کامل payload/extension و binding نصب/هدف | ناقص |
| transaction همهٔ bucketها / rollback سراسری | اثبات نشده؛ storeها در حلقه تدریجی‌اند |
| ترتیب `.build.info` و فعال‌شدن build کامل | استخراج نشده |
| هم‌زمانی واقعی Windows / قطع برق | آزمایش نشده |

نبود rollback/FlushViewOfFile در این قطعه به معنی نبودشان در کل Agent نیست. قفل‌ها به‌تنهایی تضمین دوام دیسک یا اتمیک‌بودن همهٔ build نمی‌دهند. مدل ساختگی journal/active.json قبلی همچنان مدل خودمان است، نه قرارداد Blizzard.

## بازتولید

از ریشهٔ `downloader/patch_audit_lab`:

```sh
python -B agent_publication_audit.py --agent /path/to/Agent.9824.exe
SYNTHETIC_NATIVE_DIR=/path/to/native-oracles python -B -m unittest discover -s tests -v
```

SHA256 باینری مجاز: `b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`؛ executable در این checkpoint منتشر نشده است. ابزار ممیزی فایل را فقط می‌خواند و JSON چاپ می‌کند؛ شبکه، patch کردن exe یا نوشتن نصب ندارد. این ماژول به helperهای موجود در شاخه وابسته است.

`DISASSEMBLY-MANIFEST.json` محدوده‌های دقیق و hash هر excerpt را دارد. receipt و `TEST-RESULTS.json` وضعیت واقعی این اجرا را ثبت می‌کنند. portable اصلی و Release assetها تغییر نکردند؛ companion منتشرشده همان snapshot ۲۷۸تایی است.

## ادامهٔ هدفمند

اکنون بازکردن دوبارهٔ مسیر عمومی flush یا زیادکردن بی‌هدف تست‌های ساختگی اولویت ندارد. دو شکاف بعدی: اتصال guard بیرونی به نام/binding نصب، و layout بخش payload/extension. پس از آن یک snapshot کوچک واقعی و کنترل‌شده برای تطبیق observer لازم خواهد شد؛ نه اسکن یا دانلود دوبارهٔ میلیون‌ها payload. هنوز از کاربر اجرای تازه‌ای درخواست نشده است.
