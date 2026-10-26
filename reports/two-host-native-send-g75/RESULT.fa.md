# G75 — کنترل پیش از send واقعی در ویندوز، فقط fixture محلی

## نتیجهٔ عملی
adapter محدود synchronous Winsock `send` روی برنامهٔ C# بومی‌فراخوان در هر دو معماری x86 و x64 آزمایش شد. تصمیم **قبل از صداکردن تابع اصلی** انجام شد، نه در onLeave پس از ارسال. ۲۴ حالت در هر معماری، مجموعاً **۴۸ کنترل**، در مشاهدهٔ نهایی گذشتند و تک‌تک ردیف‌های شواهد بازبینی شدند.

در **۳۸ حالت کاملاً ردشده**، تابع اصلی send صفر بار صدا زده شد و گیرندهٔ فیزیکی loopback صفر payload دریافت کرد. در ۱۰ حالت دیگر، شامل درخواست‌های عمومی، کنترل mutation و حالت ترکیبی درخواست مجاز/دنبالهٔ خصوصی، فقط bytes عمومی دقیقِ مورد انتظار رسید. تعداد invocation واقعی تابع اصلی مجموعاً ۱۰ بود؛ هیچ sentinel خصوصی به گیرنده نرسید. این‌ها موارد مصنوعی کنترل‌شده‌اند، نه آمار Battle.net.

## اتصال تصمیم به ارسال
Frida تابع send را در همان برنامهٔ مالک جایگزین می‌کند. peer باید دقیقاً IPv4 loopback و port اختصاصی گیرنده باشد؛ flags غیرصفر، اندازهٔ ناپشتیبانی‌شده، socket استفاده‌شده و ورودی ناقص رد می‌شوند. هر socket فقط یک تلاش قابل بررسی دارد. WSASend در fixture بدون فراخوانی تابع اصلی رد می‌شود؛ بررسی همان API مجاور، اثبات پوشش همهٔ راه‌های خروجی نیست.

درخواست bounded در RAM snapshot می‌شود. controller همان policy عمومی پین‌شدهٔ G74 را اجرا می‌کند و علاوه بر قبولی policy، **برابری byte-for-byte با درخواست canonical** را الزامی می‌داند. بنابراین ورودی benign ولی غیرcanonical هم رد می‌شود؛ در این adapter بازنویسی انجام نمی‌شود و success count جعلی به برنامه داده نمی‌شود.

در صورت اجازه، original send از **کپی خصوصی همان snapshot** فراخوانی می‌شود، نه pointer قابل تغییرِ برنامه. مقدار بازگشتی و last error واقعی حفظ می‌شود. رد native برابر SOCKET_ERROR/WSAEACCES است. exception پس از تلاش original، به‌عنوان original_called=true/unknown ثبت می‌شود، نه اینکه به‌اشتباه رد پیش از ارسال گزارش شود.

خروجی‌های مثبت، هم return code برنامهٔ کنترل و هم receipt فیزیکی دقیق را الزام می‌کنند. برنامه تازه spawn، در Job با kill-on-close قرار داده، image/path/hash آن guard و معماری runtime نیز تأیید می‌شود. به هیچ فرایند نصب‌کننده‌ای attach نشده است.

## کنترل‌های کلیدی
- CDN عمومی، Range کامل عمومی و metadata عمومی عیناً به گیرنده رسیدند.
- identifier مصنوعی در query، UA، cookie، authorization، body و header ناشناخته، Range یک‌بایت کوتاه، Host نامعتبر/تکراری، framing ناسازگار، پیام ناقص/چندتایی و TLS opaque، بدون صداکردن original رد شدند.
- دو send واقعی از قطعات یک header هر دو رد شدند؛ adapter برای سازگاری، قطعات را زودتر به شبکه نفرستاد. این اثبات پشتیبانی از fragmentation نیست؛ fragmentation فعلاً مسدود است.
- تلاش WSASend، peer/port ناسازگار، flags ناپشتیبانی‌شده و پاسخ controller با string به‌جای boolean true رد شدند.
- در هر معماری، پس از send مجاز، send دومِ حاوی payload خصوصی رد شد؛ فقط درخواست اول به گیرنده رسید. این دو مورد **ترکیبی** هستند و جزو ۳۸ حالت صفر-payload شمرده نشده‌اند.
- در کنترل mutation، thread دیگر برنامه پس از snapshot و پیش از اجازهٔ controller، buffer اصلی unmanaged را واقعاً تغییر داد. marker تکمیل mutation، exit code native و receipt برابر snapshot عمومی، هر سه تأیید شدند. این کنترل در هر دو معماری گذشت؛ در برابر مهاجم دارای اختیار تغییر خود agent/controller، مقاومت اثبات نمی‌کند.

مجموع native resultها ۵۲ بود؛ دو مورد split و دو مورد tail هر کدام دو فراخوانی داشتند. کلید ردیف‌ها `(architecture, case)` است؛ نام‌های تکراری case بین معماری‌ها نگه داشته شدند. ۴۸ ردیف کامل، بدون duplicate دارند. null در ستون mutation یا snapshot-copy برای حالت نامرتبط است، نه missing evidence. ثابت بودن pass/identity یا نبود sentinel مصنوعی، نبود شناسه‌های ناشناخته را ثابت نمی‌کند.

## صفر payload، نه صفر اتصال
**connect قبلاً انجام شده بود:** getpeername نیازمند socket متصل است. در تمام ۴۸ حالت، یک اتصال TCP به گیرندهٔ محلی ثبت شد. ادعای این مرحله برای موارد ردشده، صفر payload است، نه صفر اتصال. نتیجهٔ G74 دربارهٔ صفر اتصال مربوط به relay پیش از connect همان harness بود و به این لایه تعمیم داده نمی‌شود. این fixture هیچ endpoint اینترنتی را برای target مصرف نکرد.

## اجراها و انتشار شواهد
1. [اجرای اولیه 40314502416](https://github.com/kokononox/battle-net-agent-lab/actions/runs/40314502416)، source `2722b33f3e38e73d59e9cca804a9e7cb01e45aa7`، موفق شد. annotation شامل passed=true بود ولی GitHub متن آن را در 4096 کاراکتر برید؛ فقط ۶ ردیف نخست کامل قابل بازیابی بود. این شکست کنترل native نبود؛ محدودیت انتشار شواهد بود.
2. فقط انتشار اصلاح شد: summary و سه chunk compact، هر پیام حداکثر 3400 بایت، با run/source و SHA256 مجموعهٔ ردیف‌های canonical-redacted. gate JS، fixture C# و admission Python بین دو source عیناً یکسان ماندند؛ bytes نسخهٔ اول با نسخهٔ بعدی مقایسه شدند. کنترل‌ها عمداً ضعیف نشدند.
3. [اجرای نهایی 40314863305](https://github.com/kokononox/battle-net-agent-lab/actions/runs/40314863305)، source `6db91a46fa8eceaf80a2cbed3e6f7cf329981101`، attempt 1، job `121544805423`، موفق شد. summary و هر سه chunk از API عمومی Checks خوانده، identity/index/count و digest کنترل و **تمام ۴۸ ردیف** بازسازی و بازبینی شدند. درخواست ورود دوباره لازم نشد.

این مرحله دو اجرای workflow کنترل native داشت، اما **صفر اجرای Battle.net**. مجموعهٔ محلی دقیق Git blobها ۱۸۲ تست discovery داشت، با یک skip مختص ویندوز؛ ۱۱ تست جدید شامل admission دقیق و انتشار bounded اضافه شد. مرحلهٔ unittest ویندوز نیز طبق API موفق بود؛ تعداد چاپ‌شده در log ویندوز مستقلاً خوانده نشده است.

Artifact نهایی `12645923213` است. digest اعلام‌شدهٔ API:

`sha256:e2a452bf8c39d1da63f0b1cbbc9b9e9ac9dbe0a619a29cddccf196ef1acbeb99`

ZIP دانلود نشد و hash آن محلی بازبررسی نشده است. فایل `native-report-reconstructed.json` از **annotationهای کامل** بازسازی شده، نه اینکه به‌عنوان bytes دانلودشدهٔ artifact معرفی شود. digest canonical ردیف‌ها، برخلاف digest ZIP، واقعاً با دادهٔ بازسازی‌شده بررسی شد. هیچ raw request/path/header/شناسهٔ واقعی در این انتشار نیست؛ فقط شواهد fixture مصنوعی و byte count/verdict منتشر شدند.

## محدودیت‌های لازم قبل از اتصال به Battle.net
**این هنوز فیلتر قابل استفادهٔ نصب‌کننده نیست.** تنها برنامهٔ مالک آزمایشی با APIهای کنترل‌شده بررسی شده است. TLS/SSPI plaintext binding، async I/O، partial-write recovery، fragmentation سازگار، پاسخ سرور، فرآیندهای دیگر، sendto/kernel I/O و همهٔ مسیرهای بدون injection پوشش داده نشده‌اند. snapshot عمومی ثابت است و policy فعلی برخی درخواست‌های سالم واقعی را عمداً رد خواهد کرد.

پاسخ malformed controller بررسی شد، اما شکست واقعی controller، detach/unload اجباری hook و تمام شرایط lifecycle هنوز کنترل نشده‌اند. Job/timeout محافظ آزمایش است؛ نباید بدون آزمون جداگانه ادعای fail-closed بودن سراسری در خرابی injection کرد. انتخاب مسیرهای عمومی، timing، ترتیب و تعداد نیز می‌تواند کانال اطلاعاتی باقی بماند.

مقصد runtime تازه، allow rule جدید، تغییر firewall/certificate، دانلود کامل، login یا Install click وجود نداشت. main و Unified Firewall Desktop 0.9.10 تغییر نکردند؛ استثنای قبلی مدیریت CI دست‌نخورده است. نصب dependency پین‌شدهٔ Frida و checkout/upload خود CI، ترافیک نصب‌کننده نیست.

هدف همچنان دانلود مجاز بدون ارسال fingerprint است. گام بعدیِ ایمن، اثبات رفتار بسته در lifecycle/خرابی مسیر کنترل و بستن bypassهای لازم است؛ سپس اتصال به مسیرهای واقعی مورد نیاز دانلود، نه اعلام آماده‌بودن ابزار یا بازکردن مقصدها بر اساس این کنترل‌های محدود.

## شواهد و بازتولید
Source در `analysis-tools/two-host-native-send-g75` و workflow در `.github/workflows/battlenet-native-send-g75.yml` قرار دارد. compose پایه‌های G69 تا G74 را با Git-blob pin می‌خواند. `native_send_control.py` فقط روی GitHub-hosted Windows اجرا می‌شود؛ ورودی‌های temp شامل مقادیر عمومی/مصنوعی‌اند و پاک می‌شوند.

`run-api.json`، `jobs-api.json`، `annotations-api.json` و `artifacts-api.json` ورودی‌های اصلی عمومی اجرای نهایی‌اند؛ فایل‌های `initial-*` اجرای اول را جدا نگه می‌دارند. `manifest.json` حدود ادعا را ثبت می‌کند. `analyze.py` با `--run`، `--jobs`، `--annotations`، `--artifacts`، `--source-dir` و `--out` بازسازی، digest، هویت و hierarchy شمارش را کنترل می‌کند؛ source-dir باید materialized runtime همین مرحله باشد. بازسازی ناقص یا تغییرکرده fail می‌شود. profiler فقط ردیف‌های normalized را بررسی کرده است؛ هیچ deduplication روی نتایج اعمال نشده.
