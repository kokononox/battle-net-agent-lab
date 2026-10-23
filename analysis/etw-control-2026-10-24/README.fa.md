# بررسی metadata ویندوز و آماده‌سازی کنترل ETW 0.1

## نتیجه
metadata ارسالی کاربر قابل خواندن است. هفت فایل در ریشه و هفت کپی بایت‌به‌بایت یکسان در زیرپوشه وجود داشت؛ فقط نسخه‌های ریشه خوانده شدند. پوشهٔ تکراری دلیل خرابی فایل یا نیاز به ارسال دوباره نیست. هیچ کدی از ورودی اجرا نشد.

بیلد ویندوز طبق خروجی قبلی کاربر 26200 و نسخهٔ گزارش‌شدهٔ WPR در این بسته 10.0.26100 CoreSystem است. اختلاف این شماره‌ها به‌تنهایی نشانهٔ نصب خراب یا لزوم ارتقا نیست. Network در فهرست پروفایل‌های داخلی موجود است، اما نام پروفایل به‌تنهایی اثبات ثبت stack فرستنده نیست.

## انتخاب از schema واقعی دستگاه
- Winsock-Sockets: ۱۶ event، taskهای SockCreate، SockClose، SockAccept، SockSetOpt، SockConnect، SockBind، SockGetOpt، SockListen. task به نام Send در این export وجود ندارد. این فقط دربارهٔ manifest صادرشده است، نه اثبات نبود هر event دینامیک ممکن.
- Winsock-AFD: ۹۶ event. event 1003 version 0، task AfdSend، opcode 12، level 4، keywords 0x8000000000000004 و متن شامل Process/Endpoint/Buffer Count/Buffer/Length/Seq/Status است. event 1000 به socket creation و 1018 به connect دارای Address مربوط است. event قدیمی 18 Send posted نیز در export هست؛ collector فعلی خانوادهٔ جدید دارای bit 0x4 را انتخاب می‌کند، نه اینکه شناسه‌های قدیمی را تنها گزینه فرض کند.
- TCPIP: ۷۵۳ event در export وجود دارد؛ برای کنترل اول این provider فعال نمی‌شود تا دامنه و حجم غیرضروری زیاد نشود.
- exportهای wevtutil قالب typed payload را ارائه نکرده‌اند. پیام‌های %1 و %2 schema نوع/چیدمان باینری نیستند؛ offset و نوع propertyها حدس زده نمی‌شود. هنگام تحلیل ETL باید metadata/TDH مربوط به خود event/version استفاده شود.

شمار eventها با XML parser و مستقلاً شمارش lexical تگ event کنترل شد. نمونه‌های مرتبط و hash ورودی‌ها در reports/metadata-evidence.json ثبت‌اند؛ فهرست فرایندهای سیستم کاربر از خروجی logman در مخزن منتشر نمی‌شود.

## بستهٔ آماده برای آزمایش، نه آزمایش موفق
package/Control.wprp درخواست Stack=true برای AFD keyword 0x4 و Sockets keyword 0x1 دارد. فقط collector رویدادی، memory mode و ۶۴ بافر ۶۴ KiB استفاده شده است. keywordها MatchAny هستند؛ فیلتر قطعی تک PID یا تک event ادعا نمی‌شود. رویدادهای پس‌زمینهٔ سیستم ممکن است ثبت شوند.

package/Run-Control.ps1:
- نیازمند Windows PowerShell x64 و دسترسی administrator برای WPR است؛ اگر بازی باز باشد متوقف می‌شود و آن را kill نمی‌کند.
- از WPR -profiles برای بررسی اولیهٔ profile روی خود دستگاه استفاده می‌کند. شکست این مرحله بدون شروع trace گزارش می‌شود.
- یک instance با GUID تصادفی می‌سازد؛ همهٔ دستورهای start/status/stop/cancel با همان instancename و در انتهای آرگومان‌ها هستند. sessionهای دیگر عمداً هدف قرار نمی‌گیرند.
- کنترل .NET را پیش از شروع ضبط compile می‌کند؛ با Socket روی 127.0.0.1 و پورت موقت سه بلوک ۶۴/۱۲۸/۲۵۶‌بایتی، جمع ۴۴۸ بایت می‌فرستد و دریافت را بایت‌به‌بایت بررسی می‌کند. ارسال جزئی مدل شده و تعداد واقعی callهای Send در JSON ثبت می‌شود؛ ۳ پیام برابر ۳ packet فرض نمی‌شود.
- زمان UTC، QPC و فرکانس، PID، دو endpoint و فهرست moduleهای native قبل/بعد را ذخیره می‌کند. آدرس‌های managed JIT با این فهرست خودکار به نام متد تبدیل نمی‌شوند؛ یک کنترل managed پشتیبانی stack برنامهٔ native بازی را تضمین نمی‌کند.
- ETL خام را نگه می‌دارد. وجود فایل، control_success و start_succeeded جایگزین بررسی extended stack نیستند؛ stack_presence_verified تا تحلیل واقعی false است.
- برای temp همان process و WPR مسیر RESULT را انتخاب می‌کند؛ hard cap کل فضای temp/ETL ادعا نمی‌شود. بافر درخواست‌شده حدود ۴ MiB است، نه سقف کل حافظهٔ ابزار. حداقل فضای بررسی‌شده ۲۵۶ MiB و gate ورود ETL به ZIP حداکثر ۶۴ MiB است. این gate حجم فایل در حال merge را محدود نمی‌کند.
- در خروج عادی try/finally همان session را متوقف می‌کند. terminate شدن اجباری پنجره یا hang WPR پوشش تضمین‌شده ندارد؛ recovery با نام دقیق instance داخل RESULT نوشته می‌شود. هیچ دستور cancel عمومی داده نشده است.
- هیچ اتصال اینترنت، دانلود، نصب، دسترسی حافظهٔ بازی، debugger، patch، تغییر رجیستری/ExecutionPolicy یا آپلود خودکار ندارد.

## اعتبارسنجی انجام‌شده و انجام‌نشده
روی این محیط Linux فقط XML well-formedness، ارجاع providerها، keywordهای منطبق با metadata و چند invariant متنی source کنترل شده است. این‌ها parser کامل PowerShell/C#، کامپایل کنترل، تأیید XSD/WPR یا اجرای Windows نیستند. بسته صریحاً برای آزمون روی سیستم هدف تحویل می‌شود، نه به عنوان collector دارای موفقیت تأییدشده. خروجی خطا همان‌قدر معتبر است که خروجی موفق؛ برای عبور از خطا تغییر تنظیمات امنیتی پیشنهاد نشده است.

## گام بعد از دریافت خروجی
ابتدا وجود و نسخهٔ event، انتساب process/endpoint و extended stack بررسی می‌شود. stack خالی، فقط worker/kernel یا unwind نامعتبر موفقیت در یافتن caller نیست. شمار lost events و محدودیت نگاشت moduleها نیز باید بررسی شود. تا این دروازه پاس نشود پایلوت بازی شروع نمی‌شود. این مرحله هیچ پیشرفت اثبات‌شده‌ای در رمزگشایی، handler V2 یا ارسال CPU/BIOS ادعا نمی‌کند.

## منابع عمومی برای نحو WPR
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options — Memory در برابر filemode نامحدود، recordtempto و instancename (آخرین پارامتر و ثابت در همهٔ دستورها).
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/eventprovider — درخواست Stack و keywordها.
- https://learn.microsoft.com/en-us/windows/win32/winsock/control-of-winsock-tracing — تفاوت PID/TID هدر با آغازگر و نگاشت Process/Endpoint.

commit قبلی طرح پژوهشی: 8ba28381a67a7b4f107f5a82d0daf4777c8d0c62. این تغییر فقط در شاخهٔ تحلیل است؛ main و BIOS Path GUI تغییر ندارند. ZIP خام ورودی، فهرست PIDهای کاربر و ETL در این commit قرار نمی‌گیرند.
