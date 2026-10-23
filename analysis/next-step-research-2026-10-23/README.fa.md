# انتخاب گام بعد: آزمون امکان‌پذیری انتساب ارسال شبکه به کد

## تصمیم
به جای تکرار اسکن رشته‌ها، نصب دیکامپایلر دیگر یا درخواست دامپ عمومی جدید، یک مسیر تشخیصی دوگانه انتخاب می‌شود: (۱) انتساب اتصال به پردازش و بیلد واقعی؛ (۲) آزمون امکان ثبت stack مفید در رویداد مناسب ارسال. ابزار پیشنهادی زیرساخت رسمی Windows ETW/WPR است، مشروط به تأیید provider/schema روی سیستم هدف. این یک پیشنهاد پژوهشی است؛ collector روی ویندوز ساخته یا اجرا نشده و ثبت stack بازی هنوز تأیید نشده است.

اولین اقدام اجرایی فقط پیش‌بررسی read-only سیستم هدف است، نه شروع trace. سپس برنامهٔ کنترل با کد معلوم باید درخواست stack و انتساب شبکه را اعتبارسنجی کند. موفقیت برنامهٔ کنترل، موفقیت روی بازی را تضمین نمی‌کند.

## شکاف شواهد موجود
- در capture قبلی framing V2 بازیابی شد، ولی PID/بیلد دقیق فرایندی که capture متعلق به آن است مستقل احراز نشد.
- رشته‌های BIOS، V2 و connect به زنجیرهٔ کدی اثبات‌شدهٔ جمع‌آوری→serialization→send نرسیدند. آخرین گزارش: commit b890b29c87413a0c6d8d21dab62ab1e14e50a740، analysis/connect-consumer-2026-10-23/README.fa.md.
- دامپ‌های کرش موجود پوشش کد هدف را ندارند؛ گرفتن «دامپ دیگری با همان روش» بدون تغییر اثبات‌شدهٔ پوشش، راه‌حل نیست.
- گزارش‌های ETW شخص ثالث در بستهٔ ANSWERS قبلاً بررسی شده‌اند، اما ETL خام و CSV خام آن مرحله همراه بسته نبود. این پیشنهاد، فرض گرفتن صحت آن گزارش‌ها یا تکرار استخراج رجیستری با نگاشت نامطمئن KeyObject نیست.

## یافته‌های منابع رسمی
### ۱. Winsock tracing شواهد endpoint و عملیات می‌دهد
مستندات Socket Creation، UserModePid و Endpoint را شرح می‌دهند؛ Connect مقصد و پورت را ثبت می‌کند. Send Posted شامل BufferLength، BufferCount و آدرس Buffer است. آدرس Buffer را نباید محتوای buffer نامید؛ در FastPath=false ممکن است آدرس کرنل باشد. فهرست قدیمی event IDها را نباید بدون schema محلی برای نسخهٔ هدف hardcode کرد.
منبع: https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-tracing-event-details

### ۲. درخواست stack رسمی است، اما خروجی مفید تضمین‌شده نیست
WPR EventProvider دارای Stack=true و فیلترهای stack/event است. API مربوط به EVENT_ENABLE_PROPERTY_STACK_TRACE، stack را به extended data رویدادهای EventWrite می‌افزاید. capture ممکن است ناقص یا رویداد به علت اندازه/محدودیت‌ها از دست برود. وجود گزینهٔ Stack به معنی پشتیبانی همان provider/event/version روی دستگاه هدف یا وجود frame فرستندهٔ اصلی نیست.
منابع:
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/eventprovider
- https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters

### ۳. PID و stack thread ثبت‌کننده ممکن است متعلق به آغازگر ارسال نباشند
Microsoft صریحاً هشدار می‌دهد بعضی رویدادهای TCP/IP از thread دیگری ثبت می‌شوند؛ PID/TID هدر همیشه آغازگر شبکه نیست. در schema مستند Winsock، Process در EventData آدرس EPROCESS است، نه PID. باید با Socket Creation و UserModePid، Endpoint و طول عمرشان تطبیق داده شود. برای خانوادهٔ kernel TCP/IP باید ProcessId فیلد payload مطابق schema استفاده شود. این دو schema نباید با هم قاطی شوند.
منابع:
- https://learn.microsoft.com/en-us/windows/win32/etw/tcpip
- https://learn.microsoft.com/en-us/windows/win32/winsock/control-of-winsock-tracing

### ۴. logman/tracerpt ابزارهای داخلی‌اند؛ دستور سادهٔ شروع trace کافی برای stack نیست
Microsoft استفاده از logman برای Winsock trace و tracerpt برای تبدیل ETL را مستند کرده است. دستور سادهٔ logman در آن راهنما درخواست stack مفید بازی را تضمین نمی‌کند. schema و کیفیت extended stack باید قبل از پایلوت بازی کنترل شوند. راهنمای قدیمی Winsock tracing دامنهٔ ثبت را سراسری توصیف می‌کند؛ حتی با فیلترهای جدید نباید وعده داد trace فقط شامل بازی خواهد بود.
منابع:
- https://learn.microsoft.com/en-us/windows/win32/winsock/control-of-winsock-tracing
- https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-tracing
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman-query

### ۵. PDB و Procmon جایگزین خودکار این شاهد نیستند
PDB باید دقیقاً با build تطبیق داشته باشد؛ symbol server مایکروسافت تضمینی برای PDB خصوصی Wow.exe نیست. برای استفادهٔ ابتدایی از آدرس‌ها، وجود نام تابع بازی شرط الزامی نیست، اما base/size/identity ماژول و معتبر بودن stack ضروری است. module+RVA فقط نشانی candidate می‌دهد؛ بایت‌های runtime، dataflow یا serialization را خودبه‌خود بازیابی نمی‌کند.

صفحهٔ Procmon قابلیت عمومی thread stack را شرح می‌دهد، اما از همان متن به‌تنهایی نمی‌توان نتیجه گرفت هر TCP Send دارای user-mode stack آغازگر است. بنابراین Procmon را بدون تست، راه‌حل قطعی caller بازی معرفی نمی‌کنیم. همچنین صفحهٔ فعلی Procmon برای client، Windows 11 و بالاتر ذکر می‌کند؛ قبل از هر نصب، نسخهٔ واقعی ویندوز باید مشخص شود.
منابع:
- https://learn.microsoft.com/en-us/visualstudio/debugger/specify-symbol-dot-pdb-and-source-files-in-the-visual-studio-debugger?view=visualstudio
- https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

## طرح اجرایی با دروازهٔ توقف
### گام صفر — پیش‌بررسی؛ هیچ trace فعال نمی‌شود
در PowerShell معمولی روی دستگاه هدف، فقط این اطلاعات پرسیده شود:
```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
Get-Command wpr.exe -ErrorAction SilentlyContinue | Select-Object Name, Source
logman query providers | Select-String 'Winsock|TCPIP'
```
نبود خروجی/Access denied را باید عیناً ثبت کرد، نه به نبود provider تعبیر کرد. این‌ها query هستند؛ هیچ دستور start، تغییر رجیستری، نصب، dump یا attach ندارند. خروجی مشخص می‌کند چه چیزی روی همان ویندوز واقعاً موجود است. مرحلهٔ بعد metadata دقیق providerهای پیدا‌شده را می‌خواند؛ GUID، event ID، level و keyword از روی حدس hardcode نمی‌شوند.

### گام یک — کنترل تشخیصی با کد معلوم
با برنامهٔ کوچک شبکه‌ای که رفتار و تعداد ارسال‌های آن معلوم است، trace محدود بگیریم. هدف، بررسی schema واقعی رویدادها، انتساب PID/endpoint و وجود extended stack است. برای برنامهٔ کنترل می‌توان نشان داد frameها به ماژول قابل‌انتظار نگاشت می‌شوند؛ صرف موجود بودن ETL یا چند event کافی نیست. نحوهٔ پایان و پاکسازی فقط session ایجادشدهٔ خود ابزار باید تضمین شود. ابزار موجود بازی نباید برای آزمایش اولیه دوباره وارد چرخهٔ crash شود.

### گام دو — تنها در صورت عبور کنترل، یک پایلوت کوتاه روی بازی
طرح پیشنهادی، نه تنظیم اجراشده: ثبت کوتاه ۲۰ تا ۳۰ ثانیه‌ای با سقف فایل برنامه‌ریزی‌شدهٔ ۶۴ MiB روی درایو انتخابی کاربر. Collector آینده باید سقف/زمان، لغو، stop همان session و فضای temp را واقعاً اعمال و گزارش کند؛ این گزارش به تنهایی تضمین اجرای سقف نیست. هیچ تغییر registry، protection یا تنظیم امنیتی پیشنهاد نشده است.

داده‌های لازم:
- فرایند، زمان ایجاد/عمر PID و هویت image با version/hash در صورت دسترسی؛
- شروع/پایان یا rundown ماژول‌ها با base و size برای همان process instance؛
- Socket Creation/Connect و نگاشت Endpoint معتبر؛ ترجیحاً از قبلِ ایجاد اتصال، چون شروع trace در میانه ممکن است نگاشت را از دست بدهد؛
- metadata ارسال و stack رویداد مناسب، در صورت واقعاً قابل‌جمع‌آوری بودن؛
- session stats، lost events و خطاهای decoder؛
- در صورت نیاز به تطبیق بسته‌ها، capture هم‌زمان از همین اجرای جدید؛ capture قدیمی را به اجرای امروز نسبت نمی‌دهیم. timestamp/QPC و timezone باید مشخص باشند.

فیلتر مقصد TCP/3724 فقط محدودهٔ بررسی است، نه اثبات V2 یا ارسال سخت‌افزار. کاربر نباید تصور کند ETW محتوای رمز‌شده را باز می‌کند. یک send ممکن است چند پیام را تجمیع یا بخشی از یک پیام را حمل کند؛ تطبیق یک رویداد با یک پیام بدون کنترل جریان معتبر نیست.

### معیارهای نتیجه
- اگر فقط PID و flow ثبت شد: موفقیت انتساب شبکه، نه پیشرفت در بازیابی تابع.
- اگر stack به ماژول/بازهٔ معلوم بازی نگاشت شد و context رویداد سازگار بود: candidate قابل‌بررسی برای مسیر شبکه، نه handler اثبات‌شدهٔ serialization.
- اگر فقط stack کرنلی/worker، خطای unwind، آدرس غیرقابل‌نگاشت یا فقدان رویداد مرتبط داشتیم: این مسیر برای هدف کدی متوقف شود. حجم trace را بی‌هدف زیاد نکنیم و تنظیمات سیستم را برای مجبور کردن stack تغییر ندهیم.
- lost events یا نبود Socket Creation مانع استنتاج منفی جامع است. هیچ «صفر رویداد»ی به تنهایی نبود ارسال را ثابت نمی‌کند.

## خروجی مورد انتظار این مرحله
یک پاسخ محدود به این سؤال: «آیا از APIهای تشخیصی استاندارد همین سیستم می‌توانیم یک ارسال متعلق به process instance بازی را به نشانی کد قابل‌بررسی متصل کنیم؟»

این مرحله کلید، plaintext، بایت کد محافظت‌شده یا شواهد ارسال CPU/BIOS را وعده نمی‌دهد. اگر پاسخ منفی باشد، شاهد بعدی باید واقعاً جدید باشد؛ از جمله اطلاعات debug منطبق و در دسترس یا diagnostic قانونی دارای پوشش کد مرتبط، نه نصب صرف ابزارهای بیشتر.
