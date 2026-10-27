# اتصال candidate ثابت، بازیابی audit-first و شواهد خروج

این گام ادامهٔ همان coordinator، runtime collector و ژورنال قبلی است؛ ابزار تشخیصی یا ZIP جدیدی ندارد. انتخاب فایل، مجوز مقصدهای زمان اجرا نیست و **هیچ grant، اجرای خودکار یا ادعای نصب کامل اضافه نشده است**.

## اتصال رصد به همان انتخاب

`RuntimeSession.ps1` adapterهای بومی قبلی را در `New-UfwWindowsRuntimeOps` به‌شکل callbackهای module خصوصی در دسترس جریان یکپارچه می‌گذارد؛ workflow رصد دوباره نوشته نشده است. caller باید dependencyهای pinشدهٔ candidate، reader و runtime را در همان module بار کند؛ UI نیز به STA/WinForms و الزامات Windows قبلی نیاز دارد. این factory به‌تنهایی launcher یا مجوز اجرای زنده نیست.

`New-UfwBoundRuntimeContext` رکورد انتخاب‌شدهٔ محافظت‌شده را دوباره می‌خواند و head، actor و digest برنامه‌ها را با انتخاب بازبینی‌شدهٔ live تطبیق می‌دهد. capture فقط همان مسیر را از Load می‌پذیرد؛ picker قبلی دوباره نمایش داده نمی‌شود. هر بار Load، همان head و هویت برنامه‌ها را لازم دارد؛ تغییر candidate، تعویض فایل، actor متفاوت یا انتخاب مسیر دیگر پذیرفته نمی‌شود. رضایت قبلی ذخیرهٔ candidate اختیار تغییر سیاست نیست؛ رضایت موقت live و رضایت audit موجود جداگانه باقی می‌مانند.

`Invoke-UfwBoundRuntimeCapture` فقط یک بار برای هر context اجرا می‌شود. lease/SSTP و guard سیاست به `RuntimeBridge` اضافه می‌شوند؛ guard فایروال قبلی، preflight، audit backup/restore، self-test محدود قبلی، window اجرای **دستی** و ذخیرهٔ پیشنهاد خصوصی همان collector باقی‌اند. diagnostic child مربوط به self-test قبلی است، نه فایل انتخاب‌شده؛ فایل انتخاب‌شده هیچ‌گاه توسط ابزار launch/kill نمی‌شود. ReadEvents برای شواهد خروج، یک کپی خصوصی در حافظه نگه می‌دارد؛ دادهٔ خام آن در گزارش یا مخزن منتشر نمی‌شود.

wrapper پیش از فراخوانی Window، امکان بازشدن پنجره/اجرای دستی را ثبت می‌کند؛ exception بعد از اثر UI به «برنامه اصلاً اجرا نشده» تبدیل نمی‌شود. capture لغوشده/ناقص، audit نامطمئن، خطای رخداد یا فایل خودتغییردهنده مدرک پایان امن نیست.

## بازیابی پیش از انتخاب فایل و مشاهدهٔ VPN

`RecoveryFirst.ps1` adapterهای Lock/Pending/Recover/Unlock همان coordinator را فراهم می‌کند. scanner خصوصی policy و pending audit هر دو قبل از gateهای نشست جدید و Inspect دیده می‌شوند. برای audit-only، policy-only یا هر دو، coordinator در حالت **recovery-only** می‌ماند؛ پس از موفقیت همان اجرا، نشست یا capture جدید شروع نمی‌شود.

ترتیب الزامی چنین است:

1. journal audit معتبر، actor فعلی و head مورد انتظار بررسی می‌شوند؛ سپس رضایت محلیِ recovery قبلی گرفته می‌شود.
2. پس از prompt، journal و actor دوباره خوانده می‌شوند. همان `Restore-UfwRuntimeAuditPlan` قبلی، بدون broad reset، بیت‌های ذخیره‌شده را بازمی‌گرداند.
3. archive و نبود pending دوباره بررسی، actor و مقدار واقعی هر بیت پس از archive بازخوانی می‌شوند. cancel، drift، تعویض journal یا archive نامطمئن اجازهٔ بازیابی policy نمی‌دهد.
4. فقط سپس callback بازیابی policy با handle دقیقِ reopenشده اجرا می‌شود. آن callback باید actor/audit/quiescence/exit-consent مستقل و همان backend reconciliation را bind کند. terminal journal هم با همان parser دوباره تأیید می‌شود؛ true فرضیِ callback بدون بسته‌شدن معتبر کافی نیست. پس از callback سیاست نیز actor و مقدار واقعی بیت‌های audit با یک کپی مستقلِ baseline پیشین دوباره بررسی می‌شوند؛ نبود pending به‌تنهایی موفقیت نیست.

این dispatcher به SSTP، DNS، فایل EXE یا picker نیاز ندارد. بااین‌حال callback واقعیِ ایمن policy پس از crash هنوز نهایی نشده است؛ dispatcher جای آن را با true پر نمی‌کند. رقابت یا تغییر بعدی audit باید در guard مستقل policy نیز بررسی شود؛ هیچ snapshot یا check کاربرمحور اتمیک نیست. ابزارهای قدیمی مستقل از این global lock ممکن است هم‌زمان دخالت کنند؛ ادعای قفل فراگیر Windows نداریم.

## مرز مهم: رخداد خروج، اختیار بازکردن Allow نیست

`Get-UfwCapturedLifecycleStatus` شواهد 4688/4689 را محافظه‌کارانه دنبال می‌کند: root انتخاب‌شده و فرزند از parent/path شناخته‌شده، فرزندی که بعد از parent زنده مانده، PID reuse نامطمئن، parent یا خروج نامطابق، ترتیب رکورد، parse/integrity warning و نبود root بررسی می‌شوند. شمارش شروع با reducer موجود نیز باید سازگار باشد. همهٔ exitهای دیده‌شده فقط `observed_all_exits` می‌دهند؛ **`quiescence_authorized` همیشه false است**.

`Test-UfwBoundRuntimeQuiescence` بدون probe مستقل، با پاسخ غیربولی، یا با lifecycle نامطمئن false می‌دهد. خوانندهٔ قدیمی `Get-UfwObserverProcesses` خطاهای دسترسی را نادیده می‌گیرد؛ خروجی خالی آن **نباید** برای اثبات پایان برنامه/فرزندان استفاده شود. هیچ probe بومیِ کامل یا اثبات recovery پس از restart در این گام جعل نشده است. بنابراین در جریان زندهٔ هنوز منتشرنشده، نبود این binding باید بازگردانی Allowهای قبلی را pending نگه دارد.

شواهد این context در حافظه است و پس از crash در دسترس نیست. journal سیاست فعلی نیز به‌تنهایی سابقهٔ فرایندها یا انتساب سرویس/IPC را اثبات نمی‌کند؛ recovery بومی به شاهد خصوصیِ پایدار و بررسی مستقل نیاز دارد. این موضوع مانع واقعی باقی‌مانده است، نه تستِ موفق‌فرض‌شده. سرویس/فرزند خودکار مجاز نمی‌شود و sandbox علیه مدیر/IPC یا تضمین no-leak/fingerprint نداریم.

## بررسی انجام‌شده و آنچه هنوز باقی است

suite جدید، collector واقعی با candidate ثابت و مسیر recovery-only همان coordinator را اجرا می‌کند؛ policy recovery از همان backend و journal فایل واقعی استفاده می‌کند. providers اثر Windows و guardهای مستقل در fixture هستند. suite mixed قبلی نیز اکنون از wrapper candidate ثابت عبور می‌کند؛ source collector قبلی و هش dependencyها تغییر نکرده‌اند. نتیجهٔ نهایی و شمارش در `evidence/QA-SUMMARY.json` و `evidence/runtime-recovery-binding-tests.json` است؛ هیچ Windows API فایروال/audit/RAS واقعی اجرا نشده است.

کار باقی: binding بومیِ actor و شاهد پایدار target/helper برای recovery پس از crash، probe کامل quiescence با شکستِ دسترسیِ مسدودکننده، رضایت خروج و ورودی/UI نهایی؛ همچنین performance برای ۱۰۶ Allow با reader کامل و lease محدود. سپس یک اعتبارسنجی هدفمند Windows برای جریان واحد. همچنان **ready_for_apply=false** و کاربر فعلاً فایل، snapshot یا آزمون دستی جدیدی نمی‌فرستد.
