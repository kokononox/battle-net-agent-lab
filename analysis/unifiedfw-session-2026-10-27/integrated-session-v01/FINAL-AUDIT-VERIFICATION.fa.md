# بازخوانی مستقل Audit در پایان بازیابی

## شکاف مشخص

وقتی دفتر Audit پیش‌تر archive شده و فقط policy journal باقی مانده بود، dispatcher قبلی برای بررسی نهایی maskهای واقعی، proof مستقلی از Audit نداشت؛ این بررسی فقط از pending audit اولیه گرفته می‌شد. guard رضایت خروج در callback بررسی داشت، اما dispatcher نباید به آن یا closed شدن دفتر به‌تنهایی تکیه کند.

شکاف دوم این بود که backend پیش از خواندن نهاییِ سیاست finish guard را اجرا می‌کرد، ولی پس از آن خواندنِ احتمالاً طولانی و پیش از نوشتن restored همان guard دوباره اجرا نمی‌شد. تغییر actor/audit/رضایت در طول آن خواندن می‌توانست از آخرین guard عبور کند.

## اصلاح در همان مسیر، بدون موتور جدید

- `RecoveryFirst.ps1` برای arm v02، actor و سه mask اصلی را از همان دفتر پایدار policy می‌گیرد، حتی اگر pending audit از ابتدا null باشد. از mask فعلی baseline تازه نمی‌سازد.
- اگر هر دو دفتر موجود باشند، head و session ID قبلی همچنان باید مطابق باشند؛ audit plan نیز صریحاً با plan ذخیره‌شدهٔ arm یکسان می‌خواهد. mismatch پیش از بازیابی/آرشیو Audit رد می‌شود.
- `Assert-UfwIntegratedAuditBaseline` قبل از callback سیاست و دوباره پیش از موفقیت نهایی dispatcher، maskهای واقعی را با مقادیر before می‌سنجد. int/uint32/long پذیرفته‌اند؛ رشتهٔ «0»، bool، float، null یا نوع نامعلوم حتی اگر قابل تبدیل به صفر باشد پذیرفته نیست.
- actor و نبود pending هم قبل و هم پس از خواندن maskها دوباره بررسی می‌شوند. تغییر حین query موفقیت تولید نمی‌کند. پس از archive در مسیر audit-only نیز همین کنترل strict اجرا می‌شود.
- `LocalPolicyBackend.ps1` در recovery باز و در `Finish` هماهنگ‌کننده، guard موجود را پس از آخرین snapshot سیاست و پیش از نوشتن restored دوباره اجرا می‌کند. بازخوانی مستقیمِ یک دفتر بسته نیز بعد از snapshot و پیش از return این guard را می‌خواهد. guardهای مستقل actor/audit/رضایت/process/service حذف یا با یک true جایگزین نشده‌اند.

schema دفتر تغییر نکرده؛ دسترسی شبکه، انتخاب مجدد EXE، اجرای برنامه، تغییر اضافهٔ Audit، Allow عمومی، reset سیاست یا stop سرویس اضافه نشده است. legacy arm v01 همچنان خواندنی است، ولی baseline اصلیِ مفقود آن حدس زده یا به اختیار جدیدِ بازیابی تبدیل نمی‌شود؛ محدودیت native Apply آن برداشته نشده است.

## آنچه آزمون واقعاً اثبات می‌کند

`tests/Test-FinalAudit.ps1` collector، journal، registry، dispatcher و reconciler فعلی را استفاده می‌کند. native Audit/policy/process/UI با fixture جایگزین شده‌اند؛ دادهٔ خصوصی کاربر ورودی آزمون یا خروجی عمومی نیست.

- بدون pending audit اولیه، مقدار نامطابق یا رشته‌ای قبل از callback مانع همهٔ inverseها می‌شود.
- تغییر mask/نوع/actor یا ظهور pending پس از callback سیاست، حتی با policy journal بسته، گزارش موفقیت نهایی نمی‌سازد. این آزمون callback بدون audit guard را عمداً استفاده می‌کند تا کنترلِ مستقل dispatcher سنجیده شود؛ این callback یک الگوی production نیست.
- تغییر actor/pending در طول خواندن maskها رد می‌شود.
- تغییر Audit در snapshot نهایی recovery یا Finish مانع نوشتن terminal جدید می‌شود؛ inverseهای دقیق ممکن است قبلاً انجام شده باشند، ولی این مرحله closed موفق اضافه نمی‌کند.
- بازخوانی مستقیم دفتر ازقبل‌بسته نیز چنین تغییری را موفق تلقی نمی‌کند.

نتایج aggregate در `evidence/final-audit-tests.json` و `evidence/QA-SUMMARY.json` هستند.

## محدودیت صریح

این کنترل‌ها خواندن‌های نقطه‌ای و متوالی user-space هستند، نه تراکنش اتمیک Windows یا منع تغییر بعدی. ممکن است پس از آخرین guard یا حتی پس از نوشتن terminal، سیستم دوباره تغییر کند. اگر dispatcher تغییرِ پس از terminal را ببیند، نتیجهٔ این فراخوانی ناموفق و pending گزارش می‌شود، **اما registry همچنان همهٔ دفترهای تاریخیِ بسته را خودکار برای drift بازپویش نمی‌کند**؛ صرف این نتیجه تضمین کشف خودکار آن دفتر در اجرای بعدی نیست. این گام نه تشخیص تاریخیِ علت Block شدن شبکه را اثبات می‌کند، نه آن محدودیت discovery را حل می‌کند.

پوشش مستقل helper/service/IPC، ورودی نهایی UI، عملکرد و qualification بومی Windows همچنان حل‌نشده‌اند. `ready_for_apply=false` باقی می‌ماند و آزمون/ZIP دستی تازه‌ای از کاربر درخواست نشده است.
