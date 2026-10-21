# اصلاحیهٔ 0.1.3 — اختلاف نام فایل پایشگر بازتولید و رفع شد

## گزارش کاربر
endpoint-results-0acd6506ff0243eaaf309b8bad45c017.json نسخهٔ 0.1.2 دو setup_failed برای 3.124.215.108:443 و 3.75.62.211:443 دارد. هر دو connection_monitor.status=monitor_not_started و rule_absence_verified=true هستند؛ observation هر دو null است. baseline_restored برای اول yes و برای دوم null است. این دو مرحله نتیجهٔ آزمایش اتصال/ورود نیستند و روی طبقه‌بندی مقصدها اثری ندارند. تأیید رفتار عادی مرحلهٔ دوم ثبت نشده، هرچند حذف قانون گزارش شده است.

## نقص مشخص و بازتولید
در monitor.ps1 عبارت `[IO.Path]::ChangeExtension($jpath,$null)` برای تولید stem به کار رفته بود. با PowerShell رسمی 7.6.7 روی Linux، خروجی نام با نقطهٔ انتهایی بازتولید شد؛ افزودن `.monitor-ready` نام `session-id..monitor-ready` می‌سازد. Python انتظار `session-id.monitor-ready` دارد. همین اختلاف برای stop/result وجود داشت؛ بنابراین اجرای worker ممکن بود بدون دریافت آمادگی توسط کنترل‌کننده رخ دهد و marker توقف نیز دیده نشود. این نقص توضیح مشخصی برای نبود handshake است؛ شواهد اجرای واقعی Windowsِ کاربر هنوز جمع نشده‌اند.

## اصلاح و QA
stem اکنون با Combine(GetDirectoryName,GetFileNameWithoutExtension) تولید می‌شود؛ زمان انتظار صرفاً زیاد نشده و تنظیم امنیتی تغییر نکرده است. آزمون واقعی PowerShell/Python ساخت فایل آمادگیِ یک‌نقطه‌ای، دریافت stop و خواندن JSON نتیجه را گذراند. عبارت قدیمی جدا بازتولید شد و Parser واقعی هر دو PS script را بدون خطای نحو خواند.

۶۰ تست پاس شدند. runtime رسمی PowerShell فقط برای QA سازنده روی Linux دانلود و با digest اعلام‌شدهٔ release رسمی تطبیق داده شد؛ وارد بستهٔ Windows/Git نشده است. در آزمون handoff منابع مختص Windows (NetTCPConnection و Get-WinEvent) mock بودند؛ سازگاری واقعی Windows Firewall/WFP یا موفقیت دریافت داده در سیستم کاربر هنوز ادعا نمی‌شود.

## تحویل و شرط ادامه
Update بدون runtime روی همان پوشهٔ قبلی با حفظ runtime/private-state/output نصب شود؛ کنسول قبلی بسته و Restore.cmd نبود قوانین همان journalها را تأیید کند. رفتار عادی نیز جدا بررسی شود. پس از آن فقط اولین مقصد 3.124.215.108:443 با بستن/بازکردن عادی بازی و یک تلاش ورود بررسی و JSON جدید ارسال شود. نتیجه‌های ناموفق راه‌اندازی قبلی به نتیجهٔ نقش مقصد ارتقا داده نشوند. عدم مشاهدهٔ WFP یا TCP همچنان اثبات قطع/نبود تله‌متری نیست.
