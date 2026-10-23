# CodeRead 0.1.1 — سه صفحهٔ هدف PAGE_NOACCESS هستند

اصلاح MEM_MAPPED از مانع header عبور کرد: 4096 بایت header واقعاً خوانده شده و بررسی PE به مرحلهٔ صفحهٔ کد رسیده است. PID/creation time، مسیر/پایه/اندازهٔ ماژول و SHA256 دیسک با هدف پین‌شده تطبیق دارند.

در planned_region_census، هر سه صفحهٔ 0x1b11000، 0x1b14000 و 0x3306000، state=MEM_COMMIT، type=MEM_MAPPED، allocation base موردانتظار و protect=1 دارند. مقدار 1 یعنی PAGE_NOACCESS؛ بیت PAGE_GUARD (0x100) در این مقدار تنظیم نیست. پیام عمومی «guard or no-access» در این نمونه باید مشخصاً no-access تفسیر شود. این متفاوت از شرط نوع mapping در 0.1.0 است.

ابزار روی هیچ‌کدام از سه صفحهٔ هدف ReadProcessMemory اجرا نکرد و فایل .bin صادر نشد؛ فقط header قابل‌خواندن خوانده شد. در سه نمونهٔ metadata همان فرایند زنده و Responding بوده، ولی تأیید تازهٔ انسانی دربارهٔ قابل‌استفاده‌بودن بازی در این پیام نداریم.

این مشاهده فقط وضعیت لحظه‌های query را نشان می‌دهد. نه اثبات می‌کند این صفحات هرگز قابل‌خواندن نمی‌شوند، نه ثابت می‌کند چه مؤلفه‌ای protection را تنظیم کرده، نه دخالت anti-cheat یا علت شکست PSS قبلی را تشخیص می‌دهد. دربارهٔ اجراشدن/نشدن این توابع، population، serialization یا ارسال CPU/BIOS هنوز نتیجه نداریم.

قدم فعلی: توقف تکرار فوری همین خواندن زنده یا full dump قبلی. هیچ تغییر protection، injection، debugger attach، driver، افزایش debug privilege، bypass یا polling/retry خودکار اضافه نشده است. در این نقطه انتشار نسخهٔ تازه صرفاً برای حذف gate محافظت، راه‌حل این طرح نیست.

خط پیشنهادی بعدی، تحلیل آفلاینِ هدفمند همان build برای جداکردن تعریف schema از مقداردهی واقعی و زنجیرهٔ serialization/send است؛ نه بازکردن دوبارهٔ detour عمومی loader. این هنوز پیشنهاد مسیر بعدی است، نه پیشرفت انجام‌شده یا شاهد شبکه. main و GUI BIOS Path 0.2 تغییر نکرده‌اند. TCP/3724 CPU/BIOS sending همچنان unresolved است.
