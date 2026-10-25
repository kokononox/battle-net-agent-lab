# G25 — نصب تا خروج طبیعی Setup؛ چندفرایندی، نه چند اجرای کامل
Source: 27783c448ff21a953db6db45450ed1fcb09e2b56
Run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/40187272765

Setup در حدود ثانیه138 با کد0 پیش از پایان اجباری Job خارج شد. launcher و client در مسیر نصب موجودند؛ hash/PE و Authenticode کامل با امضاکنندهٔ پذیرفتهٔ Blizzard، زیر همان gate تأیید شد. رجیستری uninstall نام Battle.net و InstallLocation درست دارد. مسیر uninstaller داخل Program Files نبود؛ این آزمون فقط داخل همان ریشه را قبول می‌کرد و شاهدی برای نبود uninstaller واقعی نیست.

در این اجرا14 فرایند Job ثبت شد: Setup، دو Agent، یک conhost، یک فرایند اصلی client با no_type_switch، شش gpu_process، یک renderer و دو utility. بنابراین ده نمونهٔ Battle.net.exe ده restart کامل نیستند. پنج GPU child با کد0 خارج شدند و یکی باقی ماند؛ از این داده علت خروج GPU یا crash نتیجه نمی‌گیریم. parent/نقش‌ها best-effort و فقط تشخیصی‌اند؛ هیچ مجوز شبکه براساس command line داده نشده است.

فرایند اصلی از حدودثانیه138 تا180 زنده بود؛ فقط42139ms مشاهده شد. پس نبود حداقل۶۰ثانیه بقا، محدودیت پنجرهٔ آزمون است نه شاهد ناپایداری. پنجرهٔ client در سه نمونه147،153و159ثانیه marker login داشت، اما UIA truncated بود و کنترل password خوانده نشد؛ login form آماده تأیید نشده و حساب وارد نشده است. رخداد Application1000/1001 منطبق با نام‌های شناخته‌شده در بازه پیدا نشد؛ این عدم وجود همهٔ crashها را ثابت نمی‌کند.

گیت قبل/بعد و canary تأیید شدند. Job با صفر فرایند فعال بسته، proxy drain کامل و firewall/IIS بازیابی شد. تنها تغییر task همان reschedule محدود قبلی بود؛ هیچ استثنای بازیابی جدیدی افزوده نشد. هر دو job مشاهده و collect موفق و دو artifact ایجاد شدند. گزارش پایانی158935بایت با manifest/hash/source/run تطبیق دارد. پرچم‌های کامل نصب/پایداری همچنان false هستند؛ شرط uninstaller درون ریشه و پنجرهٔ کوتاه باید بدون بازکردن شبکه در آزمون بعدی دقیق‌تر شوند. Desktop0.9.10 ثابت است.
