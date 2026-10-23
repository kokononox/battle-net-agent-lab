# اصلاح خطای خود ابزار در تشخیص وضعیت WPR — 0.1.3

## نتیجهٔ واقعی نسخهٔ 0.1.2
آرشیو برگشتی SHA-256 `4911a666cd5760a827a40289f8b8feee2733129181bbe5abcf1ef128ee2ce51e` شامل STATUS، فهرست profile و status قبلی است. هیچ case اجرا نشده، هیچ ETL وجود ندارد. خروجی WPR صریحاً `WPR is not recording` است، ولی برنامهٔ ما پیام فعال بودن ضبط قبلی را ساخته است.

این اشتباه کد ماست، نه شاهد ضبط فعال، خرابی ویندوز، دخالت بازی یا anti-cheat. عبارت `$prior -eq 0` روی کد خروج native نادرست بود: exit code صفر این دستور، معنی فعال بودن session ندارد. فرض قبلی دربارهٔ اینکه کد خاص منفی تنها حالت «inactive» خواهد بود نیز برای خروجی این دستگاه قابل اتکا نیست.

## اصلاح محدود
- `Get-InstanceState` هم متن status و هم کد را می‌خواند. دو عبارت صریح inactive به Inactive نگاشت می‌شوند؛ عبارت صریح recording-in-progress همراه موفقیت به Active. متن نامفهوم به Unknown، نه فعال یا غیرفعال، نگاشت می‌شود.
- gate مربوط به session قبلی فقط در Active یا Unknown متوقف می‌شود و پیام دقیق متناسب می‌دهد؛ Inactive واقعی مانع شش تست نمی‌شود.
- cleanup هر case نیز بر همین مبناست. در Active/Unknown تنها برای instance تصادفی خود آن تست cancel درخواست و سپس status مجدد خوانده می‌شود؛ اگر Inactive تأیید نشود ادامهٔ تست‌ها متوقف می‌شود.
- به status قبلی فقط query زده می‌شود؛ هیچ session پیشین/متعلق به دیگران خودکار متوقف نمی‌شود.
- شش profile، GUID/keyword/Strict، loopback C# و محدودیت‌ها نسبت به 0.1.2 تغییر نکردند. فایل profile و بخش C# بایت/متن متناظر مقایسه شده‌اند.

## تست رگرسیون واقعی تابع
PowerShell رسمی Linux از release رسمی PowerShell/PowerShell با کنترل hash منتشرشده آماده شد. نسخهٔ اجراشده 7.6.8 است. source/Test-Status.ps1 تابع واقعی را با AST از خود فایل کنترل استخراج می‌کند؛ فقط فراخوان native WPR mock می‌شود، نه منطق تابع.

هفت fixture پاس شدند:
- خروجی واقعی ارسالی کاربر با exit=0 → Inactive؛
- عبارت صریح inactive با exit غیرصفر → Inactive؛
- عبارت no trace profiles → Inactive؛
- متن صریح active با exit=0 → Active؛
- متن active همراه exit خطا → Unknown؛
- متن خالی با exit=0 → Unknown؛
- متن نامفهوم با exit=0 → Unknown.

همچنین کل Run-Control.ps1 با parser واقعی PowerShell بدون خطای AST parse و بخش واقعی C# compile شد؛ کنترل شبکه اجرا نشده و native WPR در تست محلی فراخوانی نشده است. این تست روی PowerShell 7 لینوکس است، نه Windows PowerShell 5.1؛ اجرای دستگاه هدف، UAC، start/stop provider و کیفیت stack همچنان تأیید نشده‌اند. localization ناشناختهٔ WPR نیز Unknown می‌شود، نه اینکه از روی exit code حدس زده شود.

Build Windows x64 GUI و Go vet موفق شدند. ساختار PE، embedded payload، بودجهٔ خط فرمان و عدم تغییر profile/C# کنترل شده‌اند. provider enable error اصلی `0xc558300c` هنوز تعیین علت یا رفع نشده؛ این انتشار فقط مانع تشخیصی نادرست خود ما را اصلاح می‌کند.

## تحویل و sync
نسخهٔ executable همراه راهنمای دوبارکلیک تحویل می‌شود. فقط source، fixture متنی کمینه و گزارش‌های بررسی در شاخهٔ تحلیل ثبت‌اند؛ raw ETL، module list کاربر یا باینری داخل متن مخزن قرار نمی‌گیرند. main و BIOS Path GUI تغییر نمی‌کنند. مبنای قبلی: commit d604ceaada52ece1ee7d942634e7019eb47c687d.
