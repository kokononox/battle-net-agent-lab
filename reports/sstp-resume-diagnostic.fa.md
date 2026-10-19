# تشخیص خطای دستگاه کاربر پس از Prepare فقط

کاربر فقط Prepare disabled را زده و سپس بستهٔ Resume را اجرا کرده است؛ Enable اجرا نشده است. startup-error.json ارسالی گزارش می‌کند resume_v6_create_failed در Windows PowerShell5.1 x64 STA، CimException/HRESULT=-2146233088/StatusCode=1/NativeErrorCode=1. علت دقیق از این کدهای عمومی قابل تعیین نیست؛ نمایش CIDR نیز روی دستگاه موفق نشده و به‌عنوان رفع قطعی معرفی نمی‌شود.

تغییر: فقط helper حذف اطلاعات خصوصی از Exception.Message و افزودن آن به native_codes در catch ایجاد v6. تمام منطق ساخت/lock/journal/تطبیق/توقف/عدم‌تصاحب بدون تغییر است؛ حذف helper و خطوط گزارش افزوده، فایل Resume.ps1 پایه را byte-for-byte در متن بازسازی می‌کند. سایر ۹ فایل runtime بسته از بستهٔ پایه بدون تغییر کپی شده‌اند. فایل CMD از Resume-Prepare پایه کپی و فقط نام فایل توزیعی Diagnose-Prepare.cmd است؛ همان Launcher -Action Resume و تأیید دستی.

این دستور خواندنی صرف نیست؛ یک تلاش محدود برای ساخت قاعدهٔ غیرفعال، با شرط‌های قبلی، تکرار می‌کند. Enable/reset/Allow/delete/adoption ندارد. اگر v6 موجود و ثبت‌نشده باشد، بدون دست‌کاری متوقف می‌شود. در موفقیت همهٔ قواعد همچنان غیرفعال‌اند. هیچ ادعای موفقیت دستگاه کاربر یا نبود نشتی مطرح نیست.

آزمون تشخیصی de589ee اولیهٔ helper14 با بازبینی قبل از انتشار کنار گذاشته شد؛ Sort-Unique بر اساس Length به حذف یکی از مقادیر خصوصی هم‌طول منجر می‌شد. پیش از ساخت بسته، unique روی خود رشته و سپس sort بر اساس طول اصلاح و تست هم‌طول اضافه شد.

نسخهٔ نهایی source1b74ca031f4c267d487a6cdf8f39bb40b1fa7ddd/run39323089693 موفق: parse و۱۵ بررسی pure روی WindowsPS5.1 بدون عملیات فایروال. native resume و UAC تعاملی برای این تغییر catch در CI تکرار نشده‌اند؛ موتور پایه قبلاً run39318914571 را با recovery46/native40 گذرانده ولی روی دستگاه کاربر ساخت IPv6 شکست خورده است. این دو واقعیت مستقل نگه داشته شده‌اند.

رسید ZIP c4a1cd17e198a71bff4ab5566f4726cee5b6463afea60e5401c8968dda17aa1a با digest مرورگر و هر۳ فایل payload تطبیق داده شد. بستهٔ۱۵فایلی با manifest و هش‌های محتوا بازخوانی شد. متن پیام محدود به۲۰۰۰کاراکتر+نشان truncation، حذف IP/دامنه/URL/path/GUID و مقادیر خصوصی شناخته‌شده است؛ قبل از ارسال کاربر نیز باید فایل را بررسی کند، زیرا sanitization الگو‌محور تضمین بی‌نقص نیست.

اقدام کاربر: استخراج کامل پوشهٔ جدید، فقط Diagnose-Prepare.cmd و تأیید آن، ارسال startup-error.json تازه یا resume-result.json در موفقیت. Prepare/Enable مجدد یا حذف journal درخواست نشده است.

https://github.com/kokononox/battle-net-agent-lab/actions/runs/39323089693
