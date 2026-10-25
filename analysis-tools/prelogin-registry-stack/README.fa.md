# a12: ردیابی مستقیم فراخوان‌های UserUUID

این مسیر روی Windows آمادهٔ GitHub است؛ هیچ مهمان QEMU، reboot، حساب Battle.net، کلیک Install یا دانلود بازی ندارد. شاخهٔ تحقیق و attempt اول با guard اختصاصی لازم است.

## تغییر نسبت به a11

caller_rva همچنان فقط returnAddress مستقیم داخل mainModule است. اگر API از wrapper/forwarder فراخوانی شود ممکن است null باشد. فیلد مستقل main_module_stack_rvas حداکثر 16 frame از Backtracer.ACCURATE را بررسی و فقط RVAهای یکتای داخل محدودهٔ mainModule همان فرایندِ pinشده را نگه می‌دارد. سایر ماژول‌ها، نام/مسیر آن‌ها و آدرس‌های مطلق صادر نمی‌شوند. stack_status=captured با آرایهٔ خالی یعنی هیچ frame واجد شرایط دیده نشد، نه اینکه فراخوانی وجود نداشت. failed هرگز با backtrace حدسی جایگزین نمی‌شود.

فقط key/name ثابت a11 بررسی می‌شود. UUID/هش آن صادر نمی‌شود؛ بایت‌ها صرفاً در RAM با host_id همان اجرا مقایسه می‌شوند. observer رجیستری هدف را تغییر نمی‌دهد و TLS validation عوض نمی‌شود. callbackهای تو در تو dedup نشده‌اند و شمار آن‌ها را تعداد مستقل عملیات نمی‌نامیم.

## گیت بومی

یک fixture C++ بدون شبکه با MSVC برای x64/x86 کامپایل می‌شود؛ /Od و /Oy- برای کنترل frameها. تصویر fixture و هویت فرایند کنترل می‌شود؛ پس از instrument-before-resume، خواندن/نوشتن W و A، RegGetValueW و منفی size-only آزمایش می‌شوند. frame mainModule در read/write و capture دقیق باید در هر دو معماری موفق باشد؛ وگرنه هدف اجرا نمی‌شود. fixture فقط کلید مخصوص پروژه با UUID مصنوعی را می‌سازد و پاک می‌کند، نه کلید Blizzard. PDB، exe و فایل‌های کامپایل موقت‌اند و artifact عمومی نیستند.

36 آزمون Python و 50 کنترل اجرای واقعی hook با حافظهٔ mock برای x86/x64، از جمله direct-return خارجی با frame داخلی، empty stack و failure پاس شده‌اند. این‌ها جای گیت بومی یا رفتار هدف نیستند.

## نتیجه و ادعا

matching_agent_read_stack_observed فقط وقتی true است که در هر دو startup، خواندن موفق Agent دارای SHA pin، مقدار برابر با پیام wire-linked همان مرحله و stack دقیقِ دارای frame mainModule داشته باشد. این پرچم فقط حضور frame است؛ assignment provider یا جریان دادهٔ کامل را ثابت نمی‌کند. provider_assignment_causality_proven=false، reboot_tested=false و global_install_uniqueness_proven=false اجباری‌اند.

گزارش محدود: reports/prelogin-registry-stack-runtime.json. شواهد a11 حفظ می‌شوند. status=observation_complete یعنی مشاهده و کانال‌های پیشین clean بوده‌اند، نه اینکه لزوماً stack موفق یا causality اثبات شده باشد؛ پرچم‌های نتیجه جدا خوانده شوند.
