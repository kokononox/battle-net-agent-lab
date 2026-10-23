# نتیجهٔ کنترل اول و نسخهٔ تشخیصی جداگانهٔ ETW 0.1.2

## شاهد واقعی از اجرای کاربر
آرشیو READY-TO-SEND با SHA-256 `6476fea203d46df7c5e6f93ea15fd70700692b82a71922357229a8d1e1b87925` بررسی شد. فایل‌ها فقط داده خوانده شدند؛ هیچ کدی از آن اجرا نشد.

- WPR روی دستگاه فایل profile را فهرست کرده و جریان اسکریپت تا قبل از start پیش رفته است.
- start.txt خطای `0xc558300c` و `The event provider was not enabled` دارد.
- STATUS.json: start_succeeded=false، control_success=false، trace_saved=false، game_accessed=false.
- control.json و هیچ ETL در آرشیو نیستند؛ کنترل loopback به مرحلهٔ اجرا نرسیده است.
- این نتیجه دربارهٔ فعال‌سازی profile ماست، نه شکست یا موفقیت stack بازی، رمزنگاری، حفاظت، جمع‌آوری سخت‌افزار یا ارسال شبکهٔ بازی.

بررسی مستقل در source/analyze_return.py هم flags و هم متن خطا و اعضای آرشیو را کنترل می‌کند. modules-before.json و مسیرهای دستگاه کاربر وارد مخزن نمی‌شوند.

## اشکال تشخیصی نسخهٔ قبلی
دو provider هم‌زمان و هر دو با Stack=true و Strict=true فعال می‌شدند؛ بنابراین یک خطای عمومی، provider ناموفق را مشخص نمی‌کند. این نسخه علت خطا را از پیش اعلام یا رفع‌شده فرض نمی‌کند. Strict=false نیز راه‌حل نیست: ممکن است ضبط ظاهراً موفق ولی فاقد provider لازم بسازد. Strict در همهٔ تست‌ها true می‌ماند.

## تغییر نسخهٔ 0.1.2
شش profile جدا با یک provider در هر بار:
1. AFD / paged / بدون stack
2. AFD / paged / درخواست stack
3. AFD / nonpaged / بدون stack
4. AFD / nonpaged / درخواست stack
5. Sockets / paged / بدون stack
6. Sockets / paged / درخواست stack

AFD با bit 0x4 و Sockets با bit 0x1، level 5، بر مبنای metadata خود کاربر. مقایسهٔ AFD در دو نوع بافر، آزمون یک فرضیهٔ مستند است: بعضی providerها به nonpaged memory نیاز دارند. مستندات موجود نیاز قطعی AFD همین بیلد را اثبات نمی‌کنند؛ این تنظیم نه رمزگشایی یا دورزدن حفاظت است و نه وعدهٔ رفع خطا.

هر تست session GUID مستقل دارد. فقط پس از start موفق، همان کنترل loopback قبلی 448 بایتی اجرا می‌شود؛ بعد status و stop همان instance درخواست می‌شوند. در شکست start نیز status همان instance بررسی می‌شود تا partial-start بدون بررسی باقی نماند. اگر status حالت فعال گزارش کند، فقط همان instance cancel می‌شود. اگر cleanup شکست بخورد، یا status نه موفق و نه کد مستند «no active profile» باشد، تست‌های بعدی متوقف می‌شوند. نام session و دستور recovery همان تست در خروجی است.

نام instance شکست‌خوردهٔ قبلی از نتیجهٔ ارسال‌شده استخراج و فقط status آن پرسیده می‌شود. اگر هنوز فعال باشد آزمایش‌های جدید شروع نمی‌شوند؛ خودکار session قبلی یا هیچ session دیگر cancel نمی‌شود. خطای query قبلی به‌تنهایی نبود آن را اثبات نمی‌کند؛ لاگ آن برای بررسی نگه داشته می‌شود.

برای هر case، حداکثر ۳۲ event از Microsoft-Windows-Kernel-EventTracing/Admin در بازهٔ زمانی همان تست، در صورت دسترسی، نگه داشته می‌شود. این eventها صرفاً candidate زمانی‌اند؛ تا تطبیق session/provider/status نمی‌توان آن‌ها را علت خطای خود تست دانست. نبود event یا شکست خواندن لاگ علت را روشن نمی‌کند.

## محدودیت‌ها
- XML/ارجاع‌ها و cross-compile/Go vet بررسی شده‌اند؛ profile جدید، syntax/runtime اسکریپت و GUI/UAC جدید هنوز روی Windows آزمایش نشده‌اند.
- منطق C# loopback بایت‌به‌بایت با نسخهٔ قبل یکسان است. هر case موفق 448 بایت محلی ارسال می‌کند؛ ارسال جزئی ثبت می‌شود. حداکثر شش کنترل، نه اتصال اینترنت یا تست بازی.
- Memory mode، یک collector با ۳۲ بافر ۶۴ KiB در هر تست (درخواست حدود ۲ MiB دادهٔ بافر؛ نه سقف کل حافظه/دیسک)، و اجرا به‌صورت متوالی. filemode نامحدود نیست. سقف تجمعی ETLهای داخل ZIP، ۶۴ MiB است؛ فایل‌های بزرگ‌تر محلی می‌مانند و در STATUS فهرست می‌شوند. سقف قطعی فضای ETL/merge/temp یا زمان پایان ادعا نمی‌شود.
- native module snapshot پیش/پس برای کنترل است؛ managed JIT خودکار نام‌گذاری نمی‌شود. رویدادهای پس‌زمینه و متادیتای شبکه/مسیرها ممکن است در trace باشند. هیچ raw trace، module list یا eventlog کاربر خودکار به مخزن نمی‌رود.
- درخواست stack، start موفق، loopback موفق و ETL موجود، هیچ‌کدام به‌تنهایی اثبات stack مفید نیستند؛ stack_presence_verified=false باقی می‌ماند.
- بازی باید بسته باشد و ابزار به آن attach نمی‌کند. policy، رجیستری، حفاظت، anti-virus یا تنظیمات امنیتی تغییر نمی‌کنند. لانچر unsigned است و در صورت مسدود شدن باید خطا بررسی شود، نه حفاظت غیرفعال شود.

## تصمیم بعدی بر اساس نتیجه
- baseline موفق، Stack ناموفق: تفاوت در این پیکربندی محدود بررسی می‌شود؛ علت دقیق بدون event/status پایین‌سطح اعلام نمی‌شود.
- AFD paged ناموفق، nonpaged موفق: شواهدی از وابستگی به نوع بافر این تست، نه حکم کلی دربارهٔ هر AFD/ویندوز.
- یکی از providerها موفق: هنوز باید ETL و extended stack واقعی و انتساب آن بررسی شود؛ مرحلهٔ بازی شروع نمی‌شود.
- همه ناموفق یا cleanup نامطمئن: WPR profile route برای این gate متوقف و کد خطای زیرساختی بررسی می‌شود؛ اندازهٔ dump یا تعداد اسکن رشته‌ها افزایش نمی‌یابد.

## منابع
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/eventprovider — Strict، Stack و NonPagedMemory.
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/2-system-and-event-provider-definitions — هشدار دربارهٔ نیاز بعضی providerها به nonpaged memory؛ بدون ادعای مشخص دربارهٔ AFD این دستگاه.
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options — Memory، instancename و کد/معنای نبود profile فعال در مثال مستند.

مبنای لانچر قبلی: commit `8d65340c22ba87029ccaa32e3ca359c06a37831d`. فقط source و گزارش‌ها در شاخهٔ تحلیل sync می‌شوند. main و BIOS Path GUI تغییر ندارند.
