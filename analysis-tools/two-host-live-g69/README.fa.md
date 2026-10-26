# G69 — مرز دقیق Range و منشأ کلید مسیر باقی‌مانده

هدف: همان یک مسیرِ نامنطبق و 13 Range مشاهده‌شده در G68؛ نه تکرار آزمون نصب یا رمزگشایی. کد hook، شناسایی process، سیاست شبکه، گواهی و UI نسبت به G68 فقط تغییر نام مرحله دارند.

## مرجع مستقل
از snapshot معتبر عمومی G68 و قبل از مشاهدهٔ جدید، 11 GET ثابت دیگر فقط برای metadata دریافت شد؛ مجموع بدنه‌ها 262244 بایت است. encoding/install/size/patch-indexهای agent و bna با اندازهٔ اعلام‌شده، BLTE EKey/chunk/CKey کنترل شدند؛ download manifestها از fixture عمومی قبلی بازاستفاده شدند. EN با parser محدود G44 و install با parser قبلی بررسی شد. هیچ archive body یا فایل اجرایی دریافت نشد.

سه archive index عمومیِ Agent از کلیدهای CDNConfig دریافت و با parser G46 بررسی شدند: key/footer checksum، TOC، checksum همهٔ blockها، ترتیب کلید، اندازه، offset و padding. مرجع Range هر رکورد مستقیماً از offset/اندازهٔ index معتبر استخراج شد. برای ده metadata BLTE نیز مرز دقیق کل شیء، حداقل هدر، جدول chunk و chunkهای کامل مرجع است. این مرزها از درخواست installer یاد گرفته نشده‌اند.

تکمیل EN و نسخه‌های منطقه‌ای مسیر تازه‌ای به مجموعهٔ 1241تایی اضافه نکرد؛ بنابراین قبل از اجرای جدید، حلِ مسیرِ نامنطبق ادعا نمی‌شود. برای تشخیص محدود، شکل canonical path، fanout، prefix عمومی و برابری leaf key با مجموعهٔ کلیدهای عمومی BuildConfig/versions/encoding بررسی می‌شود؛ نه raw token منتشر می‌شود و نه CKey به‌طور حدسی EKey فرض می‌شود. شکل hash یا عمومی‌بودن leaf، به‌تنهایی تأیید endpoint یا مجوز نیست.

reference SHA256 در download_path_audit.py پین است. snapshot عمومی تمام دریافت‌ها در public-reference-fixtures.json و receiptها داخل catalog حفظ شده‌اند. source دقیق اسکریپت پژوهشی اجراشده در extended-reference-acquisition.provenance.txt با مسیرهای همان sandbox نگهداری می‌شود؛ workflow آن را اجرا نمی‌کند. داده‌های پایه در G68 و کدهای خالص EN/index از encoding-map-g44/encoding.py و archive-index-g46/index_parser.py در commit 3a23c62ae80666d428603e4ab3fd211ff73b6aa1 آمده‌اند.

## معنی خروجی Range
- equality دقیق با یک رکورد کامل index یا اجتماع رکوردهای کاملِ کاملاً پیوسته، به‌صورت public boundary match ثبت می‌شود.
- slice درون یک رکورد، عبور از gap، خارج از مرز، چند range یا syntax پشتیبانی‌نشده، full match محسوب نمی‌شود.
- equality با مرز BLTE metadata نشان می‌دهد درخواست همان بخش ساختاریِ عمومی را انتخاب کرده است؛ علت/ضرورت انتخاب، زمان‌بندی و نبود تمام کانال‌های covert را اثبات نمی‌کند.
- هیچ raw path، key، offset یا Range مشاهده‌شده صادر نمی‌شود؛ فقط کلاس و نتیجهٔ equality گزارش می‌شود. range referenceهای منتشرشده، مرجع مستقل عمومی هستند، نه capture خام کاربر.

## کنترل‌ها و دامنه
76 تست محلی گذشتند. تست‌های تازه، بازاعتبارسنجی سه index واقعی و فساد checksum، مرز metadata، slice/gap و عدم افشای raw را پوشش می‌دهند. قبل از mutation، تست‌ها دوباره در ویندوز و سپس ده کنترل بومی x86/x64 اجرا می‌شوند.

دریافت پژوهشی HTTPS از us.cdn.blizzard.com جدا از runtime است؛ همان منبع مستقل قبلی G43/G68، نه allowlist جدید. Runtime فقط دو مقصد قبلی و استثنای قبلی مدیریت CI را دارد. بررسی ابطال/TLS ضعیف نشده، main و 0.9.10 دست‌نخورده‌اند. مشاهده هنوز 120 ثانیه است؛ پوشش کامل دانلود یا همهٔ API/فرایندها و نبود fingerprint ثابت نشده‌اند. هیچ unknown به allow rule تبدیل نمی‌شود.

## یک اجرای ادامه‌دهنده پس از توقف ابزار
اجرای 40289287822 پیش از رسیدن به مسیر هدف با late_process_image_failed متوقف شد؛ cleanup موفق بود. در بخش ثبت‌شده، 9 از 10 Range به مرز مستقل دقیق متصل شدند. کد جدید فقط در صورت failure خواندن image و signalled بودن همان process handle با WaitForSingleObject(...,0)==WAIT_OBJECT_0، از تلاش attach به پردازش قطعاً خاتمه‌یافته عبور می‌کند. TIMEOUT/WAIT_FAILED/unknown و process زنده همچنان stop هستند؛ مسیر/hash/امضا و firewall/TLS تغییر نمی‌کنند. OpenProcess اکنون SYNCHRONIZE را هم لازم دارد؛ شکست بازکردن handle همچنان fail-closed است. شمار چنین skipهایی در گزارش می‌ماند و پوشش کامل از آن نتیجه نمی‌شود. 78 تست کشف شدند؛ روی Linux یک تست native Windows skip شد و بقیه گذشتند. تست owned-child زنده/خاتمه‌یافته قبل از mutation روی Windows الزامی است. یک اجرای ادامه‌دهنده شروع می‌شود؛ تکرار بیشتر خودکار انجام نمی‌شود.
