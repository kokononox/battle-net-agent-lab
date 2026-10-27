# ادامهٔ جلسهٔ Unified Firewall

آخرین ادامه: [جریان واحد و توقف آزمون‌های دستی خرد](../../docs/SESSION-UNIFIED-FIREWALL-INTEGRATED-01.fa.md).

اول [تحویل جامع](../../docs/SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md) و [وضعیت جاری](../../docs/UNIFIED-FIREWALL-CURRENT.json) را بخوانید.

- `source-overlay/`: تغییرات متنی نسبت به سورس پایهٔ immutable؛ [قرارداد بازسازی](SOURCE-OVERLAY.json). runtime نیست؛ manifestهای release داخل overlay تاریخیِ HF1.1 و برای کاندید فعلی نامعتبرند. این پوشه را روی برنامهٔ آزمایش جایگزین نکنید.
- `windows-receipts/`: رسیدهای پالایش‌شدهٔ drift، بازیابی و مقایسهٔ خواندنی (شکست و موفقیت جدا).
- `qa/`: آزمون‌های محلی با scope صریح؛ قبولی Linux برابر qualification ویندوز نیست.
- `diagnostics/hf121/`: سورس همان ابزار فقط‌خواندنیِ نمونه‌ای؛ دستور اجرای تازه نیست. مسیرهای مطلق مدل‌تست‌ها متعلق به محیط ساخت‌اند؛ برای بازتولید آزمون باید پارامتر Root/مسیرها به checkout محلی تنظیم شوند.
- `reconnect-design-v01/`: kernel تصمیم با ۶۷ بررسی؛ بدون native observer/executor و بدون دخالت در guardian.
- `ARTIFACT-INDEX.json`: هش بسته‌های تحویلی و وضعیت تاریخی/غیرقابل‌نصب؛ ZIP و runtime منتشر نشده‌اند.

این سینک raw chat، dump، pcap، اطلاعات ورود، آدرس سرور VPN، نام/مسیر شخصی، ژورنال محافظت‌شده یا backup خصوصی را منتشر نمی‌کند. اصلِ هدف: ابزار کوچک Battle.net؛ جلوگیری کامل از فینگرپرینت هنوز تأیید نشده است.

- `program-observer-v01/`: ادامهٔ candidate موجود با انتخاب صریح/بازمشاهدهٔ فایل و TCP sampling غیرفعال، فقط پیشنهاد خصوصی و diagnostic پالایش‌شده؛ ۶۴۵ assertion جدید و۵۶۹ regression، یک رسید Windows با صفر فرایند پایدار و صفر مقصد دریافت شد؛ qualification انتساب غیرصفر نیست، نه Apply.

- `runtime-capture-v01/`: رصد رخدادهای زمان اجرا با audit موقت و بازیابی صریح؛ فقط پس از READY اجرای دستی هدف، بدون Allow جدید؛ recorder آزمایشی و نه تضمین ایزولاسیون.۷۱۸ assertion و۱۲۱۴ regression؛ Windows native هنوز تأیید نشده.

- `allow-review-v01/`: تشخیص مستقل فقط‌خواندنی و شمارشی علت رد قواعد Allow؛۱۶۱۷ assertion؛ بدون تغییر فایروال/audit، انتخاب candidate یا اجرای نصب‌کننده. نخستین اجرای runtime در gate قواعد متوقف شد و هنوز audit/READY/capture بومی تأیید نشده است.

- `isolation-transaction-v01/`: قرارداد و مدل آفلاین journal-before-effect/quarantine/recovery؛۱۱test methodجدید،۶۰حالت ابهام اثر و۱۰گام resume بازیابی؛ فاقد setter/Apply/backup خصوصی واقعی. تشخیص Allow روی Windows موفق و۱۰۶mismatch بدون خطای خواندن ثبت شد.

- `private-inventory-v01/`: ثبت محلیِ خصوصی دو store و هفت دستهٔ فیلتر با رضایت ذخیره؛۱۷۲assertion/۱۹callback و۱۶۱۷regression؛ Windows جریان ذخیرهٔ خصوصی موفق شد؛ فاقد setter/Apply/restore. فقط diagnostic عمومی برگردد، نه snapshot خصوصی.

- `integrated-session-v01/`: یک coordinator با bridge رصدگر موجود و journal فایل واقعی؛۲۷سناریو/۱۲۳assertion داخلی. backend بومیِ محدودِ Enabled/restore محلی و reader کامل اضافه و به همان coordinator در fixture متصل شد؛ اثر آزمون حافظه‌ای است، حمل disabled/materialize/enable/remove اکنون در همان دفتر پیاده شد؛ observer/review زنده، UI/recovery نهایی و performance هنوز qualify نشده‌اند؛ ZIP یا آزمون دستی تازه ندارد. inventory خصوصی Windows قبلی موفق شد و تکرار نشود.

- ادامهٔ داخلی `integrated-session-v01`: adapter بازبینی زندهٔ SSTP/EXE و lease موقت، global lock/scan و reopen با parser قبلی اضافه شدند؛ restore به VPN وابسته نیست. اثر Windows/UI نهایی و quiescence/performance هنوز تأیید نشده‌اند؛ ZIP جدید ندارد. جزئیات در `LIVE-REVIEW-REGISTRY.fa.md` و آمار نهایی در QA-SUMMARY است.

- ادامهٔ داخلی همان جریان: candidate ثابت به collector قبلی bind و dispatcher بازیابی audit-before-policy اضافه شد؛ شواهد exit به‌تنهایی quiescence نیست. probe بومی کامل و شاهد پایدار فرایند برای recovery پس از crash هنوز مانع‌اند؛ Apply/Windows launcher منتشر نشده است. شرح در `integrated-session-v01/RUNTIME-RECOVERY-BINDING.fa.md`.

## ادامه: شاهد پایدار در همان دفتر نشست

`RuntimeWitness.ps1` پیش از Window، arm را در journal موجود flush/readback می‌کند و پس از collector، evidence محدود فرایندها را append می‌کند. registry همان نشست را پس از قطع بازمی‌خواند؛ factory بومی بدون witness معتبر READY نمی‌دهد. این evidence انتساب کامل helper/service یا authority بازگردانی Allow نیست؛ probe مستقل و recovery/UI بومی همچنان لازم‌اند. جزئیات در `integrated-session-v01/DURABLE-RUNTIME-WITNESS.fa.md`، نتیجهٔ آزمون‌ها در QA-SUMMARY است. اثر بومی Windows یا آزمون دستی تازه‌ای انجام/درخواست نشده است.

## ادامه: guard وضعیت فعلی فرایندها

`ProcessQuiescence.ps1` همان witness را با دو census فعلی و cross-check دو enumerator بررسی می‌کند. دسترسی نامعلوم، تغییر actor/boot/head یا اجرای هدف/فرزند شناخته‌شده رد می‌شود. این guard به همان backend بازیابی وصل شده و guard قبلی و helper/service coverage مستقل را حفظ می‌کند؛ recovery پیش از close، finish guard هم دارد. جزئیات در `integrated-session-v01/PROCESS-QUIESCENCE.fa.md` است. native coverage و qualification همچنان مانع‌اند؛ شمارش معتبر از QA-SUMMARY خوانده شود. آزمون دستی یا فایل خصوصی تازه‌ای درخواست نشد.

## ادامه: رضایت خروج محدود و مبنای audit پایدار

`ExitReview.ps1` رابط کنسولی محلی و lease موقت رضایت را به همان recovery-first/backend وصل می‌کند. arm v02 plan و head/session_id دفتر audit اصلی را نگه می‌دارد؛ مقدار واقعی before ماسک‌ها در خروج لازم است و pending نامرتبط پیش از archive/اثر رد می‌شود. v01 بدون baseline به‌طور خودکار upgrade/approved نمی‌شود. cancel/drift/انقضا inverse یا closed موفق نمی‌سازد؛ هیچ reset/Allow عمومی نیست. جزئیات در `integrated-session-v01/EXIT-REVIEW.fa.md` است؛ helper/service guard، UI نهایی و Windows/performance qualification هنوز مانع‌اند. شمارش معتبر از QA-SUMMARY خوانده شود؛ آزمون دستی تازه درخواست نشد.
