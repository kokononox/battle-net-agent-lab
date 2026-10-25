# G45 — سه آزمون واقعی دریافت مستقل رد شدند؛ هیچ payload تأیید نشد

## نتیجهٔ واقعی، نه موفقیت مصنوعی
سه شیء کوچک از نامزدهای Windows در snapshot G44 انتخاب شدند. هر سه درخواست HTTPS به آدرس مستقلِ پیشنهادی پاسخ404 دادند. هیچ‌یک به مرحلهٔ بررسی BLTE/CKey یا محاسبهٔ SHA-256 payload واقعی نرسید. وضعیت پذیرش sample_plan_incomplete است؛ تعداد payload تأییدشده و تعداد resource اجرایی approved هر دو صفرند.

| نمونه | اندازهٔ encoded مورد انتظار | نتیجهٔ HTTP | بررسی بایت واقعی |
| --- | --- | --- | --- |
| sample_1 |27بایت |404 |انجام نشد |
| sample_2 |4283بایت |404 |انجام نشد |
| sample_3 |7461بایت |404 |انجام نشد |

سه منبع بر پایهٔ کوچک‌ترین encoded_bytes و سپس EKey انتخاب شدند، نه وضعیت کاربر یا شناسهٔ دستگاه. نمونهٔ اول در manifest به165مسیر locale .pak مشترک اشاره می‌کند؛ دو نمونهٔ دیگر Microsoft.Gaming.XboxApp.Extensions.winmd و api-ms-win-core-fibers-l1-1-0.dll هستند. نام‌ها و اندازه‌ها فقط انتظار برگرفته از manifest هستند؛ محتوای واقعی آن‌ها در این آزمون دریافت نشده و اصالت publisher آن‌ها بررسی نشده است.

## معنای شکست
نگاشت صحیح CKey↔EKey در G44 به‌تنهایی تضمین نمی‌کند `{cdn}/data/aa/bb/ekey` برای تک‌تک payloadها پاسخ200 بدهد. این سه URL مشخص در زمان آزمون404 دادند؛ نتیجه به همهٔ196نامزد، همهٔ میزبان‌ها یا همیشه تعمیم داده نشده است.

از404 به‌تنهایی نمی‌توان نتیجه گرفت این سه شیء حتماً داخل archive هستند؛ metadata CDN وجود archive و indexها را اعلام می‌کند، اما محل این سه EKey هنوز با index اثبات نشده است. تغییر مقصد، query، HTTP fallback، دنبال‌کردن redirect، retry یا بازکردن ترافیک برای جبران شکست انجام نشد.

## طرح محدود اجراشده
برنامهٔ سه‌نمونه‌ای از G44 با source commit1503ae7c842058a580cbb9e31143e666eb5af589 و SHA-256 فایل نامزدها پین شد. URL، EKey، CKey، اندازه و ترتیب از plan ثابت آمدند؛ ورودی نصاب relay نشد.

- سقف3attempt بود و هر3attempt پیش از ارتباط reserve شدند؛ شکست سهم را پس نداد.
- جمع اندازهٔ encoded مورد انتظار11771بایت بود. این سقفِ اندازهٔ نمونه‌های معتبر است، نه شمار کل bytes سیم/TLS یا headerها.
- برای تشخیص oversize، reader حداکثر یک بایت اضافه برای هر نمونه می‌خواند؛ سقف application-body read در حالت دریافت بد11774بایت است. برای پاسخ‌های404، body در برنامه خوانده نشد؛ این به معنیِ تضمین نبود دادهٔ buffered در socket یا اندازه‌گیری wire نیست.
- تنها میزبان واقعی آزمون us.cdn.blizzard.com روی HTTPS بود؛ certificate/hostname validation عادی، بدون proxy محیطی، cookie، Authorization، Referer، query یا body درخواست. Host، User-Agent ثابت و metadata معمول TCP/TLS همچنان خارج می‌شوند و سرور IP/fingerprint شبکهٔ محیط آزمایش را می‌بیند.
- timeout20ثانیه مربوط به عملیات شبکه است، نه یک deadline سراسریِ اثبات‌شده برای دانلود production.
- marker یک‌بارهٔ محلی قبل از شبکه نوشته شد. هیچ attempt در همین جلسه دوباره اجرا نشد. این marker آزمایشگاهی، journal امن محصول Windows یا دفاع کامل علیه admin/replay بین ماشین‌ها نیست.

هیچ DLL/PE load، اجرای فایل، نصب، ورود به حساب یا تغییر firewall/CA/task انجام نشد. فایل payload برای انتشار وجود ندارد. اگر دریافت معتبر انجام می‌شد، فقط .encoded.bin/.decoded.bin خصوصی0600 در پوشه0700 نوشته می‌شد و اجرا نمی‌شد.

## بررسی بعدی — هنوز اجرا نشده
CDNConfig عمومی G43 دوباره از fixture با SHA-256 و MD5 content key بررسی شد. در آن45archive index با اندازه‌های مشخص و یک file-index وجود دارد. next-index-plan.unexecuted.json برای46metadata object، با مجموع اندازهٔ مورد انتظار623408بایت، آماده شد؛ هیچ‌یک در G45 درخواست نشد.

گام بعد، بررسی همین indexها برای یافتن EKeyهای سه نمونه است. اگر mapping معتبر archive/offset/length به دست آید، درخواست Range باید کاملاً از catalog مورد اعتماد بازسازی شود؛ client نباید Range/offset دلخواه بدهد. قبل از خواندن بدنه باید206، Content-Range دقیق و طول پاسخ بررسی شوند و پاسخ200ِ کل archive رد شود. سپس BLTE/EKey، CKey، اندازه و SHA-256 بایت واقعی دوباره لازم‌اند. این‌ها طرح بعدی‌اند، نه قابلیتی که اکنون موفق آزمایش شده باشد.

## آزمون‌های آفلاین
16آزمون آفلاین موفق شدند: pin و بودجه، رد URL/query/credential/مقصد telemetry، هدر ثابت و body غایب، عدم follow redirect، عدم خواندن body غیر200، طول کوتاه/بلند، transfer ambiguity و Content-Range نامناسب، بررسی BLTE مصنوعی و فساد آن، فایل خصوصی بدون execute/overwrite، مصرف سه attempt حتی با404، رد بازاجرای همان جلسه و حفظ نتیجهٔ واقعیِ شکست.

موفقیت fixture مصنوعی برای آزمون verify، موفقیت دانلود Battle.net نیست. سه درخواست واقعی شکست خوردند؛ شانزده آزمون فقط قرارداد و نحوهٔ مواجهه با شکست را بررسی می‌کنند. تست‌ها با ساخت socket ممنوع اجرا شدند و هیچ CI/نصب بومی جدیدی ادعا نمی‌شود.

## شواهد و نسخهٔ کد
- fetch-evidence.json: facts مشاهده‌شده با چهار annotation صریح دربارهٔ بودجه/body/count؛ HTTP404ها یا errorها تغییر نکرده‌اند.
- fetch-observed.reconstructed.json: گزارش اولیه بازسازی‌شده با حذف قطعی همان چهار annotation؛ این بازسازی از ثبت محلی است، نه attestation بومی CI.
- fetch_samples.initial-source.py.txt: متن source اولیه از فرمان ساخت ثبت‌شده و تغییرات دنبال‌شده بازیابی شده است؛ hash آن runtime-measured نبوده است.
- source-versions.json: جدایی source اجرای اولیه از سخت‌گیری‌های آفلاین بعدی. پس از سه درخواست واقعی، کنترل shape/type plan و توضیح POSIX/بودجه و مسیر خروجی محلی سخت‌گیرانه‌تر شد؛ درخواست واقعی تکرار نشد. مسیر و headerهای درخواستِ برنامهٔ ثابت تغییر نکردند.
- source-plan-binding.json و pins.py: اتصال انتخاب‌ها به snapshot G44.
- next-index-plan.unexecuted.json: صرفاً برنامهٔ metadata بعدی، نه دانلود انجام‌شده یا مجوز runtime.
- runtime-catalog-unchanged.json: hash کاتالوگ deny-all G37 با baseline G44 برابر است.

## تصمیم
گیت یا محدودیت‌های G37 تغییر نکردند. هیچ hostname یا Range به runtime اضافه نشد و نصب همچنان دستی است. این مرحله نشان داد روش standalone برای این سه نمونه جواب نداده؛ به‌جای اعلام موفقیت یا بزرگ‌کردن allowlist، بررسی index مسیر بعدی است. ادعای جلوگیری کامل از fingerprinting، آمادگی محصول یا ساخت EXE نهایی نداریم.
