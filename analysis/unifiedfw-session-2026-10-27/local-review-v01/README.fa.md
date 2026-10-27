# adapter بازبینی محلیِ draft مقصد SSTP — ۰٫۱

کد واقعی اتصال به readerهای موجود، نمایش مشخصات فقط روی console محلی، prompt دستی با challenge تصادفی و native revalidation بعد از prompt پیاده شد. Snapshot/endpoint/lifecycle/draft قبلی بدون تغییر بایت‌اند. بستهٔ مستقل Windows با manifest/payload کنترل‌شده و RemoteSigned پردازش فرزند ساخته شد؛ سیاست دائمی/GPO تغییر نمی‌کند. بسته فقط CurrentUser و یک host تک‌سرویس با یک endpoint پایدار را می‌پذیرد؛ AllUsers صریحاً blocked است.

۶۴ assertion مدل جدید و رگرسیون ۶۱ endpoint، ۸۴ lifecycle و ۸۶ draft روی Linux گذشتند. مسیر موفق در مدل ۴ lifecycle و ۴ snapshot native قبل/بعد از prompt دارد. تغییر آدرس، flow، PID، creation time، image hash یا binding بعد از prompt تأیید را کنار می‌گذارد؛ لغو/wrong challenge و native failure اجازه نمی‌دهند. کد علت observer را پنهان نمی‌کند. API/Read-Host در مدل mock هستند؛ اجرای واقعی Windows این بسته و prompt واقعی هنوز آزموده نشده‌اند. مشاهده‌های native اتمیک نیستند.

این acknowledge فقط بازبینی draft در همان invocation است؛ هیچ approval authority محافظت‌شده، pin اجرایی، persistence، guardian/executor یا مجوز Apply ساخته نشده است. raw binding و draft فقط در حافظه‌اند و نتیجهٔ sanitized حتی digest/challenge/IP/GUID را ندارد. فایل approved=true یا cache خودکار مجوز نمی‌شود. این milestone حل bootstrap DNS/TLS، اعتماد امضا/service-tag یا تضمین reconnect/no-leak نیست.

اقدام بعد کاربر: با VPN فعلی بدون Apply/Restore/قطع‌و‌وصل، ZIP را در پوشهٔ تازه Extract و Run-Observer.cmd را با همان کاربر و Administrator اجرا کند. صفحهٔ محلی مشخصات را نباید screenshot یا ارسال کند. اگر مشخصات موردنظرش است می‌تواند عبارت REVIEW تصادفی را برای بازبینی draft تایپ کند؛ Enter خالی لغو است. فقط JSON جدید SSTP-LOCAL-REVIEW-01-*.json فرستاده شود؛ حتی cancellation/failure مفید است. کاربر لازم نیست مالکیت cryptographic یا مستقل IP را تضمین کند؛ این هنوز approval فایروال نیست.

[راهنمای کامل فارسی](package/README-FA.md)، [هش ZIP تحویلی](PACKAGE-SUMMARY.json) و [آزمون‌ها](MODEL-RESULTS.json). فایل ZIP در مخزن ذخیره نمی‌شود. کد build/QA مسیرهای آزمایشگاهی دارد؛ فقط محتویات package برای اجرای Windows است. هدف همچنان فونداسیون ابزار اختصاصی نصاب Battle.net است.
