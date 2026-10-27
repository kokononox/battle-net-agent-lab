# اصلاح مشاهده‌گر مقصد ۰٫۳٫۱ — بدون تغییر شبکه

دو اجرای واقعی v0.3 با payload معتبر به مرحلهٔ endpoint نرسیدند: اول vpn_state=disconnected و سپس unknown. دومی در identity_before شکست خورده، اما wrapper علت lifecycle را از JSON حذف کرده بود. بنابراین unknown را نباید disconnected، شکست LAN، یا شکست native endpoint تلقی کرد.

v0.3.1 فقط گزارش پالایش‌شدهٔ lifecycle_before و lifecycle_after را حفظ می‌کند؛ شرط full-tunnel و همهٔ native readerها بدون تغییرند. v0.2 Observer/Identity/IdentityPolicy/RasIdentity byte-identical باقی‌اند. ۶۱ assertion جدید (۳ regression افزوده برای حفظ علت/توقف پیش از endpoint/حفظ مشاهدهٔ دوم) و ۸۴ assertion lifecycle در Linux گذشتند. این اصلاح هنوز Windows receipt ندارد. Windows native endpoint reader هنوز بررسی زنده نشده است.

بعد از بازسازی پروفایل، کاربر قبلاً SplitTunneling=True گزارش کرده بود؛ این شرط باعث رد پروفایل در lifecycle می‌شود. اما آخرین receipt آن مقدار یا کد lifecycle را ندارد، پس علت شکست کنونی قطعی نیست. برای عبور از آزمون شرط را حذف یا تنظیمات کاربر را خودکار تغییر ندهید.

کاربر مشکل موقت ۷۳۴ روی LAN همان روتر را گزارش کرد؛ بعد گفت اتصال برقرار شد و خواست به ایزولاسیون برگردیم. علت حل‌شدن نامعلوم است؛ آن را تعمیر تأییدشدهٔ LAN یا reconnect تحت ایزولاسیون محسوب نکنید. raw RasClient logs/نام سرور/نام کاربر در مخزن ذخیره نشده‌اند.

گام بعد: اجرای فقط‌خواندنی بستهٔ جداگانهٔ ۰٫۳٫۱ با VPN فعلی بدون Apply/Restore/قطع‌و‌وصل؛ دریافت JSON تازه حتی در failure و بررسی lifecycle_before.code/stage. هیچ مجوز فایروال، endpoint pin، no-leak، امضا یا bootstrap داده نشده است. این مرحله صرفاً اصلاح مشاهده‌پذیری است، نه یک مرحلهٔ تازهٔ اعمال ایزولاسیون.


## به‌روزرسانی: reader مقصد روی Windows گذشت

[رسید و مرز تأیید](windows-results/CONNECTED-REVIEW.fa.md). پس از اصلاح هدفمند full-tunnel، یک اجرای واقعی Windows v0.3.1 زنجیرهٔ هویت ثابت و یک endpoint همبسته با host تک‌سرویس را ثبت کرد. این مجوز Apply یا تأیید pin/bootstrap نیست. تکرار آزمون لازم نیست؛ گام بعد توسعهٔ آفلاین است.
