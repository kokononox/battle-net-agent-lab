# اصلاح گزارش‌گیری بازبینی محلی ۰٫۱٫۱

اولین اجرای واقعی v0.1 روی Windows با payload معتبر پیش از نمایش مقصد/prompt متوقف شد: review_unique_stable_endpoint_required. این شاخه بعد از عبور از هویت lifecycle و host تک‌سرویس اجرا می‌شود، ولی شمار tupleهای منطبق در snapshotها دقیقاً یکسان/یکتا نبوده است. رسید شمارنده نداشت؛ cache سرد/منقضی، نبود تطبیق، چند flow یا تغییر flow ممکن‌اند و علت دقیق هنوز مشخص نیست. این receipt نه قطع VPN را ثابت می‌کند نه نشت/اشکال فایروال را. هیچ تأیید انسانی یا تغییر شبکه رخ نداد.

v0.1.1 صرفاً metrics قبل/بعد اضافه می‌کند: آدرس‌های cache و منبعشان، شمار TCP443 میزبان، شمار tupleهای منطبق و اشتراک پایدار؛ بدون raw IP/نام/GUID/digest. پذیرش هنوز دقیقاً یک match در هر snapshot و همان یک tuple پایدار را می‌خواهد؛ هیچ lookup خودکار، cache promotion، fallback اولین flow یا weakening نداریم. شرط حفظ هویت/host بعد از prompt و همهٔ مرزهای عدم approval اجرایی/persistence بدون تغییرند.

۶۸ assertion مدل جدید/رگرسیون بازبینی، ۶۱ endpoint، ۸۴ lifecycle و ۸۶ draft در Linux گذشتند. Windows v0.1.1 هنوز اجرا نشده است. readerهای native و draft byte-identical به مبنا هستند. شمارنده‌ها فقط به تشخیص کمک می‌کنند و اثبات هویت/مجوز Apply نیستند.

گام بعد فقط اجرای بستهٔ جداگانهٔ v0.1.1 روی وضعیت فعلی VPN و بازگرداندن JSON جدید است؛ تکرار نسخهٔ قدیمی، تغییر DNS/فایروال، Apply/Restore یا قطع‌و‌وصل درخواست نشود. اگر به prompt رسید، مشخصات فقط محلی دیده شود؛ REVIEW challenge برای acknowledge draft یا Enter برای لغو است. raw console/screenshot ارسال نشود. نتیجهٔ لغو هم برای تشخیص معتبر است. راهنمای کامل در package/README-FA.md است. fingerprint prevention و bootstrap/reconnect تحت ایزولاسیون همچنان تأیید نشده‌اند.
