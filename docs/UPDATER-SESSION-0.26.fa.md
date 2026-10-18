# اتصال ترجیحات نصب به انتخاب نامزد — ۰٫۲۶

ترجیحات دیگر فقط یک گزارش جدا نیستند: بندهای عمومی واقعی کپی .build.info، با حفظ optional و رابطهٔ دقیق زبان/text/speech، به دو manifest هدف و نامزد موجود وصل شدند. ابتدا هویت baseline/config و سپس زنجیرهٔ target، candidate، catalogue و decoded metadata دوباره کنترل می‌شود؛ ProductConfig نیز به همان versions bytes متصل است. تغییر alias زبان، نام ناشناخته، نوع نامتناسب یا ابهام باعث توقف می‌شود؛ ترجیحات بی‌خبر بازنویسی نمی‌شوند. مدل typed-profile سخت‌گیرانه صرفاً مقایسه است، نه fallback.

کنترل حریم خصوصی تازه: optionalهای خصوصی acct/geoip تنها اگر در هیچ‌کدام از دو جدول تگ موجود نباشند از عبارت کنار گذاشته می‌شوند؛ اگر در یکی موجود باشند، بدون چاپ نام خصوصی توقف می‌کنیم. چهار qualifier تاریخی غایب و withheld بودند. خروجی مسیر نصب یا نام خصوصی ندارد. این کنترل بر پایهٔ candidate grammar است، نه اثبات semantics رسمی Agent.

روی کپی تاریخی baseline 12.1.0.69933 و target ذخیره‌شدهٔ 12.1.5.70448 اجرا شد: همان ۳۹ رکورد Install و ۱٬۵۷۸٬۰۲۲ رکورد Download نامزد قبلی حاصل شد. یک پیاده‌سازی جدا، predicate را برای تک‌تک رکوردها محاسبه کرد و هر دو bitmap/hash و count را تأیید کرد. این بررسی مستقلِ داخلی است، نه oracle مستقل رسمی. candidate و catalogue قبل/بعد هش شدند و تغییر نکردند. هدف «آخرین نسخهٔ آنلاین امروز» فرض نمی‌شود.

۳۲ تست جدید؛ مجموع ۷۰۶ Linux و ۳۶۴ Windows/Python 3.12.10 با صفر failure/error/skip. تست‌های native همچنان فقط پوشه‌های موقت مصنوعی هستند. fixture نسخهٔ آینده زنجیرهٔ واقعی سازگار می‌سازد؛ کنترل هویت در تست‌های ادغام mock نشده است. شمار دو پلتفرم هم‌پوشان است.

مرحلهٔ اول هنوز باز: قواعد کامل feature/variant/dependency، ترجیحات واقعاً تازه و نسل فعال همساز اثبات نشده‌اند. این ماژول reader/candidate review است، نه updater. هیچ فایل بازی تغییر نکرد، CDN درخواست نشد و shmem/LRU خوانده نشد. فعلاً اقدام کاربر لازم نیست. required_set_selected/active_generation_proven/installation_ready/apply_authorized=false و required_network_download_bytes=null باقی‌اند.

[منطق و شواهد](research/PREFERENCE-SELECTION-BRIDGE.md) · [گزارش اجرای ذخیره‌شده](reports/PREFERENCE-CANDIDATE-BRIDGE-to-share.json) · [رسید ویندوز](reports/WINDOWS-PREFERENCE-BRIDGE-CI-to-share.json)

## ادامه

# اقدامات باقی‌مانده پس از ۰٫۲۶

## پیشرفت واقعی
بندهای عمومی ترجیحات کپی تاریخی، بدون حذف optional یا قاطی‌کردن زبان متن/صدا، به نامزد hash-verified وصل شد. حذف تگ خصوصی فقط پس از اثبات غیبت نامش در هر دو manifest ممکن است. bitmap نامزدها مستقل برای تک‌تک رکوردها بررسی شد؛ نامزد تغییر نکرد. ۷۰۶ Linux و ۳۶۴ Windows پاس‌اند. [تحویل](UPDATER-SESSION-0.26.fa.md).

## ترتیب باقی‌مانده
1. **مرحلهٔ اول هنوز باز است:** قواعد کامل feature/variant/dependency، ترجیحات واقعاً تازه و نسل فعال همساز. اتصال candidate و تگ تاریخی oracle رسمی یا live capture نیست. برای نسل فعال ابتدا قرارداد bounded/versioned شامل مسیر/حجم/حریم خصوصی و معیار مستقل سازگاری طراحی شود؛ نه حدس offset و نه بزرگ‌ترین filename. هیچ خواندن تازه shmem/LRU یا اجرای کاربر در این مرحله خواسته نشده است.
2. اثبات reuse محلی، required set معتبر و حجم دقیق شبکه؛ unknown صفر نیست.
3. qualification انتقال واقعی محدود، resume/recovery با budget و approval مستقل.
4. writer تراکنشی CASC، rollback و activation؛ ابتدا کپی مستقل و آزمون شکست/قطع عملیات. writer نصب واقعی هنوز پیاده نشده است.
5. آزمون نسخه‌های متفاوت و نسخهٔ آینده، stop برای قالب ناشناخته؛ سپس UI، بسته‌بندی و انتشار.

فعلاً اقدام کاربر لازم نیست. admin/ACL، update/repair رسمی، broad upload و game write درخواست یا مجاز نشده‌اند. required_set_selected=false، active_generation_proven=false، required_network_download_bytes=null، installation_ready=false و apply_authorized=false. تست‌های Windows پوشهٔ موقت‌اند و qualification تولید/نصب واقعی محسوب نمی‌شوند. کش‌ها حفظ و دوباره دانلود نشوند؛ workflow مستقل Agent تغییر نکند.
