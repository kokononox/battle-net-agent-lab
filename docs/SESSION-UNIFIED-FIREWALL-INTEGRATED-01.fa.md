# ادامهٔ پروژه: تغییر مسیر به جریان یکپارچه

کاربر پرسید آیا این آزمون‌ها لازم‌اند و آیا هدفش روشن است. پاسخ پذیرفت که بررسی‌های لازم بیش‌ازحد به بسته‌ها و رفت‌وبرگشت‌های دستی خرد شده‌اند. سپس کاربر گفت «شروع کن». تصمیم این مرحله: یکپارچه‌سازی اجزای موجود و توقف درخواست آزمون‌های دستی تک‌تابعی؛ نه تقلیل هدف به گزارش‌گیری یا معرفی مدل به‌عنوان نسخهٔ نهایی.

## رسید خصوصی inventory قبلی

PRIVATE-INVENTORY-01 روی Windows5.1 کامل شد: دو store،۸۵۲رکورد در مجموع (نه تعداد قاعدهٔ یکتا)،۵۹۶۴فیلتر،۶پروفایل،۲header recheck مطابق، رضایت و private snapshot readback تأییدشده.۱۰۶Allow فعال همگی source=Local و۱۰۶نام یکتای متناظر داشتند؛ نام برابر، semantic match یا اختیار تغییر نیست. هیچ تغییر یا اجرای هدف درخواست نشده بود. فایل عمومی پالایش‌شده ثبت شد؛ فایل خصوصی اصلاً دریافت یا منتشر نشده است. این جریان موفق تکرار نشود.

## خروجی واقعی جدید

[جریان واحد داخلی](../analysis/unifiedfw-session-2026-10-27/integrated-session-v01/README.fa.md) شامل coordinator مرحله‌ای، bridge مستقیم رصدگر موجود، adapter ژورنال فایل واقعی با helperهای قبلی، مقایسهٔ معنایی خصوصی و registry موانع بومی است.۲۷سناریو/۱۲۳assertion یکپارچه با خود runtime coordinator و Linux file IO گذشتند؛ mutation فایروال در حافظه بود.۷۱۸assertion رصدگر و۱۷۲inventory نیز regression شدند.

این commit **Windows setter/restore backend یا public Apply/ZIP ندارد**؛ UI یکپارچهٔ نهایی نیز هنوز منتشر نشده است. وضعیت native-before-review به‌طور صریح توقف می‌دهد. فایل approval=true یا تست fixture نمی‌تواند شاهد واقعی محسوب شود. native-ready و no-leak=false می‌مانند.

مسیر واحد: pending recovery → prerequisites → inspect/review → fresh binding → backup → هر intent قبل از اثر → حمل → quarantine → guard → رصد و audit restore → quiescence/exit consent → restore صرفاً همان intentها → close. ابهام effect/checkpoint، capture exception، target فعال، audit pending و خطای خروج مسیر نگه‌داری pending دارند؛ قواعد قبلی درحالی‌که هدف فعال است خودکار باز نمی‌شوند.

## دامنهٔ نسخهٔ نخست و مسیر کوتاه‌تر

نسخهٔ اول به SSTP ازقبل‌وصل‌شده با هویت تازه و حمل دقیق بازبینی‌شده محدود شد. cold-start/reconnect/reboot/underlay switch فعلاً قابلیت آن نیستند و آزمونشان پیش‌شرط دامنهٔ محدود نیست؛ موفق نیز ادعا نمی‌شوند. قطع اتصال باید capture را متوقف کند، نه broad fallback. هدف بلندمدت همان یک پروفایل برنامه‌محور فعال و ابتدا نصاب Battle.net است؛ مرحلهٔ فعلی هنوز صفر grant داده دارد و نصب کامل را انجام نمی‌دهد.

دو کار اجرایی باقی است: review/live semantic binding دقیق به نشست، و bind بومی policy change/restore/حمل با recovery مستقل و quiescence. سپس یک آزمون هدفمندِ بستهٔ واحد؛ نه انتشار ابزار تشخیصی خرد تازه. فعلاً کاربر اقدام یا تستی ندارد؛ snapshot خصوصی و تنظیمات فعلی حفظ شوند. fingerprint داخل ارتباط مجاز از scope فایروال فراتر است و تضمین نشده است.
