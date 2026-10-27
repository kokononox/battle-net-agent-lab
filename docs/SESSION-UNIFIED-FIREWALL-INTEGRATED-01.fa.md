# ادامهٔ پروژه: تغییر مسیر به جریان یکپارچه

کاربر پرسید آیا این آزمون‌ها لازم‌اند و آیا هدفش روشن است. پاسخ پذیرفت که بررسی‌های لازم بیش‌ازحد به بسته‌ها و رفت‌وبرگشت‌های دستی خرد شده‌اند. سپس کاربر گفت «شروع کن». تصمیم این مرحله: یکپارچه‌سازی اجزای موجود و توقف درخواست آزمون‌های دستی تک‌تابعی؛ نه تقلیل هدف به گزارش‌گیری یا معرفی مدل به‌عنوان نسخهٔ نهایی.

## رسید خصوصی inventory قبلی

PRIVATE-INVENTORY-01 روی Windows5.1 کامل شد: دو store،۸۵۲رکورد در مجموع (نه تعداد قاعدهٔ یکتا)،۵۹۶۴فیلتر،۶پروفایل،۲header recheck مطابق، رضایت و private snapshot readback تأییدشده.۱۰۶Allow فعال همگی source=Local و۱۰۶نام یکتای متناظر داشتند؛ نام برابر، semantic match یا اختیار تغییر نیست. هیچ تغییر یا اجرای هدف درخواست نشده بود. فایل عمومی پالایش‌شده ثبت شد؛ فایل خصوصی اصلاً دریافت یا منتشر نشده است. این جریان موفق تکرار نشود.

## خروجی واقعی جدید

[جریان واحد داخلی](../analysis/unifiedfw-session-2026-10-27/integrated-session-v01/README.fa.md) شامل coordinator مرحله‌ای، bridge مستقیم رصدگر موجود، adapter ژورنال فایل واقعی با helperهای قبلی، مقایسهٔ معنایی خصوصی و registry موانع بومی است.۲۷سناریو/۱۲۳assertion یکپارچه با خود runtime coordinator و Linux file IO گذشتند؛ mutation فایروال در حافظه بود.۷۱۸assertion رصدگر و۱۷۲inventory نیز regression شدند.

مرحلهٔ اولیه **Windows setter/restore backend یا public Apply/ZIP نداشت**؛ UI یکپارچهٔ نهایی نیز هنوز منتشر نشده است. وضعیت native-before-review به‌طور صریح توقف می‌دهد. فایل approval=true یا تست fixture نمی‌تواند شاهد واقعی محسوب شود. native-ready و no-leak=false می‌مانند.

مسیر واحد: pending recovery → prerequisites → inspect/review → fresh binding → backup → هر intent قبل از اثر → حمل → quarantine → guard → رصد و audit restore → quiescence/exit consent → restore صرفاً همان intentها → close. ابهام effect/checkpoint، capture exception، target فعال، audit pending و خطای خروج مسیر نگه‌داری pending دارند؛ قواعد قبلی درحالی‌که هدف فعال است خودکار باز نمی‌شوند.

## دامنهٔ نسخهٔ نخست و مسیر کوتاه‌تر

نسخهٔ اول به SSTP ازقبل‌وصل‌شده با هویت تازه و حمل دقیق بازبینی‌شده محدود شد. cold-start/reconnect/reboot/underlay switch فعلاً قابلیت آن نیستند و آزمونشان پیش‌شرط دامنهٔ محدود نیست؛ موفق نیز ادعا نمی‌شوند. قطع اتصال باید capture را متوقف کند، نه broad fallback. هدف بلندمدت همان یک پروفایل برنامه‌محور فعال و ابتدا نصاب Battle.net است؛ مرحلهٔ فعلی هنوز صفر grant داده دارد و نصب کامل را انجام نمی‌دهد.

دو کار اجرایی باقی است: review/live semantic binding دقیق به نشست، و bind بومی policy change/restore/حمل با recovery مستقل و quiescence. سپس یک آزمون هدفمندِ بستهٔ واحد؛ نه انتشار ابزار تشخیصی خرد تازه. فعلاً کاربر اقدام یا تستی ندارد؛ snapshot خصوصی و تنظیمات فعلی حفظ شوند. fingerprint داخل ارتباط مجاز از scope فایروال فراتر است و تضمین نشده است.

## ادامهٔ بعدی: backend اجرایی محلی

با درخواست «قدم بعدی»، `NativePolicyIO.ps1` و `LocalPolicyBackend.ps1` به همین جریان افزوده شدند. reader دو پاس کامل فیلترها، تطبیق خام InstanceID با Name، setter تک‌شیء PersistentStore فقط برای Enabled، callbackهای coordinator و بازیابی prefix از journal واقعی پیاده شدند. [شرح مرز و کار باقی‌مانده](../analysis/unifiedfw-session-2026-10-27/integrated-session-v01/NATIVE-LOCAL-BACKEND.fa.md).

coordinator موجود با همین callbackها در fixture از backup تا restore عبور می‌کند؛ اثرها/qualification/capture این fixture فرضی‌اند، نه Windows واقعی. reader واقعی با cmdlet fixture و serializer موجود آزموده شد. backend فعلی فقط plan محلی دارد؛ mixed transport+quarantine، review/live SSTP، قفل سراسری/recovery مستقل و guard quiescence هنوز کامل نیستند. native readiness مسدود باقی است. شمارش نهایی فقط از QA-SUMMARY خوانده شود؛ فایل خصوصی کاربر دریافت نشد و هیچ تست یا ZIP دستی تازه درخواست نشد.

## ادامهٔ گام بعدی: حمل و quarantine با یک دفتر

`OwnedTransport.ps1` و `MixedPolicyBackend.ps1` به backend قبلی افزوده شدند؛ state parser و callbackها گسترش یافتند، نه اینکه engine یا journal موازی ساخته شود. حمل ابتدا disabled ساخته، هر هفت فیلتر و رکورد local/effective بررسی و در result مشاهده‌شده pin می‌شود؛ سپس enable و quarantine. inverse همان دفتر، ابتدا قواعد محلی را بازمی‌گرداند، سپس حمل متعلق به نشست را disable/remove می‌کند. [شرح دقیق](../analysis/unifiedfw-session-2026-10-27/integrated-session-v01/OWNED-TRANSPORT.fa.md).

هدف هنوز اجرای عملی Battle.net است، نه صرف مدل. Native New/Set/Remove کد شده‌اند، اما روی Windows اجرا نشده‌اند. اتصال واقعی تازهٔ SSTP/review، guard quiescence/audit/exit، قفل سراسری و ورودی recovery مستقل و performance هنوز لازم‌اند. مقدار qualified fixture مدرک واقعی نیست. تست‌ها داخلی‌اند و runtime coordinator/reducer موجود نیز در جریان mixed فراخوانی می‌شود. هیچ ZIP/آزمون دستی تازه یا فایل خصوصی از کاربر درخواست نشد. شمارش نهایی از QA-SUMMARY خوانده شود.

## ادامهٔ فعلی: review زنده و قفل سراسری

`LiveReview.ps1` از observer SSTP و reader EXE قبلی، بدون تغییر آنها، استفاده می‌کند؛ رضایت محلی موقت به فایل، actor، RAS/flow/host و view کامل bind شده و در تغییر یا پایان مهلت باطل می‌شود. `SessionRegistry.ps1` global lock و scan/reopen را با همان journal/parser فراهم می‌کند؛ pending قبل از نشست جدید بررسی می‌شود. guard موجود actor/audit/quiescence/exit حفظ و restore/finish از SSTP و lease مستقل شده‌اند. [شرح و محدودیت‌ها](../analysis/unifiedfw-session-2026-10-27/integrated-session-v01/LIVE-REVIEW-REGISTRY.fa.md).

آزمون داخلی assembled همین coordinator/backend با adapterهای تازه را برای موفقیت، cancel و disconnect اجرا می‌کند؛ اثرهای Windows همچنان fixture هستند. launcher و recovery safety/capture UI نهایی، quiescence واقعی و performance هنوز bind/qualify نشده‌اند. هیچ فایل خصوصی تازه، ZIP یا آزمون دستی از کاربر درخواست نشد؛ Apply و no-leak همچنان false هستند. شمارش نهایی از QA-SUMMARY خوانده شود.
