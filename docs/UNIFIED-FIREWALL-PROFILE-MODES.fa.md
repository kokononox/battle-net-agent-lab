# قرارداد جاری — یک پروفایل فعال، فقط برنامه‌های همان پروفایل

کاربر انتخاب قبلی all-programs را صریحاً اصلاح کرد: وقتی مود مرورگر فعال است، فقط مرورگر و اجزای مشخص‌شدهٔ مجاز آن اجازهٔ ارتباط دارند و بقیهٔ برنامه‌ها حتی به همان مقصدهای مجاز مسدودند. هر مجوز ترکیب برنامه+مقصد+پورت روی SSTP معتبر است، نه اینترنت آزاد برای برنامه. مودهای browser/game/installer روی یک موتور با یک مود فعال در هر لحظه؛ ابتدا نصاب بتل‌نت تکمیل شود. افزودن/حذف مقصد همچنان لازم است ولی به معنی جهانی‌شدن مجوز نیست.

## کد و شواهد مرحله

[شرح و قرارداد سازندهٔ پلن](../analysis/unifiedfw-session-2026-10-27/app-profile-plan-v01/README.fa.md) و [source](../analysis/unifiedfw-session-2026-10-27/app-profile-plan-v01/source/app_profile_plan.py). compiler خالص Python فقط grantهای پروفایل فعال را جدا برای هر برنامه با template disabled و token binding تازهٔ SSTP تولید می‌کند. cross-product برنامه‌ها×مقصدها، union مودهای غیرفعال، child/service permission خودکار و input approval پذیرفته نمی‌شوند. path/hash ورودی اثبات فایل واقعی و digest/generation مجوز اجرا نیستند. خام پلن واقعی حاوی اطلاعات خصوصی خواهد بود و نباید خودکار ارسال یا commit شود.

۲۵ test method و ۱۰۰۰ predicate case مستقل آفلاین پاس شدند؛ ۸۶ assertion سازندهٔ exact SSTP transport قبلی هم دوباره، بدون تغییر source، پاس شد. predicate مدل native/WFP نیست. recorder، program identity reader واقعی، DNS/site enforcement، mode-switch executor و Apply در این مرحله ساخته نشده‌اند. Windows API/هویت برنامه/SSTP/flow revocation/reboot/reconnect واقعی با این مدل qualification نمی‌شوند. ready_for_apply=false و no_leak_certified=false.

## گیت‌ها و ادامه

هویت native برنامه و file replacement/reparse/ACL، رضایت دقیق محتوا و Apply، baseline تازه، foreign Allow و effective policy، approval و service filter حمل SSTP، DNS/certificate/underlay bootstrap، تعلیق داده در disconnect، جمع‌کردن scopeدار مجوزهای مود قبلی و اتصال‌های برقرار، native journal/recovery و packet/reboot/reconnect هنوز لازم‌اند. blanket Block-all rule با default Block+Allow انتخابی یکسان نیست؛ قواعد Allow قبلی با default Block خودبه‌خود حذف نمی‌شوند. hash/selection فقط draft است و برای گشودن این گیت‌ها کافی نیست.

مرحلهٔ بعد local program-and-destination review برای نصاب و سپس composition با baseline/transport است؛ نه تکرار آزمون عمومی یا old Apply. کاربر فعلاً اقدام ندارد، journal محافظت‌شده و شبکه/SSTP همان وضعیت بماند. بستهٔ Windows یا تغییر واقعی شبکه در این milestone تحویل/اجرا نشده است.
