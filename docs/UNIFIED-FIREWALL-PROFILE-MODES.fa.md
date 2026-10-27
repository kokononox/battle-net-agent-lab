# قرارداد جاری — یک پروفایل فعال، فقط برنامه‌های همان پروفایل

کاربر انتخاب قبلی all-programs را صریحاً اصلاح کرد: وقتی مود مرورگر فعال است، فقط مرورگر و اجزای مشخص‌شدهٔ مجاز آن اجازهٔ ارتباط دارند و بقیهٔ برنامه‌ها حتی به همان مقصدهای مجاز مسدودند. هر مجوز ترکیب برنامه+مقصد+پورت روی SSTP معتبر است، نه اینترنت آزاد برای برنامه. مودهای browser/game/installer روی یک موتور با یک مود فعال در هر لحظه؛ ابتدا نصاب بتل‌نت تکمیل شود. افزودن/حذف مقصد همچنان لازم است ولی به معنی جهانی‌شدن مجوز نیست.

## کد و شواهد مرحله

[شرح و قرارداد سازندهٔ پلن](../analysis/unifiedfw-session-2026-10-27/app-profile-plan-v01/README.fa.md) و [source](../analysis/unifiedfw-session-2026-10-27/app-profile-plan-v01/source/app_profile_plan.py). compiler خالص Python فقط grantهای پروفایل فعال را جدا برای هر برنامه با template disabled و token binding تازهٔ SSTP تولید می‌کند. cross-product برنامه‌ها×مقصدها، union مودهای غیرفعال، child/service permission خودکار و input approval پذیرفته نمی‌شوند. path/hash ورودی اثبات فایل واقعی و digest/generation مجوز اجرا نیستند. خام پلن واقعی حاوی اطلاعات خصوصی خواهد بود و نباید خودکار ارسال یا commit شود.

۲۵ test method و ۱۰۰۰ predicate case مستقل آفلاین پاس شدند؛ ۸۶ assertion سازندهٔ exact SSTP transport قبلی هم دوباره، بدون تغییر source، پاس شد. predicate مدل native/WFP نیست. recorder، program identity reader واقعی، DNS/site enforcement، mode-switch executor و Apply در این مرحله ساخته نشده‌اند. Windows API/هویت برنامه/SSTP/flow revocation/reboot/reconnect واقعی با این مدل qualification نمی‌شوند. ready_for_apply=false و no_leak_certified=false.

## گیت‌ها و ادامه

هویت native برنامه و file replacement/reparse/ACL، رضایت دقیق محتوا و Apply، baseline تازه، foreign Allow و effective policy، approval و service filter حمل SSTP، DNS/certificate/underlay bootstrap، تعلیق داده در disconnect، جمع‌کردن scopeدار مجوزهای مود قبلی و اتصال‌های برقرار، native journal/recovery و packet/reboot/reconnect هنوز لازم‌اند. blanket Block-all rule با default Block+Allow انتخابی یکسان نیست؛ قواعد Allow قبلی با default Block خودبه‌خود حذف نمی‌شوند. hash/selection فقط draft است و برای گشودن این گیت‌ها کافی نیست.

مرحلهٔ بعد local program-and-destination review برای نصاب و سپس composition با baseline/transport است؛ نه تکرار آزمون عمومی یا old Apply. کاربر فعلاً اقدام ندارد، journal محافظت‌شده و شبکه/SSTP همان وضعیت بماند. بستهٔ Windows یا تغییر واقعی شبکه در این milestone تحویل/اجرا نشده است.


## گام جدید — مشاهدهٔ محلی EXE، بدون اجرای برنامه

[بسته و شرح](../analysis/unifiedfw-session-2026-10-27/program-review-v01/package/UFW-PROGRAM-REVIEW-01/README-FA.md) و [C# reader](../analysis/unifiedfw-session-2026-10-27/program-review-v01/package/UFW-PROGRAM-REVIEW-01/ProgramReader.cs) ساخته شد. مسیرهای واقعی را کاربر فقط محلی وارد می‌کند؛ برنامهٔ انتخابی اجرا نمی‌شود و program config ذخیره نمی‌شود. مشاهدهٔ file handle/path/metadata/two SHA256 و PE header، جای ACL/trust/Authenticode/approval یا pin دائمی نیست. والدها root-to-leaf بدون دنبال‌کردن reparse باز و تا پایان pin می‌شوند؛ fixed local drive، hardlink=1، EXE header x86/x64، محدودیت اندازه؛ mapped/UNC/reparse/ناسازگاری/busy fail می‌کنند. این native behavior هنوز روی Windows اجرا نشده است.

۱۴۷ assertion با C# compile واقعی روی Linux، path/PE fixture، metadata reflection mock، prompt/native observation mock، cancel/duplicate/max/error/privacy و static boundary پاس شد؛ دو PS1 و bootstrap/manifest/ZIP کنترل شدند. خط ادعایی Windows file API/WinPS5.1/هویت واقعی اجرا نشده است. source/test/evidence همگی بدون اطلاعات واقعی کاربرند. Add-Type ممکن است compiler Temp/cache ایجاد کند؛ فقط خواندن EXE منتخب و نوشتن گزارش درخواست شده، نه اجرای آن یا تغییر شبکه.

اقدام تازهٔ کاربر: ZIP در پوشهٔ جدا، Run-Review.cmd با دوبارکلیک معمولی (admin لازم نیست)، فقط مسیر واقعی EXE نصاب موجود و در صورت نیاز helper مشخص؛ Enter پایان/لغو. خود installer/update هم‌زمان اجرا نشود. فقط JSON تازه حتی در شکست ارسال شود، نه مسیر/hash/fileID/فایل EXE/عکس یا transcript خصوصی. اگر فایل نصاب موجود نیست Enter/cancel؛ فایل ساختگی/نامربوط انتخاب نشود. شبکه/SSTP و ژورنال قبلی بدون تغییر؛ storage/preparation/reopen موفق تکرار نشوند.

نتیجهٔ موفق این مرحله فقط observation/review همان اجراست؛ raw هویت در حافظه/console می‌ماند و persist نمی‌شود؛ در مرحلهٔ آینده انتخاب و revalidation تازه لازم خواهد بود. recorder، destination approval، native policy application/recovery، SSTP bootstrap/binding و mode-switch همچنان ساخته/qualified نشده‌اند. profile برنامه‌محور و یک active حفظ می‌شود؛ ready_for_apply/no_leak=false.
