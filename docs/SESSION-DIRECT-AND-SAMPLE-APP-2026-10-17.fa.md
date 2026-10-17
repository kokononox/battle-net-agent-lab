# ادامه ترتیبی: خواندن مستقیم و برنامه نمونه سرتاسری

## مرحله خواندن مستقیم

ثبت‌شده در commit `ae69ad15acda13212730d12b71bffaf896eb5ef1` روی `patch-audit-20261016`.

- `owned_v8_lock.py`: lease محدود به پردازش/root/عمر context قفل.
- تنها تغییر در چرخه قبلی: ثبت lease در `retail_v8_cycle.locked` بعد از flock؛ protocol انتشار عوض نشده.
- `agent_archive_direct.py`: پذیرش فقط root strict V8 زیر lease فعال، بازکردن FD فقط‌خواندنی و pin کردن inode واقعی data.000.
- `research/archive-direct-9824/native/`: همان fragmentهای اصلی با آداپتور جدید CreateFileW → Linux dup روی FD پین‌شده؛ نه pathname open یا اجرای Windows.
- descriptor همان lock نیز به child ارث داده می‌شود.
- `retail_direct_cycle.py`: lookup → direct cached read → span parser → کنترل مستقل BLTE/EKey/CKey.
- 117 تست واقعاً دوباره اجرا شد: 73 قبلی + 24 چرخه مستقیم + 20 مرز FD/lease. هر 9 توقف/بازیابی مسیر مستقیم و 9 رگرسیون snapshot پاس شدند.
- snapshot و marker اضافه در مسیر مستقیم صفر است. reader سطح بالاتر کامل، native BLTE و Windows اثبات نشده‌اند.

## شروع اجرایی مرحله سرتاسری

`retail_sample_updater.py` اکنون CLI پژوهشی Linux و آفلاین برای همان جفت واقعی پین‌شده دارد:

- init: Portable را کامل بررسی و workspace تازه source-only می‌سازد.
- plan: فقط همین رابطه PA و source/patch/target را گزارش می‌کند؛ تعیین نسخه و برنامه build کامل نیست.
- update: اعمال patch، re-encode دقیق، gateهای اصلی، انتشار سفارشی Linux و resume.
- status: اعتبارسنجی تازه وضعیت با همان gateها.
- export: target committed را از آرشیو زنده می‌خواند و decode می‌کند؛ فایل decoded مستقل و بدون overwrite می‌نویسد.

خروجی واقعی 33940 بایت، CKey=`3d42bf2e42127f313b0ec64cb440cde9` و SHA-256=`3818ed3b407ad07a407fb104a65c03ab39f8a89e86937ea4e261e26b99c71bd9` است. export از فایل target.decoded داخل Portable کپی نمی‌کند.

27 تست برنامه، شامل 9 توقف CLI واقعی و resume و export دقیق پاس شد. کل 144 تست با هم دوباره اجرا شد؛ failure/error/skip صفر. این عدد جمع با 814 تاریخی نیست. 9 failpoint در سه suite snapshot/direct/CLI اجرا شده، نه 27 نقطه مستقل جدید.

اصل Portable، بازی، Lab و .build.info تغییر نکرده؛ main و Release نیز دست‌نخورده‌اند. هیچ رمز/cookie/token در commitها نیست. Encoding در init از فایل ذخیره‌شده و آفلاین hash شد، نه دانلود مجدد. runner تست از template آماده استفاده می‌کند و آن را مجدداً scan نمی‌کند.

## مسیرهای محلی موجود

همه مسیرها فیزیکی‌اند؛ `/data` در این محیط symlink است و guard مسیر آن را رد می‌کند.

- `/vercel/sandbox/data/sample-updater-v1`: template برنامه source-only و ورودی بازتولید؛ تغییر ندهید.
- `/vercel/sandbox/data/sample-updater-final-v2-evidence`: smoke-workspace، export واقعی، trace و کل شواهد تست.
- `/vercel/sandbox/data/direct-native-v1/archive_direct_oracle`: oracle مستقیم جدید، فرمت receipt=`agent-archive-direct-build-1`.
- `/vercel/sandbox/data/direct-final-reproduction`: شواهد 117 تست مرحله مستقیم.
- oracleهای bind/lookup/span و ورودی‌های checkpoint قبل همچنان موجودند.

## مرز محصول و ادامه

این CLI نه updater کامل بازی، نه downloader شبکه‌ای و نه .exe ویندوز است. خروجی همه فرمان‌ها installation_ready=false دارد. دریافت از CDN، نسخه‌یابی نصب، برنامه‌ریزی build کامل، انتخاب source عمومی، چند object/ESpec، fallback به full، حجم واقعی archive، Windows و قطع برق انجام نشده‌اند.

init ناقص resumable نیست و fail-closed است؛ resume آزموده‌شده مربوط به update است. export نیز ممکن است در hard crash فایل موقت باقی بگذارد. همکاری قفل‌ها جلوی نویسنده غیرهمکار/مهاجم را به‌طور قطعی نمی‌گیرد.

ادامه به ترتیب: تکمیل ورودی/برنامه build و provider دریافت در محیط جدا، سپس تعمیم چند object، سپس اجرای Windows و آزمون روی کپی نصب. برای ادعای رفتار واقعی نصب، inventory خواندنی نصب هدف و محیط Windows لازم خواهد بود؛ Portable تک‌نمونه جای آن‌ها را نمی‌گیرد.
