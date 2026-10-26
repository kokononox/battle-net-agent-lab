# G72 — مسیر نامنطبقِ مشاهدهٔ جدید به ProductConfig عمومی bts وصل شد

## نتیجهٔ اصلی
ابهام مشخصِ field و مسیر CDN در مشاهدهٔ نهایی حل شد: leaf key همان مقدار کامل ستون **ProductConfig** محصول **bts** بود؛ این مقدار هم در پاسخ‌های جفت‌شدهٔ `/bts/versions` و `/v2/products/bts/versions` و هم در دریافت عمومی مستقلِ پیش از اجرای target، equality دقیق داشت. ستون 6 صفرمبناست. این مقایسه در RAM انجام شد و raw key صادر نشد.

**کل مسیر CDN هم برابر مرجع مستقل بود، نه فقط leaf یا شکل هش.** مسیر از ProductConfig در versions عمومی، ConfigPath در cdns عمومی و fanout دقیق دو/دو/کلید مشتق شد؛ Host هدف در metadata عمومی اعلام شده بود. query، spelling متفاوت یا fanout نادرست از این تطبیق عبور نمی‌کند. بدین ترتیب همان یک observation مسیر نامنطبق نسبت به catalog G69 در اجرای نهایی، اکنون پایهٔ عمومی مستقل دارد. این نتیجه به‌تنهایی allow rule تازه‌ای ایجاد نکرد.

config عمومی مربوطه نیز مستقل دریافت شد: 308 بایت JSON معتبر؛ MD5 محتوا دقیقاً با ProductConfig اعلام‌شده در versions برابر بود. فایل اجرایی/پیش‌نیاز دریافت نشد. این checksum/pin امضای ناشر نیست. بدنهٔ پاسخ واقعی target با فایل مستقل در این مرحله byte-for-byte مقایسه نشده؛ شواهد مثبت عبارت‌اند از field equality، whole-path equality و اعتبارسنجی محتوای **دریافت مستقل**. وابستگی علّی یا نبود تمام fingerprintها ادعا نمی‌شود.

## چرا G71 فیلد را نمی‌شناخت
header واقعی از `VersionsName!String:0` استفاده می‌کند. regex قدیمی فقط `STRING` تمام‌بزرگ را می‌پذیرفت؛ یک ستون mixed-case باعث ردشدن کل schema می‌شد. قالب، جدول typed معتبر بود، نه اینکه لزوماً JSON/MIME ناشناخته باشد. اصلاح فقط پذیرش case-insensitive نوع‌های مشخص STRING/HEX/DEC است؛ نام field یا نوع دلخواه حدس زده نمی‌شود. regression test هر دو versions واقعیِ پین‌شده و کنترل TLS بومی همین حالت را پوشش می‌دهند.

عامل دوم، نبود metadata محصول **bts** در مجموعهٔ مستقل قبلی بود؛ مسیرهای bnt قبلی 404 می‌دادند و جای bts نیستند. نام bts پیش از target در summary مستقل عمومی وجود داشت. پس از شناسایی route در مشاهدهٔ اول، metadata ثابت bts به‌طور مستقل دریافت شد؛ هیچ leaf key یا URL دلخواهِ target برای ساخت GET مستقل بازتاب داده نشد.

## نکتهٔ مهم دربارهٔ ستون Region در bts
در snapshot عمومی bts، برچسب‌های Region، selector محصول‌اند و ردیف‌های us/eu در versions وجود ندارند. تنها ردیف `launcher` ProductConfig غیرخالی داشت. بنابراین فرض Region=us یا Region=bna نادرست بود و در بررسی آفلاین رد شد.

برای bts فقط ProductConfig مشتق می‌شود و فقط وقتی **ConfigPath غیرخالی در تمام ردیف‌های cdns عیناً یکسان باشد** و Host هدف در metadata اعلام شده باشد. این شرط در مرجع برقرار بود: prefix از تمام regionها مستقل بود. BuildConfig/CDNConfig این محصول با این استثنا مشتق نمی‌شوند؛ هیچ region یا fallback حدسی وارد قاعده نشد. تست ناسازگاری ConfigPath نیز مثبت شدن نادرست را رد می‌کند.

## اجراها و صحت کنترل‌ها
- پیش‌اجرا [40300241533](https://github.com/kokononox/battle-net-agent-lab/actions/runs/40300241533): در تستِ pin فایل JSON جدید متوقف شد؛ dependency/native fixture، firewall و target هنوز اجرا نشده بودند. مرجع جدید از working tree ویندوز کپی می‌شد؛ خواندن تمام overlayها نیز به bytes مستقیم Git blob تغییر کرد. pin حفظ شد، نه اینکه hash جدیدِ working tree پذیرفته یا کنترل حذف شود. نوع دقیق تفاوت بایتِ working tree در log ثبت نشده بود؛ تبدیل پایان‌خط علت محتمل است.
- مشاهدهٔ واقعی اول [40300539643](https://github.com/kokononox/battle-net-agent-lab/actions/runs/40300539643)، source `706e9695b44207168869e5ac611e31aa95b4ba23`: موفق، 120.4 ثانیه؛ field و route مشخص شدند، ولی چون مرجع bts هنوز نبود، public match عمداً false ماند.
- مشاهدهٔ تکمیلی [40301741045](https://github.com/kokononox/battle-net-agent-lab/actions/runs/40301741045)، source `4c1c84b55fe3f88a4a79b4551df829093625cff1`: موفق، 120.3 ثانیه؛ equality مستقلِ ProductConfig و کل مسیر CDN مثبت شد. 12 درخواست و 12 پاسخ کامل جفت شدند، با صفر context ردشده، صفر buffer باقی‌مانده و صفر درخواست بی‌پاسخ در دامنهٔ parser.
- دو پاسخ کاملِ پیش از observation ارسال، field equality داشتند؛ این دو پاسخ، دو منبع مستقل یا اثبات causality نیستند.
- 134 تست Windows و هر 12 کنترل بومی x86/x64 گذشتند. Linux یک skip مختص Windows داشت. fixtureهای TLS نیز type marker مختلط واقعی را آزمایش کردند؛ آمار آن‌ها وارد دادهٔ واقعی نشد.
- در هر دو مشاهدهٔ واقعی، error تهی، firewall verify و cleanup موفق بود. cache گواهی آنلاین و آفلاین موفق بود؛ revocation/اعتبار TLS ضعیف نشد. اجرای دیگری خودکار آغاز نشده است.

## وضعیت مرتبط با هدف اصلی
در مشاهدهٔ نهایی 34 observation API مربوط به CDN بود. 33 مسیر کامل با catalog مستقل قدیمی تطبیق داشتند و یک مسیر با مرجع مستقل تازهٔ bts تأیید شد؛ بنابراین هر 34 observation در این اجرا، پایهٔ عمومیِ **مسیر کامل** دارند. این‌ها شمار درخواست شبکهٔ یکتا نیستند و به‌معنای تأیید همهٔ خصوصیات درخواست نیستند.

**یک Range هنوز حل نشده است:** از 13 observation دارای Range، 12 مرز دقیق عمومی داشتند و یکی با `no_independent_range_reference` باقی ماند. offset آن صفر است و در محدودهٔ اندازهٔ عمومی قرار دارد، اما این برای تأیید مرز دقیق کافی نیست. این مسئله از مسیر config نامنطبقِ اکنون حل‌شده جداست.

Runtime همچنان همان `us.version.battle.net` و `level3.blizzard.com` به‌علاوهٔ استثنای قبلی مدیریت CI است. مقصد یا allow rule جدید اضافه نشد. main و Unified Firewall Desktop 0.9.10 تغییر نکردند. هیچ login، Install click یا دانلود کامل انجام نشد.

## مرز نتیجهٔ حریم خصوصی
- عمومی بودن مقدار ProductConfig و path، نبود شناسهٔ خصوصی در تمام کانال‌ها یا بی‌خطر بودن timing/selection را ثابت نمی‌کند. GET، بدنهٔ خالی و allowlist دامنه هم تضمین نیستند.
- 48 ReadFile دارای overlapped I/O در ردیاب منشأ قدیمی gap باقی ماند. mmap، API/فرایندهای دیگر و دانلود کامل پوشش کامل ندارند.
- accounting outgoing API برقرار بود: 9,470 بایت، شامل 4,378 بایت HTTP candidate و 5,092 بایت record کامل TLS. cap یا byte-buffer طبقه‌بندی‌نشده باقی نماند. TLS framing معادل تأیید plaintext نیست و نگاشت یک‌به‌یک ciphertext به SSPI ثابت نشده است.
- raw key/path/query/row/response واقعی صادر نشد؛ فقط field/route عمومیِ شناخته‌شده، کلاس‌های ساختاری و نتایج equality صادر شدند. فایل reference حاوی دادهٔ عمومی مستقل است، نه capture خام target.
- equality یک raw key مشخص بین تمام اجراهای تاریخی G69–G72 قابل اثبات نیست، چون مقدار خام تاریخی نگه داشته نشده بود. ادعای حل، مربوط به همان کلاس مسیر نامنطبق در **مشاهدهٔ جدید و مستند G72** است؛ تاریخچهٔ قدیمی با حدس بازنویسی نمی‌شود.

## مرجع مستقل و دریافت پژوهشی
summary عمومی ثابت و metadata agent_beta/agent_redist پیش از مشاهدهٔ اول دریافت شدند؛ این دو محصول منشأ کلید target نبودند. پس از شناسایی bts، دو metadata ثابت versions/cdns و config با کلید **برگرفته از versions عمومی** قبل از مشاهدهٔ تکمیلی دریافت و پین شدند. receiptهای bts در `bts-reference-receipts.json` هستند؛ schema/reference کامل در source مرحله نگهداری می‌شود.

برای config، Host/path از cdns/versions عمومی bts آمد. bts در Servers، HTTP را اعلام می‌کند؛ دریافت پژوهشی با HTTPS همان us.cdn شناخته‌شده انجام شد و قابلیت HTTPS این Host در metadata عمومی مستقل دیگر اعلام شده بود. MD5 محتوای دریافت‌شده با کلید رسمی برابر بود. این دریافت جدا از runtime بود و هیچ دسترسی نصب‌کننده را گسترش نداد.

## گام بعدیِ محدود
بررسی برابری دقیق Range باقی‌مانده با اندازه/مرز شیء عمومی، سپس پوشش پیوستهٔ مسیر دانلود کامل تحت همان محدودیت‌ها. در این مرحله دیگر نیازی به تکرار جست‌وجوی منشأ ProductConfig bts یا آزمون دوبارهٔ نصب/TLS برای این ابهام نیست. هدف اصلی، دانلود مجاز بدون ارسال fingerprint است؛ G72 یک مانع مشخص را برداشت، نه اینکه آماده‌بودن محصول نهایی یا نبود تمام fingerprintها را اعلام کند.

## شواهد و بازتولید
`runtime.json` و `control.json` مربوط به مشاهدهٔ تکمیلی‌اند؛ `initial-runtime.json` و `initial-control.json` مشاهدهٔ اول را جدا حفظ می‌کنند. `manifest.json` یافته‌ها و حدود ادعا را ثبت می‌کند. `analyze.py` هویت run/source، شمارش مستقل hierarchy، مرجع schema، MD5 config و reconciliation را کنترل می‌کند. برای استفاده از فایل‌های گزارش، مسیرها را با `--runtime`، `--control`، `--initial` و `--source-dir` بدهید؛ `--artifact` اختیاری برای بازبررسی SHA256 ZIP است و `--out` محل خروجی را تعیین می‌کند.

SHA256 artifact اول `6651e80aabfb62158dda75a43fc8685bec88df94f3bcb4cd2f17e53c86e17f12` و تکمیلی `e50a1b3bcef45ce97eff3e286777d3b7dfacae20fe91eafd62670e473972e648` است؛ هر دو با digest صفحهٔ GitHub مقایسه شدند.

profiler، runtime ناهمگن را مستقیم نپذیرفت؛ آرایهٔ request rows جدا profile شد: 46 observation با 17 تکرار پالایش‌شده، همگی حفظ شدند. null بودن public_download_path برای ردیف‌های سرور نسخه طراحی‌شده است؛ constant بودن method/body و falseهای privacy دلیل نبود fingerprint نیست. nullهای error کنترل یعنی خطایی ثبت نشده؛ run_id شناسه است نه معیار عددی.
