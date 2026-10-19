# پیشنهادات مدل‌های دیگر

<!-- project-current-status-link:start -->
> **پیش از پیشنهاد تازه، [وضعیت جاری و گام فعال پروژه](STATUS.fa.md) را بخوانید.** عامل اجرایی همان فایل را پس از نتایج/تصمیم‌های مهم در جلسات فعال به‌روز می‌کند. تحلیل تاریخیِ پایین، بر مبنای `2614b3a` است و شواهد جدید H1/U1 را پوشش نمی‌دهد؛ متن پیشنهادهای همکاران بدون تغییر حفظ شده است.
<!-- project-current-status-link:end -->


> این سند فقط پیشنهاد است، نه تصمیم یا مجوز. هیچ workflow، کد یا گزارشی با آن تغییر نکرده است. مبنای بررسی: README، `NEXT-STEPS.fa.md`، `UPDATER-REMAINING.fa.md`، `CLASSIC-BASELINE-EXPERIMENT.fa.md`، `reports/classic-install-latest.json`، `reports/classic-disk-latest.json` و `reports/classic-old-build-69722-availability.json` در commit `2614b3a`.

## ۱. جمع‌بندی وضعیت از نگاه بیرونی

- هدف اصلی طبق README **اثبات تله‌متری WoW در سطح فیلد/درخواست/مقصد** است؛ دانلودر/اپدیتر «پیش‌نیاز موقت» اعلام شده است.
- با این حال، بیشتر کار (۲۷ نسخهٔ اپدیتر، ده‌ها run) صرف پیش‌نیاز شده و پرچم‌های کلیدی هنوز false هستند: `installation_ready`، `required_set_selected`، `vendor_selection_policy_qualified`.
- آخرین اجرای نصب Classic (`run 39143903496`) روی فرم Agent متوقف شد با سه مانع: `eula_review_pending`، `game_dir_error=800`، `minimum_spec_error=2513`. حدود ۱۰ اجرای `classic-install` پشت‌سرهم ثبت شده است.

## ۲. پیشنهاد اصلی: پیش‌نیاز را از مسیر رسمی تأمین کنید و به هدف اصلی برگردید

بزرگ‌ترین ریسک پروژه این است که «پیش‌نیاز موقت» خودش به پروژهٔ اصلی تبدیل شده است (CASC writer تراکنشی، policy انتخاب Retail، cache، rollback). پیشنهاد:

1. بازی را با **اپ رسمی Battle.net روی دستگاه/VM خود کاربر و با حساب خود کاربر** نصب و آپدیت کنید. این سریع‌ترین مسیر به یک کلاینت سالم و به‌روز است و برای مطالعهٔ تله‌متری کافی است.
2. پروژهٔ اپدیتر مستقل را به حالت «پارک‌شده/تحقیقاتی» ببرید و از مسیر بحرانی هدف اصلی خارج کنید. اسناد فعلی آن (UPDATER-REMAINING) برای ادامهٔ بعدی کافی‌اند.
3. معیار توقف صریح برای پیش‌نیاز تعریف شود؛ مثلاً: «اگر تا N اجرای دیگر baseline کامل نشد، مسیر رسمی جایگزین می‌شود».

## ۳. مسیر runner میزبانی‌شدهٔ GitHub برای نصب بازی ساختاراً بسته است

- `min_spec_error=2513` روی runner بدون GPU/دسکتاپ تعاملی قابل رفع مشروع نیست و پروژه به‌درستی دورزدن حداقل سخت‌افزار را ممنوع کرده است. پس تکرار همین run نتیجهٔ متفاوتی نمی‌دهد.
- `eula_review_pending`: پذیرش EULA تصمیم حقوقی خود کاربر است و نباید خودکار شود؛ این هم روی runner بدون حضور کاربر حل‌شدنی نیست.
- نصب پایدار هم با حذف VM از بین می‌رود، پس baseline برای آزمون نسخه‌به‌نسخه آنجا ماندگار نمی‌ماند.
- استفادهٔ طولانی از GitHub Actions برای دانلود/نصب بازی ممکن است با هدف و قواعد استفادهٔ Actions هم‌خوان نباشد؛ بهتر است کار سنگین از Actions خارج شود.

**پیشنهاد:** حلقهٔ `classic-install` روی runner متوقف شود. اگر baseline لازم است، روی یک Windows VM محلی دورریختنی (Hyper-V/VirtualBox با snapshot) و با حضور کاربر برای EULA انجام شود. snapshot قبل از آپدیت، همان «baseline قدیمی ماندگار» را می‌دهد که آزمون نسخه‌به‌نسخه لازم دارد.

نکات جانبی اگر باز هم روی runner ادامه داده شد:
- آستانهٔ ۴۰GiB برای Classic Era (حجم انتخاب‌شدهٔ build قدیمی حدود ۴٫۸GB encoded) بیش از حد محافظه‌کارانه است و پاک‌سازی toolchainها را تحمیل کرده؛ آستانه را از `game_dir.required_space` خود فرم × ضریب اطمینان محاسبه کنید.
- `game_dir_error=800` را پیش از هر اجرای تازه با مقادیر `required_space`/`required_space_info`/`warning` (که الان فقط نوعشان export می‌شود) تشخیص دهید؛ export مقدار عددی این فیلدها بی‌خطر است.

## ۴. پیشنهاد برای هدف اصلی: اثبات تله‌متری در سطح فیلد

معیار موفقیت پروژه «فیلد → درخواست → مقصد → زمان/مرحله» است و رمزگشایی TLS بازی و دست‌زدن به anti-cheat کنار گذاشته شده‌اند. با این قید، مسیرهای پیشنهادی:

1. **درخواست دسترسی به داده (GDPR، مادهٔ ۱۵) از Blizzard.** قوی‌ترین منبع مشروع برای «کدام فیلدها جمع‌آوری می‌شوند» است و هیچ دست‌کاری فنی لازم ندارد. پاسخ رسمی را با مشاهدات شبکه تطبیق دهید.
2. **مشاهدهٔ سطح سیستم‌عامل بدون رمزگشایی:** ETW (`Microsoft-Windows-TCPIP`، `Microsoft-Windows-DNS-Client`)، Sysmon (رویداد 3 و 22) یا `pktmon` برای مقصد، زمان، حجم و فرایند مبدأ هر اتصال. این «درخواست/مقصد/زمان/مرحله» را می‌پوشاند.
3. **آزمایش تفاضلی:** هر تنظیم حریم خصوصی/اشتراک داده در اپ Battle.net و تنظیمات بازی را خاموش/روشن کنید و تفاوت مقصدها، دفعات و حجم ارسال را در مراحل pre-login، login و in-world مقایسه کنید. تفاوت معنادار، اتصال «تنظیم → درخواست» را اثبات می‌کند.
4. **مسدودسازی کنترل‌شده روی دستگاه خود کاربر:** مسدودکردن یک مقصد مشکوک (مثلاً در فایروال ویندوز) و ثبت اینکه کدام قابلیت از کار می‌افتد، بدون تغییر در باینری یا حفاظت بازی.
5. **منابع محلی خود بازی:** پوشه‌های `Logs`، `Errors` و فایل‌های `WTF/Config.wtf`، و سیاست حریم خصوصی رسمی Blizzard به‌عنوان شاهد مستقل.

همهٔ این‌ها با قواعد فعلی پروژه سازگارند: بدون انتشار token/cookie/شناسهٔ حساب، فقط دادهٔ redacted.

## ۵. پیشنهادهای فرایندی

- **یک فایل وضعیت واحد:** بنرهای پشت‌سرهم «متن پایین سابقه است» در NEXT-STEPS خواندن را سخت کرده‌اند. یک `STATUS.fa.md` کوتاه (هدف، مانع فعلی، تصمیم بعدی، تصمیم‌های منتظر کاربر) و انتقال بقیه به HISTORY پیشنهاد می‌شود.
- **تصمیم‌های منتظر کاربر صریح شوند:** (الف) ادامه یا توقف مسیر runner؛ (ب) نصب رسمی روی دستگاه/VM خود کاربر؛ (ج) ارسال درخواست GDPR.
- **بودجهٔ تلاش:** برای هر مسیر سقف تعداد run/جلسه تعیین شود تا تکرار بی‌نتیجه زود تشخیص داده شود.

## ۶. ترتیب پیشنهادی گام‌ها

1. توقف حلقهٔ نصب روی runner و ثبت دلیل (min_spec و EULA).
2. نصب رسمی بازی روی دستگاه/VM کاربر با حساب خودش.
3. ارسال درخواست GDPR به Blizzard (موازی، چون پاسخ هفته‌ها طول می‌کشد).
4. راه‌اندازی ثبت ETW/Sysmon و اجرای آزمایش تفاضلی در سه مرحلهٔ pre-login/login/in-world.
5. تطبیق نتایج با پاسخ GDPR و نوشتن جدول «فیلد → درخواست → مقصد → مرحله».

---

## ۷. پیشنهادهای Notion AI — بر مبنای وضعیت H1/U1

> این بخش هم فقط پیشنهاد است، نه تصمیم یا مجوز. مبنای بررسی: `docs/STATUS.fa.md` در commit `5eea0d3` (به‌روزرسانی 2026-10-18 22:32 UTC). هیچ کد، workflow یا گزارشی با آن تغییر نکرده است.

### ۷.۱. پیش از اجرای SelfTest روی سیستم کاربر
- **معیار پاس/شکست از قبل مکتوب شود:** کدام فیلدهای `selftest-to-share-….json` باید OK باشند (تأیید امضا، نصب hook روی `send`/`WSASend`/`EncryptMessage`، بکاپ و بازیابی hosts). این کار از تفسیر پس‌از‌واقعه جلوگیری می‌کند.
- **تطبیق SHA256 فایل ZIP دانلودشده** با رسید build، تا اطمینان حاصل شود همان بستهٔ مبتنی بر `a735312` اجرا می‌شود.
- **قالب کوتاه گزارش کاربر:** نسخهٔ ویندوز، هر هشدار Windows Security، متن خطا و مدت اجرا.

### ۷.۲. جداکردن دو سؤال در گام بعد
اکنون «آیا آپدیت با بلوک دامنه کار می‌کند؟» و «چه داده‌ای می‌رود؟» در یک اجرا ترکیب شده‌اند. چون تزریق مشاهده‌گر خودش می‌تواند پایداری/زمان‌بندی را تغییر دهد، شکست آپدیت در آن حالت قابل انتساب نیست. پیشنهاد:
- **اجرای الف:** فقط بلوک hosts + فرادادهٔ pktmon/ETW، بدون تزریق؛ پاسخ تمیز به سؤال ۲ وضعیت.
- **اجرای ب:** همان شرایط + مانیتور U1، برای مشاهدهٔ محتوای درخواست‌ها.

### ۷.۳. نقاط کور بلوک با hosts
- پیش از شروع `ipconfig /flushdns` اجرا و ثبت شود.
- IPهای `telemetry-in.battle.net` پیش از بلوک resolve و ثبت شوند و در فرادادهٔ شبکه اتصال به آن‌ها بررسی شود (با درنظرگرفتن IP مشترک CDN).
- احتمال DoH یا IP ثابت درون برنامه در نظر گرفته شود؛ صفرشدن درخواست به دامنه به‌تنهایی آن‌ها را رد نمی‌کند.

### ۷.۴. معیار موفقیت و توقف آپدیت واقعی
- **موفقیت:** آپدیت کامل شود، دکمهٔ Play فعال شود، build در `.build.info` درست باشد، اتصالی به دامنهٔ بلوک‌شده نباشد و Host تازه‌ای در فهرست ظاهر نشود.
- **توقف:** گیرکردن بیش از N دقیقه، خطا یا کرش Agent ← detach، بازیابی hosts و ثبت خطا؛ برای دورزدن خطا Repair/Resume انجام نشود.
- **نسخهٔ Battle.net Agent قبل و بعد ثبت شود:** Agent ممکن است ابتدا خودش را آپدیت کند؛ در آن صورت هش باینری‌ها با H1 متفاوت و مقایسه ناهمسان می‌شود.

### ۷.۵. آزمون ارزان برای سؤال ۴ (fingerprint)
CASC محتوامحور است؛ اگر هش فایل‌های دادهٔ دانلودشده با content keyهای منتشرشده در CDN منطبق باشد، fingerprint اختصاصی کاربر در محتوای داده وجود ندارد. در این صورت جای محتمل شناسهٔ محلی فایل‌های متادیتا/محلی است: `.build.info`، `.product.db`، `WTF/`، `Cache/` و تنظیمات Agent. پیشنهاد می‌شود بررسی از این‌ها شروع شود، نه کل دادهٔ بازی.

### ۷.۶. پیشنهادهای مستندسازی
- **جدول «لاگ تصمیم‌ها»** (تاریخ، تصمیم، شاهد، commit) در STATUS؛ اکنون تصمیم‌ها در متن پراکنده‌اند.
- **برچسب وضعیت برای پیشنهادهای قدیمی** (پذیرفته / ردشده / منسوخ) کنار هر بند بخش‌های ۱ تا ۶، چون بر `2614b3a` نوشته شده‌اند؛ تا پیشنهادهای تکراری داده نشود.
- **ثبت دقیقه‌های مصرف‌شدهٔ Actions** برای هر run، تا هزینه قابل پیگیری باشد.

### ۷.۷. ترتیب پیشنهادی
1. ۷.۱ و ۷.۴ (همین الان، بدون اجرای جدید).
2. پس از پاس‌شدن SelfTest: اجرای الف، سپس اجرای ب (۷.۲).
3. پس از موفقیت آپدیت با بلوک: ۷.۳ و ۷.۵.

---

## ۸. پیشنهادهای Notion AI — بر مبنای نخستین گزارش T1.1

> ثبت‌شده در 2026-10-19. این بخش صرفاً پیشنهاد و نقد است، نه تصمیم اجرایی، مجوز آزمایش یا شاهد اجرای موفق. فقط همین سند تکمیل می‌شود؛ کد، BAT، hosts، فایروال، workflow و گزارش‌های پروژه با این ثبت تغییر نمی‌کنند. پیشنهادهای پیشین، از جمله بخش ۷، خودکار اقدام جاری محسوب نمی‌شوند.

### مبنای بازخورد
- [وضعیت بررسی‌شده](https://github.com/kokononox/battle-net-agent-lab/blob/2b1eb498e75a6709a45e65a1602f13767c3b8aaf/docs/STATUS.fa.md) و [تحلیل نخستین گزارش T1.1](https://github.com/kokononox/battle-net-agent-lab/blob/2b1eb498e75a6709a45e65a1602f13767c3b8aaf/reports/level3-audit-t11-user-analysis.fa.md)، هر دو در commit `2b1eb498e75a6709a45e65a1602f13767c3b8aaf`.
- ۲۶ درخواست بازسازی‌شده Level3 شاهد محدود و مفیدند؛ چهار مقصد عمومی TCP/443 متعلق به `battle.net.exe` با `input_events=0` شکاف پوشش باقی می‌گذارند. این مشاهده اثبات «فقط آپدیت» یا «صفر تله‌متری» نیست.
- پیشنهاد اصلی: فعلاً BAT تغییر نکند و همان نمونه Level3 تکرار نشود؛ ابتدا روشن شود مشاهده‌گر چه چیزی را نمی‌بیند و چرا.

### ۸.۱. پیش از فرض TLS متفاوت، فعالیت همان اتصال را مشخص کنید
- **سؤال تمایزبخش:** آیا پس از نصب hook، روی همان اتصال و از همان فرایند واقعاً ارسال جدید رخ داده است؟ وجود اتصال در snapshot به‌تنهایی پاسخ نیست.
- **شاهد پیشنهادی:** زمان attach و نصب hook، PID همراه زمان ایجاد فرایند و هش باینری، شناسه اتصال شامل عمر آن و endpointها، و در صورت امکان فراداده فعالیت مستقل همان اتصال؛ بدون جمع‌آوری payload خام.
- **هدف:** تفکیک اتصال قدیمی یا بی‌فعالیت در پنجره مشاهده از API پوشش‌داده‌نشده، انتساب نادرست یا فقدان مشاهده. صفر بودن input event به‌تنهایی علت را مشخص نمی‌کند.
- **شرط توقف:** اگر فعالیت پس از نصب hook یا انتساب به همان فرایند قابل احراز نبود، نتیجه «نامعلوم» بماند؛ از همان داده علت TLS یا نبود ارسال نتیجه گرفته نشود.

### ۸.۲. شناسایی کتابخانه/API هدفمند و فقط‌خواندنی باشد
- ابتدا همان فرایند صاحب اتصال از نظر معماری، هویت باینری، ماژول‌های بارگذاری‌شده و APIهای قابل‌شناسایی بررسی شود؛ بدون تغییر BAT، hosts یا فایروال و بدون کنترل lifecycle فرایند یا اجرای بازی.
- BoringSSL/OpenSSL همچنان فرضیه‌اند. حضور یک کتابخانه یا نام API به‌تنهایی اثبات استفاده آن اتصال از آن مسیر نیست؛ انتساب مسیر به اتصال باید جداگانه اعتبارسنجی شود.
- این مرحله مجوز hook حدسی، تغییر TLS/certificate validation، استخراج کلید یا دست‌کاری حفاظت/ضدتقلب نیست. اگر مسیر قابل‌شناسایی نبود، خروجی درست «نامعلوم» است.

### ۸.۳. پیش از نمونه‌گیری دوباره از کاربر، کنترل مثبت متناسب تعریف شود
- اگر مسیر API/TLS مشخص شد، مشاهده‌گر ابتدا با کلاینت آزمایشی تحت‌کنترل و داده مصنوعی روی همان مسیر اعتبارسنجی شود؛ fixture عمومی Winsock به‌تنهایی تضمین پوشش مسیر دیگر نیست.
- **معیار پذیرش پیشنهادی:** ارسال معلوم دیده شود، ورودی API از ارسال موفق/دریافت سرور تفکیک بماند، خطا و موفقیت قاطی نشوند و مقدار خام حساس وارد JSON نشود.
- ساخت یا اجرای چنین آزمونی اقدام انجام‌شده نیست؛ نیازمند طراحی مشخص و رعایت دامنه مجاز است. اگر کنترل مثبت پاس نشد، از نبود رخداد در نمونه واقعی نتیجه محتوایی گرفته نشود.

### ۸.۴. parser باید علت رد یا ناتمام‌ماندن را گزارش کند
- طبق تحلیل مبنا، ۱۸۷ stream برچسب `parsed_to_end` دارند ولی ۲۶ request صادر شده است. stream و request واحد یکسان نیستند؛ تفاضل این دو تعداد «درخواست گم‌شده» نیست.
- شمارنده‌ها و وضعیت‌های صریح برای request صادرشده، Host نامعتبر، پورت پشتیبانی‌نشده، پیام ناقص و سایر علت‌های رد پیشنهاد می‌شود؛ بدون صدور مقادیر خام. پایان پردازش ورودی با audit موفق همه پیام‌ها یکی گرفته نشود.
- تست‌های تمایزبخش پیشنهادی: fragmentation، چند درخواست در یک اتصال و حفظ جداسازی اتصال‌ها؛ انتظار هر fixture پیشاپیش مشخص باشد.

### ۸.۵. وضعیت جاری از تاریخچه جدا شود
- در نسخه STATUS مبنای این بازخورد، نتیجه T1.1 بالای سند آمده، اما ردیف «اقدام بعدی کاربر» هنوز اجرای بسته و نمونه‌گیری را می‌گوید و پایین‌تر «هنوز READY/نمونه محتوایی سیستم کاربر نداریم» باقی مانده است. این ترکیب می‌تواند به تکرار آزمایش منجر شود.
- پیشنهاد: یک کادر کوتاه «اکنون / مانع / اقدام بعد / کارهای ممنوع فعلی» مرجع اقدام باشد و بخش‌های قبلی صریحاً تاریخی علامت بخورند؛ سابقه و متن همکاران حذف نشوند.
- این بند پیشنهاد مستندسازی است؛ با ثبت این بخش، خود STATUS تغییر نمی‌کند.

### تحویل بعدی و مرز اجرا
- تحویل پیشنهادی یک گزارش کوچک است: «صاحب اتصال کیست، فعالیت ارسال پس از نصب hook احراز شده یا نه، مسیر API چیست، پوشش چگونه اعتبارسنجی شده و چه چیزهایی همچنان نامعلوم‌اند».
- پیش از هر اجرای تازه، سؤال، شاهد مورد انتظار، هزینه/ریسک و شرط توقف مشخص شود. بازبینی اسناد و طراحی آزمون به‌خودی‌خود نیازمند runner یا دانلود/نصب دوباره بازی نیست.
- تا تصمیم بعدی، Pause مطابق وضعیت مبنا حفظ شود. این پیشنهادها مجوز Resume، login، تکمیل آپدیت، Repair، حذف/rollback بازی، تغییر block یا اجرای runner بزرگ/پولی نیستند.
- نتیجه Level3، پوشش HTTPS، تکمیل دانلود و سؤال fingerprint انتقال A→B جدا بمانند؛ از پاسخ یکی نتیجه دیگری گرفته نشود.

---

## ۹. بازخورد تازه Notion AI — پس از PASS واقعی S2، پیش از rollback و Apply

> مبنای بازبینی: commit `8b28e7929a3ac2ed984114bb54a80ae0e1af2e7b`، وضعیت ثبت‌شده در 2026-10-19 01:52 UTC. این بخش صرفاً پیشنهاد طراحی و آزمون است؛ نه مجوز اعمال ایزولاسیون و نه شاهد اجرای آزمون‌های زیر. فقط این سند تکمیل می‌شود؛ هیچ کد، policy، BAT، VPN یا فایل بازی با این ثبت تغییر نمی‌کند و هیچ workflow آزمایشی دستی راه‌اندازی نمی‌شود. متن بخش‌های قبلی حفظ شده است.

### ۹.۱. جمع‌بندی جدید و تغییر اولویت
- [STATUS مبنا](https://github.com/kokononox/battle-net-agent-lab/blob/8b28e7929a3ac2ed984114bb54a80ae0e1af2e7b/docs/STATUS.fa.md)، [درخواست نقد S2](https://github.com/kokononox/battle-net-agent-lab/blob/8b28e7929a3ac2ed984114bb54a80ae0e1af2e7b/docs/PEER-REQUEST-SSTP-S2.fa.md)، [تحلیل واقعی S2](https://github.com/kokononox/battle-net-agent-lab/blob/8b28e7929a3ac2ed984114bb54a80ae0e1af2e7b/reports/sstp-recovery-s2-user-analysis.fa.md) و [تحلیل واقعی S1](https://github.com/kokononox/battle-net-agent-lab/blob/8b28e7929a3ac2ed984114bb54a80ae0e1af2e7b/reports/sstp-preflight-s1-user-analysis.fa.md) خوانده شدند.
- پیشرفت معتبر: export/ACL/hash، اجرای زمان‌دار SYSTEM، receipt و cleanup روی دستگاه کاربر PASS شده‌اند. اما import، rollback واقعی، enforcement و قطع/وصل امن SSTP اثبات نشده‌اند؛ `ready_to_apply_isolation=false` درست است و فعلاً باید false بماند.
- تغییر جهت صریح کاربر به allowlist کل Windows پذیرفته شود. ادامه DLL/N2 و تکرار T1 یا S2 اولویت جاری نیست؛ پیشنهادهای بخش ۸ در این زمینه تاریخی‌اند، نه دستور ادامه خودکار.
- **اولویت پیشنهادی: ابتدا rollback محدود و قابل‌ممیزی، سپس اثبات enforcement.** هیچ‌یک به‌تنهایی نبود telemetry در مقصد مجاز یا نبود fingerprint انتقال A→B را ثابت نمی‌کنند.

### ۹.۲. P0 — rollback مبتنی بر delta و journal، نه import کورکورانه
**یافته/مستند:** `ActiveStore` حاصل سیاست مؤثر چند store از جمله GPO، PersistentStore و service hardening است؛ PersistentStore همان سیاست محلی پایدار است. بنابراین مقدار مؤثرِ دیده‌شده الزاماً همان مقداری نیست که باید در store محلی بازگردانده شود. برای مثال، بازگرداندن Allow مؤثر به‌جای مقدار محلی قبلی NotConfigured می‌تواند معنای تنظیم را عوض کند. [مستند storeها](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps). مستند netsh، export/import را برای policy store فایروال معرفی می‌کند، نه snapshot تراکنشی تمام route/VPN/ابزارهای WFP و نویسندگان همزمان سیاست؛ از آن تضمین بازگردانی کل شبکه نتیجه نگیریم و درباره پوشش IPsec نیز حکم کلیِ بدون بررسی ندهیم. [مستند netsh](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall).

**الگوریتم پیشنهادی برای بازبینی، نه patch اجراشده:**
1. snapshot تازه از مقدار محلی قابل‌ویرایش و نتیجه مؤثر بگیرید؛ نام داخلی rule و store، profile defaults و فیلترهای برنامه/سرویس/آدرس/پورت/interface را کامل و بدون truncation نگه دارید. فقط مواردی که قرار است تغییر کنند وارد مجموعه مجاز mutation شوند؛ Blockهای موجود، GPO و موارد با منشأ مبهم دست‌نخورده بمانند.
2. پیش از هر فرمان، intent پایدار بنویسید: شناسه جلسه/عملیات، هدف و property دقیق، مقدار قبلی `B`، مقدار مورد انتظار بعدی `A` و وضعیت اجرا. نوشتن باید قطع‌پذیری و کمبود فضای دیسک را تحمل/تشخیص دهد؛ پس از ثبت پایدار و arm شدن recovery تازه mutation مجاز شود.
3. پیش از mutation، مقدار جاری دوباره با `B` تطبیق داده شود؛ پس از آن مقدار واقعی با `A` کنترل و نتیجه در journal ثبت شود. crash میان اجرای فرمان و ثبت موفقیت، با بازخوانی وضعیت تعیین تکلیف شود، نه با تکرار کور فرمان.
4. در rollback، برای هر property تغییریافته مقدار جاری `C` را بسنجید: اگر `C=A`، به `B` برگردانید؛ اگر `C=B`، no-op؛ در غیر این صورت conflict ثبت کنید و مقدار خارجی را overwrite نکنید. rule افزوده‌شده فقط با هویت یکتا و تطابق تعریف مورد انتظار همان جلسه حذف شود؛ نه با wildcard یا نام نمایشی مشترک.
5. ترتیب برگشت وابستگی‌ها از قبل طراحی و تست شود و ترتیب ناموفق میانی هم پوشش داده شود؛ هدف برگشت فقط delta خود ابزار است. فایل .wfw پشتیبان خصوصی بماند، نه مسیر پیش‌فرض و بی‌قیدِ recovery.

**محدودیت مهم:** این compare/recheck، CAS اتمی فایروال نیست. mutex ابزار، GPO/EDR/مدیر دیگری را قفل نمی‌کند. حفظ هر تغییر خارجی و تضمین بازگشت کامل در همه تعارض‌ها همزمان قابل تضمین نیست؛ drift هم‌پوشان باید نتیجه `rollback_conflict` و توقف بدهد، نه PASS یا import کلی. برنامه recovery محلی برای چنین تعارضی باید پیش از تحویل تعریف شود؛ هیچ EmergencyReset عمومی یا تحمیل outbound=Allow جایگزین بازگردانی دقیق نشود.

### ۹.۳. P0 — چرخه عمر watchdog باید با probe فعلی فرق کند
**یافته مشخص منبع:** در `Recovery-Rehearsal.ps1`، بلوک `finally` حتی در مسیر شکست برای حذف task اقدام می‌کند؛ برای worker فعلی که فقط receipt می‌نویسد خطر تغییر شبکه ندارد، اما همین الگو نباید عیناً به Apply منتقل شود. worker فعلی نیز receipt را با `CreateNew` می‌نویسد؛ این رفتار به‌خودی‌خود الگوی rollback تکرارپذیر نیست. [main آزموده‌شده](https://github.com/kokononox/battle-net-agent-lab/blob/684626bec2cb7e7c610126b46187eb61db508e4b/sstp-recovery-s2/Recovery-Rehearsal.ps1)؛ [worker آزموده‌شده](https://github.com/kokononox/battle-net-agent-lab/blob/684626bec2cb7e7c610126b46187eb61db508e4b/sstp-recovery-s2/Rollback-Probe.ps1).

**طرح پیشنهادی:**
- ماشین حالت روشن: `PREPARED → ARMED → APPLYING → ROLLING_BACK → VERIFIED`؛ خطا/تعارض وضعیت جدا دارد. پیش از اولین تغییر شبکه، worker محلی، journal، deadline، ACL/hash و تعریف task شامل principal/action/trigger/settings بازخوانی و تأیید شوند. recovery به مرورگر، VPN، DNS یا دریافت فایل تازه وابسته نباشد.
- Apply، rollback دستی و task زمان‌دار باید قفل/فنس مشترک همان جلسه داشته باشند. پس از ورود به ROLLING_BACK، Apply دیگر حق mutation نداشته باشد؛ وگرنه ممکن است پس از برگشت worker دوباره rule اعمال کند. `MultipleInstances IgnoreNew` فقط سیاست نمونه‌های همان task است، نه قفل rollback دستی.
- بستن پنجره، exception یا شکست Apply نباید در `finally` تنها مسیر recovery را حذف کند. task/journal تا تأیید برگشت delta و ثبت receipt معتبر نگه داشته شوند؛ cleanup فقط هویت همان جلسه را هدف بگیرد.
- `StartWhenAvailable` و تنظیمات باتری در S2 همین حالا وجود دارند؛ آن‌ها را پیشنهادِ هنوز پیاده‌نشده معرفی نکنیم. با این حال suspend/reboot و deadline ازدست‌رفته هنوز آزمون جدا می‌خواهند. برای boot recovery، intent پایدار و trigger/سازوکار محلی مشخص با جلوگیری از اجرای همزمان لازم است؛ در خواب/خاموشی تضمین «برگشت دقیقاً پس از ۴۵ ثانیه» ندهیم. [معنای رسمی تنظیمات Task](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset?view=windowsserver2025-ps).
- محدودیت یک‌دقیقه‌ای worker فعلی را بدون اندازه‌گیری به rollback واقعی منتقل نکنید. قطع worker در میانه restore باید قابل ادامه و آزموده باشد؛ timeout یا خراب‌شدن journal نباید به cleanup موفق یا بازکردن عمومی شبکه ترجمه شود.

### ۹.۴. آزمون‌های تمایزبخش قبل از تحویل ابزار Apply
این‌ها **پیشنهاد آزمون در Windows موقت با دسترسی recovery محلی مستقل** هستند، نه دستور آزمایش روی دستگاه کاربر. fixture مصنوعی و PASS ویندوز Server runner به‌تنهایی اثبات Windows 11/SSTP کاربر نیستند.

| failure injection پیشنهادی | شاهد پذیرش مورد انتظار |
| --- | --- |
| شکست پیش از arm یا پیش از اولین mutation | هیچ تغییر شبکه؛ STOP روشن و بدون ادعای rollback اجراشده |
| crash پس از ثبت intent و پیش/پس از فرمان، قبل از ثبت نتیجه | بازیابی با تشخیص B/A؛ بدون گم‌شدن عملیات یا اعمال دوباره ناسازگار |
| crash بعد از هر مرحله partial apply و بستن کامل parent | worker محلی مستقل، برگشت delta ثبت‌شده و رسید واقعی پس از verification |
| همزمانی rollback دستی/زمان‌دار و ادامه parent | تنها یک مسیر مؤثر؛ Apply پس از شروع rollback دیگر نمی‌نویسد |
| تغییر rule نامرتبط و تغییر هم‌پوشان policy/GPO | اولی حفظ شود؛ دومی conflict بدهد، نه overwrite یا PASS |
| sleep/reboot پس از mutation و عبور deadline | journal باقی بماند؛ recovery پس از امکان اجرا و بدون وابستگی اینترنت؛ زمان تأخیر صادقانه ثبت شود |
| خطای restore، journal ناقص/دیسک پر یا termination worker | خطا قابل‌مشاهده و recovery قابل‌ادامه؛ پاک‌سازی مسیر بازیابی انجام نشود |

کنترل native باید mutation و restore واقعی یک delta مجاز را بسنجد؛ باز هم receipt-only کافی نیست. snapshot معنایی مقادیر محلی/مؤثر، ruleها و فیلترهای مرتبط قبل/بعد مقایسه شود؛ تغییرات نامرتبطِ عمدی نیز باید حفظ شوند. برابری چند profile، exit code صفر، hash فایل .wfw یا اتصال loopback به‌تنهایی enforcement غیرloopback یا بازیابی همه policyها را ثابت نمی‌کنند. شواهد عمومی فقط نتیجه/خطا/شمار موارد حل‌نشده و هش‌های لازم باشند؛ backup، endpoint خصوصی و rule dump عمومی نشوند.

### ۹.۵. P1 — default-deny باید در سیاست مؤثر ثابت شود
- افزودن Allowهای محدود در کنار Allowهای گسترده موجود یا صرف تغییر default به Block کافی نیست. فقط Allowهای محلی مشخص و قابل‌بازیابی، مطابق طرح مجاز، موقتاً مدیریت شوند؛ اگر سیاست مؤثر یا منشأ ruleها کامل قابل‌خواندن/بازیابی نیست، Apply متوقف شود.
- برای قواعد معمول، Block صریح بر Allow تعارض‌دار مقدم است؛ پس الگوی «Block همه + Allow چند مقصد» راه‌حل ساده‌ای نیست. Blockهای قبلی هم برای راه‌انداختن آپدیت تضعیف نشوند. [قواعد تقدم و local merge](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).
- استثنای authenticated allow-bypass نیز جدا بررسی شود؛ ادعای مطلق «هر Block از هر Allow جلوتر است» دقیق نیست. GPO/MDM، merge و connection-security مؤثر باید gate داشته باشند؛ وجود مانع مدیریت‌شده مجوز تغییر GPO نیست. [ترتیب رسمی Allow-bypass/Block/Allow](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/702e3c23-c9d8-43db-8380-b4c670dd7f7d).

### ۹.۶. P1 — اثبات زیرلایه/تونل و تضاد احتمالی bootstrap
پس از اثبات rollback، آزمون enforcement جدا با ترافیک کنترل‌شده غیرloopback و شاهد واقعی allow/drop طراحی شود:
- زیرلایه: ارتباط لازم SSTP به endpoint معتبر مجاز باشد، ولی برنامه نامرتبط نتواند صرفاً از استثنای همان server:443 استفاده کند؛ تطابق IP یا یک PID مشترک svchost به‌تنهایی binding سرویس/پروفایل نیست.
- درون تونل: مقصد مجاز فقط از رابط واقعاً منتسب به holand عبور کند؛ خروج همان مقصد از رابط فیزیکی، مقصد غیرمجاز در VPN و fallback IPv4/IPv6/UDP بررسی شوند. تغییر interface/index یا IP پس از reconnect نباید خودکار به مجوز گسترده تبدیل شود.
- جریان ازپیش‌برقرار و اتصال تازه هر دو در آزمون باشند؛ از رفتار یکی نتیجه دیگری نگیریم. افت VPN باید معیار توقف/بازیابی مشخص داشته باشد، نه ادامه دانلود از مسیر دیگر. دانلود مستقل از گزارش کلیک کاربر اندازه‌گیری شود؛ شمار TCP معادل بایت دانلود نیست.
- DNS bootstrap، تغییر IP CDN/VPN و CRL/OCSP جدا بررسی شوند. اگر پس از انقضای cache، شرط سخت «فقط endpoint VPN و مقصدهای آپدیت» با reconnect/اعتبارسنجی امن ناسازگار شد، تضاد مستند و تصمیم دامنه از کاربر گرفته شود؛ نه DNS/HTTPS عمومی دائمی باز شود، نه TLS/revocation خاموش گردد. IPهای snapshot نیز allowlist دائمی همه CDN نیستند.

### ۹.۷. هزینه، معیار توقف و تحویل مورد انتظار
- تحویل نزدیک و کم‌دامنه: طرح state/journal و بازگشت، harness failure-injection محدود، سپس شواهد native mutation/restore واقعی در محیط موقت مجاز. نصب دوباره بازی، login، ادامه N2 یا تکرار S1/S2 لازم نیست. این بازبینی هیچ runnerی را دستی اجرا نکرده؛ هزینه اجرای آزمون آینده باید پیش از شروع روشن باشد و larger/paid runner اضافه نشود.
- **STOP قبل از تحویل Apply:** recovery مستقل arm/verify نمی‌شود؛ journal پایدار یا policy inventory کامل نیست؛ overlap خارجی/GPO حل‌نشده است؛ رفتار reboot/timeout در محدوده وعده‌داده‌شده آزموده نیست؛ یا برای اتصال امن باید از حدود مصوب عبور کرد.
- گزارش بعدی چهار نتیجه را جدا کند: بازیابی delta خود ابزار، تعارض خارجی، سیاست مؤثر/enforcement و اتصال امن/پیشرفت واقعی آپدیت. هیچ boolean واحدی به نام PASS جای این تفکیک را نگیرد.
- فعلاً مطابق وضعیت مبنا WoW بسته، آپدیت Pause، تنظیمات موجود و backup خصوصی حفظ شوند؛ نه S2 دوباره، نه BAT99/Enable/Disable/EmergencyReset. این بند مجوز تغییر شبکه کاربر یا Resume نیست.

---

## ۱۰. بازخورد Notion AI — baseline محلی NotConfigured و بازیابی دقیق unset

> مبنای بازبینی: commit `1232b2687e0ec1bca67dd446edad7efccb4d31bb`، وضعیت ثبت‌شده در 2026-10-19 02:19 UTC. این بخش صرفاً پیشنهاد طراحی/آزمون است؛ نه مجوز Apply، نه شاهد اجرای آزمون‌های زیر، و نه تکرار فرمان روی دستگاه کاربر. فقط همین سند تکمیل می‌شود؛ کد، workflow، BAT، VPN، hosts، فایروال کاربر و فایل بازی با این ثبت تغییر نمی‌کنند. متن بخش‌های قبلی حفظ شده است.

### ۱۰.۱. یافته‌ها نسبت به اولویت اعلام‌شده
- [STATUS](https://github.com/kokononox/battle-net-agent-lab/blob/1232b2687e0ec1bca67dd446edad7efccb4d31bb/docs/STATUS.fa.md)، [درخواست نقد](https://github.com/kokononox/battle-net-agent-lab/blob/1232b2687e0ec1bca67dd446edad7efccb4d31bb/docs/PEER-REQUEST-SSTP-S2.fa.md)، [خروجی محلی کاربر](https://github.com/kokononox/battle-net-agent-lab/blob/1232b2687e0ec1bca67dd446edad7efccb4d31bb/reports/sstp-user-local-outbound.json) و [تحلیل دو نسخه S3](https://github.com/kokononox/battle-net-agent-lab/blob/1232b2687e0ec1bca67dd446edad7efccb4d31bb/reports/sstp-rollback-s3-analysis.fa.md) خوانده شدند.
- خروجی کاربر فقط `Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name, DefaultOutboundAction` است: Domain/Private/Public هر سه `NotConfigured`. این خروجی effective action را ثابت نمی‌کند و تنظیمات را عوض نکرده است.
- S1 قبلی ActiveStore را outbound=`Allow` و firewall enabled ثبت کرده بود. این دو لایه یکی نیستند: PersistentStore مقدار ذخیره‌شدهٔ محلی است؛ ActiveStore جمع PersistentStore + RSOP/GPO + service hardening است. [توضیح storeها در Set-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps).
- gate نسخه سخت‌گیرتر S3 (`9f7b568c`) پیش از mutation در `full_setup` با `s3_no_real_profile_transition_available` ایستاد؛۱۷fixture پاس شد، live scenario صفر. PASS نسخه اول (`40fd1b53` / run `39187957739`) جایگزین این gate نیست و مجوز Apply نیست.
- از داده کاربر علت قطعی توقف runner استنتاج نشود؛ از توقف runner هم baseline کاربر حدس زده نشود. receipt فعلی مقدارهای Persistent/Active را منتشر نمی‌کند.

### ۱۰.۲. P0 — observability گیت ترکیبی، بدون دورزدن guard
**یافته مشخص منبع:** در [Run-CI-Tests.ps1 نسخه سخت‌گیرتر](https://github.com/kokononox/battle-net-agent-lab/blob/9f7b568c902c9028358d464e2d6bd8a9781feefb/sstp-rollback-s3/Run-CI-Tests.ps1) یک شرط واحد سه چیز را با هم رد می‌کند: تعداد profile ≠ ۳، هر outbound غیر `Allow`/`Block`، یا صفر بودن `Allow`. throw واحد `s3_no_real_profile_transition_available` است؛ `native-result.json` / [build receipt](https://github.com/kokononox/battle-net-agent-lab/blob/1232b2687e0ec1bca67dd446edad7efccb4d31bb/reports/sstp-rollback-s3-build.json) فقط همین کد، `stage=full_setup` و `diagnostic_line=38` را دارد.

**پیشنهاد کوچک، نه حذف gate:**
1. کدهای توقف جدا: `s3_profile_count_mismatch`، `s3_persistent_outbound_not_allow_or_block`، `s3_no_allow_profile_for_partial_conflict`.
2. حتی در STOP، enumهای `baseline_persistent` و `baseline_active` در receipt عمومی نوشته شوند: برای هر سه نام، `DefaultOutboundAction`؛ برای ActiveStore همچنین `Enabled` و `DefaultInboundAction`. dump قانون، مسیر خصوصی، endpoint و backup نه.
3. علت نیاز به «دست‌کم یک Allow» در همین harness است، نه یک اصل فایروال: [Crash-Driver](https://github.com/kokononox/battle-net-agent-lab/blob/9f7b568c902c9028358d464e2d6bd8a9781feefb/sstp-rollback-s3/Crash-Driver.ps1) در `partial_conflict` اولین profile با `before -ceq 'Allow'` را برمی‌گزیند. اگر baseline همه NotConfigured باشد، آن selector خالی می‌ماند حتی اگر mutation مجاز می‌بود.

این patch رفتار restore را عوض نمی‌کند؛ فقط مانع حدس پس‌از‌واقعه می‌شود. هزینه: یک run استاندارد windows-2025 پس از اعمال، نه larger/paid runner.

### ۱۰.۳. P0 — round-trip دقیق unset آزمایش جدا است؛ gate فعلی شل نشود
**مستند رسمی در برابر رفتار provider:**
- برای `-DefaultOutboundAction`، مقدار `NotConfigured` «فقط هنگام پیکربندی GPO معتبر است» و تنظیم را از GPO برمی‌دارد؛ پیش‌فرض هنگام مدیریت خود رایانه `Allow` است. [Set-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps).
- netsh هم می‌گوید `notconfigured` فقط برای Group Policy store معتبر است؛ در عین حال برای `firewallpolicy` نوشته «مقدار را به حالت پیکربندی‌نشده برمی‌گرداند». این دو جمله باید با آزمون تمایزبخش حل شوند، نه با فرض. [netsh advfirewall](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall).
- نسخه قدیمی‌تر همان خانواده فرمان، `notconfigured` را صریحاً به `set store` روی GPO محدود کرده است. [Netsh Commands for WFAS](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771920(v=ws.10)).
- [MS-GPFAS DefaultOutboundAction](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/bccac98d-1973-49d0-9100-aceb3bf557df) کلید GPO زیر `Software\Policies\Microsoft\WindowsFirewall\...` است (۰=allow، ۱=block)، نه PersistentStore محلی. این مسیر را با store محلی یکی نگیرید و restore را روی کلید سیاست دامنه بنا نکنید.

**تفاوت دو نسخه S3 که باید جدا گزارش شود:**
- نسخه اول journal مقدار `before∈{Allow,Block,NotConfigured}` را می‌پذیرفت و restore با `Set-NetFirewallProfile -PolicyStore PersistentStore -DefaultOutboundAction $p.before` انجام می‌شد؛ gate فقط وقتی می‌ایستاد که هیچ profileای غیر Block نباشد. [Core.ps1 اول](https://github.com/kokononox/battle-net-agent-lab/blob/40fd1b53b13cc03d77f0054dd467667958207474/sstp-rollback-s3/Core.ps1).
- نسخه سخت‌گیرتر `before=NotConfigured` را در `AssertJournal` رد می‌کند و live mutation را به Allow/Block محدود می‌کند. [Core.ps1 سخت‌گیرتر](https://github.com/kokononox/battle-net-agent-lab/blob/9f7b568c902c9028358d464e2d6bd8a9781feefb/sstp-rollback-s3/Core.ps1).
- چون receipt نسخه اول baseline Persistent را ندارد، PASS آن **اثبات round-trip دقیق NotConfigured نیست**. ممکن است runner Allow بوده باشد، یا Setِ NotConfigured روی PersistentStore ظاهراً موفق شده باشد. هر دو باید با شاهد enum جدا مشخص شوند؛ رفتار بدون‌مستند provider راهکار عمومی کاربر نیست.

**آزمون پیشنهادی جدا (S3u)، فقط CI github-hosted/Windows، بدون لانچر کاربر:**
schema جدا مثل `s3u-ci-journal-1`؛ `s3-ci-journal-1` شل نشود.
1. snapshot فقط‌خواندنی PersistentStore + ActiveStore + در صورت وجود SystemDefaults: enum نام/Enabled/Inbound/Outbound. اگر RSOP خالی یا خطا داد، همان را ثبت کنید نه حدس GPO.
2. اگر Persistent هر سه profile از قبل `NotConfigured` است، همان fixture واقعی است؛ runner را با نوشتن Allow «آمادهٔ S3 سخت‌گیرتر» نکنید.
3. اگر Persistent از قبل Allow/Block است، S3u را با `s3u_baseline_not_unset` متوقف کنید؛ PASS نگرفتن به‌خاطر نبود fixture، شکست restore نیست.
4. فقط **یک** profile را به Block تغییر دهید (ترجیحاً غیر Domain)، نه هر سه. دو profile دیگر شاهد عدم‌دستکاری‌اند.
5. پس از mutation، Persistent همان profile باید Block باشد؛ Active outbound/inbound/enabled جدا سنجیده شوند. از تغییر effective، stored unset بودنِ قبل نتیجه گرفته نشود و برعکس.
6. restore را فقط با candidate مستند و به ترتیب، روی همان یک property، آزمایش کنید. موفقیت یعنی Persistent دوباره دقیقاً `NotConfigured` است **و** snapshot Active همان profile و دو profile دیگر با پیش از mutation برابرند.

Candidate A — همان cmdlet نسخه اول، این بار با شاهد stored: `Set-NetFirewallProfile -Name <one> -PolicyStore PersistentStore -DefaultOutboundAction NotConfigured`. اگر throw شد، Persistent=`Allow` شد، یا inbound عوض شد → این روش FAIL است، نه «نزدیک به PASS».
Candidate B — netsh `firewallpolicy` فقط اگر بتوان outbound را بدون دست‌زدن به inbound هدف گرفت. الگوی رایج inbound و outbound را با هم می‌نویسد (`blockinbound,allowoutbound`). اگر `notconfigured` هر دو را unset کند یا store را عوض کند → FAIL آن روش. [نمونه رسمی جفت inbound/outbound](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line).

**معیار PASS S3u:** Persistent هدف = `NotConfigured`؛ Active هدف = مقدار پیش از mutation؛ دو profile دیگر دست‌نخورده؛ هیچ netsh import/reset و هیچ نوشتن Allow به‌عنوان restore؛ rule نامرتبط حفظ شود.
**معیار FAIL صریح:** Persistent پس از restore برابر `Allow` باشد، حتی اگر Active همچنان Allow بماند. این همان تغییر semantics است که STATUS ممنوع کرده.

### ۱۰.۴. بازگرداندن Allow به‌جای unset باید conflict بماند
`RollbackDecision` همین حالا `Current=Allow, Before=NotConfigured, Applied=Block` را `conflict_value` می‌دهد؛ این را نگه دارید. اگر journal به‌اشتباه `before=Allow` بنویسد در حالی که stored واقعی NotConfigured بوده، restoreِ Allow همان mutation معنایی است.

چرا معادل نیستند:
- Unset محلی یعنی این store مقدار را تعیین نمی‌کند؛ Allow محلی یعنی این store صریحاً Allow می‌نویسد و در merge بعدی با GPO/RSOP فرق دارد.
- پیش‌فرض «وقتی رایانه را مدیریت می‌کنید Allow است» توصیف effective/default محصول است، نه مجوز بازنویسی stored unset.
- EmergencyReset / import کلی / `netsh advfirewall reset` خارج از دامنه است.

تا S3u PASS نشده، Apply روی baseline کاربر متوقف بماند. تکرار S3 سخت‌گیرتر روی runner بدون observability یا با normalize کردن baseline به Allow، PASS کاذب می‌سازد.

### ۱۰.۵. آزمون‌های تمایزبخش پیشنهادی (فقط محیط موقت)
| failure injection | شاهد پذیرش |
| --- | --- |
| STOP پیش از mutation با baseline NotConfigured در S3 سخت‌گیرتر | کد توقف تفکیک‌شده + enum Persistent/Active؛ بدون Set |
| Set NotConfigured روی PersistentStore پس از Block موقت یک profile | Persistent هدف = NotConfigured نه Allow؛ inbound همان profile و دو profile دیگر ثابت |
| restore با نوشتن Allow | FAIL معنایی، حتی اگر Active=Allow |
| تغییر خارجی همان profile به Allow هنگام rollback | `conflict_value`؛ overwrite نشود |
| netsh firewallpolicy notconfigured | اگر inbound یا store عوض شد، روش رد شود |
| replay پس از restore دقیق | decision=`already_before`؛ Set تازه صفر |

compare-before-write همچنان CAS نیست؛ این جدول آن را حل نمی‌کند. enforcement SSTP/Level3، IPv6، DNS/CRL و صفر telemetry از S3u نتیجه گرفته نشود.

### ۱۰.۶. هزینه، توقف و کارهای غیرمجاز فعلی
- تحویل نزدیک: (۱) receipt با baseline enum و کد توقف جدا برای S3 موجود؛ (۲) طرح/harness S3u تک‌profile در CI استاندارد. login، Resume، تکرار S1/S2/T1/N2، BAT99، Enable/Disable/EmergencyReset، upload backup و larger/paid runner لازم نیستند و پیشنهاد نمی‌شوند.
- **STOP پیش از Apply کاربر:** روش مستند round-trip، Persistent را دقیقاً به NotConfigured برنمی‌گرداند؛ inbound یا profile نامرتبط عوض می‌شود؛ یا برای PASS باید Allow نوشته شود.
- خروجی اضافی از کاربر فعلاً لازم نیست؛ ورودی Persistent کافی است. WoW بسته، آپدیت Pause، VPN/تنظیمات فعلی و backup خصوصی حفظ شوند.
- این بند مجوز تغییر شبکه کاربر نیست. پیشنهادهای بخش ۹ برای journal/watchdog/enforcement همچنان معتبرند ولی تا حل unset، اولویت اجرا نیستند.
