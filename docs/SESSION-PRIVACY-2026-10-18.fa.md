# تحویل جلسه — حریم خصوصی Battle.net و منشأ فایل‌های آپدیت

وضعیت ثبت‌شده: ۲۰۲۶-۱۰-۱۸، پس از نتیجه E2 و درخواست کاربر برای همگام‌سازی. این سند جمع‌بندی عملیاتی جلسه است، نه رونویسی کلمه‌به‌کلمه گفتگو. تاریخچه قدیمی اپدیتر در اسناد قبلی حفظ شده و نباید جای نتیجه تازه خوانده شود.

## از اینجا ادامه بده

**دستاورد تازه:** به ورودی واقعی `EncryptMessage` در Agent زنده و امضاشده دسترسی داریم؛ در بدنه بازسازی‌شده `POST /data` با Host برابر `telemetry-in.battle.net`، مدل CPU ماشین موقت دقیقاً مطابق مرجع رجیستری دیده شد: `AMD EPYC 7763 64-Core Processor`. این داده مربوط به VM گیتهاب است، نه کامپیوتر HP کاربر. API input پیش از رمزگذاری، دریافت/ذخیره آن در سرور را ثابت نمی‌کند.

**قدم بعدی:** تحلیل آفلاین همین نمونه‌ها و بخش‌های multipart/ساختار باینری، استخراج فیلد/مقدار و نسبت‌دادن آن به درخواست/مقصد. برای این مرحله لازم نیست دوباره برنامه را اجرا یا بازی را resume کنیم. سؤال نبودِ ارسال روی همه مسیرها و سؤال اثرانگشت A→B هنوز باز است.

کد و receiptهای آزمایش‌ها در شاخه `privacy-observation-20261018-a1` هستند. آخرین receipt کامل E2 در commit `d64629013489a4a51d93defbc11531b629aacccb` قرار دارد. کد آزمایشی/workflowهای شاخه عمداً با این sync به main ادغام نشده‌اند؛ فقط مستندات، ابزارهای تحویلی کاربر و تحلیل آفلاین به main آمده‌اند. هیچ آزمایش جدیدی با این sync سفارش داده نشده است.

## ۱. خواسته و تصمیم کاربر

- اولویت فعلی: محدودکردن Battle.net رسمی به به‌روزرسانی، بدون ارسال مشخصات سخت‌افزاری/سیستمی اضافی. اگر شد، اپدیتر مستقل ضرورت ندارد. تله‌متری خود WoW و Battle.net با هم مخلوط نشوند.
- کاربر صریحاً اجازه بررسی ساختار و **مقدارهای واقعی ماشین آزمایشی** را داد؛ محدودیت صرف نام‌فیلد انتخاب بیش‌ازحد محافظه‌کارانه ابزار ما بود، نه خواسته کاربر. دیدن CPU/OS/شناسه آزمایشی مجاز و برای پاسخ لازم است. رمز/توکن واقعی حساب یا credential گیتهاب بی‌جهت منتشر نشود؛ ولی این نباید بهانه توقف تحلیل مقدارها شود.
- سؤال مهم دوم: آیا به‌روزرسانی بدون حساب در A فایل‌های مختص همان سیستم می‌نویسد؟ اگر فایل‌های بازی به B کپی شوند، آیا سرور منشأ آن‌ها را می‌فهمد؟ payload عمومی، metadata/config/cache/log محلی، آثار فایل‌سیستم و سابقه سمت سرور جدا بررسی شوند. فایل یکسان به معنی نبود سابقه دانلود سمت سرور نیست؛ شناسه محلی تا مشاهده ارسال، اثبات آگاهی سرور نیست.
- شواهد واقعی لازم است: نام مقصد، خود درخواست، فیلد و مقدار. دامنه با نام telemetry، keyword لاگ، import یا DLL بارگذاری‌شده به‌تنهایی ارسال سخت‌افزار را ثابت نمی‌کند.
- کاربر از نسخه‌سازی/اسکن‌های طولانی بدون پیشرفت خسته است. هر اجرای جدید یک سؤال، کنترل‌ها، سقف و شرط توقف داشته باشد. پس از رسیدن به نمونه قابل تحلیل، ابتدا آفلاین تحلیل کن.

## ۲. وضعیت سیستم کاربر — دست نزن

- Windows 11 Pro، مینی‌کیس HP نسل ۷؛ Virtualization Enabled گزارش شد.
- نصب تست `G:\World of Warcraft`، نسخه گزارش‌شده `12.1.0.69933`، Battle.net signed_out، آپدیت خودکار خاموش.
- کاربر از Initializing عبور کرد، در حدود ۳٪ دانلود Pause زد. آخرین وضعیت اعلامی همچنان Pause است؛ Cancel/تکمیل آپدیت/ورود موفق/Play-ready ثابت نشده.
- کپی قدیمی کامل روی هارد اکسترنال دارد. برای تکرار تست، کاربر را مجبور به پاک‌کردن/بازیابی ۱۳۰ گیگ نکن؛ نصب/بکاپ را بی‌دلیل تغییر نده. یکسان‌بودن .build.info پیش/پس به معنی بدون تغییر بودن بقیه فایل‌ها نیست.
- تغییر به مسیر GitHub lab با خواسته کاربر بود؛ تعمیر Windows Sandbox پیش‌نیاز پروژه نیست. Enable-WindowsOptionalFeature خطای component store corrupted داد. DISM فقط repairable/operation successful برای check را نشان داد؛ این تعمیر موفق نیست. SFC فایل خرابِ تعمیرنشده داشت. موفقیت RestoreHealth ثابت نشده؛ این کار جداست و نباید دوباره به کاربر تحمیل شود.

## ۳. ابزارهای محلی و گزارش‌های کاربر

ابزارها در `user-tools/session-20261018/` و JSONهای کاربر در `evidence/user-observer-20261018/` با byte/hash اولیه حفظ شده‌اند؛ شاخص `evidence/session-20261018-index.json` را بخوانید.

- Observer 1.0/1.1 به directory limit خوردند و خواندن صفر داشتند. 1.2 ریشه‌ها را به Logs مشخص محدود کرد؛ no broad fallback. SHA256 core: `acd9d4d562fb193c95de10e204cefeb92720baa2143879c47813b4b34251f6d5`.
- Observer فقط version/menu/keyword counts و آمار I/O است: به نام فاز رسمی یا مقدار دانلود اعتماد نکن. counter صریح Initializing ندارد، نمونه تجمعی ۳۰ ثانیه و JSON نهایی روی خروج عادی دارد؛ crash-safe نیست. اولین خط دنبال‌شده محافظه‌کارانه حذف می‌شود. ابزار آپدیتر/CASC writer نیست و شبکه را ضبط نمی‌کند.
- Windows self-test کاربر ۱۶ check را پاس کرد؛ fixture مصنوعی است، نه اثبات عملیات واقعی update.
- passive relaunch: ۱۴۳۳۲۶ بایت/۱۳۳۷ خط خوانده شد، بدون limit/error؛ شمارش keyword error معادل خرابی نیست.
- run واقعی update-pause: ۹۱۸۱۷۱ بایت/۳۳۵۱۲ خط، ۵۷ لاگ، بدون I/O/discovery limit/error. نسخه قبل/بعد یکی بود. menu اشتباهاً check_only/Play ثبت شد؛ توضیح مستقیم کاربر update سپس pause در ~۳٪ مقدم است. ۳٪ اندازه‌گیری ابزار نیست.
- Paused-Log-Review تحویل شد تا لاگ موجود را فقط‌خواندنی ببیند؛ نتیجه آن از کاربر برنگشته. native Windows آن ابزار جدا تأیید نشده است. بازه UTC: 17:44:36 تا 17:52:27؛ timestamp mapping ممکن است assumed/unknown باشد، keyword فاز را ثابت نمی‌کند.

## ۴. آزمایش‌های GitHub این جلسه

همه روی VM تازه GitHub-hosted Windows، بدون حساب/بازی و بدون پذیرش حقوقی/Install از صفحه بعد؛ در صورت مجاز بودن فقط Continue صفحه زبان. raw capture اولیه منتشر نشد. محیط فرزند از tokenهای GitHub پاک شد. سقف سخت بایتی برای شبکه childها وجود نداشت؛ این محدودیت پنهان نشود. آزمایش‌ها چرخه کامل نصب Battle.net یا آپدیت WoW نیستند.

| مرحله | run ID | نتیجه معتبر |
| --- | --- | --- |
| A1 startup endpoint | 39156465402 | TCP metadata؛ DNS cache probe خطا، SSLKEYLOGFILE بدون فایل؛ payload دیده نشد |
| B1 packet metadata | 39157489237 | Pktmon و DNS/SNI/HTTP Host؛ telemetry SNI در Setup، نه شواهد قدیمی WoW. PowerShell cache probe timeout باقی ماند |
| C1 دو arm A/B | 39158224605 | همان bootstrap hash و Windows image؛ baseline SNI target داشت، block فقط target با IPv4/IPv6 loopback تأیید شد و اتصال عمومی target/آدرس قبلی دیده نشد؛ Agent و Continue در هر دو دیده شد |
| D1 | 39159715814 | self-test در attach شکست خورد؛ هیچ کلاینت واقعی اجرا نشد. API cancellation جدید Frida با روش قدیم ناسازگار بود |
| D2 | 39160098761 | self-test پاس؛ hash/path/PID Agent واقعی و bufferهای EncryptMessage دیده شد. body قالب ناشناخته، مقدارها در این نسخه حفظ نشد |
| E1 | 39160679721 | نگه‌داری مقدارها به خطای script خورد؛ صفر نمونه، نه شاهد نبود داده. this.context با property رزروشده تداخل داشت |
| E2 | 39161239853 | property اصلاح و self-test WinHTTP و EncryptMessage هر دو پاس؛ ۲۲ نمونه واقعی API با alias context نگه‌داری شد؛ CPU در بدنه Agent پیدا شد |

receiptهای ثابت و source SHA در `evidence/session-20261018-index.json` ثبت شده‌اند. نام latest را به‌تنهایی سند نکنید.

## ۵. تمایز مهم هویت Agent

فایل Agent کاندید دیسکی قبلی ۵۴۰۸۸۰ بایت و hash `7d20ba6ef1d34a3cedbd7d3fd7c14228f173668a9a1e338351d529048de45079` بود؛ این image همه PIDها نبود. در D2/E2 Agent زنده در پوشه Agent.9824 شناسایی شد: ۷۲۷۵۲۱۶ بایت، hash `b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`، امضای معتبر Blizzard. شماره پوشه را با version resource خوانده‌نشده یکی نگیرید.

Bootstrap pin مشترک: `de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf`. اگر دانلود رسمی تغییر کند، قبل اجرا توقف؛ pin بی‌صدا تغییر نکند.

بارگذاری secur32/winhttp به‌تنهایی شاهد استفاده نبود؛ callback واقعی EncryptMessage در PID/hash تأییدشده شاهد استفاده در همان اجراست. هنوز انتساب socket/سرور و دریافت/ذخیره payload سمت سرور جداست. هیچ SSLKEYLOGFILE موفقی نداریم؛ روش فعلی مشاهده ورودی API پیش از TLS است، نه داشتن کلید نشست یا MITM. TLS trust/verification تغییر داده نشد و API result/buffer دستکاری نشد. instrumentation می‌تواند رفتار/زمان‌بندی را عوض کند.

## ۶. یافته E2 و تحلیل قابل بازتولید

منابع در commit ثابت `d64629013489a4a51d93defbc11531b629aacccb`:
- `reports/startup-tls-e2-buffers.json`: نمونه base64، sequence/context alias، SHA و reference ماشین موقت؛ با اجازه صریح کاربر. auth/cookie headerهای HTTP/1 پوشانده شده‌اند؛ body آزمایشی حفظ شده است.
- `reports/startup-tls-e2-live.json`: self-test، pin، هویت process، API events و خطاها.
- `reports/startup-tls-e2-network.json`: packet metadata؛ `reports/startup-tls-e2-bootstrap.json`: GUI/startup receipt.

تحلیل از context streamهای EncryptMessage انجام شد؛ ۲۰ request کاندید بازسازی شد، نه ادعای ۲۰ درخواست قطعی دریافت‌شده در سرور. مورد شماره ۱۸: PID 3452، Agent.9824 با hash بالا، Host `telemetry-in.battle.net`، `POST /data`، content-type `multipart/mixed; boundary="telem-boundary"`، body مطابق Content-Length کامل، ۵۹۱۷ بایت. در بخش پنجم multipart از ده بخش، رشته CPU دقیقاً مطابق reference رجیستری VM دیده شد. وجود CPU با scan مستقل خود نمونه base64 نیز cross-check شد.

- مدل CPU: `AMD EPYC 7763 64-Core Processor`.
- SHA256 کل body بازسازی‌شده: `e8808a8ed1314cf633a6fcd6473fd11256d54e618eaa7b8406cf77c10eeda4ff`.
- بخش دارای CPU: ۵۷۹ بایت، SHA256 `e24a9969bebfdca1a07a0e53b6bd561486b9a890a37844d0238795a4eeae2d69`.
- رشته `Windows Server 2022` هم در نمونه هست؛ این را به‌عنوان تشخیص دقیق OS واقعی تلقی نکنید. reference build ویندوز 26100 است و نام‌های legacy ممکن است متفاوت باشند.
- RAM مرجع و logical processor در reference ثبت شده، اما ارسال آن‌ها هنوز decode/اثبات نشده؛ مقدار reference را جای payload اعلام نکنید.
- JSON نبودن بدنه یا صفر بودن key hint در D2، به معنی نبود سخت‌افزار نبود؛ اکنون CPU در قالب باینری/multipart دیده شده است.

اسکریپت بازسازی: `analysis-tools/reconstruct_tls_requests.py`. خروجی evidence مشتق‌شده در `evidence/telemetry-e2-analysis.json` و CPU finding خلاصه در `evidence/telemetry-e2-cpu-evidence.json` است. در صورت نیاز، با MCP نمونه ثابت را بگیرید و آفلاین decode کنید؛ صفرِ sample/خطای ابزار در e1 با نمونه معتبر E2 مخلوط نشود.

## ۷. hostsهای کاربر و نتیجه محدود C1

`3-fixed.bat` و `4-fixed.bat` خوانده و بدون تغییر در شاخه تحقیق حفظ شدند؛ اجرا نشدند. مسیر: `research-inputs/20261018-hosts/`. این‌ها فایروال IP نیستند، hosts را تغییر می‌دهند. ورودی `breaking-news.support.blizzard.com:443` قالب معتبر hostname نیست. cleanup می‌تواند ruleهای مشابه خارج marker را حذف کند و backup مشترک را بازنویسی می‌کند؛ unblock بازگردانی دقیق snapshot نیست.

C1 فقط مسدودسازی یک دامنه را با کنترل resolver آزمود، نه همین دو BAT و نه کل denylist. نبود اتصال عمومی آن دامنه در بازه با ادامه startup Agent همراه بود. این نه موفقیت آپدیت کامل، نه نبود fallback و نه نبود telemetry روی باقی مسیرها را ثابت می‌کند. در E2 فقط GETهای نسخه دیده‌شده بدون body بودند؛ header/query، سایر APIها و مراحل آینده باید جدا بررسی شوند.

## ۸. Enterprise samix

کاربر اعلام کرد Enterprise فعال کرده: https://github.com/enterprises/samix . تنظیمات/اشتراک/سهمیه/runner group آن از ابزار فعلی تأیید نشده؛ هیچ انتقال مخزن، تغییر permission، خرید یا larger runner جدید انجام نشد. برای تحلیل آفلاین فعلی نیاز تازه‌ای نیست. RAM/disk بیشتر و egress IP ثابت و کنترل runnerها برای تست بزرگ آینده ممکن است مفید باشند؛ IP ثابت runner به معنی ثابت‌شدن IP مقصد CDN نیست. دسترسی همین مخزن به organization/runner group باید جدا بررسی شود. هزینه larger runner جداست و included minutes را مصرف نمی‌کند؛ قبل هر استفاده واقعیِ هزینه‌دار تأیید هزینه لازم است. جزئیات: `docs/ENTERPRISE-SAMIX-RELEVANCE.fa.md`.

## ۹. ادامه با کمترین تکرار

1. همین E2 را آفلاین multipart و قالب wire-compatible باینری decode کنید؛ بدون schema نام/معنای field number را حدس نزنید. فیلد، مقدار و مقصد را با دامنه قطعیت مشخص گزارش کنید.
2. یافته CPU را به «همه مشخصات/همه درخواست‌ها/سرور ذخیره می‌کند» تعمیم ندهید. برای جلوگیری، باید مسیرهای مجاز و امکان اشتراک telemetry با update بررسی شود؛ صرف blocklist تضمین نمی‌دهد.
3. تست کامل update و A→B هنوز به نصب baseline/target و محیط مناسب نیاز دارد؛ روی G کاربر خودسرانه عملیات نکنید. اگر منابع Enterprise لازم شد، اول runner access/disk/billing را روشن کنید.
4. پروژه اپدیتر مستقل و مرور بزرگ محلی قبلاً انجام شده؛ prepare/اسکن ۱٫۵میلیونی را به‌خاطر جلسه جدید تکرار نکنید. sample patch موفق پژوهشی معادل اپدیتر Windows نیست؛ fcntl/POSIX در مسیر نمونه مانع بسته‌بندی مستقیم Windows است.
