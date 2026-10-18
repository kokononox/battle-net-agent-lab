# آزمایش رابط محلی Agent در ویندوز بدون حساب و بدون بازی

## نتیجهٔ اجرای نخست

[رسید، نتیجه و گام بعد](../docs/AGENT-INTERFACE-RESULT.fa.md): source `1f8c3803ec96e1e60d673a4d53bbc10357282343`، run `39098949663`، HTTP 200 و وجود token محلی بدون ورود حساب تأیید شد. اثبات آپدیت بازی نیست.

## سؤال مشخص

آیا Agent روی ویندوز تازه، بدون ورود حساب و بدون نصب بازی، از رابط محلی `/agent` پاسخ JSON و فیلد authorization برمی‌گرداند؟ این آزمایش نه آپدیت بازی است، نه اثبات اینکه همهٔ عملیات Agent بدون حساب ممکن‌اند، نه انتخاب معماری وابسته به Agent به‌جای اپدیتر مستقل.

این مسیر جایگزین بسته‌های پژوهشی پیاپی با یک مشاهدهٔ واقعی و قابل رد شدن است. هیچ نسخهٔ Classic از قبل انتخاب و هیچ دانلود بازی مجاز نشده است.

## شواهد پیشین که مبنا قرار گرفتند

در [گزارش bootstrap موجود](https://github.com/kokononox/battle-net-agent-lab/blob/dcd9b9c2becf6382e088b3be82b72e2f74fffabf/reports/latest.json)، source_commit=`0352212413d3421e293c9814e49bb20298c74c7f`، run=`38937038793`، status=`agent_process_observed` است. انتخاب زبان انجام شد ولی مرحلهٔ نصب با `executable_identity_refused` متوقف شد. بنابراین Agent مشاهده شد؛ نصب کامل برنامه یا آپدیت WoW اثبات نشد. گزارش خطاها/کلیدواژه‌های log شاهد اجرای عملیات نیست.

فرضیهٔ HTTP از کد عمومی community، commit `3aa2d98d866b393197da0b75d7381b7fff495ad9` در `barncastle/Battle.Net-Installer` گرفته شده:

- [AgentApp.cs](https://github.com/barncastle/Battle.Net-Installer/blob/3aa2d98d866b393197da0b75d7381b7fff495ad9/BNetInstaller/AgentApp.cs): اجرای Agent با `--internalclienttools`.
- [AgentEndpoint.cs](https://github.com/barncastle/Battle.Net-Installer/blob/3aa2d98d866b393197da0b75d7381b7fff495ad9/BNetInstaller/Endpoints/Agent/AgentEndpoint.cs): دریافت authorization از پاسخ endpoint محلی.
- [AgentClient.cs](https://github.com/barncastle/Battle.Net-Installer/blob/3aa2d98d866b393197da0b75d7381b7fff495ad9/BNetInstaller/AgentClient.cs): loopback و User-Agent مشخص.

API رسمی پشتیبانی‌شده فرض نمی‌شود. README آن پروژه شرط عمومی ورود برای آپدیت Battle.net را اثبات نمی‌کند.

## اجرای دقیق

فقط GitHub-hosted `windows-2025` تازه، push یک‌باره با پیام مجوز دقیق و run_attempt=1. اجرا روی دستگاه کاربر، self-hosted، Linux یا تکرار workflow رد می‌شود. ثبت این منبع به‌تنهایی نتیجهٔ آزمایش نیست؛ رسید باید source_commit همین اجرا را نشان دهد.

1. آزمون‌های ایمنی و fixture بومی ویندوز برای تطبیق مسیر فرایند و مالک listener اجرا می‌شوند.
2. تابع موجود `observe_agent.observe` استفاده می‌شود: دانلود راه‌انداز از HTTPS allowlist، حداکثر 128 MiB، امضای WinVerifyTrust و ناشر Blizzard، محیط فرزند بدون token گیتهاب. فقط صفحهٔ زبان English US → Continue، یک بار و با محافظ‌های قبلی؛ بدون کلیک Install، legal، login یا بازی. مشاهده 120 ثانیه و سپس cleanup قبلی.
3. ادامه فقط اگر Agent مشاهده شده، انتخاب زبان قطعی باشد، cleanup درخواست شده و هیچ فرایند شناخته‌شدهٔ Battle.net باقی نمانده باشد. فقط زیرشاخهٔ صریح `ProgramData/Battle.net/Agent/Agent.<number>/Agent.exe` در همان VM بررسی می‌شود. فایل والد launcher جایگزین نیست؛ چند نسخه، reparse یا فایل نامناسب باعث توقف است.
4. امضا و ناشر فایل انتخابی دوباره بررسی و hash آن ثبت می‌شود؛ همان فایل با `--internalclienttools` و محیط پاک راه می‌افتد. این مرحله ممکن است state و شبکهٔ داخلی خود Agent را ایجاد کند؛ dry-run یا صفرنوشتن روی VM ادعا نمی‌شود.
5. تا 30 ثانیه، فقط جدول TCP ویندوز برای PID دقیقِ فرایند آغازشده خوانده می‌شود. هیچ port scan انجام نمی‌شود. مسیر executable با API ویندوز تطبیق داده می‌شود. فقط یک listener IPv4 متعلق به همان PID با bind به 127.0.0.1 یا wildcard مجاز است؛ اتصال همیشه به 127.0.0.1 است. IPv6-only، چند listener، خروج/جابجایی فرایند یا تغییر مالکیت موجب توقف می‌شود؛ آدرس/پورت جایگزین حدس زده نمی‌شود.
6. فقط یک `GET /agent`، بدون Authorization حساب، Cookie، body، query یا دنبال‌کردن redirect. حداکثر 64 KiB پاسخ پذیرفته می‌شود؛ یک بایت اضافه فقط برای تشخیص تجاوز خوانده می‌شود. timeout سوکت 3 ثانیه برای I/O است، نه تضمین مهلت کل پاسخ؛ سقف نهایی اجرای job ده دقیقه است. درخواست شکست‌خورده/نامعلوم تکرار نمی‌شود.
7. فقط status HTTP، طول پاسخ، JSON-object بودن و وجود یک token رشته‌ای غیرخالی با سقف طول ثبت می‌شوند. هیچ مقدار token، بدنه، نام فیلد اضافی یا متن exception صادر نمی‌شود. وجود token شاهد ورود حساب یا موفقیت آپدیت نیست.
8. مالکیت listener/مسیر فرایند دوباره بررسی، cleanup تلاش و VM پس از job دور انداخته می‌شود. cleanup_attempted تضمین خاتمهٔ تک‌تک فرزندها نیست؛ جداسازی نهایی از disposal محیط hosted است.

## خروجی و حریم خصوصی

فقط گزارش strict-schema حداکثر 16 KiB، source commit/run identity، hash فایل امضاشده، شواهد بولی محدود و فضای آزاد قبل/بعد صادر می‌شود. گزارش bootstrap، logها، executableها، screenshotها و پاسخ HTTP در artifact قرار نمی‌گیرند. publisher جدا در Linux گزارش را دوباره اعتبارسنجی و فقط دو فایل `reports/agent-interface-latest.json` و سابقهٔ همان run را commit می‌کند. گزارش موفق با source متفاوت به این اجرا نسبت داده نمی‌شود.

حساب، فایل‌های نصب کاربر و WoW در محیط نیستند. هیچ install/update/repair/product endpoint فراخوانی نمی‌شود. فایل‌های Agent/راه‌انداز در VM موقت می‌توانند نوشته شوند. سقف 128 MiB فقط دانلود مستقیم راه‌انداز است؛ سقف سخت حجم شبکهٔ فرزند وجود ندارد. job محدود به زمان است؛ دانلود بازی درخواست نمی‌شود. هیچ runner پولی یا زیرساخت تازه خریداری نشده؛ سهمیهٔ حساب GitHub ممکن است مانع اجرا شود.

## تفسیر نتیجه و گام بعد

- `handshake_token_observed`: توکن ارتباط محلی در این محیط بدون ورود حساب مشاهده شد. فقط همین؛ هنوز token به هیچ درخواست بعدی فرستاده نشده است.
- `handshake_without_token` / `http_rejected`: پاسخ همان مسیر برای فرضیه کافی نبود؛ این نتیجه به معنی الزام ورود حساب یا ناممکن بودن آپدیت بدون ورود نیست.
- توقف پیش از HTTP: علت محیط/آماده‌سازی/هویت/listener باید از شواهد محدود بررسی شود؛ bypass محافظ یا کلیک خودکار مرحلهٔ بعد ممنوع است.

پس از نتیجهٔ مثبت، endpointهای مشاهده/وضعیت باید از منبع و آزمایش محدود شناسایی شوند. قبل از انتخاب آزمایش Classic، حجم قابل‌اعتماد دانلود/نصب همان محصول و build، فضای staging و حاشیهٔ امن در برابر فضای واقعی runner بررسی می‌شود. اگر جا نشود، دانلود شروع نمی‌شود؛ میزبان بزرگ‌تر بدون تأیید هزینه تهیه نمی‌شود. نصب یک build تازه به‌تنهایی تست آپدیت نسخه‌به‌نسخه نیست؛ برای آن baseline قدیمی معتبر و target تازه‌تر لازم است.

موفقیت Classic شاهد سیاست کامل Retail نیست. فعلاً نه 130 گیگ کپی، نه فایل حجیم کاربر، نه رمز حساب و نه اجازهٔ تغییر نصب اصلی لازم است.
