# تحویل جلسهٔ Unified Firewall — HF1.1 تا HF1.2.2 و شروع اتصال مجدد SSTP

## ابتدا این بخش را بخوانید

- هدف کاربر: پایهٔ کوچک و قابل اتکا برای نصب/دانلود Battle.net با مسیر مجاز SSTP؛ نه گسترش بی‌پایان داشبورد عمومی فایروال.
- خواستهٔ صریح: وقتی ایزولاسیون روشن و VPN خاموش است، اتصال VPN مجاز نباید نیازمند خاموش‌کردن ایزولاسیون باشد؛ ترافیک برنامه نباید بیرون تونل باز شود.
- هدف اولیهٔ حریم خصوصی هنوز حل نشده: وایت‌لیست IP/پورت، عدم ارسال فینگرپرینت در یک ارتباط مجاز را اثبات نمی‌کند. فیلتر محتوای کامل تحویل نشده و هیچ گواهی no-leak صادر نشده است.
- کاربر یک سیستم Windows آزمایش مستقل دارد و قبلاً آزمون‌های واقعی زیادی انجام داده است؛ دوباره از او نپرسید آیا سیستم آزمایش دارد.
- آخرین وضعیت واقعی: بازیابی محدود HF1.1 کامل شد و کاربر برگشت اینترنت را تأیید کرد. پس از آن فقط آزمون‌های خواندنی اجرا شدند؛ Apply جدید درخواست نشده است.
- آخرین سورس توسعه: HF1.2.2 با خواندن گروهی فقط در ساخت طرح Prepare؛ نسخهٔ نصب یا Apply نیست.
- کار باز: اتصال مجدد SSTP. kernel تصمیم با ۶۷ بررسی و مشاهده‌گر بومی فقط‌خواندنی v0.2 با ۸۴ بررسی مدل ساخته شده‌اند؛ مشاهده‌گر در دو اجرای واقعی Windows در حالت connected تأیید شد؛ endpoint، حالت disconnected، executor و اتصال مجدد واقعی هنوز تأیید/تکمیل نشده‌اند. [پیشرفت تازهٔ مشاهده‌گر](../analysis/unifiedfw-session-2026-10-27/observer-v02/README.fa.md).

## منشأ و نسخه‌ها

شاخهٔ ادامه: `analysis/entry-loader-startup-2026-10-23`؛ این سینک main یا فایل‌های بازی را عوض نمی‌کند. سورس پایهٔ بازبینی‌شده در commit `f4ba758b1aa358e2a36c4fda7795072d7b700acc` و مسیر `analysis/unifiedfw-desktop-0.9.10-2026-10-25` قرار دارد. ۲۲۹ فایل سورس/شاهد آرشیو ۰.۹.۱۰ با Git blobها تطبیق داشتند. وجود آزمون‌های واقعی قدیمی Windows را انکار نکنید؛ اما آن‌ها را به تأیید خودکار ایزولاسیون سراسری فعلی تعمیم ندهید.

HF1/HF1.1 دو اصلاح محدود داشتند: خواندن درست `DisabledInterfaceAliases` در پروفایل‌ها، و نگه‌داشتن task محافظ تا پایان موفق Restore. روی سیستم کاربر، null در ActiveStore فقط با property موجود و نوع CIM برابر StringArray پذیرفته شد؛ property ناشناخته/نوع نامعلوم همچنان رد می‌شود. این اصلاح شکل تصویر چهار‌فیلدی پروفایل و قیود ژورنال را عوض نمی‌کند.

## حادثهٔ Apply و بازیابی واقعی

پس از Prepare، آزمون زندهٔ HF1.1 با `iso_owned_drift_before_enable` شکست خورد؛ phase برابر `arming_failed_no_automatic_allow` شد. چهار قانون خود برنامه ساخته شده بودند و ۱۰۰ Allow خارجی در ژورنال پشتیبان داشتند. Restore عادی با `iso_restore_owned_rule_drift` متوقف شد و اینترنت قطع ماند.

رسید فقط‌خواندنی مشخص کرد هر چهار قانون خود برنامه غیرفعال بودند. در قوانین ۱، ۲ و ۴ تنها اختلاف `interface.InterfaceAlias` بود؛ اختلاف صرفاً جابه‌جایی ترتیب نبود. قانون ۳ با تصویر غیرفعال تطبیق داشت. علت دقیق تغییر Alias هنوز اثبات نشده است؛ ترتیب قبلیِ Block/قرنطینه قبل از فعال‌سازی حمل SSTP یک خطر وابستگی بود، نه علت قطعی ثابت‌شده.

بازیابی یک‌بارهٔ محدود فقط برای همان ژورنال و با تأیید کاربر اجرا شد: مالکیت و غیرفعال‌بودن چهار قانون، همهٔ تصاویر خارجی، پروفایل‌ها و هویت task پیش از تغییر بررسی شدند. حذف چهار قانون فقط با استثنای InterfaceAlias انجام شد، سپس Restore اصلی بدون شل‌کردن مقایسهٔ عمومی اجرا شد. رسید: `owned_rules_removed=4`، `foreign_restored=100`، `profiles_restored=3`، cleanup task و backup ژورنال موفق. کاربر برگشت اینترنت را تأیید کرد. 4/4 پایان حذف قوانین بود، نه پایان کل Restore.

اسکریپت بازیابی به همان جلسه مقید بود؛ آن را برای جلسهٔ تازه دوباره اجرا یا به force-Allow تبدیل نکنید. شناسه‌های واقعی مالک/جلسه، ژورنال محافظت‌شده و پشتیبان خصوصی وارد این مخزن نشده‌اند.

## تغییرات آفلاین HF1.2

1. کامپایلر نام دقیق قانون محدود SstpSvc به IP مشاهده‌شدهٔ سرور روی TCP/443 را جدا می‌کند. Arm آن را با همان seal/اعتبارسنجی سخت‌گیرانه، قبل از Block پروفایل‌ها و قرنطینهٔ Allowهای قدیمی فعال می‌کند. whitelist برنامه و DNS داخل تونل بعداً فعال می‌شوند. این اصلاح در Windows Apply هنوز تأیید نشده است.
2. Restore یک callback صرفاً حذف دارد: قانون **غیرفعال Allow** متعلق به همان session/owner تنها در صورت اختلاف Alias و برابر بودن سایر فیلدها قابل حذف است؛ هویت بومی و خواندن تازه دوباره بررسی می‌شوند. این استثنا برای enable، Verify، قوانین فعال یا قواعد دیگر نیست؛ تصویر ژورنال rebased نمی‌شود.
3. ژورنال بادوام، flush/جایگزینی اتمیک فایل و ترتیب Restore حفظ شدند. نوشتن‌ها موازی نشده‌اند. snapshot خواندنی هم اتمیک نیست.

## آزمون خواندن گروهی روی Windows

HF12 نخستین بستهٔ فقط‌خواندنی بود؛ در هر دو Store در `compare_1` با PropertyNotFoundException متوقف شد. این شکست آزمون بود، نه شاهد خرابی ایزولاسیون. کد فرض می‌کرد Name حتماً در `CimInstanceProperties` خام وجود دارد؛ در حالی که Name می‌تواند property تطبیقیِ شیء PowerShell باشد. مدل قبلی این تفاوت را نداشت.

HF121 خطای هم‌نوع را محلی بازسازی و هویت را روی شیء بومی بررسی کرد، بدون اختراع فیلد در تصویر خام. کاربر HF121 را روی Windows PowerShell `5.1.26100.6899`، ۶۴بیتی اجرا کرد:

- در هر مخزن ۴۲۰ قانون دیده شد؛ چهار نمونه از هر Store مقایسه شد.
- تمام هشت **مقایسهٔ نمونه** exact_match بودند؛ لزوماً هشت قانون متمایز نیستند.
- diagnostic_completed و sampled_image_parity برابر true؛ full_store_parity_proven و optimization_approved برابر false باقی ماندند.
- تغییر فایروال/پروفایل/VPN، دسترسی ژورنال و probe شبکه درخواست نشد.
- زمان واقعی اندازه‌گیری نشد؛ این گزارش تأیید سرعت، نبود نشتی، bootstrap یا کل ۴۲۰ قانون نیست.

## ادغام HF1.2.2

`IsoPrepareForeignAllows` خواندن گروهی PersistentStore و موجودی ActiveStore را برای ساخت `name/image` طرح به کار می‌گیرد. Prepare ممکن است پیش از Apply هم اجرا شود، اما snapshot جای خواندن تازهٔ قبل/بعد از mutation یا Verify را نمی‌گیرد. محدودیت GPO، هویت تکراری، پوشش ناقص، وضعیت ناسازگار و سقف ۲۰۴۸ قانون fail-closed باقی‌اند؛ cache عمومی وجود ندارد.

در مقایسه با HF1.2، چهار فایل حساس `lab/native.ps1`، `lab/session-core.ps1`، `app/isolation-core.ps1` و `app/isolation-worker.ps1` بایت‌به‌بایت ثابت ماندند؛ هشت تابع حساس آداپتور بومی نیز ثابت‌اند. آزمون تازه نشان داد تغییر فیلتر پس از Prepare، توسط خواندن اصلی پیش از Disable رد می‌شود و در آن مسیر write/checkpoint شروع نمی‌شود.

نتایج محیط ساخت Linux: ۴۴ مجموعه‌آزمون PowerShell موفق، ۵۳۱ آزمون Python موفق و دو مقایسهٔ قدیمی skipped به‌علت نبود منبع مقایسه؛ ۹۹ فایل PS بدون خطای parser؛ ۳۳ بررسی اختصاصی ادغام. **ادغام کامل HF1.2.2 هنوز روی Windows اجرا نشده است.** سه آزمون کامپایلر فقط در مرز خواندن موجودی mock شدند؛ آزمون جدید مسیر واقعی Prepare را با بدل CIM می‌آزماید.

در بدل، بخش ساخت فهرست Allowها دو خواندن موجودی و هفت خواندن مجموعهٔ فیلتر دارد؛ این شمار کل Prepare یا ادعای چندبرابرشدن سرعت نیست.

## اتصال مجدد SSTP — وضعیت واقعی و قدم بعد

بررسی کد فعلی: detector اولیه یک SSTP متصل و full-tunnel می‌خواهد؛ DNS سرور VPN را فقط از cache/آدرس literal می‌پذیرد. guardian در خطا محدودیت‌ها را حفظ می‌کند، ولی مسیر مدیریت reconnect، تعلیق data و rebind ژورنالیِ مطمئن هنوز ندارد. نام و index به‌تنهایی زنجیرهٔ هویت کامل نیستند.

kernel تصمیم جدید زیر `reconnect-design-v01` اجراپذیر در مدل است، نه executor ویندوز. حالت‌های انتظار، تعلیق data، نیاز به bootstrap، rebind محدود، بررسی تازه و online candidate را جدا می‌کند. از ورودی ناقص/نوع نادرست مجوز نمی‌سازد. ورودی‌های اعتماد باید بعداً از observer بومی معتبر بیایند؛ boolهای داخل config مدرک امنیتی نیستند. ۶۷ بررسی گذشت؛ هیچ فرمان فایروال، dial/hangup، probe، DNS یا تغییر TLS اجرا نشده است.

قدم بعد دقیق:
1. مشاهده‌گر v0.2 در دو اجرای واقعی connected گذشت؛ آزمون تکرار نشود. disconnected/reconnect و cross-run binding هنوز آزموده نشده‌اند. گام بعد طراحی مشاهدهٔ endpoint/pin/service با تفکیک ابهام PID مشترک است. سپس بررسی اتصال هویت مشاهده‌شده به پروفایل تأییدشده؛ GUID+scope+hostname و full-tunnel، سپس زنجیرهٔ RAS/projection/interface GUID/LUID و بازخوانی برای اتصال تازه. ماژول قدیمی ۰.۱.۲ فقط منبع بازبینی است، نه انتقالِ تأییدشده.
2. قرارداد executor تعلیق data و rebind دقیقِ همان مالک با seal، ژورنال و خواندن تازه؛ بدون گسترش alias، IP یا port و بدون مساوی‌گرفتن تغییر index با هویت درست.
3. bootstrap DNS، underlay/DHCP و TLS/گواهی را جدا حل کنید. اجازهٔ عمومی DNS/443 راه‌حل پذیرفته‌شده نیست. تغییر hostname به IP ممکن است با نام گواهی ناسازگار باشد؛ بررسی hostname/TLS/گواهی نباید خاموش شود. pin محلی/hosts صرفاً گزینهٔ طراحی با رضایت و بازیابی اختصاصی است؛ پیاده یا مجاز نشده است.
4. زمان‌بندی دوره‌ای guardian به‌تنهایی ضمانت اتمیک در برابر تغییرات رابط/Admin/GPO/WFP نیست. بدون شاهد بومی و packet test، «همهٔ دروازه‌ها بسته‌اند» نگویید.
5. تست تازهٔ Apply/قطع VPN/راه‌اندازی مجدد درخواست نکنید تا وابستگی‌ها و بازیابی مشخص شوند. آزمون خواسته‌شدهٔ v0.2 انجام شد؛ اکنون اقدام تازه یا تکرار آزمون لازم نیست.

منابع بررسی‌شده برای این مرحله: [MS-SSTP و تطبیق نام گواهی/EKU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/60a4676f-7eec-495e-926f-af7b22a72a40)، [ترتیب cache/hosts/DNS در Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/troubleshoot-dns-client-resolution-issues). این‌ها تأیید رفتار سرور VPN کاربر یا کفایت cache گواهی نیستند.

## نکات عملی Windows

- PowerShell 5.1 quoting در `python -I -c $code` خراب شد؛ کد چندخطی Python را از stdin بفرستید: `$code | & <python> -I - <root>`.
- `foreach {...} | Format-Table` مستقیم parser error داد؛ ابتدا خروجی را به متغیر اختصاص دهید.
- همهٔ policy scopeهای کاربر ابتدا Undefined بودند. فقط child process با RemoteSigned و Unblock فایل‌های دقیقاً hash-verified استفاده شد؛ Bypass یا تغییر دائمی policy پیشنهاد نشود.
- paste خط‌به‌خط پس از خطای بارگذاری باعث اجرای خطوط بعد و پیام گمراه‌کنندهٔ «No differences» شد. بستهٔ guarded/کامل بهتر از دستورهای پراکنده است.
- تنظیم SplitTunneling برای آزمایش با رضایت کاربر به false تغییر کرد؛ recovery فایروال آن را برنگرداند. پیش از هر تغییر بعدی، وضعیت فعلی را بررسی کنید؛ از روی سابقه فرض نکنید.
- دامنه‌های هدف `us.version.battle.net` و `level3.blizzard.com` هستند. whitelist کوچک آزمایش نصب‌گر کامل نبود؛ IPهای قدیمی DNS با TTL کوتاه را whitelist جاری تلقی نکنید.

## دامنهٔ سینک

سورس overlay و manifest محتوای آن، سورس ابزارهای خواندنی، رسیدهای پالایش‌شده، خلاصه‌های QA، kernel تصمیم، هش بسته‌های تحویل و این handoff ذخیره شده‌اند. transcript خام، runtime/EXE/ZIP، اطلاعات ورود، آدرس/نام سرور VPN، مسیر کاربر، ژورنال و backup خصوصی منتشر نشده‌اند. بسته‌های قدیمی در artifact index با وضعیت تاریخی مشخص‌اند؛ hash داشتن = مجوز اجرا یا qualification نیست. README مخزن فقط یک نشانگر تازه در ابتدا می‌گیرد و سابقه حفظ می‌شود.

## شرط تازهٔ نوع اتصال فیزیکی

کاربر گفت دو اجرای فعلی با دانگل USB وای‌فای انجام شده‌اند و بعداً قرار است کابل Ethernet استفاده شود. خود JSON نوع carrier را اندازه‌گیری نکرده؛ این بخش گزارش مستقیم کاربر است. شرط طراحی: حمل SSTP به نام/شمارهٔ کارت فیزیکی بایند نشود؛ data فقط روی هویت معتبر SSTP مجاز بماند.

بازبینی و مدل کامپایلر نشان داد قانون حمل فعلی InterfaceAlias/InterfaceType=Any دارد، اما همچنان program/service/IP/TCP443 دقیق است؛ قوانین data و DNS به رابط SSTP/RemoteAccess محدودند. مدل جداگانه تغییر نام/index فیزیکی را مستقل از قواعد تشخیص داد؛ این آزمون واقعی جابه‌جایی کارت نیست. با همان alias ممکن است index/نشست VPN عوض شود، پس مشاهدهٔ هویت و rebind لازم باقی است.

پیکربندی IP، DHCP، route، DNS و احتمال IPv6 متفاوت در کارت تازه زیر ایزولاسیون هنوز حل/آزموده نشده‌اند. هیچ استثنای عمومی یا تغییر تنظیم برای رفع ظاهری اضافه نشده است. Windows Ethernet و تعویض واقعی کارت تأیید نشده؛ کاربر فعلاً شبکه را عوض نکند.


## آخرین گام — مشاهده‌گر مقصد v0.3

[کد، دامنه و محدودیت‌ها](../analysis/unifiedfw-session-2026-10-27/endpoint-v03/README.fa.md): بستهٔ مستقل فقط‌خواندنی با ۵۸ assertion جدید و ۸۴ lifecycle آماده شد؛ نتیجهٔ endpoint واقعی Windows هنوز نداریم. اقدام جاری، یک اجرای بدون تغییر وضعیت VPN/فایروال و ارسال JSON است. عبارت‌های قدیمی «اکنون اقدامی لازم نیست» مربوط به پایان آزمون v0.2 هستند؛ مرحلهٔ جاری را از LATEST و CURRENT بخوانید. هیچ مجوز Apply/Restore صادر نشده است.


## تازه‌ترین گام — اصلاح گزارش‌گیری v0.3.1

[رسیدها و مرز اصلاح](../analysis/unifiedfw-session-2026-10-27/endpoint-v031/README.fa.md). v0.3 در دو اجرای Windows پیش از endpoint متوقف شد؛ اجرای دوم unknown بود و علت lifecycle پنهان ماند. v0.3.1 این علت را نگه می‌دارد، guardها بدون تغییرند. اکنون بستهٔ جدید فقط‌خواندنی برای یک اجرا در وضعیت موجود درخواست شده است؛ دستور قدیمی اجرای v0.3 جایگزین شده. هیچ Apply یا تغییر شبکه درخواست نشده است.


## آخرین نتیجه — مشاهدهٔ endpoint روی Windows تکمیل شد

[رسید و تحلیل](../analysis/unifiedfw-session-2026-10-27/endpoint-v031/windows-results/CONNECTED-REVIEW.fa.md). پس از Connected/False پروفایل فعلی، v0.3.1 یک هویت پایدار داخل اجرا و یک endpoint همبسته در host تک‌سرویس مشاهده کرد. کاربر فعلاً اقدام یا تکرار آزمون ندارد؛ گام بعد توسعهٔ آفلاین pin/طرح bootstrap است. این موفقیت را no-leak، service-tag، امضا، reconnect یا Apply تلقی نکنید. دستور قبلی برای اجرای v0.3.1 انجام شده و دیگر اقدام جاری نیست.


## گام آفلاین بعد از مشاهدهٔ موفق — draft حمل دقیق

[کد و مرزها](../analysis/unifiedfw-session-2026-10-27/exact-transport-plan-v01/README.fa.md) و [bootstrap gates](../analysis/unifiedfw-session-2026-10-27/exact-transport-plan-v01/BOOTSTRAP-GATES.fa.md). ۸۶ assertion مدل گذشت. این سازنده هیچ approval یا دستور اعمال نمی‌سازد؛ digest تنها fingerprint ورودی است و منبع اعتماد نیست. مرحلهٔ بعد adapter بازبینی محلی با native revalidation است. کاربر فعلاً اقدامی ندارد.


## آخرین توسعه — بازبینی محلی draft مقصد

[adapter و راهنما](../analysis/unifiedfw-session-2026-10-27/local-review-v01/README.fa.md): readerهای موجود به نمایش محلی، challenge دستی و revalidation پس از prompt وصل شدند. ۶۴ assertion جدید و رگرسیون‌های قبلی گذشتند. هیچ approval اجرایی/persistence یا Apply نداریم. اکنون یک اجرای بستهٔ جداگانه روی وضعیت فعلی Windows درخواست شده؛ raw console ارسال نشود، فقط JSON sanitized حتی در لغو/شکست. عبارت قدیمی «اقدام لازم نیست» مربوط به گام آفلاین قبلی است.


## تازه‌ترین رسید — توقف بازبینی قبل از prompt

[رسید و اصلاح v0.1.1](../analysis/unifiedfw-session-2026-10-27/local-review-v011/README.fa.md): v0.1 در review_unique_stable_endpoint_required متوقف شد؛ علت دقیق به دلیل نبود شمارنده معلوم نیست. نسخهٔ جدید فقط metrics بدون raw identity اضافه می‌کند؛ guardها تضعیف نشده‌اند. گام جاری یک اجرای بدون تغییر وضعیت و دریافت JSON جدید است؛ هیچ approval انسانی قبلی ثبت نشده است.


## اولویت جدید — رخداد قطع اینترنت و HF1.2.3 آفلاین

[شرح کامل و اصلاح](../analysis/unifiedfw-session-2026-10-27/recovery-hf123/README.fa.md). اینترنت بدون VPN با تغییر صریح و مجاز فقط خروجی پیش‌فرض به Allow برگشت؛ فایروال روشن ماند. ژورنال restored/before NotConfigured با وضعیت Block تطبیق نداشت. علت reboot ثابت نیست؛ باگ early-return و UI و قرارداد local NotConfigured در کپی آفلاین اصلاح شدند. ۴۵ PS suite و ۵۳۱ Python+۲ skip و ۴۹ recovery assertion گذشت. patch روی Windows نصب/تست نشده؛ source-only است. تمام درخواست‌های قبلی اجرای local-review/Apply/Restore فعلاً لغو/متوقف‌اند. کاربر اقدام تازه ندارد؛ backup را نگه دارد و اینترنت عادی را دست‌کاری نکند.


## آخرین توسعه — رکورد جداگانهٔ خروج به حالت عادی HF1.2.4

[کد، قرارداد و مرز اعتماد](../analysis/unifiedfw-session-2026-10-27/normal-exit-hf124/README.fa.md): کتابخانهٔ واقعی Review/Record با consent دقیق، digest تازه، بررسی قواعد/پروفایل‌ها/task، قفل و CreateNew ساخته شد. ۷۲ assertion اختصاصی و ۴۶ PS suite و ۵۳۱ Python+۲ skip گذشتند. کد بازیابی/worker/UI/helperهای محافظت‌شده بدون تغییر بایت‌اند. ژورنال کاربر یا سیستمش تغییر نکرد؛ رکورد هنوز روی Windows کاربر نوشته نشده، migration و Apply-authority ندارد. کاربر اقدام تازه‌ای ندارد.


## جدیدترین تحویل — NORMAL-EXIT-REVIEW-01

[راه‌انداز، source و راهنمای اجرا](../analysis/unifiedfw-session-2026-10-27/normal-exit-runner-v01/README.fa.md): fixture جدا برای آزمون واقعی Windows storage، سپس real read-only review و consent اختیاری ثبت رکورد جداگانه. ۴۷ assertion runner و ۷۲ library rerun و parse/hash گذشتند؛ Windows هنوز pending است. کاربر فقط همین بستهٔ جدید را بدون تغییر اینترنت/VPN اجرا می‌کند و JSON را برمی‌گرداند؛ لغو prompt مجاز است. legacy journal و firewall تغییر نمی‌کنند؛ در failure پس از write attempt، وجود رکورد باید بررسی شود. Apply/migration/reboot/no-leak authority وجود ندارد و مسیرهای قدیمی همچنان متوقف‌اند.


## دریافت نتیجهٔ Windows NORMAL-EXIT-REVIEW-01

storage fixture تماماً گذشت و cleanup موفق بود؛ real legacy journal preserved=true. real review با normal_exit_current_profile_not_normal_allow پیش از prompt/record متوقف شد. هیچ تغییر firewall/VPN یا نوشتن رکورد واقعی درخواست نشد. field دقیق معلوم نیست؛ فقط دو-store profile table برای Name/Enabled/DefaultOutboundAction/AllowLocalFirewallRules درخواست شود؛ از روی این کد Block مجدد را نتیجه نگیرید. [receipt](../analysis/unifiedfw-session-2026-10-27/normal-exit-runner-v01/evidence/Windows-normal-exit-review-01-result.json).


## تازه‌ترین شواهد — ترتیب زمانی تغییر Block

[رسید امن زمان‌بندی](../analysis/unifiedfw-session-2026-10-27/normal-exit-runner-v01/evidence/Windows-profile-change-timeline.json): هر سه profile در ۰۶:۲۹:۰۹ محلی Allow و در ۰۷:۲۳:۰۵ محلی Block شده‌اند؛ رویداد اخیر UTC=04:23:05.1253967 است. نام گزارش runner UTC=04:23:51 و در کد پیش از qualification و review ساخته می‌شود؛ پس review این اجرای مشخص حدود ۴۶ ثانیه پس از رویداد Block آغاز شده است، نه پیش از آن. این نتیجه همهٔ نسخه‌های قدیمی یا علت تغییر را تعیین نمی‌کند.

WmiPrvSE.exe فقط نام میزبان ثبت‌شده است؛ requester معلوم نیست. task شناخته‌شده صفر و process match فعلی صفر، عدم وجود writer گذشته را ثابت نمی‌کند. کاربر reboot یا بازکردن UI قدیمی را در فاصله رد کرده؛ SSTP متصل است. لاگ فعال با ۸۵۹ رکورد Circular است. WMI چهار event خواند ولی ردیف دارای ClientProcessId نداد؛ نبود requester دلیل نبود درخواست نیست. XPathهای قبلی namespace را لحاظ نمی‌کردند و باید با local-name اصلاح شوند؛ «فیلد خالی» قبلی مشکل parser بود.

ممیزی top-level مسیر مستقیم setter در runner/review پیدا نکرد، اما اثبات رفتار پلتفرم نیست. آزمون/تغییر جدیدی روی سیستم درخواست نشود؛ WmiPrvSE را نبندید و Allow را کورکورانه تکرار نکنید. علت تاریخی هنوز حل نشده. live Apply/Restore/reconnect متوقف؛ ادامهٔ آفلاین باید به بنیاد کوچک نصاب Battle.net، reader حداقلی بدون بارگذاری mutatorهای نامرتبط و baseline صریح local/effective متمرکز بماند، نه گسترش بی‌پایان ابزار تشخیصی.
