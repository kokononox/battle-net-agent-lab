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


## جدیدترین پیشرفت کد — reader حداقلی مستقل ۰٫۱

[کد و قرارداد](../analysis/unifiedfw-session-2026-10-27/minimal-readonly-v01/README.fa.md): یک module مستقل با تنها entry خواندنی؛ هیچ dependency از runtime قدیمی و هیچ تعریف mutator ندارد. local/effective جدا، NotConfigured بدون coercion، coverage/encoding/exclusion guard و دو مشاهدهٔ برابر با چهار getter در مسیر موفق. Block مشاهدهٔ معتبر است نه normal mode یا protection. همهٔ authorityها false؛ snapshot اتمیک نیست.

۵۴ assertion آفلاین با Windows getter mock گذشت؛ ۷۲ library و ۴۷ runner قبلی دوباره pass شدند. payload تحویل قبلی byte-unchanged است. ماژول جدید روی Windows آزموده نشده، worker-integrated یا deployed نیست. هیچ اقدام کاربری درخواست نمی‌شود؛ اینترنت/SSTP فعلی همان‌طور بماند و Apply/Restore/reconnect/Allow قدیمی تکرار نشود. مرحلهٔ بعد ادغام آفلاین قرارداد خواندن در preflight و آزمون reset-free recovery هستهٔ کوچک نصاب Battle.net است؛ این reader به‌تنهایی ابزار ایزولاسیون یا حل cold-start نیست.


## جدیدترین توسعه — هستهٔ کوچک، ادغام و recovery callback ۰٫۱

[کد، آزمون و مرزها](../analysis/unifiedfw-session-2026-10-27/installer-core-v01/README.fa.md): ورودی عمومی فقط‌خواندنی به reader واقعی با hash pin وصل شد. reader بدون تغییر بایت است. منطق private بازیابی profile_outbound_only با Save/ReadProfiles/WriteOutbound حافظه‌ای آزموده شد؛ هیچ native writer یا journal دیسکی این مسیر ساخته نشده است و draft execution_authorized=false مجوز اجرا نیست.

۷۸ assertion جدید pass: اتصال کامل getter-mock، pin mismatch، schema/baseline guards، ۸ خطای Save، ۳ خطای write، ۳ crash پس از write، resume بدون duplicate write، readback/drift/final-sweep و restored-stamp checks، baseline Block بدون Allow، عدم وابستگی به ترتیب property/row. ۵۴ reader و ۷۲ library و ۴۷ runner قبلی نیز rerun شدند؛ Windows و persistence واقعی آزموده نشده‌اند. full regression تاریخی rerun نشده و payload قبلی unchanged است.

profile-stage completed یا سازگاری draft، preflight کامل/ایزولاسیون نیست؛ pending components در خروجی آشکار و ready_for_apply/no_leak_certified=false است. کاربر اقدام ندارد، سیستمش تغییر نکرده است. مرحلهٔ بعد authorization و journal جدید محافظت‌شده با failure tests پیش از native write است؛ old NotConfigured journal یا normal-mode receipt هیچ bypass مجوزی نمی‌گیرند.


## جدیدترین توسعه — رضایت محدود و ژورنال مستقل ۰٫۱

[کد و قرارداد](../analysis/unifiedfw-session-2026-10-27/session-journal-v01/README.fa.md): رضایت دقیق challenge برای prepare_profile_journal_only با session/baseline binding، مهلت ۱۲۰ ثانیه، بازخوانی پیش/پس write؛ scope عمداً authorizes_firewall_change=false است، نه consent اجرای ایزولاسیون. JSON consent_validated=true به‌تنهایی capability یا اثبات مستقل انسان نیست. public entry نوشتن هنوز غیرفعال است؛ تنها export capabilities است.

adapter جدید Windows storage در root مستقل InstallerSessions ساخته شد؛ ACL هنگام ایجاد admin/SYSTEM و guard مسیر/owner/DACL دارد، اما API/ACL واقعی Windows آن آزموده نشده است. checkpointهای CreateNew شماره‌دار با lock انحصاری، Flush، checksum، hash-chain، schema/phase/flag checks و readback جایگزین overwrite می‌شوند. فایل مبهم پس از failure حفظ و write_attempted از موفقیت جدا می‌شود. hash-chain نه WORM/HMAC است، نه تضمین کشف tail rollback یا power-loss کامل.

۷۳ assertion جدید با فایل واقعی Linux و metadata ACL mock گذشت؛ recovery core با checkpoint واقعی و profile writer حافظه‌ای تا ۱۱ رکورد آزموده شد. ۷۸ core، ۵۴ reader، ۷۲ HF124 و ۴۷ runner rerun و parse چهار فایل گذشت. core/reader و payload کاربر unchanged اند. هیچ native firewall writer، migration ژورنال قدیمی، deployment یا no-leak/Apply authority نداریم.

کاربر اقدام تازه ندارد؛ مرحلهٔ بعد fixture جداگانهٔ storage-only روی Windows برای همین adapter است، بدون تماس با ژورنال قدیمی یا تغییر شبکه. consent واقعی policy/SSTP و recovery native هنوز pending هستند؛ علت Block تاریخی حل نشده است.


## جدیدترین تحویل — UFW-JOURNAL-STORAGE-01، فقط fixture ذخیره‌سازی

[بسته، source و راهنمای اجرا](../analysis/unifiedfw-session-2026-10-27/journal-storage-test-v01/README.fa.md): سه module بدون تغییر بایت بسته‌بندی شدند. fixture جدید فقط در root جداگانهٔ ProgramData با دادهٔ ساختگی، ACL root/session/record/lock، CreateNew، stale head، exclusive lock، chain، ۱۱ checkpoint با recovery حافظه‌ای، baseline change و فساد/partial record را بررسی می‌کند. هیچ real profile query، consent/store واقعی، legacy journal یا تغییر network/rule/task/VPN اجرا نمی‌کند. پاک‌سازی غیرrecursive و مشروط به validation تمام ساختار است.

۳۶ assertion بسته و ۷۳ ژورنال و parse پنج PS file/CMD و payload hash گذشتند؛ **Windows واقعی هنوز pending است**. simulation Linux native/ACL flagهای Windows را false نگه می‌دارد. اقدام کاربر فقط ZIP تازه در پوشهٔ جدا و Run-Test.cmd با admin همان حساب؛ SSTP/شبکه همان وضعیت. فقط JSON تشخیصی حتی failure برگردد. cleanup failure را با حذف/تکرار خودسرانه دنبال نکنید. engine Apply/Restore، consent نشست واقعی و همهٔ authorityهای ایزولاسیون همچنان غیرفعال‌اند؛ علت تاریخی Block حل نشده است.


## آخرین نتیجه و اصلاح — UFW-JOURNAL-STORAGE-011

[تحویل اصلاحی و receipt](../analysis/unifiedfw-session-2026-10-27/journal-storage-test-v011/README.fa.md): v01 روی Windows، ACL و roundtrip/lock/no-overwrite/stale-head را پاس کرد و cleanup موفق بود، ولی memory-profile recovery با ufw_core_profile_coverage متوقف شد؛ full qualification پاس نشده است. falseهای مراحل بعد و count=0 را به معنی اجرای آن مراحل/نبود رکورد نگیرید.

whole-array JSON clone در WinPS5.1 می‌تواند nested array بدهد. shim این قرارداد روی PS7 دقیقاً خطای v01 را بازتولید کرد و یک‌خط اصلاح row-wise clone در v011 کل fixture را عبور داد. سه module تولیدی و guard سه profile unchanged اند؛ ۳۶ fixture، ۷۳ journal و ۱۰ compatibility assertion گذشتند. **اجرای واقعی Windows نسخهٔ اصلاحی هنوز pending است.**

کاربر فقط ZIP v011 در پوشهٔ جدا با admin همان حساب و بدون تغییر شبکه/SSTP اجرا کند؛ JSON جدید UFW-JOURNAL-STORAGE-011-*.json حتی failure برگردد. هیچ Apply/Restore/real session store، profile query یا legacy access درخواست نشده است.


## تازه‌ترین نتیجهٔ واقعی — STORAGE-011 روی Windows کامل پاس شد

[receipt واقعیِ بدون اطلاعات شخصی](../analysis/unifiedfw-session-2026-10-27/journal-storage-test-v011/evidence/Windows-storage-011-passed-result.json): completed=true در runner و fixture، Windows PS5.1 x64، payload verified، ACL root/session/record/lock، roundtrip، CreateNew/no-overwrite، stale head، exclusive lock، append chain، baseline-change و checksum/partial refusal همه true؛ recovery حافظه‌ای با ۱۱ checkpoint واقعی فایل و cleanup موفق است. اصلاح row-wise JSON clone در همین اجرای Windows تأیید شد.

این فقط **qualification fixture ذخیره‌سازی همین اجرا** است، نه original Restore/Apply/WFP/reboot/SSTP/fingerprint/no-leak. consent انسانی واقعی، نوشتن نشست واقعی در root تولیدی و recovery بومی هنوز انجام نشده‌اند. profile query/legacy access/firewall/VPN/DNS changes همگی requested=false و ready_for_apply/no_leak_certified=false اند. علت Block تاریخی همچنان مجهول است.

کاربر اقدام ندارد و این آزمون موفق تکرار نشود؛ شبکه/SSTP همان حالت بماند. مرحلهٔ بعد runner کنترل‌شدهٔ preparation-only با fresh real profile read و رضایت محدود ثبت ژورنال مستقل است، نه consent برای تغییر فایروال. وجود baseline صریح Block به معنی ایزولاسیون سالم یا اجازهٔ تبدیل به Allow نیست؛ تمام guardهای policy/SSTP/native recovery پابرجا می‌مانند.


## گام بعد آماده شد — UFW-PREPARE-SESSION-01

راه‌انداز محدود [source و بسته](../analysis/unifiedfw-session-2026-10-27/prepare-session-v01/package/UFW-PREPARE-SESSION-01/) خواندن واقعی profileها را به review و consent مخصوص ثبت preparation متصل می‌کند. سه ماژول تولیدی همان بایت‌های milestone قبلی‌اند و native firewall writer وجود ندارد. ۶۰ بررسی راه‌انداز، با getter/prompt شبیه‌سازی‌شده و فایل واقعی Linux، و ۷۳ بررسی ژورنال دوباره پاس شدند؛ پنج PS file و bootstrap/manifest/ZIP کنترل شدند. این آمار، اجرای واقعی WinPS5.1 راه‌انداز یا consent انسانی نیست. آزمون STORAGE-011 قبلاً روی Windows کامل پاس شد و دوباره لازم نیست.

کاربر فقط بستهٔ تازه را در پوشهٔ جدا با همان حساب و admin اجرا می‌کند؛ شبکه و SSTP بدون تغییر. baseline فعلی Block در هر سه profile فقط برای preparation قابل ثبت است، نه normal-mode یا isolation qualification. prompt دقیق `PREPARE JOURNAL <ID> <nonce>` حداکثر دو دقیقه و تنها برای ثبت فایل معتبر است؛ Enter خالی/پاسخ متفاوت بدون نوشتن ژورنال نشست لغو می‌کند و گزارش تشخیصی می‌سازد. عبارت تأیید و فایل محافظت‌شده هرگز ارسال نشوند؛ فقط JSON تازهٔ sanitized. موفقیت سه preflight/۱۲ getter call، یک prepared checkpoint مستقل و authorizes_firewall_change=false دارد. تغییر baseline/انقضا/ACL نامعتبر متوقف می‌کند. پس از attempted write ممکن است رکورد باقی مانده باشد؛ تکرار/حذف خودکار مجاز نیست.

root جدید CommonApplicationData/UnifiedFW-InstallerSessions-01 از ژورنال قدیمی مستقل است؛ legacy read/migration، Apply/Restore، Block→Allow، rule/task/VPN/route/DNS changes انجام نمی‌شود. native recovery، policy/rules/SSTP integration، cold-start/reconnect، reboot، fingerprint و no-leak همچنان حل/تأیید نشده‌اند. هدف همان نصاب کوچک بتل‌نت است؛ این مرحله تنها مبنای بازیابی مستقل آن را ثبت می‌کند، نه محصول نهایی.

وضعیت جاری برای جلوگیری از برداشت اشتباه: آخرین گفتهٔ کاربر SSTP connected، بدون reboot بعد از Allow قبلی؛ آخرین خروجی profileها Block محلی/موثر هر سه بود. علت برگشت Block مجهول است. موفقیت اینترنت بدون VPN پس از Allow یک رخداد تاریخی است نه اثبات وضعیت فعلی؛ normal-exit review بعد از Block آغاز شده و WmiPrvSE.exe فقط host است نه انتساب requester. هیچ آزمون زندهٔ Apply/Restore/reconnect درخواست نشده است.


## نتیجهٔ واقعی Windows — PREPARE-SESSION-01 موفق شد

[receipt پاک‌سازی‌شده](../analysis/unifiedfw-session-2026-10-27/prepare-session-v01/evidence/Windows-preparation-01-passed-result.json): Windows PS5.1.26100.6899 x64، payload verified، review_shown/consent_received/journal_preparation_recorded=true، code=ufw_journal_prepared_no_firewall_authority و write_status=prepared_and_revalidated_no_firewall_authority. سه preflight موفق با چهار getter در هرکدام (۱۲ query)؛ در هر سه، Domain/Private/Public local/effective outbound=Block، firewall enabled=True، effective localrules=True و local localrules=NotConfigured بدون تفاوت مشاهده شده‌اند. این یک نتیجهٔ actual Windows است، نه مدل Linux.

بسته واقعاً profile reader/core preflight و ثبت نشست مستقل preparation را طی کرده؛ مرحلهٔ ذخیره‌سازی و بازخوانی داخلی و postwrite observation پاس شده‌اند. receipt هیچ challenge/session ID/private path ندارد. VPN در این runner query نمی‌شود؛ وضعیت SSTP از گفتهٔ قبلی کاربر است نه این receipt. legacy access/firewall/VPN/DNS changes requested=false، normal_mode_restored/original_restore_verified/ready_for_apply/no_leak_certified=false. بدون packet capture یا تله‌متری مستقل، این فیلدها ادعای اثبات جامع نبود هرگونه ترافیک/تغییر نیستند.

موفقیت فقط preparation همین اجراست؛ بازکردن همان رکورد در process مستقل، reboot، native recovery، rule/SSTP binding و Apply هنوز تست نشده‌اند. baseline Block باید به عنوان Block نگه داشته شود، نه تبدیل بی‌اجازه به Allow یا ادعای اینترنت عادی. علت Block قبلی همچنان مجهول است. آزمون موفق را تکرار نکنید، journal را حذف/بازسازی نکنید و شبکه/SSTP را همان وضعیت نگه دارید.

گام بعد محدود: ساخت و آزمون validator مستقل read-only برای بازخوانی نشست جدید و مقایسه با profile تازه؛ ACL root/session/record/lock، chain/checkpoint/receipt و baseline بررسی شود. اگر چند session باشد انتخاب خودکار آخرین ممنوع؛ بدون فایل خصوصی در چت، بدون write/migration/Apply/Restore یا اعطای authority. این validator هنوز تحویل/اجرا نشده و کاربر فعلاً اقدام ندارد.


## گام تازه — بازخوان مستقل read-only آمادهٔ اجرای Windows

[بسته و source بازخوان](../analysis/unifiedfw-session-2026-10-27/reopen-session-v01/package/UFW-REOPEN-SESSION-01/) فقط root مستقل جدید و **تک‌نشست موجود** را باز می‌کند؛ root/lock/record گم‌شده را نمی‌سازد، چند نشست را خودکار انتخاب نمی‌کند و journal را repair/migrate نمی‌کند. operation.lock فقط Open/Read/FileShare.None؛ فقط یک prepared checkpoint و lock خالی مجازند. ACL، schema، receipt، baseline، checksum/chain بررسی می‌شوند. دو preflight واقعی جدید (۸ getter در موفقیت) باید با baseline یکسان باشند؛ سپس رکورد و تک‌نشست دوباره بررسی می‌شوند. گزارش، ID/path/hash/nonce ندارد. تنها خروجی جدید، JSON تشخیصی کنار بسته است؛ محتوا/ساختار journal write نمی‌شود. metadata دسترسی فایل‌سیستم ممکن است تغییر کند.

۳۸۸ assertion در ۲۴ سناریوی پایه، PS5.1 top-level JSON-array contract shim، child process تازهٔ Linux، کنترل byte/inventory، parse و boundary پاس شده؛ ۷۳ assertion ژورنال هم rerun شد. سه module قبلی بدون تغییر بایت هستند. این آمار اجرای Windows/ACL/getter واقعی بستهٔ جدید نیست؛ getterها و platform guards در مدل جایگزین شده‌اند. receipt قبلی actual Windows preparation و storage در evidence حفظ شده است.

اقدام کاربر: در پوشهٔ محلی تازه، Run-Reopen.cmd با همان حساب و admin؛ شبکه/SSTP بدون تغییر؛ prompt/consent جدید ندارد؛ فقط JSON تازه حتی در شکست ارسال شود. preparation را تکرار نکند، فایل‌های خصوصی/عکس نفرستد، journal را حذف/اصلاح نکند و تنظیمات را برای pass تغییر ندهد. old Apply/Restore، reboot یا reconnect درخواست نشده است.

موفقیت بازخوان فقط سازگاری رکورد prepared با مشاهدات همان اجراست؛ baseline Block همان Block می‌ماند. external anchor برای اثبات قطعی هویت نشست تاریخی وجود ندارد، خواندن اتمیک یا دفاع در برابر admin مخرب نیست؛ reboot/power-loss/native recovery/rule/SSTP/cold-start/reconnect/no-leak/fingerprint همچنان qualification ندارند. ready_for_apply=false؛ هدف نصاب محدود بتل‌نت باقی است، نه اضافه‌کردن اختیار Apply با خواندن یک receipt. اجرای Windows این بسته هنوز pending است.


## نتیجهٔ واقعی Windows — بازخوان مستقل REOPEN-SESSION-01 پاس شد

[receipt واقعی بدون شناسه/مسیر خصوصی](../analysis/unifiedfw-session-2026-10-27/reopen-session-v01/evidence/Windows-reopen-01-passed-result.json): Windows PS5.1.26100.6899 x64، payload verified، completed=true و code=ufw_reopen_prepared_matches_current_no_authority. یک نشست با یک prepared checkpoint معتبر؛ قفل موجود فقط‌خواندنی گرفته و آزاد شد. دو preflight تازه و هشت getter، هر دو با baseline ذخیره‌شده برابرند: Domain/Private/Public local/effective outbound=Block، enabled=True، effective localrules=True و local localrules=NotConfigured. hash بایت‌های رکورد و selection تک‌نشست در بازبینی پایانی بدون تغییر بودند.

این اجرای مستقلِ واقعی مسیر بازخوان/اعتبارسنجی موجود و profile comparison را تأیید می‌کند؛ journal write/repair، legacy access، firewall/VPN/DNS changes requested=false و normal_mode_restored/original_restore_verified/reboot_qualified/ready_for_apply/no_leak_certified=false. VPN query نشده؛ SSTP connected هنوز از گفتهٔ قبلی کاربر است. هیچ anchor بیرونی برای اثبات هویت تاریخی ضد‌دستکاری، مشاهدهٔ اتمیک، packet capture یا آزمون reboot/native recovery وجود ندارد. موفقیت را به آن‌ها تعمیم ندهید.

prepare/reopen plumbing فعلاً پاس شده و نباید دوباره از کاربر آزمون موفق یا ارسال فایل خصوصی خواست. کاربر فعلاً اقدام ندارد؛ journal و شبکه/SSTP همان وضعیت بماند. مرحلهٔ بعد باید به هدف اصلی برگردد: پلن حداقلی و قابل بازبینی برای ایزولاسیون نصاب بتل‌نت، با executable/destinations و SSTP transport/binding صریح، گیت‌های اجرا و recovery محدود. این receipt صرفاً baseline را فراهم می‌کند؛ native writer/Apply/Restore/rules/reconnect هنوز مجاز یا qualified نیستند. علت Block تاریخی همچنان مجهول است و Block هرگز بی‌اجازه به Allow تفسیر نشود.
