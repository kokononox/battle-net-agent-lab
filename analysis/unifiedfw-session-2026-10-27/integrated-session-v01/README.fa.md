# جریان واحد نشست — یکپارچه‌سازی داخلی، نه انتشار اجرایی

## تصمیم مسیر

کاربر تأکید کرد هدف، ابزار عملی و کوچک برای یک پروفایل برنامه‌محور فعال است، نه زنجیره‌ای از بسته‌های تشخیصی. هدف قبلی عوض نشده: ابتدا نصاب Battle.net؛ فقط برنامه‌های حالت فعال و مقصدهای تأییدشده روی SSTP، نه مجوز عمومی همان مقصد برای همهٔ برنامه‌ها. این مرحله اجزای موجود را به یک هماهنگ‌کننده وصل می‌کند و **آزمون دستی یا ZIP تشخیصی جدیدی از کاربر نمی‌خواهد**.

**وضعیت دقیق:** مسیر واحد در کد و آزمون سرتاسری داخلی کار می‌کند. ژورنال فایل واقعی روی Linux و خودِ coordinator موجود رصدگر استفاده شده‌اند؛ اثرهای فایروال در آزمون حافظه‌ای‌اند. backend بومیِ تغییر Enabled/بازگردانی قواعد محلی و حمل متعلق به نشست اکنون در سورس به همان coordinator وصل‌اند، اما observer/review/recovery بومی نهایی هنوز به ورودی زنده وصل نشده‌اند؛ Windows setter واقعی اجرا نشده است. نسخهٔ Windows آمادهٔ Apply یا نصب کامل Battle.net معرفی نمی‌شود.

## آنچه واقعاً متصل شد

- `Ufw.UnifiedSession.ps1`: قفل → pending recovery → پیش‌شرط اجرایی → مشاهده/بازبینی محلی → بازاعتبارسنجی → backup/readback → intent پیش از هر اثر → حمل قبل از quarantine → guard → رصد → quiescence → restore → پایان journal.
- `RuntimeBridge.ps1`: مستقیماً `Invoke-UfwRuntimeCallbacks` موجود را فراخوانی می‌کند. candidate، reobservation، audit backup/restore، reducer و ذخیرهٔ پیشنهاد قبلی دوباره نوشته نشده‌اند. guard نشست به guard فایروال قبلی **افزوده** می‌شود، نه جایگزین آن. UI audit/candidate موجود هنوز خودکار ادغام‌شده در یک پنجره معرفی نشده است؛ این bridge اتصال backend است.
- `StorageBridge.ps1`: adapter فایل واقعی، با helperهای خصوصی قبلیِ بدون تغییر؛ ریشهٔ جدید `UnifiedFW-IntegratedSessions-01`. هر نشست زیرپوشهٔ تصادفی، قفل انحصاری، فایل شماره‌دار CreateNew، Flush، hash chain، readback و کنترل stale head دارد. partial/gap/فایل نامنتظر/ادامه پس از بسته‌شدن رد می‌شود؛ overwrite، حذف یا تعمیر خودکار نداریم. این یک File adapter پیاده‌شده است؛ دوام power-loss و جریان ACL جدید روی Windows هنوز آزموده نشده‌اند.
- `SemanticComparison.ps1`: مقایسهٔ type-aware رکوردهای ثبت‌شدهٔ local/effective؛ فقط metadata مشخص مشاهده‌ای کنار گذاشته می‌شود، همهٔ فیلترها و propertyهای ناشناخته در مقایسه می‌مانند. match، مالکیت، تازگی داده یا اختیار تغییر نیست. روی دادهٔ خصوصی واقعی کاربر اجرا نشده است.
- `NativeReadiness.ps1`: موانع واقعی را در یک محل نگه می‌دارد. مسیر زنده تا حل آنها پیش از review/backup/mutation متوقف می‌شود؛ `qualified`های fixture منبع approval واقعی نیستند. callback قابل‌تعویض ابزار امنیتی در برابر توسعه‌دهنده یا مدیر مخرب نیست و public Apply منتشر نشده است.

- `OwnedTransport.ps1` و `MixedPolicyBackend.ps1`: حمل متعلق به نشست با create-disabled، materialization هفت فیلتر قبل از enable و plan/dispatcher مشترک quarantine. همان parser دفتر برای result دارای observed pair و inverse استفاده می‌شود؛ نه engine دوم.۱۰۷assertion جدید mixed و۱۰۱assertion backend محلی عبور کردند؛ اثر Windows هنوز اجرا نشده است.

## اصلاح دامنه برای نسخهٔ اول

نسخهٔ نخستِ جریان، رصد کنترل‌شده با **SSTP ازقبل‌متصل و تازه‌شناسایی‌شده** است؛ review حمل دقیق همچنان لازم است. خود ابزار reconnect، شروع سرد VPN، تغییر underlay یا ماندگاری ایزولاسیون پس از reboot را در این نسخه پشتیبانی/آزموده‌شده ادعا نمی‌کند. قطع یا تغییر هویت اتصال باید capture را متوقف کند؛ هیچ broad443/DNS یا تغییر hostname/TLS برای رفع شکست ایجاد نشود. رفتار reconnect خود Windows نیز تضمین یا دست‌کاری نشده است.

در نتیجه تست cache سرد/reboot/reconnect شرط انتشار این دامنهٔ محدود نیست؛ به قابلیت آینده منتقل می‌شود، نه اینکه «موفق» علامت بخورد. بازیابی مستقل از شبکه، قاعدهٔ حمل دقیق و اجرای واقعی محدودیت همچنان شرط ضروری‌اند. این کاهش دامنهٔ نسخهٔ نخست است، نه حذف هدف بلندمدت اتصال پایدار روی underlayهای گوناگون.

مرحلهٔ فعلی صفر grant دادهٔ برنامه دارد و هنوز نصب کامل را انجام نمی‌دهد؛ مقصدهای زمان اجرا باید پیش از grant صریح بازبینی شوند. فرزند و سرویس خودکار مجاز نمی‌شوند. فایروال Windows sandbox علیه مدیر مخرب/IPC نیست و fingerprint داخل ارتباط مجاز را منع نمی‌کند؛ ادعاهای no-leak/fingerprint همواره false هستند.

## شکست‌هایی که در مسیر اصلی مهار شدند

- شکست write ممکن است بعد از اثر رخ دهد: intent ذخیره‌شده در فهرست بازیابی می‌ماند، نه اینکه فقط عملیات موفق شمرده شود.
- ابهام در checkpoint: head نامطمئن مجوز ادامه یا restore با journal فرضی نیست؛ pending حفظ شود.
- capture exception بدون رسید روشن: audit نامعلوم تلقی می‌شود؛ قواعد قبلی کورکورانه باز نشوند.
- هدف/helper فعال یا exit consent نامعتبر: restore Allowهای قبلی اجرا نشود؛ recovery محلی باقی بماند.
- capture لغوشده، رصد موفق معرفی نشود؛ policy در صورت ایمنی قابل‌بازگردانی است ولی نتیجهٔ capture incomplete می‌ماند.
- خطای مرحلهٔ finally/unlock در نتیجهٔ نهایی گم نشود.
- restore صرفاً intentهای همین نشست، به ترتیب معکوس و با before/after/drift checking backend است. default Block به Allow تغییر نمی‌کند، legacy journal بازنویسی نمی‌شود و نصب انجام‌شده undo نمی‌شود.

## شواهد و مرز آنها

۲۷ سناریوی یکپارچه و۱۲۳ assertion، با journal فایل واقعی و خود رصدگر موجود، عبور کردند. سناریوی عادی تمام مراحل backup/intent/mutation مدل/capture/audit restore/policy restore را طی کرد؛ برای خطا و pending نیز مسیر جدا آزموده شد.۷۱۸ assertion رصدگر و۱۷۲ assertion inventory قبلی دوباره عبور کردند. همه داخلی و روی Linux/PowerShell7؛ نه setter یا رصد بومی جدید Windows و نه آزمون اجرای نصب‌کننده روی سیستم کاربر.

`python qa.py --pwsh <pwsh>` harness داخلی را اجرا می‌کند. runtime fixture از تست قبلی در فایل موقت گرفته می‌شود؛ سورس قدیمی جایگزین نمی‌شود. شواهد فقط aggregate هستند؛ private snapshot، rule، IP، مسیر شخصی یا SID کاربر وارد repo نشده‌اند. checksum/ACL نه امضای ناشرند و نه WORM/anti-rollback کامل. append/readbackها اتمیک در برابر GPO، admin یا تغییر بین دو cmdlet نیستند و سرعتشان روی Windows اندازه‌گیری نشده است.

## ادامهٔ اجرایی در همین جریان

[اتصال بومی قواعد محلی و بازیابی](NATIVE-LOCAL-BACKEND.fa.md) اضافه شد؛ کد واقعی NetSecurity reader/setter و prefix recovery وجود دارد، نه فقط مدل پایتون. آزمون اثر همچنان provider حافظه‌ای است و transport/live UI/recovery نهایی ناقص‌اند. در ادامه، [حمل متعلق به نشست](OWNED-TRANSPORT.fa.md) به همان backend/دفتر وصل شد: create-disabled، materialize، enable، quarantine و inverse مشترک. reader اتصال واقعی و review زنده هنوز bind نشده‌اند. شواهد آن جدا از qualification Windows در QA-SUMMARY آمده‌اند.

## باقی‌ماندهٔ مشخص تا نسخهٔ قابل‌آزمون

1. bind مشاهدهٔ تازهٔ local/effective و پنجرهٔ review دقیق برنامه/حمل SSTP به نشست و رضایت معتبر؛ snapshot فعلی حفظ شود و دوباره از کاربر ارسال نشود.
2. plan/dispatcher مشترک حمل و قواعد محلی پیاده شد؛ اکنون bind review، recovery مستقل، قفل سراسری و quiescence/قطع اتصال و بررسی هزینهٔ بازخوانی‌های تکراری لازم است. adapter خصوصی ساخت/تغییر/حذف وجود دارد اما ورودی زنده و qualification Windows ندارد.
3. فقط پس از این اتصال، یک بستهٔ واحد و یک آزمون هدفمند روی PC آزمایشی؛ تا آن زمان نه ابزار تشخیصی دستی تازه، نه درخواست Disable قاعده و نه ادعای ready_for_apply.
