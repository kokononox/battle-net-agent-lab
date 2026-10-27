# رضایت خروج محدود، با مبنای audit همان نشست

این بخش ادامهٔ همان collector، storage و backend بازیابی است؛ مجوز reset فایروال، profile=Allow، اجرای EXE یا پاک‌کردن journal قدیمی نمی‌سازد. `ExitReview.ps1` هم رابط کنسولی محلی و هم اتصال رضایت موقت به بازیابی را پیاده می‌کند. اجرای بومی Windows و پوشش مستقل helper/service هنوز qualification ندارند.

## مبنای audit از کجا می‌آید؟

arm جدیدِ `ufw-runtime-arm-02` علاوه بر هویت انتخاب/actor/boot/view، سه mask اصلی before/during و head/session_id دفتر audit محافظت‌شدهٔ collector را در همان policy journal نگه می‌دارد. قبل از ثبت، همان validatorهای pinشدهٔ audit، checksum/head، actor و مقدار واقعی during بررسی می‌شوند؛ plan تازه از تنظیمات فعلی حدس زده نمی‌شود. collector و فایل‌های audit قدیمی تغییر نکرده‌اند.

factory پنجرهٔ بومی، arm بدون این مبنای v02 را برای READY نمی‌پذیرد. v01های قبلی همچنان برای parser و بررسی شاهد خواندنی‌اند، اما از آنها مبنای audit اختراع یا approval تازه ساخته نمی‌شود. direct armهای بدون pending audit فقط اطلاعات legacy می‌دهند؛ native Window و exit review آنها را مجاز نمی‌شمارند.

در بازیابی هم‌زمان policy+audit، head و session_id دفتر audit باید با arm v02 همان نشست برابر باشد؛ mismatch پیش از بازیابی audit، archive یا پرسش خروج رد می‌شود. سپس همان مسیر audit-first قبلی کار می‌کند. نبود audit-pending به‌تنهایی کافی نیست: هنگام review و در guardهای inverse، هر سه مقدار واقعی باید دقیقاً به before ذخیره‌شده برگشته باشند.

برای بازکردن دفتر v02، helperهای audit اصلی باید در همان module خصوصی بار شده باشند؛ نبود validator موجب توقف است، نه قبول داده. هیچ فایل approval قابل‌واردکردن یا migration خودکارِ دفتر قدیمی وجود ندارد.

## review و رضایت موقت

`New-UfwExitReviewContext` فقط روی handle قفل‌شدهٔ همان نشست ساخته می‌شود. قبل از پرسش محلی:

- actor، journal، نبود audit-pending و maskهای before واقعی بررسی می‌شوند؛
- سیاست فعلی با prefix دقیقِ intent/result/restore همان journal reconcile می‌شود؛ drift متوقف می‌کند؛
- بررسی مستقل فرایندهای فعلی و guard مستقل پوشش helper/service باید اجازه بدهند. بدون آنها اصلاً سؤال بی‌فایدهٔ رضایت نمایش داده نمی‌شود.

رابط کنسولی فقط برنامه‌های انتخاب‌شده و inverseهای باقی‌ماندهٔ همان نشست را محلی نمایش می‌دهد. روشن می‌گوید saved Block همان Block می‌ماند؛ این خروج معادل Allow عمومی، reset یا تضمین اینترنت عادی نیست. هیچ برنامه/فرزندی launch/kill یا خودکار مجاز نمی‌شود.

پاسخ باید عین challenge تصادفیِ همان session باشد؛ Enter، پاسخ ناقص یا نوع نامعتبر لغو است. پاسخ بیش از ۱۲۰ثانیه یا تغییر state/head/policy/actor هنگام prompt رد می‌شود. پس از پاسخ نیز وضعیت واقعی و guardهای مستقل دوباره بررسی می‌شوند. رضایت حداکثر ۱۸۰ثانیه از زمان پاسخ، فقط در حافظه باقی می‌ماند؛ ساعت عقب‌رفته، انقضا یا خطای بررسی آن را غیرقابل‌احیا باطل می‌کند.

رضایت به view، arm، مجموعهٔ دقیق saved intentها و materialization حمل تعلق دارد؛ نه به یک head ثابت که با inverseهای قانونی عوض می‌شود. parser همچنان ترتیب دقیق inverseها را کنترل می‌کند. بنابراین پیشرفت عادی restore رضایت را باطل نمی‌کند، اما actor/audit/binding متفاوت مجاز نیست. این بررسی جای census و پوشش helper/service نیست و باید با guard آنها ترکیب شود.

## اتصال به همان dispatcher و backend

`New-UfwReviewedPolicyRecovery` callback موردنیاز `New-UfwRecoveryFirstBindings` را می‌سازد. بعد از audit recovery، همان handle reopenشده را می‌گیرد، review محلی می‌کند، guard موجود + رضایت خروج + process/helper checks را ترکیب و `Recover-UfwLocalBackend` موجود را فراخوانی می‌کند. جریان coordinator همچنان recovery-only است؛ پس از بازیابی در همان اجرا capture جدید شروع نمی‌شود.

در guardهای recovery/restore/immediately_before_restore/finish، actor، maskهای اصلی، lease و binding دوباره خوانده می‌شوند. drift audit بعد از یک inverse، ادامه و closed موفق را مسدود می‌کند؛ inverse انجام‌شده مخفی یا موفقیت کامل نامیده نمی‌شود. backend نیز baseline واقعی و finish guard را پیش از restored تأیید می‌کند. Cancel همان نشست را pending می‌گذارد؛ هیچ «برای درست‌شدن اینترنت Allow کن» پنهانی ندارد.

این اتصال به VPN زنده، DNS، picker یا بازشدن فایل EXE فعلی وابسته نیست. هویت ذخیره‌شده از همان شاهد خصوصی می‌آید؛ raw paths/PIDs/actor/boot در گزارش عمومی یا مخزن منتشر نمی‌شوند. رابط بومی این گام کنسولی است، نه ادعای dashboard نهایی یا launcher عمومی.

## وضعیت واقعی

suite جدید collector واقعی و journal فایل واقعی، audit baseline پایدار، guardهای قبلی و backend reopenشده را در fixture اجرا می‌کند. cancel، audit drift/type/pending، v01 بدون baseline، تغییر prompt، انقضا/ساعت، drift بعد از اولین inverse و مسیر recovery-only با audit مرتبط/نامرتبط پوشش دارند. نتیجه و شمارش معتبر در `evidence/exit-review-tests.json` و `evidence/QA-SUMMARY.json` است. UI/effects Windows واقعی اجرا نشده‌اند؛ providerها و guard موفق helper/service فرضی و صریح‌اند.

پوشش بومیِ معتبر سرویس/IPC یا helper خارج از زنجیره در این گام حل نشده است؛ callback تهی یا true فرضی جای آن را نمی‌گیرد. دامنهٔ native restore، عملکرد reader/lease و رابط نهایی باید پیش از یک اعتبارسنجی هدفمند Windows روشن و تکمیل شوند. `ready_for_apply=false`؛ هیچ ZIP یا diagnostic دستی تازه از کاربر خواسته نمی‌شود.

## ادامه: تطبیق محدود سرویس و PID

[تطبیق سرویس‌ها](SERVICE-QUIESCENCE.fa.md) اکنون به‌صورت factory داخلیِ قابل‌ترکیب با همان بازیابی و رضایت خروج پیاده شده است. این مشاهده فقط یک شرط لازم است؛ پوشش مستقل helper/service/IPC همچنان اجباری و در production حل‌نشده است. entrypoint بومی یا ready-for-Apply از آن نتیجه نمی‌شود.

## کنترل نهایی مستقل Audit

[بازخوانی نهایی Audit](FINAL-AUDIT-VERIFICATION.fa.md) اکنون حتی بدون pending audit اولیه از arm v02 تغذیه می‌شود. guard موجود پس از snapshot نهایی سیاست نیز دوباره اجرا می‌شود. این بررسی اتمیک یا بازپویش خودکار همهٔ دفترهای تاریخیِ بسته نیست و آمادگی Apply را تغییر نمی‌دهد.
