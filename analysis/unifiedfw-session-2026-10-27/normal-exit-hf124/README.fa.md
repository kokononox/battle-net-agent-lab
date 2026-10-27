# HF1.2.4 — رکورد جداگانهٔ خروج صریح به حالت عادی، فقط توسعهٔ آفلاین

این مرحله بعد از اصلاح بازیابی HF1.2.3 است. هدف آن تغییر معنای ژورنال قدیمی یا مجازکردن ایزولاسیون نیست؛ یک کتابخانهٔ واقعی برای Review/Record جداگانهٔ وضعیت عادیِ از قبل برقرارشده پیاده شده است. سیستم کاربر، فایل backup و ژورنال او دست‌نخورده‌اند.

## قرارداد روشن

- ژورنال قدیمی session.json که restored/NotConfigured دارد بازنویسی، archive، حذف یا به Allow تبدیل نمی‌شود. حالت عادیِ فعلی، همان خروج صریحی است که کاربر قبلاً برایش اجازه داد و مرورگر بدون VPN را موفق گزارش کرد؛ آن را restore دقیق baseline قبلی نمی‌نامیم.
- Review فقط می‌خواند و digest وابسته به همان ژورنال، قواعد و سه پروفایل محلی/مؤثر می‌سازد. digest رضایت یا امضای رمزنگاری‌شده نیست.
- Record رضایت دقیق `ACKNOWLEDGE EXISTING NORMAL NETWORK MODE` و همان digest را می‌خواهد؛ سپس تمام شواهد را از نو می‌خواند. approved=true یا برچسب restored به‌تنهایی اجازه نمی‌دهد.
- فقط ژورنال restored با هویت معتبر، سه پروفایل موردانتظار و flags boolean واقعی پذیرفته می‌شود. تمام قواعد owned که intent داشته‌اند باید واقعاً غایب باشند و تصویر کامل قواعد foreign باید با before اصلی برابر باشد؛ برای عبور از اختلاف مشروع/نامشروع، هیچ قاعده‌ای enable/remove نمی‌شود.
- هر سه پروفایل اکنون باید در PersistentStore و ActiveStore خروجی Allow و فایروال روشن داشته باشند. مقدار NotConfigured در baseline قدیمی برای شناسایی رخداد مجاز است، **نه** برای setter یا مجوز Restore. local/effective snapshotها در رکورد جدا ثبت می‌شوند.
- اگر هر task با پیشوند شناخته‌شدهٔ UnifiedFW-Isolation- باقی مانده باشد، ثبت متوقف می‌شود؛ حتی task متوقف. هیچ task یا controller حذف/نصب نمی‌شود. این فقط بررسی taskهای شناخته‌شدهٔ این موتور است، نه کشف همهٔ برنامه‌ها، GPOها یا عاملِ بازنویسی policy.

## فایل و مرز اعتماد

رکورد فقط در ریشهٔ محافظت‌شدهٔ موجود، به نام `normal-mode-exit-<legacy-id>.json` نوشته می‌شود. نام از ID هگز محدودشده ساخته می‌شود، نه ورودی مسیر آزاد. wrapper ابتدا UAdmin و IsoSecureRoot را به‌کار می‌گیرد: مالک و ACL ریشه/فرزندان و reparse path مطابق کد موجود بررسی می‌شوند. همان operation.lock انحصاری موتور استفاده می‌شود؛ قفل busy به خطا منجر می‌شود و وارد رقابت با guardian نمی‌شویم.

نوشتن از UWritePrivateBytes موجود با CreateNew استفاده می‌کند؛ در Windows مالک/DACL ادمین و SYSTEM هنگام ایجاد داده می‌شود، نه Set-Acl بعدی. رکورد موجود overwrite نمی‌شود. checksum payload و read-back بررسی می‌شوند و پس از write، native evidence دوباره مقایسه می‌شود. اختلاف post-write به خطا منجر می‌شود؛ فایل برای بررسی باقی می‌ماند و کورکورانه تأیید نمی‌شود. تکرار همان درخواست فقط پس از fresh validation و برابری رکورد قبلی idempotent است؛ رکورد conflicting/extra authority fields رد می‌شود.

checksum به‌تنهایی امضا یا حفاظت در برابر admin نیست. مرز حفاظت ACL موجود و قفل تعاونی موتور است؛ Admin/GPO/برنامهٔ دیگر می‌تواند خارج از این قفل تغییر ایجاد کند. snapshotها متوالی‌اند و تضمین اتمیک ندارند. مرورگر، TLS، اینترنت عمومی، reboot یا packet توسط ثبت فایل تأیید نمی‌شوند. خود Record هیچ تست شبکه‌ای هم نمی‌فرستد.

قالب زمان UTC در این رکورد عمداً با پسوند متنی ` UTC` ذخیره می‌شود تا ConvertFrom-Json در PowerShell7 آن را خودکار به DateTime تبدیل نکند و با رشته در WinPS5.1 ناسازگار نشود؛ timestamp منبع اعتماد یا مجوز نیست.

## دامنهٔ کد و استقرار

تنها فایل production جدید `app/normal-exit-record.ps1` است؛ ورودی تابعی Review/Record دارد، نه یک اسکریپتِ دارای اجرای خودکار. کد worker/guardian، HF1.2.3 recovery، UI و helperهای native/private-write **بدون تغییر بایت** باقی‌اند. کتابخانه در worker فعلی auto-load نشده و هیچ controller فعال به‌روزرسانی نشده است.

این یعنی ثبت واقعی روی سیستم کاربر هنوز انجام نشده است. wrapper بومی، protected-write و قرارداد callbacks پیاده‌اند، اما بستهٔ قابل‌نصب، runner با consent UI و مسیر migration/پذیرش baseline جدید برای Apply هنوز آماده نیست. این رکورد مجوز Apply نمی‌دهد و guard سخت‌گیرانهٔ HF1.2.3 برای ژورنال قدیمی همچنان برقرار است. تنها وجود رکورد نباید آن guard را bypass کند. `authorizes_isolation`، `original_restore_verified`، `reboot_qualified`، `ready_for_apply` و `no_leak_certified` false می‌مانند.

رکورد protected شامل شناسه‌های قدیمی و شواهد profile است؛ در محصول آینده نباید فایل خامش خودکار export یا commit شود. خروجی عمومی Review فقط شمارنده‌ها، نام سه profile و وضعیت آنها و review digest دارد، نه نام قواعد foreign یا raw journal.

## آزمون‌ها

۷۲ assertion اختصاصی گذشت: consent، stale review، owned/foreign drift، NotConfigured قدیمی بدون coercion، profile local/effective، controller task، race حین بررسی/بعد از write، readback، idempotence، conflict، حفظ byte ژورنال روی دیسک، checksum، CreateNew، قفل واقعی فایل در Linux و cleanup root پس از خطا.

Windows native API/ACL/admin identity و محافظت واقعی task هنوز اجرا نشده‌اند؛ در مدل wrapper این بخش‌ها mock هستند. فایل IO واقعی فقط Linux بوده است. سایر نتایج رگرسیون در QA-SUMMARY.json ثبت شده‌اند. هیچ ادعای نوشتن روی ProgramData کاربر یا qualification reboot نکنید.

## اقدام بعد

فعلاً کاربر هیچ بسته یا دستور تازه‌ای اجرا نکند؛ اینترنت عادی و فایل backup را نگه دارد. Apply/Restore/local-review و آزمون live reconnect همچنان متوقف بمانند. مرحلهٔ بعد، اتصال کنترل‌شدهٔ این کتابخانه به review/consent در بستهٔ آتی و آزمون هدفمند ACL/legacy-preservation روی Windows است؛ نه ارتقای خودکار controller یا تبدیل بی‌اجازهٔ journal. پیش از درخواست آن آزمون، بسته و مسیر خطای امن باید آماده شوند. هدف ابزار کوچک اختصاصی نصاب Battle.net است.
