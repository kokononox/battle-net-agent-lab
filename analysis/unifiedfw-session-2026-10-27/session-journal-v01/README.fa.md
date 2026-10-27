# رضایت محدود و ژورنال مستقل نشست — ۰٫۱

## خروجی واقعی این مرحله

`source/Ufw.SessionJournal.psm1` با core و reader بدون تغییر بایت ساخته شد. consent orchestration، adapter فایل Windows و checkpoint append-only پیاده‌سازی شده‌اند، اما **تنها export عمومی Get-UfwPreparationCapabilities است**. ورود عمومی برای prompt/نوشتن و native firewall setter فعال نشده‌اند. هیچ فایل یا تنظیمی روی سیستم کاربر تغییر نکرده است.

رضایت این milestone عمداً **prepare_profile_journal_only** است: ثبت baseline همان نشست، نه consent برای تغییر فایروال. schema رسید authorizes_firewall_change=false و ready_for_apply=false را اجباری می‌کند. consent ثبت فایل، old normal-mode receipt یا private/export بودن تابع، مجوز ایزولاسیون یا مرز sandbox نیستند.

## قرارداد رضایت

- هسته draft از مشاهدهٔ معتبر می‌سازد؛ session ID و nonce تصادفی ایجاد می‌شوند و prompt دقیق `PREPARE JOURNAL ...` برای همان invocation است.
- baseline digest مستقل از ترتیب field/profile است. پس از پاسخ دقیق، baseline تازه خوانده و با همان digest مقایسه می‌شود. پس از ذخیره هم دوباره خوانده می‌شود.
- پاسخ خالی، YES، Boolean یا تفاوت حروف consent نیست؛ هیچ store write درخواست نمی‌شود.
- دو دقیقه فرصت، UTC بودن ساعت و عدم عقب‌گرد در نقاط نمونه‌برداری کنترل می‌شوند؛ زمان پس از write نیز کنترل می‌شود. این کنترل، clock امن سخت‌افزاری یا snapshot اتمیک نیست.
- nonce خام در ژورنال یا خروجی عمومی ثبت نمی‌شود؛ digest challenge در رسید است. JSON با consent_validated=true به‌تنهایی اثبات مستقل حضور انسان نیست و به‌هیچ‌وجه capability اجرای native firewall نیست. adapter واقعی Read-Host نوشته شده ولی هنوز با انسان روی Windows اجرا نشده است.
- اگر Save/readback/revalidation بعدی شکست بخورد، journal_write_attempted=true می‌ماند؛ ممکن است فایل ایجاد شده باشد. false بودن موفقیت به معنی عدم وجود فایل نیست. retry، پاک‌سازی یا overwrite خودکار نداریم.

## ذخیره‌سازی مستقل

مسیر adapter خصوصی Windows: ProgramData زیر `UnifiedFW-InstallerSessions-01`، سپس `UfwInstaller-Session-<random-ID>`. مسیر legacy isolation یا فایل session.json قدیمی هدف نوشتن نیست. directory موجود با همان session ID پذیرفته نمی‌شود؛ pre-existing root/record ناامن تعمیر خودکار نمی‌شود.

owner/DACL هنگام ایجاد Windows برای Administrators و SYSTEM، با inheritance محافظت‌شده داده می‌شوند؛ ruleها، owner و pathهای reparse کنترل می‌شوند. هویت admin، PS5.1 x64 و Windows پیش از نوشتن adapter بومی لازم‌اند. ACL metadata validator با mock آزموده شده است، نه با impersonation یا API واقعی Windows این ماژول. این محافظت در برابر admin مخرب یا جایگزینی runtime ادعا نمی‌شود.

هر checkpoint یک فایل جدید شماره‌دار است: CreateNew، قفل FileShare.None، Flush(true)، checksum، previous hash، sequence و readback. فایل قبلی جایگزین نمی‌شود. schema رسید/draft/entry، session binding، baseline، phase و flagهای monotonic بررسی می‌شوند. تعداد هر نشست حداکثر ۱۲۸ و هر فایل حداکثر ۲۵۶ KiB است؛ prune/rollover خودکار نداریم.

ژورنال ناقص، نام ناشناخته، شکاف sequence، hash یا chain نامعتبر failure می‌دهد و حفظ می‌شود. **append-only در برابر writer همکار است، نه WORM storage.** checksum/chain امضای cryptographic ناشر یا HMAC نیست؛ admin می‌تواند همه را بازنویسی کند. حذف کل tail بدون anchor مستقل لزوماً قابل تشخیص نیست. Flush فایل، تضمین directory fsync یا دوام در تمام power-lossها نیست. بنابراین «tamper-proof»، «crash-proof» یا rollback detection کامل ادعا نمی‌شود.

## ادغام بازیابی

منطق callback هسته با Save متصل به فایل واقعی ژورنال و WriteOutbound حافظه‌ای اجرا شد. ۱۱ checkpoint واقعی به phase restored مدل رسیدند، در حالی که هیچ فایروال واقعی تغییر نکرد. intent باید در phase arming ثبت شود؛ phase/flag regression و تغییر baseline رد می‌شوند. این فایل‌ها فعلاً **ژورنال preparation/model** هستند، نه یک authorization journal آمادهٔ native Apply. native recovery/Apply، rules یا SSTP executor به آن‌ها وصل نشده است.

## آزمون

۷۳ assertion جدید روی PowerShell Linux گذشت: consent cancel/wrong/stale/expired/clock rollback، post-write drift/expiry، خروجی بدون nonce/identity/digest، actual filesystem roundtrip، CreateNew collision، exclusive lock، stale head، baseline/receipt/schema/phase/flag binding، checksum/chain/gap، partial record، size limit، شکست Write/Flush/readback، حفظ فایل مبهم، property-order و ۱۲ metadata fixture مجوزها، و recovery با checkpoint واقعی و profile writer حافظه‌ای.

۷۸ core، ۵۴ reader، ۷۲ HF124 library و ۴۷ runner قبلی نیز rerun شدند. dependencyها و بستهٔ تحویل قبلی بدون تغییر بایت‌اند. native Windows ACL، prompt انسانی واقعی، durable power-loss و اجرای واقعی تغییر پروفایل در این milestone آزموده نشده‌اند. full historical regression suite نیز دوباره اجرا نشده است.

## ادامه و وضعیت کاربر

مرحلهٔ بعد باید آزمون storage-only همین adapter روی Windows در fixture جدا باشد؛ نه live Apply یا نوشتن روی legacy journal. فعال‌سازی consent ثبت فایل واقعی فقط پس از موفقیت fixture و review جدید ممکن است. پیش از هر setter هنوز consent کاملِ عملیات و policy، rule ownership/effective-policy، SSTP transport/bootstrap/reconnect و recovery بومی لازم‌اند.

علت تاریخی برگشت Block هنوز مجهول است. هدف بنیاد کوچک اختصاصی نصاب Battle.net است، نه گسترش dashboard. **کاربر فعلاً هیچ اقدامی ندارد**؛ اینترنت/SSTP فعلی تغییر نکند و بسته‌های Apply/Restore/reconnect قبلی تکرار نشوند. no_leak_certified و ready_for_apply false می‌مانند.
