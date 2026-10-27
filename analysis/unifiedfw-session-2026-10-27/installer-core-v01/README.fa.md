# هستهٔ کوچک نصاب — ادغام preflight و recovery callback، نسخهٔ ۰٫۱

این مرحله ادامهٔ مستقیم reader مستقل ۰٫۱ است. هدف ابزار کوچک اختصاصی نصاب Battle.net با حمل SSTP است؛ **نه نسخهٔ اجرایی ایزولاسیون برای سیستم کاربر**. هیچ user deployment، Apply یا تغییر تنظیمات Windows در این milestone انجام نشده است.

## ادغام واقعی کد

`source/Ufw.InstallerCore.psm1` reader کنار خودش را با SHA256 ثابت و بررسی reparse مسیر بارگذاری می‌کند. فایل reader بدون تغییر بایت از milestone قبلی کپی شده است. تنها export هسته `Invoke-UfwInstallerPreflightReadOnly` است؛ مسیر عمومی به reader واقعی وصل است، نه فقط یک قرارداد روی کاغذ. getterهای Windows در آزمون موفق این مسیر mock هستند؛ guard واقعی Linux جدا آزموده شده است.

خروجی preflight فقط می‌گوید ساخت draft پروفایل با مقادیر صریح ممکن است یا نه؛ `completed=true` به معنی تکمیل بخش profile stage است، نه تکمیل preflight کامل نصاب. `pending_components` نبود consent صریح نشست، journal محافظت‌شده، rule/effective-policy checks، SSTP reconnect/transport و native recovery executor را آشکار می‌کند. `ready_for_apply` و `no_leak_certified` false می‌مانند.

## منطق داخلی بازیابی — فقط آداپتور حافظه‌ای آزموده شده

توابع private، draft مستقل profile_outbound_only می‌سازند و بازیابی را با callbackهای `ReadProfiles`, `Save`, `WriteOutbound` انجام می‌دهند. آداپتور native setter یا journal دیسکی در این مرحله وجود ندارد. private/export مرز مجوز امنیتی یا sandbox نیست؛ عمداً هیچ مسیر عمومی اجرای بازیابی عرضه نشده است. draft با execution_authorized=false صرفاً دادهٔ مدل است، نه رضایت اجرا. این routine نباید بدون ساخت authorization و persistence واقعی به native writer وصل شود.

- سه baseline محلی و مؤثر دقیق و مستقل، با نام/coverage/encoding اجباری نگه داشته می‌شوند. NotConfigured outbound و journal قدیمی پذیرفته/مهاجرت نمی‌شوند.
- وضعیت snapshot کپی می‌شود تا تغییر object ورودی baseline را عوض نکند. ترتیب property یا سطر profile اختلاف policy محسوب نمی‌شود.
- پیش از هر write مدل، phase ذخیره و وضعیت دوباره خوانده می‌شود؛ بعد write نیز readback کنترل می‌شود. writes ترتیبی و معکوس‌اند؛ parallel mutation یا reset سراسری وجود ندارد.
- فقط profile دارای intent که تصویرش baseline یا تصویر Block قابل‌انتظار همین مدل باشد قابل بررسی برای بازیابی است. flagها و مقادیر، مالکیت واقعی تغییر را ثابت نمی‌کنند؛ journal/actor معتبر برای native deployment هنوز لازم است.
- مقدار baseline دقیق حفظ می‌شود: baseline=Block هیچ Allow نمی‌سازد. profile دست‌نخورده write نمی‌شود و drift آن کل عملیات را متوقف می‌کند.
- خطای Save، write، readback یا drift موفقیت برنمی‌گرداند. در تست، از آخرین snapshot حافظه‌ای ذخیره‌شده ادامه داده می‌شود؛ write انجام‌شدهٔ قبل crash دوباره لازم نیست.
- phase=restored بدون خواندن تازه قابل اعتماد نیست؛ sweep نهایی هر سه profile باید تطبیق کند. موفقیت فقط current profile model state است؛ original_restore_verified، reboot_qualified و ready_for_apply false هستند.

## آزمون‌های این مرحله

۷۸ assertion جدید روی PowerShell Linux گذشتند: اتصال core→reader→getter mock، dependency pin mismatch، Allow/Block، baseline ناسازگار/NotConfigured، metadata و schema ناقص، data clone، callback recovery، ترتیب write، هر ۸ نقطهٔ شکست Save، هر ۳ نقطهٔ شکست write، هر ۳ crash پس از write، readback ناموفق، drift هم‌زمان و sweep نهایی، restored-stamp drift، شروع دوباره از snapshot ذخیره‌شده و عدم تکرار write، property/row order و export فقط‌خواندنی.

۵۴ assertion reader، ۷۲ library HF124 و ۴۷ runner قبلی نیز دوباره گذشتند؛ فایل‌های QA تفکیک شده‌اند. این اعداد success روی Windows یا آزمون persistence واقعی نیستند. full historical regression suite این milestone تکرار نشده است. نسخهٔ قبلی برنامه، worker و ZIP کاربر دست‌نخورده‌اند.

## مرزهای باز و مرحلهٔ بعد

هیچ engine کامل rules یا ایزولاسیون به این کد وصل نشده است. اتصال سرد SSTP، transport pin/service identity، تغییر LAN/Wi-Fi، existing flows، reboot و جلوگیری از fingerprint هنوز با این milestone تأیید نشده‌اند. علت تاریخی Block نیز حل نشده است.

مرحلهٔ بعد باید authorization و journal محافظت‌شدهٔ جدید را با failure tests به همین هسته وصل کند، پیش از هر native setter. baseline قدیمی NotConfigured را بازنویسی نکنید و رسید normal-mode را مجوز Apply ندانید. بازگشت به اینترنت عادی نباید خودکار یا مبتنی بر حدس Allow باشد.

**اقدام کاربر: هیچ.** SSTP/شبکهٔ فعلی ثابت بماند؛ بستهٔ قدیمی، Apply/Restore/reconnect و Allow مجدد درخواست نشده‌اند. این کد به سیستم کاربر نصب نشده است.
