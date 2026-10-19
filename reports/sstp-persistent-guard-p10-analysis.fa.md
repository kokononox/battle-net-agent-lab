# P10 — گارد پایدارِ گذار و آزمون واقعی TCP با دامنهٔ محدود

## نتیجه ثبت‌شده
**PASS محدود**، نه کیل‌سوییچ کامل یا مجوز اعمال روی کاربر.

- source: `f9f86eaf606f19d4c1e7af23d6c506f4fffbfe35`
- run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39221080984 — Success، زمان UI: 2m48s.
- checks=64، شش termination و شش recovery در powershell.exe تازه.
- دو جفت آزمایش هنگام Hold: executable A متصل نمی‌شود و executable B همسان با مسیر متفاوت به همان IPv4/443 متصل می‌شود. هر دو پیش از Hold و پس از Release موفق بودند. process اعمال‌کننده پیش از probe خارج شده بود.
- owned label/filter conflict stops=2؛ journal گمشده/خراب موجب توقف شد و قانون held از مسیر محصول آزاد نشد. idempotency و Release مستقیم از دو Hold ناقص هم بررسی شدند.
- fixture rules=9؛ remaining=0؛ baseline کامل rule/هفت filter/profile نامرتبط برابر=True؛ اختلاف label نمایشی=0.
- ZIP digest: `8aa955e8ebce8bec6df06f697f550bd6c91a1279c0ff83b990d1ae21e0326a8d`. digest واقعی فایل، schema/flags/countها، source/run و hash هشت فایل کد با LF/CRLF checkout مستقلاً بررسی شد.

## آنچه پیاده شد
Guard.ps1 یک کتابخانهٔ داخلی جداگانه است. قانون اولیهٔ Block در PersistentStore غیرفعال ساخته می‌شود؛ original کامل raw rule و هر هفت filter در journal P2 ذخیره می‌شود. Hold/Release فقط Enabled همان object را با write-ahead/pending، قفل، revision و readback کامل عوض می‌کنند. همهٔ labelهای owned strict هستند؛ هیچ معافیت drift خارجی برای گارد خودمان وجود ندارد. pending فقط before/after دقیق mutation خود را می‌پذیرد. پس از شروع Release، Hold دوباره مجاز نیست.

اگر ایجاد قبل از ثبت journal قطع شود، قانون orphan فقط غیرفعال است؛ خودکار adopt/delete نمی‌شود. قانون held با گم‌شدن یا خرابی journal خودکار باز نمی‌شود. Release داخلی برابر بازگردانی Enabled=False اصلی است، نه حذف/reset. پاک‌سازی CI مسیر جداست و تنها نُه fixture با Group و strict hash کامل original/Enabled را حذف کرده است؛ این رفتار emergency cleanup CI به محصول تعمیم داده نمی‌شود.

Scope=WholeMachine در کتابخانه با Program=Any تعریف شده، اما **در این اجرا هرگز ساخته/فعال/آزمایش نشد**. CI فقط Scope=Fixture و executable یکتا داشت. هیچ profile default، GPO یا قانون قدیمی runner تغییر نکرد. این جزء هنوز با P9 در coordinator واحد ادغام نشده است؛ P9 مستقل همان qualification قبلی را دارد.

## ارتباط با خواستهٔ بدون برنامهٔ مقیم
در آزمون اتصال اصلی، powershell.exe جداگانه قانون native را فعال کرد و خارج شد؛ پس از آن دو دور تلاش اتصال با executable تازه انجام شد. مسدودسازی به زنده‌ماندن process اعمال‌کننده وابسته نبود. هیچ resident، service سفارشی، task، watcher، expiry یا rollback زمان‌دار اضافه نشد. این فقط ماندن اثر پس از خروج process را آزمود، نه restart ویندوز یا ترتیب boot.

## مرز ادعا و گام بعد
probe فقط TCP تازه به یک IPv4 عمومی/443 بود. DNS github.com صرفاً setup آزمایش، بیرون probe و بدون credential/payload کاربردی است؛ در محصول DNS آزاد نشده و IP/نام executable/raw inventory/journal upload نشده است. ConnectAsync ناموفق در کنار کنترل موفق و readback قانون مشاهده شد؛ pcap گرفته نشده و ترافیک اتصال‌های قبلی، UDP، IPv6، همهٔ آدرس‌ها، DNS/LAN، SSTP/reconnect یا reboot بررسی نشده‌اند.

explicit Block سراسری، Allowهای SSTP را هم خنثی می‌کند. پس گارد فقط برای گذار/بازیابی است، نه حالت نهایی Allowlist. coordinator نهایی باید زیر گارد تأییدشده پیش‌فرض outbound=Block را برای profileهای لازم اعمال کند، Allowهای قبلی را با P9 قرنطینه کند، allowهای مقید به هویت SSTP/مقصد و bootstrap محدود را تأیید کند و فقط پس از ممیزی تازه گارد را آزاد کند. این شروط، سلامت مؤثر Firewall/BFE، merge/GPO و شرط واقعی آزادسازی در این P10 پیاده/qualified نشده‌اند. API Release کتابخانه جای شرط coordinator نیست و نباید مستقیم روی ماشین کاربر استفاده شود.

مستند Set-NetFirewallProfile مقدار NotConfigured را برای GPO معتبر توصیف می‌کند؛ درحالی‌که گزارش ذخیرهٔ محلی کاربر چنین مقدارهایی دارد. پیش از profile adapter باید مسیر دقیق بازگردانی همان stored value روی store هدف را راستی‌آزمایی کرد، نه معادل‌گرفتن آن با Allow یا Force-Allow. تا اثبات بازگردانی دقیق، تنظیم واقعی profile مجاز اعلام نشده است.

هیچ تغییری روی دستگاه کاربر انجام نشد؛ ready_for_user_apply=false. مرحلهٔ بعد adapter دقیق profile و coordinator گارد+P9+allowهای SSTP است؛ بدون ادعای زودهنگام no-leak.

## منابع طراحی
- تقدم Block صریح بر Allow: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
- قرارداد InputObject/PolicyStore و محدودیت مستند NotConfigured: https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps
